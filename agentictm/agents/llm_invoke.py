"""LLM invocation — prompt building, tool-calling loop, and retry logic."""

from __future__ import annotations

import json
import logging
import re
import time
from typing import TYPE_CHECKING

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    before_sleep_log,
)

from agentictm.agents._utils import ensure_str_content
from agentictm.agents.reflection import _strip_think_tags, _self_reflect
from agentictm.agents.metrics import _record_metric
from agentictm.agents.json_extraction import extract_json_from_response

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel
    from langchain_core.tools import BaseTool

logger = logging.getLogger(__name__)

# Models known to NOT support Ollama's tool-calling API (reasoning models, etc.)
_MODELS_WITHOUT_TOOL_SUPPORT: set[str] = {
    "deepseek-r1", "deepseek-r1:1.5b", "deepseek-r1:7b", "deepseek-r1:8b",
    "deepseek-r1:14b", "deepseek-r1:32b", "deepseek-r1:70b",
    "deepseek-r1:671b",
}


def build_messages(
    system_prompt: str,
    human_prompt: str,
) -> list:
    """Build the message list for invoking an LLM."""
    return [
        SystemMessage(content=system_prompt),
        HumanMessage(content=human_prompt),
    ]


def _invoke_tools_into_prompt(
    tools: list[BaseTool],
    human_prompt: str,
    agent_name: str = "",
    prompt_budget_chars: int | None = None,
) -> str:
    """Pre-invoke RAG tools and embed results into the prompt.

    Fallback for models that don't support native tool-calling.
    Extracts key terms from the prompt, queries each RAG tool,
    and appends results as reference material.

    Args:
        prompt_budget_chars: Max total chars for the human prompt (incl. RAG).
            When set, stops adding RAG results once the budget is reached.
    """
    prefix = f"[{agent_name}] " if agent_name else ""

    query_text = re.sub(r'```[\s\S]*?```', '', human_prompt)
    query_text = re.sub(r'\{[\s\S]{50,}?\}', '', query_text)
    query = query_text.strip()[:500]
    if not query:
        query = human_prompt[:500]

    rag_sections: list[str] = []
    accumulated_rag_chars = 0

    _CITATION_STRIP = re.compile(
        r"\n{0,3}-{3,}\n"
        r"IMPORTANT:.*?evidence_sources.*?\"<relevant quote>\"\}\n?",
        re.DOTALL,
    )

    for tool in tools:
        tool_name = getattr(tool, "name", str(tool))

        if prompt_budget_chars:
            current_total = len(human_prompt) + accumulated_rag_chars + 120
            if current_total >= prompt_budget_chars:
                logger.warning(
                    "%sPrompt budget reached (%d/%d chars). Skipping remaining RAG tools.",
                    prefix, current_total, prompt_budget_chars,
                )
                break

        try:
            t0 = time.perf_counter()
            result = tool.invoke({"query": query})
            elapsed = time.perf_counter() - t0
            result_str = str(result).strip()
            result_str = _CITATION_STRIP.sub("", result_str).strip()
            if result_str and len(result_str) > 20:
                if len(result_str) > 10000:
                    result_str = result_str[:10000] + "\n... [truncated]"
                rag_sections.append(f"### {tool_name}\n{result_str}")
                accumulated_rag_chars += len(rag_sections[-1]) + 2
                logger.info(
                    "%sPre-invoked RAG tool '%s' in %.1fs -> %d chars",
                    prefix, tool_name, elapsed, len(result_str),
                )
            else:
                logger.info("%sPre-invoked RAG tool '%s' -> no useful results", prefix, tool_name)
        except Exception as exc:
            logger.warning("%sFailed to pre-invoke RAG tool '%s': %s", prefix, tool_name, exc)

    if rag_sections:
        rag_block = (
            "\n\n---\n"
            "## REFERENCE MATERIAL (from knowledge base)\n"
            "Use these sources as background context ONLY. "
            "Do NOT copy entries, IDs (TMA-xxxx), or formats from these results. "
            "Your output MUST follow the JSON schema described above, NOT the format of these references.\n\n"
            + "\n\n".join(rag_sections)
        )
        human_prompt = human_prompt + "\n" + rag_block
        logger.info(
            "%sEmbedded %d RAG tool results into prompt (+%d chars)",
            prefix, len(rag_sections), len(rag_block),
        )

    return human_prompt


# ---------------------------------------------------------------------------
# Retry-wrapped LLM invocation — handles transient Ollama / network errors
# ---------------------------------------------------------------------------

_RETRYABLE_ERRORS: tuple[type[Exception], ...] = (
    ConnectionError,
    TimeoutError,
    OSError,
)

try:
    from anthropic import RateLimitError as _AnthropicRateLimit, APIStatusError as _AnthropicAPIStatus
    _RETRYABLE_ERRORS = (*_RETRYABLE_ERRORS, _AnthropicRateLimit, _AnthropicAPIStatus)
except ImportError:
    pass
try:
    from openai import RateLimitError as _OpenAIRateLimit
    _RETRYABLE_ERRORS = (*_RETRYABLE_ERRORS, _OpenAIRateLimit)
except ImportError:
    pass


def _is_retryable(exc: BaseException) -> bool:
    """Check if an exception should trigger a retry.

    Retries on transient errors (connection, timeout, rate limit, 5xx).
    Does NOT retry on 4xx client errors other than 429 (rate limit).
    """
    if isinstance(exc, _RETRYABLE_ERRORS):
        status = getattr(exc, "status_code", None)
        if status is not None:
            return status == 429 or status >= 500
        return True
    return False


@retry(
    retry=lambda rs: _is_retryable(rs.outcome.exception()) if rs.outcome and rs.outcome.exception() else False,
    stop=stop_after_attempt(4),
    wait=wait_exponential(multiplier=4, min=5, max=65),
    before_sleep=before_sleep_log(logger, logging.WARNING),
    reraise=True,
)
def _llm_invoke_with_retry(llm_instance, messages, prefix: str = ""):
    """Call llm.invoke(messages) with automatic retry on transient errors."""
    try:
        return llm_instance.invoke(messages)
    except Exception as exc:
        exc_str = str(exc)
        if "Just a moment" in exc_str or "cf_chl" in exc_str:
            logger.error(
                "Anthropic API blocked by Cloudflare bot protection (403). "
                "This happens after too many rapid requests. "
                "Wait 2-3 minutes and try again."
            )
        raise


_MAX_LOCAL_RESPONSE_CHARS = 120_000


def _estimate_prompt_budget(llm: BaseChatModel) -> int | None:
    """Return a safe max prompt size in chars, leaving room for LLM response.

    For local (Ollama) models, derives the budget from num_ctx.
    For cloud providers, returns their known limits.
    Returns None only if nothing is determinable.
    """
    cls_name = type(llm).__name__
    if cls_name == "ChatAnthropic":
        return 80_000
    if cls_name in ("ChatOpenAI", "AzureChatOpenAI"):
        return 400_000
    if cls_name == "ChatGoogleGenerativeAI":
        return 200_000
    num_ctx = getattr(llm, "num_ctx", None)
    if num_ctx and isinstance(num_ctx, int):
        num_predict = getattr(llm, "num_predict", None)
        if num_predict and isinstance(num_predict, int):
            return int((num_ctx - num_predict) * 3.5)
        return int(num_ctx * 3.5 * 0.70)
    return None


def _estimate_cloud_prompt_limit(llm: BaseChatModel) -> int | None:
    """Return max human_prompt chars for cloud LLMs, or None for local/unlimited."""
    cls_name = type(llm).__name__
    if cls_name == "ChatAnthropic":
        return 80_000
    if cls_name in ("ChatOpenAI", "AzureChatOpenAI"):
        return 400_000
    if cls_name == "ChatGoogleGenerativeAI":
        return 200_000
    return None


def _maybe_truncate_local_response(llm: BaseChatModel, text: str, prefix: str = "") -> str:
    """Truncate oversized responses from local (Ollama) models to prevent OOM.

    Attempts to preserve valid JSON by extracting it from the full response
    before falling back to a naive character cut.  When the response contains
    huge Mermaid diagrams embedded in JSON, tries to shrink them while keeping
    the threats/data arrays intact.
    """
    if _estimate_cloud_prompt_limit(llm) is not None:
        return text
    if len(text) <= _MAX_LOCAL_RESPONSE_CHARS:
        return text

    logger.warning(
        "%sLocal LLM response oversized: %d chars (cap=%d). Attempting smart truncation.",
        prefix, len(text), _MAX_LOCAL_RESPONSE_CHARS,
    )

    try:
        parsed = extract_json_from_response(text)
        if parsed:
            if isinstance(parsed, dict):
                for tree in parsed.get("attack_trees", []):
                    mermaid = tree.get("tree_mermaid", "")
                    if isinstance(mermaid, str) and len(mermaid) > 3000:
                        tree["tree_mermaid"] = mermaid[:3000] + "\\n... [truncated]"

            compact = json.dumps(parsed, ensure_ascii=False, separators=(',', ':'))
            if len(compact) <= _MAX_LOCAL_RESPONSE_CHARS:
                logger.info(
                    "%sExtracted valid JSON and re-serialized: %d -> %d chars",
                    prefix, len(text), len(compact),
                )
                return compact
            readable = json.dumps(parsed, ensure_ascii=False, indent=2)
            if len(readable) <= _MAX_LOCAL_RESPONSE_CHARS:
                return readable
            logger.info(
                "%sJSON re-serialized still large (%d chars) but preserving structure",
                prefix, len(compact),
            )
            return compact
    except Exception:
        pass

    return (
        text[:_MAX_LOCAL_RESPONSE_CHARS]
        + "\n... [response truncated to prevent memory issues]"
    )


def invoke_agent(
    llm: BaseChatModel,
    system_prompt: str,
    human_prompt: str,
    tools: list[BaseTool] | None = None,
    max_tool_rounds: int = 3,
    agent_name: str = "",
    enable_self_reflection: bool = False,
    reflection_llm: BaseChatModel | None = None,
    pre_invoke_tools: bool = False,
) -> str:
    """Invoke an LLM agent with iterative tool calling.

    If the agent has tools, runs a loop:
    1. Call the LLM
    2. If it requests tool calls -> execute them and re-invoke
    3. Repeat until no more tools are requested or max_tool_rounds

    If enable_self_reflection=True, after the main response the agent
    performs a critique-then-revise cycle for higher quality output.

    Returns:
        The final agent response text.
    """
    model_name = getattr(llm, "model", getattr(llm, "model_name", "unknown"))
    prefix = f"[{agent_name}] " if agent_name else ""

    max_chars = _estimate_cloud_prompt_limit(llm)
    if max_chars and len(human_prompt) > max_chars:
        original_kb = len(human_prompt) / 1024
        human_prompt = (
            human_prompt[:max_chars]
            + f"\n\n[... TRUNCATED — original input was {original_kb:.0f} KB, "
            f"reduced to {max_chars // 1024} KB to fit cloud API token limits. "
            f"Focus on the information provided above.]"
        )
        logger.warning(
            "%sPrompt truncated for cloud API: %.1f KB -> %d KB (model=%s, limit=%d chars)",
            prefix, original_kb, max_chars // 1024, model_name, max_chars,
        )

    prompt_kb = len(human_prompt) / 1024

    logger.info(
        "%sLLM invoke starting | model=%s | system_prompt=%d chars | human_prompt=%.1f KB | tools=%s",
        prefix, model_name,
        len(system_prompt), prompt_kb,
        [t.name for t in tools] if tools else "none",
    )

    model_base = model_name.split(":")[0] if model_name else ""
    model_lacks_tools = any(
        model_name == m or model_base == m.split(":")[0]
        for m in _MODELS_WITHOUT_TOOL_SUPPORT
    )

    _reasoning_disabled = getattr(llm, "reasoning", None) is False
    _should_pre_invoke = model_lacks_tools or _reasoning_disabled or pre_invoke_tools

    if tools and _should_pre_invoke:
        logger.info(
            "%sPre-invoking RAG tools (model=%s, reasoning_off=%s). "
            "Embedding results in prompt to preserve format=json.",
            prefix, model_name, _reasoning_disabled,
        )
        prompt_budget = _estimate_prompt_budget(llm)
        human_prompt = _invoke_tools_into_prompt(
            tools, human_prompt, agent_name=agent_name,
            prompt_budget_chars=prompt_budget,
        )
        tools = None

    llm_for_tools = llm
    if tools:
        llm_format = getattr(llm, "format", None)
        if llm_format:
            logger.info(
                "%sStripping format='%s' for tool-calling compatibility",
                prefix, llm_format,
            )
            try:
                llm_for_tools = llm.model_copy(update={"format": ""})
            except Exception:
                try:
                    import copy as _copy
                    llm_for_tools = _copy.deepcopy(llm)
                    llm_for_tools.format = ""  # type: ignore[attr-defined]
                except Exception:
                    llm_for_tools = llm

    messages = build_messages(system_prompt, human_prompt)

    if tools:
        try:
            llm_with_tools = llm_for_tools.bind_tools(tools)
        except Exception as bind_exc:
            logger.warning(
                "%sbind_tools failed (%s). Falling back to prompt-embedded RAG.",
                prefix, bind_exc,
            )
            human_prompt = _invoke_tools_into_prompt(
                tools, messages[1].content, agent_name=agent_name,
            )
            messages = build_messages(system_prompt, human_prompt)
            tools = None
            llm_with_tools = llm
    else:
        llm_with_tools = llm

    total_start = time.perf_counter()
    tool_call_count = 0
    _tools_fallback_done = False

    for round_num in range(max_tool_rounds + 1):
        round_start = time.perf_counter()
        logger.info("%sLLM call round %d/%d starting...", prefix, round_num + 1, max_tool_rounds + 1)

        try:
            response: AIMessage = _llm_invoke_with_retry(llm_with_tools, messages, prefix=prefix)
        except Exception as invoke_exc:
            exc_msg = str(invoke_exc).lower()
            if "does not support tools" in exc_msg or "status code: 400" in exc_msg:
                if _tools_fallback_done:
                    raise
                logger.warning(
                    "%sRuntime tool-calling error (%s). "
                    "Falling back to prompt-embedded RAG and retrying.",
                    prefix, invoke_exc,
                )
                _tools_fallback_done = True
                original_human = messages[1].content if len(messages) > 1 else human_prompt
                human_prompt = _invoke_tools_into_prompt(
                    tools or [], original_human, agent_name=agent_name,
                )
                messages = build_messages(system_prompt, human_prompt)
                llm_with_tools = llm
                tools = None
                response = _llm_invoke_with_retry(llm_with_tools, messages, prefix=prefix)
            else:
                raise

        elapsed = time.perf_counter() - round_start

        resp_len = len(ensure_str_content(response.content))
        logger.info(
            "%sLLM call round %d completed in %.1fs | response=%d chars | tool_calls=%d",
            prefix, round_num + 1, elapsed, resp_len, len(response.tool_calls or []),
        )

        messages.append(response)

        if not response.tool_calls:
            total_elapsed = time.perf_counter() - total_start
            result_text = _strip_think_tags(ensure_str_content(response.content))

            if enable_self_reflection and result_text:
                result_text = _self_reflect(
                    llm=reflection_llm or llm,
                    original_output=result_text,
                    system_prompt=system_prompt,
                    agent_name=agent_name,
                )

            _record_metric(agent_name or "unknown", {
                "execution_time_seconds": total_elapsed,
                "llm_calls": round_num + 1,
                "tool_calls": tool_call_count,
                "response_chars": len(result_text),
                "self_reflection_applied": enable_self_reflection,
                "model": model_name,
                "timestamp": time.time(),
            })

            result_text = _maybe_truncate_local_response(llm, result_text, prefix)

            logger.info(
                "%sLLM invoke DONE in %.1fs (total) | response=%d chars",
                prefix, total_elapsed, len(result_text),
            )
            return result_text

        tool_map = {t.name: t for t in (tools or [])}
        for tc in response.tool_calls:
            tool_name = tc["name"]
            tool_args = tc["args"]
            tool_start = time.perf_counter()
            tool_call_count += 1
            logger.info("%s  Tool call: %s(%s)", prefix, tool_name, list(tool_args.keys()))

            if tool_name in tool_map:
                try:
                    result = tool_map[tool_name].invoke(tool_args)
                    tool_elapsed = time.perf_counter() - tool_start
                    result_str = str(result)
                    logger.info(
                        "%s  Tool %s returned %d chars in %.1fs",
                        prefix, tool_name, len(result_str), tool_elapsed,
                    )
                except Exception as exc:
                    result = f"Error executing {tool_name}: {exc}"
                    logger.warning("%s  Tool %s FAILED: %s", prefix, tool_name, exc)
            else:
                result = f"Tool '{tool_name}' not available"
                logger.warning("%s  Tool %s not found in tool_map", prefix, tool_name)

            messages.append(ToolMessage(content=str(result), tool_call_id=tc["id"]))

    logger.info("%sMax tool rounds exhausted, making final LLM call (tools unbound)...", prefix)
    messages.append(HumanMessage(
        content="You have gathered enough context from the tools above. "
                "Now produce your COMPLETE final analysis as structured JSON. "
                "Do NOT call any more tools — respond with your full output."
    ))
    final_start = time.perf_counter()
    final = _llm_invoke_with_retry(llm, messages, prefix=prefix)
    total_elapsed = time.perf_counter() - total_start

    result_text = _strip_think_tags(ensure_str_content(final.content))
    result_text = _maybe_truncate_local_response(llm, result_text, prefix)

    _record_metric(agent_name or "unknown", {
        "execution_time_seconds": total_elapsed,
        "llm_calls": max_tool_rounds + 2,
        "tool_calls": tool_call_count,
        "response_chars": len(result_text),
        "self_reflection_applied": False,
        "max_rounds_exhausted": True,
        "model": model_name,
        "timestamp": time.time(),
    })

    logger.info(
        "%sLLM invoke DONE (max rounds) in %.1fs total | response=%d chars",
        prefix, total_elapsed, len(result_text),
    )
    return result_text
