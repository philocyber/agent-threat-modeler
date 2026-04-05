"""Base utilities para agentes — prompt building, tool running, response parsing."""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from typing import TYPE_CHECKING, Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
    before_sleep_log,
)

from pydantic import BaseModel as PydanticBaseModel, ValidationError

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel
    from langchain_core.tools import BaseTool

logger = logging.getLogger(__name__)


def ensure_str_content(content: str | list | None) -> str:
    """Extract text from an LLM response's content field.

    ChatAnthropic returns content as a list of typed blocks
    (e.g. [{"type": "text", "text": "..."}, ...]) while Ollama/OpenAI
    return a plain string.  This normalizes both to a single string.
    """
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))
            elif isinstance(block, str):
                parts.append(block)
        return "\n".join(parts)
    return str(content)


# Type alias for structured output model parameter
_StructuredModel = type[PydanticBaseModel] | None

# Models known to NOT support Ollama's tool-calling API (reasoning models, etc.)
_MODELS_WITHOUT_TOOL_SUPPORT: set[str] = {
    "deepseek-r1", "deepseek-r1:1.5b", "deepseek-r1:7b", "deepseek-r1:8b",
    "deepseek-r1:14b", "deepseek-r1:32b", "deepseek-r1:70b",
    "deepseek-r1:671b",
}


# ---------------------------------------------------------------------------
# Quality Metrics — collected per-agent invocation
# ---------------------------------------------------------------------------

_agent_metrics: dict[str, list[dict]] = {}
_metrics_lock = threading.Lock()


def get_agent_metrics() -> dict[str, list[dict]]:
    """Return all collected agent quality metrics."""
    with _metrics_lock:
        return dict(_agent_metrics)


def clear_agent_metrics() -> None:
    """Reset agent metrics (e.g., at the start of a new analysis)."""
    with _metrics_lock:
        _agent_metrics.clear()


def _record_metric(agent_name: str, metric: dict) -> None:
    """Record a quality metric for an agent."""
    with _metrics_lock:
        _agent_metrics.setdefault(agent_name, []).append(metric)


def _strip_think_tags(text: str | list) -> str:
    """Strip <think>...</think> blocks from qwen3/DeepSeek reasoning models.

    Handles three cases:
    1. Complete pairs: <think>...</think>
    2. Orphaned closing tag: content...</think>  (qwen3 chat template puts
       <think> in the assistant turn prefix, so the API response starts
       mid-think-block with only </think> visible)
    3. Orphaned opening tag: <think>... (model was cut off before closing)
    """
    if isinstance(text, list):
        parts = []
        for block in text:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))
            elif isinstance(block, str):
                parts.append(block)
        text = "\n".join(parts)
    if not isinstance(text, str):
        text = str(text)
    # 1. Strip complete <think>...</think> pairs
    cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    # 2. Strip orphaned </think> and everything before it (reasoning remnants)
    cleaned = re.sub(r"^.*?</think>", "", cleaned, flags=re.DOTALL)
    # 3. Strip orphaned <think> at the end (model cut off before closing)
    cleaned = re.sub(r"<think>.*$", "", cleaned, flags=re.DOTALL)
    cleaned = cleaned.strip()
    return cleaned if cleaned else text


# ---------------------------------------------------------------------------
# Self-Reflection — critique-then-revise for quality improvement
# ---------------------------------------------------------------------------

_REFLECTION_PROMPT = """\
You are a quality reviewer for security threat analysis.

Review the following agent output and identify specific issues:
1. Are threat descriptions vague or missing concrete details?
2. Are DREAD scores inconsistent (e.g., high damage but low priority)?
3. Are mitigations generic instead of actionable?
4. Are evidence_sources missing or too vague?
5. Are confidence_scores unreasonably high or not calibrated?
6. Is the JSON structure valid and complete?

Output a brief critique (max 200 words) listing ONLY concrete issues found.
If the output is good, say "NO_ISSUES_FOUND".
"""

_REVISION_PROMPT = """\
You are revising your previous output based on quality feedback.

ORIGINAL SYSTEM PROMPT (for context on what was expected):
{system_prompt_excerpt}

YOUR ORIGINAL OUTPUT:
{original_output}

CRITIQUE:
{critique}

Produce a REVISED version of your original output that addresses the critique.
Maintain the EXACT same JSON structure. Only improve the content quality.
If the critique says NO_ISSUES_FOUND, return the original output unchanged.

Output ONLY the revised JSON — no explanations.
"""


def _self_reflect(
    llm: BaseChatModel,
    original_output: str,
    system_prompt: str,
    agent_name: str = "",
) -> str:
    """Perform one round of self-reflection: critique → revise.

    This adds ~1 extra LLM call but significantly improves output quality
    by catching vague descriptions, inconsistent scores, and missing fields.
    """
    prefix = f"[{agent_name}] " if agent_name else ""
    logger.info("%sSelf-reflection: starting critique phase...", prefix)

    t0 = time.perf_counter()

    # Truncate for reflection prompt to stay within context
    excerpt = original_output[:20000]
    system_excerpt = system_prompt[:6000]

    try:
        # Phase 1: Critique
        critique_messages = [
            SystemMessage(content=_REFLECTION_PROMPT),
            HumanMessage(content=f"Agent output to review:\n\n{excerpt}"),
        ]
        critique_response = llm.invoke(critique_messages)
        critique = _strip_think_tags(ensure_str_content(critique_response.content))

        logger.info("%sSelf-reflection critique (%d chars): %s", prefix, len(critique), critique[:200])

        # If no issues, return original
        if "NO_ISSUES_FOUND" in critique.upper():
            logger.info("%sSelf-reflection: no issues found, keeping original", prefix)
            return original_output

        # Phase 2: Revise
        revision_prompt = _REVISION_PROMPT.format(
            system_prompt_excerpt=system_excerpt,
            original_output=excerpt,
            critique=critique,
        )
        revision_messages = [
            SystemMessage(content="You are a security expert revising your own analysis output."),
            HumanMessage(content=revision_prompt),
        ]
        revision_response = llm.invoke(revision_messages)
        revised = _strip_think_tags(ensure_str_content(revision_response.content))

        elapsed = time.perf_counter() - t0
        logger.info(
            "%sSelf-reflection DONE in %.1fs | revised output=%d chars",
            prefix, elapsed, len(revised),
        )

        # Only use revised if it's valid (longer than a minimal threshold)
        if len(revised) > len(original_output) * 0.3:
            return revised
        else:
            logger.warning("%sSelf-reflection: revised output too short, keeping original", prefix)
            return original_output

    except Exception as exc:
        logger.warning("%sSelf-reflection FAILED: %s -- keeping original output", prefix, exc)
        return original_output


def build_messages(
    system_prompt: str,
    human_prompt: str,
) -> list:
    """Construye la lista de mensajes para invocar un LLM."""
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

    # Build a concise search query from the prompt (strip JSON/code blocks)
    query_text = re.sub(r'```[\s\S]*?```', '', human_prompt)
    query_text = re.sub(r'\{[\s\S]{50,}?\}', '', query_text)  # strip large JSON
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

        # Budget check: stop adding RAG if prompt is already near the limit
        if prompt_budget_chars:
            current_total = len(human_prompt) + accumulated_rag_chars + 120  # header overhead
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

# Exceptions that are worth retrying (connection issues, timeouts, rate limits)
_RETRYABLE_ERRORS: tuple[type[Exception], ...] = (
    ConnectionError,
    TimeoutError,
    OSError,       # covers socket/network errors
)

# Dynamically add provider-specific retryable errors when available
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
        return True  # ConnectionError, TimeoutError, OSError — always retry
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


# Safety cap for local LLM responses to prevent OOM from degenerate outputs.
# With Qwen 3.5 models (num_predict up to 16384 ≈ 57K chars), we need generous room.
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
    # Local / Ollama — compute from num_ctx minus num_predict to get actual prompt budget
    num_ctx = getattr(llm, "num_ctx", None)
    if num_ctx and isinstance(num_ctx, int):
        num_predict = getattr(llm, "num_predict", None)
        if num_predict and isinstance(num_predict, int):
            # Precise: prompt budget = (context - reserved_for_generation) * chars_per_token
            return int((num_ctx - num_predict) * 3.5)
        # Fallback: keep 70% for prompt
        return int(num_ctx * 3.5 * 0.70)
    return None


def _estimate_cloud_prompt_limit(llm: BaseChatModel) -> int | None:
    """Return max human_prompt chars for cloud LLMs, or None for local/unlimited."""
    cls_name = type(llm).__name__
    if cls_name == "ChatAnthropic":
        return 80_000   # ~20K tokens — fits tier-1 30K/min with room for system prompt
    if cls_name in ("ChatOpenAI", "AzureChatOpenAI"):
        return 400_000  # ~100K tokens — GPT-4 has high limits
    if cls_name == "ChatGoogleGenerativeAI":
        return 200_000
    return None  # Ollama / local — no limit


def _maybe_truncate_local_response(llm: BaseChatModel, text: str, prefix: str = "") -> str:
    """Truncate oversized responses from local (Ollama) models to prevent OOM.

    Attempts to preserve valid JSON by extracting it from the full response
    before falling back to a naive character cut.  When the response contains
    huge Mermaid diagrams embedded in JSON, tries to shrink them while keeping
    the threats/data arrays intact.
    """
    if _estimate_cloud_prompt_limit(llm) is not None:
        return text  # cloud providers handle their own limits
    if len(text) <= _MAX_LOCAL_RESPONSE_CHARS:
        return text

    logger.warning(
        "%sLocal LLM response oversized: %d chars (cap=%d). Attempting smart truncation.",
        prefix, len(text), _MAX_LOCAL_RESPONSE_CHARS,
    )

    # Strategy 1: Try to extract valid JSON from the FULL response.
    try:
        parsed = extract_json_from_response(text)
        if parsed:
            # Strategy 1a: Shrink Mermaid diagrams inside tree_mermaid fields
            if isinstance(parsed, dict):
                for tree in parsed.get("attack_trees", []):
                    mermaid = tree.get("tree_mermaid", "")
                    if isinstance(mermaid, str) and len(mermaid) > 3000:
                        # Keep first 3000 chars of Mermaid + truncation note
                        tree["tree_mermaid"] = mermaid[:3000] + "\\n... [truncated]"

            compact = json.dumps(parsed, ensure_ascii=False, separators=(',', ':'))
            if len(compact) <= _MAX_LOCAL_RESPONSE_CHARS:
                logger.info(
                    "%sExtracted valid JSON and re-serialized: %d -> %d chars",
                    prefix, len(text), len(compact),
                )
                return compact
            # JSON valid but still too big — try with indent for readability
            readable = json.dumps(parsed, ensure_ascii=False, indent=2)
            if len(readable) <= _MAX_LOCAL_RESPONSE_CHARS:
                return readable
            # Still too big — return compact anyway (better than naive truncation)
            logger.info(
                "%sJSON re-serialized still large (%d chars) but preserving structure",
                prefix, len(compact),
            )
            return compact
    except Exception:
        pass

    # Strategy 2: Naive truncation as last resort.
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
    """Invoca un agente LLM con tool calling iterativo.

    Si el agente tiene tools, ejecuta un loop:
    1. Llamar al LLM
    2. Si pide tool calls → ejecutarlos y re-invocar
    3. Repetir hasta que no pida más tools o max_tool_rounds

    If enable_self_reflection=True, after the main response the agent
    performs a critique-then-revise cycle for higher quality output.

    Returns:
        El texto de la respuesta final del agente.
    """
    # Extract model name for logging
    model_name = getattr(llm, "model", getattr(llm, "model_name", "unknown"))
    prefix = f"[{agent_name}] " if agent_name else ""

    # ── Prompt truncation for cloud providers ────────────────────────
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

    # ── Check if model supports tool-calling API ──────────────────
    model_base = model_name.split(":")[0] if model_name else ""
    model_lacks_tools = any(
        model_name == m or model_base == m.split(":")[0]
        for m in _MODELS_WITHOUT_TOOL_SUPPORT
    )

    # Pre-invoke tools when: model lacks tool support, reasoning is disabled,
    # or caller explicitly requests it (e.g. Synthesizer wants deep model quality
    # without iterative tool-calling overhead).
    _reasoning_disabled = getattr(llm, "reasoning", None) is False
    _should_pre_invoke = model_lacks_tools or _reasoning_disabled or pre_invoke_tools

    if tools and _should_pre_invoke:
        logger.info(
            "%sPre-invoking RAG tools (model=%s, reasoning_off=%s). "
            "Embedding results in prompt to preserve format=json.",
            prefix, model_name, _reasoning_disabled,
        )
        # Calculate prompt budget from context window size
        prompt_budget = _estimate_prompt_budget(llm)
        human_prompt = _invoke_tools_into_prompt(
            tools, human_prompt, agent_name=agent_name,
            prompt_budget_chars=prompt_budget,
        )
        tools = None  # proceed without binding

    # ── Strip format="json" when using tools (they conflict in Ollama) ──
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
                    llm_for_tools = llm  # last resort, keep as-is

    messages = build_messages(system_prompt, human_prompt)

    if tools:
        try:
            llm_with_tools = llm_for_tools.bind_tools(tools)
        except Exception as bind_exc:
            # Fallback: if bind_tools itself fails, pre-invoke tools
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
    _tools_fallback_done = False  # track if we already fell back

    for round_num in range(max_tool_rounds + 1):
        round_start = time.perf_counter()
        logger.info("%sLLM call round %d/%d starting...", prefix, round_num + 1, max_tool_rounds + 1)

        try:
            response: AIMessage = _llm_invoke_with_retry(llm_with_tools, messages, prefix=prefix)
        except Exception as invoke_exc:
            # Runtime fallback: model rejected tool-calling at API level
            exc_msg = str(invoke_exc).lower()
            if "does not support tools" in exc_msg or "status code: 400" in exc_msg:
                if _tools_fallback_done:
                    raise  # already tried fallback once
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
                llm_with_tools = llm  # unbind tools
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

        # Si no hay tool calls, terminamos
        if not response.tool_calls:
            total_elapsed = time.perf_counter() - total_start
            result_text = _strip_think_tags(ensure_str_content(response.content))

            # ── Self-Reflection Step ──
            if enable_self_reflection and result_text:
                result_text = _self_reflect(
                    llm=reflection_llm or llm,
                    original_output=result_text,
                    system_prompt=system_prompt,
                    agent_name=agent_name,
                )

            # Record quality metrics
            _record_metric(agent_name or "unknown", {
                "execution_time_seconds": total_elapsed,
                "llm_calls": round_num + 1,
                "tool_calls": tool_call_count,
                "response_chars": len(result_text),
                "self_reflection_applied": enable_self_reflection,
                "model": model_name,
                "timestamp": time.time(),
            })

            # Guard against oversized local model responses
            result_text = _maybe_truncate_local_response(llm, result_text, prefix)

            logger.info(
                "%sLLM invoke DONE in %.1fs (total) | response=%d chars",
                prefix, total_elapsed, len(result_text),
            )
            return result_text

        # Ejecutar tool calls
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
                    result = f"Error ejecutando {tool_name}: {exc}"
                    logger.warning("%s  Tool %s FAILED: %s", prefix, tool_name, exc)
            else:
                result = f"Tool '{tool_name}' no disponible"
                logger.warning("%s  Tool %s not found in tool_map", prefix, tool_name)

            # Agregar el resultado como ToolMessage
            messages.append(ToolMessage(content=str(result), tool_call_id=tc["id"]))

    # Si agotamos rounds, force the model to produce a final text answer
    # by removing tool bindings and adding a directive.
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

    # Record metrics for exhausted rounds too
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


# ---------------------------------------------------------------------------
# JSON extraction — robust multi-strategy parser
# ---------------------------------------------------------------------------

def _fix_common_json_issues(s: str) -> str:
    """Fix common LLM JSON generation issues.

    Handles trailing commas, JS-style comments, unquoted keys, unquoted
    simple-word values, missing commas between adjacent objects,
    orphaned bare strings inside objects, and ``key: value`` pairs where
    the value is an unquoted identifier (common VLM output like
    ``id: CloudFront``).
    """
    # Remove trailing commas before } or ]
    s = re.sub(r",\s*([}\]])", r"\1", s)
    # Remove JavaScript-style comments
    s = re.sub(r"//[^\n]*", "", s)
    # Remove C-style block comments
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.DOTALL)
    # Remove orphaned bare strings inside objects (LLM hallucination artifacts):
    # "key1": "val1", "orphan string", "key2": "val2"  ->  "key1": "val1", "key2": "val2"
    s = re.sub(r'(?<="),\s*"[^"]{0,200}"\s*(?=,\s*"[^"]*"\s*:)', ',', s)
    # Fix unquoted keys (simple cases): {key: ... or ,key: ...
    s = re.sub(r"(?<=[{,])\s*(\w+)\s*:", r' "\1":', s)
    # Fix unquoted string values: "key": SomeWord  ->  "key": "SomeWord"
    # Only match single-word or dot-separated identifiers (e.g. CloudFront, S3.bucket)
    s = re.sub(
        r'(:\s*)([A-Za-z_][\w.]*)\s*([,}\]\n])',
        lambda m: m.group(1) + '"' + m.group(2) + '"' + m.group(3),
        s,
    )
    # Fix missing comma between adjacent objects: }{ -> },{
    s = re.sub(r"\}\s*\{", "},{", s)
    return s


def _repair_truncated_json(s: str) -> str | None:
    """Attempt to repair JSON truncated by LLM token limits.

    Walks through the string tracking brace depth and finds the last
    complete ``}`` at any depth above 0. Truncates there and closes
    all remaining open brackets/braces.
    """
    last_good = -1
    depth = 0
    in_string = False
    escape = False
    for i, ch in enumerate(s):
        if escape:
            escape = False
            continue
        if ch == '\\' and in_string:
            escape = True
            continue
        if ch == '"' and not escape:
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth >= 1:
                last_good = i
    if last_good > 0:
        truncated = s[:last_good + 1]
        open_brackets = truncated.count('[') - truncated.count(']')
        open_braces = truncated.count('{') - truncated.count('}')
        repair = truncated + (']' * max(0, open_brackets)) + ('}' * max(0, open_braces))
        return repair
    return None


def _try_parse(s: str) -> dict | list | None:
    """Try parsing a string as JSON, with and without fixes."""
    for label, candidate_str in [("raw", s), ("fixed", _fix_common_json_issues(s))]:
        try:
            return json.loads(candidate_str)
        except json.JSONDecodeError as e:
            logger.debug("[JSON parse] %s attempt failed: %s (pos %d)", label, e.msg, e.pos)
    # Try repairing truncated JSON
    repaired = _repair_truncated_json(s)
    if repaired:
        for label, candidate_str in [("repaired", repaired), ("repaired+fixed", _fix_common_json_issues(repaired))]:
            try:
                return json.loads(candidate_str)
            except json.JSONDecodeError as e:
                logger.debug("[JSON parse] %s attempt failed: %s (pos %d)", label, e.msg, e.pos)
    # Last resort: use json-repair library for broken keys/values
    try:
        from json_repair import repair_json
        fixed = repair_json(s, return_objects=True)
        if isinstance(fixed, (dict, list)):
            logger.info("[JSON parse] json-repair library succeeded")
            return fixed
    except Exception as exc:
        logger.debug("[JSON parse] json-repair failed: %s", exc)
    return None


def _extract_individual_json_objects(text: str) -> list[dict]:
    """Last-resort extraction: find individual JSON objects in malformed text.

    When the outer JSON structure is broken (truncated, malformed keys, etc.),
    this finds all complete {...} blocks that look like threat entries.
    """
    threat_keys = {"id", "title", "description", "name", "component",
                   "leaf_action", "stride_category", "attack_scenario",
                   "severity", "impact", "mitigation"}
    results: list[dict] = []
    depth = 0
    in_string = False
    escape = False
    obj_start = -1

    for i, ch in enumerate(text):
        if escape:
            escape = False
            continue
        if ch == '\\' and in_string:
            escape = True
            continue
        if ch == '"' and not escape:
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == '{':
            if depth == 2:
                obj_start = i
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 2 and obj_start >= 0:
                candidate = text[obj_start:i + 1]
                try:
                    obj = json.loads(candidate)
                    if isinstance(obj, dict) and (set(obj.keys()) & threat_keys):
                        results.append(obj)
                except json.JSONDecodeError:
                    fixed = _fix_common_json_issues(candidate)
                    try:
                        obj = json.loads(fixed)
                        if isinstance(obj, dict) and (set(obj.keys()) & threat_keys):
                            results.append(obj)
                    except json.JSONDecodeError:
                        pass
                obj_start = -1

    # If depth=2 didn't work (flat structure), try depth=1
    if not results:
        depth = 0
        in_string = False
        escape = False
        obj_start = -1
        for i, ch in enumerate(text):
            if escape:
                escape = False
                continue
            if ch == '\\' and in_string:
                escape = True
                continue
            if ch == '"' and not escape:
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == '{':
                if depth == 1:
                    obj_start = i
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 1 and obj_start >= 0:
                    candidate = text[obj_start:i + 1]
                    try:
                        obj = json.loads(candidate)
                        if isinstance(obj, dict) and (set(obj.keys()) & threat_keys):
                            results.append(obj)
                    except json.JSONDecodeError:
                        fixed = _fix_common_json_issues(candidate)
                        try:
                            obj = json.loads(fixed)
                            if isinstance(obj, dict) and (set(obj.keys()) & threat_keys):
                                results.append(obj)
                        except json.JSONDecodeError:
                            pass
                    obj_start = -1

    return results


def extract_json_from_response(text: str | list) -> dict | list | None:
    """Robust multi-strategy JSON extraction from LLM responses.

    Strategies (in order):
    1. Strip <think> tags from reasoning models
    2. Find ```json code blocks
    3. Try parsing entire cleaned text
    4. Extract first { } or [ ] balanced block
    5. Fix common JSON issues and retry all above
    """
    if isinstance(text, list):
        parts = []
        for block in text:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))
            elif isinstance(block, str):
                parts.append(block)
        text = "\n".join(parts)
    if not isinstance(text, str):
        text = str(text) if text else ""
    if not text or not text.strip():
        logger.warning("Respuesta vacía del agente")
        return None

    # Strip <think>...</think> blocks (handles paired, orphaned closing, and orphaned opening tags)
    cleaned = _strip_think_tags(text)
    if not cleaned:
        cleaned = text

    # Try both cleaned and original text
    for candidate in [cleaned, text]:
        # Strategy 1: Find ```json ... ``` GREEDY code blocks (largest possible)
        # Use greedy .* to capture the maximum content between opening and last ```
        match_greedy = re.search(r"```(?:json)?\s*\n?(.*)\n?\s*```", candidate, re.DOTALL)
        if match_greedy:
            result = _try_parse(match_greedy.group(1).strip())
            if result is not None:
                return result

        # Strategy 1b: Non-greedy fallback (for multiple code blocks)
        match = re.search(r"```(?:json)?\s*\n?(.*?)\n?\s*```", candidate, re.DOTALL)
        if match:
            result = _try_parse(match.group(1).strip())
            if result is not None:
                return result

        # Strategy 1c: Unclosed/truncated code block — extract balanced braces
        # from everything after the opening ```json marker
        code_start = re.search(r"```(?:json)?\s*\n", candidate)
        if code_start:
            block = candidate[code_start.end():].rstrip("`").strip()
            for sc, ec in [("{", "}"), ("[", "]")]:
                si = block.find(sc)
                ei = block.rfind(ec)
                if si != -1 and ei != -1 and ei > si:
                    result = _try_parse(block[si : ei + 1])
                    if result is not None:
                        return result

        # Strategy 2: Try parsing entire text
        result = _try_parse(candidate.strip())
        if result is not None:
            return result

        # Strategy 3: Find balanced { } or [ ] blocks in full text
        for start_char, end_char in [("{", "}"), ("[", "]")]:
            start = candidate.find(start_char)
            end = candidate.rfind(end_char)
            if start != -1 and end != -1 and end > start:
                result = _try_parse(candidate[start : end + 1])
                if result is not None:
                    return result

    logger.warning("No se pudo extraer JSON de la respuesta del agente")
    logger.info("Respuesta completa del agente:\n%s", cleaned if cleaned else text)
    return None


def parse_structured_response(
    text: str,
    model: type[PydanticBaseModel],
    *,
    many: bool = False,
) -> PydanticBaseModel | list[PydanticBaseModel] | None:
    """Parse LLM response into Pydantic model(s) with fallback chain (I03).

    Fallback chain:
    1. Extract JSON via ``extract_json_from_response``
    2. Validate extracted JSON against the Pydantic *model*
    3. If ``many=True``, expect a list of items; each item is validated individually

    Returns a validated Pydantic model instance (or list if *many*), or ``None``
    on failure.  Invalid items in a list are silently skipped (logged).
    """
    raw = extract_json_from_response(text)
    if raw is None:
        return None

    try:
        if many:
            items_raw: list[dict] = []
            if isinstance(raw, list):
                items_raw = raw
            elif isinstance(raw, dict):
                # Try common wrapper keys
                for key in ("threats", "items", "results", "data"):
                    if key in raw and isinstance(raw[key], list):
                        items_raw = raw[key]
                        break
                else:
                    items_raw = [raw]

            validated: list[PydanticBaseModel] = []
            for idx, item in enumerate(items_raw):
                try:
                    validated.append(model.model_validate(item))
                except ValidationError as ve:
                    logger.warning("Structured parse: item %d failed validation: %s", idx, ve)
            return validated if validated else None

        else:
            if isinstance(raw, dict):
                return model.model_validate(raw)
            elif isinstance(raw, list) and raw:
                return model.model_validate(raw[0])
            return None

    except ValidationError as ve:
        logger.warning("Structured parse failed for %s: %s", model.__name__, ve)
        return None


# ---------------------------------------------------------------------------
# Generic threat-list finder for flexible JSON structures
# ---------------------------------------------------------------------------

_COMMON_THREAT_KEYS = [
    "threats", "threat_model", "threat_assessments", "identified_threats",
    "threat_analysis", "findings", "vulnerabilities", "attack_scenarios",
    "assessments", "results", "analysis",
]

_THREAT_DICT_KEYS = {
    "id", "title", "description", "threat", "severity", "component",
    "leaf_action", "stride_category", "impact", "mitigation",
    "name", "category", "attack_path", "confidence_score",
}


def _looks_like_threat_list(lst: list) -> bool:
    """Heuristic: list of dicts with at least one threat-like key."""
    if not lst or not isinstance(lst[0], dict):
        return False
    sample_keys = set(lst[0].keys())
    return bool(sample_keys & _THREAT_DICT_KEYS)


def find_threats_in_json(parsed: dict | None) -> list[dict]:
    """Recursively search a parsed JSON dict for a list of threat-like dicts.

    Handles varying LLM key names (threats, threat_model, findings, etc.)
    and nested structures (e.g. attack_trees[].threats[], threat_analysis.stage_4_threats[]).
    """
    if not isinstance(parsed, dict):
        return []

    # 1. Check known threat key names at this level
    for key in _COMMON_THREAT_KEYS:
        val = parsed.get(key)
        if isinstance(val, list) and _looks_like_threat_list(val):
            return _ensure_descriptions(val)

    # 2. Recurse into known threat key names that are dicts
    for key in _COMMON_THREAT_KEYS:
        val = parsed.get(key)
        if isinstance(val, dict):
            found = find_threats_in_json(val)
            if found:
                return found

    # 3. Look for any list of threat-like dicts under any key
    best: list[dict] = []
    for _key, val in parsed.items():
        if isinstance(val, list) and _looks_like_threat_list(val):
            if len(val) > len(best):
                best = val
        elif isinstance(val, dict):
            found = find_threats_in_json(val)
            if found and len(found) > len(best):
                best = found

    if best:
        return _ensure_descriptions(best)

    # 4. Check for nested arrays (e.g. attack_trees[].threats[])
    for _key, val in parsed.items():
        if isinstance(val, list) and val and isinstance(val[0], dict):
            collected: list[dict] = []
            for item in val:
                if isinstance(item, dict):
                    sub_threats = find_threats_in_json(item)
                    collected.extend(sub_threats)
            if collected:
                return _ensure_descriptions(collected)

    return []


def _ensure_descriptions(threats: list[dict]) -> list[dict]:
    """Guarantee every threat dict has a non-empty 'description' field."""
    _DESC_FALLBACKS = (
        "attack_scenario", "threat", "vulnerability", "scenario",
        "title", "name", "attack_path",
    )
    for t in threats:
        if not t.get("description"):
            for key in _DESC_FALLBACKS:
                val = t.get(key)
                if val and isinstance(val, str) and len(val.strip()) > 10:
                    t["description"] = val.strip()
                    break
    return threats


# ---------------------------------------------------------------------------
# Markdown -> structured threat extraction (fallback for non-JSON responses)
# ---------------------------------------------------------------------------

def extract_threats_from_markdown(text: str, methodology: str = "Unknown") -> list[dict]:
    """Extract threats from a markdown-formatted response.

    Parses markdown sections, looking for numbered lists, headers,
    and DREAD score patterns. This is a fallback when the LLM
    returns markdown instead of JSON.
    """
    if not text:
        return []

    # Strip think tags
    cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    if not cleaned:
        cleaned = text

    threats = []
    threat_counter = 1

    # Try to find numbered threat entries (### 1. Title, #### **1. Title, ### TM-001, etc.)
    sections = re.split(r"(?:^|\n)#{1,6}\s+\*{0,2}\s*(?:\d+\.?\s*|TM-\d+[:\s])", cleaned)

    # Also try splitting by numbered lists: "1. ", "2. ", "**1. " etc.
    if len(sections) <= 1:
        sections = re.split(r"\n(?=\*{0,2}\d+\.\s+\*{0,2})", cleaned)

    # Try splitting by PASTA/Attack Tree style headers:
    # "### **Stage N:", "#### Goal X:", "#### Attack Tree N:", "**Path X:"
    if len(sections) <= 1:
        sections = re.split(
            r"(?:^|\n)(?:#{1,6}\s+\*{0,2}\s*(?:Stage\s+\d+|Goal\s+[A-Z]|Attack\s+Tree\s+\d+|Path\s+[A-Z])[:\s]"
            r"|\*{2}Path\s+[A-Z][:\s]"
            r"|\*{2}Sub-Goal\s+[A-Z]\d+)",
            cleaned,
        )

    # Last resort: split on any H3/H4 heading
    if len(sections) <= 1:
        sections = re.split(r"(?:^|\n)#{3,4}\s+", cleaned)

    _NON_THREAT_PATTERNS = re.compile(
        r"(?i)^(?:\*{0,2})\s*(?:"
        r"evidence|conclusion|referencias|fuentes|references|mitigation\s+mapping"
        r"|summary|resumen|contextual\s+analysis|recommended|bibliography|appendix"
        r"|stage\s+[178]"
        r"|attack\s+tree\s+construction|attacker\s+goals|decomposition"
        r"|descripci[oó]n\s+general|arquitectura\s+del\s+sistema|general\s+description"
        r"|risk\s+assessment|prioritiz|priorizaci"
        r"|an[aá]lisis\s+stride|an[aá]lisis\s+contextual|an[aá]lisis\s+por\s+elemento"
        r"|mapeo\s+de\s+mitigaci|mitigation\s+map"
        r"|fuentes\s+de\s+evidencia|evidence\s+sources"
        r"|the\s+system\s+is\s+a|el\s+sistema\s+es"
        r"|improvements?\s+over|mejoras?\s+sobre"
        r"|principios?\s+de\s+seguridad|estrategias?\s+de\s+mitigaci"
        r"|security\s+principles|mitigation\s+strateg"
        r"|recomendaciones?\s+de\s+seguridad|security\s+recommendation"
        r"|gobernanza|governance|key\s+security"
        r")",
    )

    _THREAT_INDICATOR_TERMS = re.compile(
        r"(?i)\b(?:vulnerab|attack|exploit|inject|breach|unauthori"
        r"|intercept|spoof|tamper|denial|elevat|privilege"
        r"|exfiltrat|bypass|overflow|malicious|compromis"
        r"|forgery|hijack|phishing|credential|brute.force"
        r"|sensitive.data|man.in.the.middle|cross.site"
        r"|remote.code|buffer|replay|session.?hijack|token.?leak"
        r"|escalat|impersonat|poisoning|adversarial|dos\b|ddos"
        r"|inyecci|suplantaci|manipulaci|denegaci|acceso\s+no\s+autoriz"
        r"|robo\s+de|fuga\s+de|secuestro)\b"
    )

    for section in sections[1:] if len(sections) > 1 else []:
        stripped = section.strip()
        if len(stripped) < 40:
            continue
        first_line = stripped.split("\n", 1)[0].strip().lstrip("#* ")
        if _NON_THREAT_PATTERNS.match(first_line):
            continue

        if not _THREAT_INDICATOR_TERMS.search(stripped):
            continue

        if re.search(r"\|\s*-{2,}\s*\|", stripped) and stripped.count("|") > 10:
            continue

        threat = _parse_markdown_threat_section(section, threat_counter, methodology)
        if threat.get("description"):
            threats.append(threat)
            threat_counter += 1

    return threats


def _parse_markdown_threat_section(
    section: str, index: int, methodology: str
) -> dict:
    """Parse a single markdown section into a threat dict."""
    lines = section.strip().split("\n")

    # First non-empty line is usually the title
    title = ""
    for line in lines:
        line = line.strip()
        if line and not line.startswith("---"):
            title = re.sub(r"^\*\*|\*\*$|^#+\s*", "", line).strip()
            break

    # Extract fields by looking for bold labels or key: value patterns
    fields = {}
    field_patterns = {
        "component": r"(?:component|componente|target|asset|elemento)[:\s]*(.+)",
        "stride_category": r"(?:stride|category|categoría)[:\s]*([STRIDE]{1,6}|Spoofing|Tampering|Repudiation|Information|Denial|Elevation)",
        "damage": r"(?:damage|daño|D)[:\s=]*(\d+)",
        "reproducibility": r"(?:reproducibility|reproducibilidad|R)[:\s=]*(\d+)",
        "exploitability": r"(?:exploitability|explotabilidad|E)[:\s=]*(\d+)",
        "affected_users": r"(?:affected.?users?|usuarios|A)[:\s=]*(\d+)",
        "discoverability": r"(?:discoverability|descubribilidad|D)[:\s=]*(\d+)",
        "dread_total": r"(?:dread.?total|total|score|puntaje)[:\s=]*(\d+)",
        "priority": r"(?:priority|prioridad|risk|riesgo)[:\s]*(\w+)",
        "mitigation": r"(?:mitigation|mitigación|control|recomendación)[:\s]*(.+)",
        "impact": r"(?:impact|impacto)[:\s]*(\w+)",
    }

    full_text = "\n".join(lines)
    for field, pattern in field_patterns.items():
        match = re.search(pattern, full_text, re.IGNORECASE)
        if match:
            fields[field] = match.group(1).strip()

    # Map STRIDE text to letter
    stride_map = {
        "spoofing": "S", "tampering": "T", "repudiation": "R",
        "information": "I", "denial": "D", "elevation": "E",
    }
    stride_cat = fields.get("stride_category", "")
    if stride_cat.lower() in stride_map:
        fields["stride_category"] = stride_map[stride_cat.lower()]

    # Parse DREAD numbers
    dread_fields = ["damage", "reproducibility", "exploitability", "affected_users", "discoverability"]
    for f in dread_fields:
        if f in fields:
            try:
                fields[f] = int(fields[f])
            except ValueError:
                fields[f] = 5

    # Compute DREAD total if not explicit
    if "dread_total" not in fields:
        dread_vals = [fields.get(f, 5) for f in dread_fields]
        if all(isinstance(v, int) for v in dread_vals):
            fields["dread_total"] = sum(dread_vals)
        else:
            fields["dread_total"] = 25

    # Map priority from impact if not explicit (calibrated bands: avg-based)
    if "priority" not in fields:
        dread = fields.get("dread_total", 25)
        if isinstance(dread, str):
            dread = int(dread) if dread.isdigit() else 25
        if dread >= 45:
            fields["priority"] = "Critical"
        elif dread >= 35:
            fields["priority"] = "High"
        elif dread >= 20:
            fields["priority"] = "Medium"
        else:
            fields["priority"] = "Low"

    desc_lines = [l.strip() for l in lines if l.strip()
                   and not re.match(r"^(?:\*\*)?(?:component|stride|damage|reproduc|exploit|affect|discover|dread|priority|impact|mitiga|control|risk|categor)", l.strip(), re.IGNORECASE)
                   and not re.match(r"^```|^\|[\s:-]+\|$|^---$", l.strip())]
    body = " ".join(desc_lines).strip()
    body = re.sub(r"\*{1,2}([^*]+)\*{1,2}", r"\1", body)
    body = re.sub(r"`([^`]+)`", r"\1", body)
    body = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", body)
    body = re.sub(r"\s{2,}", " ", body)
    if title and body.startswith(title):
        body = body[len(title):].strip().lstrip(".:- ")
    description = f"{title}: {body}" if title and body else (body or title or full_text[:300])

    return {
        "id": f"TM-{index:03d}",
        "component": fields.get("component", ""),
        "description": description[:500],
        "methodology": methodology,
        "stride_category": fields.get("stride_category", ""),
        "attack_path": "",
        "damage": fields.get("damage", 5),
        "reproducibility": fields.get("reproducibility", 5),
        "exploitability": fields.get("exploitability", 5),
        "affected_users": fields.get("affected_users", 5),
        "discoverability": fields.get("discoverability", 5),
        "dread_total": fields.get("dread_total", 25),
        "priority": fields.get("priority", "Medium"),
        "mitigation": fields.get("mitigation", ""),
        "control_reference": "",
        "effort": "Medium",
        "observations": f"[Parsed from markdown] {methodology}",
        "status": "Open",
        "evidence_sources": [],
        "confidence_score": 0.3,
        "justification": None,
    }
