"""Self-reflection utilities — critique-then-revise cycle for quality improvement."""

from __future__ import annotations

import logging
import re
import time
from typing import TYPE_CHECKING

from langchain_core.messages import HumanMessage, SystemMessage

from agentictm.agents._utils import ensure_str_content

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel

logger = logging.getLogger(__name__)


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
    cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    cleaned = re.sub(r"^.*?</think>", "", cleaned, flags=re.DOTALL)
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
    """Perform one round of self-reflection: critique -> revise.

    This adds ~1 extra LLM call but significantly improves output quality
    by catching vague descriptions, inconsistent scores, and missing fields.
    """
    prefix = f"[{agent_name}] " if agent_name else ""
    logger.info("%sSelf-reflection: starting critique phase...", prefix)

    t0 = time.perf_counter()

    excerpt = original_output[:20000]
    system_excerpt = system_prompt[:6000]

    try:
        critique_messages = [
            SystemMessage(content=_REFLECTION_PROMPT),
            HumanMessage(content=f"Agent output to review:\n\n{excerpt}"),
        ]
        critique_response = llm.invoke(critique_messages)
        critique = _strip_think_tags(ensure_str_content(critique_response.content))

        logger.info("%sSelf-reflection critique (%d chars): %s", prefix, len(critique), critique[:200])

        if "NO_ISSUES_FOUND" in critique.upper():
            logger.info("%sSelf-reflection: no issues found, keeping original", prefix)
            return original_output

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

        if len(revised) > len(original_output) * 0.3:
            return revised
        else:
            logger.warning("%sSelf-reflection: revised output too short, keeping original", prefix)
            return original_output

    except Exception as exc:
        logger.warning("%sSelf-reflection FAILED: %s -- keeping original output", prefix, exc)
        return original_output
