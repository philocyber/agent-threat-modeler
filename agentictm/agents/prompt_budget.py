"""Centralized prompt budget management for AgenticTM agents.

Replaces ad-hoc character slicing with a priority-based fitting strategy
that adapts to the model's context window and generation budget.

Usage::

    from agentictm.agents.prompt_budget import PromptBudget

    budget = PromptBudget.from_llm(llm, system_prompt_chars=1000)
    fitted = budget.fit(
        sections={"system_desc": desc, "components": comps_json, "raw_input": raw},
        priorities=["system_desc", "components", "raw_input"],
    )
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Approximate chars-per-token ratio for Qwen / Llama-family models.
# Conservative (3.0) to avoid overrunning the context window.
_CHARS_PER_TOKEN = 3.0

# Default context/predict when not explicitly configured
_DEFAULT_NUM_CTX = 32768
_DEFAULT_NUM_PREDICT = 8192

# Small model names — get tighter budgets to avoid overloading KV cache
_SMALL_MODEL_TAGS = ("4b", "3b", "1.7b", "2b")


def _is_small_model(model_name: str) -> bool:
    name = model_name.lower()
    return any(f":{tag}" in name for tag in _SMALL_MODEL_TAGS)


class PromptBudget:
    """Token-aware prompt budget calculator.

    Computes the available input character budget from the model's context
    window minus the generation budget, then provides utilities to fit
    multiple named sections into that budget by priority.
    """

    def __init__(
        self,
        model_name: str = "",
        num_ctx: int | None = None,
        num_predict: int | None = None,
        system_prompt_chars: int = 1000,
    ):
        self.model_name = model_name
        self.num_ctx = num_ctx or _DEFAULT_NUM_CTX
        self.num_predict = num_predict or _DEFAULT_NUM_PREDICT
        self.system_prompt_chars = system_prompt_chars

        self._small = _is_small_model(model_name)
        if self._small:
            self.num_ctx = min(self.num_ctx, 16384)

        total_input_tokens = self.num_ctx - self.num_predict
        total_input_chars = int(total_input_tokens * _CHARS_PER_TOKEN)
        self._available = max(1000, total_input_chars - system_prompt_chars)

    @classmethod
    def from_llm(cls, llm: Any, system_prompt_chars: int = 1000) -> "PromptBudget":
        """Create a PromptBudget from a LangChain LLM instance."""
        model_name = getattr(llm, "model", getattr(llm, "model_name", ""))
        num_ctx = getattr(llm, "num_ctx", None)
        num_predict = getattr(llm, "num_predict", None)
        return cls(
            model_name=model_name,
            num_ctx=num_ctx,
            num_predict=num_predict,
            system_prompt_chars=system_prompt_chars,
        )

    @property
    def available_chars(self) -> int:
        """Max characters available for the human prompt (after system prompt)."""
        return self._available

    @property
    def is_small_model(self) -> bool:
        return self._small

    def fit(
        self,
        sections: dict[str, str],
        priorities: list[str],
    ) -> dict[str, str]:
        """Fit multiple named text sections into the budget by priority.

        Higher-priority sections (earlier in ``priorities``) get their full
        content first.  Lower-priority sections are truncated to fill the
        remaining space.  Sections not in ``priorities`` are included after
        all prioritised sections.

        Returns a dict with the same keys as ``sections`` but with values
        truncated to fit within ``available_chars``.
        """
        remaining = self._available
        result: dict[str, str] = {}

        ordered_keys = list(priorities)
        for k in sections:
            if k not in ordered_keys:
                ordered_keys.append(k)

        for key in ordered_keys:
            text = sections.get(key, "")
            if not text:
                result[key] = ""
                continue

            if len(text) <= remaining:
                result[key] = text
                remaining -= len(text)
            else:
                result[key] = self.truncate(text, remaining)
                remaining = 0

            if remaining <= 0:
                for leftover in ordered_keys:
                    if leftover not in result:
                        result[leftover] = ""
                break

        return result

    def truncate(self, text: str, max_chars: int, strategy: str = "tail") -> str:
        """Truncate text to ``max_chars`` using the specified strategy.

        Strategies:
            ``tail``   — Keep the start, cut the end (default).
            ``middle`` — Keep start + end, cut the middle.
            ``smart``  — Keep structured elements (JSON brackets, headers).
        """
        if len(text) <= max_chars:
            return text
        if max_chars <= 0:
            return ""

        marker = f"\n\n... [truncated from {len(text):,} to {max_chars:,} chars]"
        usable = max(0, max_chars - len(marker))

        if strategy == "middle":
            half = usable // 2
            return text[:half] + marker + text[-half:]
        elif strategy == "smart":
            return self._smart_truncate(text, usable, marker)
        else:
            return text[:usable] + marker

    def _smart_truncate(self, text: str, usable: int, marker: str) -> str:
        """Keep structural elements — try to preserve JSON opening/closing
        brackets and markdown headers."""
        if usable <= 200:
            return text[:usable] + marker

        head_budget = int(usable * 0.7)
        tail_budget = usable - head_budget

        head = text[:head_budget]
        tail = text[-tail_budget:] if tail_budget > 0 else ""

        return head + marker + tail

    def section_budget(self, section_name: str, default_pct: float = 0.25) -> int:
        """Suggest a character budget for a named section.

        Standard allocations (percentage of available budget):
            system_description: 15%
            components:         15%
            data_flows:         15%
            methodology:        25%
            raw_input:          15%
            other:              15%
        """
        allocations = {
            "system_description": 0.15,
            "components": 0.15,
            "data_flows": 0.15,
            "methodology": 0.25,
            "raw_input": 0.15,
            "debate": 0.20,
            "threats": 0.20,
        }
        pct = allocations.get(section_name, default_pct)
        return int(self._available * pct)
