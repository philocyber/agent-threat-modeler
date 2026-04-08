"""Shared leaf utilities with no intra-package dependencies.

This module exists to break circular imports: submodules like reflection.py
and llm_invoke.py need ``ensure_str_content``, which base.py re-exports.
Putting it here means no submodule ever needs to import from base.py.
"""

from __future__ import annotations

from pydantic import BaseModel as PydanticBaseModel


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
