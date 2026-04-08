"""Agent base utilities — public API (re-exports from submodules).

This module was decomposed in v2.0.0 for maintainability. Import from here
for backward compatibility, or directly from submodules for explicit deps.
"""

from agentictm.agents._utils import ensure_str_content, _StructuredModel  # noqa: F401


# ---------------------------------------------------------------------------
# Re-exports from submodules — keeps ``from agentictm.agents.base import X``
# working for all existing call sites.
# ---------------------------------------------------------------------------

from agentictm.agents.metrics import (  # noqa: E402
    get_agent_metrics,
    clear_agent_metrics,
    _record_metric,
)

from agentictm.agents.reflection import (  # noqa: E402
    _strip_think_tags,
    _self_reflect,
)

from agentictm.agents.json_extraction import (  # noqa: E402
    extract_json_from_response,
    parse_structured_response,
    find_threats_in_json,
    _ensure_descriptions,
    _fix_common_json_issues,
    _repair_truncated_json,
    _try_parse,
    _extract_individual_json_objects,
    _looks_like_threat_list,
    _COMMON_THREAT_KEYS,
    _THREAT_DICT_KEYS,
)

from agentictm.agents.markdown_extraction import (  # noqa: E402
    extract_threats_from_markdown,
    _parse_markdown_threat_section,
)

from agentictm.agents.llm_invoke import (  # noqa: E402
    invoke_agent,
    build_messages,
    _invoke_tools_into_prompt,
    _MODELS_WITHOUT_TOOL_SUPPORT,
    _RETRYABLE_ERRORS,
    _is_retryable,
    _llm_invoke_with_retry,
    _MAX_LOCAL_RESPONSE_CHARS,
    _estimate_prompt_budget,
    _estimate_cloud_prompt_limit,
    _maybe_truncate_local_response,
)
