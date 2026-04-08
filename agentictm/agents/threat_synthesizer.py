"""Threat Synthesizer — backward-compatible re-export.

Code decomposed into agentictm.agents.synthesis package in v2.0.0.
"""
from agentictm.agents.synthesis.orchestrator import run_threat_synthesizer
from agentictm.agents.synthesis.classification import (
    _STRIDE_TO_CATEGORY, _CATEGORY_PREFIX_MAP, _assign_category_ids,
    _classify_threat_category, _normalize_stride_category, _infer_stride_category,
)
from agentictm.agents.synthesis.deduplication import _deduplicate_threats
from agentictm.agents.synthesis.quality_gates import (
    _apply_quality_gates, _extract_threats_from_reports,
)
from agentictm.agents.synthesis.enrichment import _enrich_weak_threats

__all__ = ["run_threat_synthesizer", "_STRIDE_TO_CATEGORY"]
