"""Threat Model Diff Engine — compares two threat models and surfaces changes.

Compares two analysis results and produces a structured diff showing:
- New threats (added in the later version)
- Removed threats (present in old, missing in new)
- Modified threats (description changed, score changed)
- Risk delta (overall risk level change)

Usage::

    from agentictm.agents.diff_engine import diff_threat_models

    diff = diff_threat_models(old_threats, new_threats)
    print(f"Added: {len(diff['added'])}, Removed: {len(diff['removed'])}")
"""

from __future__ import annotations

import logging
from difflib import SequenceMatcher
from typing import Any

logger = logging.getLogger(__name__)


def diff_threat_models(
    old_threats: list[dict[str, Any]],
    new_threats: list[dict[str, Any]],
    *,
    similarity_threshold: float = 0.65,
) -> dict[str, Any]:
    """Compare two threat model outputs and produce a structured diff.

    Args:
        old_threats: Threats from the earlier analysis
        new_threats: Threats from the later analysis
        similarity_threshold: Min similarity ratio to consider a match (0.0-1.0)

    Returns:
        Dict with keys: added, removed, modified, unchanged, summary
    """
    # Build a map by threat ID for quick lookup
    old_by_id = {t.get("id", f"old-{i}"): t for i, t in enumerate(old_threats)}
    new_by_id = {t.get("id", f"new-{i}"): t for i, t in enumerate(new_threats)}

    # Phase 1: Match by ID
    matched_old: set[str] = set()
    matched_new: set[str] = set()
    modifications: list[dict[str, Any]] = []
    unchanged: list[dict[str, Any]] = []

    for old_id, old_t in old_by_id.items():
        if old_id in new_by_id:
            new_t = new_by_id[old_id]
            changes = _compare_threats(old_t, new_t)
            if changes:
                modifications.append({
                    "threat_id": old_id,
                    "old": old_t,
                    "new": new_t,
                    "changes": changes,
                })
            else:
                unchanged.append(old_t)
            matched_old.add(old_id)
            matched_new.add(old_id)

    # Phase 2: Match unmatched by description similarity
    unmatched_old = [(k, v) for k, v in old_by_id.items() if k not in matched_old]
    unmatched_new = [(k, v) for k, v in new_by_id.items() if k not in matched_new]

    for old_id, old_t in unmatched_old:
        best_match = None
        best_ratio = 0.0
        for new_id, new_t in unmatched_new:
            if new_id in matched_new:
                continue
            ratio = SequenceMatcher(
                None,
                old_t.get("description", "").lower(),
                new_t.get("description", "").lower(),
            ).ratio()
            if ratio > best_ratio and ratio >= similarity_threshold:
                best_ratio = ratio
                best_match = (new_id, new_t)

        if best_match:
            new_id, new_t = best_match
            changes = _compare_threats(old_t, new_t)
            changes.append({
                "field": "id_remapped",
                "old_value": old_id,
                "new_value": new_id,
                "detail": f"Matched by description similarity ({best_ratio:.0%})",
            })
            modifications.append({
                "threat_id": f"{old_id} → {new_id}",
                "old": old_t,
                "new": new_t,
                "changes": changes,
            })
            matched_old.add(old_id)
            matched_new.add(new_id)

    # Phase 3: Remaining unmatched = added/removed
    added = [v for k, v in new_by_id.items() if k not in matched_new]
    removed = [v for k, v in old_by_id.items() if k not in matched_old]

    # Summary statistics
    old_avg_dread = _avg_dread(old_threats) if old_threats else 0
    new_avg_dread = _avg_dread(new_threats) if new_threats else 0
    risk_delta = new_avg_dread - old_avg_dread

    summary = {
        "old_count": len(old_threats),
        "new_count": len(new_threats),
        "added_count": len(added),
        "removed_count": len(removed),
        "modified_count": len(modifications),
        "unchanged_count": len(unchanged),
        "old_avg_dread": round(old_avg_dread, 1),
        "new_avg_dread": round(new_avg_dread, 1),
        "risk_delta": round(risk_delta, 1),
        "risk_trend": "increased" if risk_delta > 1 else "decreased" if risk_delta < -1 else "stable",
    }

    logger.info(
        "[Diff] Compared %d vs %d threats: +%d -%d ~%d =%d (risk: %s)",
        len(old_threats), len(new_threats),
        len(added), len(removed), len(modifications), len(unchanged),
        summary["risk_trend"],
    )

    return {
        "added": added,
        "removed": removed,
        "modified": modifications,
        "unchanged": unchanged,
        "summary": summary,
    }


def _compare_threats(old: dict[str, Any], new: dict[str, Any]) -> list[dict[str, Any]]:
    """Compare two matched threats and return a list of field changes."""
    changes: list[dict[str, Any]] = []
    compare_fields = [
        ("description", "Description changed"),
        ("mitigation", "Mitigation changed"),
        ("stride_category", "STRIDE category changed"),
        ("priority", "Priority changed"),
        ("status", "Status changed"),
        ("component", "Component changed"),
    ]

    for field, detail in compare_fields:
        old_val = str(old.get(field, "")).strip()
        new_val = str(new.get(field, "")).strip()
        if old_val != new_val and (old_val or new_val):
            changes.append({
                "field": field,
                "old_value": old_val,
                "new_value": new_val,
                "detail": detail,
            })

    # DREAD score changes
    dread_fields = ["damage", "reproducibility", "exploitability", "affected_users", "discoverability", "dread_total"]
    for field in dread_fields:
        old_val = old.get(field, 0)
        new_val = new.get(field, 0)
        if old_val != new_val:
            changes.append({
                "field": field,
                "old_value": old_val,
                "new_value": new_val,
                "detail": f"DREAD {field}: {old_val} → {new_val}",
            })

    return changes


def _avg_dread(threats: list[dict[str, Any]]) -> float:
    """Calculate average DREAD total across threats."""
    totals = [t.get("dread_total", 0) for t in threats if t.get("dread_total")]
    return sum(totals) / len(totals) if totals else 0.0
