"""Quality Judge — LLM-based automatic quality evaluation of threat models.

Post-analysis module that evaluates the quality of a generated threat model
using configurable criteria and produces a structured quality report.

Usage::

    from agentictm.agents.quality_judge import evaluate_threat_model

    quality_report = evaluate_threat_model(threats, system_description)
    print(quality_report.overall_score)  # 0-100
    print(quality_report.verdict)        # "PASS" | "NEEDS_REVIEW" | "FAIL"
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Quality Criteria (rule-based — no LLM needed for these)
# ---------------------------------------------------------------------------

@dataclass
class CriterionResult:
    """Result of evaluating a single quality criterion."""
    name: str
    score: float  # 0.0 – 1.0
    max_score: float  # weight
    details: str = ""
    passed: bool = True


@dataclass
class QualityReport:
    """Complete quality evaluation report for a threat model."""
    overall_score: int = 0  # 0-100
    verdict: str = "NEEDS_REVIEW"  # PASS | NEEDS_REVIEW | FAIL
    criteria: list[CriterionResult] = field(default_factory=list)
    summary: str = ""
    recommendations: list[str] = field(default_factory=list)
    threats_evaluated: int = 0


def evaluate_threat_model(
    threats: list[dict[str, Any]],
    system_description: str = "",
    *,
    min_threats: int = 5,
    max_threats: int = 50,
) -> QualityReport:
    """Evaluate the quality of a threat model using rule-based criteria.

    This is a deterministic evaluation (no LLM calls) that checks:
    - Threat count adequacy
    - DREAD score completeness and consistency
    - Mitigation quality
    - STRIDE coverage
    - Description quality
    - Evidence presence

    Args:
        threats: List of threat dicts from the pipeline
        system_description: Original system description (for coverage check)
        min_threats: Minimum expected threats
        max_threats: Maximum expected threats

    Returns:
        QualityReport with overall score, verdict, and per-criterion details
    """
    report = QualityReport(threats_evaluated=len(threats))
    criteria: list[CriterionResult] = []

    if not threats:
        report.overall_score = 0
        report.verdict = "FAIL"
        report.summary = "No threats were generated."
        report.recommendations = ["Re-run analysis with a more detailed system description."]
        return report

    # ── C1: Threat Count Adequacy (weight: 15) ──
    count = len(threats)
    if min_threats <= count <= max_threats:
        c1_score = 1.0
        c1_detail = f"{count} threats generated (target: {min_threats}-{max_threats})"
    elif count < min_threats:
        c1_score = max(0.2, count / min_threats)
        c1_detail = f"Only {count} threats (minimum: {min_threats}). Analysis may be incomplete."
    else:
        c1_score = max(0.5, 1.0 - (count - max_threats) / max_threats)
        c1_detail = f"{count} threats exceeds maximum {max_threats}. Consider deduplication."
    criteria.append(CriterionResult("threat_count", c1_score, 15, c1_detail, c1_score >= 0.6))

    # ── C2: DREAD Score Completeness (weight: 20) ──
    dread_fields = ["damage", "reproducibility", "exploitability", "affected_users", "discoverability"]
    dread_complete = 0
    dread_valid = 0
    for t in threats:
        has_all = all(t.get(f) is not None and t.get(f) != 0 for f in dread_fields)
        if has_all:
            dread_complete += 1
        # Check score validity (all scores 1-10, total matches)
        scores = [t.get(f, 0) for f in dread_fields]
        if all(1 <= s <= 10 for s in scores if s != 0):
            expected_total = sum(scores)
            actual_total = t.get("dread_total", 0)
            if actual_total == 0 or abs(expected_total - actual_total) <= 2:
                dread_valid += 1

    c2_score = dread_complete / count if count else 0
    c2_detail = f"{dread_complete}/{count} threats have complete DREAD scores"
    criteria.append(CriterionResult("dread_completeness", c2_score, 20, c2_detail, c2_score >= 0.7))

    # ── C3: DREAD Score Consistency (weight: 10) ──
    c3_score = dread_valid / count if count else 0
    c3_detail = f"{dread_valid}/{count} threats have internally consistent DREAD scores"
    criteria.append(CriterionResult("dread_consistency", c3_score, 10, c3_detail, c3_score >= 0.8))

    # ── C4: Mitigation Quality (weight: 20) ──
    has_mitigation = 0
    actionable_mitigations = 0
    min_mitigation_length = 20  # characters
    for t in threats:
        mit = t.get("mitigation", "").strip()
        if mit:
            has_mitigation += 1
            # Check if mitigation is actionable (not just "see X" or "implement Y")
            if len(mit) >= min_mitigation_length:
                actionable_mitigations += 1

    c4_score = (has_mitigation / count * 0.4 + actionable_mitigations / count * 0.6) if count else 0
    c4_detail = f"{has_mitigation}/{count} have mitigations, {actionable_mitigations}/{count} are actionable (>={min_mitigation_length} chars)"
    criteria.append(CriterionResult("mitigation_quality", c4_score, 20, c4_detail, c4_score >= 0.6))

    # ── C5: STRIDE Coverage (weight: 15) ──
    stride_categories = {"S", "T", "R", "I", "D", "E"}
    found_categories = set()
    for t in threats:
        cat = t.get("stride_category", "").upper().strip()
        if cat and cat in stride_categories:
            found_categories.add(cat)

    coverage = len(found_categories) / len(stride_categories) if stride_categories else 0
    c5_score = coverage
    missing = stride_categories - found_categories
    c5_detail = f"Covers {len(found_categories)}/6 STRIDE categories"
    if missing:
        c5_detail += f". Missing: {', '.join(sorted(missing))}"
    criteria.append(CriterionResult("stride_coverage", c5_score, 15, c5_detail, c5_score >= 0.67))

    # ── C6: Description Quality (weight: 10) ──
    good_descriptions = 0
    min_desc_length = 30
    for t in threats:
        desc = t.get("description", "").strip()
        if len(desc) >= min_desc_length:
            good_descriptions += 1

    c6_score = good_descriptions / count if count else 0
    c6_detail = f"{good_descriptions}/{count} threats have descriptions >={min_desc_length} chars"
    criteria.append(CriterionResult("description_quality", c6_score, 10, c6_detail, c6_score >= 0.8))

    # ── C7: Evidence Presence (weight: 10) ──
    has_evidence = 0
    for t in threats:
        sources = t.get("evidence_sources", [])
        if sources and len(sources) > 0:
            has_evidence += 1

    c7_score = has_evidence / count if count else 0
    c7_detail = f"{has_evidence}/{count} threats have evidence sources"
    criteria.append(CriterionResult("evidence_presence", c7_score, 10, c7_detail, c7_score >= 0.3))

    # ── Calculate Overall Score ──
    total_weight = sum(c.max_score for c in criteria)
    weighted_sum = sum(c.score * c.max_score for c in criteria)
    overall = int(round((weighted_sum / total_weight) * 100)) if total_weight > 0 else 0

    report.criteria = criteria
    report.overall_score = overall

    # ── Verdict ──
    if overall >= 75:
        report.verdict = "PASS"
        report.summary = f"Threat model quality is GOOD ({overall}/100). {count} threats with adequate coverage."
    elif overall >= 50:
        report.verdict = "NEEDS_REVIEW"
        report.summary = f"Threat model quality is MODERATE ({overall}/100). Review recommended."
    else:
        report.verdict = "FAIL"
        report.summary = f"Threat model quality is LOW ({overall}/100). Consider re-running analysis."

    # ── Generate Recommendations ──
    recommendations = []
    for c in criteria:
        if not c.passed:
            if c.name == "threat_count":
                recommendations.append(f"Adjust threat count: {c.details}")
            elif c.name == "dread_completeness":
                recommendations.append("Enable DREAD validator to ensure all threats have complete scoring.")
            elif c.name == "dread_consistency":
                recommendations.append("Review DREAD scores for internal consistency (sum should match total).")
            elif c.name == "mitigation_quality":
                recommendations.append("Improve mitigation descriptions — provide actionable, specific remediation steps.")
            elif c.name == "stride_coverage":
                recommendations.append(f"Expand analysis to cover missing STRIDE categories: {c.details.split('Missing: ')[-1] if 'Missing:' in c.details else 'check coverage'}.")
            elif c.name == "description_quality":
                recommendations.append("Improve threat descriptions — provide detailed attack scenarios.")
            elif c.name == "evidence_presence":
                recommendations.append("Enable RAG evidence tracking to provide source citations for threats.")
    report.recommendations = recommendations

    logger.info(
        "Quality evaluation: score=%d/100 verdict=%s threats=%d criteria_passed=%d/%d",
        overall, report.verdict, count,
        sum(1 for c in criteria if c.passed), len(criteria),
    )

    return report
