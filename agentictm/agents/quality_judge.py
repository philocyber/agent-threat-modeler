"""Quality Judge — Multi-Agent Reflexion (MAR) quality gate for threat models.

Combines deterministic rule-based scoring (``evaluate_threat_model``) with an
LLM-backed quality evaluation (``run_quality_judge``) that acts as a LangGraph
node.  When the quality score falls below the acceptance threshold the graph
can loop back to the synthesizer via ``should_retry_synthesis``.

Usage::

    # Rule-based only (no LLM)
    from agentictm.agents.quality_judge import evaluate_threat_model
    quality_report = evaluate_threat_model(threats, system_description)

    # LangGraph node (LLM-augmented)
    from agentictm.agents.quality_judge import run_quality_judge, should_retry_synthesis
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from agentictm.state import ThreatModelState

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel
    from agentictm.config import AgenticTMConfig

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


# ---------------------------------------------------------------------------
# STRIDE+A categories (A = Agentic threat, ASTRIDE extension)
# ---------------------------------------------------------------------------

_STRIDE_CATEGORIES = frozenset({"S", "T", "R", "I", "D", "E"})
_AGENTIC_CATEGORY = "A"
_AGENTIC_KEYWORDS = frozenset({
    "agent", "agentic", "llm", "ai", "model", "autonomous", "orchestrat",
    "langchain", "langgraph", "tool_use", "function_call", "plugin",
    "copilot", "assistant", "rag", "retrieval", "embedding",
})


def _has_agentic_components(state: ThreatModelState) -> bool:
    """Return True if the system under analysis contains agentic/AI components."""
    components: list[dict[str, Any]] = state.get("components", [])
    description = (state.get("system_description", "") or "").lower()
    for kw in _AGENTIC_KEYWORDS:
        if kw in description:
            return True
    for comp in components:
        comp_text = f"{comp.get('name', '')} {comp.get('description', '')} {comp.get('type', '')}".lower()
        for kw in _AGENTIC_KEYWORDS:
            if kw in comp_text:
                return True
    return False


# ---------------------------------------------------------------------------
# LangGraph Node — run_quality_judge
# ---------------------------------------------------------------------------

_PASS_THRESHOLD = 70
_QUALITY_PROMPT_TEMPLATE = """\
You are a senior security quality reviewer. Evaluate the following threat \
model output and provide constructive feedback.

## System Description
{system_description}

## Threats ({threat_count} total)
{threats_summary}

## Rule-Based Scores
{rule_scores}

## Your Task
Identify specific weaknesses and provide actionable feedback for improving \
the threat model. Focus on:
- Missing attack scenarios for the described architecture
- Threats that are too vague or generic
- DREAD scores that seem miscalibrated for this system
- Gaps in STRIDE category coverage

Respond with a concise paragraph of feedback (max 200 words). Do NOT repeat \
the threats back. Only give constructive criticism.
"""


def run_quality_judge(
    state: ThreatModelState,
    llm: BaseChatModel,
    config: AgenticTMConfig | None = None,
) -> dict:
    """LangGraph node: evaluate synthesized threats and decide whether to retry.

    Combines deterministic criteria checks with an optional LLM feedback pass
    to produce a ``validation_result`` dict that the conditional edge
    ``should_retry_synthesis`` inspects.

    Returns a state-update dict with ``validation_result`` and ``iteration_count``.
    """
    from agentictm.config import AgenticTMConfig

    if config is None:
        config = AgenticTMConfig.load()

    threats: list[dict[str, Any]] = state.get("threats_final", [])
    components: list[dict[str, Any]] = state.get("components", [])
    iteration = state.get("iteration_count", 0) + 1
    min_threats = config.pipeline.min_threats

    logger.info(
        "quality_judge: iteration=%d  threats=%d  components=%d",
        iteration, len(threats), len(components),
    )

    criteria: dict[str, dict[str, Any]] = {}
    issues: list[str] = []

    # ── C1: STRIDE+A coverage ─────────────────────────────────────────────
    expected_cats = set(_STRIDE_CATEGORIES)
    agentic = _has_agentic_components(state)
    if agentic:
        expected_cats.add(_AGENTIC_CATEGORY)

    found_cats: set[str] = set()
    for t in threats:
        cat = (t.get("stride_category") or "").upper().strip()
        if cat in expected_cats:
            found_cats.add(cat)

    stride_score = (len(found_cats) / len(expected_cats) * 100) if expected_cats else 100
    missing = sorted(expected_cats - found_cats)
    criteria["stride_coverage"] = {
        "score": round(stride_score, 1),
        "found": sorted(found_cats),
        "missing": missing,
        "agentic_required": agentic,
    }
    if missing:
        issues.append(f"Missing STRIDE categories: {', '.join(missing)}")

    # ── C2: Evidence rate ─────────────────────────────────────────────────
    evidence_count = sum(
        1 for t in threats
        if t.get("evidence_sources") and len(t["evidence_sources"]) > 0
    )
    evidence_rate = (evidence_count / len(threats) * 100) if threats else 0
    criteria["evidence_rate"] = {
        "score": round(evidence_rate, 1),
        "with_evidence": evidence_count,
        "total": len(threats),
    }
    if evidence_rate < 30:
        issues.append(
            f"Only {evidence_count}/{len(threats)} threats have evidence sources "
            f"({evidence_rate:.0f}%)"
        )

    # ── C3: Component coverage ────────────────────────────────────────────
    component_names = {c.get("name", "").lower().strip() for c in components if c.get("name")}
    covered_components: set[str] = set()
    for t in threats:
        comp = (t.get("component") or "").lower().strip()
        if comp in component_names:
            covered_components.add(comp)

    comp_coverage = (len(covered_components) / len(component_names) * 100) if component_names else 100
    criteria["component_coverage"] = {
        "score": round(comp_coverage, 1),
        "covered": len(covered_components),
        "total": len(component_names),
        "uncovered": sorted(component_names - covered_components)[:10],
    }
    if comp_coverage < 50:
        uncov = sorted(component_names - covered_components)[:5]
        issues.append(
            f"Only {len(covered_components)}/{len(component_names)} components "
            f"covered ({comp_coverage:.0f}%). Missing: {', '.join(uncov)}"
        )

    # ── C4: DREAD distribution ────────────────────────────────────────────
    dread_totals = [t.get("dread_total", 0) for t in threats if t.get("dread_total")]
    if len(dread_totals) >= 2:
        mean_d = sum(dread_totals) / len(dread_totals)
        variance = sum((x - mean_d) ** 2 for x in dread_totals) / len(dread_totals)
        std_dev = math.sqrt(variance)
    else:
        std_dev = 0.0

    dread_dist_ok = std_dev > 1.5
    dread_dist_score = min(100, std_dev / 1.5 * 100) if dread_totals else 0
    criteria["dread_distribution"] = {
        "score": round(dread_dist_score, 1),
        "std_dev": round(std_dev, 2),
        "threshold": 1.5,
        "ok": dread_dist_ok,
        "sample_size": len(dread_totals),
    }
    if not dread_dist_ok and dread_totals:
        issues.append(
            f"DREAD scores are clustered (std dev {std_dev:.2f} < 1.5). "
            f"Scores should show more differentiation."
        )

    # ── C5: Minimum threat count ──────────────────────────────────────────
    count_score = min(100, len(threats) / min_threats * 100) if min_threats > 0 else 100
    criteria["threat_count"] = {
        "score": round(count_score, 1),
        "actual": len(threats),
        "minimum": min_threats,
    }
    if len(threats) < min_threats:
        issues.append(
            f"Only {len(threats)} threats generated (minimum: {min_threats})"
        )

    # ── Composite score (weighted average) ────────────────────────────────
    weights = {
        "stride_coverage": 25,
        "evidence_rate": 15,
        "component_coverage": 25,
        "dread_distribution": 15,
        "threat_count": 20,
    }
    weighted_sum = sum(criteria[k]["score"] * weights[k] for k in weights)
    total_weight = sum(weights.values())
    composite_score = int(round(weighted_sum / total_weight))

    # ── LLM feedback pass (best-effort, non-blocking) ────────────────────
    llm_feedback = ""
    if issues and llm is not None:
        try:
            rule_report = evaluate_threat_model(
                threats,
                state.get("system_description", ""),
                min_threats=min_threats,
            )
            rule_summary = "; ".join(
                f"{c.name}: {c.score:.0%}" for c in rule_report.criteria
            )
            threats_summary = "\n".join(
                f"- [{t.get('id', '?')}] {t.get('stride_category', '?')}: "
                f"{(t.get('description', '') or '')[:120]}"
                for t in threats[:30]
            )
            prompt = _QUALITY_PROMPT_TEMPLATE.format(
                system_description=(state.get("system_description", "") or "")[:2000],
                threat_count=len(threats),
                threats_summary=threats_summary,
                rule_scores=rule_summary,
            )
            response = llm.invoke(prompt)
            llm_feedback = (
                response.content
                if hasattr(response, "content")
                else str(response)
            ).strip()
            logger.info("quality_judge: LLM feedback received (%d chars)", len(llm_feedback))
        except Exception:
            logger.warning("quality_judge: LLM feedback failed, using rule-based only", exc_info=True)

    # ── Build feedback string ─────────────────────────────────────────────
    feedback_parts = []
    if issues:
        feedback_parts.append("Issues found:\n" + "\n".join(f"  • {i}" for i in issues))
    if llm_feedback:
        feedback_parts.append(f"LLM feedback:\n  {llm_feedback}")
    if not feedback_parts:
        feedback_parts.append("All quality criteria passed.")

    passed = composite_score >= _PASS_THRESHOLD
    feedback = "\n\n".join(feedback_parts)

    logger.info(
        "quality_judge: score=%d/100 passed=%s issues=%d iteration=%d",
        composite_score, passed, len(issues), iteration,
    )

    return {
        "validation_result": {
            "passed": passed,
            "score": composite_score,
            "feedback": feedback,
            "criteria": criteria,
        },
        "iteration_count": iteration,
    }


# ---------------------------------------------------------------------------
# Conditional Edge — should_retry_synthesis
# ---------------------------------------------------------------------------

def should_retry_synthesis(
    state: ThreatModelState,
    max_iterations: int = 2,
) -> str:
    """LangGraph conditional edge: retry synthesizer or advance to DREAD validation.

    Returns:
        ``"threat_synthesizer"`` if the quality gate failed and retries remain,
        ``"dread_validator"`` otherwise.
    """
    validation = state.get("validation_result", {})
    iteration = state.get("iteration_count", 0)
    passed = validation.get("passed", True)

    if not passed and iteration < max_iterations:
        logger.info(
            "should_retry_synthesis: RETRY (passed=%s, iteration=%d/%d)",
            passed, iteration, max_iterations,
        )
        return "threat_synthesizer"

    logger.info(
        "should_retry_synthesis: FORWARD to dread_validator (passed=%s, iteration=%d/%d)",
        passed, iteration, max_iterations,
    )
    return "dread_validator"
