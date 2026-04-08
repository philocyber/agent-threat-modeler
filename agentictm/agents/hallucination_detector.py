"""Hallucination Detector — Chain-of-Verification (CoVe) for threat grounding.

Validates each threat against three dimensions:
  1. Architecture grounding: Does the threat reference real components?
  2. Evidence consistency: Are cited sources plausible?
  3. Attack vector plausibility: Is the attack path technically feasible?

Each threat receives a confidence_score (0.0-1.0). Threats below 0.3
are flagged as low_confidence in reports.

Research basis: Chain-of-Verification (CoVe), HalluGuard (arXiv),
hierarchical verification patterns.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from agentictm.state import ThreatModelState

logger = logging.getLogger(__name__)

# Generic/vague terms that indicate a likely hallucinated component
_GENERIC_COMPONENTS = {
    "system", "application", "service", "component", "module",
    "general", "overall", "various", "multiple", "all",
    "n/a", "na", "none", "unknown", "", "the system",
}


def _check_architecture_grounding(
    threat: dict[str, Any],
    known_components: set[str],
) -> float:
    """Check if the threat references components from the parsed architecture.
    
    Returns a score 0.0-1.0 where 1.0 means fully grounded.
    """
    component = (threat.get("component") or "").strip().lower()
    
    if not component or component in _GENERIC_COMPONENTS:
        return 0.2  # Vague component reference
    
    # Exact match
    if component in known_components:
        return 1.0
    
    # Partial match (component name appears within a known component or vice versa)
    for known in known_components:
        if component in known or known in component:
            return 0.8
    
    # Check if any word from the component matches known components
    component_words = set(re.split(r'[\s_\-/]+', component)) - {"", "the", "a", "an"}
    for known in known_components:
        known_words = set(re.split(r'[\s_\-/]+', known))
        if component_words & known_words:
            return 0.6
    
    return 0.3  # Component not found in architecture


def _check_evidence_consistency(threat: dict[str, Any]) -> float:
    """Check if the threat has evidence sources and they are meaningful.
    
    Returns a score 0.0-1.0 where 1.0 means strong evidence.
    """
    evidence = threat.get("evidence_sources", [])
    if not evidence:
        return 0.2  # No evidence at all
    
    valid_sources = 0
    for src in evidence:
        if not isinstance(src, dict):
            continue
        source_name = (src.get("source_name") or "").strip()
        excerpt = (src.get("excerpt") or "").strip()
        
        if source_name and len(source_name) > 3:
            valid_sources += 1
            if excerpt and len(excerpt) > 20:
                valid_sources += 0.5  # Bonus for having a meaningful excerpt
    
    if valid_sources >= 2:
        return 1.0
    elif valid_sources >= 1:
        return 0.7
    elif valid_sources >= 0.5:
        return 0.5
    return 0.3


def _check_attack_plausibility(threat: dict[str, Any]) -> float:
    """Check if the attack path is specific and technically plausible.
    
    Returns a score 0.0-1.0 where 1.0 means highly plausible.
    """
    description = (threat.get("description") or "").strip()
    attack_path = (threat.get("attack_path") or "").strip()
    mitigation = (threat.get("mitigation") or "").strip()
    
    score = 0.3  # Baseline
    
    # Longer, more specific descriptions are more likely grounded
    if len(description) > 100:
        score += 0.2
    elif len(description) > 50:
        score += 0.1
    
    # Having a specific attack path is a strong signal
    if attack_path and len(attack_path) > 30:
        score += 0.2
    
    # Having a specific mitigation suggests the threat is well-understood
    if mitigation and len(mitigation) > 30:
        score += 0.15
    
    # Check for technical specificity indicators
    technical_terms = [
        "exploit", "inject", "bypass", "intercept", "overflow",
        "escalat", "exfiltrat", "tamper", "spoof", "brute",
        "credential", "token", "session", "certificate", "api",
        "endpoint", "payload", "header", "query", "parameter",
    ]
    desc_lower = f"{description} {attack_path}".lower()
    tech_matches = sum(1 for t in technical_terms if t in desc_lower)
    if tech_matches >= 3:
        score += 0.15
    elif tech_matches >= 1:
        score += 0.1
    
    return min(score, 1.0)


def compute_threat_confidence(
    threat: dict[str, Any],
    known_components: set[str],
) -> float:
    """Compute overall confidence score for a single threat.
    
    Weighted combination of three verification dimensions:
    - Architecture grounding: 40%
    - Evidence consistency: 30%
    - Attack plausibility: 30%
    """
    grounding = _check_architecture_grounding(threat, known_components)
    evidence = _check_evidence_consistency(threat)
    plausibility = _check_attack_plausibility(threat)
    
    confidence = (
        grounding * 0.40
        + evidence * 0.30
        + plausibility * 0.30
    )
    return round(confidence, 2)


def run_hallucination_detection(state: ThreatModelState) -> dict:
    """LangGraph-compatible node that scores threat confidence.
    
    Reads: threats_final, components
    Writes: threats_final (with updated confidence_score per threat)
    """
    threats = state.get("threats_final", [])
    if not threats:
        logger.info("[HallucinationDetector] No threats to evaluate")
        return {}
    
    # Build set of known component names from parsed architecture
    components = state.get("components", [])
    known_components = set()
    for comp in components:
        name = (comp.get("name") or "").strip().lower()
        if name:
            known_components.add(name)
    
    # Also add data stores and external entities
    for store in state.get("data_stores", []):
        name = (store.get("name") or "").strip().lower()
        if name:
            known_components.add(name)
    for entity in state.get("external_entities", []):
        name = (entity.get("name") or "").strip().lower()
        if name:
            known_components.add(name)
    
    updated_threats = []
    low_confidence_count = 0
    total_confidence = 0.0
    
    for threat in threats:
        confidence = compute_threat_confidence(threat, known_components)
        updated_threat = dict(threat)
        updated_threat["confidence_score"] = confidence
        updated_threats.append(updated_threat)
        total_confidence += confidence
        if confidence < 0.3:
            low_confidence_count += 1
    
    avg_confidence = total_confidence / len(threats) if threats else 0
    
    logger.info(
        "[HallucinationDetector] Scored %d threats: avg_confidence=%.2f, low_confidence=%d (%.0f%%)",
        len(threats), avg_confidence, low_confidence_count,
        (low_confidence_count / len(threats) * 100) if threats else 0,
    )
    
    return {"threats_final": updated_threats}
