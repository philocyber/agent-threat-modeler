"""Agente: PASTA Analyst -- Fase II: Analisis por Metodologia.

Aplica PASTA (Process for Attack Simulation and Threat Analysis):
enfoque risk-centric y business-oriented de 7 etapas que complementa STRIDE
con analisis de objetivos de negocio y simulacion de ataques.
"""

from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING

from agentictm.agents.base import (
    invoke_agent, extract_json_from_response, extract_threats_from_markdown,
    find_threats_in_json, _extract_individual_json_objects,
)
from agentictm.rag.tools import ANALYST_TOOLS
from agentictm.state import ThreatModelState

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
!!! OUTPUT FORMAT: You MUST respond with a SINGLE JSON object. NO markdown, NO headers, NO stage narratives. !!!

You are a PASTA (Process for Attack Simulation and Threat Analysis) expert.
Use PASTA's attacker-centric 7-stage methodology internally to identify threats:
1) Business objectives  2) Technical scope  3) App decomposition
4) Threat analysis  5) Vulnerability analysis  6) Attack simulation  7) Risk assessment

But OUTPUT ONLY the JSON below -- do NOT write stage-by-stage narrative.

AUDIENCE: Developers with NO security training. Write attack_scenario as a story.

Your response must be EXACTLY this JSON structure:
{"methodology":"PASTA","threats":[<6-12 threat objects>],"summary":"<1 paragraph>"}

Each threat object:
{
  "attack_scenario": "3-5 sentences: who attacks, how they enter, what steps they take, what damage results. Name specific components.",
  "target_asset": "the specific component or data store under attack",
  "attack_path": "1. step -> 2. step -> 3. step",
  "likelihood": "High|Medium|Low",
  "business_impact": "High|Medium|Low",
  "risk_level": "Critical|High|Medium|Low",
  "vulnerabilities_exploited": "CWE-XX or CVE-XXXX-XXXXX",
  "reasoning": "2-3 sentences: what design flaw makes this possible",
  "countermeasures": "specific code/config/infra change to prevent this",
  "control_reference": "NIST 800-53, OWASP ASVS, or CIS control ID",
  "evidence_sources": [{"source_type": "rag", "source_name": "source", "excerpt": "quote"}],
  "confidence_score": 0.85
}

RULES:
- Think through all 7 PASTA stages INTERNALLY to find threats
- Output ONLY the JSON object -- no markdown, no stage headers, no explanations outside JSON
- 6-12 threats covering multi-step attacks, lateral movement, and business impact
- Each threat must reference SPECIFIC components from the architecture
- Each evidence_source must cite where the finding comes from

!!! CRITICAL: DO NOT COPY RAG ENTRIES !!!
- RAG results (e.g. TMA-xxxx IDs from threats.csv) are REFERENCE MATERIAL ONLY
- Do NOT copy their IDs, titles, or descriptions into your output
- Perform YOUR OWN original attack scenario analysis for THIS specific system
- Use RAG only to find supporting CVEs/CWEs for YOUR findings
- Generic cloud controls are NOT attack scenarios -- analyze the SPECIFIC architecture
"""


def _build_human_prompt(state: ThreatModelState) -> str:
    components = json.dumps(state.get("components", []), indent=2, ensure_ascii=False)
    data_flows = json.dumps(state.get("data_flows", []), indent=2, ensure_ascii=False)
    trust_boundaries = json.dumps(state.get("trust_boundaries", []), indent=2, ensure_ascii=False)
    external_entities = json.dumps(state.get("external_entities", []), indent=2, ensure_ascii=False)

    components_list = state.get("components", [])
    has_structured = bool(components_list)

    arch_note = ""
    if not has_structured:
        arch_note = (
            "\n\nNOTE: The structured component list is empty. "
            "The System Description above contains the FULL architecture details. "
            "You MUST extract components, data flows and trust boundaries from the description text "
            "and perform a complete PASTA attack simulation on them. "
            "Do NOT return an error or empty result.\n"
        )

    return f"""\
Analyze the following system using PASTA (7 stages).
Think like an ATTACKER: what are the most realistic attack paths?

IMPORTANT: Respond with the JSON object ONLY. Do NOT write markdown or stage descriptions.

## System Description
{state.get("system_description", "Not available")}

## Components
{components}

## Data Flows
{data_flows}

## Trust Boundaries
{trust_boundaries}

## External Entities
{external_entities}

## Scope Notes
{state.get("scope_notes", "No notes")}
{arch_note}
Focus on:
- Multi-step attack scenarios (lateral movement)
- Business impact (not only technical impact)
- Realistic attack paths, not purely theoretical ones
- Use your attacker expertise first, then enrich with RAG tools to validate scenarios against known vulnerability databases (CWE/CVE)

REMINDER: Output a single JSON object with "methodology", "threats" array, and "summary". No markdown.
"""


import re as _re


_STAGE_KEY_PATTERN = _re.compile(
    r"(?i)(?:stage_?\d+.*(?:threat|vulnerab|exploit|attack|scenario|risk))"
    r"|^(?:threats?|threat_analysis|vulnerability_analysis|attack_paths?"
    r"|attack_scenarios?|vulnerabilit|exploit)$"
)

_THREAT_DICT_KEYS = frozenset({
    "description", "attack_scenario", "threat", "vulnerability",
    "attack_path", "target", "target_asset", "component", "mitigation",
})


def _looks_like_threat_list(items: list) -> bool:
    """Return True if a list contains dicts with threat-like keys."""
    if not items:
        return False
    dicts = [it for it in items if isinstance(it, dict)]
    if not dicts:
        return False
    return any(set(d.keys()) & _THREAT_DICT_KEYS for d in dicts[:3])


def _string_to_threat(text: str) -> dict:
    """Convert a free-text string into a minimal PASTA threat dict."""
    title_match = _re.match(
        r"^(?:Attack\s+Path\s+\d+:\s*)?([^:.]+(?:\([^)]+\))?)[:.]\s*(.+)",
        text, _re.DOTALL,
    )
    if title_match:
        title = title_match.group(1).strip()
        desc = title_match.group(2).strip()
    else:
        title = text[:80]
        desc = text
    return {
        "attack_scenario": desc[:500],
        "target_asset": "",
        "description": f"{title}: {desc[:300]}",
        "component": "",
        "methodology": "PASTA",
    }


def _extract_threats_from_stages(parsed: dict) -> list[dict]:
    """Extract threats from PASTA stage-based JSON when model outputs per-stage
    keys instead of the expected ``{"threats": [...]}`` format.

    Uses regex-based key discovery to catch arbitrary stage naming variants
    (e.g. ``stage_2_identify_threats``, ``stage_4_exploit_threats``) and
    recursively unwraps nested dicts up to depth 3.
    """
    collected_dicts: list[dict] = []
    collected_strings: list[str] = []

    def _walk(obj: dict, depth: int = 0) -> None:
        if depth > 3:
            return
        for key, val in obj.items():
            is_stage_key = bool(_STAGE_KEY_PATTERN.match(key))
            if isinstance(val, list) and val:
                if _looks_like_threat_list(val):
                    collected_dicts.extend(d for d in val if isinstance(d, dict))
                elif is_stage_key:
                    for item in val:
                        if isinstance(item, str) and len(item.strip()) > 30:
                            collected_strings.append(item.strip())
            elif isinstance(val, str) and is_stage_key and len(val) > 50:
                collected_strings.append(val)
            elif isinstance(val, dict) and depth < 3:
                _walk(val, depth + 1)

    _walk(parsed)

    if collected_dicts:
        for d in collected_dicts:
            d.setdefault("methodology", "PASTA")
            if not d.get("description"):
                d["description"] = (
                    d.get("attack_scenario") or d.get("threat")
                    or d.get("vulnerability") or d.get("scenario")
                    or d.get("title") or d.get("name")
                    or d.get("attack_path") or ""
                )
        return collected_dicts

    if not collected_strings:
        return []

    results: list[dict] = []
    for text in collected_strings:
        chunks = _re.split(r"(?:\n\d+\.\s+|;\s*(?=[A-Z]))", text)
        for chunk in chunks:
            chunk = chunk.strip()
            if len(chunk) > 30:
                results.append(_string_to_threat(chunk))

    return results


def run_pasta_analyst(
    state: ThreatModelState,
    llm: BaseChatModel,
) -> dict:
    """Nodo de LangGraph: PASTA Analyst."""
    logger.info("[PASTA] Starting analysis...")
    human_prompt = _build_human_prompt(state)
    t0 = time.perf_counter()
    response = invoke_agent(llm, SYSTEM_PROMPT, human_prompt, tools=ANALYST_TOOLS, agent_name="PASTA")
    elapsed = time.perf_counter() - t0

    logger.info("[PASTA] LLM response (%d chars):\n%s", len(response), response)

    parsed = extract_json_from_response(response)
    threats_raw = find_threats_in_json(parsed) if isinstance(parsed, dict) else []

    if not threats_raw and isinstance(parsed, dict):
        stage_threats = _extract_threats_from_stages(parsed)
        if stage_threats:
            logger.info("[PASTA] Extracted %d threats from stage-based JSON response", len(stage_threats))
            threats_raw = stage_threats

    if not threats_raw:
        logger.warning("[PASTA] JSON extraction produced 0 threats. Trying individual object extraction...")
        threats_raw = _extract_individual_json_objects(response)

    if not threats_raw:
        logger.warning("[PASTA] Individual extraction produced 0 threats. Attempting markdown fallback...")
        threats_raw = extract_threats_from_markdown(response, "PASTA")

    report = {
        "methodology": "PASTA",
        "agent": "pasta_analyst",
        "report": response,
        "threats_raw": threats_raw,
    }

    logger.info("[PASTA] Completed in %.1fs: %d attack scenarios", elapsed, len(report["threats_raw"]))
    return {
        "methodology_reports": [report],
    }
