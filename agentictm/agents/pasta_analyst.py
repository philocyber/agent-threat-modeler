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

from agentictm.agents.base import invoke_agent, extract_json_from_response, extract_threats_from_markdown
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
"""


def _build_human_prompt(state: ThreatModelState) -> str:
    components = json.dumps(state.get("components", []), indent=2, ensure_ascii=False)
    data_flows = json.dumps(state.get("data_flows", []), indent=2, ensure_ascii=False)
    trust_boundaries = json.dumps(state.get("trust_boundaries", []), indent=2, ensure_ascii=False)
    external_entities = json.dumps(state.get("external_entities", []), indent=2, ensure_ascii=False)

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

Focus on:
- Multi-step attack scenarios (lateral movement)
- Business impact (not only technical impact)
- Realistic attack paths, not purely theoretical ones
- Use your attacker expertise first, then enrich with RAG tools to validate scenarios against known vulnerability databases (CWE/CVE)

REMINDER: Output a single JSON object with "methodology", "threats" array, and "summary". No markdown.
"""


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
    threats_raw = parsed.get("threats", []) if isinstance(parsed, dict) else []

    if not threats_raw:
        logger.warning(
            "[PASTA] JSON extraction produced 0 threats. "
            "Attempting markdown fallback..."
        )
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
