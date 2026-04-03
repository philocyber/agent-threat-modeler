"""Agente: PASTA Analyst — Fase II: Análisis por Metodología.

Aplica PASTA (Process for Attack Simulation and Threat Analysis):
enfoque risk-centric y business-oriented de 7 etapas que complementa STRIDE
con análisis de objetivos de negocio y simulación de ataques.
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
You are a threat analyst specialized in PASTA
(Process for Attack Simulation and Threat Analysis).

PASTA is a 7-stage risk-centric approach. Cover:
1) Business objectives and impact
2) Technical scope and dependencies
3) Application decomposition (boundaries, entry points, critical assets)
4) Threat analysis
5) Vulnerability analysis (CWE/CVE)
6) Attack simulation (realistic multi-step paths)
7) Risk and business impact assessment

Unlike STRIDE (component-centric), PASTA is attack-centric.
Reason from the attacker perspective and objectives.

CRITICAL — AUDIENCE: Your descriptions will be read by developers with NO formal
security training. Explain every attack as a story: who the attacker is, what they
want, and the exact sequence of actions they take against this specific system.

For EVERY threat:
- "attack_scenario": 3–5 sentences narrating the FULL attack story against THIS system.
  Describe the attacker's goal, their entry point, the specific steps they take, and
  the final impact. Name the exact components they interact with.
- "attack_path": A numbered step-by-step sequence (e.g. '1. Attacker registers a free
  account -> 2. Uses API endpoint /export to request another user’s data by changing
  the user_id parameter -> 3. Receives full PII export without authorization check').
- "reasoning": 2–3 sentences explaining what specific design or implementation choice
  makes this attack possible (e.g., 'The /export endpoint trusts the user_id parameter
  from the request body without verifying it matches the authenticated session user').

Respond with JSON only:
{
  "methodology": "PASTA",
  "business_context": "business risk analysis including financial, reputational, compliance impact",
  "threats": [
     {
        "attack_scenario": "3-5 sentence narrative of the full attack story against this specific system",
        "target_asset": "specific asset being attacked (e.g. 'user credential database', 'payment records')",
        "attack_path": "1. step -> 2. step -> 3. step (numbered, specific to this system)",
        "likelihood": "High|Medium|Low",
        "business_impact": "High|Medium|Low",
        "risk_level": "Critical|High|Medium|Low",
        "vulnerabilities_exploited": "CWE-XX, CVE-XXXX-XXXXX",
        "reasoning": "2-3 sentences on the specific design flaw or missing control that makes this attack possible",
        "countermeasures": "2-3 sentence specific mitigation: what code/config/infrastructure change prevents this attack. Reference the target_asset by name.",
        "control_reference": "NIST 800-53 control ID, OWASP ASVS section, or CIS control (e.g. 'NIST SI-10, CWE-639')",
        "evidence_sources": [{"source_type": "rag|llm_knowledge|contextual|architecture", "source_name": "e.g. CWE-639", "excerpt": "supporting reference"}],
        "confidence_score": 0.85
     }
  ],
  "summary": "executive summary of PASTA analysis"
}

EVIDENCE: Each threat MUST include at least 1 evidence_source citing where the finding comes from.
CONFIDENCE: Rate 0.0-1.0 how certain you are this attack scenario applies to THIS specific system.
"""


def _build_human_prompt(state: ThreatModelState) -> str:
    components = json.dumps(state.get("components", []), indent=2, ensure_ascii=False)
    data_flows = json.dumps(state.get("data_flows", []), indent=2, ensure_ascii=False)
    trust_boundaries = json.dumps(state.get("trust_boundaries", []), indent=2, ensure_ascii=False)
    external_entities = json.dumps(state.get("external_entities", []), indent=2, ensure_ascii=False)

    return f"""\
Analyze the following system using PASTA (7 stages).
Think like an ATTACKER: what are the most realistic attack paths?

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

    # FALLBACK: If JSON parsing failed, try markdown extraction
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
