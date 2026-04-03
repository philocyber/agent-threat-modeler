"""Agente: STRIDE Analyst — Fase II: Análisis por Metodología.

Aplica STRIDE-per-element: para cada componente y flujo del sistema,
evalúa las 6 categorías de amenaza (Spoofing, Tampering, Repudiation,
Information Disclosure, Denial of Service, Elevation of Privilege).
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
You are a threat analyst specialized in STRIDE.

STRIDE categories:
- S: Spoofing
- T: Tampering
- R: Repudiation
- I: Information Disclosure
- D: Denial of Service
- E: Elevation of Privilege

Perform STRIDE-per-element: analyze EVERY component and data flow against all categories.

IMPORTANT — DUAL KNOWLEDGE APPROACH:
1. FIRST, apply your deep expertise in STRIDE threat analysis. Reason from your
   own training knowledge about common vulnerability patterns, attack techniques,
   and security weaknesses relevant to the system architecture.
2. THEN, use RAG tools to enrich and validate your findings with supporting
   references (CAPEC, CWE, MITRE ATT&CK). Cross-reference your expert analysis
   with RAG results to produce a comprehensive, well-cited output that blends
   both knowledge sources.

Do not provide generic statements. Base findings on the specific system context,
data sensitivity, protocols, and trust boundaries.

CRITICAL — AUDIENCE: Your threat descriptions will be read by software developers
with LIMITED security background. Write as if explaining to a senior developer
who has never studied cybersecurity formally.

For EVERY threat:
- "description": Write 3–5 sentences that explain:
  1. WHAT the specific vulnerability or weakness is (explain any security term used)
  2. EXACTLY HOW an attacker would exploit it, step by step, against THIS system
  3. WHAT concrete harm results (data lost, service down, account taken over, etc.)
  Use specific component names from the system. Avoid vague phrases like
  "could be exploited" — say HOW and by WHOM.
- "reasoning": 2–3 sentences explaining WHY this specific system is exposed
  (e.g., which architecture decision, protocol choice, or missing control enables it)

BAD description: "Spoofing via weak authentication"
GOOD description: "The API Gateway does not validate the signature of incoming JWT
  tokens — it only checks that a token is present. An attacker can forge a JWT by
  setting the algorithm to 'none' (Algorithm Confusion Attack, CVE-2015-9235), which
  many libraries accept without signature checking. This lets any anonymous user create
  a token claiming to be any user ID, gaining full access to that account’s data and
  actions without knowing their password."

Respond with JSON only:
{
    "methodology": "STRIDE",
    "threats": [
        {
            "component": "component or data flow name",
            "stride_category": "S|T|R|I|D|E",
            "description": "3-5 sentence developer-friendly explanation of the threat, how it is exploited, and the concrete impact",
            "impact": "High|Medium|Low",
            "reasoning": "2-3 sentences on why THIS system is specifically exposed to this threat",
            "references": "CAPEC-XX, CWE-XX, ATT&CK Txxxx",
            "mitigation": "2-3 sentence specific mitigation: what code/config change fixes this. Reference the component by name.",
            "control_reference": "NIST 800-53 control ID, OWASP ASVS section, or CIS control (e.g. 'NIST AC-3, OWASP ASVS V4.2')",
            "evidence_sources": [{"source_type": "rag|llm_knowledge|contextual|architecture", "source_name": "e.g. CAPEC-196", "excerpt": "supporting reference"}],
            "confidence_score": 0.85
        }
    ],
    "summary": "executive summary of STRIDE analysis"
}

EVIDENCE: Each threat MUST include at least 1 evidence_source citing where the finding comes from (RAG result, known standard, architecture observation).
CONFIDENCE: Rate 0.0-1.0 how certain you are this threat applies to THIS specific system.
"""


def _build_human_prompt(state: ThreatModelState) -> str:
    """Build the STRIDE prompt with system context."""
    from agentictm.agents.prompt_budget import PromptBudget

    pb = PromptBudget(system_prompt_chars=len(SYSTEM_PROMPT))

    components = json.dumps(state.get("components", []), indent=2, ensure_ascii=False)
    data_flows = json.dumps(state.get("data_flows", []), indent=2, ensure_ascii=False)
    trust_boundaries = json.dumps(state.get("trust_boundaries", []), indent=2, ensure_ascii=False)
    data_stores = json.dumps(state.get("data_stores", []), indent=2, ensure_ascii=False)

    fitted = pb.fit(
        sections={
            "system_description": str(state.get("system_description", "Not available")),
            "components": components,
            "data_flows": data_flows,
            "trust_boundaries": trust_boundaries,
            "data_stores": data_stores,
            "scope_notes": str(state.get("scope_notes", "No notes")),
        },
        priorities=["system_description", "components", "data_flows", "trust_boundaries", "data_stores", "scope_notes"],
    )

    return f"""\
Analyze the following system using STRIDE-per-element:

## System Description
{fitted["system_description"]}

## Components
{fitted["components"]}

## Data Flows
{fitted["data_flows"]}

## Trust Boundaries
{fitted["trust_boundaries"]}

## Data Stores
{fitted["data_stores"]}

## Scope Notes
{fitted["scope_notes"]}

Apply STRIDE to each relevant component and flow.
Use your expert knowledge first, then enrich with RAG tools to cite known attack patterns and validate your findings.
"""


def run_stride_analyst(
    state: ThreatModelState,
    llm: BaseChatModel,
) -> dict:
    """Nodo de LangGraph: STRIDE Analyst.

    Lee: components, data_flows, trust_boundaries, data_stores
    Escribe: methodology_reports (append)
    """
    logger.info("[STRIDE] Starting analysis...")
    human_prompt = _build_human_prompt(state)
    t0 = time.perf_counter()
    response = invoke_agent(llm, SYSTEM_PROMPT, human_prompt, tools=ANALYST_TOOLS, agent_name="STRIDE")
    elapsed = time.perf_counter() - t0

    logger.info("[STRIDE] LLM response (%d chars):\n%s", len(response), response)

    parsed = extract_json_from_response(response)
    threats_raw = parsed.get("threats", []) if isinstance(parsed, dict) else []

    # FALLBACK: If JSON parsing failed, try markdown extraction
    if not threats_raw:
        logger.warning(
            "[STRIDE] JSON extraction produced 0 threats. "
            "Attempting markdown fallback..."
        )
        threats_raw = extract_threats_from_markdown(response, "STRIDE")

    report = {
        "methodology": "STRIDE",
        "agent": "stride_analyst",
        "report": response,
        "threats_raw": threats_raw,
    }

    logger.info("[STRIDE] Completed in %.1fs: %d threats", elapsed, len(report["threats_raw"]))
    return {
        "methodology_reports": [report],
    }
