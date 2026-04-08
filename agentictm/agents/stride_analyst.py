"""Agent: STRIDE Analyst -- Phase II: Methodology-based Analysis.

Applies STRIDE-per-element: for each component and data flow in the system,
evaluates the 6 threat categories (Spoofing, Tampering, Repudiation,
Information Disclosure, Denial of Service, Elevation of Privilege).
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
!!! OUTPUT FORMAT: You MUST respond with a SINGLE JSON object. NO markdown, NO headings, NO narrative text outside JSON. !!!

You are a STRIDE threat analyst. Apply STRIDE-per-element internally:
- S: Spoofing  - T: Tampering  - R: Repudiation
- I: Information Disclosure  - D: Denial of Service  - E: Elevation of Privilege

When the system under analysis includes AI agents, autonomous components, or multi-agent orchestration, also evaluate threats under the ASTRIDE 'A' category: Agent Threats. These include prompt injection, unsafe tool invocation, reasoning subversion, context poisoning, and cross-agent trust exploitation.

Analyze EVERY component and data flow against all 6 categories INTERNALLY (plus the A category when AI agents are present),
then OUTPUT ONLY the JSON below.

AUDIENCE: Developers with NO security training. Each description must be a story.

Your response must be EXACTLY this JSON structure:
{"methodology":"STRIDE","threats":[<8-15 threat objects>],"summary":"<1 paragraph>"}

Each threat object:
{
  "component": "exact component or data flow name from the architecture",
  "stride_category": "S|T|R|I|D|E|A",
  "description": "3-5 sentences: WHAT the vulnerability is (explain security terms), HOW an attacker exploits it step-by-step against THIS system, WHAT concrete harm results. Name specific components.",
  "impact": "High|Medium|Low",
  "reasoning": "2-3 sentences on what design flaw or missing control makes this possible",
  "references": "CAPEC-XX, CWE-XX, ATT&CK Txxxx",
  "mitigation": "2-3 sentence specific fix: what code/config change blocks this. Name the component.",
  "control_reference": "NIST 800-53, OWASP ASVS, or CIS control ID",
  "evidence_sources": [{"source_type": "rag", "source_name": "e.g. CAPEC-196", "excerpt": "supporting quote"}],
  "confidence_score": 0.85
}

BAD description: "Spoofing via weak authentication"
GOOD description: "The API Gateway does not validate JWT token signatures -- it only checks a token is present. An attacker can forge a JWT by setting the algorithm to 'none' (Algorithm Confusion, CVE-2015-9235), which many libraries accept. This lets any anonymous user impersonate any account, accessing their data and performing actions without credentials."

RULES:
- Output ONLY the JSON object -- no markdown, no STRIDE-per-element tables, no narrative
- Cover ALL 6 STRIDE categories (plus the A category for agent-based systems) with at least 1 threat per category when applicable
- Each threat must name a SPECIFIC component from the architecture
- Each evidence_source must cite where the finding comes from
- Use your expertise first, then enrich with RAG tools
- If the architecture explicitly mentions multi-tenant isolation, object identifiers, share links, presigned URLs, or async scan/approval workflows, include threats for object-level authorization, cross-tenant access, and workflow/state bypasses when applicable
- If the architecture explicitly states there are no AI/LLM/agentic components, do NOT output prompt injection, LLM, or agent-tooling threats

!!! CRITICAL: DO NOT COPY RAG ENTRIES !!!
- RAG results (e.g. TMA-xxxx IDs from threats.csv) are REFERENCE MATERIAL ONLY
- Do NOT copy their IDs, titles, or descriptions into your output
- Perform YOUR OWN original STRIDE analysis of the specific system architecture
- Use RAG only to find supporting standards (CWE, CAPEC, ATT&CK) for YOUR findings
- Each threat MUST reference specific components from THIS system, not generic cloud controls
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
            "threat_surface_summary": str(state.get("threat_surface_summary", "No architecture review briefing available.")),
        },
        priorities=["system_description", "components", "data_flows", "trust_boundaries", "data_stores", "scope_notes", "threat_surface_summary"],
    )

    components_list = state.get("components", [])
    has_structured = bool(components_list)

    arch_note = ""
    if not has_structured:
        arch_note = (
            "\n\nNOTE: The structured component list is empty. "
            "The System Description above contains the FULL architecture details. "
            "You MUST extract components, data flows and trust boundaries from the description text "
            "and perform a complete STRIDE analysis on them. "
            "Do NOT return an empty result.\n"
        )

    return f"""\
Analyze the following system using STRIDE-per-element.

IMPORTANT: Respond with the JSON object ONLY. Do NOT write markdown or narrative text.

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
{arch_note}
## Architecture Review Briefing
{fitted["threat_surface_summary"]}
Focus explicitly on:
- Object-level authorization, tenant isolation, and direct-object-reference abuse when identifiers or multi-tenant data are present
- State transitions and asynchronous workflow bypasses when upload/scan/quarantine/approval/download steps exist
- Only non-AI threats when the system explicitly says there is no AI/LLM/agentic surface
Use your expert knowledge first, then enrich with RAG tools to cite known attack patterns.

REMINDER: Output a single JSON object with "methodology", "threats" array, and "summary". No markdown.
"""


def run_stride_analyst(
    state: ThreatModelState,
    llm: BaseChatModel,
) -> dict:
    """LangGraph node: STRIDE Analyst."""
    logger.info("[STRIDE] Starting analysis...")
    human_prompt = _build_human_prompt(state)
    t0 = time.perf_counter()
    response = invoke_agent(llm, SYSTEM_PROMPT, human_prompt, tools=ANALYST_TOOLS, agent_name="STRIDE")
    elapsed = time.perf_counter() - t0

    logger.info("[STRIDE] LLM response (%d chars):\n%s", len(response), response)

    parsed = extract_json_from_response(response)
    threats_raw = find_threats_in_json(parsed) if isinstance(parsed, dict) else []

    if not threats_raw:
        logger.warning("[STRIDE] JSON extraction produced 0 threats. Trying individual object extraction...")
        threats_raw = _extract_individual_json_objects(response)

    if not threats_raw:
        logger.warning("[STRIDE] Individual extraction produced 0 threats. Attempting markdown fallback...")
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
