"""Agent: MAESTRO Analyst — Phase II: AI/Agentic Threat Analysis.

Applies the MAESTRO (CSA) 7-layer framework + OWASP Agentic AI Top 10 2026
to evaluate threats specific to systems with AI, ML, LLM, or autonomous
agent components.

Activated CONDITIONALLY: only if the system has AI components.
"""

from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING

from agentictm.agents.base import invoke_agent, extract_json_from_response, extract_threats_from_markdown
from agentictm.rag.tools import AI_ANALYST_TOOLS
from agentictm.state import ThreatModelState

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are a specialist in threats against AI systems and agentic applications.

Use these two reference frameworks:

**MAESTRO (CSA) — 7 analysis layers:**
- L1: Foundation Models — attacks on the base model (extraction, poisoning)
- L2: Data Operations — data poisoning, RAG poisoning
- L3: Agent Frameworks — vulnerabilities in LangChain/LangGraph/etc.
- L4: Deployment — misconfigs, API exposure, model serving
- L5: Multi-Agent Systems — collusion, cascading failures, coordination attacks
- L6: Ecosystem & Plugins — tool/plugin supply chain, third-party risks
- L7: Governance — audit gaps, compliance, human oversight gaps

**OWASP Agentic AI Top 10 2026:**
- ASI01: Agent Goal Hijack
- ASI02: Tool Misuse
- ASI03: Identity & Privilege Abuse
- ASI04: Agentic Supply Chain
- ASI05: Unexpected Code Execution
- ASI06: Memory & Context Poisoning
- ASI07: Insecure Inter-Agent Comms
- ASI08: Cascading Failures
- ASI09: Human-Agent Trust Exploitation
- ASI10: Rogue Agents

When the system includes autonomous AI agents or multi-agent orchestration, also evaluate against the OWASP Agentic AI Top 10 2026 categories: ASI01 Agent Goal Hijack, ASI02 Tool Misuse, ASI03 Identity & Privilege Abuse, ASI04 Agentic Supply Chain, ASI05 Unexpected Code Execution, ASI06 Memory & Context Poisoning, ASI07 Insecure Inter-Agent Comms, ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents.

If the system has NO AI/ML/Agentic components, respond:
{
    "methodology": "MAESTRO",
    "applicable": false,
    "reason": "No AI/ML/Agentic components identified",
    "threats": [],
    "summary": "System has no AI components — MAESTRO not applicable"
}

If the system HAS AI components, analyze each one with MAESTRO + OWASP:
{
    "methodology": "MAESTRO",
    "applicable": true,
    "threats": [
        {
            "component": "affected AI component",
            "maestro_layer": "L1-L7",
            "owasp_id": "ASI01-ASI10 (if applicable)",
            "description": "3-5 sentence developer-friendly explanation: what the AI-specific vulnerability is, how an attacker exploits it against this system, and the concrete business impact. Explain AI security terms (e.g. prompt injection, RAG poisoning) as if the reader has never heard them.",
            "attack_vector": "Step-by-step concrete attack sequence: 1. attacker does X -> 2. system responds with Y -> 3. attacker achieves Z. Use actual component names from the system.",
            "impact": "High|Medium|Low",
            "reasoning": "2-3 sentences: what specific architectural decision or missing safeguard in THIS system enables this attack",
            "mitigation": "2-3 sentence specific mitigation: what code/config change mitigates this AI-specific risk. Reference the component by name.",
            "control_reference": "NIST AI RMF, OWASP AI Security controls, or ISO 42001 (e.g. 'NIST AI RMF MAP-1.5, OWASP ASI-01')",
            "evidence_sources": [{"source_type": "rag|llm_knowledge|contextual|architecture", "source_name": "e.g. OWASP ASI-01", "excerpt": "supporting reference"}],
            "confidence_score": 0.85
        }
    ],
    "summary": "executive summary of MAESTRO/OWASP analysis"
}

EVIDENCE: Each threat MUST include at least 1 evidence_source citing where the finding comes from.
CONFIDENCE: Rate 0.0-1.0 how certain you are this AI threat applies to THIS specific system.

!!! CRITICAL: DO NOT COPY RAG ENTRIES !!!
- RAG results (e.g. TMA-xxxx IDs from threats.csv) are REFERENCE MATERIAL ONLY
- Do NOT copy their IDs, titles, or descriptions into your output
- Perform YOUR OWN original MAESTRO/OWASP analysis of the specific AI components
- Use RAG only to find supporting standards for YOUR findings
"""


def _has_ai_components(state: ThreatModelState) -> bool:
    """Detect whether the system has AI/ML/Agentic components.

    Uses a two-tier keyword strategy to avoid false positives on non-AI
    systems whose descriptions naturally contain words like "model", "agent",
    or "prompt".

    - **Strong indicators**: unambiguously AI (any single word-boundary match
      is enough).
    - **Ambiguous indicators**: common in non-AI contexts — require ≥3 distinct
      matches before triggering.

    The raw_input fallback (user text + uploads) only checks strong indicators
    to avoid false positives from triage Q&A or generic architecture language.
    """
    import re as _re

    _STRONG_AI_KEYWORDS = {
        "llm", "gpt", "langchain", "langgraph", "ollama", "openai",
        "anthropic", "neural", "embedding", "rag", "transformer", "bert",
        "chatbot", "nlp", "pytorch", "tensorflow", "huggingface",
        "fine-tun", "rlhf", "dpo", "sagemaker", "bedrock", "copilot",
        "gemini", "claude", "crewai", "autogen", "agentic",
        "machine learning", "deep learning", "artificial intelligence",
        "ml model", "model serving", "feature ingestion", "vector store",
        "multi-agent", "multi_agent", "a2a", "agent2agent",
        "mcp-get", "mcp_installer", "tool_registry",
    }
    _AMBIGUOUS_AI_KEYWORDS = {
        "model", "ai", "ml", "agent", "prompt", "inference", "training",
        "prediction", "adversarial", "generative", "scoring model",
        "risk engine", "vector", "plugin", "orchestrat",
    }

    def _to_str(val: object) -> str:
        if isinstance(val, str):
            return val
        if isinstance(val, dict):
            return json.dumps(val, ensure_ascii=False)
        if isinstance(val, list):
            return " ".join(str(i) for i in val)
        return str(val) if val else ""

    def _wb_match(keyword: str, text: str) -> bool:
        return bool(_re.search(r"\b" + _re.escape(keyword) + r"\b", text))

    arch_text = (
        _to_str(state.get("system_description", "")).lower()
        + " "
        + json.dumps(state.get("components", []), ensure_ascii=False).lower()
    )

    if any(_wb_match(kw, arch_text) for kw in _STRONG_AI_KEYWORDS):
        return True
    ambiguous_hits = sum(1 for kw in _AMBIGUOUS_AI_KEYWORDS if _wb_match(kw, arch_text))
    if ambiguous_hits >= 3:
        return True

    raw_input = _to_str(state.get("raw_input", "")).lower()
    strong_in_raw = [kw for kw in _STRONG_AI_KEYWORDS if _wb_match(kw, raw_input)]
    if strong_in_raw:
        logger.info("[MAESTRO] Strong AI keywords found in raw_input: %s", strong_in_raw[:5])
        return True

    for report in state.get("methodology_reports", []):
        report_text = json.dumps(report, ensure_ascii=False).lower()
        strong_in_report = sum(1 for kw in _STRONG_AI_KEYWORDS if _wb_match(kw, report_text))
        if strong_in_report >= 2:
            logger.info("[MAESTRO] AI keywords found in %s methodology report", report.get("methodology", "?"))
            return True

    return False


def _build_human_prompt(state: ThreatModelState) -> str:
    components = json.dumps(state.get("components", []), indent=2, ensure_ascii=False)
    data_flows = json.dumps(state.get("data_flows", []), indent=2, ensure_ascii=False)
    _sd = state.get("system_description", "Not available")
    if isinstance(_sd, dict):
        _sd = json.dumps(_sd, ensure_ascii=False)

    components_list = state.get("components", [])
    arch_note = ""
    if not components_list:
        arch_note = (
            "\n\nNOTE: The structured component list is empty. "
            "The System Description above contains the FULL architecture details including AI components. "
            "Extract AI/ML/LLM/Agentic components from the description and analyze them. "
            "Do NOT return an empty result.\n"
        )

    return f"""\
Analyze the following system for AI/ML/Agentic-specific threats.

## System Description
{_sd}

## Components
{components}

## Data Flows
{data_flows}

## Scope Notes
{state.get("scope_notes", "No notes")}
{arch_note}
Apply MAESTRO (7 layers) + OWASP Agentic AI Top 10 2026 to each AI/ML/LLM/Agentic component.
Use your expertise first, then enrich with RAG tools to cross-reference AI threat research and validate your findings.
"""


def run_maestro_analyst(
    state: ThreatModelState,
    llm: BaseChatModel,
) -> dict:
    """LangGraph node: MAESTRO Analyst (conditional)."""
    # Check for AI components
    if not _has_ai_components(state):
        logger.info("[MAESTRO] No AI/ML/agentic components detected, skipping")
        report = {
            "methodology": "MAESTRO",
            "agent": "maestro_analyst",
            "report": "No AI/ML/Agentic components identified in the system.",
            "threats_raw": [],
        }
        return {
            "methodology_reports": [report],
        }

    logger.info("[MAESTRO] Starting AI threat analysis...")
    human_prompt = _build_human_prompt(state)
    t0 = time.perf_counter()

    try:
        response = invoke_agent(llm, SYSTEM_PROMPT, human_prompt, tools=AI_ANALYST_TOOLS, agent_name="MAESTRO")
    except Exception as exc:
        logger.error("[MAESTRO] LLM invocation FAILED: %s. Returning empty report.", exc)
        return {
            "methodology_reports": [{
                "methodology": "MAESTRO",
                "agent": "maestro_analyst",
                "report": f"MAESTRO analysis failed: {exc}",
                "threats_raw": [],
            }],
        }

    elapsed = time.perf_counter() - t0

    logger.info("[MAESTRO] LLM response (%d chars):\n%s", len(response), response[:2000])

    parsed = extract_json_from_response(response)
    threats_raw = parsed.get("threats", []) if isinstance(parsed, dict) else []

    # FALLBACK: If JSON parsing failed, try markdown extraction
    if not threats_raw:
        logger.warning(
            "[MAESTRO] JSON extraction produced 0 threats. "
            "Attempting markdown fallback..."
        )
        threats_raw = extract_threats_from_markdown(response, "MAESTRO")

    report = {
        "methodology": "MAESTRO",
        "agent": "maestro_analyst",
        "report": response,
        "threats_raw": threats_raw,
    }

    logger.info("[MAESTRO] Completed in %.1fs: %d AI threats", elapsed, len(report["threats_raw"]))
    return {
        "methodology_reports": [report],
    }
