"""Agente: MAESTRO Analyst — Fase II: Análisis de Amenazas AI/Agénticas.

Aplica el framework MAESTRO (CSA) de 7 capas + OWASP Agentic Top 10
para evaluar amenazas específicas de sistemas con componentes de IA,
ML, LLMs o agentes autónomos.

Se activa CONDICIONALMENTE: solo si el sistema tiene componentes AI.
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

**MAESTRO (CSA) — 7 capas de análisis:**
- L1: Foundation Models — ataques al modelo base (extraction, poisoning)
- L2: Data Operations — envenenamiento de datos, RAG poisoning
- L3: Agent Frameworks — vulnerabilidades en LangChain/LangGraph/etc
- L4: Deployment — misconfigs, API exposure, model serving
- L5: Multi-Agent Systems — collusion, cascading failures, coordination attacks
- L6: Ecosystem & Plugins — supply chain de tools/plugins, third-party risks
- L7: Governance — audit gaps, compliance, human oversight gaps

**OWASP Agentic Applications Top 10:**
- ASI01: Prompt Injection (directa e indirecta)
- ASI02: Sensitive Information Disclosure
- ASI03: Supply Chain Vulnerabilities
- ASI04: Excessive Agency
- ASI05: Insecure Output Handling
- ASI06: Insufficient Logging/Monitoring
- ASI07: Improper Context Management
- ASI08: Memory Poisoning
- ASI09: Privilege Mismanagement
- ASI10: Uncontrolled Code Generation

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
            "owasp_id": "ASI01-ASI10 (si aplica)",
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
"""


def _has_ai_components(state: ThreatModelState) -> bool:
    """Detecta si el sistema tiene componentes de IA/ML/Agénticos.

    Checks multiple sources: system_description, components, raw_input,
    and methodology_reports (other analysts may have identified AI components).
    """
    ai_keywords = {
        "llm", "model", "ai", "ml", "gpt", "agent", "rag", "vector",
        "embedding", "neural", "inference", "training", "prediction",
        "langchain", "langgraph", "ollama", "openai", "anthropic",
        "transformer", "bert", "chatbot", "nlp", "prompt",
        "machine learning", "deep learning", "artificial intelligence",
        "risk engine", "scoring model", "ml model", "model serving",
        "feature ingestion", "adversarial", "generative",
    }

    def _to_str(val: object) -> str:
        if isinstance(val, str):
            return val
        if isinstance(val, dict):
            return json.dumps(val, ensure_ascii=False)
        if isinstance(val, list):
            return " ".join(str(i) for i in val)
        return str(val) if val else ""

    text_to_check = (
        _to_str(state.get("system_description", "")).lower()
        + " "
        + json.dumps(state.get("components", []), ensure_ascii=False).lower()
    )

    if any(kw in text_to_check for kw in ai_keywords):
        return True

    # Fallback: also check raw_input (the original user text + attached docs)
    raw_input = _to_str(state.get("raw_input", "")).lower()
    if any(kw in raw_input for kw in ai_keywords):
        logger.info("[MAESTRO] AI keywords found in raw_input (not in parsed components)")
        return True

    # Fallback 2: check if other methodology analysts found AI components
    for report in state.get("methodology_reports", []):
        report_text = json.dumps(report, ensure_ascii=False).lower()
        ai_in_report = sum(1 for kw in ai_keywords if kw in report_text)
        if ai_in_report >= 3:  # at least 3 AI keywords in a single report
            logger.info("[MAESTRO] AI keywords found in %s methodology report", report.get("methodology", "?"))
            return True

    return False


def _build_human_prompt(state: ThreatModelState) -> str:
    components = json.dumps(state.get("components", []), indent=2, ensure_ascii=False)
    data_flows = json.dumps(state.get("data_flows", []), indent=2, ensure_ascii=False)
    _sd = state.get("system_description", "Not available")
    if isinstance(_sd, dict):
        _sd = json.dumps(_sd, ensure_ascii=False)

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

Apply MAESTRO (7 layers) + OWASP Agentic Top 10 to each AI/ML/LLM/Agentic component.
Use your expertise first, then enrich with RAG tools to cross-reference AI threat research and validate your findings.
"""


def run_maestro_analyst(
    state: ThreatModelState,
    llm: BaseChatModel,
) -> dict:
    """Nodo de LangGraph: MAESTRO Analyst (condicional)."""
    # Chequear si hay componentes AI
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
