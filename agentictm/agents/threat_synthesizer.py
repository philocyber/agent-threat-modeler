"""Agente: Threat Synthesizer — Fase III: Síntesis final.

Combina lo mejor de cada metodología (STRIDE, PASTA, Attack Tree, MAESTRO),
incorpora el resultado del debate Red/Blue, y produce la lista final de
amenazas con DREAD scores y mitigaciones.

Este es un agente Deep Thinker — usa el modelo más capaz.

**Hybrid strategy**: Always starts with a BASELINE of ALL raw threats from
every analyst, then asks the LLM to enrich/deduplicate.  If the LLM
produces fewer threats than a safety threshold, the baseline is used
(supplemented with any LLM enrichments that match).
"""

from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING

from agentictm.agents.base import (
    invoke_agent,
    extract_json_from_response,
    extract_threats_from_markdown,
)
from agentictm.rag.tools import ALL_RAG_TOOLS
from agentictm.state import ThreatModelState

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel


def _to_str(val: object) -> str:
    """Coerce any LLM-generated value to str (handles list, dict, None, int)."""
    if val is None:
        return ""
    if isinstance(val, str):
        return val
    if isinstance(val, list):
        return " -> ".join(str(item) for item in val)
    if isinstance(val, dict):
        return json.dumps(val, ensure_ascii=False)
    return str(val)
    from agentictm.config import AgenticTMConfig
    from langchain_core.language_models import BaseChatModel

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Threat classification & category-based ID assignment
# (mirrors report_generator logic — single source of truth)
# ---------------------------------------------------------------------------

_THREAT_CATEGORY_KEYWORDS: dict[str, list[str]] = {
    "Infraestructura y Cumplimiento": [
        "infrastructure", "infraestructura", "credential", "secret", "deploy",
        "compliance", "environment", ".env", "token", "certificate", "server",
        "host", "container", "docker", "kubernetes", "monitoring", "logging",
        "cloud", "aws", "azure", "gcp", "terraform", "tls", "ssl", "network",
        "firewall", "dns", "cicd", "ci/cd", "pipeline", "config", "iac",
    ],
    "Privacidad y Lógica de Negocio": [
        "privacy", "privacidad", "pii", "gdpr", "ccpa", "personal data",
        "consent", "business logic", "repudiation", "repudio", "audit trail",
        "data protection", "retention", "anonymi", "trazab", "exfiltr",
    ],
    "Vulnerabilidades Web y API": [
        "web", "api", "frontend", "xss", "csrf", "sql inject", "idor", "http",
        "cors", "cookie", "session", "jwt", "oauth", "endpoint", "gateway",
        "rate limit", "input valid", "sanitiz", "deserialization", "ssrf",
        "inyecci",
    ],
    "Riesgos de Integración Agéntica": [
        "agent", "agentic", "agéntic", "orchestrat", "orquest", "loop",
        "recursion", "tool misuse", "mcp", "langchain", "langgraph",
        "checkpoint", "state manip", "multi-agent", "tool call", "bucle",
    ],
    "Amenazas Nativas de IA y LLM": [
        "llm", "prompt inject", "jailbreak", "hallucin", "alucinaci", "model",
        "training", "poisoning", "embedding", "rag", "vector", "adversarial",
        "extraction", "system prompt", "guardrail", "artificial intelligence",
        "machine learning", "nlp", "bias", "sesgo",
    ],
    "Factores Humanos y Gobernanza": [
        "human", "humano", "governance", "gobernanza", "oversight",
        "automation bias", "trust", "review", "approval", "social engineer",
        "insider", "phishing",
    ],
}

_CATEGORY_PREFIX_MAP: dict[str, str] = {
    "Infraestructura y Cumplimiento": "INF",
    "Privacidad y Lógica de Negocio": "PRI",
    "Vulnerabilidades Web y API": "WEB",
    "Riesgos de Integración Agéntica": "AGE",
    "Amenazas Nativas de IA y LLM": "LLM",
    "Factores Humanos y Gobernanza": "HUM",
}


def _classify_threat_category(threat: dict) -> str:
    """Classify a threat into a professional category by content analysis."""
    text = " ".join(
        _to_str(threat.get(k, ""))
        for k in ("description", "component", "methodology", "mitigation", "attack_path")
    ).lower()
    for cat, kws in _THREAT_CATEGORY_KEYWORDS.items():
        if any(kw in text for kw in kws):
            return cat
    return "Amenazas Generales"


# ---------------------------------------------------------------------------
# STRIDE inference from description keywords (for baseline fallback)
# ---------------------------------------------------------------------------

_STRIDE_KEYWORDS: dict[str, list[str]] = {
    "S": [
        "spoofing", "spoof", "impersonat", "identity", "authentication bypass",
        "credential", "phishing", "forged token", "jwt", "session hijack",
        "unauthorized access", "forged", "fake identity", "suplantaci",
        "robo de credencial", "stolen credential", "hijack",
        "dominio no verificado", "unverified domain", "token theft",
        "robo de token", "stolen session", "fake email", "fake sender",
        "confianza en dominio", "trust domain", "whitelist bypass",
    ],
    "T": [
        "tampering", "tamper", "integrity", "modif", "alter",
        "corrupt", "inject", "manipulat", "overwrite", "patch", "forgery",
        "data integrity", "unauthorized change", "code injection",
        "deserializ", "rce", "remote code", "ejecuci",
        "malicious payload", "payload malicioso", "code execut",
        "field mapping", "mapeo de", "sql inject", "command inject",
        "xss", "cross-site script",
        "input validat", "validaci", "schema bypass", "no valida",
    ],
    "R": [
        "repudiation", "repudio", "non-repudiation", "logging", "audit",
        "traceability", "accountability", "log", "evidence", "deniab",
        "no record", "unlogged", "auditoria", "auditoría", "trazabilidad",
        "forensic", "forense", "log tampering", "log injection",
        "without logging", "sin registro", "borrado de log", "log deletion",
    ],
    "I": [
        "information disclosure", "data leak", "exfiltrat", "exposure",
        "sensitive data", "confidential", "privacy", "data breach",
        "unauthorized read", "intercept", "sniff", "man-in-the-middle",
        "mitm", "eavesdrop", "disclosure", "divulgaci",
        "datos sensibles", "fuga de dato", "expose secret",
    ],
    "D": [
        "denial of service", "dos", "ddos", "availability", "resource exhaust",
        "crash", "timeout", "overload", "flood", "disruption", "denegaci",
        "unavailab", "outage", "degrade", "slow",
    ],
    "E": [
        "elevation of privilege", "privilege escalat", "escalat", "admin access",
        "root access", "unauthorized role", "rbac bypass", "iam", "overprivileg",
        "permission", "role", "sudo", "least privilege", "elevaci",
        "gain admin", "become admin", "bypass authorization", "bypass authz",
        "higher privilege", "privileged access", "acceso privilegiado",
        "comprometer sesión admin", "compromise admin", "mfa bypass",
        "panel administrativo", "admin panel", "admin dashboard",
        "supply chain", "cadena de suministro", "ci/cd", "pipeline compromise",
    ],
}


_VALID_STRIDE = frozenset({"S", "T", "R", "I", "D", "E"})


def _normalize_stride_category(raw: str) -> str:
    """Normalize a STRIDE category value, extracting a valid letter if possible.

    Handles:
      - Standard single letters: "S", "T", "R", "I", "D", "E"
      - Full words: "Spoofing", "Tampering", etc.
      - Invalid AI framework codes: "LLM02|ASI03|L1" → ""
      - Mixed/junk: "Bias, Fairness & Discrimination|LLM09" → ""
    """
    raw = (raw or "").strip()
    if not raw or raw == "-":
        return ""
    if raw in _VALID_STRIDE:
        return raw
    first_char = raw[0].upper()
    if first_char in _VALID_STRIDE and (len(raw) == 1 or not raw[1].isalpha()):
        return first_char
    word_map = {
        "spoofing": "S", "suplantaci": "S",
        "tampering": "T", "manipulaci": "T",
        "repudiation": "R", "repudio": "R",
        "information disclosure": "I", "divulgaci": "I", "info": "I",
        "denial": "D", "denegaci": "D",
        "elevation": "E", "escalat": "E", "elevaci": "E",
        "privilege": "E",
    }
    raw_lower = raw.lower()
    for keyword, cat in word_map.items():
        if keyword in raw_lower:
            return cat
    return ""


def _infer_stride_category(threat: dict) -> str:
    """Infer the STRIDE category from threat text when not explicitly set."""
    text = " ".join(
        _to_str(threat.get(k, ""))
        for k in ("description", "attack_path", "component", "methodology")
    ).lower()
    best: str = ""
    best_score = 0
    for cat, kws in _STRIDE_KEYWORDS.items():
        score = sum(1 for kw in kws if kw in text)
        if score > best_score:
            best_score = score
            best = cat
    return best


# Default mitigations per STRIDE category (used when analyst doesn't provide one)
_DEFAULT_MITIGATIONS: dict[str, str] = {
    "S": "Implementar autenticación multifactor (MFA) y validación robusta de tokens/sesiones.",
    "T": "Aplicar validación de integridad de datos, checksums y controles de acceso de escritura.",
    "R": "Implementar logging centralizado y auditoría inmutable de todas las operaciones críticas.",
    "I": "Aplicar cifrado en tránsito (TLS 1.3) y en reposo; restringir acceso según principio de mínimo privilegio.",
    "D": "Implementar rate limiting, auto-scaling y monitoreo de disponibilidad con alertas.",
    "E": "Aplicar principio de mínimo privilegio en todos los roles IAM; revisar y auditar permisos periódicamente.",
}

_DEFAULT_CONTROLS: dict[str, str] = {
    "S": "NIST IA-2, OWASP ASVS V2",
    "T": "NIST SI-7, OWASP ASVS V5",
    "R": "NIST AU-2, AU-3, OWASP ASVS V7",
    "I": "NIST SC-8, SC-28, OWASP ASVS V8",
    "D": "NIST SC-5, OWASP ASVS V11",
    "E": "NIST AC-6, OWASP ASVS V4",
}


def _clamp_dread(val: int) -> int:
    """Clamp a DREAD dimension to the valid 1-10 range."""
    return max(1, min(10, val))


def _asymmetric_dread(base: int, stride_cat: str, desc: str) -> dict[str, int]:
    """Generate asymmetric DREAD scores based on STRIDE category and description.

    Rather than assigning the same base score to all 5 dimensions (which is
    unrealistic), this uses heuristics per STRIDE category to produce varied
    scores.  The total remains close to base*5 but individual dimensions differ.
    """
    b = _clamp_dread(base)
    desc_lower = (desc or "").lower()

    # Base offsets per STRIDE category (relative to base)
    offsets = {
        "S": {"damage": 1, "reproducibility": 0, "exploitability": -1, "affected_users": 1, "discoverability": -2},
        "T": {"damage": 2, "reproducibility": 0, "exploitability": -1, "affected_users": 1, "discoverability": -1},
        "R": {"damage": -1, "reproducibility": 1, "exploitability": 0, "affected_users": -1, "discoverability": -2},
        "I": {"damage": 1, "reproducibility": 0, "exploitability": -1, "affected_users": 2, "discoverability": -1},
        "D": {"damage": 0, "reproducibility": 2, "exploitability": 1, "affected_users": 1, "discoverability": -2},
        "E": {"damage": 2, "reproducibility": -1, "exploitability": -2, "affected_users": 1, "discoverability": -2},
    }
    off = offsets.get(stride_cat, {"damage": 1, "reproducibility": 0, "exploitability": -1, "affected_users": 0, "discoverability": -1})

    # Additional keyword-driven adjustments
    if any(kw in desc_lower for kw in ("multi-step", "multi step", "cadena", "chain")):
        off["reproducibility"] = off.get("reproducibility", 0) - 1
        off["exploitability"] = off.get("exploitability", 0) - 1
    if any(kw in desc_lower for kw in ("public", "internet", "externo", "external")):
        off["discoverability"] = off.get("discoverability", 0) + 2
    if any(kw in desc_lower for kw in ("internal", "interno", "vpn", "intranet")):
        off["discoverability"] = off.get("discoverability", 0) - 1
        off["exploitability"] = off.get("exploitability", 0) - 1

    return {
        "damage": _clamp_dread(b + off.get("damage", 0)),
        "reproducibility": _clamp_dread(b + off.get("reproducibility", 0)),
        "exploitability": _clamp_dread(b + off.get("exploitability", 0)),
        "affected_users": _clamp_dread(b + off.get("affected_users", 0)),
        "discoverability": _clamp_dread(b + off.get("discoverability", 0)),
    }


def _compute_priority(dread_total: int) -> str:
    """Priority from DREAD sum using calibrated bands aligned to industry standard.

    Based on average per-dimension score (total / 5):
      avg >= 9.0 (sum >= 45): Critical
      avg >= 7.0 (sum >= 35): High
      avg >= 4.0 (sum >= 20): Medium
      avg < 4.0  (sum < 20):  Low
    """
    if dread_total >= 45:
        return "Critical"
    if dread_total >= 35:
        return "High"
    if dread_total >= 20:
        return "Medium"
    return "Low"


_THREAT_DESCRIPTION_KEYS = frozenset({
    "description", "title", "threat", "descripcion", "vulnerability",
    "scenario", "attack_scenario", "leaf_action", "amenaza",
})

_THREATS_ARRAY_KEYS = [
    "threats", "amenazas", "threat_list", "threat_analysis",
    "analysis", "results", "data", "items", "findings",
]


def _looks_like_threat(item: dict) -> bool:
    """Heuristic: does this dict look like a threat object?"""
    return any(item.get(k) for k in _THREAT_DESCRIPTION_KEYS)


def _find_threats_array(parsed: dict, _depth: int = 0) -> list[dict]:
    """Auto-detect the threats array from an LLM JSON response.

    Tries known key names first, then falls back to finding the largest
    list-of-dicts value in the parsed object (up to 2 nesting levels).
    """
    # 1. Try known key names at this level
    for key in _THREATS_ARRAY_KEYS:
        val = parsed.get(key)
        if isinstance(val, list) and val and isinstance(val[0], dict):
            logger.info("[Synthesizer] Found threats under key '%s' (%d items)", key, len(val))
            return [t for t in val if isinstance(t, dict)]

    # 2. Try any key whose value is a list of threat-like dicts
    best_key, best_list = "", []
    for key, val in parsed.items():
        if isinstance(val, list) and len(val) > len(best_list):
            dicts = [t for t in val if isinstance(t, dict)]
            if dicts and any(_looks_like_threat(d) for d in dicts[:3]):
                best_key, best_list = key, dicts

    if best_list:
        logger.info(
            "[Synthesizer] Auto-detected threats under key '%s' (%d items)",
            best_key, len(best_list),
        )
        return best_list

    # 3. Recurse one level into nested dicts (max depth 2)
    if _depth < 2:
        for key, val in parsed.items():
            if isinstance(val, dict):
                nested = _find_threats_array(val, _depth + 1)
                if nested:
                    logger.info("[Synthesizer] Found threats nested under '%s'", key)
                    return nested

    # 4. The entire dict might itself be a single threat
    if _looks_like_threat(parsed):
        logger.info("[Synthesizer] Parsed dict is itself a single threat")
        return [parsed]

    if _depth == 0:
        logger.warning(
            "[Synthesizer] Could not find threats array. Top-level keys: %s",
            list(parsed.keys())[:20],
        )
    return []


def _assign_category_ids(threats: list[dict]) -> list[dict]:
    """Assign professional category-based IDs (WEB-01, INF-02, etc.) to all threats.

    Groups threats by category, then assigns sequential IDs within each group.
    Replaces any generic TM-xxx or THREAT-xxx IDs.
    """
    # Group by category
    groups: dict[str, list[dict]] = {}
    for t in threats:
        cat = _classify_threat_category(t)
        groups.setdefault(cat, []).append(t)

    # Category display order
    category_order = [
        "Infraestructura y Cumplimiento",
        "Privacidad y Lógica de Negocio",
        "Vulnerabilidades Web y API",
        "Riesgos de Integración Agéntica",
        "Amenazas Nativas de IA y LLM",
        "Factores Humanos y Gobernanza",
        "Amenazas Generales",
    ]

    result = []
    for cat in category_order:
        cat_threats = groups.get(cat, [])
        prefix = _CATEGORY_PREFIX_MAP.get(cat, "TM")
        for i, t in enumerate(cat_threats, 1):
            t["id"] = f"{prefix}-{i:02d}"
            result.append(t)

    return result

SYSTEM_PROMPT = """\
You are the Lead Security Architect and final threat model synthesizer.

Your task is the most critical in the pipeline: combine the best findings
from every methodology and the adversarial debate to produce THE final,
comprehensive, prioritized threat model.

You receive:
- Structured threat lists from 4-5 analysts (STRIDE, PASTA, Attack Tree, MAESTRO, AI Threat)
- Full debate between Red Team and Blue Team
- Previous threat model context (via RAG tools)
- System components, trust boundaries, data flows

Your job:

1. CONSOLIDATE: Merge threats from all methodologies.
   - STRIDE: per-element coverage (Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation)
   - PASTA: business risk and attack scenarios
   - Attack Tree: structured attack paths and leaf actions
   - MAESTRO/AI Threat: AI/ML-specific risks (if applicable)
   Deduplicate but preserve each methodology's unique angle.

   **MANDATORY MINIMUM: You MUST generate AT LEAST 15 distinct, well-defined threats.**
   Professional threat models contain 15-25 threats. Aim for 18-25 threats
   covering the full attack surface. If you have fewer than 15 after deduplication,
   revisit the methodology outputs — there are always overlooked vectors such as:
   denial of service, supply chain, configuration drift, insider threat,
   credential stuffing, session hijacking, crypto weaknesses, logging gaps,
   trust boundary violations, and API abuse.

2. INCORPORATE DEBATE: The Red Team may have found threats the analysts
   missed. The Blue Team may have correctly dismissed some with good arguments.
   Use the debate to calibrate risk scores. Red Team arguments that went
   unchallenged or poorly rebutted should become HIGH priority threats.

3. ASSIGN DREAD SCORES for every threat (each dimension 1-10):
   - damage (1-10): how bad is it if the attack succeeds?
   - reproducibility (1-10): how easy to repeat the attack?
   - exploitability (1-10): how easy to launch? (10 = trivial script, 1 = nation-state)
   - affected_users (1-10): breadth of impact (10 = all users, 1 = single admin)
   - discoverability (1-10): how easy to find the vulnerability?
   - dread_total = sum of all five (5-50)

   CRITICAL SCORING RULES:
   - Each dimension MUST have a DIFFERENT value. Real vulnerabilities have varying
     impact across dimensions. Uniform scores like 8/8/8/8/8 are NEVER acceptable.
   - Be REALISTIC for THIS specific system, not generic worst-case.
   - Internal systems behind VPNs/firewalls → lower Exploitability (3-5)
   - Systems without PII → lower Affected Users (2-4)
   - Well-known attack patterns → higher Discoverability (7-9)
   - Complex multi-step attacks → lower Reproducibility (2-4)
   - Example of GOOD asymmetric scoring: D=7, R=5, E=4, A=8, D=3 (total=27, High)

4. PRIORITIZE based on average score (total / 5):
   - avg >= 9.0 (total 45-50): Critical — fix immediately (RARE: max 2-3 per model)
   - avg >= 7.0 (total 35-44): High — fix this sprint
   - avg >= 4.0 (total 20-34): Medium — plan for next cycle
   - avg < 4.0  (total 5-19):  Low — monitor, accept risk
   Most threats in a well-scoped system should be Medium or High.
   Having more than 2-3 Critical threats is unusual and suggests score inflation.

5. PROPOSE MITIGATIONS that are concrete and specific to this system.
   Map to NIST 800-53, OWASP ASVS, or CIS controls when possible.
   Each mitigation MUST be actionable (e.g., "Implement WAF rule X" not just "Use WAF").

6. WRITE VERBOSE, DEVELOPER-FRIENDLY DESCRIPTIONS:
   Your threat model will be read by software developers with LIMITED security knowledge.
   Each threat's "description" field MUST be 4–6 sentences that:
   a) Explain WHAT the vulnerability or weakness is (define any security term used)
   b) Describe EXACTLY HOW an attacker would exploit it step by step against THIS specific system
   c) Name the specific components, endpoints, or data stores involved
   d) State WHAT concrete harm results (accounts compromised, data exfiltrated, service disrupted, etc.)
   e) Optionally: mention what a developer can look for in code to spot this issue
   AVOID vague one-liners like "Injection attack via user input". BE SPECIFIC.

   GOOD EXAMPLE:
   "The /api/search endpoint in the Express server passes the user-supplied 'query'
   parameter directly to a MongoDB $where clause without sanitization. An attacker
   crafts a query like \"this.password.match(/^a.*/)\" to enumerate password characters
   through boolean-based extraction (NoSQL Injection, CWE-943). By sending thousands
   of requests iterating through each character, the attacker can reconstruct all user
   passwords in plain text within hours. Every user account in the system would be
   fully compromised, including admin accounts, with no authentication required."

   Each "attack_path" MUST be a numbered sequence of concrete attacker steps:
   '1. Attacker identifies unauthenticated /admin endpoint via Shodan -> 2. Sends
    POST request with default credentials admin:admin -> 3. Receives admin session
    token -> 4. Exports full user database via /admin/export endpoint'

   Each "mitigation" MUST include what the developer should actually change in code
   or infrastructure (e.g., 'Replace string concatenation in UserRepository.findById()
   with parameterized query: db.query("SELECT * FROM users WHERE id = ?", [userId])').

CRITICAL OUTPUT RULE: Your entire response MUST be a single valid JSON object.
Do NOT include any markdown, explanations, reasoning, or code fences outside the JSON.
Start your response with { and end with }.

Required JSON schema:
{
    "threats": [
        {
            "id": "TM-001",
            "component": "affected component name",
            "description": "4-6 sentence developer-friendly description: what the vulnerability is, how an attacker exploits it step-by-step against THIS system, which components/endpoints are involved, and what concrete harm results",
            "methodology_sources": ["STRIDE", "PASTA"],
            "stride_category": "S or T or R or I or D or E",
            "attack_path": "1. Attacker does X against component Y -> 2. System responds with Z -> 3. Attacker achieves goal W (be specific to this system)",
            "damage": 8,
            "reproducibility": 7,
            "exploitability": 6,
            "affected_users": 9,
            "discoverability": 5,
            "dread_total": 35,
            "priority": "High",
            "mitigation": "specific, actionable mitigation with concrete implementation steps",
            "control_reference": "NIST AC-3, OWASP ASVS V3.5",
            "effort": "Low|Medium|High",
            "observations": "additional notes, cross-references to other threats",
            "status": "Open",
            "evidence_sources": [
                {"source_type": "rag|llm_knowledge|contextual|architecture", "source_name": "e.g. OWASP Top 10 2021 - A03", "excerpt": "relevant quote or reference supporting this threat"}
            ],
            "confidence_score": 0.85
        }
    ],
    "executive_summary": "executive summary of the complete threat model (3-5 sentences)",
    "methodology_contributions": {
        "STRIDE": "key contributions and unique findings",
        "PASTA": "key contributions and unique findings",
        "ATTACK_TREE": "key contributions and unique findings",
        "MAESTRO": "key contributions if applicable"
    }
}

EVIDENCE RULES:
- Every threat MUST have at least 1 evidence_source explaining WHERE the finding comes from.
- source_type "rag" = from retrieved documentation or knowledge base.
- source_type "llm_knowledge" = from your training data (cite the standard or framework).
- source_type "contextual" = derived from the specific system architecture or debate.
- source_type "architecture" = from the analyzed architecture diagram/description.
- The excerpt should be a concise reference (max 2 sentences) supporting the threat.

CONFIDENCE RULES:
- confidence_score is 0.0 to 1.0, reflecting how certain you are this threat is real and applicable.
- 0.9-1.0: Confirmed by multiple methodologies + architecture evidence
- 0.7-0.89: Supported by at least one methodology with clear architectural basis
- 0.5-0.69: Plausible but based on general knowledge, architecture details ambiguous
- 0.3-0.49: Speculative, included for completeness
- Below 0.3: Do not include — insufficient evidence

REMEMBER: The threats array MUST contain at least 15 items. This is non-negotiable.
"""


def _build_human_prompt(state: ThreatModelState) -> str:
    # ── Deduplicate methodology_reports ──
    # LangGraph operator.add + fan-in/debate loop can duplicate entries.
    seen_methodologies: set[str] = set()
    unique_reports: list[dict] = []
    for r in state.get("methodology_reports", []):
        methodology = r.get("methodology", "Unknown")
        if methodology in seen_methodologies:
            continue
        seen_methodologies.add(methodology)
        unique_reports.append(r)

    # Structured threats_raw from each analyst
    structured_threats_text = ""
    total_raw = 0
    for r in unique_reports:
        methodology = r.get("methodology", "Unknown")
        threats_raw = r.get("threats_raw", [])
        total_raw += len(threats_raw)
        if threats_raw:
            # Include ALL threats (up to 100) — generous char limit per methodology
            structured_threats_text += (
                f"\n### {methodology} — {len(threats_raw)} structured threats:\n"
                + json.dumps(threats_raw[:100], indent=2, ensure_ascii=False)[:40000]
                + "\n"
            )
        else:
            # Fallback to narrative report
            report = r.get("report", "")
            if len(report) > 15000:
                report = report[:15000] + "\n... [truncated]"
            structured_threats_text += (
                f"\n### {methodology} — narrative report:\n{report}\n"
            )

    # Debate — includes structured per-threat assessments for synthesis decisions
    debate_text = ""
    debate_verdicts_text = ""
    for entry in state.get("debate_history", []):
        side = entry.get("side", "?") if isinstance(entry, dict) else getattr(entry, "side", "?")
        rnd = entry.get("round", "?") if isinstance(entry, dict) else getattr(entry, "round", "?")
        arg = entry.get("argument", "") if isinstance(entry, dict) else getattr(entry, "argument", "")
        assessments = entry.get("threat_assessments", []) if isinstance(entry, dict) else getattr(entry, "threat_assessments", [])
        tag = "[RED TEAM]" if side == "red" else "[BLUE TEAM]"
        if len(arg) > 10000:
            arg = arg[:10000] + "\n... [truncated]"
        debate_text += f"\n{tag} (Round {rnd}):\n{arg}\n"

        # Structured verdicts — critical for synthesis weighting
        if assessments:
            for ta in assessments[:30]:
                threat_id = ta.get("threat_id", "?")
                if side == "red":
                    action = ta.get("action", "?")
                    reasoning = ta.get("reasoning", "")[:600]
                    proposed = ta.get("proposed_dread_total", "")
                    debate_verdicts_text += f"  RED {action}: {threat_id}"
                    if proposed:
                        debate_verdicts_text += f" (proposed DREAD: {proposed})"
                    debate_verdicts_text += f" — {reasoning}\n"
                else:
                    verdict = ta.get("verdict", "?")
                    mitigation = ta.get("mitigation", "")
                    control = ta.get("control_reference", "")
                    debate_verdicts_text += f"  BLUE {verdict}: {threat_id}"
                    if mitigation:
                        debate_verdicts_text += f" -> Mitigation: {mitigation[:400]}"
                    if control:
                        debate_verdicts_text += f" [{control}]"
                    debate_verdicts_text += "\n"

    from agentictm.agents.prompt_budget import PromptBudget

    pb = PromptBudget(system_prompt_chars=len(SYSTEM_PROMPT))

    components_json = json.dumps(state.get("components", []), indent=2, ensure_ascii=False)
    trust_json = json.dumps(state.get("trust_boundaries", []), indent=2, ensure_ascii=False)
    flows_json = json.dumps(state.get("data_flows", [])[:60], indent=2, ensure_ascii=False)

    fitted = pb.fit(
        sections={
            "system_description": state.get("system_description", "Not available"),
            "components": components_json,
            "trust_boundaries": trust_json,
            "data_flows": flows_json,
            "methodology": structured_threats_text,
            "debate": debate_text + "\n" + debate_verdicts_text,
            "raw_input": state.get("previous_tm_context", "No previous threat models available."),
        },
        priorities=[
            "system_description", "components", "data_flows",
            "trust_boundaries", "methodology", "debate", "raw_input",
        ],
    )

    return f"""\
## System Under Analysis
{fitted["system_description"]}

## Components ({len(state.get('components', []))} total)
{fitted["components"]}

## Trust Boundaries
{fitted["trust_boundaries"]}

## Data Flows
{fitted["data_flows"]}

## Analyst Findings ({total_raw} raw threats total across all methodologies)
{fitted["methodology"]}

## Red Team vs Blue Team Debate
{fitted["debate"] if fitted["debate"].strip() else "No debate occurred."}

## Previous Threat Model Context (RAG)
{fitted["raw_input"]}

Synthesize all of the above into the final threat model. Use RAG tools to
cross-reference with previous threat models for consistency. Blend your own synthesis
expertise with RAG findings for a comprehensive result. Return ONLY valid JSON — no other text.
"""


_SECURITY_TERMS = frozenset({
    "sql", "xss", "dos", "rce", "lfi", "rfi", "ssrf", "idor", "csrf", "jwt",
    "tls", "mtls", "mfa", "rbac", "iam", "oauth", "imap", "smtp",
    "injection", "inyección", "inyeccion", "bypass", "overflow", "exfiltration",
    "privilege", "escalation", "hijack", "spoofing", "tampering", "repudiation",
    "disclosure", "sanitization", "validation", "authentication",
})


def _tokenize(text: str) -> set[str]:
    """Extract a bag of meaningful tokens from text for similarity comparison."""
    import re
    tokens = set(re.findall(r"[a-záéíóúñü]{3,}", text.lower()))
    _STOP = {"the", "and", "for", "that", "this", "with", "from", "can", "are",
             "una", "del", "que", "los", "las", "para", "por", "con", "como",
             "ser", "está", "este", "esta", "uno", "más", "not", "but"}
    return tokens - _STOP


_ATTACK_CONCEPT_GROUPS = [
    {"sql", "injection", "inyección", "inyeccion", "database", "datos"},
    {"session", "sesión", "sesion", "cookie", "hijack", "admin"},
    {"file", "archivo", "mime", "extension", "sanitiz", "upload"},
    {"poll", "polling", "flood", "rate", "limit", "dos", "brut"},
    {"oauth", "token", "credential", "credencial", "secret", "secreto"},
    {"privilege", "escalat", "elevaci", "rbac", "permis"},
    {"log", "audit", "auditoría", "repudi", "trazab", "forens"},
    {"xss", "script", "render", "html", "content"},
]


def _weighted_jaccard(a: set[str], b: set[str]) -> float:
    """Jaccard with double weight for security-specific terms and a concept-group bonus."""
    if not a or not b:
        return 0.0
    intersection = a & b
    union = a | b
    sec_bonus = len(intersection & _SECURITY_TERMS)

    concept_bonus = 0.0
    for group in _ATTACK_CONCEPT_GROUPS:
        a_hits = len(a & group)
        b_hits = len(b & group)
        if a_hits >= 1 and b_hits >= 1:
            concept_bonus += 0.10

    base_sim = (len(intersection) + sec_bonus) / (len(union) + sec_bonus)
    return min(1.0, base_sim + concept_bonus)


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _normalize_component(comp: str) -> str:
    """Normalize component name for grouping: strip parentheticals, lowercase, trim."""
    import re
    comp = (comp or "").strip().lower()
    comp = re.sub(r"\(.*?\)", "", comp).strip()
    comp = re.sub(r"\s+", " ", comp)
    for noise in ("módulo de ", "modulo de ", "servicio de ", "capa "):
        comp = comp.replace(noise, "")
    return comp[:50]


_DEDUP_SIMILARITY_THRESHOLD = 0.25
_CROSS_GROUP_SIMILARITY_THRESHOLD = 0.28


def _merge_cluster(threats: list[dict], cluster_indices: list[int]) -> dict:
    """Merge a cluster of duplicate threats: keep richest description, combine metadata."""
    group = [threats[idx] for idx in cluster_indices]
    best = max(group, key=lambda t: len(t.get("description") or ""))
    best = dict(best)
    methodologies = {t.get("methodology", "") for t in group if t.get("methodology")}
    if len(methodologies) > 1:
        best["methodology"] = ", ".join(sorted(methodologies))
    if not best.get("mitigation"):
        for t in group:
            if t.get("mitigation"):
                best["mitigation"] = t["mitigation"]
                break
    if not best.get("control_reference"):
        for t in group:
            if t.get("control_reference"):
                best["control_reference"] = t["control_reference"]
                break
    if not (best.get("component") or "").strip():
        for t in group:
            if (t.get("component") or "").strip():
                best["component"] = t["component"]
                break
    return best


def _deduplicate_threats(threats: list[dict]) -> list[dict]:
    """Two-pass semantic deduplication.

    Pass 1: Group by normalized component, merge within groups (Jaccard >= 0.35).
    Pass 2: Cross-group dedup for threats with the same STRIDE category,
            using a higher threshold (Jaccard >= 0.45) to catch the same
            vulnerability described under different component names.
    """
    # ── Pass 1: intra-component dedup ──
    comp_groups: dict[str, list[int]] = {}
    for i, t in enumerate(threats):
        key = _normalize_component(t.get("component", ""))
        comp_groups.setdefault(key, []).append(i)

    merged_indices_p1: set[int] = set()
    pass1_winners: list[dict] = []

    for _comp_key, indices in comp_groups.items():
        if len(indices) == 1:
            pass1_winners.append(threats[indices[0]])
            continue

        token_cache = {}
        for idx in indices:
            token_cache[idx] = _tokenize(threats[idx].get("description", ""))

        local_clusters: list[list[int]] = []
        assigned: set[int] = set()

        for i_pos, i_idx in enumerate(indices):
            if i_idx in assigned:
                continue
            cluster = [i_idx]
            assigned.add(i_idx)
            for j_idx in indices[i_pos + 1:]:
                if j_idx in assigned:
                    continue
                same_stride = (
                    threats[i_idx].get("stride_category", "")
                    == threats[j_idx].get("stride_category", "")
                    and threats[i_idx].get("stride_category", "")
                )
                threshold = 0.15 if same_stride else _DEDUP_SIMILARITY_THRESHOLD
                sim = _weighted_jaccard(token_cache[i_idx], token_cache[j_idx])
                if sim >= threshold:
                    cluster.append(j_idx)
                    assigned.add(j_idx)
            local_clusters.append(cluster)

        for cluster in local_clusters:
            winner = _merge_cluster(threats, cluster)
            pass1_winners.append(winner)
            if len(cluster) > 1:
                merged_indices_p1.update(cluster[1:])

    if merged_indices_p1:
        logger.info(
            "[Dedup P1] Intra-component: %d -> %d (merged %d across %d groups)",
            len(threats), len(pass1_winners), len(merged_indices_p1), len(comp_groups),
        )

    # ── Pass 2: cross-component dedup (same STRIDE + high description similarity) ──
    stride_groups: dict[str, list[int]] = {}
    for i, t in enumerate(pass1_winners):
        cat = t.get("stride_category", "?")
        stride_groups.setdefault(cat, []).append(i)

    token_cache_p2 = {i: _tokenize(t.get("description", "")) for i, t in enumerate(pass1_winners)}
    absorbed: set[int] = set()
    pass2_winners: list[dict] = []

    for _cat, indices in stride_groups.items():
        if len(indices) <= 1:
            continue
        for i_pos, i_idx in enumerate(indices):
            if i_idx in absorbed:
                continue
            cluster = [i_idx]
            for j_idx in indices[i_pos + 1:]:
                if j_idx in absorbed:
                    continue
                sim = _weighted_jaccard(token_cache_p2[i_idx], token_cache_p2[j_idx])
                if sim >= _CROSS_GROUP_SIMILARITY_THRESHOLD:
                    cluster.append(j_idx)
                    absorbed.add(j_idx)
            if len(cluster) > 1:
                winner = _merge_cluster(pass1_winners, cluster)
                pass1_winners[i_idx] = winner
                absorbed.update(cluster[1:])

    pass2_winners = [t for i, t in enumerate(pass1_winners) if i not in absorbed]

    if absorbed:
        logger.info(
            "[Dedup P2] Cross-component: %d -> %d (merged %d with same STRIDE + similar desc)",
            len(pass1_winners), len(pass2_winners), len(absorbed),
        )

    total_merged = len(merged_indices_p1) + len(absorbed)
    if total_merged:
        logger.info(
            "[Dedup] Reduced %d threats to %d (merged %d duplicates across %d component groups)",
            len(threats), len(pass2_winners), total_merged, len(comp_groups),
        )
    return pass2_winners


def _extract_threats_from_reports(state: ThreatModelState) -> list[dict]:
    """Extrae amenazas directamente de los reportes de metodología.

    Cada analista produce un JSON con 'threats' o 'threats_raw' que podemos
    reutilizar si el synthesizer no produce JSON válido.
    Deduplicates methodology_reports from LangGraph fan-in duplication.
    """
    threats = []
    threat_counter = 1

    # ── Deduplicate methodology_reports ──
    seen_methodologies: set[str] = set()
    unique_reports: list[dict] = []
    for report in state.get("methodology_reports", []):
        methodology = report.get("methodology", "Unknown")
        if methodology in seen_methodologies:
            continue
        seen_methodologies.add(methodology)
        unique_reports.append(report)

    for report in unique_reports:
        methodology = report.get("methodology", "Unknown")
        raw_threats = report.get("threats_raw", [])

        for raw in raw_threats:
            # Normalizar: cada analista usa campos ligeramente distintos
            description = _to_str(
                raw.get("description")
                or raw.get("attack_scenario")
                or raw.get("leaf_action")
                or ""
            )
            component = _to_str(
                raw.get("component")
                or raw.get("target_asset")
                or raw.get("element")
                or ""
            )
            # ── STRIDE: normalize, then infer from content if invalid ──
            stride_cat = _normalize_stride_category(
                _to_str(raw.get("stride_category") or raw.get("category") or "")
            )
            if not stride_cat:
                stride_cat = _infer_stride_category({"description": description, "attack_path": _to_str(raw.get("attack_path", "")), "component": component, "methodology": methodology})

            # ── Mitigation: check multiple field names across analyst formats ──
            mitigation = _to_str(
                raw.get("mitigation")
                or raw.get("mitigations")
                or raw.get("countermeasures")
                or raw.get("recommendations")
                or raw.get("controls")
                or raw.get("remediation")
                or ""
            )
            if not mitigation and stride_cat in _DEFAULT_MITIGATIONS:
                mitigation = _DEFAULT_MITIGATIONS[stride_cat]

            # ── Control reference: mitre_technique goes here, not mitigation ──
            control_ref = _to_str(
                raw.get("control_reference")
                or raw.get("references")
                or raw.get("mitre_technique")
                or ""
            )
            if not control_ref and stride_cat in _DEFAULT_CONTROLS:
                control_ref = _DEFAULT_CONTROLS[stride_cat]

            # Asignar DREAD scores estimados según prioridad/dificultad
            risk = _to_str(
                raw.get("risk_level")
                or raw.get("risk")
                or raw.get("difficulty")
                or "Medium"
            )
            risk_lower = risk.lower()

            if risk_lower in ("critical", "easy"):
                dread_base = 8
            elif risk_lower == "high":
                dread_base = 7
            elif risk_lower in ("medium", "moderate"):
                dread_base = 5
            else:
                dread_base = 3

            dread_base = _clamp_dread(dread_base)
            scores = _asymmetric_dread(dread_base, stride_cat, description)
            dread_total = sum(scores.values())
            priority = _compute_priority(dread_total)

            threats.append({
                "id": f"TM-{threat_counter:03d}",
                "component": component,
                "description": description,
                "methodology": methodology,
                "stride_category": stride_cat,
                "attack_path": _to_str(raw.get("attack_path", "")),
                "damage": scores["damage"],
                "reproducibility": scores["reproducibility"],
                "exploitability": scores["exploitability"],
                "affected_users": scores["affected_users"],
                "discoverability": scores["discoverability"],
                "dread_total": dread_total,
                "priority": priority,
                "mitigation": mitigation,
                "control_reference": control_ref,
                "effort": raw.get("effort", "Medium"),
                "observations": f"[Fallback] Extraído de {methodology}",
                "status": "Open",
                "evidence_sources": raw.get("evidence_sources", []),
                "confidence_score": float(raw.get("confidence_score", 0.3)),
                "justification": None,
            })
            threat_counter += 1

    raw_count = len(threats)

    # ── Semantic deduplication ──
    threats = _deduplicate_threats(threats)

    logger.info(
        "[Fallback] Extracted %d threats from methodology reports (%d before dedup)",
        len(threats), raw_count,
    )
    return threats


_COMPONENT_SYNONYMS: dict[str, list[str]] = {
    "database": ["base de datos", "db", "database", "almacen", "almacén"],
    "service": ["servicio", "service", "worker", "daemon"],
    "gateway": ["gateway", "puerta", "interfaz", "pasarela"],
    "interface": ["interfaz", "interface", "panel", "pantalla", "ui"],
    "engine": ["motor", "engine", "procesador"],
    "admin": ["admin", "administración", "administracion", "administrador"],
    "user": ["usuario", "user"],
    "email": ["email", "correo", "mail", "buzón", "buzon"],
    "file": ["archivo", "file", "fichero", "adjunto", "attachment"],
    "secrets": ["secreto", "secrets", "credential", "credencial"],
    "rule": ["regla", "rule", "norma"],
}


def _infer_component_from_description(
    desc: str,
    known_components: list[str],
) -> str:
    """Try to infer the component from the threat description by matching
    against the parsed architecture component names."""
    desc_lower = desc.lower()

    # Exact substring match first
    for comp in known_components:
        if comp.lower() in desc_lower:
            return comp

    # Word-level matching with synonym expansion
    best_match = ""
    best_score = 0
    for comp in known_components:
        comp_lower = comp.lower()
        comp_words = [w for w in comp_lower.split() if len(w) > 2]
        score = 0
        for w in comp_words:
            if w in desc_lower:
                score += 1
                continue
            synonyms = _COMPONENT_SYNONYMS.get(w, [])
            if any(syn in desc_lower for syn in synonyms):
                score += 1
        if score > best_score:
            best_score = score
            best_match = comp
    if best_score >= 2:
        return best_match
    # Accept single strong word match for short component names
    if best_score >= 1 and best_match:
        comp_words = [w for w in best_match.lower().split() if len(w) > 2]
        if len(comp_words) <= 2:
            return best_match
    return ""


def _apply_quality_gates(
    threats: list[dict],
    *,
    max_threats: int = 30,
    known_components: list[str] | None = None,
) -> list[dict]:
    """Post-processing quality gate applied to ALL final threats.

    1. Drop garbage (very short descriptions, no real content)
    2. Infer missing component names from description + architecture
    3. Normalize STRIDE and guarantee mitigations/controls
    4. Penalize uniform DREAD scores
    5. Cap count at max_threats (keep highest DREAD scores)
    6. Log quality stats
    """
    before = len(threats)

    # ── 1. Drop garbage ──
    filtered: list[dict] = []
    for t in threats:
        desc = (t.get("description") or "").strip()
        if len(desc) < 40:
            continue
        if " " not in desc:
            continue
        filtered.append(t)

    dropped = before - len(filtered)
    if dropped:
        logger.info("[QualityGate] Dropped %d garbage threats (<%d chars or no content)", dropped, 40)

    # ── 2. Infer missing component names ──
    comp_list = known_components or []
    comp_filled = 0
    for t in filtered:
        if not (t.get("component") or "").strip() and comp_list:
            inferred = _infer_component_from_description(
                t.get("description", ""), comp_list
            )
            if inferred:
                t["component"] = inferred
                comp_filled += 1
    if comp_filled:
        logger.info("[QualityGate] Inferred component for %d threats from architecture", comp_filled)

    # ── 3. Normalize STRIDE categories and guarantee mitigations/controls ──
    stride_fixed = 0
    mit_filled = 0
    ctrl_filled = 0
    for t in filtered:
        raw_stride = t.get("stride_category", "")
        normalized = _normalize_stride_category(raw_stride)
        if raw_stride and not normalized:
            stride_fixed += 1
        if not normalized:
            normalized = _infer_stride_category(t)
        t["stride_category"] = normalized

        if not (t.get("mitigation") or "").strip():
            t["mitigation"] = _DEFAULT_MITIGATIONS.get(normalized, _DEFAULT_MITIGATIONS.get("I", ""))
            mit_filled += 1
        if not (t.get("control_reference") or "").strip():
            t["control_reference"] = _DEFAULT_CONTROLS.get(normalized, _DEFAULT_CONTROLS.get("I", ""))
            ctrl_filled += 1

    if stride_fixed:
        logger.info("[QualityGate] Fixed %d invalid STRIDE categories (e.g. LLM02|ASI03 -> inferred)", stride_fixed)

    if mit_filled:
        logger.info("[QualityGate] Filled %d empty mitigations with STRIDE defaults", mit_filled)
    if ctrl_filled:
        logger.info("[QualityGate] Filled %d empty control_references with STRIDE defaults", ctrl_filled)

    # ── 4. Recalculate priority with calibrated bands ──
    for t in filtered:
        d = t.get("damage", 5)
        r = t.get("reproducibility", 5)
        e = t.get("exploitability", 5)
        a = t.get("affected_users", 5)
        disc = t.get("discoverability", 5)
        total = d + r + e + a + disc
        t["dread_total"] = total
        t["priority"] = _compute_priority(total)

    # ── 5. Cap count ──
    if len(filtered) > max_threats:
        filtered.sort(key=lambda t: t.get("dread_total", 0), reverse=True)
        logger.info("[QualityGate] Capping threats from %d to %d (by DREAD score)", len(filtered), max_threats)
        filtered = filtered[:max_threats]

    # ── 6. Log quality stats ──
    descs = [len((t.get("description") or "")) for t in filtered]
    short = sum(1 for d in descs if d < 150)
    prio_dist: dict[str, int] = {}
    stride_dist: dict[str, int] = {}
    for t in filtered:
        p = t.get("priority", "Unknown")
        prio_dist[p] = prio_dist.get(p, 0) + 1
        s = t.get("stride_category", "?")
        stride_dist[s] = stride_dist.get(s, 0) + 1

    missing_stride = [c for c in "STRIDE" if c not in stride_dist]
    if missing_stride:
        logger.warning(
            "[QualityGate] STRIDE coverage gaps: missing %s (%s). "
            "Consider improving methodology prompts for these categories.",
            ", ".join(missing_stride),
            {
                "S": "Spoofing", "T": "Tampering", "R": "Repudiation",
                "I": "Information Disclosure", "D": "Denial of Service",
                "E": "Elevation of Privilege",
            },
        )

    empty_comp = sum(1 for t in filtered if not (t.get("component") or "").strip())
    logger.info(
        "[QualityGate] Final: %d threats (dropped=%d, mit_filled=%d, ctrl_filled=%d, "
        "short_desc=%d, empty_comp=%d, priority_dist=%s, stride_dist=%s)",
        len(filtered), dropped, mit_filled, ctrl_filled, short, empty_comp,
        prio_dist, stride_dist,
    )
    return filtered


_AI_KEYWORDS = frozenset({
    "llm", "large language model", "machine learning", " ml ",
    "neural network", "deep learning", "nlp", "natural language processing",
    "chatbot", "generative ai", "transformer", "embedding model",
    "rag pipeline", "vector database", "prompt injection", "model training",
    "fine-tun", "inference", "ai agent", "ai model", "langchain",
    "openai", "anthropic", "artificial intelligence",
})

_AI_THREAT_MARKERS = frozenset({
    "llm", "prompt inject", "model poison", "training data",
    "hallucin", "alucinaci", "jailbreak", "adversarial input",
    "bias, fairness", "nlp", "machine learning", "embedding",
    "asi0", "lml0", "plot4ai",
})


def _system_has_ai_components(state: dict) -> bool:
    """Check whether the system under analysis uses AI/ML/LLM components."""
    text = " ".join([
        str(state.get("system_description", "")),
        " ".join(
            str(c.get("name", "") if isinstance(c, dict) else c) + " " +
            str(c.get("description", "") if isinstance(c, dict) else "")
            for c in state.get("components", [])
        ),
    ]).lower()
    return any(kw in text for kw in _AI_KEYWORDS)


def _threat_references_architecture(
    threat: dict,
    known_component_names: set[str],
    system_desc_lower: str,
) -> bool:
    """Check if a threat is grounded in the actual system architecture.

    Returns True if the threat description mentions any known component or
    a technology/keyword that appears in the system description.
    """
    desc_lower = (threat.get("description") or "").lower()
    comp_lower = (threat.get("component") or "").lower()
    combined = desc_lower + " " + comp_lower

    for comp_name in known_component_names:
        words = [w for w in comp_name.split() if len(w) > 2]
        if any(w in combined for w in words):
            return True

    tech_keywords = set()
    import re
    for word in re.findall(r"[a-záéíóúñü]{3,}", system_desc_lower):
        if len(word) >= 4 and word not in {"the", "and", "for", "that", "this", "with", "from",
                                             "una", "del", "que", "los", "las", "para", "por",
                                             "con", "como", "ser", "está", "este", "esta",
                                             "sistema", "system", "data", "datos", "información"}:
            tech_keywords.add(word)
    overlap = sum(1 for kw in tech_keywords if kw in combined)
    return overlap >= 2


_VACUOUS_THREAT_MARKERS = [
    "currently empty",
    "are currently empty",
    "no data stores or specific components defined",
    "no data flows or data stores are defined",
    "no defined entry point",
    "no specific information currently at risk",
    "there is no known mechanism",
    "there is no current risk",
    "no data stores or specific components",
    "in a hypothetical scenario",
    "in a typical scenario, if",
    "no componentes definidos",
    "no hay flujos de datos definidos",
    "no hay componentes específicos",
    "actualmente vacíos",
    "actualmente vacío",
    "no se han definido componentes",
]


def _filter_irrelevant_threats(
    threats: list[dict],
    state: dict,
) -> list[dict]:
    """Remove threats that don't apply to this system's architecture.

    1. Drop vacuous threats that explicitly state components/data are empty.
    2. If the system has no AI/ML components, drop AI-specific threats.
    3. Reduce confidence of threats with no connection to the architecture
       (but don't drop them outright — lower their DREAD scores instead).
    """
    has_ai = _system_has_ai_components(state)
    known_components_raw = [
        c.get("name", "") if isinstance(c, dict) else str(c)
        for c in state.get("components", [])
    ]
    known_component_names = {
        _normalize_component(c) for c in known_components_raw if c
    }
    system_desc_lower = (state.get("system_description", "") or "").lower()

    filtered = []
    dropped_ai = 0
    dropped_vacuous = 0
    demoted = 0

    for t in threats:
        desc_lower = (t.get("description") or "").lower()
        methodology = (t.get("methodology") or "").upper()

        if any(marker in desc_lower for marker in _VACUOUS_THREAT_MARKERS):
            dropped_vacuous += 1
            continue

        component = (t.get("component") or "").lower()
        if "placeholder" in component:
            dropped_vacuous += 1
            continue

        if not has_ai and "AI_THREAT" in methodology:
            is_ai_specific = any(marker in desc_lower for marker in _AI_THREAT_MARKERS)
            if is_ai_specific:
                dropped_ai += 1
                continue

        stride_cat = (t.get("stride_category") or "").lower()
        if not has_ai and any(marker in stride_cat for marker in ("llm", "asi", "bias")):
            dropped_ai += 1
            continue

        if known_component_names and not _threat_references_architecture(
            t, known_component_names, system_desc_lower
        ):
            for dim in ("damage", "reproducibility", "exploitability", "affected_users", "discoverability"):
                old_val = t.get(dim, 5)
                t[dim] = max(1, old_val - 1)
            t["dread_total"] = sum(t.get(d, 1) for d in ("damage", "reproducibility", "exploitability", "affected_users", "discoverability"))
            t["priority"] = _compute_priority(t["dread_total"])
            t["confidence_score"] = max(0.1, float(t.get("confidence_score", 0.5)) - 0.15)
            demoted += 1

        filtered.append(t)

    if dropped_vacuous:
        logger.info(
            "[ArchFilter] Dropped %d vacuous/placeholder threats (empty architecture references)",
            dropped_vacuous,
        )
    if dropped_ai:
        logger.info(
            "[ArchFilter] Dropped %d AI/LLM-specific threats (system has no AI components)",
            dropped_ai,
        )
    if demoted:
        logger.info("[ArchFilter] Demoted %d threats with weak architectural grounding (DREAD -1/dim)", demoted)

    return filtered


_TRANSLATE_SYSTEM_PROMPT = """\
You are a professional security content translator.

Task: translate threat model text fields from English to neutral professional Spanish.

Rules:
1. Keep technical terms, acronyms, and framework references in English:
   STRIDE, DREAD, XSS, IDOR, SSRF, JWT, NIST, CIS, OWASP, CAPEC, CWE,
   ATT&CK, CVE, API, SQL, IAM, S3, OAuth, MFA, TLS, RBAC, PII, DoS, etc.
2. Return ONLY a JSON array with {"index": <int>, "description": "...", "mitigation": "...", "attack_path": "..."}.
3. Match the "index" to the position in the input array (0-based).
4. Keep the meaning, severity, and specificity identical — only change the language.
5. If a field is already in Spanish, return it unchanged.
"""

_TRANSLATE_BATCH_SIZE = 12
_TRANSLATE_TIMEOUT = 180


def _detect_english(text: str) -> bool:
    """Heuristic: return True if text looks predominantly English."""
    if not text or len(text) < 20:
        return False
    english_markers = [
        "the ", " is ", " are ", " was ", " with ", " this ", " that ",
        " could ", " would ", " should ", " which ", " have ", " from ",
        " into ", " without ", " their ", " there ", " however ",
        " if an ", " an attacker", " allowing ", " ensure ",
    ]
    text_lower = text.lower()
    hits = sum(1 for m in english_markers if m in text_lower)
    return hits >= 3


def _translate_baseline_threats(
    threats: list[dict],
    llm: "BaseChatModel",
    output_language: str = "en",
) -> list[dict]:
    """Translate English baseline threats to the target language via batched LLM calls.

    Only processes threats whose description looks English. On failure, returns
    originals unchanged (never loses data).
    """
    if output_language != "es":
        return threats

    english_indices: list[int] = []
    for i, t in enumerate(threats):
        desc = t.get("description", "")
        mit = t.get("mitigation", "")
        if _detect_english(desc) or _detect_english(mit):
            english_indices.append(i)

    if not english_indices:
        logger.info("[Translate] All %d baseline threats appear to be in Spanish -- skipping", len(threats))
        return threats

    logger.info(
        "[Translate] %d/%d baseline threats detected as English — translating to Spanish",
        len(english_indices), len(threats),
    )

    import concurrent.futures

    for batch_start in range(0, len(english_indices), _TRANSLATE_BATCH_SIZE):
        batch_idx = english_indices[batch_start:batch_start + _TRANSLATE_BATCH_SIZE]
        batch_items = []
        for pos, idx in enumerate(batch_idx):
            t = threats[idx]
            batch_items.append({
                "index": pos,
                "description": t.get("description", ""),
                "mitigation": t.get("mitigation", ""),
                "attack_path": t.get("attack_path", ""),
            })

        human_prompt = (
            "Translate these threat fields to professional Spanish:\n\n"
            f"```json\n{json.dumps(batch_items, indent=2, ensure_ascii=False)}\n```"
        )

        try:
            def _invoke_translate():
                return invoke_agent(
                    llm, _TRANSLATE_SYSTEM_PROMPT, human_prompt,
                    agent_name="BaselineTranslator",
                )

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_invoke_translate)
                response = future.result(timeout=_TRANSLATE_TIMEOUT)

            parsed = extract_json_from_response(response)
            translated_items: list[dict] = []
            if isinstance(parsed, list):
                translated_items = [e for e in parsed if isinstance(e, dict)]
            elif isinstance(parsed, dict):
                translated_items = _find_threats_array(parsed) or ([parsed] if "description" in parsed else [])

            applied = 0
            for item in translated_items:
                try:
                    pos = int(item.get("index", -1))
                except (TypeError, ValueError):
                    continue
                if 0 <= pos < len(batch_idx):
                    real_idx = batch_idx[pos]
                    new_desc = _to_str(item.get("description", ""))
                    new_mit = _to_str(item.get("mitigation", ""))
                    new_path = _to_str(item.get("attack_path", ""))
                    if new_desc and len(new_desc) > 20:
                        threats[real_idx]["description"] = new_desc
                        applied += 1
                    if new_mit and len(new_mit) > 10:
                        threats[real_idx]["mitigation"] = new_mit
                    if new_path and len(new_path) > 10:
                        threats[real_idx]["attack_path"] = new_path

            logger.info(
                "[Translate] Batch %d-%d: translated %d/%d threats",
                batch_start, batch_start + len(batch_idx), applied, len(batch_idx),
            )
        except concurrent.futures.TimeoutError:
            logger.warning("[Translate] Batch %d timed out after %ds -- keeping originals", batch_start, _TRANSLATE_TIMEOUT)
        except Exception as exc:
            logger.warning("[Translate] Batch %d failed: %s -- keeping originals", batch_start, exc)

    return threats


_ENRICH_SYSTEM_PROMPT = """\
You are a senior security engineer improving threat descriptions for developers.

You receive a list of threats that are too short or vague. For EACH threat, you must:

1. EXPAND the description to 3-5 sentences that explain:
   - WHAT the vulnerability is (specific CWE/technique if applicable)
   - HOW an attacker exploits it step-by-step against the given component
   - WHAT concrete harm results (data exfiltration, service disruption, etc.)
   Write for developers who are smart but lack security expertise.

2. PROVIDE a specific mitigation (2-3 sentences) with concrete implementation steps.
   Reference the component name and suggest actual code/config changes.

3. PROVIDE a control_reference (NIST 800-53, OWASP ASVS, CIS controls).

Return ONLY a JSON array where each element has:
  {"index": 0, "description": "...", "mitigation": "...", "control_reference": "..."}

Match the "index" to the position in the input array (0-based).
Generate ALL text in professional Spanish (neutral Latin American).
Keep technical terms, acronyms, and framework references in English.
"""

_ENRICH_BATCH_SIZE = 10
_ENRICH_TIMEOUT = 180


def _enrich_weak_threats(
    threats: list[dict],
    llm: BaseChatModel,
    system_description: str = "",
) -> list[dict]:
    """Expand short descriptions and fill empty mitigations via a batched LLM call.

    Only processes threats below quality threshold.  On failure, returns
    originals unchanged (never loses data).
    """
    weak_indices: list[int] = []
    default_mit_set = set(_DEFAULT_MITIGATIONS.values())

    for i, t in enumerate(threats):
        desc_len = len((t.get("description") or "").strip())
        mit = (t.get("mitigation") or "").strip()
        is_default_mit = mit in default_mit_set
        if desc_len < 150 or not mit or is_default_mit:
            weak_indices.append(i)

    if not weak_indices:
        logger.info("[Enrich] All %d threats meet quality threshold -- skipping enrichment", len(threats))
        return threats

    logger.info(
        "[Enrich] %d/%d threats below quality threshold — enriching in batches of %d",
        len(weak_indices), len(threats), _ENRICH_BATCH_SIZE,
    )

    import concurrent.futures

    for batch_start in range(0, len(weak_indices), _ENRICH_BATCH_SIZE):
        batch_idx = weak_indices[batch_start:batch_start + _ENRICH_BATCH_SIZE]
        batch_items = []
        for pos, idx in enumerate(batch_idx):
            t = threats[idx]
            batch_items.append({
                "index": pos,
                "component": t.get("component", "Unknown"),
                "description": t.get("description", ""),
                "stride_category": t.get("stride_category", ""),
                "attack_path": t.get("attack_path", ""),
            })

        human_prompt = f"System context: {system_description[:2000]}\n\nThreats to enrich:\n{json.dumps(batch_items, indent=2, ensure_ascii=False)}"

        try:
            from agentictm.agents.base import invoke_agent

            def _invoke():
                return invoke_agent(
                    llm, _ENRICH_SYSTEM_PROMPT, human_prompt,
                    agent_name="Enrichment",
                )

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_invoke)
                response = future.result(timeout=_ENRICH_TIMEOUT)

            parsed = extract_json_from_response(response)
            enriched_items: list[dict] = []
            if isinstance(parsed, list):
                enriched_items = [e for e in parsed if isinstance(e, dict)]
            elif isinstance(parsed, dict):
                enriched_items = _find_threats_array(parsed) or ([parsed] if "description" in parsed else [])

            applied = 0
            for item in enriched_items:
                try:
                    pos = int(item.get("index", -1))
                except (TypeError, ValueError):
                    continue
                if 0 <= pos < len(batch_idx):
                    real_idx = batch_idx[pos]
                    new_desc = _to_str(item.get("description", ""))
                    new_mit = _to_str(item.get("mitigation", ""))
                    new_ctrl = _to_str(item.get("control_reference", ""))
                    if new_desc and len(new_desc) > len(threats[real_idx].get("description", "")):
                        threats[real_idx]["description"] = new_desc
                        applied += 1
                    if new_mit and len(new_mit) > len(threats[real_idx].get("mitigation", "")):
                        threats[real_idx]["mitigation"] = new_mit
                    if new_ctrl and len(new_ctrl) > len(threats[real_idx].get("control_reference", "")):
                        threats[real_idx]["control_reference"] = new_ctrl

            logger.info(
                "[Enrich] Batch %d-%d: enriched %d/%d threats",
                batch_start, batch_start + len(batch_idx), applied, len(batch_idx),
            )
        except concurrent.futures.TimeoutError:
            logger.warning("[Enrich] Batch %d timed out after %ds -- keeping originals", batch_start, _ENRICH_TIMEOUT)
        except Exception as exc:
            logger.warning("[Enrich] Batch %d failed: %s -- keeping originals", batch_start, exc)

    return threats


def run_threat_synthesizer(
    state: ThreatModelState,
    llm: BaseChatModel,
    config: AgenticTMConfig | None = None,
) -> dict:
    """Nodo de LangGraph: Threat Synthesizer (Deep Thinker).

    HYBRID STRATEGY:
    1. Always extract the BASELINE of ALL raw threats from analyst reports.
    2. Try LLM synthesis for enrichment/deduplication.
    3. If LLM produces enough threats (>= MIN_THRESHOLD), use LLM output.
    4. Otherwise, use baseline threats (all analyst raw threats), which
       guarantees we NEVER lose threats.
    5. Apply category-based IDs (WEB-01, INF-02, etc.) to ALL threats.

    Lee: methodology_reports, debate_history, components, trust_boundaries
    Escribe: threats_final
    """
    logger.info("[Synthesizer] Combining analysis from all methodologies...")

    # ── Step 1: Build the baseline (ALL raw threats from all analysts) ──
    baseline_threats = _extract_threats_from_reports(state)
    baseline_count = len(baseline_threats)
    logger.info(
        "[Synthesizer] BASELINE: %d threats extracted from analyst reports",
        baseline_count,
    )

    # Self-reflection from config
    _self_reflect = False
    if config and config.pipeline.self_reflection_enabled and config.pipeline.self_reflection_rounds > 0:
        _self_reflect = True
        logger.info("[Synthesizer] Self-reflection ENABLED (%d rounds)", config.pipeline.self_reflection_rounds)

    # Safety thresholds (use config if available for I13)
    _target = config.pipeline.target_threats if config else 20
    _min_t = config.pipeline.min_threats if config else 8
    MIN_LLM_THREATS = max(_min_t, int(baseline_count * 0.6))  # LLM must produce at least 60% of raw count
    logger.info(
        "[Synthesizer] MIN_LLM_THREATS threshold: %d (baseline=%d, target=%d)",
        MIN_LLM_THREATS, baseline_count, _target,
    )

    # Build dynamic system prompt with configurable target (I13)
    _max_t = config.pipeline.max_threats if config else 40
    effective_system_prompt = SYSTEM_PROMPT
    if _target != 20:  # Override the default 15-25 range if config differs
        effective_system_prompt = effective_system_prompt.replace(
            "**MANDATORY MINIMUM: You MUST generate AT LEAST 15 distinct, well-defined threats.**\n"
            "   Professional threat models contain 15-25 threats. Aim for 18-25 threats",
            f"**MANDATORY MINIMUM: You MUST generate AT LEAST {_min_t} distinct, well-defined threats.**\n"
            f"   Professional threat models contain {_min_t}-{_max_t} threats. Aim for {_target}-{_target + 5} threats",
        )

    # ── Add Spanish output directive when configured ──
    _output_lang = config.pipeline.output_language if config else "en"
    if _output_lang == "es":
        effective_system_prompt += """

LANGUAGE RULE — CRITICAL:
You MUST generate ALL text content in professional Spanish (neutral Latin American).
This applies to: descriptions, attack_paths, mitigations, executive_summary,
observations, methodology_contributions, and evidence_source excerpts.
Keep the following in English:
  - Field/key names in JSON (id, component, stride_category, etc.)
  - Industry-standard acronyms and technical terms (STRIDE, DREAD, XSS, IDOR, SSRF, JWT,
    NIST, CIS, OWASP, CAPEC, CWE, ATT&CK, CVE, API, SQL, IAM, S3, etc.)
  - DREAD numeric scores and priority labels (Critical, High, Medium, Low)
Example description in Spanish:
  "Un atacante compromete las credenciales de un usuario a través de phishing, roba su
   token JWT y lo utiliza para acceder al API Gateway. Luego explota una función Lambda
   mal configurada para extraer metadatos de DynamoDB."
"""

    human_prompt = _build_human_prompt(state)
    logger.info(
        "[Synthesizer] Prompt sizes: system=%d chars | human=%.1f KB | target=%d threats",
        len(effective_system_prompt), len(human_prompt) / 1024, _target,
    )
    t0 = time.perf_counter()

    # ── Step 2: Try LLM synthesis ──
    import concurrent.futures
    SYNTH_TIMEOUT = 900  # 15 minutes hard cap

    def _invoke_synth():
        return invoke_agent(
            llm, effective_system_prompt, human_prompt,
            tools=ALL_RAG_TOOLS,
            max_tool_rounds=3,
            agent_name="Synthesizer",
            enable_self_reflection=_self_reflect,
            pre_invoke_tools=True,
        )

    llm_threats: list[dict] = []
    executive_summary = ""
    raw_response = ""

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_invoke_synth)
            response = future.result(timeout=SYNTH_TIMEOUT)
            raw_response = response
    except concurrent.futures.TimeoutError:
        elapsed = time.perf_counter() - t0
        logger.error(
            "[Synthesizer] TIMEOUT after %.0fs (limit=%ds). Using baseline threats.",
            elapsed, SYNTH_TIMEOUT,
        )
        response = ""
    except Exception as exc:
        logger.error("[Synthesizer] LLM invocation failed: %s. Using baseline threats.", exc)
        response = ""

    elapsed_llm = time.perf_counter() - t0
    if response:
        logger.info("[Synthesizer] LLM invoke completed in %.1fs | response=%d chars", elapsed_llm, len(response))
    else:
        logger.warning("[Synthesizer] No LLM response, will use baseline threats.")

    # ── Step 3: Parse LLM response ──
    if response:
        parsed = extract_json_from_response(response)

        threat_items: list[dict] = []
        if isinstance(parsed, dict):
            executive_summary = parsed.get("executive_summary", "")
            threat_items = _find_threats_array(parsed)
        elif isinstance(parsed, list):
            logger.info(
                "[Synthesizer] Got list instead of dict from JSON parse "
                "(likely truncated output). Treating as threats array (%d items).",
                len(parsed),
            )
            threat_items = [t for t in parsed if isinstance(t, dict)]
        elif parsed is None:
            logger.warning(
                "[Synthesizer] extract_json_from_response returned None. "
                "Response first 500 chars: %s",
                response[:500],
            )

        if threat_items:
            logger.info("[Synthesizer] Found %d threat items from LLM JSON", len(threat_items))
        else:
            logger.warning(
                "[Synthesizer] 0 threat items after JSON parse. "
                "parsed type=%s, keys=%s",
                type(parsed).__name__,
                list(parsed.keys())[:20] if isinstance(parsed, dict) else "N/A",
            )

        for t in threat_items:
            desc = _to_str(
                t.get("description") or t.get("title") or t.get("threat")
                or t.get("descripcion") or t.get("vulnerability")
                or t.get("scenario") or t.get("attack_scenario") or ""
            )
            if not desc:
                continue

            try:
                d = _clamp_dread(int(t.get("damage", 0) or 0))
                r = _clamp_dread(int(t.get("reproducibility", 0) or 0))
                e = _clamp_dread(int(t.get("exploitability", 0) or 0))
                a = _clamp_dread(int(t.get("affected_users", 0) or 0))
                disc = _clamp_dread(int(t.get("discoverability", 0) or 0))
            except (TypeError, ValueError):
                d = r = e = a = disc = 5

            if len({d, r, e, a, disc}) == 1 and d > 3:
                logger.warning(
                    "[Synthesizer] Uniform DREAD %d/%d/%d/%d/%d for '%s' — LLM did not differentiate dimensions",
                    d, r, e, a, disc, _to_str(t.get("component", ""))[:40],
                )

            computed_total = d + r + e + a + disc
            reported_total = t.get("dread_total", computed_total)
            try:
                final_total = computed_total if computed_total > 0 else int(reported_total or 0)
            except (TypeError, ValueError):
                final_total = 25

            priority = _compute_priority(final_total)

            llm_threats.append({
                "id": _to_str(t.get("id", "")),
                "component": _to_str(t.get("component") or t.get("componente") or ""),
                "description": desc,
                "methodology": ", ".join(t.get("methodology_sources", [])) if isinstance(t.get("methodology_sources"), list) else _to_str(t.get("methodology", "")),
                "stride_category": _normalize_stride_category(_to_str(t.get("stride_category", ""))) or _infer_stride_category(t),
                "attack_path": _to_str(t.get("attack_path") or t.get("ruta_ataque") or ""),
                "damage": d,
                "reproducibility": r,
                "exploitability": e,
                "affected_users": a,
                "discoverability": disc,
                "dread_total": final_total,
                "priority": priority,
                "mitigation": _to_str(t.get("mitigation") or t.get("mitigacion") or "") or _DEFAULT_MITIGATIONS.get(_infer_stride_category(t), ""),
                "control_reference": _to_str(t.get("control_reference") or t.get("referencia_control") or "") or _DEFAULT_CONTROLS.get(_infer_stride_category(t), ""),
                "effort": _to_str(t.get("effort", "Medium")),
                "observations": _to_str(t.get("observations") or t.get("observaciones") or ""),
                "status": _to_str(t.get("status", "Open")),
                "evidence_sources": t.get("evidence_sources", []),
                "confidence_score": float(t.get("confidence_score", 0.5) or 0.5),
                "justification": None,
            })

        # Fallback parse from markdown
        if not llm_threats:
            logger.warning(
                "[Synthesizer] JSON extraction yielded 0 threats. "
                "Trying markdown extraction. Response first 1000 chars: %s",
                response[:1000],
            )
            llm_threats = extract_threats_from_markdown(response, "Synthesizer")

    logger.info(
        "[Synthesizer] LLM produced %d threats (threshold=%d, baseline=%d)",
        len(llm_threats), MIN_LLM_THREATS, baseline_count,
    )

    # ── Step 4: Decide which threats to use (hybrid merge) ──
    _used_baseline = False
    if len(llm_threats) >= MIN_LLM_THREATS:
        threats_final = llm_threats
        logger.info(
            "[Synthesizer] Using LLM output: %d threats (above threshold %d)",
            len(threats_final), MIN_LLM_THREATS,
        )
    elif llm_threats and baseline_count > 0:
        logger.warning(
            "[Synthesizer] LLM produced only %d threats (below threshold %d). "
            "MERGING with baseline %d threats.",
            len(llm_threats), MIN_LLM_THREATS, baseline_count,
        )
        _used_baseline = True
        threats_final = list(baseline_threats)

        baseline_descs = {t.get("description", "").lower()[:80] for t in baseline_threats}
        added_from_llm = 0
        for lt in llm_threats:
            lt_desc = (lt.get("description", "") or "").lower()[:80]
            if lt_desc and lt_desc not in baseline_descs:
                threats_final.append(lt)
                added_from_llm += 1
        logger.info(
            "[Synthesizer] Merged: %d baseline + %d unique LLM = %d total",
            baseline_count, added_from_llm, len(threats_final),
        )
    else:
        _used_baseline = True
        threats_final = list(baseline_threats)
        logger.warning(
            "[Synthesizer] LLM produced 0 threats. Using ALL %d baseline threats.",
            len(threats_final),
        )

    # ── Step 4b: Translate baseline threats to Spanish if needed ──
    if _used_baseline and _output_lang == "es":
        threats_final = _translate_baseline_threats(threats_final, llm, output_language=_output_lang)

    # ── Step 5: Quality gates (filter, deduplicate, fill gaps, cap count) ──
    _max_t = config.pipeline.max_threats if config else 30
    _known_comps = [
        c.get("name", "") if isinstance(c, dict) else str(c)
        for c in state.get("components", [])
    ]
    threats_final = _filter_irrelevant_threats(threats_final, state)
    threats_final = _deduplicate_threats(threats_final)
    threats_final = _apply_quality_gates(threats_final, max_threats=_max_t, known_components=_known_comps)

    # ── Step 5b: Enrich weak threats (expand short descriptions, fill mitigations) ──
    _sys_desc = state.get("system_description", "")
    threats_final = _enrich_weak_threats(threats_final, llm, system_description=_sys_desc)

    # ── Step 6: Assign category-based IDs (WEB-01, INF-02, etc.) ──
    threats_final.sort(key=lambda t: t.get("dread_total", 0), reverse=True)
    threats_final = _assign_category_ids(threats_final)

    total_elapsed = time.perf_counter() - t0
    logger.info(
        "[Synthesizer] COMPLETED in %.1fs (LLM=%.1fs): %d final prioritized threats "
        "(baseline=%d, llm_raw=%d)",
        total_elapsed, elapsed_llm, len(threats_final),
        baseline_count, len(llm_threats),
    )

    # Log final threat IDs for traceability
    for t in threats_final[:30]:
        logger.info(
            "  -> %s [%s] %s | DREAD=%s | %s",
            t.get("id", "?"), t.get("stride_category", "?"),
            (t.get("component", "") or "?")[:40],
            t.get("dread_total", 0),
            t.get("priority", "?"),
        )

    return {
        "threats_final": threats_final,
        "executive_summary": executive_summary or (
            "Modelo de amenazas sintetizado a partir de múltiples análisis metodológicos."
            if _output_lang == "es"
            else "Threat model synthesized from multiple methodology analyses."
        ),
        "report_output": raw_response,  # Keep raw response for report
    }
