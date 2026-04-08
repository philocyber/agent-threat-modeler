"""Threat classification, STRIDE inference, DREAD scoring, and category-based IDs."""

from __future__ import annotations

import json
import logging
import math
from typing import TYPE_CHECKING

from agentictm.state import ThreatModelState

if TYPE_CHECKING:
    from agentictm.config import AgenticTMConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Threat classification & category-based ID assignment
# (mirrors report_generator logic — single source of truth)
# ---------------------------------------------------------------------------

_THREAT_CATEGORY_KEYWORDS: dict[str, list[str]] = {
    "Infrastructure and Compliance": [
        "infrastructure", "infraestructura", "credential", "secret", "deploy",
        "compliance", "environment", ".env", "token", "certificate", "server",
        "host", "container", "docker", "kubernetes", "monitoring", "logging",
        "cloud", "aws", "azure", "gcp", "terraform", "tls", "ssl", "network",
        "firewall", "dns", "cicd", "ci/cd", "pipeline", "config", "iac",
    ],
    "Privacy and Business Logic": [
        "privacy", "privacidad", "pii", "gdpr", "ccpa", "personal data",
        "consent", "business logic", "repudiation", "repudio", "audit trail",
        "data protection", "retention", "anonymi", "trazab", "tenant isolation",
        "multi-tenant", "cross-tenant", "tenant boundary", "object ownership",
        "row-level security", "workflow state", "state transition", "quarantine",
        "approval", "pending", "clean status", "business rule",
    ],
    "Web and API Vulnerabilities": [
        "web", "api", "frontend", "xss", "csrf", "sql inject", "sql", "idor", "http",
        "cors", "cookie", "session", "jwt", "oauth", "endpoint", "gateway",
        "rate limit", "input valid", "sanitiz", "deserialization", "ssrf",
        "inyecci", "inject", "clickjack", "header", "redirect", "traversal",
        "upload", "path travers", "open redirect", "broken auth", "bola",
        "broken access control", "object level authorization", "presigned",
        "pre-signed", "share link", "doc_id", "tenant_id",
    ],
    "Agentic Integration Risks": [
        "agent", "agentic", "agéntic", "orchestrat", "orquest", "loop",
        "recursion", "tool misuse", "mcp", "langchain", "langgraph",
        "checkpoint", "state manip", "multi-agent", "tool call", "bucle",
    ],
    "Native AI and LLM Threats": [
        "llm", "prompt inject", "jailbreak", "hallucin", "alucinaci",
        "training data", "data poisoning", "model poisoning", "embedding attack",
        "rag pipeline", "vector database", "adversarial input", "adversarial example",
        "model extraction", "system prompt leak", "guardrail bypass",
        "artificial intelligence", "machine learning", "nlp pipeline",
        "bias", "sesgo", "fine-tun", "inference attack",
    ],
    "Human Factors and Governance": [
        "human", "humano", "governance", "gobernanza", "oversight",
        "automation bias", "trust", "review", "approval", "social engineer",
        "insider", "phishing",
    ],
}

_CATEGORY_PREFIX_MAP: dict[str, str] = {
    "Infrastructure and Compliance": "INF",
    "Privacy and Business Logic": "PRI",
    "Web and API Vulnerabilities": "WEB",
    "Agentic Integration Risks": "AGE",
    "Native AI and LLM Threats": "LLM",
    "Human Factors and Governance": "HUM",
    "General Threats": "GEN",
}

_STRIDE_TO_CATEGORY: dict[str, str] = {
    "S": "Infrastructure and Compliance",
    "T": "Web and API Vulnerabilities",
    "R": "Privacy and Business Logic",
    "I": "Infrastructure and Compliance",
    "D": "Infrastructure and Compliance",
    "E": "Infrastructure and Compliance",
    "A": "Agentic Integration Risks",
}


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


import re  # noqa: E402 — needed by _has_ai_surface


def _has_ai_surface(state: ThreatModelState) -> bool:
    categories = {str(c).lower() for c in state.get("threat_categories", [])}
    if "ai" in categories:
        return True

    text_chunks = [state.get("system_description", ""), state.get("raw_input", "")]
    for component in state.get("components", []):
        if isinstance(component, dict):
            text_chunks.append(component.get("name", ""))
            text_chunks.append(component.get("description", ""))

    haystack = " ".join(_to_str(chunk) for chunk in text_chunks).lower()
    negation_patterns = (
        r"\bno\s+ai\b",
        r"\bno\s+llm\b",
        r"\bno\s+agentic\b",
        r"\bwithout\s+ai\b",
        r"\bwithout\s+llm\b",
        r"\bwithout\s+agentic\b",
        r"\bthere\s+are\s+no\s+ai\b",
        r"\bthere\s+are\s+no\s+llm\b",
        r"\bthere\s+are\s+no\s+agentic\b",
        r"\bno\s+ai/ml/agentic\s+components\b",
        r"\bno\s+ai\s+components\b",
        r"\bno\s+llm\s+components\b",
        r"\bno\s+agentic\s+ai\s+components\b",
    )
    if any(re.search(pattern, haystack) for pattern in negation_patterns):
        return False
    ai_keywords = (
        "llm", "agent", "agentic", "rag", "embedding", "model",
        "prompt", "vector database", "machine learning", "artificial intelligence",
    )
    return any(keyword in haystack for keyword in ai_keywords)


def _estimate_expected_threat_count(
    state: ThreatModelState,
    config: AgenticTMConfig | None,
) -> dict[str, object]:
    components = state.get("components", [])
    data_flows = state.get("data_flows", [])
    trust_boundaries = state.get("trust_boundaries", [])
    external_entities = state.get("external_entities", [])
    active_categories = [
        str(cat).lower()
        for cat in state.get("threat_categories", [])
        if str(cat).lower() not in {"base", "auto"}
    ]
    ai_present = _has_ai_surface(state)
    min_threats = config.pipeline.min_threats if config else 8
    max_threats = config.pipeline.max_threats if config else 40

    expected = (
        3
        + math.ceil(len(components) * 0.5)
        + math.ceil(len(data_flows) * 0.35)
        + len(trust_boundaries)
        + min(4, len(active_categories))
        + (1 if len(external_entities) >= 2 else 0)
        + (3 if ai_present else 0)
    )
    expected = max(min_threats, min(max_threats, expected))

    dimensions = [
        f"{len(components)} components",
        f"{len(data_flows)} data flows",
        f"{len(trust_boundaries)} trust boundaries",
        f"{len(active_categories)} active categories",
    ]
    if ai_present:
        dimensions.append("AI/LLM surface")

    return {
        "expected_count": expected,
        "dimensions": dimensions,
        "ai_present": ai_present,
    }


def _classify_threat_category(threat: dict) -> str:
    """Classify a threat into a professional category by keyword score.

    Counts how many keywords from each category appear in the threat text
    and returns the category with the highest match count.  On a tie the
    more specific category wins (Web > Privacy > Infrastructure).
    """
    text = " ".join(
        _to_str(threat.get(k, ""))
        for k in ("description", "component", "methodology", "mitigation", "attack_path")
    ).lower()

    _SPECIFICITY_BONUS: dict[str, float] = {
        "Web and API Vulnerabilities": 1.0,
        "Native AI and LLM Threats": 0.8,
        "Agentic Integration Risks": 0.6,
        "Human Factors and Governance": 0.2,
        "Privacy and Business Logic": 0.1,
        "Infrastructure and Compliance": 0.0,
    }

    _SPECIFIC_CATEGORIES = frozenset({
        "Web and API Vulnerabilities",
        "Native AI and LLM Threats",
        "Agentic Integration Risks",
        "Human Factors and Governance",
    })
    _BROAD_CATEGORIES = frozenset({
        "Infrastructure and Compliance",
        "Privacy and Business Logic",
    })

    scores: dict[str, float] = {}
    for cat, kws in _THREAT_CATEGORY_KEYWORDS.items():
        hits = sum(1 for kw in kws if kw in text)
        if hits > 0:
            scores[cat] = hits + _SPECIFICITY_BONUS.get(cat, 0.0)

    if not scores:
        stride = (threat.get("stride_category") or "").strip()
        if stride in _STRIDE_TO_CATEGORY:
            return _STRIDE_TO_CATEGORY[stride]
        return "General Threats"

    best_cat = max(scores, key=lambda c: scores[c])
    best_score = scores[best_cat]

    if best_cat in _BROAD_CATEGORIES:
        for cat in _SPECIFIC_CATEGORIES:
            if cat in scores and scores[cat] >= best_score - 1.0:
                best_cat = cat
                break

    return best_cat


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
        "authentication", "autenticaci", "login bypass", "account takeover",
        "password brute", "password spray", "credential stuff", "oauth misconfig",
        "saml", "sso bypass", "token replay", "session fixation", "weak auth",
        "broken auth", "missing auth", "identity fraud",
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
        "parameter tamper", "request forgery", "csrf", "file upload",
        "path traversal", "directory traversal", "insecure deserializ",
        "prototype pollut", "xml inject", "ldap inject", "nosql inject",
        "template inject", "ssti", "header inject", "crlf inject",
    ],
    "R": [
        "repudiation", "repudio", "non-repudiation", "logging", "audit",
        "traceability", "accountability", "log", "evidence", "deniab",
        "no record", "unlogged", "auditoria", "auditoría", "trazabilidad",
        "forensic", "forense", "log tampering", "log injection",
        "without logging", "sin registro", "borrado de log", "log deletion",
        "insufficient log", "missing log", "no audit", "audit trail",
        "compliance gap", "siem", "monitoring gap", "untracked",
        "undocumented", "no trace", "accountability gap",
    ],
    "I": [
        "information disclosure", "data leak", "exfiltrat", "exposure",
        "sensitive data", "confidential", "privacy", "data breach",
        "unauthorized read", "intercept", "sniff", "man-in-the-middle",
        "mitm", "eavesdrop", "disclosure", "divulgaci",
        "datos sensibles", "fuga de dato", "expose secret",
        "verbose error", "stack trace", "debug info", "api key expos",
        "secret leak", "credential expos", "unencrypt", "plaintext",
        "insecure storage", "s3 public", "bucket public", "misconfigur",
        "information leak", "metadata expos", "pii expos", "data expos",
        "side channel", "timing attack",
    ],
    "D": [
        "denial of service", "dos", "ddos", "availability", "resource exhaust",
        "crash", "timeout", "overload", "flood", "disruption", "denegaci",
        "unavailab", "outage", "degrade", "slow",
        "rate limit", "throttl", "memory exhaust", "cpu exhaust",
        "disk exhaust", "connection exhaust", "socket exhaust",
        "infinite loop", "deadlock", "starvat", "backpressure",
        "queue overflow", "service disrupt", "downtime",
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
        "horizontal escalat", "vertical escalat", "insecure direct object",
        "idor", "broken access", "missing access control", "function level",
        "mass assignment", "forced browsing", "jwt privilege",
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
    """Infer the STRIDE category from threat text when not explicitly set.

    Returns "I" (Information Disclosure) as a safe default when no keywords
    match, since it is the most common STRIDE category and preferable to an
    empty string that breaks downstream processing.
    """
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
    return best or "I"


_DEFAULT_MITIGATIONS: dict[str, str] = {
    "S": "Implementar autenticación multifactor (MFA), validación robusta de tokens/sesiones y protección contra credential stuffing. Verificar identidad en cada capa de confianza.",
    "T": "Aplicar validación de integridad de datos con checksums/HMAC, controles de acceso de escritura estrictos y mecanismos de detección de modificaciones no autorizadas.",
    "R": "Implementar logging centralizado e inmutable (append-only) de todas las operaciones críticas. Incluir timestamps, usuario, acción y resultado en cada registro de auditoría.",
    "I": "Aplicar cifrado en tránsito (TLS 1.3) y en reposo (AES-256). Restringir acceso según principio de mínimo privilegio. Clasificar datos por sensibilidad y aplicar controles proporcionales.",
    "D": "Implementar rate limiting por IP/usuario, auto-scaling con umbrales definidos, circuit breakers en dependencias y monitoreo de disponibilidad con alertas automatizadas.",
    "E": "Aplicar principio de mínimo privilegio en todos los roles IAM. Implementar separación de funciones, revisión periódica de permisos y detección de escalamiento anómalo.",
}

_DEFAULT_CONTROLS: dict[str, str] = {
    "S": "NIST IA-2 (Identification and Authentication), IA-5 (Authenticator Management), OWASP ASVS V2 (Authentication)",
    "T": "NIST SI-7 (Software, Firmware, and Information Integrity), SI-10 (Information Input Validation), OWASP ASVS V5 (Validation)",
    "R": "NIST AU-2 (Event Logging), AU-3 (Content of Audit Records), AU-6 (Audit Record Review), OWASP ASVS V7 (Error Handling and Logging)",
    "I": "NIST SC-8 (Transmission Confidentiality), SC-28 (Protection of Information at Rest), AC-3 (Access Enforcement), OWASP ASVS V8 (Data Protection)",
    "D": "NIST SC-5 (Denial-of-Service Protection), CP-9 (System Backup), CP-10 (System Recovery), OWASP ASVS V11 (Business Logic)",
    "E": "NIST AC-6 (Least Privilege), AC-2 (Account Management), AC-5 (Separation of Duties), OWASP ASVS V4 (Access Control)",
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

    offsets = {
        "S": {"damage": 1, "reproducibility": 0, "exploitability": -1, "affected_users": 1, "discoverability": -2},
        "T": {"damage": 2, "reproducibility": 0, "exploitability": -1, "affected_users": 1, "discoverability": -1},
        "R": {"damage": -1, "reproducibility": 1, "exploitability": 0, "affected_users": -1, "discoverability": -2},
        "I": {"damage": 1, "reproducibility": 0, "exploitability": -1, "affected_users": 2, "discoverability": -1},
        "D": {"damage": 0, "reproducibility": 2, "exploitability": 1, "affected_users": 1, "discoverability": -2},
        "E": {"damage": 2, "reproducibility": -1, "exploitability": -2, "affected_users": 1, "discoverability": -2},
    }
    off = offsets.get(stride_cat, {"damage": 1, "reproducibility": 0, "exploitability": -1, "affected_users": 0, "discoverability": -1})

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
    for key in _THREATS_ARRAY_KEYS:
        val = parsed.get(key)
        if isinstance(val, list) and val and isinstance(val[0], dict):
            logger.info("[Synthesizer] Found threats under key '%s' (%d items)", key, len(val))
            return [t for t in val if isinstance(t, dict)]

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

    if _depth < 2:
        for key, val in parsed.items():
            if isinstance(val, dict):
                nested = _find_threats_array(val, _depth + 1)
                if nested:
                    logger.info("[Synthesizer] Found threats nested under '%s'", key)
                    return nested

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
    groups: dict[str, list[dict]] = {}
    for t in threats:
        cat = _classify_threat_category(t)
        groups.setdefault(cat, []).append(t)

    category_order = [
        "Infrastructure and Compliance",
        "Privacy and Business Logic",
        "Web and API Vulnerabilities",
        "Agentic Integration Risks",
        "Native AI and LLM Threats",
        "Human Factors and Governance",
        "General Threats",
    ]

    result = []
    for cat in category_order:
        cat_threats = groups.get(cat, [])
        prefix = _CATEGORY_PREFIX_MAP.get(cat, "TM")
        for i, t in enumerate(cat_threats, 1):
            t["id"] = f"{prefix}-{i:02d}"
            result.append(t)

    return result
