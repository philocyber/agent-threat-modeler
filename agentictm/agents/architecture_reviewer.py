"""Agent: Architecture Reviewer — Phase I.5: Pre-Analysis Intelligence.

Sits between architecture parsing and methodology analysis. Autonomously:
  1. Gap Detection: identifies what the parser missed
  2. Architecture Enrichment: infers likely components from domain patterns
  3. Threat Surface Pre-Mapping: classifies complexity and attack surfaces
  4. Analyst Guidance: writes a focused briefing for downstream agents

Skippable via config.pipeline.skip_architecture_review (default: False).
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

from agentictm.state import ThreatModelState

logger = logging.getLogger(__name__)

_AI_NEGATION_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bno\s+(?:ai|llm|ml|agentic|agents?)\b",
        r"\bwithout\s+(?:ai|llm|ml|agentic|agents?)\b",
        r"\bnon[-\s]?ai\b",
        r"\bdoes\s+not\s+use\s+(?:ai|llm|ml|agentic|agents?)\b",
        r"\b(?:there\s+is|there\s+are)\s+no\s+(?:ai|llm|ml|agentic|agents?)\b",
        r"\b(?:sin|no)\s+(?:ia|llm|ml|agentes?|agentic)\b",
    )
]

_AI_STRONG_SIGNALS: dict[str, tuple[re.Pattern[str], ...]] = {
    "llm": (
        re.compile(r"\bllm\b", re.IGNORECASE),
        re.compile(r"\blarge language model\b", re.IGNORECASE),
        re.compile(r"\bopenai\b", re.IGNORECASE),
        re.compile(r"\banthropic\b", re.IGNORECASE),
        re.compile(r"\bollama\b", re.IGNORECASE),
    ),
    "agentic": (
        re.compile(r"\bagentic\b", re.IGNORECASE),
        re.compile(r"\bmulti-agent\b", re.IGNORECASE),
        re.compile(r"\bautonomous agent\b", re.IGNORECASE),
        re.compile(r"\bagent orchestr", re.IGNORECASE),
        re.compile(r"\btool[-\s]?use agent\b", re.IGNORECASE),
    ),
    "rag": (
        re.compile(r"\brag\b", re.IGNORECASE),
        re.compile(r"\bretrieval[-\s]?augmented\b", re.IGNORECASE),
        re.compile(r"\bvector store\b", re.IGNORECASE),
        re.compile(r"\bembedding(?:s)?\b", re.IGNORECASE),
        re.compile(r"\bchroma(?:db)?\b", re.IGNORECASE),
    ),
    "tooling": (
        re.compile(r"\bmcp\b", re.IGNORECASE),
        re.compile(r"\bfunction call(?:ing)?\b", re.IGNORECASE),
        re.compile(r"\bplugin\b", re.IGNORECASE),
        re.compile(r"\btool executor\b", re.IGNORECASE),
        re.compile(r"\blangchain\b", re.IGNORECASE),
        re.compile(r"\blanggraph\b", re.IGNORECASE),
    ),
    "model_ops": (
        re.compile(r"\bmodel inference\b", re.IGNORECASE),
        re.compile(r"\bmodel registry\b", re.IGNORECASE),
        re.compile(r"\bprompt(?:ing)?\b", re.IGNORECASE),
        re.compile(r"\bguardrail(?:s)?\b", re.IGNORECASE),
    ),
}

_AI_STRONG_COMPONENT_HINTS = (
    "llm",
    "model",
    "embedding",
    "vector",
    "rag",
    "prompt",
    "ollama",
    "openai",
    "anthropic",
    "langchain",
    "langgraph",
    "mcp",
    "agentic",
)

# ---------------------------------------------------------------------------
# Domain patterns: common architectural elements that often go unmentioned
# ---------------------------------------------------------------------------

_INFERABLE_COMPONENTS: list[dict[str, Any]] = [
    {
        "trigger_keywords": ["api", "rest", "graphql", "endpoint", "microservice"],
        "infer_if_missing": "API Gateway / Load Balancer",
        "type": "gateway",
        "reason": "API-based architectures typically have a gateway or load balancer",
    },
    {
        "trigger_keywords": ["login", "auth", "oauth", "sso", "saml", "jwt", "token"],
        "infer_if_missing": "Identity Provider / Auth Service",
        "type": "auth_service",
        "reason": "Authentication implies an identity provider or auth service",
    },
    {
        "trigger_keywords": ["database", "postgres", "mysql", "mongo", "redis", "sql"],
        "infer_if_missing": "Database Backup System",
        "type": "backup",
        "reason": "Databases typically have backup/disaster recovery mechanisms",
    },
    {
        "trigger_keywords": ["upload", "file", "document", "image", "storage", "s3", "blob"],
        "infer_if_missing": "File Storage / CDN",
        "type": "storage",
        "reason": "File handling typically involves dedicated storage and/or CDN",
    },
    {
        "trigger_keywords": ["microservice", "service", "api", "container", "docker", "kubernetes"],
        "infer_if_missing": "Service Discovery / Registry",
        "type": "infrastructure",
        "reason": "Microservice architectures need service discovery",
    },
    {
        "trigger_keywords": ["queue", "event", "async", "worker", "rabbitmq", "kafka", "pubsub"],
        "infer_if_missing": "Dead Letter Queue / Error Handler",
        "type": "error_handling",
        "reason": "Message queues should have dead letter queues for failed messages",
    },
    {
        "trigger_keywords": ["agent", "llm", "ai", "model", "ml", "mcp"],
        "infer_if_missing": "AI Model Registry / Guardrails",
        "type": "ai_infrastructure",
        "reason": "AI systems typically need model management and safety guardrails",
    },
    {
        "trigger_keywords": ["payment", "stripe", "checkout", "billing", "transaction"],
        "infer_if_missing": "Payment Gateway / PCI Scope Boundary",
        "type": "payment",
        "reason": "Payment processing requires PCI DSS compliance boundaries",
    },
]

# Dimensions evaluated for architecture completeness
_COMPLETENESS_DIMENSIONS = [
    ("components", "Component Identification", 25),
    ("data_flows", "Data Flow Mapping", 20),
    ("trust_boundaries", "Trust Boundary Definition", 20),
    ("auth_mechanisms", "Authentication/Authorization", 15),
    ("data_sensitivity", "Data Sensitivity Classification", 10),
    ("tech_stack", "Technology Stack Clarity", 10),
]


# ---------------------------------------------------------------------------
# Core analysis functions
# ---------------------------------------------------------------------------

def _build_text_corpus(state: ThreatModelState) -> str:
    """Build a lowercased text corpus from all architecture fields for keyword matching."""
    parts = [
        state.get("raw_input", ""),
        state.get("system_description", ""),
    ]
    for comp in state.get("components", []):
        parts.append(comp.get("name", ""))
        parts.append(comp.get("description", ""))
        parts.append(comp.get("type", ""))
    for flow in state.get("data_flows", []):
        parts.append(flow.get("source", ""))
        parts.append(flow.get("destination", ""))
        parts.append(flow.get("protocol", ""))
        parts.append(flow.get("data_type", ""))
    for tb in state.get("trust_boundaries", []):
        parts.append(tb.get("name", ""))
    for ext in state.get("external_entities", []):
        parts.append(ext.get("name", ""))
    for ds in state.get("data_stores", []):
        parts.append(ds.get("name", ""))
    parts.append(state.get("scope_notes", ""))
    return " ".join(p for p in parts if p).lower()


def _iter_architecture_entries(state: ThreatModelState) -> list[tuple[str, str]]:
    """Return normalized architecture text blocks for evidence checks."""
    entries: list[tuple[str, str]] = []
    for key in ("components", "external_entities", "data_stores"):
        for item in state.get(key, []):
            if not isinstance(item, dict):
                continue
            text = " ".join(
                str(item.get(field, "") or "")
                for field in ("name", "type", "description", "technology", "notes")
            ).strip()
            if text:
                entries.append((key, text))
    for label in ("raw_input", "system_description", "scope_notes"):
        text = str(state.get(label, "") or "").strip()
        if text:
            entries.append((label, text))
    return entries


def _detect_ai_evidence(state: ThreatModelState) -> dict[str, Any]:
    """Detect AI/agentic scope conservatively using structured evidence."""
    entries = _iter_architecture_entries(state)
    combined_text = "\n".join(text for _, text in entries)
    negations = sorted({
        match.group(0).strip()
        for pattern in _AI_NEGATION_PATTERNS
        for match in pattern.finditer(combined_text)
    })

    signal_hits: dict[str, list[str]] = {}
    structured_signal_count = 0

    for label, pattern_group in _AI_STRONG_SIGNALS.items():
        matches: list[str] = []
        for scope, text in entries:
            if scope not in {"components", "external_entities", "data_stores"}:
                continue
            lowered = text.lower()
            if not any(hint in lowered for hint in _AI_STRONG_COMPONENT_HINTS):
                continue
            if any(pattern.search(text) for pattern in pattern_group):
                matches.append(text.strip()[:160])
        if matches:
            structured_signal_count += 1
            signal_hits[label] = sorted(set(matches))[:3]

    unstructured_hits: dict[str, list[str]] = {}
    free_text_segments = [
        text for scope, text in entries
        if scope in {"raw_input", "system_description", "scope_notes"}
        and not any(pattern.search(text) for pattern in _AI_NEGATION_PATTERNS)
    ]
    free_text = " ".join(free_text_segments)
    for label, pattern_group in _AI_STRONG_SIGNALS.items():
        matches = sorted({
            pattern.search(free_text).group(0).strip()
            for pattern in pattern_group
            if pattern.search(free_text)
        })
        if matches:
            unstructured_hits[label] = matches[:5]

    unstructured_signal_count = sum(1 for matches in unstructured_hits.values() if matches)
    has_ai = structured_signal_count > 0 or unstructured_signal_count >= 2

    if negations and structured_signal_count == 0 and unstructured_signal_count < 2:
        has_ai = False

    confidence = "high" if structured_signal_count else ("medium" if has_ai else "low")
    return {
        "has_ai_components": has_ai,
        "negations": negations,
        "structured_hits": signal_hits,
        "unstructured_hits": unstructured_hits,
        "confidence": confidence,
    }


def _detect_gaps(state: ThreatModelState, corpus: str) -> list[dict[str, str]]:
    """Detect architectural gaps that could degrade analysis quality."""
    gaps = []

    components = state.get("components", [])
    data_flows = state.get("data_flows", [])
    trust_boundaries = state.get("trust_boundaries", [])
    external_entities = state.get("external_entities", [])
    data_stores = state.get("data_stores", [])

    if len(components) < 2:
        gaps.append({
            "dimension": "components",
            "severity": "critical",
            "finding": "Fewer than 2 components identified. The architecture may be under-specified.",
            "impact": "Methodology analysts cannot perform component-level threat analysis.",
        })

    if not data_flows:
        gaps.append({
            "dimension": "data_flows",
            "severity": "high",
            "finding": "No data flows identified between components.",
            "impact": "STRIDE and PASTA analysis lose precision without explicit data movement.",
        })

    if not trust_boundaries:
        gaps.append({
            "dimension": "trust_boundaries",
            "severity": "high",
            "finding": "No trust boundaries defined.",
            "impact": "Spoofing and elevation-of-privilege threats cannot be properly scoped.",
        })

    # Check for authentication mentions
    auth_keywords = {"auth", "login", "oauth", "jwt", "saml", "sso", "credential", "password", "token", "certificate"}
    if not any(kw in corpus for kw in auth_keywords):
        gaps.append({
            "dimension": "auth_mechanisms",
            "severity": "medium",
            "finding": "No authentication or authorization mechanisms mentioned.",
            "impact": "Spoofing and identity threats may be under-reported.",
        })

    # Check for encryption/TLS mentions
    crypto_keywords = {"tls", "ssl", "encrypt", "https", "certificate", "cipher"}
    if not any(kw in corpus for kw in crypto_keywords):
        gaps.append({
            "dimension": "data_sensitivity",
            "severity": "medium",
            "finding": "No encryption or TLS configuration mentioned.",
            "impact": "Information disclosure threats related to data-in-transit may be missed.",
        })

    # Check for monitoring/logging mentions
    obs_keywords = {"log", "monitor", "audit", "alert", "prometheus", "grafana", "siem", "observability"}
    if not any(kw in corpus for kw in obs_keywords):
        gaps.append({
            "dimension": "observability",
            "severity": "low",
            "finding": "No logging, monitoring, or audit trail mechanisms mentioned.",
            "impact": "Repudiation threats may not be fully covered.",
        })

    # Components without any data flow connections
    flow_components = set()
    for f in data_flows:
        flow_components.add((f.get("source") or "").lower())
        flow_components.add((f.get("destination") or "").lower())

    isolated = []
    for comp in components:
        name = (comp.get("name") or "").lower()
        if name and name not in flow_components:
            isolated.append(comp.get("name", name))
    if isolated:
        gaps.append({
            "dimension": "data_flows",
            "severity": "medium",
            "finding": f"Components with no data flow connections: {', '.join(isolated[:5])}.",
            "impact": "Isolated components receive less thorough threat analysis.",
        })

    return gaps


def _infer_components(
    state: ThreatModelState,
    corpus: str,
    ai_evidence: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Infer likely missing components based on domain patterns."""
    existing_names = {
        (c.get("name") or "").lower()
        for c in state.get("components", [])
    }
    existing_names |= {
        (e.get("name") or "").lower()
        for e in state.get("external_entities", [])
    }
    existing_names |= {
        (d.get("name") or "").lower()
        for d in state.get("data_stores", [])
    }

    inferred = []
    for pattern in _INFERABLE_COMPONENTS:
        if pattern.get("type") == "ai_infrastructure" and not (ai_evidence or {}).get("has_ai_components"):
            continue
        # Check if trigger keywords are present
        triggered = any(kw in corpus for kw in pattern["trigger_keywords"])
        if not triggered:
            continue

        # Check if the inferred component already exists
        inferred_lower = pattern["infer_if_missing"].lower()
        already_exists = any(
            inferred_lower in name or name in inferred_lower
            for name in existing_names
            if name
        )
        if already_exists:
            continue

        inferred.append({
            "name": pattern["infer_if_missing"],
            "type": pattern["type"],
            "inferred": True,
            "reason": pattern["reason"],
        })

    return inferred


def _classify_complexity(state: ThreatModelState, corpus: str) -> dict[str, Any]:
    """Classify system complexity to guide analysis depth."""
    components = state.get("components", [])
    data_flows = state.get("data_flows", [])
    external_entities = state.get("external_entities", [])

    n_components = len(components)
    n_flows = len(data_flows)
    n_external = len(external_entities)

    ai_evidence = _detect_ai_evidence(state)
    has_ai = ai_evidence["has_ai_components"]

    # Microservice detection
    ms_keywords = {"microservice", "container", "docker", "kubernetes", "k8s", "service mesh"}
    has_microservices = any(kw in corpus for kw in ms_keywords)

    # Calculate complexity score
    score = 0
    score += min(n_components * 5, 30)      # Up to 30 for components
    score += min(n_flows * 3, 20)            # Up to 20 for data flows
    score += min(n_external * 5, 15)         # Up to 15 for external entities
    score += 15 if has_ai else 0             # AI systems are inherently complex
    score += 10 if has_microservices else 0  # Distributed = complex
    score += 10 if len(state.get("trust_boundaries", [])) > 2 else 0

    if score >= 60:
        level = "complex"
    elif score >= 30:
        level = "moderate"
    else:
        level = "simple"

    return {
        "level": level,
        "score": score,
        "has_ai_components": has_ai,
        "ai_evidence": ai_evidence,
        "has_microservices": has_microservices,
        "component_count": n_components,
        "data_flow_count": n_flows,
        "external_entity_count": n_external,
    }


def _map_threat_surfaces(state: ThreatModelState, complexity: dict, corpus: str) -> dict[str, Any]:
    """Pre-map the system's threat surfaces to guide downstream agents."""
    surfaces = {
        "external": [],
        "internal": [],
        "data": [],
        "agentic": [],
    }

    # External attack surface
    for comp in state.get("components", []):
        ctype = (comp.get("type") or "").lower()
        cname = (comp.get("name") or "").lower()
        if any(t in ctype for t in ("gateway", "frontend", "web", "api", "public")):
            surfaces["external"].append(comp.get("name", ""))
        elif any(t in cname for t in ("gateway", "frontend", "web", "api", "cdn", "load balancer")):
            surfaces["external"].append(comp.get("name", ""))

    for ext in state.get("external_entities", []):
        surfaces["external"].append(ext.get("name", ""))

    # Internal attack surface
    for flow in state.get("data_flows", []):
        protocol = (flow.get("protocol") or "").lower()
        if protocol and "tls" not in protocol and "https" not in protocol:
            surfaces["internal"].append(
                f"{flow.get('source', '?')} -> {flow.get('destination', '?')} ({protocol})"
            )

    # Data sensitivity surface
    sensitive_keywords = {"password", "credential", "secret", "pii", "personal", "payment",
                         "credit card", "ssn", "health", "financial", "token", "key"}
    for kw in sensitive_keywords:
        if kw in corpus:
            surfaces["data"].append(kw)

    # Agentic attack surface
    if complexity.get("has_ai_components"):
        agent_patterns = {
            "prompt injection": ["prompt", "inject", "llm", "agent"],
            "tool misuse": ["tool", "mcp", "function call", "plugin"],
            "memory poisoning": ["memory", "context", "vector", "embedding", "rag"],
            "inter-agent communication": ["agent-to-agent", "multi-agent", "orchestrat"],
        }
        for surface_name, keywords in agent_patterns.items():
            if any(kw in corpus for kw in keywords):
                surfaces["agentic"].append(surface_name)

    return surfaces


def _compute_quality_score(
    state: ThreatModelState,
    gaps: list[dict],
    complexity: dict,
) -> int:
    """Compute a 0-100 architecture quality score."""
    score = 100

    severity_penalties = {"critical": 25, "high": 15, "medium": 8, "low": 3}
    for gap in gaps:
        score -= severity_penalties.get(gap["severity"], 5)

    # Bonus for richness
    if len(state.get("data_flows", [])) >= 3:
        score += 5
    if len(state.get("trust_boundaries", [])) >= 1:
        score += 5
    if state.get("mermaid_dfd"):
        score += 5

    return max(0, min(100, score))


def _build_clarification_focus(
    gaps: list[dict[str, str]],
    inferred: list[dict[str, Any]],
    complexity: dict[str, Any],
) -> list[str]:
    """Summarize the highest-value clarification targets for the clarifier."""
    focus: list[str] = []
    for gap in sorted(gaps, key=lambda g: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(g["severity"], 4)):
        focus.append(gap["finding"])
        if len(focus) >= 4:
            break
    for comp in inferred:
        if comp.get("type") == "ai_infrastructure":
            continue
        focus.append(
            f"Confirm whether '{comp.get('name', 'Unnamed component')}' actually exists or what fulfills that role."
        )
        if len(focus) >= 5:
            break
    ai_evidence = complexity.get("ai_evidence", {}) if isinstance(complexity, dict) else {}
    if ai_evidence.get("negations") and ai_evidence.get("has_ai_components"):
        focus.append("Resolve conflicting AI/LLM statements before enabling AI-specific threat surfaces.")
    return focus[:5]


def _should_request_clarification(
    state: ThreatModelState,
    gaps: list[dict[str, str]],
    quality_score: int,
    complexity: dict[str, Any],
) -> bool:
    """Decide if the reviewer should pause for user clarification."""
    if state.get("user_answers"):
        return False
    if quality_score < 65:
        return True
    severe_gap_count = sum(1 for gap in gaps if gap.get("severity") in {"critical", "high"})
    if severe_gap_count >= 2:
        return True
    ai_evidence = complexity.get("ai_evidence", {}) if isinstance(complexity, dict) else {}
    if ai_evidence.get("negations") and ai_evidence.get("structured_hits"):
        return True
    return False


def _detect_mandatory_patterns(
    state: ThreatModelState,
    gaps: list[dict],
    surfaces: dict,
) -> list[dict]:
    """Detect high-risk architectural patterns that MUST produce at least one
    threat downstream.  Each pattern carries keywords the synthesizer can use
    to verify coverage.
    """
    corpus = " ".join(
        str(state.get(key, ""))
        for key in ("system_description", "raw_input", "scope_notes")
    ).lower()

    comp_text = " ".join(
        str(c.get("name", "")) + " " + str(c.get("description", ""))
        if isinstance(c, dict) else str(c)
        for c in state.get("components", [])
    ).lower()

    flow_text = " ".join(
        str(f.get("source", "")) + " " + str(f.get("destination", ""))
        + " " + str(f.get("data_type", ""))
        if isinstance(f, dict) else str(f)
        for f in state.get("data_flows", [])
    ).lower()

    all_text = corpus + " " + comp_text + " " + flow_text
    patterns: list[dict] = []

    # -- IDOR / BOLA: multi-tenant identifiers --
    idor_signals = ("tenant_id", "doc_id", "user_id", "object_id",
                    "multi-tenant", "cross-tenant", "object-level",
                    "presigned", "pre-signed", "share link")
    if sum(1 for s in idor_signals if s in all_text) >= 2:
        patterns.append({
            "pattern_id": "IDOR_BOLA",
            "name": "IDOR / Broken Object-Level Authorization",
            "description": (
                "The architecture contains multi-tenant identifiers or "
                "shareable object references.  An attacker incrementing or "
                "guessing IDs can access another tenant's resources."
            ),
            "keywords": [
                "idor", "bola", "object-level", "tenant", "cross-tenant",
                "doc_id", "tenant_id", "insecure direct object",
                "broken access", "authorization",
            ],
            "stride_category": "E",
        })

    # -- TOCTOU / race on async scan --
    scan_signals = ("scan", "quarantine", "clamav", "antivirus",
                    "async", "upload", "clean status", "status update")
    if sum(1 for s in scan_signals if s in all_text) >= 3:
        patterns.append({
            "pattern_id": "TOCTOU_SCAN_RACE",
            "name": "Time-of-Check / Time-of-Use Race on Async Scan",
            "description": (
                "Files are uploaded and scanned asynchronously.  A user can "
                "download the file in the window between upload and the "
                "scanner marking it CLEAN, bypassing malware protection."
            ),
            "keywords": [
                "race condition", "toctou", "time-of-check",
                "async", "scan", "quarantine", "download",
                "window", "bypass", "upload",
            ],
            "stride_category": "T",
        })

    # -- MFA enforcement gap --
    has_auth = any(k in all_text for k in ("cognito", "auth", "login", "oauth", "jwt"))
    has_mfa = any(k in all_text for k in ("mfa", "multi-factor", "two-factor", "2fa", "totp"))
    if has_auth and not has_mfa:
        patterns.append({
            "pattern_id": "MFA_ENFORCEMENT",
            "name": "Missing MFA Enforcement",
            "description": (
                "Authentication is present but no MFA documentation found.  "
                "Without MFA, a compromised password grants full access."
            ),
            "keywords": [
                "mfa", "multi-factor", "authentication", "password",
                "credential", "brute", "stuffing", "weak auth",
                "missing auth", "login",
            ],
            "stride_category": "S",
        })

    # -- Message queue replay / tampering --
    has_queue = any(k in all_text for k in ("sqs", "queue", "event bus", "sns", "message"))
    has_signing = any(k in all_text for k in ("sign", "hmac", "integrity", "message auth"))
    if has_queue and not has_signing:
        patterns.append({
            "pattern_id": "QUEUE_REPLAY",
            "name": "Message Queue Replay / Tampering",
            "description": (
                "The system uses a message queue with no documented message "
                "signing or integrity checks.  An attacker with queue access "
                "can replay or tamper with messages."
            ),
            "keywords": [
                "sqs", "queue", "replay", "tamper", "message",
                "integrity", "signing", "event",
            ],
            "stride_category": "T",
        })

    # -- Supply chain (third-party dependencies) --
    supply_signals = ("lambda", "npm", "pip", "requirements", "package",
                      "dependency", "node_modules", "pypi")
    if sum(1 for s in supply_signals if s in all_text) >= 2:
        patterns.append({
            "pattern_id": "SUPPLY_CHAIN",
            "name": "Third-Party Dependency / Supply Chain Risk",
            "description": (
                "The system relies on third-party packages.  A compromised "
                "or malicious dependency can execute arbitrary code inside "
                "the runtime environment."
            ),
            "keywords": [
                "supply chain", "dependency", "npm", "pip", "package",
                "lambda", "malicious", "poisoning", "typosquat",
            ],
            "stride_category": "T",
        })

    if patterns:
        logger.info(
            "[ArchitectureReviewer] Detected %d mandatory threat patterns: %s",
            len(patterns),
            ", ".join(p["pattern_id"] for p in patterns),
        )
    return patterns


def _generate_analyst_briefing(
    state: ThreatModelState,
    gaps: list[dict],
    inferred: list[dict],
    complexity: dict,
    surfaces: dict,
    quality_score: int,
    mandatory_patterns: list[dict] | None = None,
) -> str:
    """Generate a structured briefing for downstream methodology analysts."""
    lines = ["# Architecture Review — Analyst Briefing\n"]

    # System overview
    lines.append(f"**System:** {state.get('system_name', 'Unknown')}")
    lines.append(f"**Complexity:** {complexity['level'].upper()} (score: {complexity['score']})")
    lines.append(f"**Architecture Quality:** {quality_score}/100")
    lines.append(f"**Components:** {complexity['component_count']} identified" +
                 (f" + {len(inferred)} inferred" if inferred else ""))
    lines.append(f"**Data Flows:** {complexity['data_flow_count']}")
    lines.append(f"**AI/Agentic:** {'Yes — activate ASTRIDE A category and OWASP Agentic ASI01-ASI10' if complexity.get('has_ai_components') else 'No'}")
    lines.append("")

    # Priority focus areas
    if gaps:
        lines.append("## Identified Gaps (prioritize threats in these areas)\n")
        for gap in sorted(gaps, key=lambda g: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(g["severity"], 4)):
            lines.append(f"- **[{gap['severity'].upper()}]** {gap['finding']}")
            lines.append(f"  Impact: {gap['impact']}")
        lines.append("")

    # Inferred components
    if inferred:
        lines.append("## Inferred Components (consider threats for these)\n")
        for comp in inferred:
            lines.append(f"- **{comp['name']}** ({comp['type']}): {comp['reason']}")
        lines.append("")

    # Threat surface map
    lines.append("## Threat Surface Map\n")
    if surfaces.get("external"):
        lines.append(f"**External Attack Surface:** {', '.join(surfaces['external'][:10])}")
    if surfaces.get("internal"):
        lines.append(f"**Internal (unencrypted flows):** {', '.join(surfaces['internal'][:5])}")
    if surfaces.get("data"):
        lines.append(f"**Sensitive Data Types:** {', '.join(surfaces['data'][:10])}")
    if surfaces.get("agentic"):
        lines.append(f"**Agentic Attack Surface:** {', '.join(surfaces['agentic'])}")
    lines.append("")

    # Mandatory coverage requirements
    if mandatory_patterns:
        lines.append("## Mandatory Coverage Requirements\n")
        lines.append("The following patterns MUST produce at least one threat each.\n")
        for pat in mandatory_patterns:
            lines.append(f"- **[{pat['pattern_id']}] {pat['name']}**: {pat['description']}")
        lines.append("")

    # Analyst-specific guidance
    lines.append("## Analyst Guidance\n")
    if complexity["level"] == "complex":
        lines.append("- This is a complex system. Prioritize inter-component threats and trust boundary crossings.")
        lines.append("- Expect 20-40 threats from synthesis.")
    elif complexity["level"] == "moderate":
        lines.append("- Moderate system. Balance breadth across STRIDE categories with depth on external surfaces.")
        lines.append("- Expect 12-25 threats from synthesis.")
    else:
        lines.append("- Simple system. Focus on the most impactful threats rather than exhaustive coverage.")
        lines.append("- Expect 8-15 threats from synthesis.")

    if complexity.get("has_ai_components"):
        lines.append("- **AI SYSTEM DETECTED**: Apply ASTRIDE 'A' category, OWASP Agentic AI Top 10 (ASI01-ASI10), ATFAA/SHIELD domains, and MCP security patterns.")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# LangGraph node
# ---------------------------------------------------------------------------

def run_architecture_reviewer(state: ThreatModelState, llm=None, config=None) -> dict:
    """LangGraph node: Architecture Reviewer — Pre-Analysis Intelligence.

    Reads: raw_input, system_description, components, data_flows, trust_boundaries,
           external_entities, data_stores, scope_notes, mermaid_dfd
    Writes: architecture_review, threat_surface_summary, system_complexity
    """
    t0 = time.perf_counter()
    logger.info("[ArchitectureReviewer] Starting pre-analysis review...")

    corpus = _build_text_corpus(state)

    # 1. Gap Detection
    gaps = _detect_gaps(state, corpus)
    logger.info("[ArchitectureReviewer] Found %d architectural gaps", len(gaps))

    # 2. Complexity Classification
    complexity = _classify_complexity(state, corpus)
    logger.info("[ArchitectureReviewer] System complexity: %s (score=%d)", complexity["level"], complexity["score"])

    # 3. Component Inference
    inferred = _infer_components(state, corpus, complexity.get("ai_evidence"))
    logger.info("[ArchitectureReviewer] Inferred %d additional components", len(inferred))

    # 4. Threat Surface Pre-Mapping
    surfaces = _map_threat_surfaces(state, complexity, corpus)
    surface_counts = {k: len(v) for k, v in surfaces.items()}
    logger.info("[ArchitectureReviewer] Threat surfaces: %s", surface_counts)

    # 5. Quality Score
    quality_score = _compute_quality_score(state, gaps, complexity)
    logger.info("[ArchitectureReviewer] Architecture quality: %d/100", quality_score)
    clarification_focus = _build_clarification_focus(gaps, inferred, complexity)
    clarification_needed = _should_request_clarification(state, gaps, quality_score, complexity)

    # 6. Mandatory Threat Pattern Detection
    mandatory_patterns = _detect_mandatory_patterns(state, gaps, surfaces)

    # 7. Analyst Briefing
    briefing = _generate_analyst_briefing(state, gaps, inferred, complexity, surfaces, quality_score, mandatory_patterns)

    # 8. LLM-based enrichment (if available): ask the LLM to identify non-obvious gaps
    llm_insights = ""
    if llm is not None and quality_score < 80:
        try:
            from langchain_core.messages import HumanMessage, SystemMessage
            prompt = (
                "You are a senior security architect reviewing a system architecture before threat modeling.\n\n"
                f"## System Description\n{state.get('system_description', state.get('raw_input', ''))[:3000]}\n\n"
                f"## Parsed Components\n{json.dumps([c.get('name', '') for c in state.get('components', [])], indent=2)}\n\n"
                f"## Identified Gaps\n{json.dumps([g['finding'] for g in gaps], indent=2)}\n\n"
                "In 3-5 bullet points, identify the most critical architectural assumptions or "
                "missing information that could lead to blind spots in threat modeling. "
                "Focus on what's NOT explicitly stated but likely exists."
            )
            response = llm.invoke([
                SystemMessage(content="You are a security architecture reviewer. Be concise and specific."),
                HumanMessage(content=prompt),
            ])
            content = response.content if hasattr(response, "content") else str(response)
            if content and len(content) > 20:
                llm_insights = content
                logger.info("[ArchitectureReviewer] LLM insights generated (%d chars)", len(content))
        except Exception as exc:
            logger.warning("[ArchitectureReviewer] LLM enrichment failed (non-fatal): %s", exc)

    elapsed = time.perf_counter() - t0

    review = {
        "quality_score": quality_score,
        "gaps": gaps,
        "gap_count": len(gaps),
        "inferred_components": inferred,
        "complexity": complexity,
        "threat_surfaces": surfaces,
        "clarification_focus": clarification_focus,
        "llm_insights": llm_insights,
        "elapsed_seconds": round(elapsed, 2),
    }

    logger.info(
        "[ArchitectureReviewer] Review complete in %.1fs: quality=%d, gaps=%d, inferred=%d, complexity=%s",
        elapsed, quality_score, len(gaps), len(inferred), complexity["level"],
    )

    return {
        "architecture_review": review,
        "threat_surface_summary": briefing,
        "system_complexity": complexity["level"],
        "quality_score": quality_score,
        "clarification_needed": clarification_needed,
        "mandatory_threat_patterns": mandatory_patterns,
    }
