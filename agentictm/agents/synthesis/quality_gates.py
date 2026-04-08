"""Quality filtering, sanitization, and architectural relevance checks."""

from __future__ import annotations

import logging
import re

from agentictm.state import ThreatModelState

from agentictm.agents.synthesis.classification import (
    _to_str,
    _normalize_stride_category,
    _infer_stride_category,
    _STRIDE_KEYWORDS,
    _DEFAULT_MITIGATIONS,
    _DEFAULT_CONTROLS,
    _clamp_dread,
    _asymmetric_dread,
    _compute_priority,
)
from agentictm.agents.synthesis.deduplication import (
    _deduplicate_threats,
    _normalize_component,
    _tokenize,
    _weighted_jaccard,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Component synonym table for fuzzy matching
# ---------------------------------------------------------------------------

_COMPONENT_SYNONYMS: dict[str, list[str]] = {
    "database": ["base de datos", "db", "database", "almacen", "almacén", "dynamo", "rds", "postgres", "mysql", "mongo"],
    "service": ["servicio", "service", "worker", "daemon", "microservicio"],
    "gateway": ["gateway", "puerta", "pasarela", "api gateway", "api-gateway"],
    "interface": ["interfaz", "interface", "panel", "pantalla", "ui", "frontend", "spa"],
    "engine": ["motor", "engine", "procesador"],
    "admin": ["admin", "administración", "administracion", "administrador"],
    "user": ["usuario", "user", "cliente", "consumidor"],
    "email": ["email", "correo", "mail", "buzón", "buzon", "ses", "smtp"],
    "file": ["archivo", "file", "fichero", "adjunto", "attachment", "upload"],
    "secrets": ["secreto", "secrets", "credential", "credencial", "contraseña", "password"],
    "rule": ["regla", "rule", "norma", "política", "politica"],
    "lambda": ["lambda", "función", "funcion", "function", "serverless", "faas"],
    "api": ["api", "endpoint", "rest", "graphql", "recurso"],
    "storage": ["almacenamiento", "s3", "bucket", "blob", "object storage"],
    "cache": ["cache", "caché", "redis", "memcached", "elasticache"],
    "queue": ["cola", "queue", "sqs", "message", "mensaje", "evento", "event"],
    "cdn": ["cdn", "cloudfront", "distribución", "distribucion", "edge"],
    "payment": ["pago", "payment", "stripe", "pasarela de pagos", "billing", "facturación"],
    "auth": ["autenticación", "autenticacion", "authentication", "auth", "login", "cognito", "oauth", "jwt", "token"],
    "container": ["contenedor", "container", "docker", "kubernetes", "ecs", "eks", "pod"],
    "network": ["red", "network", "vpc", "subnet", "firewall", "security group", "waf"],
    "model": ["modelo", "model", "llm", "embedding", "inferencia", "inference", "ml"],
    "agent": ["agente", "agent", "orquestador", "orchestrator", "pipeline"],
}

# Patterns that indicate embedded garbage *within* an otherwise valid description.
_INLINE_GARBAGE_RE = re.compile(
    r"(?:"
    r"\|\s*-{2,}\s*\|"                             # markdown table separator
    r"|```"                                         # fenced code block
    r"|\*\s*\*\*(?:Root|Leaf|Child)\s+Node"         # attack-tree ASCII
    r"|#{2,}\s+Attack\s+Tree"                       # markdown heading for attack tree
    r"|(?:^|\n)\s*[-*]\s+\*\*(?:Frontend|Backend|Orquestaci|Datos|Pagos)[:\*]"  # arch dump
    r"|(?:^|\n)\s*\d+\.\s+\*\*(?:Attacker|Attack|Root|Goal)"  # numbered attack steps
    r"|\bID\s*\|\s*Threat\s+Name"                   # risk assessment table header
    r"|\bstage_\d+_"                                # raw PASTA stage keys
    r")",
    re.IGNORECASE | re.MULTILINE,
)

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

_APP_CONTEXT_TERMS = frozenset({
    "tenant", "tenant_id", "multi-tenant", "cross-tenant", "doc_id",
    "object ownership", "object-level", "authorization", "authorisation",
    "presigned", "pre-signed", "share link", "shareable link", "download link",
    "quarantine", "clean status", "status update", "race condition", "toctou",
    "scan", "scanner", "approval", "workflow state", "state transition",
})

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


# ---------------------------------------------------------------------------
# Threat extraction from analyst reports (baseline builder)
# ---------------------------------------------------------------------------

def _extract_threats_from_reports(state: ThreatModelState) -> list[dict]:
    """Extract threats directly from methodology reports.

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
            stride_cat = _normalize_stride_category(
                _to_str(raw.get("stride_category") or raw.get("category") or "")
            )
            if not stride_cat:
                stride_cat = _infer_stride_category({"description": description, "attack_path": _to_str(raw.get("attack_path", "")), "component": component, "methodology": methodology})

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

            control_ref = _to_str(
                raw.get("control_reference")
                or raw.get("references")
                or raw.get("mitre_technique")
                or ""
            )
            if not control_ref and stride_cat in _DEFAULT_CONTROLS:
                control_ref = _DEFAULT_CONTROLS[stride_cat]

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


# ---------------------------------------------------------------------------
# Component inference from description
# ---------------------------------------------------------------------------

def _infer_component_from_description(
    desc: str,
    known_components: list[str],
) -> str:
    """Try to infer the component from the threat description by matching
    against the parsed architecture component names."""
    desc_lower = desc.lower()

    for comp in known_components:
        if comp.lower() in desc_lower:
            return comp

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
    if best_score >= 1 and best_match:
        return best_match
    return ""


# ---------------------------------------------------------------------------
# Description sanitization
# ---------------------------------------------------------------------------

def _sanitize_description(desc: str, _re_module=None) -> str:
    """Truncate a description at the first embedded garbage pattern.

    Returns the clean prefix (stripped).  If the entire description is garbage,
    returns an empty string so the caller can drop it.
    """
    m = _INLINE_GARBAGE_RE.search(desc)
    if m:
        clean = desc[: m.start()].rstrip(" \t\n:;,-")
        if len(clean) >= 40:
            logger.info(
                "[Sanitize] Truncated description at pos %d (pattern: %s)",
                m.start(), m.group()[:30],
            )
            return clean
        return ""
    return desc


# ---------------------------------------------------------------------------
# Main quality gate
# ---------------------------------------------------------------------------

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
    _GARBAGE_DESCRIPTION_PATTERNS = re.compile(
        r"(?i)^(?:attack\s+tree\s+construction|attacker\s+goals|descripci[oó]n\s+general"
        r"|risk\s+assessment|an[aá]lisis\s+stride|an[aá]lisis\s+contextual"
        r"|mapeo\s+de\s+mitigaci|fuentes\s+de\s+evidencia|evidence\s+sources"
        r"|the\s+system\s+is\s+a|el\s+sistema\s+es\s+una"
        r"|conclusi[oó]n|below\s+is\s+the\s+structured"
        r"|principios?\s+de\s+seguridad|estrategias?\s+de\s+mitigaci"
        r"|security\s+principles|mitigation\s+strateg"
        r"|recomendaciones?\s+de\s+seguridad|security\s+recommendation"
        r"|key\s+security\s+principles|para\s+contrarrestar"
        r"|cloud\s+and\s+infrastructure\s+security|desaf[ií]os\s+de\s+seguridad"
        r"|marcos\s+de\s+threat\s+model|advanced\s+threat\s+model"
        r"|modern\s+threat\s+model|el\s+threat\s+modeling\s+moderno"
        r"|autonom[ií]a\s+no\s+controlada|el\s+auge\s+de\s+los"
        r"|threat\s+modeling\s+is\s+moving|there\s+is\s+a\s+transition"
        r"|the\s+focus\s+of\s+threat|new\s+approaches\s+emphasize"
        r"|threat\s+modeling\s+methodologies|emerging\s+technologies\s*[&y]\s*security"
        r"|the\s+documents?\s+outline|the\s+documentation\s+highlights"
        r"|threat\s+landscape\s*[&y]\s*vulnerability|core\s+methodologies\s+for"
        r"|the\s+documents?\s+categorize|vulnerability\s+categories)"
    )
    _THREAT_CONTENT_TERMS = re.compile(
        r"(?i)(?:"
        # English threat terms (word-start boundary only)
        r"\b(?:vulnerab|attack|exploit|inject|breach|unauthori"
        r"|intercept|spoof|tamper|denial|elevat|privilege"
        r"|exfiltrat|bypass|overflow|malicious|compromis"
        r"|forgery|hijack|phishing|credential|brute.force"
        r"|cross.site|remote.code|replay|session.?hijack"
        r"|sensitive.?data|man.in.the|mitm|sqli|xss|csrf|ssrf|rce"
        r"|ddos|misconfig|exposure|leak|theft|steal"
        r"|insecure|weak|missing|lack|absent|default"
        r"|encrypt|cleartext|plaintext|unprotect|token"
        r"|escalat|impersonat|poisoning|adversarial"
        r"|untrust|unauthor|unauth|unenforce"
        r")"
        # Spanish threat terms (no trailing \b to allow suffixes)
        r"|(?:inyecci|inyectar|suplantaci|manipulaci|denegaci|ataqu)"
        r"|(?:vulnerabilidad|explot|amenaz|riesg|acceso.{0,5}no.{0,5}autoriz)"
        r"|(?:datos.{0,5}sensib|robo|fuga|secuestro|suplant|escala)"
        r"|(?:cifra|texto.{0,5}claro|sin.{0,5}cifr|sin.{0,5}autent|sin.{0,5}valid)"
        r"|(?:configuraci.n.{0,5}inseg|exposi|filtraci)"
        r"|(?:ejecutar.{0,10}malicioso|ejecutar.{0,10}c.digo|ejecutar.{0,10}instruc)"
        r"|(?:brecha|desactualiz|parches|exploit)"
        r"|(?:acceso.{0,5}excesiv|acceso.{0,5}no.{0,5}restringid|sin.{0,5}restricci)"
        r"|(?:contrase.a|credencial|IP.{0,3}p.blic|direcci.n.{0,5}IP)"
        # Additional Spanish/domain terms for threats commonly missed
        r"|(?:no.{0,5}confiab|entradas.{0,10}no.{0,5}confiab|entrada.{0,5}no.{0,5}valid)"
        r"|(?:accesib.{0,10}p.blic|red.{0,5}p.blic|expuest.{0,5}p.blic)"
        r"|(?:usuarios?.{0,5}invitad|sin.{0,5}requerir|permiti.{0,10}sin)"
        r"|(?:archivos?.{0,5}malicioso|carga.{0,10}malicioso|c.digo.{0,5}malicioso)"
        r"|(?:tr.fico.{0,10}no.{0,5}restring|grupo.{0,5}de.{0,5}seguridad)"
        r"|(?:no.{0,5}registra|no.{0,5}restringe|no.{0,5}cifra|no.{0,5}valida)"
        r"|(?:componentes?.{0,10}desactualiz|componentes?.{0,10}vulnerab)"
        r"|(?:intercepta|exfiltra|compromet|secuestra|suplanta)"
        r"|(?:cargar.{0,10}ejecutar|leer.{0,10}ejecutar|interpret.{0,10}ejecutar)"
        # Infrastructure/protocol terms
        r"|(?:LDAP|SAML|HTTPS?|XML|XXE|NoSQL|IDOR|BOLA)"
        r"|S3.bucket|IAM.pol|API.?Gateway|Lambda|Redis|RDS|DynamoDB"
        r"|CloudFront|VPN|WAF|JWT|OAuth|SSL|TLS|Kubernetes|EKS|S3"
        r"|ChromaDB|LangGraph|FastAPI|WebSocket"
        r")"
    )

    _RAG_COPY_PATTERN = re.compile(r"^TMA-[0-9A-Fa-f]{4}$")

    filtered: list[dict] = []
    dropped_short = 0
    dropped_garbage = 0
    dropped_rag_copy = 0
    for t in threats:
        desc = (t.get("description") or "").strip()
        tid = (t.get("id") or "").strip()

        if len(desc) < 40 or " " not in desc:
            dropped_short += 1
            continue
        if _RAG_COPY_PATTERN.match(tid):
            dropped_rag_copy += 1
            continue
        ttype = (t.get("type") or "").strip().lower()
        if ttype == "control":
            dropped_rag_copy += 1
            continue
        if _GARBAGE_DESCRIPTION_PATTERNS.match(desc):
            dropped_garbage += 1
            continue
        _control_pattern = re.compile(
            r"(?i)^(?:asegurar\s+que|implementar|verificar\s+que|utilizar|emplear|recopilar"
            r"|controles?\s+de\s+seguridad|marco\s+de\s+modelado|redactar.+ofuscar"
            r"|inspeccionar\s+las\s+entradas"
            r"|implement\s+(?:robust|controls|mechanisms|strong)|ensure\s+(?:all|aws|only|that)"
            r"|integrate\s+resources|use\s+aws|require\s+imdsv2|redact,?\s+obfuscat"
            r"|assign\s+a\s+resource|establish\s+and\s+enforce|collect,?\s+process"
            r"|verify\s+that\s+the|configure\s+(?:all|endpoint|security)"
            r"|maintain\s+(?:all|a\s+list|an\s+inventory)|protect\s+against\s+automated)"
        )
        if _control_pattern.match(desc):
            dropped_garbage += 1
            continue
        if re.search(r"\|\s*-{2,}\s*\|", desc) and desc.count("|") > 8:
            dropped_garbage += 1
            continue
        if "```json" in desc or '{"evidence_sources"' in desc or '"source_type"' in desc:
            dropped_garbage += 1
            continue
        _rag_overview_pattern = re.compile(
            r"(?i)(?:el\s+auge\s+de|the\s+rise\s+of|has\s+shifted\s+to|se\s+est[aá]\s+alejando"
            r"|nueva\s+clase\s+de\s+vulnerabilidades|new\s+class\s+of\s+vulnerabilit"
            r"|traditional\s+models|modelos\s+tradicionales"
            r"|modern\s+.*\s+is\s+moving|methodological\s+shift"
            r"|context.aware\s+model|as\s+infrastructure\s+shifts)"
        )
        if _rag_overview_pattern.search(desc):
            logger.info("[QualityGate] Dropped (RAG overview content): %.200s", desc[:200])
            dropped_garbage += 1
            continue
        desc = _sanitize_description(desc)
        if len(desc) < 40:
            dropped_garbage += 1
            continue
        t["description"] = desc
        if not _THREAT_CONTENT_TERMS.search(desc):
            logger.info("[QualityGate] Dropped (no threat terms): %.200s", desc[:200])
            dropped_garbage += 1
            continue
        filtered.append(t)

    dropped = dropped_short + dropped_garbage + dropped_rag_copy
    if dropped:
        logger.info(
            "[QualityGate] Dropped %d garbage threats (short=%d, non-threat=%d, rag-copy=%d)",
            dropped, dropped_short, dropped_garbage, dropped_rag_copy,
        )

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
    stride_defaulted = 0
    mit_filled = 0
    ctrl_filled = 0
    for t in filtered:
        raw_stride = t.get("stride_category", "")
        normalized = _normalize_stride_category(raw_stride)
        if raw_stride and not normalized:
            stride_fixed += 1
        if not normalized:
            inferred = _infer_stride_category(t)
            if inferred == "I" and not any(
                kw in (t.get("description", "") + " " + t.get("attack_path", "")).lower()
                for kw in ("disclosure", "leak", "exfiltrat", "exposure", "confidential")
            ):
                stride_defaulted += 1
            normalized = inferred
        t["stride_category"] = normalized

        if not (t.get("mitigation") or "").strip():
            t["mitigation"] = _DEFAULT_MITIGATIONS.get(normalized, _DEFAULT_MITIGATIONS.get("I", ""))
            mit_filled += 1
        if not (t.get("control_reference") or "").strip():
            t["control_reference"] = _DEFAULT_CONTROLS.get(normalized, _DEFAULT_CONTROLS.get("I", ""))
            ctrl_filled += 1

    if stride_fixed:
        logger.info("[QualityGate] Fixed %d invalid STRIDE categories (e.g. LLM02|ASI03 -> inferred)", stride_fixed)
    if stride_defaulted:
        logger.info("[QualityGate] Defaulted %d threats to STRIDE=I (no keywords matched)", stride_defaulted)

    if mit_filled:
        logger.info("[QualityGate] Filled %d empty mitigations with STRIDE defaults", mit_filled)
    if ctrl_filled:
        logger.info("[QualityGate] Filled %d empty control_references with STRIDE defaults", ctrl_filled)

    # ── 3b. STRIDE cross-validation — override semantically inconsistent assignments ──
    stride_overridden = 0
    for t in filtered:
        text = " ".join(
            _to_str(t.get(k, ""))
            for k in ("description", "attack_path", "component")
        ).lower()
        scores_by_cat: dict[str, int] = {}
        for cat, kws in _STRIDE_KEYWORDS.items():
            score = sum(1 for kw in kws if kw in text)
            if score > 0:
                scores_by_cat[cat] = score
        if not scores_by_cat:
            continue
        best_cat = max(scores_by_cat, key=lambda c: scores_by_cat[c])
        best_score = scores_by_cat[best_cat]
        assigned = t.get("stride_category", "")
        assigned_score = scores_by_cat.get(assigned, 0)
        if (
            best_score >= 3
            and assigned_score < best_score * 0.5
            and best_cat != assigned
            and not (best_cat == "I" and best_score < 4)
        ):
            logger.info(
                "[QualityGate] STRIDE override: %s -> %s (assigned_score=%d, best_score=%d) for '%.80s'",
                assigned, best_cat, assigned_score, best_score,
                (t.get("description") or "")[:80],
            )
            t["stride_category"] = best_cat
            if not (t.get("mitigation") or "").strip() or t["mitigation"] == _DEFAULT_MITIGATIONS.get(assigned, ""):
                t["mitigation"] = _DEFAULT_MITIGATIONS.get(best_cat, t.get("mitigation", ""))
            if not (t.get("control_reference") or "").strip() or t["control_reference"] == _DEFAULT_CONTROLS.get(assigned, ""):
                t["control_reference"] = _DEFAULT_CONTROLS.get(best_cat, t.get("control_reference", ""))
            stride_overridden += 1
    if stride_overridden:
        logger.info("[QualityGate] Overrode %d semantically inconsistent STRIDE assignments", stride_overridden)

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


# ---------------------------------------------------------------------------
# Coverage reconciliation — recover valid baseline threats dropped by LLM
# ---------------------------------------------------------------------------

_RECONCILIATION_THRESHOLD = 0.30


def _recover_unmatched_baseline(
    baseline_threats: list[dict],
    llm_threats: list[dict],
    *,
    threshold: float = _RECONCILIATION_THRESHOLD,
) -> list[dict]:
    """Return baseline threats with no semantic match in the LLM output.

    For each baseline threat, compute the max weighted-Jaccard similarity to
    any LLM threat.  If below *threshold*, the threat is recovered so it won't
    be silently discarded when the synthesizer prefers LLM output.
    """
    if not baseline_threats or not llm_threats:
        return []

    llm_tokens = [_tokenize(t.get("description", "")) for t in llm_threats]

    recovered: list[dict] = []
    for bt in baseline_threats:
        bt_tokens = _tokenize(bt.get("description", ""))
        if not bt_tokens:
            continue
        max_sim = max(
            (_weighted_jaccard(bt_tokens, lt) for lt in llm_tokens),
            default=0.0,
        )
        if max_sim < threshold:
            entry = dict(bt)
            obs = (entry.get("observations") or "").rstrip()
            entry["observations"] = f"{obs} [Baseline-Recovered]".strip()
            recovered.append(entry)

    if recovered:
        logger.info(
            "[Reconciliation] Recovered %d baseline threats unmatched by LLM output (threshold=%.2f)",
            len(recovered), threshold,
        )
    return recovered


# ---------------------------------------------------------------------------
# AI/architectural relevance filtering
# ---------------------------------------------------------------------------

def _system_has_ai_components(state: dict) -> bool:
    """Check whether the system under analysis uses AI/ML/LLM components."""
    text = " ".join([
        str(state.get("system_description", "")),
        str(state.get("raw_input", "")),
        str(state.get("scope_notes", "")),
        str(state.get("threat_surface_summary", "")),
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
    architecture_context_lower: str,
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

    if any(term in combined and term in architecture_context_lower for term in _APP_CONTEXT_TERMS):
        return True

    tech_keywords = set()
    for word in re.findall(r"[a-z0-9_áéíóúñü/-]{3,}", architecture_context_lower):
        if len(word) >= 4 and word not in {"the", "and", "for", "that", "this", "with", "from",
                                             "una", "del", "que", "los", "las", "para", "por",
                                             "con", "como", "ser", "está", "este", "esta",
                                             "sistema", "system", "data", "datos", "información"}:
            tech_keywords.add(word)
    overlap = sum(1 for kw in tech_keywords if kw in combined)
    return overlap >= 2


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
    architecture_context_lower = " ".join([
        str(state.get("system_description", "")),
        str(state.get("raw_input", "")),
        str(state.get("scope_notes", "")),
        str(state.get("threat_surface_summary", "")),
    ]).lower()

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

        if not has_ai and any(marker in desc_lower for marker in _AI_THREAT_MARKERS):
            dropped_ai += 1
            continue

        if known_component_names and not _threat_references_architecture(
            t, known_component_names, architecture_context_lower
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
