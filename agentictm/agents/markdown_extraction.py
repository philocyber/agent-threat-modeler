"""Markdown -> structured threat extraction (fallback for non-JSON LLM responses)."""

from __future__ import annotations

import re


def extract_threats_from_markdown(text: str, methodology: str = "Unknown") -> list[dict]:
    """Extract threats from a markdown-formatted response.

    Parses markdown sections, looking for numbered lists, headers,
    and DREAD score patterns. This is a fallback when the LLM
    returns markdown instead of JSON.
    """
    if not text:
        return []

    cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    if not cleaned:
        cleaned = text

    threats = []
    threat_counter = 1

    sections = re.split(r"(?:^|\n)#{1,6}\s+\*{0,2}\s*(?:\d+\.?\s*|TM-\d+[:\s])", cleaned)

    if len(sections) <= 1:
        sections = re.split(r"\n(?=\*{0,2}\d+\.\s+\*{0,2})", cleaned)

    if len(sections) <= 1:
        sections = re.split(
            r"(?:^|\n)(?:#{1,6}\s+\*{0,2}\s*(?:Stage\s+\d+|Goal\s+[A-Z]|Attack\s+Tree\s+\d+|Path\s+[A-Z])[:\s]"
            r"|\*{2}Path\s+[A-Z][:\s]"
            r"|\*{2}Sub-Goal\s+[A-Z]\d+)",
            cleaned,
        )

    if len(sections) <= 1:
        sections = re.split(r"(?:^|\n)#{3,4}\s+", cleaned)

    _NON_THREAT_PATTERNS = re.compile(
        r"(?i)^(?:\*{0,2})\s*(?:"
        r"evidence|conclusion|referencias|fuentes|references|mitigation\s+mapping"
        r"|summary|resumen|contextual\s+analysis|recommended|bibliography|appendix"
        r"|stage\s+[178]"
        r"|attack\s+tree\s+construction|attacker\s+goals|decomposition"
        r"|descripci[oó]n\s+general|arquitectura\s+del\s+sistema|general\s+description"
        r"|risk\s+assessment|prioritiz|priorizaci"
        r"|an[aá]lisis\s+stride|an[aá]lisis\s+contextual|an[aá]lisis\s+por\s+elemento"
        r"|mapeo\s+de\s+mitigaci|mitigation\s+map"
        r"|fuentes\s+de\s+evidencia|evidence\s+sources"
        r"|the\s+system\s+is\s+a|el\s+sistema\s+es"
        r"|improvements?\s+over|mejoras?\s+sobre"
        r"|principios?\s+de\s+seguridad|estrategias?\s+de\s+mitigaci"
        r"|security\s+principles|mitigation\s+strateg"
        r"|recomendaciones?\s+de\s+seguridad|security\s+recommendation"
        r"|gobernanza|governance|key\s+security"
        r")",
    )

    _THREAT_INDICATOR_TERMS = re.compile(
        r"(?i)\b(?:vulnerab|attack|exploit|inject|breach|unauthori"
        r"|intercept|spoof|tamper|denial|elevat|privilege"
        r"|exfiltrat|bypass|overflow|malicious|compromis"
        r"|forgery|hijack|phishing|credential|brute.force"
        r"|sensitive.data|man.in.the.middle|cross.site"
        r"|remote.code|buffer|replay|session.?hijack|token.?leak"
        r"|escalat|impersonat|poisoning|adversarial|dos\b|ddos"
        r"|inyecci|suplantaci|manipulaci|denegaci|acceso\s+no\s+autoriz"
        r"|robo\s+de|fuga\s+de|secuestro)\b"
    )

    for section in sections[1:] if len(sections) > 1 else []:
        stripped = section.strip()
        if len(stripped) < 40:
            continue
        first_line = stripped.split("\n", 1)[0].strip().lstrip("#* ")
        if _NON_THREAT_PATTERNS.match(first_line):
            continue

        if not _THREAT_INDICATOR_TERMS.search(stripped):
            continue

        if re.search(r"\|\s*-{2,}\s*\|", stripped) and stripped.count("|") > 10:
            continue

        threat = _parse_markdown_threat_section(section, threat_counter, methodology)
        if threat.get("description"):
            threats.append(threat)
            threat_counter += 1

    return threats


def _parse_markdown_threat_section(
    section: str, index: int, methodology: str
) -> dict:
    """Parse a single markdown section into a threat dict."""
    lines = section.strip().split("\n")

    title = ""
    for line in lines:
        line = line.strip()
        if line and not line.startswith("---"):
            title = re.sub(r"^\*\*|\*\*$|^#+\s*", "", line).strip()
            break

    fields = {}
    field_patterns = {
        "component": r"(?:component|componente|target|asset|elemento)[:\s]*(.+)",
        "stride_category": r"(?:stride|category|categoría)[:\s]*([STRIDE]{1,6}|Spoofing|Tampering|Repudiation|Information|Denial|Elevation)",
        "damage": r"(?:damage|daño|D)[:\s=]*(\d+)",
        "reproducibility": r"(?:reproducibility|reproducibilidad|R)[:\s=]*(\d+)",
        "exploitability": r"(?:exploitability|explotabilidad|E)[:\s=]*(\d+)",
        "affected_users": r"(?:affected.?users?|usuarios|A)[:\s=]*(\d+)",
        "discoverability": r"(?:discoverability|descubribilidad|D)[:\s=]*(\d+)",
        "dread_total": r"(?:dread.?total|total|score|puntaje)[:\s=]*(\d+)",
        "priority": r"(?:priority|prioridad|risk|riesgo)[:\s]*(\w+)",
        "mitigation": r"(?:mitigation|mitigación|control|recomendación)[:\s]*(.+)",
        "impact": r"(?:impact|impacto)[:\s]*(\w+)",
    }

    full_text = "\n".join(lines)
    for field, pattern in field_patterns.items():
        match = re.search(pattern, full_text, re.IGNORECASE)
        if match:
            fields[field] = match.group(1).strip()

    stride_map = {
        "spoofing": "S", "tampering": "T", "repudiation": "R",
        "information": "I", "denial": "D", "elevation": "E",
    }
    stride_cat = fields.get("stride_category", "")
    if stride_cat.lower() in stride_map:
        fields["stride_category"] = stride_map[stride_cat.lower()]

    dread_fields = ["damage", "reproducibility", "exploitability", "affected_users", "discoverability"]
    for f in dread_fields:
        if f in fields:
            try:
                fields[f] = int(fields[f])
            except ValueError:
                fields[f] = 5

    if "dread_total" not in fields:
        dread_vals = [fields.get(f, 5) for f in dread_fields]
        if all(isinstance(v, int) for v in dread_vals):
            fields["dread_total"] = sum(dread_vals)
        else:
            fields["dread_total"] = 25

    if "priority" not in fields:
        dread = fields.get("dread_total", 25)
        if isinstance(dread, str):
            dread = int(dread) if dread.isdigit() else 25
        if dread >= 45:
            fields["priority"] = "Critical"
        elif dread >= 35:
            fields["priority"] = "High"
        elif dread >= 20:
            fields["priority"] = "Medium"
        else:
            fields["priority"] = "Low"

    desc_lines = [l.strip() for l in lines if l.strip()
                   and not re.match(r"^(?:\*\*)?(?:component|stride|damage|reproduc|exploit|affect|discover|dread|priority|impact|mitiga|control|risk|categor)", l.strip(), re.IGNORECASE)
                   and not re.match(r"^```|^\|[\s:-]+\|$|^---$", l.strip())]
    body = " ".join(desc_lines).strip()
    body = re.sub(r"\*{1,2}([^*]+)\*{1,2}", r"\1", body)
    body = re.sub(r"`([^`]+)`", r"\1", body)
    body = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", body)
    body = re.sub(r"\s{2,}", " ", body)
    if title and body.startswith(title):
        body = body[len(title):].strip().lstrip(".:- ")
    description = f"{title}: {body}" if title and body else (body or title or full_text[:300])

    return {
        "id": f"TM-{index:03d}",
        "component": fields.get("component", ""),
        "description": description[:500],
        "methodology": methodology,
        "stride_category": fields.get("stride_category", ""),
        "attack_path": "",
        "damage": fields.get("damage", 5),
        "reproducibility": fields.get("reproducibility", 5),
        "exploitability": fields.get("exploitability", 5),
        "affected_users": fields.get("affected_users", 5),
        "discoverability": fields.get("discoverability", 5),
        "dread_total": fields.get("dread_total", 25),
        "priority": fields.get("priority", "Medium"),
        "mitigation": fields.get("mitigation", ""),
        "control_reference": "",
        "effort": "Medium",
        "observations": f"[Parsed from markdown] {methodology}",
        "status": "Open",
        "evidence_sources": [],
        "confidence_score": 0.3,
        "justification": None,
    }
