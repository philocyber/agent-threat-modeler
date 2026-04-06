"""Agente: Report Generator — Fase IV: Generación de Output.

Genera:
  1. CSV en el formato profesional del equipo (STRIDE + DREAD)
  2. Reporte Markdown completo con DFD, attack trees, y tablas
"""

from __future__ import annotations

import csv
import io
import json
import logging
import time
from datetime import datetime
from typing import TYPE_CHECKING

from agentictm import __version__
from agentictm.state import ThreatModelState

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Professional CSV format — matches the team's existing threat model structure
# ---------------------------------------------------------------------------

# CSV columns matching the team's format
PROFESSIONAL_CSV_COLUMNS = [
    "Threat ID",
    "Threat Scenario",
    "STRIDE",
    "Threat Control (to implement)",
    "D",
    "R",
    "E",
    "A",
    "D.1",  # Second D column (Discoverability)
    "DREAD Score",
    "Implementation Priority",
    "Status",
    "Control Risk Treatment",
    "Jira Ticket",
    "Justification/Observations",
]

# STRIDE category mapping: letter → full name
_STRIDE_FULL = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information Disclosure",
    "D": "Denial of Service",
    "E": "Elevation of Privilege",
}

# Priority mapping to Spanish
_PRIORITY_ES = {
    "Critical": "CRITICAL",
    "High": "HIGH",
    "Medium": "MEDIUM",
    "Low": "LOW",
}

# Threat ID prefix mapping by category
_CATEGORY_PREFIX = {
    "infrastructure": "INF",
    "privacy": "PRI",
    "web": "WEB",
    "api": "WEB",
    "agentic": "AGE",
    "ai": "LLM",
    "llm": "LLM",
    "network": "NET",
    "data": "DAT",
    "auth": "AUT",
}


def _compute_dread_average(threat: dict) -> str:
    """Compute DREAD average score as comma-separated string (Spanish format)."""
    d = threat.get("damage", 0)
    r = threat.get("reproducibility", 0)
    e = threat.get("exploitability", 0)
    a = threat.get("affected_users", 0)
    disc = threat.get("discoverability", 0)

    if all(isinstance(v, (int, float)) for v in [d, r, e, a, disc]):
        avg = (d + r + e + a + disc) / 5
        # Format as Spanish decimal: "7,4" instead of "7.4"
        return f"{avg:.1f}".replace(".", ",")
    return "0"


def _assign_threat_id(threat: dict, index: int) -> str:
    """Assign a professional threat ID based on category."""
    existing_id = threat.get("id", "")
    if existing_id and not existing_id.startswith("TM-"):
        return existing_id

    # Use content-based classification
    cat = _classify_threat_category(threat)
    prefix = _CATEGORY_PREFIX_MAP.get(cat, "TM")
    return f"{prefix}-{index:02d}"


def generate_csv(state: ThreatModelState) -> str:
    """Genera el CSV profesional del threat model.

    Format matches the team's existing structure:
    - Grouped by category sections
    - DREAD as individual columns + average
    - Spanish field names
    - Category section separators
    """
    threats = state.get("threats_final", [])
    if not threats:
        return "# No threats were generated"

    system_name = state.get("system_name", "System")
    analysis_date = state.get("analysis_date", datetime.now().strftime("%Y-%m-%d"))

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    # Header row (team info placeholder)
    writer.writerow(["l", "", "", "", "", "", "", "", "", "", "Development Team", "", "", ""])
    writer.writerow(PROFESSIONAL_CSV_COLUMNS)

    # Group threats by category (content-based, matching professional TM structure)
    groups: dict[str, list[dict]] = {}
    for threat in threats:
        group = _classify_threat_category(threat)
        groups.setdefault(group, []).append(threat)

    # Write grouped threats (ordered by professional category)
    category_order = [
        "Infraestructura y Cumplimiento",
        "Privacidad y Lógica de Negocio",
        "Vulnerabilidades Web y API",
        "Riesgos de Integración Agéntica",
        "Amenazas Nativas de IA y LLM",
        "Factores Humanos y Gobernanza",
        "Amenazas Generales",
    ]
    category_display = {
        "Infraestructura y Cumplimiento": "Infrastructure and Compliance",
        "Privacidad y Lógica de Negocio": "Privacy and Business Logic",
        "Vulnerabilidades Web y API": "Web and API Vulnerabilities",
        "Riesgos de Integración Agéntica": "Agentic Integration Risks",
        "Amenazas Nativas de IA y LLM": "Native AI and LLM Threats",
        "Factores Humanos y Gobernanza": "Human Factors and Governance",
        "Amenazas Generales": "General Threats",
    }
    threat_global_idx = 1
    for group_name in category_order:
        group_threats = groups.get(group_name)
        if not group_threats:
            continue
        # Section separator
        writer.writerow([category_display.get(group_name, group_name)] + [""] * 14)

        for threat in group_threats:
            tid = _assign_threat_id(threat, threat_global_idx)
            stride = _STRIDE_FULL.get(
                threat.get("stride_category", ""),
                threat.get("stride_category", ""),
            )
            dread_avg = _compute_dread_average(threat)
            priority = _PRIORITY_ES.get(
                threat.get("priority", "Medium"), "MEDIUM"
            )

            writer.writerow([
                tid,
                threat.get("description", ""),
                stride,
                threat.get("mitigation", ""),
                threat.get("damage", 0),
                threat.get("reproducibility", 0),
                threat.get("exploitability", 0),
                threat.get("affected_users", 0),
                threat.get("discoverability", 0),
                dread_avg,
                priority,
                threat.get("status", "Not Implemented"),
                "Mitigate",
                "",  # Jira ticket placeholder
                threat.get("observations", ""),
            ])
            threat_global_idx += 1

    # Footer with project metadata
    writer.writerow([])
    writer.writerow([])
    writer.writerow(["Project name", system_name])
    writer.writerow(["Threat model report date", analysis_date])
    writer.writerow(["Total Threat Controls", str(len(threats))])
    categories = state.get("threat_categories", [])
    writer.writerow(["Active categories", ", ".join(categories) if categories else "auto"])
    writer.writerow(["Status", "GENERATED BY AGENTICTM"])

    return output.getvalue()


def generate_markdown_report(state: ThreatModelState) -> str:
    """Genera un reporte Markdown completo del threat model."""
    system_name = state.get("system_name", "System")
    analysis_date = state.get("analysis_date", datetime.now().strftime("%Y-%m-%d"))
    threats = state.get("threats_final", [])

    # ── Header ──
    methodologies_used = set()
    for t in threats:
        for m in t.get("methodology", "").split(", "):
            if m.strip():
                methodologies_used.add(m.strip())
    methodology_line = " + ".join(sorted(methodologies_used)) if methodologies_used else "STRIDE + PASTA + Attack Trees"

    exec_summary = (
        state.get("executive_summary", "")
        or state.get("system_description", "No description available.")
    )

    report = f"""# Threat Model Report — {system_name}

> **Date:** {analysis_date}
> **Generated by:** AgenticTM v{__version__} — Threat Agent Modeler
> **Methodologies:** {methodology_line}

---

## Executive Summary

{exec_summary}

**Total threats identified:** {len(threats)}
"""

    # Counts by priority
    by_priority: dict[str, int] = {}
    for t in threats:
        p = t.get("priority", "Unknown")
        by_priority[p] = by_priority.get(p, 0) + 1

    for prio in ["Critical", "High", "Medium", "Low"]:
        count = by_priority.get(prio, 0)
        prio_es = {"Critical": "Critical", "High": "High", "Medium": "Medium", "Low": "Low"}.get(prio, prio)
        if count:
            report += f"- **{prio_es}:** {count}\n"

    # ── DFD ──
    mermaid_dfd = state.get("mermaid_dfd", "")
    if mermaid_dfd:
        report += f"""
---

## Data Flow Diagram

```mermaid
{mermaid_dfd}
```
"""

    # ── Tabla de amenazas ──
    report += """
---

## Threat Summary

| ID | Component | Threat Scenario | STRIDE | DREAD | Priority | Confidence | Threat Control |
|----|-----------|-----------------|--------|-------|----------|-----------|----------------|
"""
    for t in threats:
        tid = t.get("id", "?")
        comp = t.get("component", "?")
        desc = t.get("description", "?")
        if len(desc) > 80:
            desc = desc[:77] + "..."
        stride_raw = t.get("stride_category", "-")
        stride = _STRIDE_FULL.get(stride_raw, stride_raw)
        dread = t.get("dread_total", 0)
        prio = t.get("priority", "?")
        conf = t.get("confidence_score", 0)
        conf_str = f"{conf:.0%}" if conf else "—"
        mitigation = t.get("mitigation", "?")
        if len(mitigation) > 60:
            mitigation = mitigation[:57] + "..."
        report += f"| {tid} | {comp} | {desc} | {stride} | {dread} | {prio} | {conf_str} | {mitigation} |\n"

    # ── Detalle por amenaza ──
    report += "\n---\n\n## Threat Details\n"
    for t in threats:
        tid = t.get("id", "?")
        conf = t.get("confidence_score", 0)
        conf_str = f"{conf:.0%}" if conf else "N/A"
        stride_raw = t.get("stride_category", "N/A")
        stride_full = _STRIDE_FULL.get(stride_raw, stride_raw)

        report += f"""
### {tid}: {t.get('description', 'No description')[:100]}

- **Component:** {t.get('component', '?')}
- **STRIDE Category:** {stride_full}
- **DREAD Score:** D={t.get('damage', 0)} R={t.get('reproducibility', 0)} E={t.get('exploitability', 0)} A={t.get('affected_users', 0)} D={t.get('discoverability', 0)} → **{t.get('dread_total', 0)}/50**
- **Priority:** {t.get('priority', '?')}
- **Confidence:** {conf_str}
- **Threat Control:** {t.get('mitigation', 'No mitigation proposed')}
- **Control Reference:** {t.get('control_reference', 'N/A')}
- **Effort:** {t.get('effort', '?')}
- **Observations:** {t.get('observations', 'No observations')}
"""
        # Evidence sources
        evidence = t.get("evidence_sources", [])
        if evidence:
            report += "\n**Evidence sources:**\n"
            for es in evidence:
                if isinstance(es, dict):
                    report += f"- [{es.get('source_type', '')}] {es.get('source_name', '')}"
                    if es.get('excerpt'):
                        report += f" — _{es['excerpt'][:150]}_"
                    report += "\n"

        # Justification
        justif = t.get("justification")
        if isinstance(justif, dict) and justif.get("decision"):
            decision_labels = {
                "FALSE_POSITIVE": "False Positive",
                "MITIGATED_BY_INFRA": "Mitigated by Infrastructure",
                "ACCEPTED_RISK": "Accepted Risk",
                "NOT_APPLICABLE": "Not Applicable",
            }
            report += f"""
> **Justification:** {decision_labels.get(justif['decision'], justif['decision'])}
> **Reason:** {justif.get('reason_text', '')}
> **Justified by:** {justif.get('justified_by', 'N/A')} — {justif.get('justified_at', '')}
"""

    # ── Methodology contributions (Spanish summary only) ──
    report += """
---

## Methodology Summary

"""
    for r in state.get("methodology_reports", []):
        methodology = r.get("methodology", "Unknown")
        threats_raw = r.get("threats_raw", [])
        report += (
            f"### {methodology}\n\n"
            f"- Structured findings detected: **{len(threats_raw)}**\n"
            "- Details were consolidated and prioritized in the final threat table.\n\n"
        )

    # ── Attack Trees ──
    attack_tree_reports = []
    for r in state.get("methodology_reports", []):
        methodology = r.get("methodology", "")
        if "ATTACK_TREE" not in methodology.upper():
            continue
        raw_report = r.get("report", "")
        parsed_at = None
        try:
            parsed_at = json.loads(raw_report) if isinstance(raw_report, str) else raw_report
        except Exception:
            from agentictm.agents.base import extract_json_from_response
            parsed_at = extract_json_from_response(raw_report)
        if isinstance(parsed_at, dict):
            for tree in parsed_at.get("attack_trees", []):
                mermaid_code = tree.get("tree_mermaid", "")
                if mermaid_code:
                    attack_tree_reports.append({
                        "methodology": methodology,
                        "root_goal": tree.get("root_goal", ""),
                        "mermaid": mermaid_code,
                    })

    if attack_tree_reports:
        report += "---\n\n## Attack Trees\n\n"
        for at in attack_tree_reports:
            label = at.get("methodology", "ATTACK_TREE")
            root_goal = at.get("root_goal", "")
            report += f"### {label}: {root_goal}\n\n"
            report += f"```mermaid\n{at['mermaid']}\n```\n\n"

    # ── DREAD Analysis ──
    dread_threats = [t for t in threats if t.get("dread_total", 0) > 0]
    if dread_threats:
        report += "---\n\n## DREAD Risk Analysis\n\n"
        report += "| ID | D | R | E | A | D | Total | Priority |\n"
        report += "|----|---|---|---|---|---|-------|----------|\n"
        for t in sorted(dread_threats, key=lambda x: x.get("dread_total", 0), reverse=True):
            tid = t.get("id", "?")
            d = t.get("damage", 0)
            r2 = t.get("reproducibility", 0)
            e2 = t.get("exploitability", 0)
            a = t.get("affected_users", 0)
            disc = t.get("discoverability", 0)
            total = t.get("dread_total", 0)
            prio = t.get("priority", "?")
            report += f"| {tid} | {d} | {r2} | {e2} | {a} | {disc} | **{total}** | {prio} |\n"
        report += "\n**DREAD scoring:**\n"
        report += "- D=Damage, R=Reproducibility, E=Exploitability, A=Affected Users, D=Discoverability\n"
        report += "- Scale: 1-10 per category, Total = sum of the 5 dimensions (max 50)\n"
        report += "- Critical: 40+, High: 30-39, Medium: 20-29, Low: <20\n\n"

    # ── Debate ──
    # Prefer localized debate if available (set by output_localizer for Spanish)
    debate_localized = state.get("debate_history_localized", [])
    debate = debate_localized if debate_localized else state.get("debate_history", [])
    if debate:
        report += "## Red Team vs Blue Team Debate\n\n"
        seen_rounds: set[str] = set()
        for entry in debate:
            side_raw = entry.get("side", "") if isinstance(entry, dict) else getattr(entry, "side", "")
            rnd = entry.get("round", "?") if isinstance(entry, dict) else getattr(entry, "round", "?")
            if not side_raw or rnd == "?":
                continue
            dedup_key = f"{side_raw}-{rnd}"
            if dedup_key in seen_rounds:
                continue
            seen_rounds.add(dedup_key)
            side = "RED TEAM" if side_raw == "red" else "BLUE TEAM"
            arg = entry.get("argument", "") if isinstance(entry, dict) else getattr(entry, "argument", "")
            if arg:
                import re as _re
                arg = _re.sub(r"<think>.*?</think>", "", arg, flags=_re.DOTALL)
                arg = _re.sub(r"^.*?</think>", "", arg, flags=_re.DOTALL)
                arg = _re.sub(r"<think>.*$", "", arg, flags=_re.DOTALL)
                arg = arg.strip()
            report += f"### {side} -- Round {rnd}\n\n{arg}\n\n---\n\n"

    report += f"\n---\n\n*Report generated automatically by AgenticTM v{__version__} — {analysis_date}*\n"
    return report


def run_report_generator(state: ThreatModelState) -> dict:
    """Nodo de LangGraph: Report Generator.

    Lee: threats_final, methodology_reports, debate_history, etc.
    Escribe: csv_output, report_output
    """
    logger.info("[Report] Generating outputs...")
    t0 = time.perf_counter()

    csv_output = generate_csv(state)
    report_output = generate_markdown_report(state)
    elapsed = time.perf_counter() - t0

    logger.info(
        "[Report] Completed in %.1fs: %d bytes CSV, %d bytes Markdown",
        elapsed, len(csv_output), len(report_output),
    )

    return {
        "csv_output": csv_output,
        "report_output": report_output,
    }


# ---------------------------------------------------------------------------
# LaTeX Report Generation
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
    tid = threat.get("id", "")
    for cat, pfx in _CATEGORY_PREFIX_MAP.items():
        if tid.upper().startswith(pfx + "-"):
            return cat
    text = (
        (threat.get("description", "") or "")
        + " " + (threat.get("component", "") or "")
        + " " + (threat.get("methodology", "") or "")
        + " " + (threat.get("mitigation", "") or "")
    ).lower()
    for cat, kws in _THREAT_CATEGORY_KEYWORDS.items():
        if any(kw in text for kw in kws):
            return cat
    return "Amenazas Generales"


def _escape_latex(s: str) -> str:
    """Escape special LaTeX characters."""
    if not s:
        return ""
    replacements = [
        ("\\", r"\textbackslash{}"),
        ("&", r"\&"),
        ("%", r"\%"),
        ("$", r"\$"),
        ("#", r"\#"),
        ("_", r"\_"),
        ("{", r"\{"),
        ("}", r"\}"),
        ("~", r"\textasciitilde{}"),
        ("^", r"\textasciicircum{}"),
    ]
    for old, new in replacements:
        s = s.replace(old, new)
    return s


def generate_latex_report(state: ThreatModelState) -> str:
    """Generate a professional LaTeX threat model report."""
    system_name = state.get("system_name", "Sistema")
    analysis_date = state.get("analysis_date", datetime.now().strftime("%Y-%m-%d"))
    threats = state.get("threats_final", [])
    categories = state.get("threat_categories", [])

    esc = _escape_latex

    # Classify threats into groups
    groups: dict[str, list[dict]] = {}
    for t in threats:
        cat = _classify_threat_category(t)
        groups.setdefault(cat, []).append(t)

    # Count by priority
    by_priority: dict[str, int] = {}
    for t in threats:
        p = t.get("priority", "Unknown")
        by_priority[p] = by_priority.get(p, 0) + 1

    prio_summary = ", ".join(
        f"{count} {prio}"
        for prio in ["Critical", "High", "Medium", "Low"]
        if (count := by_priority.get(prio, 0)) > 0
    )

    exec_summary = (
        state.get("executive_summary", "")
        or state.get("system_description", "No description available.")
    )

    category_order = [
        "Infraestructura y Cumplimiento",
        "Privacidad y Lógica de Negocio",
        "Vulnerabilidades Web y API",
        "Riesgos de Integración Agéntica",
        "Amenazas Nativas de IA y LLM",
        "Factores Humanos y Gobernanza",
        "Amenazas Generales",
    ]

    # Build threat table rows
    threat_rows = ""
    for cat in category_order:
        cat_threats = groups.get(cat)
        if not cat_threats:
            continue
        pfx = _CATEGORY_PREFIX_MAP.get(cat, "TM")
        threat_rows += f"    \\midrule\n    \\multicolumn{{11}}{{l}}{{\\textbf{{{esc(cat)}}}}} \\\\\n    \\midrule\n"
        for i, t in enumerate(cat_threats, 1):
            tid = t.get("id", "")
            if not tid or tid.startswith("TM-"):
                tid = f"{pfx}-{i:02d}"
            d = t.get("damage", 0)
            r = t.get("reproducibility", 0)
            e2 = t.get("exploitability", 0)
            a = t.get("affected_users", 0)
            disc = t.get("discoverability", 0)
            avg = (d + r + e2 + a + disc) / 5
            avg_str = f"{avg:.1f}".replace(".", ",")
            stride = t.get("stride_category", "-")
            prio = t.get("priority", "Medium")
            prio_map = {"Critical": "CRÍTICO", "High": "ALTO", "Medium": "MEDIO", "Low": "BAJO"}
            prio_es = prio_map.get(prio, prio)

            desc = esc((t.get("description", "") or "")[:120])
            mitigation = esc((t.get("mitigation", "") or "")[:120])

            threat_rows += (
                f"    {esc(tid)} & {desc} & {esc(stride)} & {mitigation} "
                f"& {d} & {r} & {e2} & {a} & {disc} & {avg_str} & {prio_es} \\\\\n"
            )

    # Detailed threat sections
    detail_sections = ""
    threat_idx = 0
    for cat in category_order:
        cat_threats = groups.get(cat)
        if not cat_threats:
            continue
        pfx = _CATEGORY_PREFIX_MAP.get(cat, "TM")
        detail_sections += f"\\subsection{{{esc(cat)}}}\n\n"
        for i, t in enumerate(cat_threats, 1):
            threat_idx += 1
            tid = t.get("id", "")
            if not tid or tid.startswith("TM-"):
                tid = f"{pfx}-{i:02d}"
            d = t.get("damage", 0)
            r = t.get("reproducibility", 0)
            e2 = t.get("exploitability", 0)
            a = t.get("affected_users", 0)
            disc = t.get("discoverability", 0)
            avg = (d + r + e2 + a + disc) / 5
            avg_str = f"{avg:.1f}".replace(".", ",")

            detail_sections += f"""\\subsubsection{{{esc(tid)}: {esc((t.get('description','')or'')[:80])}}}

\\begin{{description}}
  \\item[Componente:] {esc(t.get('component', 'N/A'))}
  \\item[Categoría STRIDE:] {esc(t.get('stride_category', 'N/A'))}
  \\item[DREAD:] D={d}, R={r}, E={e2}, A={a}, D={disc} $\\rightarrow$ \\textbf{{{avg_str}}}
  \\item[Prioridad:] {esc(t.get('priority', 'N/A'))}
  \\item[Mitigación:] {esc(t.get('mitigation', 'Sin mitigación propuesta'))}
  \\item[Control de Referencia:] {esc(t.get('control_reference', 'N/A'))}
  \\item[Esfuerzo:] {esc(t.get('effort', 'N/A'))}
  \\item[Observaciones:] {esc(t.get('observations', 'N/A'))}
\\end{{description}}

"""

    latex = rf"""\documentclass[11pt,a4paper]{{article}}
\usepackage[utf8]{{inputenc}}
\usepackage[T1]{{fontenc}}
\usepackage{{lmodern}}
\usepackage[spanish]{{babel}}
\usepackage[margin=2cm]{{geometry}}
\usepackage{{longtable}}
\usepackage{{booktabs}}
\usepackage{{xcolor}}
\usepackage{{hyperref}}
\usepackage{{fancyhdr}}
\usepackage{{graphicx}}
\usepackage{{tabularx}}
\usepackage{{array}}
\usepackage{{amsmath}}

% Colors
\definecolor{{critical}}{{HTML}}{{C62828}}
\definecolor{{high}}{{HTML}}{{E65100}}
\definecolor{{medium}}{{HTML}}{{F57F17}}
\definecolor{{low}}{{HTML}}{{2E7D32}}
\definecolor{{accent}}{{HTML}}{{A874C0}}

% Header/Footer
\pagestyle{{fancy}}
\fancyhf{{}}
\fancyhead[L]{{\small\textcolor{{accent}}{{AgenticTM}} --- Threat Model Report}}
\fancyhead[R]{{\small {esc(system_name)}}}
\fancyfoot[C]{{\thepage}}
\renewcommand{{\headrulewidth}}{{0.4pt}}

\hypersetup{{
    colorlinks=true,
    linkcolor=accent,
    urlcolor=accent,
}}

\title{{
    \textcolor{{accent}}{{\Large Threat Model Report}} \\[0.5em]
    \textbf{{\huge {esc(system_name)}}}
}}
\author{{Generated by AgenticTM v{__version__} --- Threat Agent Modeler}}
\date{{{esc(analysis_date)}}}

\begin{{document}}

\maketitle
\tableofcontents
\newpage

% ════════════════════════════════════════════════════════════
\section{{Executive Summary}}

{esc(exec_summary[:2000])}

\begin{{itemize}}
  \item \textbf{{Total threats identified:}} {len(threats)}
  \item \textbf{{Distribution:}} {prio_summary}
  \item \textbf{{Active categories:}} {', '.join(categories) if categories else 'auto'}
\end{{itemize}}

% ════════════════════════════════════════════════════════════
\section{{Threat Table}}

\begin{{footnotesize}}
\begin{{longtable}}{{p{{1.2cm}}p{{4cm}}p{{1.2cm}}p{{3.5cm}}ccccccl}}
    \toprule
    \textbf{{ID}} & \textbf{{Scenario}} & \textbf{{STRIDE}} & \textbf{{Control}} & \textbf{{D}} & \textbf{{R}} & \textbf{{E}} & \textbf{{A}} & \textbf{{D}} & \textbf{{DREAD}} & \textbf{{Priority}} \\
    \midrule
    \endhead
{threat_rows}    \bottomrule
\end{{longtable}}
\end{{footnotesize}}

% ════════════════════════════════════════════════════════════
\section{{Threat Details}}

{detail_sections}

% ════════════════════════════════════════════════════════════
\section{{Report Information}}

\begin{{description}}
  \item[Tool:] AgenticTM v{__version__} --- Threat Agent Modeler
  \item[Methodologies:] STRIDE + PASTA + Attack Trees + MAESTRO + AI Threats + DREAD
  \item[Date:] {esc(analysis_date)}
  \item[Total Threat Controls:] {len(threats)}
  \item[Estado:] GENERADO POR AGENTICTM
\end{{description}}

\end{{document}}
"""
    return latex
