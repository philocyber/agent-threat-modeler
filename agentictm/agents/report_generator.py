"""Agent: Report Generator — Phase IV: Output Generation.

Generates:
  1. CSV in the team's professional format (STRIDE + DREAD)
  2. Complete Markdown report with DFD, attack trees, and tables
  3. SARIF 2.1.0 output for CI/CD integration
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
    "A": "Agent Threat",
}

# Priority mapping to normalized uppercase
_PRIORITY_NORM = {
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
    """Compute DREAD average score formatted with comma as decimal separator."""
    d = threat.get("damage", 0)
    r = threat.get("reproducibility", 0)
    e = threat.get("exploitability", 0)
    a = threat.get("affected_users", 0)
    disc = threat.get("discoverability", 0)

    if all(isinstance(v, (int, float)) for v in [d, r, e, a, disc]):
        avg = (d + r + e + a + disc) / 5
        # Format with comma decimal separator: "7,4" instead of "7.4"
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
    """Generate the professional CSV threat model output.

    Format matches the team's existing structure:
    - Grouped by category sections
    - DREAD as individual columns + average
    - Localized field names
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
        "Infrastructure and Compliance",
        "Privacy and Business Logic",
        "Web and API Vulnerabilities",
        "Agentic Integration Risks",
        "Native AI and LLM Threats",
        "Human Factors and Governance",
        "General Threats",
    ]
    category_display = {cat: cat for cat in category_order}
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
            priority = _PRIORITY_NORM.get(
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
    """Generate a complete Markdown report of the threat model."""
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

    # ── Threat table ──
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

    # ── Threat details ──
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

    # ── Methodology contributions ──
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
    # Prefer localized debate if available (set by output_localizer)
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
    """LangGraph node: Report Generator.

    Reads: threats_final, methodology_reports, debate_history, etc.
    Writes: csv_output, report_output
    """
    logger.info("[Report] Generating outputs...")
    t0 = time.perf_counter()

    csv_output = generate_csv(state)
    report_output = generate_markdown_report(state)

    # MITRE ATT&CK / CAPEC / D3FEND mapping
    mitre_mappings = []
    try:
        from agentictm.agents.mitre_mapper import map_all_threats
        threats = state.get("threats_final", [])
        if threats:
            mitre_mappings = map_all_threats(threats)
            logger.info("[Report] MITRE mappings generated for %d threats", len(threats))
    except Exception as exc:
        logger.warning("[Report] MITRE mapping failed (non-fatal): %s", exc)

    # Append MITRE mappings section to Markdown report
    if mitre_mappings:
        mitre_section = _generate_mitre_section(mitre_mappings)
        report_output += mitre_section

    elapsed = time.perf_counter() - t0

    logger.info(
        "[Report] Completed in %.1fs: %d bytes CSV, %d bytes Markdown",
        elapsed, len(csv_output), len(report_output),
    )

    return {
        "csv_output": csv_output,
        "report_output": report_output,
        "mitre_mappings": mitre_mappings,
    }


def _generate_mitre_section(mappings: list[dict]) -> str:
    """Generate a Markdown section with MITRE ATT&CK/CAPEC/D3FEND mappings."""
    lines = ["\n\n## MITRE ATT&CK / CAPEC / D3FEND Mappings\n"]
    for m in mappings:
        tid = m.get("threat_id", "N/A")
        attacks = m.get("attack_techniques", [])
        capecs = m.get("capec_patterns", [])
        defenses = m.get("d3fend_techniques", [])
        if not attacks and not capecs and not defenses:
            continue
        lines.append(f"### {tid}\n")
        if attacks:
            lines.append("**ATT&CK Techniques:**\n")
            for a in attacks[:5]:
                lines.append(f"- [{a['technique_id']}]({a['reference_url']}) {a['technique_name']} ({a['tactic']})")
            lines.append("")
        if capecs:
            lines.append("**CAPEC Patterns:**\n")
            for c in capecs[:5]:
                lines.append(f"- [{c['capec_id']}]({c['reference_url']}) {c['pattern_name']}")
            lines.append("")
        if defenses:
            lines.append("**D3FEND Defenses:**\n")
            for d in defenses[:5]:
                lines.append(f"- [{d['d3fend_id']}]({d['reference_url']}) {d['technique_name']} ({d['category']})")
            lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# LaTeX Report Generation
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
        "data protection", "retention", "anonymi", "trazab", "exfiltr",
    ],
    "Web and API Vulnerabilities": [
        "web", "api", "frontend", "xss", "csrf", "sql inject", "idor", "http",
        "cors", "cookie", "session", "jwt", "oauth", "endpoint", "gateway",
        "rate limit", "input valid", "sanitiz", "deserialization", "ssrf",
        "inyecci",
    ],
    "Agentic Integration Risks": [
        "agent", "agentic", "agéntic", "orchestrat", "orquest", "loop",
        "recursion", "tool misuse", "mcp", "langchain", "langgraph",
        "checkpoint", "state manip", "multi-agent", "tool call", "bucle",
    ],
    "Native AI and LLM Threats": [
        "llm", "prompt inject", "jailbreak", "hallucin", "alucinaci", "model",
        "training", "poisoning", "embedding", "rag", "vector", "adversarial",
        "extraction", "system prompt", "guardrail", "artificial intelligence",
        "machine learning", "nlp", "bias", "sesgo",
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
    return "General Threats"


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
    system_name = state.get("system_name", "System")
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
        "Infrastructure and Compliance",
        "Privacy and Business Logic",
        "Web and API Vulnerabilities",
        "Agentic Integration Risks",
        "Native AI and LLM Threats",
        "Human Factors and Governance",
        "General Threats",
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
            prio_map = {"Critical": "CRITICAL", "High": "HIGH", "Medium": "MEDIUM", "Low": "LOW"}
            prio_display = prio_map.get(prio, prio)

            desc = esc((t.get("description", "") or "")[:120])
            mitigation = esc((t.get("mitigation", "") or "")[:120])

            threat_rows += (
                f"    {esc(tid)} & {desc} & {esc(stride)} & {mitigation} "
                f"& {d} & {r} & {e2} & {a} & {disc} & {avg_str} & {prio_display} \\\\\n"
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
  \\item[Component:] {esc(t.get('component', 'N/A'))}
  \\item[STRIDE Category:] {esc(t.get('stride_category', 'N/A'))}
  \\item[DREAD:] D={d}, R={r}, E={e2}, A={a}, D={disc} $\\rightarrow$ \\textbf{{{avg_str}}}
  \\item[Priority:] {esc(t.get('priority', 'N/A'))}
  \\item[Mitigation:] {esc(t.get('mitigation', 'No mitigation proposed'))}
  \\item[Control Reference:] {esc(t.get('control_reference', 'N/A'))}
  \\item[Effort:] {esc(t.get('effort', 'N/A'))}
  \\item[Observations:] {esc(t.get('observations', 'N/A'))}
\\end{{description}}

"""

    latex = rf"""\documentclass[11pt,a4paper]{{article}}
\usepackage[utf8]{{inputenc}}
\usepackage[T1]{{fontenc}}
\usepackage{{lmodern}}
\usepackage[english]{{babel}}
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
  \item[Status:] GENERATED BY AGENTICTM
\end{{description}}

\end{{document}}
"""
    return latex


# ---------------------------------------------------------------------------
# SARIF 2.1.0 Output Generation
# ---------------------------------------------------------------------------

_SARIF_LEVEL_MAP = {
    "Critical": "error",
    "High": "error",
    "Medium": "warning",
    "Low": "note",
}


def generate_sarif(state: ThreatModelState) -> str:
    """Generate SARIF 2.1.0 output for CI/CD integration."""
    threats = state.get("threats_final", [])

    # --- Build rules from unique STRIDE categories found in threats ----------
    category_priorities: dict[str, list[str]] = {}
    for t in threats:
        cat = t.get("stride_category", "")
        if cat:
            category_priorities.setdefault(cat, []).append(
                t.get("priority", "Medium")
            )

    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    for cat in sorted(category_priorities):
        rule_id = f"STRIDE-{cat}"
        full_name = _STRIDE_FULL.get(cat, cat)
        priorities = category_priorities[cat]
        most_common = max(set(priorities), key=priorities.count)
        default_level = _SARIF_LEVEL_MAP.get(most_common, "warning")

        rule_index[cat] = len(rules)
        rules.append({
            "id": rule_id,
            "name": full_name,
            "shortDescription": {
                "text": f"STRIDE threat category: {full_name}",
            },
            "defaultConfiguration": {
                "level": default_level,
            },
        })

    # --- Build results -------------------------------------------------------
    results: list[dict] = []
    for t in threats:
        cat = t.get("stride_category", "")
        rule_id = f"STRIDE-{cat}" if cat else "STRIDE-unknown"
        priority = t.get("priority", "Medium")
        level = _SARIF_LEVEL_MAP.get(priority, "warning")

        dread_breakdown = {
            "D": t.get("damage", 0),
            "R": t.get("reproducibility", 0),
            "E": t.get("exploitability", 0),
            "A": t.get("affected_users", 0),
            "D2": t.get("discoverability", 0),
        }
        evidence = t.get("evidence_sources", [])

        result: dict = {
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": t.get("description", ""),
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": t.get("component", "unknown"),
                        },
                    },
                },
            ],
            "properties": {
                "threat_id": t.get("id", ""),
                "dread_total": t.get("dread_total", 0),
                "dread_breakdown": dread_breakdown,
                "priority": priority,
                "mitigation": t.get("mitigation", ""),
                "methodology": t.get("methodology", ""),
                "confidence_score": t.get("confidence_score", 0),
                "evidence_sources": len(evidence) if isinstance(evidence, list) else 0,
            },
            "fingerprints": {
                "threat_id": t.get("id", ""),
            },
        }
        results.append(result)

    # --- Assemble SARIF document ---------------------------------------------
    sarif_doc = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
            "main/sarif-2.1/schema/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AgenticTM",
                        "version": __version__,
                        "informationUri": "https://github.com/richi-tj/agent-threat-modeler",
                        "rules": rules,
                    },
                },
                "results": results,
            },
        ],
    }

    return json.dumps(sarif_doc, indent=2, ensure_ascii=False)
