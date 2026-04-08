"""Knowledge Base Auto-Updater — fetches latest security data sources.

Downloads and indexes current versions of key security knowledge bases:
- OWASP Top 10 (Web, API, LLM)
- CWE (Common Weakness Enumeration) top entries
- MITRE ATT&CK Enterprise Matrix (tactics + techniques)

Usage::

    from agentictm.agents.kb_updater import update_knowledge_base

    stats = update_knowledge_base(kb_path="rag")
    print(f"Updated: {stats['sources_updated']} sources, {stats['documents_added']} documents")
"""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# Sources to fetch
_SOURCES: list[dict[str, str]] = [
    {
        "name": "OWASP_Top_10_Web_2021",
        "url": "https://raw.githubusercontent.com/OWASP/Top10/master/2021/docs/index.md",
        "category": "owasp",
        "filename": "owasp_top10_web_2021.md",
    },
    {
        "name": "OWASP_API_Security_Top_10_2023",
        "url": "https://raw.githubusercontent.com/OWASP/API-Security/master/editions/2023/en/0x11-t10.md",
        "category": "owasp",
        "filename": "owasp_api_top10_2023.md",
    },
    {
        "name": "OWASP_LLM_Top_10",
        "url": "https://raw.githubusercontent.com/OWASP/www-project-top-10-for-large-language-model-applications/main/llm-top-10-governance-doc/LLM_AI_Security_and_Governance_Checklist-v1.1.md",
        "category": "owasp",
        "filename": "owasp_llm_top10.md",
    },
    {
        "name": "MITRE_ATT&CK_Enterprise_Tactics",
        "url": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        "category": "mitre",
        "filename": "mitre_attack_enterprise.json",
    },
    {
        "name": "CWE_Top_25_2023",
        "url": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        "category": "cwe",
        "filename": "cwe_top25.md",
        "skip_download": True,  # Too large; we'll provide a curated version
    },
]

# Curated CWE Top 25 (2023) — hardcoded since the full XML is 100MB+
_CWE_TOP_25 = """# CWE Top 25 Most Dangerous Software Weaknesses (2023)

| Rank | CWE ID | Name |
|------|--------|------|
| 1 | CWE-787 | Out-of-bounds Write |
| 2 | CWE-79 | Cross-site Scripting (XSS) |
| 3 | CWE-89 | SQL Injection |
| 4 | CWE-416 | Use After Free |
| 5 | CWE-78 | OS Command Injection |
| 6 | CWE-20 | Improper Input Validation |
| 7 | CWE-125 | Out-of-bounds Read |
| 8 | CWE-22 | Path Traversal |
| 9 | CWE-352 | Cross-Site Request Forgery (CSRF) |
| 10 | CWE-434 | Unrestricted Upload of File with Dangerous Type |
| 11 | CWE-862 | Missing Authorization |
| 12 | CWE-476 | NULL Pointer Dereference |
| 13 | CWE-287 | Improper Authentication |
| 14 | CWE-190 | Integer Overflow or Wraparound |
| 15 | CWE-502 | Deserialization of Untrusted Data |
| 16 | CWE-77 | Command Injection |
| 17 | CWE-119 | Improper Restriction of Operations within Memory Buffer |
| 18 | CWE-798 | Use of Hard-coded Credentials |
| 19 | CWE-918 | Server-Side Request Forgery (SSRF) |
| 20 | CWE-306 | Missing Authentication for Critical Function |
| 21 | CWE-362 | Race Condition (TOCTOU) |
| 22 | CWE-269 | Improper Privilege Management |
| 23 | CWE-94 | Code Injection |
| 24 | CWE-863 | Incorrect Authorization |
| 25 | CWE-276 | Incorrect Default Permissions |
"""


def update_knowledge_base(
    kb_path: str | Path = "rag",
    *,
    timeout: int = 30,
    force: bool = False,
) -> dict[str, Any]:
    """Download and update security knowledge base sources.

    Args:
        kb_path: Path to the knowledge base directory
        timeout: HTTP request timeout in seconds
        force: Re-download even if files already exist

    Returns:
        Dict with stats: sources_updated, sources_failed, documents_added
    """
    kb_dir = Path(kb_path) / "auto_updated"
    kb_dir.mkdir(parents=True, exist_ok=True)

    stats: dict[str, Any] = {
        "sources_updated": 0,
        "sources_failed": 0,
        "sources_skipped": 0,
        "documents_added": 0,
        "updated_at": datetime.now().isoformat(),
        "details": [],
    }

    for source in _SOURCES:
        name = source["name"]
        filename = source["filename"]
        filepath = kb_dir / filename

        # Skip if already exists and not forcing
        if filepath.exists() and not force:
            stats["sources_skipped"] += 1
            stats["details"].append({"name": name, "status": "skipped", "reason": "already exists"})
            continue

        # Handle special cases
        if source.get("skip_download"):
            # Write curated content
            if "cwe" in source["category"]:
                filepath.write_text(_CWE_TOP_25, encoding="utf-8")
                stats["sources_updated"] += 1
                stats["documents_added"] += 1
                stats["details"].append({"name": name, "status": "updated", "method": "curated"})
            continue

        # Download
        try:
            logger.info("[KB Updater] Downloading %s...", name)
            req = urllib.request.Request(source["url"], headers={"User-Agent": "AgenticTM/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as response:
                content = response.read()

                # Handle JSON (MITRE ATT&CK) — extract tactics/techniques summary
                if filename.endswith(".json"):
                    try:
                        data = json.loads(content)
                        content = _extract_mitre_summary(data).encode("utf-8")
                        filename = filename.replace(".json", ".md")
                        filepath = kb_dir / filename
                    except json.JSONDecodeError:
                        pass

                filepath.write_bytes(content)
                stats["sources_updated"] += 1
                stats["documents_added"] += 1
                stats["details"].append({
                    "name": name,
                    "status": "updated",
                    "size_kb": round(len(content) / 1024, 1),
                })

        except (urllib.error.URLError, TimeoutError) as e:
            logger.warning("[KB Updater] Failed to download %s: %s", name, e)
            stats["sources_failed"] += 1
            stats["details"].append({"name": name, "status": "failed", "error": str(e)})

    logger.info(
        "[KB Updater] Done: %d updated, %d failed, %d skipped",
        stats["sources_updated"], stats["sources_failed"], stats["sources_skipped"],
    )

    return stats


def _extract_mitre_summary(data: dict[str, Any]) -> str:
    """Extract a readable summary from MITRE ATT&CK STIX bundle."""
    lines = ["# MITRE ATT&CK Enterprise Matrix\n"]

    objects = data.get("objects", [])
    tactics = [o for o in objects if o.get("type") == "x-mitre-tactic"]
    techniques = [o for o in objects if o.get("type") == "attack-pattern" and not o.get("revoked")]

    lines.append(f"**Tactics**: {len(tactics)} | **Techniques**: {len(techniques)}\n")

    # Group techniques by tactic
    tactic_map: dict[str, list[str]] = {}
    for tactic in sorted(tactics, key=lambda t: t.get("x_mitre_shortname", "")):
        shortname = tactic.get("x_mitre_shortname", "unknown")
        name = tactic.get("name", shortname)
        tactic_map[shortname] = []
        lines.append(f"\n## {name}")
        desc = tactic.get("description", "")
        if desc:
            lines.append(desc[:300])

    # List top 5 techniques per tactic
    for tech in techniques[:200]:  # Cap to avoid huge output
        phases = tech.get("kill_chain_phases", [])
        for phase in phases:
            tactic_name = phase.get("phase_name", "")
            if tactic_name in tactic_map:
                tactic_map[tactic_name].append(tech.get("name", "Unknown"))

    for tactic_short, techs in tactic_map.items():
        if techs:
            lines.append(f"\n### Techniques for {tactic_short}")
            for t in techs[:10]:
                lines.append(f"- {t}")

    return "\n".join(lines)
