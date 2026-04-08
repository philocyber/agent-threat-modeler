"""LangChain tools for agents to query the RAG system (hybrid: vector + tree).

Evidence traceability (I09): All RAG tool results now include structured
source citations that agents should preserve in their threat outputs as
``evidence_sources`` entries.

v2.0.0: Cross-encoder reranking (ms-marco-MiniLM-L6-v2) applied when available.
v2.1.0: rag_query_threats_catalog — direct threats.csv lookup filtered by active
        project categories (100% coverage, no vector-search gaps).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from langchain_core.tools import tool

if TYPE_CHECKING:
    from agentictm.rag import RAGStoreManager

logger = logging.getLogger(__name__)

_store_manager: RAGStoreManager | None = None
_active_categories: list[str] | None = None
_catalog_path: Path | None = None  # override for tests / custom setups

# Citation instruction appended to RAG results so agents propagate sources
_CITATION_INSTRUCTION = (
    "\n\n---\n"
    "IMPORTANT: When using facts from the above sources in your threat analysis, "
    "include them in the threat's `evidence_sources` field using this format:\n"
    '  {"source_type": "rag", "source_name": "<document name>", "excerpt": "<relevant quote>"}\n'
)


def set_store_manager(manager: RAGStoreManager) -> None:
    """Inject the global RAGStoreManager for tool access."""
    global _store_manager
    _store_manager = manager


def set_active_categories(categories: list[str]) -> None:
    """Set active threat categories for filtered RAG queries."""
    global _active_categories
    _active_categories = categories


def set_catalog_path(path: Path) -> None:
    """Override the default threats.csv path (useful for tests)."""
    global _catalog_path
    _catalog_path = path


def _get_manager() -> RAGStoreManager:
    if _store_manager is None:
        raise RuntimeError("RAGStoreManager not initialized. Call set_store_manager() first.")
    return _store_manager


@tool
def rag_query_books(query: str) -> str:
    """Query the threat modeling book library (PDFs).
    Uses hybrid search: document structure navigation (PageIndex)
    + vector similarity (ChromaDB). Ideal for long technical books."""
    result = _get_manager().hybrid_query("books", query)
    return result + _CITATION_INSTRUCTION


@tool
def rag_query_research(query: str) -> str:
    """Query research papers, frameworks, and threat modeling guides.
    Uses hybrid search for PDF papers + vector similarity for markdown.
    Useful for finding advanced techniques, tools, and modern approaches."""
    result = _get_manager().hybrid_query("research", query)
    return result + _CITATION_INSTRUCTION


@tool
def rag_query_risks(query: str) -> str:
    """Query the known risks and mitigations database.
    Useful for finding attack patterns, weaknesses, and security controls.
    Results are filtered by active project categories (AWS, AI, etc.)."""
    import logging as _logging
    import re as _re
    _log = _logging.getLogger(__name__)
    raw = _get_manager().query("risks_mitigations", query, top_k=8)
    # Apply category filtering if active categories are set
    if _active_categories and set(_active_categories) != {"auto"}:
        from agentictm.rag.categories import CATEGORY_KEYWORDS
        active_kws: set[str] = set()
        for cat in _active_categories:
            active_kws.update(CATEGORY_KEYWORDS.get(cat, []))
        active_kws.add("base")  # always include base
        if active_kws:
            sections = raw.split("\n\n" + "\u2500" * 40 + "\n\n")
            filtered = []
            for sec in sections:
                sec_lower = sec.lower()
                if any(kw in sec_lower for kw in active_kws) or not active_kws:
                    filtered.append(sec)
            if filtered:
                _log.debug("RAG risks filter: %d/%d sections matched active categories", len(filtered), len(sections))
                raw = ("\n\n" + "\u2500" * 40 + "\n\n").join(filtered)

    cleaned = _re.sub(r"TMA-[0-9A-Fa-f]{4},", "", raw)
    cleaned = _re.sub(r",Control,No,", " [Control]: ", cleaned)
    cleaned = _re.sub(r",Amenaza,No,", " [Threat]: ", cleaned)

    return cleaned + _CITATION_INSTRUCTION


@tool
def rag_query_previous_tms(query: str) -> str:
    """Query previous threat models from the organization.
    Useful for maintaining consistency, learning the format, and reusing findings."""
    result = _get_manager().query("previous_threat_models", query)
    return result + _CITATION_INSTRUCTION


@tool
def rag_query_ai_threats(query: str) -> str:
    """Query the AI/ML-specific threat database (PLOT4ai, OWASP AI, etc.).
    Uses hybrid search for AI threat PDFs + vector similarity for JSON/CSV."""
    result = _get_manager().hybrid_query("ai_threats", query)
    return result + _CITATION_INSTRUCTION


@tool
def rag_query_threats_catalog(query: str) -> str:
    """Query the curated threats-and-controls catalog (threats.csv).

    Unlike vector-search tools, this returns the COMPLETE set of known
    threats and mitigations that are relevant to the active project
    categories (e.g. AWS, Azure, GCP, AI, web, privacy…).

    Use this tool FIRST when starting any threat analysis — it guarantees
    100% coverage of the reference catalog for the current technology stack,
    without the recall gaps of approximate nearest-neighbour search.

    The query parameter can be used to search within the filtered results,
    but all category-matched entries are always considered.
    """
    import re as _re
    from agentictm.rag.threats_catalog import (
        get_threats_for_categories,
        format_threats_for_prompt,
    )

    cats = list(_active_categories) if _active_categories else ["base"]
    logger.debug("[ThreatsCatalog tool] Active categories: %s", cats)

    threats_by_tipo = get_threats_for_categories(cats, catalog_path=_catalog_path)
    formatted = format_threats_for_prompt(threats_by_tipo, include_ids=False)

    if not formatted.strip():
        return (
            "No threats found in catalog for the active project categories. "
            "Proceeding with general threat knowledge.\n" + _CITATION_INSTRUCTION
        )

    # Optional semantic sub-filter when a meaningful query is given
    if query and len(query.strip()) > 5:
        query_lower = query.lower()
        query_terms = set(_re.findall(r"\b\w{4,}\b", query_lower))
        if query_terms:
            lines = formatted.split("\n")
            scored: list[tuple[int, str]] = []
            for line in lines:
                hits = sum(1 for t in query_terms if t in line.lower())
                scored.append((hits, line))
            # Keep header lines (### …) and lines with ≥1 hit, up to 80 lines
            kept = [ln for (sc, ln) in scored if sc > 0 or ln.startswith("#")][:80]
            if kept:
                formatted = "\n".join(kept)

    header = (
        "## Threats & Controls Catalog (threats.csv — category-filtered)\n"
        "IMPORTANT: Use these as REFERENCE KNOWLEDGE ONLY.\n"
        "- DO NOT copy entry titles or descriptions verbatim into your output.\n"
        "- DO NOT reference catalog IDs (TMA-xxxx) in your threat list.\n"
        "- Use them to validate your own findings and suggest concrete mitigations.\n\n"
    )
    return header + formatted + _CITATION_INSTRUCTION


# Tool groups by phase/agent
ANALYST_TOOLS = [rag_query_threats_catalog, rag_query_books, rag_query_research, rag_query_risks, rag_query_previous_tms]
AI_ANALYST_TOOLS = [rag_query_threats_catalog, rag_query_books, rag_query_research, rag_query_risks, rag_query_ai_threats, rag_query_previous_tms]
SYNTHESIS_TOOLS = [rag_query_threats_catalog, rag_query_previous_tms, rag_query_risks, rag_query_ai_threats]
DEBATE_TOOLS = [rag_query_threats_catalog, rag_query_books, rag_query_research, rag_query_risks, rag_query_ai_threats, rag_query_previous_tms]
VALIDATOR_TOOLS = [rag_query_threats_catalog, rag_query_previous_tms, rag_query_risks]
ALL_RAG_TOOLS = [rag_query_threats_catalog, rag_query_books, rag_query_research, rag_query_risks, rag_query_previous_tms, rag_query_ai_threats]
