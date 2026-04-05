"""LangChain tools para que los agentes consulten el RAG (hybrid: vector + tree).

Evidence traceability (I09): All RAG tool results now include structured
source citations that agents should preserve in their threat outputs as
``evidence_sources`` entries.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from langchain_core.tools import tool

if TYPE_CHECKING:
    from agentictm.rag import RAGStoreManager

# Referencia global — se inyecta al construir el graph
_store_manager: RAGStoreManager | None = None
_active_categories: list[str] | None = None

# Citation instruction appended to RAG results so agents propagate sources
_CITATION_INSTRUCTION = (
    "\n\n---\n"
    "IMPORTANT: When using facts from the above sources in your threat analysis, "
    "include them in the threat's `evidence_sources` field using this format:\n"
    '  {"source_type": "rag", "source_name": "<document name>", "excerpt": "<relevant quote>"}\n'
)


def set_store_manager(manager: RAGStoreManager) -> None:
    """Inyecta el RAGStoreManager global para que los tools lo usen."""
    global _store_manager
    _store_manager = manager


def set_active_categories(categories: list[str]) -> None:
    """Set active threat categories for filtered RAG queries."""
    global _active_categories
    _active_categories = categories


def _get_manager() -> RAGStoreManager:
    if _store_manager is None:
        raise RuntimeError("RAGStoreManager no inicializado. Llamar set_store_manager() primero.")
    return _store_manager


@tool
def rag_query_books(query: str) -> str:
    """Consulta la biblioteca de libros de threat modeling (PDFs).
    Usa búsqueda híbrida: navegación por estructura del documento (PageIndex)
    + similitud vectorial (ChromaDB). Ideal para libros largos y técnicos."""
    result = _get_manager().hybrid_query("books", query)
    return result + _CITATION_INSTRUCTION


@tool
def rag_query_research(query: str) -> str:
    """Consulta papers de investigación, frameworks y guías de threat modeling.
    Usa búsqueda híbrida para papers PDF + similitud vectorial para markdown.
    Útil para encontrar técnicas avanzadas, herramientas y enfoques modernos."""
    result = _get_manager().hybrid_query("research", query)
    return result + _CITATION_INSTRUCTION


@tool
def rag_query_risks(query: str) -> str:
    """Consulta la base de riesgos y mitigaciones conocidos.
    Útil para encontrar patrones de ataque, debilidades y controles de seguridad.
    Los resultados se filtran por las categorías activas del proyecto (AWS, AI, etc.)."""
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
    cleaned = _re.sub(r",Amenaza,No,", " [Amenaza]: ", cleaned)

    return cleaned + _CITATION_INSTRUCTION


@tool
def rag_query_previous_tms(query: str) -> str:
    """Consulta threat models previos de la organización.
    Útil para mantener consistencia, aprender el formato y reutilizar findings."""
    result = _get_manager().query("previous_threat_models", query)
    return result + _CITATION_INSTRUCTION


@tool
def rag_query_ai_threats(query: str) -> str:
    """Consulta la base de amenazas específicas de AI/ML (PLOT4ai, OWASP AI, etc.).
    Usa búsqueda híbrida para PDFs de AI threats + similitud vectorial para JSON/CSV."""
    result = _get_manager().hybrid_query("ai_threats", query)
    return result + _CITATION_INSTRUCTION


# Grupos de tools por fase/agente
ANALYST_TOOLS = [rag_query_books, rag_query_research, rag_query_risks, rag_query_previous_tms]
AI_ANALYST_TOOLS = [rag_query_books, rag_query_research, rag_query_risks, rag_query_ai_threats, rag_query_previous_tms]
SYNTHESIS_TOOLS = [rag_query_previous_tms, rag_query_risks, rag_query_ai_threats]
DEBATE_TOOLS = [rag_query_books, rag_query_research, rag_query_risks, rag_query_ai_threats, rag_query_previous_tms]
VALIDATOR_TOOLS = [rag_query_previous_tms, rag_query_risks]
ALL_RAG_TOOLS = [rag_query_books, rag_query_research, rag_query_risks, rag_query_previous_tms, rag_query_ai_threats]
