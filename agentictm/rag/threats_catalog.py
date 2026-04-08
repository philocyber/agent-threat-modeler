"""Direct threats.csv catalog — loads without vector search.

This module reads rag/risks_mitigations/threats.csv directly,
classifies each entry by technology category, and returns filtered subsets
to inject into agent prompts.

The motivation is ensuring agents ALWAYS have the full catalog of known
threats and controls, without relying on vector search retrieval — coverage
goes from ~30% (top-K RAG) to 100% for the project's active categories.
"""

from __future__ import annotations

import csv
import logging
from functools import lru_cache
from pathlib import Path
from typing import NamedTuple

from agentictm.rag.categories import classify_threat

logger = logging.getLogger(__name__)

# Default catalog path
_DEFAULT_CATALOG_PATH = Path("rag/risks_mitigations/threats.csv")

# Max entries to include per type to avoid oversized prompts
_MAX_PER_TIPO = 40


class ThreatEntry(NamedTuple):
    """Normalized entry from threats.csv."""
    id: str
    titulo: str
    tipo: str          # "Amenaza" | "Control"
    privado: str       # "Sí" | "No"
    descripcion: str
    categories: frozenset[str]  # categorías detectadas automáticamente


# ---------------------------------------------------------------------------
# Catalog loader
# ---------------------------------------------------------------------------

def _load_catalog(csv_path: Path) -> list[ThreatEntry]:
    """Read threats.csv and build the list of ThreatEntry with categories."""
    entries: list[ThreatEntry] = []
    try:
        with open(csv_path, encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                tid = row.get("id", "").strip()
                titulo = row.get("Titulo", row.get("titulo", "")).strip()
                tipo = row.get("Tipo", row.get("tipo", "")).strip()
                privado = row.get("Privado", row.get("privado", "No")).strip()
                descripcion = row.get("Descripcion", row.get("descripcion", "")).strip()

                cats = classify_threat(titulo, descripcion)
                entries.append(ThreatEntry(
                    id=tid,
                    titulo=titulo,
                    tipo=tipo,
                    privado=privado,
                    descripcion=descripcion,
                    categories=frozenset(cats),
                ))
    except FileNotFoundError:
        logger.warning("[ThreatsCatalog] threats.csv not found at: %s", csv_path)
    except Exception as exc:
        logger.error("[ThreatsCatalog] Error loading threats.csv: %s", exc)
    return entries


# Cache the full catalog — it changes only when the CSV is re-indexed
@lru_cache(maxsize=4)
def _cached_catalog(csv_path: str) -> tuple[ThreatEntry, ...]:
    return tuple(_load_catalog(Path(csv_path)))


def _get_catalog(catalog_path: Path | None = None) -> list[ThreatEntry]:
    path = catalog_path or _DEFAULT_CATALOG_PATH
    return list(_cached_catalog(str(path.resolve())))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_threats_for_categories(
    active_categories: list[str],
    tipos: list[str] | None = None,
    catalog_path: Path | None = None,
    max_per_tipo: int = _MAX_PER_TIPO,
) -> dict[str, list[ThreatEntry]]:
    """Return threats/controls filtered by active categories.

    Args:
        active_categories: List of active categories (e.g. ["aws", "ai", "base"]).
        tipos: Type filter; defaults to ["Amenaza", "Control"] (CSV column values).
        catalog_path: Path to CSV; if None uses the default path.
        max_per_tipo: Max entries returned per type.

    Returns:
        Dict {"Amenaza": [...], "Control": [...]} with relevant entries.
    """
    target_tipos = tipos or ["Amenaza", "Control"]
    active = set(active_categories) | {"base"}

    all_entries = _get_catalog(catalog_path)
    logger.debug("[ThreatsCatalog] Catalog size: %d entries", len(all_entries))

    result: dict[str, list[ThreatEntry]] = {t: [] for t in target_tipos}
    for entry in all_entries:
        if entry.tipo not in target_tipos:
            continue
        # Include if shared categories with active set
        if entry.categories & active:
            result[entry.tipo].append(entry)

    # Apply per-tipo cap (prioritise generic "base" entries last to keep
    # technology-specific ones at the top of each list)
    for tipo in target_tipos:
        bucket = result[tipo]
        if len(bucket) > max_per_tipo:
            # Sort: tech-specific first (fewer categories = more specific)
            bucket.sort(key=lambda e: len(e.categories))
            result[tipo] = bucket[:max_per_tipo]

    total = sum(len(v) for v in result.values())
    logger.info(
        "[ThreatsCatalog] Filtered %d/%d entries for categories %s",
        total, len(all_entries), sorted(active),
    )
    return result


def format_threats_for_prompt(
    threats_by_tipo: dict[str, list[ThreatEntry]],
    *,
    include_ids: bool = False,
) -> str:
    """Format the filtered catalog as a text block for prompts.

    TMA-xxxx IDs are excluded by default to prevent agents from
    copying them literally into their output.
    """
    lines: list[str] = []

    amenazas = threats_by_tipo.get("Amenaza", [])
    controles = threats_by_tipo.get("Control", [])

    if amenazas:
        lines.append(f"### Known Threats ({len(amenazas)} relevant entries)")
        for e in amenazas:
            prefix = f"[{e.id}] " if include_ids else ""
            lines.append(f"- **{prefix}{e.titulo}**: {e.descripcion}")
        lines.append("")

    if controles:
        lines.append(f"### Known Controls / Mitigations ({len(controles)} relevant entries)")
        for e in controles:
            prefix = f"[{e.id}] " if include_ids else ""
            lines.append(f"- **{prefix}{e.titulo}**: {e.descripcion}")
        lines.append("")

    return "\n".join(lines)


def get_catalog_summary(catalog_path: Path | None = None) -> dict[str, int]:
    """Return catalog statistics for diagnostics."""
    entries = _get_catalog(catalog_path)
    by_cat: dict[str, int] = {}
    by_tipo: dict[str, int] = {}
    for e in entries:
        by_tipo[e.tipo] = by_tipo.get(e.tipo, 0) + 1
        for cat in e.categories:
            by_cat[cat] = by_cat.get(cat, 0) + 1
    return {
        "total": len(entries),
        "by_tipo": by_tipo,
        "by_category": dict(sorted(by_cat.items(), key=lambda x: -x[1])),
    }


def invalidate_cache() -> None:
    """Invalidate the catalog cache (useful after re-indexing)."""
    _cached_catalog.cache_clear()
    logger.info("[ThreatsCatalog] Cache invalidated")
