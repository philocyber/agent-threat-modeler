"""Indexador de documentos a los vector stores + PageIndex tree builder."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

import fitz  # PyMuPDF — replaces PyPDFLoader for PDFs

from langchain_community.document_loaders import (
    CSVLoader,
    TextLoader,
    JSONLoader,
)
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter

from agentictm.rag.page_index import (
    build_page_index,
    save_tree,
    is_tree_current,
    DocumentTree,
)

if TYPE_CHECKING:
    from agentictm.rag import RAGStoreManager

logger = logging.getLogger(__name__)

# Default tree index output directory
_DEFAULT_TREE_DIR = Path("data/page_indices")

# Default hash manifest path for incremental indexing (I05)
_DEFAULT_HASH_MANIFEST = Path("data/vector_stores/.index_manifest.json")


def _file_hash(path: Path) -> str:
    """Hash rápido del contenido de un archivo."""
    return hashlib.md5(path.read_bytes()).hexdigest()


def _load_hash_manifest(manifest_path: Path) -> dict[str, dict[str, str]]:
    """Load the incremental indexing manifest: {store_name: {filename: md5}}."""
    if manifest_path.exists():
        try:
            return json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save_hash_manifest(manifest_path: Path, manifest: dict[str, dict[str, str]]) -> None:
    """Save the incremental indexing manifest."""
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def get_index_status(
    knowledge_base_path: Path,
    manifest_path: Path | None = None,
) -> dict[str, Any]:
    """Return indexing status for all knowledge base documents (I05).

    Returns dict with per-store status: {store: [{name, hash, indexed, changed}]}
    """
    actual_manifest = manifest_path or _DEFAULT_HASH_MANIFEST
    manifest = _load_hash_manifest(actual_manifest)

    from agentictm.rag import ALL_STORES

    status: dict[str, list[dict]] = {}
    for store_name in ALL_STORES:
        source = knowledge_base_path / store_name
        store_manifest = manifest.get(store_name, {})
        docs = []
        if source.exists():
            for f in sorted(source.rglob("*")):
                if f.is_file() and not f.name.startswith("."):
                    current_hash = _file_hash(f)
                    prev_hash = store_manifest.get(f.name)
                    docs.append({
                        "name": f.name,
                        "size_bytes": f.stat().st_size,
                        "hash": current_hash,
                        "indexed": prev_hash is not None,
                        "changed": prev_hash is not None and prev_hash != current_hash,
                    })
        status[store_name] = docs
    return status


def _load_file(path: Path) -> list[Document]:
    """Carga un archivo según su extensión."""
    suffix = path.suffix.lower()

    if suffix == ".pdf":
        return _load_pdf_pymupdf(path)
    if suffix in (".md", ".txt", ".rst"):
        return TextLoader(str(path), encoding="utf-8").load()
    if suffix == ".csv":
        # Cargar cada fila como doc individual + el archivo completo
        rows = CSVLoader(str(path), encoding="utf-8").load()
        full = Document(
            page_content=path.read_text(encoding="utf-8"),
            metadata={"source": str(path), "type": "full_csv"},
        )
        return rows + [full]
    if suffix == ".json":
        try:
            return _load_json_smart(path)
        except Exception:
            # Fallback: cargar como texto
            return TextLoader(str(path), encoding="utf-8").load()

    logger.warning("Extensión no soportada, cargando como texto: %s", path)
    return TextLoader(str(path), encoding="utf-8").load()


def _load_pdf_pymupdf(path: Path) -> list[Document]:
    """Load a PDF using PyMuPDF (fitz) for better text extraction.

    Returns one Document per page with page number metadata.
    PyMuPDF handles complex layouts, multi-column text, and tables
    much better than the basic PyPDFLoader.
    """
    docs = []
    try:
        pdf = fitz.open(str(path))
        for page_num, page in enumerate(pdf):
            text = page.get_text("text")
            if text.strip():
                docs.append(Document(
                    page_content=text,
                    metadata={
                        "source": path.name,
                        "page": page_num + 1,
                        "total_pages": len(pdf),
                    },
                ))
        pdf.close()
    except Exception as exc:
        logger.error("PyMuPDF failed for %s: %s — falling back to text", path, exc)
        try:
            docs = [Document(
                page_content=path.read_text(encoding="utf-8", errors="replace"),
                metadata={"source": path.name},
            )]
        except Exception:
            pass
    return docs


def _load_json_smart(path: Path) -> list[Document]:
    """Smart JSON loader: detects PLOT4ai deck format or generic JSON."""
    data = json.loads(path.read_text(encoding="utf-8"))

    # Detect PLOT4ai deck.json format: list of categories with cards
    if isinstance(data, list) and data and "cards" in data[0]:
        return _load_plot4ai_deck(data, path)

    # Generic JSON array
    if isinstance(data, list):
        docs = []
        for item in data:
            docs.append(Document(
                page_content=json.dumps(item, ensure_ascii=False, indent=2),
                metadata={"source": path.name, "type": "json_item"},
            ))
        return docs

    # Single JSON object
    return [Document(
        page_content=json.dumps(data, ensure_ascii=False, indent=2),
        metadata={"source": path.name, "type": "json_object"},
    )]


def _load_plot4ai_deck(data: list[dict], path: Path) -> list[Document]:
    """Load PLOT4ai threat deck format into individual card documents.

    Each card becomes a document with rich metadata for category-based retrieval.
    """
    docs = []
    for category_block in data:
        category = category_block.get("category", "Unknown")

        for card in category_block.get("cards", []):
            label = card.get("label", "")
            question = card.get("question", "")
            explanation = card.get("explanation", "")
            recommendation = card.get("recommendation", "")
            threat_if = card.get("threatif", "")
            ai_types = ", ".join(card.get("aitypes", []))
            roles = ", ".join(card.get("roles", []))
            phases = ", ".join(card.get("phases", []))
            sources = card.get("sources", "")
            sub_categories = ", ".join(card.get("categories", []))

            content = (
                f"## {label}\n\n"
                f"**Category:** {category}\n"
                f"**Sub-categories:** {sub_categories}\n"
                f"**Question:** {question}\n"
                f"**Threat if:** {threat_if}\n"
                f"**AI Types:** {ai_types}\n"
                f"**Roles:** {roles}\n"
                f"**Phases:** {phases}\n\n"
                f"### Explanation\n{explanation}\n\n"
                f"### Recommendation\n{recommendation}\n\n"
            )
            if sources:
                content += f"### Sources\n{sources}\n"

            docs.append(Document(
                page_content=content,
                metadata={
                    "source": path.name,
                    "type": "plot4ai_card",
                    "category": category,
                    "label": label,
                    "threat_if": threat_if,
                    "ai_types": ai_types,
                    "phases": phases,
                },
            ))

    logger.info("  PLOT4ai deck: %d cards from %d categories", len(docs), len(data))
    return docs


def index_store(
    store_manager: RAGStoreManager,
    store_name: str,
    source_dir: Path,
    chunk_size: int = 1000,
    chunk_overlap: int = 200,
    manifest: dict[str, dict[str, str]] | None = None,
    force: bool = False,
) -> int:
    """Indexa todos los archivos de un directorio a un vector store.

    Incremental indexing (I05): if *manifest* is provided, only files whose
    MD5 hash has changed (or are new) are re-indexed. Pass ``force=True``
    to re-index everything.

    Returns:
        Cantidad de chunks indexados.
    """
    if not source_dir.exists():
        logger.info("Directorio no existe, creando: %s", source_dir)
        source_dir.mkdir(parents=True, exist_ok=True)
        return 0

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        separators=["\n\n", "\n", ". ", " ", ""],
    )

    store = store_manager.get_store(store_name)
    total_chunks = 0

    # Incremental: get previous hashes
    store_manifest = (manifest or {}).get(store_name, {})

    files = sorted(
        f for f in source_dir.rglob("*")
        if f.is_file() and not f.name.startswith(".")
    )

    for file_path in files:
        # Skip unchanged files if incremental (I05)
        if not force and store_manifest:
            current_hash = _file_hash(file_path)
            prev_hash = store_manifest.get(file_path.name)
            if prev_hash and prev_hash == current_hash:
                logger.info("  [Incremental] Skipping unchanged: %s", file_path.name)
                continue

        logger.info("Indexando [%s]: %s", store_name, file_path.name)
        try:
            docs = _load_file(file_path)
            for doc in docs:
                doc.metadata["source"] = str(file_path.name)
                doc.metadata["store"] = store_name

            chunks = splitter.split_documents(docs)
            if chunks:
                store.add_documents(chunks)
                total_chunks += len(chunks)
                logger.info("  → %d chunks", len(chunks))

            if manifest is not None:
                manifest.setdefault(store_name, {})[file_path.name] = _file_hash(file_path)
        except Exception as exc:
            logger.error("Error indexando %s: %s", file_path, exc)

    logger.info("Store '%s': %d chunks totales de %d archivos", store_name, total_chunks, len(files))
    return total_chunks


def index_all(
    store_manager: RAGStoreManager,
    knowledge_base_path: Path,
    chunk_size: int = 1000,
    chunk_overlap: int = 200,
    tree_dir: Path | None = None,
    llm: Any | None = None,
    force: bool = False,
    manifest_path: Path | None = None,
) -> dict[str, int]:
    """Indexa todas las carpetas de knowledge_base.

    Builds both ChromaDB vector stores (for text chunks) AND
    PageIndex tree indices (for PDFs) — enabling hybrid retrieval.

    Incremental indexing (I05): only new/changed documents are re-indexed
    unless ``force=True``.

    Espera la siguiente estructura:
        knowledge_base/
        ├── books/
        ├── research/
        ├── risks_mitigations/
        ├── previous_threat_models/
        └── ai_threats/          (PLOT4ai deck.json, etc.)

    Args:
        tree_dir: Directory to store .tree.json files. Default: data/page_indices
        llm: Optional LangChain LLM for generating tree node summaries.
        force: If True, re-index everything regardless of hash.
        manifest_path: Path to hash manifest. Default: data/vector_stores/.index_manifest.json
    """
    from agentictm.rag import ALL_STORES

    actual_tree_dir = tree_dir or _DEFAULT_TREE_DIR
    actual_tree_dir.mkdir(parents=True, exist_ok=True)

    actual_manifest_path = manifest_path or _DEFAULT_HASH_MANIFEST
    manifest = _load_hash_manifest(actual_manifest_path) if not force else {}

    results = {}
    for store_name in ALL_STORES:
        source = knowledge_base_path / store_name
        results[store_name] = index_store(
            store_manager, store_name, source,
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap,
            manifest=manifest,
            force=force,
        )

    # Save updated manifest
    _save_hash_manifest(actual_manifest_path, manifest)

    # Build PageIndex trees for all PDFs
    try:
        tree_count = build_trees_for_knowledge_base(
            knowledge_base_path, actual_tree_dir, llm=llm,
        )
    except Exception:
        raise
    results["_page_index_trees"] = tree_count

    return results


# ---------------------------------------------------------------------------
# PageIndex tree building
# ---------------------------------------------------------------------------

def build_trees_for_knowledge_base(
    knowledge_base_path: Path,
    tree_dir: Path,
    llm: Any | None = None,
    generate_summaries: bool = True,
) -> int:
    """Build PageIndex trees for all PDFs in the knowledge base.

    Only rebuilds trees for PDFs that have changed since last indexing
    (uses MD5 hash for cache invalidation).

    Returns the number of trees built.
    """
    tree_dir.mkdir(parents=True, exist_ok=True)

    pdf_files = sorted(knowledge_base_path.rglob("*.pdf"))
    if not pdf_files:
        logger.info("[PageIndex] No PDF files found in knowledge base")
        return 0

    logger.info("[PageIndex] Found %d PDFs to index", len(pdf_files))
    built = 0

    for pdf_path in pdf_files:
        tree_path = tree_dir / f"{pdf_path.stem}.tree.json"

        # Skip if tree is already up-to-date
        if is_tree_current(pdf_path, tree_path):
            logger.info("[PageIndex] Tree up-to-date, skipping: %s", pdf_path.name)
            continue

        try:
            logger.info("[PageIndex] Building tree for: %s", pdf_path.name)
            doc_tree = build_page_index(
                pdf_path,
                llm=llm,
                generate_summaries=generate_summaries,
            )
            save_tree(doc_tree, tree_dir)
            built += 1
            logger.info(
                "[PageIndex] ✓ %s — %d nodes",
                pdf_path.name, len(doc_tree.all_nodes()),
            )
        except Exception as exc:
            logger.error("[PageIndex] Failed to build tree for %s: %s", pdf_path.name, exc)

    logger.info("[PageIndex] Built %d new trees (%d total PDFs)", built, len(pdf_files))
    return built

    return results
