"""Document indexer for vector stores + PageIndex tree builder."""

from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

import numpy as np
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
    from langchain_core.embeddings import Embeddings
    from agentictm.rag import RAGStoreManager

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Semantic Text Splitter
# ---------------------------------------------------------------------------

_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+|\n{2,}")
_HEADING_RE = re.compile(r"^(#{1,6}\s+.+|[A-Z][A-Za-z0-9 /&:,-]{3,80})$", re.MULTILINE)


class SemanticTextSplitter:
    """Embedding-aware text splitter that finds natural breakpoints.

    Strategy:
      1. Split text into sentences.
      2. Embed each sentence (via the RAG embedding model).
      3. Merge consecutive sentences whose cosine similarity exceeds
         *similarity_threshold* into a single chunk.
      4. Respect *chunk_size* / *chunk_overlap* as soft guidelines
         (the chunk won't be split mid-sentence, but very long sentences
         are force-split via RecursiveCharacterTextSplitter).

    Falls back to RecursiveCharacterTextSplitter when embeddings
    are unavailable (no model loaded, import error, etc.).
    """

    def __init__(
        self,
        embeddings: Embeddings | None = None,
        chunk_size: int = 1000,
        chunk_overlap: int = 200,
        similarity_threshold: float = 0.5,
    ):
        self._embeddings = embeddings
        self._chunk_size = chunk_size
        self._chunk_overlap = chunk_overlap
        self._similarity_threshold = similarity_threshold
        self._fallback = RecursiveCharacterTextSplitter(
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap,
            separators=["\n\n", "\n", ". ", " ", ""],
        )

    # ------------------------------------------------------------------

    def split_documents(self, documents: list[Document]) -> list[Document]:
        """Split a list of Documents using semantic chunking."""
        all_chunks: list[Document] = []
        for doc in documents:
            all_chunks.extend(self._split_single(doc))
        return all_chunks

    def _split_single(self, doc: Document) -> list[Document]:
        text = doc.page_content
        if not text or not text.strip():
            return []

        parent_heading = self._extract_heading(text)

        if self._embeddings is None:
            chunks = self._fallback.split_documents([doc])
            for c in chunks:
                if parent_heading:
                    c.metadata["parent_heading"] = parent_heading
            return chunks

        sentences = self._split_sentences(text)
        if len(sentences) <= 1:
            chunks = self._fallback.split_documents([doc])
            for c in chunks:
                if parent_heading:
                    c.metadata["parent_heading"] = parent_heading
            return chunks

        try:
            embeddings = self._embeddings.embed_documents(sentences)
        except Exception as exc:
            logger.debug("Embedding failed, using fallback splitter: %s", exc)
            chunks = self._fallback.split_documents([doc])
            for c in chunks:
                if parent_heading:
                    c.metadata["parent_heading"] = parent_heading
            return chunks

        return self._merge_by_similarity(
            sentences, embeddings, doc.metadata, parent_heading,
        )

    # ------------------------------------------------------------------

    @staticmethod
    def _split_sentences(text: str) -> list[str]:
        """Split text into sentence-level fragments."""
        parts = _SENTENCE_RE.split(text)
        return [s.strip() for s in parts if s.strip()]

    @staticmethod
    def _extract_heading(text: str) -> str:
        """Extract the first markdown/section heading from text."""
        match = _HEADING_RE.search(text[:500])
        return match.group(0).lstrip("# ").strip() if match else ""

    @staticmethod
    def _cosine_similarity(a: list[float], b: list[float]) -> float:
        va, vb = np.array(a), np.array(b)
        denom = np.linalg.norm(va) * np.linalg.norm(vb)
        if denom == 0:
            return 0.0
        return float(np.dot(va, vb) / denom)

    def _merge_by_similarity(
        self,
        sentences: list[str],
        embeddings: list[list[float]],
        base_metadata: dict[str, Any],
        parent_heading: str,
    ) -> list[Document]:
        """Merge consecutive sentences into chunks based on embedding similarity."""
        chunks: list[Document] = []
        current: list[str] = [sentences[0]]
        current_len = len(sentences[0])

        for i in range(1, len(sentences)):
            sim = self._cosine_similarity(embeddings[i - 1], embeddings[i])
            sent_len = len(sentences[i])

            if sim >= self._similarity_threshold and (current_len + sent_len) < self._chunk_size * 1.5:
                current.append(sentences[i])
                current_len += sent_len
            else:
                chunks.append(self._make_chunk(current, base_metadata, parent_heading))
                overlap_sents = self._overlap_sentences(current)
                current = overlap_sents + [sentences[i]]
                current_len = sum(len(s) for s in current)

        if current:
            chunks.append(self._make_chunk(current, base_metadata, parent_heading))

        force_split: list[Document] = []
        for chunk in chunks:
            if len(chunk.page_content) > self._chunk_size * 2:
                force_split.extend(self._fallback.split_documents([chunk]))
            else:
                force_split.append(chunk)
        return force_split

    def _overlap_sentences(self, sentences: list[str]) -> list[str]:
        """Return trailing sentences that fit within chunk_overlap chars."""
        overlap: list[str] = []
        total = 0
        for s in reversed(sentences):
            if total + len(s) > self._chunk_overlap:
                break
            overlap.insert(0, s)
            total += len(s)
        return overlap

    @staticmethod
    def _make_chunk(
        sentences: list[str],
        base_metadata: dict[str, Any],
        parent_heading: str,
    ) -> Document:
        meta = {**base_metadata}
        if parent_heading:
            meta["parent_heading"] = parent_heading
        return Document(page_content=" ".join(sentences), metadata=meta)

# Default tree index output directory
_DEFAULT_TREE_DIR = Path("data/page_indices")

# Default hash manifest path for incremental indexing (I05)
_DEFAULT_HASH_MANIFEST = Path("data/vector_stores/.index_manifest.json")


def _file_hash(path: Path) -> str:
    """Fast hash of a file's contents."""
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
    """Return indexing status for all RAG source documents (I05).

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
    """Load a file based on its extension."""
    suffix = path.suffix.lower()

    if suffix == ".pdf":
        return _load_pdf_pymupdf(path)
    if suffix in (".md", ".txt", ".rst"):
        return TextLoader(str(path), encoding="utf-8").load()
    if suffix == ".csv":
        # Load each row as individual doc + the full file.
        # For threats.csv specifically, enrich each row with
        # threat_category (comma-separated) and threat_tipo metadata
        # so vector search can filter results by technology domain.
        rows = CSVLoader(str(path), encoding="utf-8").load()

        if path.name.lower() == "threats.csv":
            try:
                import csv as _csv
                from agentictm.rag.categories import classify_threat as _classify
                with open(path, encoding="utf-8", newline="") as _f:
                    _csv_rows = list(_csv.DictReader(_f))
                for row_doc, row_data in zip(rows, _csv_rows):
                    titulo = row_data.get("Titulo", row_data.get("titulo", ""))
                    desc = row_data.get("Descripcion", row_data.get("descripcion", ""))
                    tipo = row_data.get("Tipo", row_data.get("tipo", ""))
                    cats = sorted(_classify(titulo, desc))
                    row_doc.metadata["threat_category"] = ",".join(cats)
                    row_doc.metadata["threat_tipo"] = tipo
                logger.info("threats.csv: enriched %d rows with category metadata", len(_csv_rows))
            except Exception as _exc:
                logger.warning("Could not enrich threats.csv metadata: %s", _exc)

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
        logger.error("PyMuPDF failed for %s: %s -- falling back to text", path, exc)
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

    Uses SemanticTextSplitter (embedding-aware) when available, falling back
    to RecursiveCharacterTextSplitter otherwise.

    Returns:
        Cantidad de chunks indexados.
    """
    if not source_dir.exists():
        logger.info("Directorio no existe, creando: %s", source_dir)
        source_dir.mkdir(parents=True, exist_ok=True)
        return 0

    embeddings = getattr(store_manager, "_embeddings", None)
    splitter = SemanticTextSplitter(
        embeddings=embeddings,
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
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
                logger.info("  -> %d chunks", len(chunks))

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
    """Indexa todas las carpetas del directorio RAG.

    Builds both ChromaDB vector stores (for text chunks) AND
    PageIndex tree indices (for PDFs) — enabling hybrid retrieval.

    Incremental indexing (I05): only new/changed documents are re-indexed
    unless ``force=True``.

    Espera la siguiente estructura:
        rag/
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

    # Invalidate the direct threats catalog cache so changes to threats.csv
    # are picked up immediately on the next rag_query_threats_catalog call.
    try:
        from agentictm.rag.threats_catalog import invalidate_cache as _invalidate_catalog
        _invalidate_catalog()
    except Exception:
        pass

    # Build PageIndex trees for all PDFs
    try:
        tree_count = build_trees_for_rag(
            knowledge_base_path, actual_tree_dir, llm=llm,
        )
    except Exception:
        raise
    results["_page_index_trees"] = tree_count

    return results


# ---------------------------------------------------------------------------
# PageIndex tree building
# ---------------------------------------------------------------------------

def build_trees_for_rag(
    knowledge_base_path: Path,
    tree_dir: Path,
    llm: Any | None = None,
    generate_summaries: bool = True,
) -> int:
    """Build PageIndex trees for all PDFs in the RAG sources directory.

    Only rebuilds trees for PDFs that have changed since last indexing
    (uses MD5 hash for cache invalidation).

    Returns the number of trees built.
    """
    tree_dir.mkdir(parents=True, exist_ok=True)

    pdf_files = sorted(knowledge_base_path.rglob("*.pdf"))
    if not pdf_files:
        logger.info("[PageIndex] No PDF files found in RAG sources")
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
                "[PageIndex] [OK] %s -- %d nodes",
                pdf_path.name, len(doc_tree.all_nodes()),
            )
        except Exception as exc:
            logger.error("[PageIndex] Failed to build tree for %s: %s", pdf_path.name, exc)

    logger.info("[PageIndex] Built %d new trees (%d total PDFs)", built, len(pdf_files))
    return built
