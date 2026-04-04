"""RAG multi-fuente — ChromaDB vector stores + PageIndex tree retrieval."""

from __future__ import annotations

import hashlib
import logging
import os
import time
from pathlib import Path
from typing import Any

import chromadb
from chromadb.config import Settings as ChromaSettings
from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings

from agentictm.rag.page_index import load_all_trees, DocumentTree
from agentictm.rag.tree_retriever import (
    hybrid_search,
    format_hybrid_results,
    llm_tree_search,
    keyword_tree_search,
    TreeRetrievalResult,
)

logger = logging.getLogger(__name__)

# Nombres de las colecciones
STORE_BOOKS = "books"
STORE_RESEARCH = "research"
STORE_RISKS = "risks_mitigations"
STORE_PREVIOUS_TMS = "previous_threat_models"
STORE_AI_THREATS = "ai_threats"

ALL_STORES = [STORE_BOOKS, STORE_RESEARCH, STORE_RISKS, STORE_PREVIOUS_TMS, STORE_AI_THREATS]

# Stores that typically have PDFs (tree indices are built for these)
PDF_STORES = [STORE_BOOKS, STORE_RESEARCH, STORE_AI_THREATS]


def _safe_chroma_settings(persist_dir: str) -> ChromaSettings:
    """Return ChromaDB Settings tuned for low-memory / single-machine use.

    Default thread_pool_size of 40 causes dozens of tokio + sqlite workers
    that fight with Ollama for RAM on 16 GB machines, leading to SIGSEGV
    inside the Rust HNSW bindings.
    """
    ram_gb = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / (1024 ** 3) if hasattr(os, "sysconf") else 16
    pool = 4 if ram_gb <= 16 else 8
    return ChromaSettings(
        persist_directory=persist_dir,
        is_persistent=True,
        anonymized_telemetry=False,
        chroma_server_thread_pool_size=pool,
        chroma_memory_limit_bytes=int(min(ram_gb * 0.10, 2) * 1024 ** 3),
    )


HNSW_LOW_MEM_META: dict[str, Any] = {
    "hnsw:num_threads": 1,
    "hnsw:M": 16,
    "hnsw:construction_ef": 100,
    "hnsw:search_ef": 50,
    "hnsw:batch_size": 100,
}


class RAGStoreManager:
    """Hybrid RAG manager: ChromaDB vector stores + PageIndex tree indices.

    Vector stores handle chunk-based similarity search across all document types.
    Tree indices handle structure-aware retrieval from PDFs (books, research papers).
    """

    def __init__(
        self,
        persist_dir: Path,
        embedding_model: str = "nomic-embed-text-v2-moe",
        embedding_provider: str = "ollama",
        base_url: str = "http://localhost:11434",
        tree_index_dir: Path | None = None,
    ):
        self._persist_dir = Path(persist_dir)
        self._persist_dir.mkdir(parents=True, exist_ok=True)

        self._embeddings = OllamaEmbeddings(
            model=embedding_model,
            base_url=base_url,
        )

        self._chroma_settings = _safe_chroma_settings(str(self._persist_dir))
        self._chroma_client = chromadb.PersistentClient(
            path=str(self._persist_dir),
            settings=self._chroma_settings,
        )
        self._stores: dict[str, Chroma] = {}

        # ── Query cache (avoid redundant RAG queries within a single run) ──
        # Key: sha256(store_name + query + top_k), Value: (result_str, timestamp)
        self._query_cache: dict[str, tuple[str, float]] = {}
        self._cache_ttl: float = 1800.0  # 30 min — covers one full pipeline run
        self._cache_hits: int = 0
        self._cache_misses: int = 0

        # PageIndex trees
        self._tree_dir = Path(tree_index_dir) if tree_index_dir else Path("data/page_indices")
        self._trees: dict[str, DocumentTree] = {}
        self._trees_loaded: bool = False
        self._tree_llm: Any | None = None  # set via set_tree_llm()
        self._load_trees()

    def _load_trees(self) -> None:
        """Load all available PageIndex trees from disk (once)."""
        if self._trees_loaded and self._trees:
            logger.debug("PageIndex trees already cached (%d trees) -- skipping disk read", len(self._trees))
            return
        if self._tree_dir.exists():
            self._trees = load_all_trees(self._tree_dir)
            self._trees_loaded = True
            if self._trees:
                logger.info(
                    "Loaded %d PageIndex trees: %s",
                    len(self._trees),
                    ", ".join(self._trees.keys()),
                )
        else:
            logger.debug("No tree index directory found at %s", self._tree_dir)

    def set_tree_llm(self, llm: Any) -> None:
        """Set the LLM used for tree-based reasoning retrieval."""
        self._tree_llm = llm

    def reload_trees(self) -> None:
        """Reload tree indices from disk (after re-indexing)."""
        self._trees_loaded = False  # force disk read
        self._load_trees()

    @property
    def trees(self) -> dict[str, DocumentTree]:
        return self._trees

    def get_store(self, name: str) -> Chroma:
        """Obtiene (o crea) un vector store por nombre."""
        if name not in self._stores:
            self._stores[name] = Chroma(
                client=self._chroma_client,
                collection_name=name,
                embedding_function=self._embeddings,
                collection_metadata=HNSW_LOW_MEM_META,
            )
        return self._stores[name]

    # ------------------------------------------------------------------
    # Cache helpers
    # ------------------------------------------------------------------

    def _cache_key(self, store_name: str, query: str, top_k: int, hybrid: bool = False) -> str:
        """Compute a stable cache key for a query."""
        raw = f"{store_name}|{query.strip().lower()}|{top_k}|{'h' if hybrid else 'v'}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def _cache_get(self, key: str) -> str | None:
        """Return cached result if fresh, else None."""
        entry = self._query_cache.get(key)
        if entry is None:
            return None
        result, ts = entry
        if (time.time() - ts) > self._cache_ttl:
            del self._query_cache[key]
            return None
        self._cache_hits += 1
        return result

    def _cache_put(self, key: str, result: str) -> None:
        """Store a result in the cache."""
        self._cache_misses += 1
        self._query_cache[key] = (result, time.time())

    def clear_cache(self) -> None:
        """Clear the query cache (call between pipeline runs)."""
        if self._query_cache:
            logger.info(
                "RAG cache cleared | hits=%d misses=%d entries=%d",
                self._cache_hits, self._cache_misses, len(self._query_cache),
            )
        self._query_cache.clear()
        self._cache_hits = 0
        self._cache_misses = 0

    # ------------------------------------------------------------------
    # Vector-only query (original behavior)
    # ------------------------------------------------------------------

    def query(
        self,
        store_name: str,
        query: str,
        top_k: int = 5,
    ) -> str:
        """Consulta un store y retorna los documentos más relevantes como texto."""
        # Check cache first
        ck = self._cache_key(store_name, query, top_k, hybrid=False)
        cached = self._cache_get(ck)
        if cached is not None:
            logger.debug("RAG cache HIT for %s query (%.0f chars)", store_name, len(cached))
            return cached

        store = self.get_store(store_name)
        results = store.similarity_search(query, k=top_k)
        if not results:
            result = f"[RAG:{store_name}] No se encontraron resultados para: {query}"
            self._cache_put(ck, result)
            return result
        parts = []
        for doc in results:
            source = doc.metadata.get("source", "unknown")
            parts.append(f"[Fuente: {source}]\n{doc.page_content}")
        result = f"\n\n{'─' * 40}\n\n".join(parts)
        self._cache_put(ck, result)
        return result

    # ------------------------------------------------------------------
    # Hybrid query: vector + tree search
    # ------------------------------------------------------------------

    def hybrid_query(
        self,
        store_name: str,
        query: str,
        top_k: int = 5,
    ) -> str:
        """Query combining vector search + PageIndex tree navigation.

        For stores with PDFs (books, research, ai_threats), this merges
        vector chunk results with tree-based section retrieval.
        For other stores, falls back to vector-only.
        """
        # Check cache first
        ck = self._cache_key(store_name, query, top_k, hybrid=True)
        cached = self._cache_get(ck)
        if cached is not None:
            logger.debug("RAG cache HIT for hybrid %s query", store_name)
            return cached

        # Vector results
        vector_text = self.query(store_name, query, top_k=top_k)

        # Tree search (only if trees exist and store has PDFs)
        if store_name in PDF_STORES and self._trees:
            try:
                tree_results = self._tree_search(query, top_k=3)
                if tree_results:
                    tree_text = self._format_tree_results(tree_results)
                    result = (
                        f"=== Tree-based results (structured sections) ===\n\n"
                        f"{tree_text}\n\n"
                        f"{'═' * 50}\n\n"
                        f"=== Vector-based results (chunk similarity) ===\n\n"
                        f"{vector_text}"
                    )
                    self._cache_put(ck, result)
                    return result
            except Exception as exc:
                logger.warning("Tree search failed, using vector-only: %s", exc)

        self._cache_put(ck, vector_text)
        return vector_text

    def _tree_search(
        self,
        query: str,
        top_k: int = 3,
    ) -> list[TreeRetrievalResult]:
        """Run tree-based retrieval across all loaded trees.

        Uses keyword-based search (no LLM calls) for performance.
        LLM tree navigation was removed because each call adds ~30-60s
        per document tree, creating hidden latency of 50-100+ LLM calls
        per pipeline run across all agents.
        """
        if not self._trees:
            return []

        # Always use keyword search — avoids hidden LLM calls
        return keyword_tree_search(query, self._trees, top_k=top_k)

    def _format_tree_results(self, results: list[TreeRetrievalResult]) -> str:
        """Format tree retrieval results into readable text."""
        parts = []
        for i, r in enumerate(results, 1):
            header = (
                f"[[Doc] {r.doc_name} -- {r.section_path}]\n"
                f"Pages: {r.page_range[0] + 1}-{r.page_range[1] + 1}"
            )
            if r.relevance_note:
                header += f" | {r.relevance_note}"

            # Truncate very long sections
            text = r.text
            if len(text) > 4000:
                text = text[:2000] + "\n...[section truncated]...\n" + text[-1500:]

            parts.append(f"{header}\n{text}")

        return f"\n\n{'─' * 40}\n\n".join(parts)

    def multi_query(
        self,
        store_names: list[str],
        query: str,
        top_k: int = 3,
    ) -> dict[str, str]:
        """Consulta múltiples stores con la misma query (hybrid)."""
        return {
            name: self.hybrid_query(name, query, top_k)
            for name in store_names
        }

    @property
    def embeddings(self) -> OllamaEmbeddings:
        return self._embeddings
