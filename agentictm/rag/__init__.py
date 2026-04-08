"""Multi-source RAG — ChromaDB vector stores + PageIndex tree retrieval."""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import chromadb
from chromadb.config import Settings as ChromaSettings
from langchain_chroma import Chroma
from langchain_core.documents import Document
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

# ---------------------------------------------------------------------------
# Optional BM25 import (graceful fallback)
# ---------------------------------------------------------------------------
try:
    from rank_bm25 import BM25Okapi
    _BM25_AVAILABLE = True
except ImportError:
    BM25Okapi = None  # type: ignore[misc,assignment]
    _BM25_AVAILABLE = False
    logger.debug("rank_bm25 not installed — BM25 sparse retrieval disabled")


# ---------------------------------------------------------------------------
# RAG Quality Metrics (2.4)
# ---------------------------------------------------------------------------

@dataclass
class RAGQueryMetric:
    """Single-query retrieval metric record."""
    query: str
    store_name: str
    retrieval_method: str  # "dense", "bm25", "hybrid", "tree"
    result_count: int
    reranker_applied: bool
    cache_hit: bool
    timestamp: float = field(default_factory=time.time)


_rag_metrics: list[RAGQueryMetric] = []
_rag_metrics_lock = threading.Lock()


def _record_metric(metric: RAGQueryMetric) -> None:
    with _rag_metrics_lock:
        _rag_metrics.append(metric)


def get_rag_metrics() -> dict[str, Any]:
    """Return aggregate RAG quality metrics (thread-safe)."""
    with _rag_metrics_lock:
        snapshot = list(_rag_metrics)
    if not snapshot:
        return {
            "total_queries": 0,
            "cache_hits": 0,
            "cache_hit_rate": 0.0,
            "avg_result_count": 0.0,
            "reranker_hit_rate": 0.0,
            "by_method": {},
        }
    total = len(snapshot)
    cache_hits = sum(1 for m in snapshot if m.cache_hit)
    reranker_hits = sum(1 for m in snapshot if m.reranker_applied)
    avg_results = sum(m.result_count for m in snapshot) / total

    by_method: dict[str, int] = {}
    for m in snapshot:
        by_method[m.retrieval_method] = by_method.get(m.retrieval_method, 0) + 1

    return {
        "total_queries": total,
        "cache_hits": cache_hits,
        "cache_hit_rate": cache_hits / total if total else 0.0,
        "avg_result_count": round(avg_results, 2),
        "reranker_hit_rate": reranker_hits / total if total else 0.0,
        "by_method": by_method,
    }


def clear_rag_metrics() -> None:
    """Clear all recorded RAG metrics (thread-safe)."""
    with _rag_metrics_lock:
        _rag_metrics.clear()

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
    BM25 sparse retrieval provides keyword-aware search alongside dense vectors.
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

        # ── BM25 sparse index per store ──
        # Lazily built on first hybrid query; maps store_name -> (BM25, docs)
        self._bm25_indices: dict[str, tuple[Any, list[Document]]] = {}

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
        """Get (or create) a vector store by name."""
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
        """Clear the query cache and BM25 indices (call between pipeline runs)."""
        if self._query_cache:
            logger.info(
                "RAG cache cleared | hits=%d misses=%d entries=%d",
                self._cache_hits, self._cache_misses, len(self._query_cache),
            )
        self._query_cache.clear()
        self._bm25_indices.clear()
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
        """Query a store and return the most relevant documents as text.

        Two-stage retrieval: bi-encoder candidates then cross-encoder reranking.
        """
        ck = self._cache_key(store_name, query, top_k, hybrid=False)
        cached = self._cache_get(ck)
        if cached is not None:
            logger.debug("RAG cache HIT for %s query (%.0f chars)", store_name, len(cached))
            _record_metric(RAGQueryMetric(
                query=query, store_name=store_name, retrieval_method="dense",
                result_count=0, reranker_applied=False, cache_hit=True,
            ))
            return cached

        store = self.get_store(store_name)
        fetch_k = min(top_k * 4, 20)
        results = store.similarity_search(query, k=fetch_k)
        if not results:
            result = f"[RAG:{store_name}] No results found for: {query}"
            self._cache_put(ck, result)
            _record_metric(RAGQueryMetric(
                query=query, store_name=store_name, retrieval_method="dense",
                result_count=0, reranker_applied=False, cache_hit=False,
            ))
            return result

        reranker_applied = False
        try:
            from agentictm.rag.reranker import rerank
            results = rerank(query, results, top_k=top_k)
            reranker_applied = True
        except Exception:
            results = results[:top_k]

        parts = []
        for doc in results:
            source = doc.metadata.get("source", "unknown")
            parts.append(f"[Source: {source}]\n{doc.page_content}")
        result = f"\n\n{'─' * 40}\n\n".join(parts)
        self._cache_put(ck, result)
        _record_metric(RAGQueryMetric(
            query=query, store_name=store_name, retrieval_method="dense",
            result_count=len(results), reranker_applied=reranker_applied,
            cache_hit=False,
        ))
        return result

    # ------------------------------------------------------------------
    # BM25 sparse search
    # ------------------------------------------------------------------

    def _build_bm25_index(self, store_name: str) -> tuple[Any, list[Document]] | None:
        """Build (or return cached) BM25 index for a store."""
        if not _BM25_AVAILABLE:
            return None
        if store_name in self._bm25_indices:
            return self._bm25_indices[store_name]

        store = self.get_store(store_name)
        try:
            collection = store._collection  # noqa: SLF001
            chroma_results = collection.get(include=["documents", "metadatas"])
        except Exception as exc:
            logger.debug("Cannot read collection for BM25 index: %s", exc)
            return None

        raw_docs = chroma_results.get("documents") or []
        raw_metas = chroma_results.get("metadatas") or [{}] * len(raw_docs)
        if not raw_docs:
            return None

        docs = [
            Document(page_content=text, metadata=meta or {})
            for text, meta in zip(raw_docs, raw_metas)
        ]
        tokenized = [d.page_content.lower().split() for d in docs]
        bm25 = BM25Okapi(tokenized)
        self._bm25_indices[store_name] = (bm25, docs)
        logger.debug("BM25 index built for '%s': %d documents", store_name, len(docs))
        return (bm25, docs)

    def _bm25_search(
        self,
        store_name: str,
        query: str,
        top_k: int = 5,
    ) -> list[Document]:
        """Return top-k documents using BM25 sparse retrieval."""
        index = self._build_bm25_index(store_name)
        if index is None:
            return []
        bm25, docs = index
        tokenized_query = query.lower().split()
        scores = bm25.get_scores(tokenized_query)

        ranked = sorted(enumerate(scores), key=lambda x: x[1], reverse=True)
        results: list[Document] = []
        for idx, score in ranked[:top_k]:
            if score > 0:
                results.append(docs[idx])
        return results

    @staticmethod
    def _reciprocal_rank_fusion(
        ranked_lists: list[list[Document]],
        k: int = 60,
        top_k: int = 5,
    ) -> list[Document]:
        """Merge multiple ranked lists using Reciprocal Rank Fusion.

        RRF score for each doc = sum(1 / (k + rank)) across all lists
        where rank is 1-indexed position in each list.
        """
        doc_scores: dict[int, float] = {}
        doc_map: dict[int, Document] = {}

        for ranked_list in ranked_lists:
            for rank, doc in enumerate(ranked_list, start=1):
                doc_id = id(doc)
                content_key = hash(doc.page_content[:200])
                for existing_key, existing_doc in doc_map.items():
                    if hash(existing_doc.page_content[:200]) == content_key:
                        doc_id = existing_key
                        break
                doc_map[doc_id] = doc
                doc_scores[doc_id] = doc_scores.get(doc_id, 0.0) + (1.0 / (k + rank))

        sorted_docs = sorted(doc_scores.items(), key=lambda x: x[1], reverse=True)
        return [doc_map[doc_id] for doc_id, _ in sorted_docs[:top_k]]

    # ------------------------------------------------------------------
    # Hybrid query: vector + tree search
    # ------------------------------------------------------------------

    def hybrid_query(
        self,
        store_name: str,
        query: str,
        top_k: int = 5,
    ) -> str:
        """Query combining dense vector + BM25 sparse + PageIndex tree retrieval.

        1. Dense vector search (existing bi-encoder + cross-encoder reranking)
        2. BM25 sparse search (keyword-based, if rank_bm25 installed)
        3. Reciprocal Rank Fusion to merge dense + BM25 result lists
        4. Tree-based section retrieval for PDF stores (books, research)
        """
        ck = self._cache_key(store_name, query, top_k, hybrid=True)
        cached = self._cache_get(ck)
        if cached is not None:
            logger.debug("RAG cache HIT for hybrid %s query", store_name)
            _record_metric(RAGQueryMetric(
                query=query, store_name=store_name, retrieval_method="hybrid",
                result_count=0, reranker_applied=False, cache_hit=True,
            ))
            return cached

        # ── Stage 1: Dense vector results ──
        store = self.get_store(store_name)
        fetch_k = min(top_k * 4, 20)
        dense_results = store.similarity_search(query, k=fetch_k)

        # ── Stage 2: BM25 sparse results ──
        bm25_results = self._bm25_search(store_name, query, top_k=fetch_k)

        # ── Stage 3: RRF fusion (dense + BM25) ──
        reranker_applied = False
        if dense_results or bm25_results:
            ranked_lists = [lst for lst in [dense_results, bm25_results] if lst]
            if len(ranked_lists) > 1:
                fused = self._reciprocal_rank_fusion(ranked_lists, top_k=top_k * 2)
            else:
                fused = ranked_lists[0] if ranked_lists else []

            try:
                from agentictm.rag.reranker import rerank
                fused = rerank(query, fused, top_k=top_k)
                reranker_applied = True
            except Exception:
                fused = fused[:top_k]
        else:
            fused = []

        if not fused:
            result = f"[RAG:{store_name}] No results found for: {query}"
            self._cache_put(ck, result)
            _record_metric(RAGQueryMetric(
                query=query, store_name=store_name, retrieval_method="hybrid",
                result_count=0, reranker_applied=False, cache_hit=False,
            ))
            return result

        parts = []
        for doc in fused:
            source = doc.metadata.get("source", "unknown")
            parts.append(f"[Source: {source}]\n{doc.page_content}")
        fused_text = f"\n\n{'─' * 40}\n\n".join(parts)

        retrieval_method = "hybrid" if bm25_results else "dense"

        # ── Stage 4: Tree search for PDF stores ──
        if store_name in PDF_STORES and self._trees:
            try:
                tree_results = self._tree_search(query, top_k=3)
                if tree_results:
                    tree_text = self._format_tree_results(tree_results)
                    result = (
                        f"=== Tree-based results (structured sections) ===\n\n"
                        f"{tree_text}\n\n"
                        f"{'═' * 50}\n\n"
                        f"=== Hybrid results (dense + BM25 RRF) ===\n\n"
                        f"{fused_text}"
                    )
                    self._cache_put(ck, result)
                    _record_metric(RAGQueryMetric(
                        query=query, store_name=store_name,
                        retrieval_method=retrieval_method,
                        result_count=len(fused) + len(tree_results),
                        reranker_applied=reranker_applied, cache_hit=False,
                    ))
                    return result
            except Exception as exc:
                logger.warning("Tree search failed, using fused-only: %s", exc)

        self._cache_put(ck, fused_text)
        _record_metric(RAGQueryMetric(
            query=query, store_name=store_name, retrieval_method=retrieval_method,
            result_count=len(fused), reranker_applied=reranker_applied,
            cache_hit=False,
        ))
        return fused_text

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
        """Query multiple stores with the same query (hybrid)."""
        return {
            name: self.hybrid_query(name, query, top_k)
            for name in store_names
        }

    @property
    def embeddings(self) -> OllamaEmbeddings:
        return self._embeddings
