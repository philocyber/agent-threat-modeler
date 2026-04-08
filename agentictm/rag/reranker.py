"""Cross-encoder reranker for RAG retrieval quality improvement.

Two-stage retrieval pipeline:
  1. Bi-encoder (existing): fast similarity search returns top-N candidates
  2. Cross-encoder (this module): reranks candidates for precision

Uses sentence-transformers cross-encoder models when available,
with graceful fallback to passthrough when the model is not installed.

Research basis: Cross-encoder reranking shows +10-40% accuracy improvement
(MRR, NDCG@10) with ~50ms overhead per batch.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_reranker = None
_reranker_available: bool | None = None


def _load_reranker():
    """Lazy-load the cross-encoder model. Returns None if unavailable."""
    global _reranker, _reranker_available
    if _reranker_available is not None:
        return _reranker
    try:
        from sentence_transformers import CrossEncoder
        _reranker = CrossEncoder("cross-encoder/ms-marco-MiniLM-L-6-v2")
        _reranker_available = True
        logger.info("Cross-encoder reranker loaded: ms-marco-MiniLM-L-6-v2")
    except Exception as exc:
        _reranker = None
        _reranker_available = False
        logger.info("Cross-encoder reranker not available (install sentence-transformers): %s", exc)
    return _reranker


def rerank(
    query: str,
    documents: list[Any],
    top_k: int = 5,
    content_key: str = "page_content",
) -> list[Any]:
    """Rerank documents using cross-encoder model.
    
    Args:
        query: The search query
        documents: List of LangChain Document objects or dicts
        top_k: Number of top results to return after reranking
        content_key: Key/attribute name for document content
        
    Returns:
        Reranked list of documents (top_k items), or original list if reranker unavailable
    """
    if not documents:
        return documents
        
    model = _load_reranker()
    if model is None:
        return documents[:top_k]
    
    # Extract text content from documents
    pairs = []
    for doc in documents:
        if hasattr(doc, "page_content"):
            text = doc.page_content
        elif isinstance(doc, dict):
            text = doc.get(content_key, str(doc))
        else:
            text = str(doc)
        pairs.append((query, text))
    
    try:
        scores = model.predict(pairs)
        # Sort by score descending, return top_k
        scored_docs = sorted(zip(scores, documents), key=lambda x: x[0], reverse=True)
        result = [doc for _, doc in scored_docs[:top_k]]
        logger.debug("Reranked %d -> %d documents (top score: %.3f, bottom: %.3f)",
                     len(documents), len(result),
                     scored_docs[0][0] if scored_docs else 0,
                     scored_docs[min(top_k-1, len(scored_docs)-1)][0] if scored_docs else 0)
        return result
    except Exception as exc:
        logger.warning("Reranker failed, falling back to original order: %s", exc)
        return documents[:top_k]


def is_available() -> bool:
    """Check if the cross-encoder reranker is available."""
    _load_reranker()
    return _reranker_available or False
