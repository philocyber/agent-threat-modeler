"""Tree-based retriever for PageIndex document trees.

Given a user query and a set of DocumentTree indices, this retriever uses
an LLM to *reason* through the tree hierarchy — navigating from root nodes
down to the most relevant sections — and extracts full-resolution text from
those sections.  This is the "reasoning-based retrieval" approach from
VectifyAI/PageIndex, adapted for local Ollama models.

When no LLM is available, falls back to keyword-matching against node
titles and summaries.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from agentictm.rag.page_index import (
    DocumentTree,
    TreeNode,
    get_node_text,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class TreeRetrievalResult:
    """A single retrieval result from tree-based search."""

    doc_name: str
    doc_path: str
    node_id: str
    node_title: str
    section_path: str          # e.g. "Chapter 3 > 3.2 STRIDE > 3.2.1 Spoofing"
    page_range: tuple[int, int]  # (start, end) 0-based inclusive
    text: str                  # full section text
    relevance_note: str = ""   # LLM's reasoning on why this section is relevant


# ---------------------------------------------------------------------------
# Keyword-based fallback retriever
# ---------------------------------------------------------------------------

def _keyword_match_score(query: str, node: TreeNode) -> float:
    """Simple keyword overlap score between query and node title+summary."""
    query_words = set(re.findall(r"\w{3,}", query.lower()))
    if not query_words:
        return 0.0

    node_text = f"{node.title} {node.summary}".lower()
    node_words = set(re.findall(r"\w{3,}", node_text))

    if not node_words:
        return 0.0

    overlap = query_words & node_words
    return len(overlap) / len(query_words)


def keyword_tree_search(
    query: str,
    trees: dict[str, DocumentTree],
    top_k: int = 5,
    min_score: float = 0.15,
) -> list[TreeRetrievalResult]:
    """Fallback keyword-based tree search (no LLM needed).

    Scores each node by keyword overlap with query, returns top-k.
    """
    scored: list[tuple[float, str, TreeNode, DocumentTree]] = []

    for doc_name, doc_tree in trees.items():
        for node in doc_tree.all_nodes():
            score = _keyword_match_score(query, node)
            if score >= min_score:
                scored.append((score, doc_name, node, doc_tree))

    # Sort by score descending
    scored.sort(key=lambda x: x[0], reverse=True)

    results: list[TreeRetrievalResult] = []
    for score, doc_name, node, doc_tree in scored[:top_k]:
        try:
            text = get_node_text(doc_tree.doc_path, node)
        except Exception as exc:
            logger.warning("Failed to extract text for %s/%s: %s", doc_name, node.node_id, exc)
            text = f"[Error extracting text: {exc}]"

        # Build section path
        section_path = _build_section_path(node, doc_tree)

        results.append(TreeRetrievalResult(
            doc_name=doc_name,
            doc_path=doc_tree.doc_path,
            node_id=node.node_id,
            node_title=node.title,
            section_path=section_path,
            page_range=(node.start_page, node.end_page),
            text=text,
            relevance_note=f"Keyword match score: {score:.2f}",
        ))

    return results


def _build_section_path(node: TreeNode, doc_tree: DocumentTree) -> str:
    """Build a human-readable path like 'Chapter 3 > 3.2 STRIDE > ...'."""
    # Walk the tree to find the path to this node
    path_parts: list[str] = []

    def _find_path(current_nodes: list[TreeNode], target_id: str, current_path: list[str]) -> bool:
        for n in current_nodes:
            current_path.append(n.title)
            if n.node_id == target_id:
                return True
            if _find_path(n.children, target_id, current_path):
                return True
            current_path.pop()
        return False

    _find_path(doc_tree.tree, node.node_id, path_parts)
    return " > ".join(path_parts) if path_parts else node.title


# ---------------------------------------------------------------------------
# LLM-based tree navigator
# ---------------------------------------------------------------------------

_TREE_NAV_SYSTEM = """You are a document navigation expert. Given a user question and a document's table of contents tree, identify the most relevant sections that would contain the answer.

RULES:
- Examine the tree structure: titles and summaries of each node
- Select 1-5 most relevant sections by their node_id
- Prefer specific/deep sections over broad chapters when possible
- Return ONLY a JSON array of objects with "node_id" and "reason" keys
- Example: [{"node_id": "0003", "reason": "Covers STRIDE methodology details"}]
- If NO sections seem relevant, return an empty array: []
"""


def llm_tree_search(
    query: str,
    trees: dict[str, DocumentTree],
    llm: Any,
    top_k: int = 5,
) -> list[TreeRetrievalResult]:
    """Use LLM to navigate document trees and find relevant sections.

    The LLM examines the tree outlines (titles + summaries) and selects
    the most relevant nodes. Then full text is extracted from the PDF.
    """
    from langchain_core.messages import HumanMessage, SystemMessage

    all_results: list[TreeRetrievalResult] = []

    for doc_name, doc_tree in trees.items():
        # Build a compact tree representation for the LLM
        tree_repr = _tree_to_llm_prompt(doc_tree)

        prompt = (
            f"DOCUMENT: {doc_tree.doc_name} ({doc_tree.total_pages} pages)\n\n"
            f"TABLE OF CONTENTS:\n{tree_repr}\n\n"
            f"USER QUESTION: {query}\n\n"
            f"Which sections (by node_id) are most relevant to answer this question? "
            f"Return a JSON array."
        )

        try:
            messages = [
                SystemMessage(content=_TREE_NAV_SYSTEM),
                HumanMessage(content=prompt),
            ]
            response = llm.invoke(messages)
            from agentictm.agents.base import ensure_str_content
            text = ensure_str_content(response.content).strip()

            # Strip <think> tags if present (qwen3)
            text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

            # Parse JSON response
            selected_nodes = _parse_llm_selection(text)
        except Exception as exc:
            logger.warning("[TreeRetriever] LLM navigation failed for %s: %s", doc_name, exc)
            continue

        if not selected_nodes:
            continue

        # Build a lookup map: node_id → TreeNode
        node_map = {n.node_id: n for n in doc_tree.all_nodes()}

        for selection in selected_nodes:
            node_id = selection.get("node_id", "")
            reason = selection.get("reason", "")

            node = node_map.get(node_id)
            if node is None:
                logger.debug("LLM selected unknown node_id %s in %s", node_id, doc_name)
                continue

            try:
                node_text = get_node_text(doc_tree.doc_path, node)
            except Exception as exc:
                logger.warning("Failed to extract text for %s/%s: %s", doc_name, node_id, exc)
                node_text = f"[Error extracting text: {exc}]"

            section_path = _build_section_path(node, doc_tree)

            all_results.append(TreeRetrievalResult(
                doc_name=doc_name,
                doc_path=doc_tree.doc_path,
                node_id=node.node_id,
                node_title=node.title,
                section_path=section_path,
                page_range=(node.start_page, node.end_page),
                text=node_text,
                relevance_note=reason,
            ))

    # Limit to top_k total
    return all_results[:top_k]


def _tree_to_llm_prompt(doc_tree: DocumentTree) -> str:
    """Convert tree to a compact text representation for LLM consumption."""
    lines = []

    def _render_node(node: TreeNode, indent: int = 0):
        prefix = "  " * indent
        summary_part = f' — "{node.summary[:120]}"' if node.summary else ""
        lines.append(
            f"{prefix}[{node.node_id}] {node.title} "
            f"(pp. {node.start_page + 1}–{node.end_page + 1})"
            f"{summary_part}"
        )
        for child in node.children:
            _render_node(child, indent + 1)

    for top_node in doc_tree.tree:
        _render_node(top_node)

    return "\n".join(lines)


def _parse_llm_selection(text: str) -> list[dict]:
    """Parse LLM's JSON array response into list of {node_id, reason}."""
    import json

    # Try to find JSON array in the response
    # Handle cases where LLM wraps in markdown code blocks
    text = text.strip()
    text = re.sub(r"```json\s*", "", text)
    text = re.sub(r"```\s*$", "", text)

    # Find the JSON array
    match = re.search(r"\[.*\]", text, re.DOTALL)
    if not match:
        logger.debug("No JSON array found in LLM response: %s", text[:200])
        return []

    try:
        parsed = json.loads(match.group())
        if isinstance(parsed, list):
            return [
                item for item in parsed
                if isinstance(item, dict) and "node_id" in item
            ]
    except json.JSONDecodeError as exc:
        logger.debug("JSON parse error: %s -- text: %s", exc, text[:200])

    return []


# ---------------------------------------------------------------------------
# Hybrid search: tree + optional vector results merge
# ---------------------------------------------------------------------------

def hybrid_search(
    query: str,
    trees: dict[str, DocumentTree],
    vector_results: list[str] | None = None,
    llm: Any | None = None,
    top_k: int = 5,
) -> list[dict[str, Any]]:
    """Combine tree-based and vector-based retrieval results.

    Args:
        query: User query text.
        trees: Loaded DocumentTree indices.
        vector_results: Optional list of text chunks from ChromaDB.
        llm: Optional LLM for reasoning-based tree navigation.
        top_k: Max results to return.

    Returns:
        List of dicts with {source, text, metadata} ready for use.
    """
    results: list[dict[str, Any]] = []

    # 1. Tree-based search
    if trees:
        if llm is not None:
            tree_results = llm_tree_search(query, trees, llm, top_k=top_k)
        else:
            tree_results = keyword_tree_search(query, trees, top_k=top_k)

        for tr in tree_results:
            # Truncate very long sections to avoid context overflow
            text = tr.text
            if len(text) > 6000:
                text = text[:3000] + "\n\n...[section truncated]...\n\n" + text[-2000:]

            results.append({
                "source": "tree",
                "text": text,
                "metadata": {
                    "doc_name": tr.doc_name,
                    "node_title": tr.node_title,
                    "section_path": tr.section_path,
                    "page_range": f"{tr.page_range[0] + 1}–{tr.page_range[1] + 1}",
                    "relevance": tr.relevance_note,
                },
            })

    # 2. Vector-based results (pass through)
    if vector_results:
        for vr in vector_results:
            results.append({
                "source": "vector",
                "text": vr,
                "metadata": {"type": "chunk"},
            })

    # 3. Deduplicate by content overlap
    results = _deduplicate_results(results)

    return results[:top_k]


def _deduplicate_results(results: list[dict]) -> list[dict]:
    """Remove results with high text overlap."""
    if len(results) <= 1:
        return results

    kept: list[dict] = []
    for result in results:
        text = result["text"][:500].lower()
        is_dup = False
        for existing in kept:
            existing_text = existing["text"][:500].lower()
            # Simple overlap check via shared words
            words_a = set(text.split())
            words_b = set(existing_text.split())
            if words_a and words_b:
                overlap = len(words_a & words_b) / min(len(words_a), len(words_b))
                if overlap > 0.7:
                    is_dup = True
                    break
        if not is_dup:
            kept.append(result)

    return kept


def format_hybrid_results(results: list[dict[str, Any]]) -> str:
    """Format hybrid search results into a readable string for agents."""
    if not results:
        return "No relevant results found."

    parts: list[str] = []
    for i, r in enumerate(results, 1):
        meta = r.get("metadata", {})
        source = r.get("source", "unknown")

        if source == "tree":
            header = (
                f"[Result {i} — Tree: {meta.get('doc_name', '?')}]\n"
                f"Section: {meta.get('section_path', '?')}\n"
                f"Pages: {meta.get('page_range', '?')}\n"
                f"Relevance: {meta.get('relevance', 'N/A')}"
            )
        else:
            header = f"[Result {i} — Vector chunk]"

        parts.append(f"{header}\n{r['text']}")

    return "\n\n{'=' * 60}\n\n".join(parts)
