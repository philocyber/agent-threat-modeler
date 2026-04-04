"""PageIndex-inspired local tree builder for PDF documents.

Builds a hierarchical "Table of Contents" tree from PDF files using:
  1. PyMuPDF (fitz) for text extraction with structural hints
  2. Heuristic heading detection (font size, bold, ALL CAPS)
  3. Optional LLM refinement for ambiguous structures
  4. Node summaries for reasoning-based retrieval

The tree is stored as JSON and used at query time by tree_retriever.py
for reasoning-based (vectorless) retrieval — navigating the tree like
a human expert would.

Inspired by VectifyAI/PageIndex (MIT license).
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

import fitz  # PyMuPDF

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TreeNode:
    """A node in the document tree (chapter, section, subsection, etc.)."""

    title: str
    node_id: str = ""
    level: int = 1                  # 1=chapter, 2=section, 3=subsection, etc.
    start_page: int = 0             # 0-based page index
    end_page: int = 0               # inclusive end page
    summary: str = ""               # LLM-generated or extracted summary
    text: str = ""                  # full text of this section (populated on demand)
    children: list["TreeNode"] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "node_id": self.node_id,
            "level": self.level,
            "start_page": self.start_page,
            "end_page": self.end_page,
            "summary": self.summary,
            "children": [c.to_dict() for c in self.children],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TreeNode":
        children = [cls.from_dict(c) for c in data.get("children", [])]
        return cls(
            title=data.get("title", ""),
            node_id=data.get("node_id", ""),
            level=data.get("level", 1),
            start_page=data.get("start_page", 0),
            end_page=data.get("end_page", 0),
            summary=data.get("summary", ""),
            children=children,
        )

    def flatten(self) -> list["TreeNode"]:
        """Return this node + all descendants in pre-order."""
        result = [self]
        for child in self.children:
            result.extend(child.flatten())
        return result

    def outline_str(self, indent: int = 0) -> str:
        """Human-readable tree outline."""
        prefix = "  " * indent
        line = f"{prefix}[{self.node_id}] {self.title} (pp. {self.start_page + 1}-{self.end_page + 1})"
        if self.summary:
            line += f" -- {self.summary[:80]}..."
        lines = [line]
        for child in self.children:
            lines.append(child.outline_str(indent + 1))
        return "\n".join(lines)


@dataclass
class DocumentTree:
    """Complete tree index for a single PDF document."""

    doc_name: str
    doc_path: str
    doc_hash: str               # MD5 of PDF file for cache invalidation
    total_pages: int
    tree: list[TreeNode]        # top-level nodes (chapters)
    doc_description: str = ""   # optional LLM-generated doc description
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "doc_name": self.doc_name,
            "doc_path": self.doc_path,
            "doc_hash": self.doc_hash,
            "total_pages": self.total_pages,
            "doc_description": self.doc_description,
            "created_at": self.created_at,
            "tree": [n.to_dict() for n in self.tree],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DocumentTree":
        tree = [TreeNode.from_dict(n) for n in data.get("tree", [])]
        return cls(
            doc_name=data.get("doc_name", ""),
            doc_path=data.get("doc_path", ""),
            doc_hash=data.get("doc_hash", ""),
            total_pages=data.get("total_pages", 0),
            doc_description=data.get("doc_description", ""),
            created_at=data.get("created_at", ""),
            tree=tree,
        )

    def outline(self) -> str:
        """Full tree outline for debugging/display."""
        lines = [f"[Doc] {self.doc_name} ({self.total_pages} pages)"]
        for node in self.tree:
            lines.append(node.outline_str(indent=1))
        return "\n".join(lines)

    def all_nodes(self) -> list[TreeNode]:
        """Flatten all nodes in the tree."""
        result = []
        for top in self.tree:
            result.extend(top.flatten())
        return result


# ---------------------------------------------------------------------------
# PDF text extraction (PyMuPDF)
# ---------------------------------------------------------------------------

def extract_pages(pdf_path: str | Path) -> list[dict[str, Any]]:
    """Extract text and structural info from each page of a PDF.

    Returns list of dicts: {page_num, text, lines} where lines are
    merged spans with dominant font size info for heading detection.
    """
    doc = fitz.open(str(pdf_path))
    pages = []
    for page_num, page in enumerate(doc):
        text = page.get_text("text")
        # Extract lines with merged span info for heading detection
        lines = []
        text_dict = page.get_text("dict", flags=fitz.TEXT_PRESERVE_WHITESPACE)
        for block in text_dict.get("blocks", []):
            if block.get("type") != 0:  # text blocks only
                continue
            for line in block.get("lines", []):
                # Merge all spans in a line into a single text with dominant font info
                span_texts = []
                sizes = []
                flags_list = []
                for span in line.get("spans", []):
                    t = span.get("text", "").strip()
                    if t:
                        span_texts.append(t)
                        sizes.append(span.get("size", 12))
                        flags_list.append(span.get("flags", 0))

                if span_texts:
                    merged_text = " ".join(span_texts)
                    # Use the maximum font size as the line's heading indicator
                    dominant_size = max(sizes)
                    # Bold if any span is bold
                    is_bold = any(f & 16 for f in flags_list)
                    lines.append({
                        "text": merged_text,
                        "size": dominant_size,
                        "flags": 16 if is_bold else 0,
                    })
        pages.append({
            "page_num": page_num,
            "text": text,
            "lines": lines,
        })
    doc.close()
    return pages


def _compute_file_hash(path: Path) -> str:
    """MD5 hash of file for cache invalidation."""
    return hashlib.md5(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Heuristic heading detection
# ---------------------------------------------------------------------------

# Common heading patterns in security/tech PDFs
_HEADING_PATTERNS = [
    re.compile(r"^(?:chapter|section|part)\s+\d", re.IGNORECASE),
    re.compile(r"^\d{1,2}(?:\.\d{1,2}){0,3}\s+[A-Z]"),    # "1.2.3 Title"
    re.compile(r"^[IVXLC]+\.\s+[A-Z]"),                     # "IV. Title"
    re.compile(r"^(?:appendix|annex)\s+[A-Z]", re.IGNORECASE),
]


def _detect_headings(pages: list[dict]) -> list[dict]:
    """Detect headings across all pages using font size and patterns.

    Uses merged line data (not individual spans) so multi-word titles
    like "1.2 Evaluating Methodologies" are detected as a single heading.

    Returns sorted list of {title, page_num, level, font_size}.
    """
    if not pages:
        return []

    # Compute median font size across all lines
    all_sizes = []
    for page in pages:
        for line in page.get("lines", []):
            text = line.get("text", "")
            if len(text) > 3:  # skip tiny fragments
                all_sizes.append(line["size"])

    if not all_sizes:
        return []

    all_sizes.sort()
    median_size = all_sizes[len(all_sizes) // 2]
    # Threshold: anything 1.2x median or larger is likely a heading
    heading_threshold = median_size * 1.2

    headings = []
    seen_text: set[str] = set()

    for page in pages:
        for line in page.get("lines", []):
            text = line["text"].strip()
            if not text or len(text) < 3 or len(text) > 200:
                continue

            is_heading = False
            level = 3  # default: sub-subsection

            font_size = line["size"]
            is_bold = bool(line["flags"] & 16)

            # Size-based detection
            if font_size >= heading_threshold:
                is_heading = True
                # Map font size to level
                if font_size >= median_size * 1.8:
                    level = 1  # chapter
                elif font_size >= median_size * 1.4:
                    level = 2  # section
                else:
                    level = 3  # subsection

            # Bold text at body size can be a subsection heading
            elif is_bold and len(text) < 80 and not text.endswith("."):
                is_heading = True
                level = 3

            # Pattern-based detection (numbered sections)
            if not is_heading:
                for pattern in _HEADING_PATTERNS:
                    if pattern.match(text):
                        is_heading = True
                        # Infer level from numbering depth
                        dots = text.split(" ")[0].count(".")
                        level = min(dots + 1, 4)
                        break

            if is_heading:
                # Deduplicate (same heading text on same page)
                key = f"{page['page_num']}:{text[:40]}"
                if key not in seen_text:
                    seen_text.add(key)
                    headings.append({
                        "title": text,
                        "page_num": page["page_num"],
                        "level": level,
                        "font_size": font_size,
                    })

    return headings


# ---------------------------------------------------------------------------
# Tree builder (heuristic + optional LLM)
# ---------------------------------------------------------------------------

def _build_tree_from_headings(
    headings: list[dict],
    total_pages: int,
) -> list[TreeNode]:
    """Build a hierarchical tree from detected headings.

    Uses level-based nesting: level 1 nodes contain level 2 children,
    which contain level 3 children, etc.
    """
    if not headings:
        # No headings detected — create a single node spanning entire doc
        return [TreeNode(
            title="Full Document",
            node_id="0001",
            level=1,
            start_page=0,
            end_page=total_pages - 1,
        )]

    # Sort by page number then by appearance order
    headings.sort(key=lambda h: (h["page_num"], h.get("_order", 0)))

    # Build flat list of TreeNodes
    nodes: list[TreeNode] = []
    for i, h in enumerate(headings):
        node = TreeNode(
            title=h["title"],
            node_id=f"{i + 1:04d}",
            level=h["level"],
            start_page=h["page_num"],
            end_page=total_pages - 1,  # will be fixed in next pass
        )
        nodes.append(node)

    # Fix end_page: each node ends where the next same-or-higher-level node starts
    for i in range(len(nodes) - 1):
        for j in range(i + 1, len(nodes)):
            if nodes[j].level <= nodes[i].level:
                nodes[i].end_page = max(nodes[j].start_page - 1, nodes[i].start_page)
                break

    # Build hierarchy using a stack-based approach
    root_nodes: list[TreeNode] = []
    stack: list[TreeNode] = []  # stack of active parent nodes

    for node in nodes:
        # Pop stack until we find a parent at a higher level
        while stack and stack[-1].level >= node.level:
            stack.pop()

        if stack:
            # This node is a child of the current top of stack
            stack[-1].children.append(node)
            # Extend parent's end_page if child goes further
            if node.end_page > stack[-1].end_page:
                stack[-1].end_page = node.end_page
        else:
            # This is a root (top-level) node
            root_nodes.append(node)

        stack.append(node)

    return root_nodes


def _generate_node_summaries(
    tree: list[TreeNode],
    pages: list[dict],
    llm: Any | None = None,
    max_nodes: int = 50,
) -> None:
    """Generate summaries for tree nodes.

    If an LLM is provided, uses it for intelligent summarization.
    Otherwise, extracts the first ~200 chars of each section as summary.
    """
    count = 0
    all_nodes = []
    for top in tree:
        all_nodes.extend(top.flatten())

    for node in all_nodes:
        if count >= max_nodes:
            break

        # Extract text for this node's page range
        section_text = ""
        for p in range(node.start_page, min(node.end_page + 1, len(pages))):
            section_text += pages[p].get("text", "") + "\n"

        if not section_text.strip():
            node.summary = "(empty section)"
            continue

        if llm is not None:
            try:
                _generate_summary_with_llm(node, section_text, llm)
                count += 1
                continue
            except Exception as exc:
                logger.warning("LLM summary failed for node %s: %s", node.node_id, exc)

        # Fallback: first 300 chars as summary
        clean = section_text.strip().replace("\n", " ")
        node.summary = clean[:300].strip()
        if len(clean) > 300:
            node.summary += "..."
        count += 1


def _generate_summary_with_llm(
    node: TreeNode,
    section_text: str,
    llm: Any,
) -> None:
    """Use LLM to generate a concise summary for a tree node."""
    # Truncate very long sections
    if len(section_text) > 8000:
        section_text = section_text[:4000] + "\n...[truncated]...\n" + section_text[-2000:]

    prompt = (
        f"Summarize the following document section in 1-2 sentences. "
        f'Section title: "{node.title}"\n\n'
        f"Text:\n{section_text}\n\n"
        f"Summary (1-2 sentences, be specific about key topics covered):"
    )

    from langchain_core.messages import HumanMessage, SystemMessage
    messages = [
        SystemMessage(content="You are a concise document summarizer. Return only the summary, nothing else."),
        HumanMessage(content=prompt),
    ]
    response = llm.invoke(messages)
    from agentictm.agents.base import ensure_str_content
    summary = ensure_str_content(response.content).strip()

    # Strip <think> tags if present (qwen3 reasoning)
    summary = re.sub(r"<think>.*?</think>", "", summary, flags=re.DOTALL).strip()
    node.summary = summary[:500]  # cap length


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_page_index(
    pdf_path: str | Path,
    llm: Any | None = None,
    generate_summaries: bool = True,
    max_summary_nodes: int = 50,
) -> DocumentTree:
    """Build a PageIndex tree from a PDF file.

    Args:
        pdf_path: Path to the PDF file.
        llm: Optional LangChain LLM for summary generation and structure
             refinement. If None, uses heuristic-only approach.
        generate_summaries: Whether to generate node summaries.
        max_summary_nodes: Max number of nodes to summarize (LLM calls).

    Returns:
        DocumentTree with hierarchical structure.
    """
    pdf_path = Path(pdf_path)
    logger.info("[PageIndex] Building tree for: %s", pdf_path.name)
    t0 = time.perf_counter()

    # 1. Extract pages
    pages = extract_pages(pdf_path)
    logger.info("[PageIndex] Extracted %d pages", len(pages))

    # 2. Detect headings
    headings = _detect_headings(pages)
    logger.info("[PageIndex] Detected %d headings", len(headings))

    # 3. Build tree
    tree = _build_tree_from_headings(headings, len(pages))

    # 4. Generate summaries
    if generate_summaries:
        _generate_node_summaries(tree, pages, llm=llm, max_nodes=max_summary_nodes)

    # 5. Create DocumentTree
    doc_tree = DocumentTree(
        doc_name=pdf_path.stem,
        doc_path=str(pdf_path),
        doc_hash=_compute_file_hash(pdf_path),
        total_pages=len(pages),
        tree=tree,
        created_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
    )

    elapsed = time.perf_counter() - t0
    all_nodes = doc_tree.all_nodes()
    logger.info(
        "[PageIndex] Tree built in %.1fs: %d nodes, %d top-level sections",
        elapsed, len(all_nodes), len(tree),
    )
    logger.debug("[PageIndex] Tree outline:\n%s", doc_tree.outline())

    return doc_tree


def get_node_text(
    pdf_path: str | Path,
    node: TreeNode,
) -> str:
    """Extract the full text for a specific tree node from the PDF.

    This is called at retrieval time to get the complete text of
    a section identified by tree search.
    """
    doc = fitz.open(str(pdf_path))
    text_parts = []
    for page_num in range(node.start_page, min(node.end_page + 1, len(doc))):
        page = doc[page_num]
        text_parts.append(f"[Page {page_num + 1}]\n{page.get_text('text')}")
    doc.close()
    return "\n\n".join(text_parts)


# ---------------------------------------------------------------------------
# Tree persistence (JSON)
# ---------------------------------------------------------------------------

def save_tree(doc_tree: DocumentTree, output_dir: Path) -> Path:
    """Save a DocumentTree to JSON."""
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{doc_tree.doc_name}.tree.json"
    output_path.write_text(
        json.dumps(doc_tree.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    logger.info("[PageIndex] Tree saved: %s", output_path)
    return output_path


def load_tree(tree_path: Path) -> DocumentTree:
    """Load a DocumentTree from JSON."""
    data = json.loads(tree_path.read_text(encoding="utf-8"))
    return DocumentTree.from_dict(data)


def load_all_trees(tree_dir: Path) -> dict[str, DocumentTree]:
    """Load all tree indices from a directory.

    Returns dict mapping doc_name → DocumentTree.
    """
    trees: dict[str, DocumentTree] = {}
    if not tree_dir.exists():
        return trees
    for path in tree_dir.glob("*.tree.json"):
        try:
            tree = load_tree(path)
            trees[tree.doc_name] = tree
            logger.info("[PageIndex] Loaded tree: %s (%d nodes)", tree.doc_name, len(tree.all_nodes()))
        except Exception as exc:
            logger.error("[PageIndex] Failed to load tree %s: %s", path, exc)
    return trees


def is_tree_current(pdf_path: Path, tree_path: Path) -> bool:
    """Check if a tree index is up-to-date with the source PDF."""
    if not tree_path.exists():
        return False
    try:
        tree = load_tree(tree_path)
        current_hash = _compute_file_hash(pdf_path)
        return tree.doc_hash == current_hash
    except Exception:
        return False
