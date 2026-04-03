"""Parser de diagramas Mermaid → componentes estructurados."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class MermaidNode:
    id: str
    label: str
    shape: str  # "rectangle" | "rounded" | "cylinder" | "circle" | "stadium"
    inferred_type: str = ""  # "process" | "data_store" | "external_entity"


@dataclass
class MermaidEdge:
    source: str
    target: str
    label: str = ""
    style: str = "solid"  # "solid" | "dotted" | "thick"


@dataclass
class MermaidSubgraph:
    id: str
    label: str
    node_ids: list[str] = field(default_factory=list)


@dataclass
class MermaidParseResult:
    nodes: list[MermaidNode] = field(default_factory=list)
    edges: list[MermaidEdge] = field(default_factory=list)
    subgraphs: list[MermaidSubgraph] = field(default_factory=list)


# ── Regex patterns ──

# Node patterns:  A[label], A([label]), A[(label)], A((label)), A{label}
_NODE_PATTERNS = [
    # A[(database label)]  → cylinder = data_store
    (r'(\w+)\[\((.+?)\)\]', "cylinder", "data_store"),
    # A([rounded label])    → stadium = external_entity
    (r'(\w+)\(\[(.+?)\]\)', "stadium", "external_entity"),
    # A((circle label))     → circle = process
    (r'(\w+)\(\((.+?)\)\)', "circle", "process"),
    # A{decision label}     → diamond
    (r'(\w+)\{(.+?)\}', "diamond", "process"),
    # A[rectangle label]    → rectangle = process
    (r'(\w+)\[(.+?)\]', "rectangle", "process"),
    # A(rounded label)      → rounded = process
    (r'(\w+)\((.+?)\)', "rounded", "process"),
]

# Edge patterns: -->, --->, -.->  with optional labels
# Use (?:[^-]|$) lookahead-like patterns. The key insight:
# in Mermaid, edge lines may have inline node defs like A([label]) -->|proto| B[label]
# So we strip node definitions first, then match edges.
_EDGE_PATTERNS = [
    # A -.->|label| B  (dotted with label)
    (r'(\w+)\s*-\.->(?:\|(.+?)\|)?\s*(\w+)', "dotted"),
    # A ==>|label| B  (thick with label)
    (r'(\w+)\s*==>(?:\|(.+?)\|)?\s*(\w+)', "thick"),
    # A -->|label| B  (solid with label)
    (r'(\w+)\s*-->(?:\|(.+?)\|)?\s*(\w+)', "solid"),
    # A --- B  (link without arrow)
    (r'(\w+)\s*---\s*(\w+)', "solid"),
]


def _strip_node_defs(line: str) -> str:
    """Remove inline node definitions, leaving only IDs for edge matching.

    E.g.: 'U([User]) -->|HTTPS| GW[API Gateway]'  →  'U -->|HTTPS| GW'
    """
    # Remove all node shape content: [(..)], ([..]), ((..)), {..}, [..], (..)
    cleaned = re.sub(r'\[\(.*?\)\]', '', line)
    cleaned = re.sub(r'\(\[.*?\]\)', '', cleaned)
    cleaned = re.sub(r'\(\(.*?\)\)', '', cleaned)
    cleaned = re.sub(r'\{.*?\}', '', cleaned)
    cleaned = re.sub(r'\[.*?\]', '', cleaned)
    cleaned = re.sub(r'\(.*?\)', '', cleaned)
    return cleaned


def parse_mermaid(code: str) -> MermaidParseResult:
    """Parsea código Mermaid flowchart y extrae nodos, edges y subgraphs.

    Soporta:
        - graph TD / graph LR / flowchart TD / flowchart LR
        - Nodos con distintas formas: [], ([]), [()], (()), {}
        - Edges: -->, -.->, ==>  con labels opcionales |label|
        - subgraph ... end  → mapeados como trust boundaries
    """
    result = MermaidParseResult()
    known_nodes: dict[str, MermaidNode] = {}

    lines = code.strip().splitlines()

    # ── Parse subgraphs ──
    current_subgraph: MermaidSubgraph | None = None
    for line in lines:
        stripped = line.strip()

        # subgraph id["label"]  o  subgraph label
        sg_match = re.match(r'subgraph\s+(\w+)\s*\["?(.+?)"?\]', stripped)
        if not sg_match:
            sg_match = re.match(r'subgraph\s+(.+)', stripped)
            if sg_match:
                label = sg_match.group(1).strip().strip('"')
                sg_id = re.sub(r'\W+', '_', label)
                sg_match = type('M', (), {'group': lambda self, n: {1: sg_id, 2: label}[n]})()

        if sg_match is not None:
            sg_id = sg_match.group(1)
            sg_label = sg_match.group(2) if hasattr(sg_match, 'lastindex') and sg_match.lastindex and sg_match.lastindex >= 2 else sg_id
            current_subgraph = MermaidSubgraph(id=sg_id, label=sg_label)
            result.subgraphs.append(current_subgraph)
            continue

        if stripped == "end" and current_subgraph is not None:
            current_subgraph = None
            continue

        # ── Parse nodes ──
        found_node_on_line = False
        for pattern, shape, inferred_type in _NODE_PATTERNS:
            for m in re.finditer(pattern, stripped):
                node_id = m.group(1)
                label = m.group(2)
                found_node_on_line = True

                if node_id not in known_nodes:
                    node = MermaidNode(
                        id=node_id,
                        label=label,
                        shape=shape,
                        inferred_type=inferred_type,
                    )
                    known_nodes[node_id] = node
                    result.nodes.append(node)

                if current_subgraph is not None and node_id not in current_subgraph.node_ids:
                    current_subgraph.node_ids.append(node_id)

        # Bare node reference inside subgraph (e.g. just "GW" on a line)
        if not found_node_on_line and current_subgraph is not None:
            bare = stripped.strip()
            if bare and re.match(r'^(\w+)$', bare):
                bare_id = bare
                if bare_id in known_nodes and bare_id not in current_subgraph.node_ids:
                    current_subgraph.node_ids.append(bare_id)

        # ── Parse edges (on cleaned line without node shape defs) ──
        edge_line = _strip_node_defs(stripped)
        for pattern, style in _EDGE_PATTERNS:
            for m in re.finditer(pattern, edge_line):
                groups = m.groups()
                if len(groups) == 3:
                    src, label, tgt = groups
                elif len(groups) == 2:
                    src, tgt = groups
                    label = ""
                else:
                    continue

                edge = MermaidEdge(
                    source=src,
                    target=tgt,
                    label=label or "",
                    style=style,
                )
                result.edges.append(edge)

    return result


def mermaid_to_system_model(result: MermaidParseResult) -> dict:
    """Convierte el resultado del parser a la estructura del SystemModel.

    Returns:
        dict con keys: components, data_flows, trust_boundaries
    """
    components = []
    for node in result.nodes:
        components.append({
            "name": node.label,
            "type": node.inferred_type,
            "description": "",
            "scope": "unknown",
        })

    data_flows = []
    node_map = {n.id: n.label for n in result.nodes}
    for edge in result.edges:
        data_flows.append({
            "source": node_map.get(edge.source, edge.source),
            "destination": node_map.get(edge.target, edge.target),
            "protocol": edge.label if edge.label else "unknown",
            "data_type": "unknown",
            "bidirectional": False,
        })

    trust_boundaries = []
    for sg in result.subgraphs:
        inside_names = [node_map.get(nid, nid) for nid in sg.node_ids]
        all_names = [n.label for n in result.nodes]
        outside_names = [n for n in all_names if n not in inside_names]
        trust_boundaries.append({
            "name": sg.label,
            "components_inside": inside_names,
            "components_outside": outside_names,
        })

    return {
        "components": components,
        "data_flows": data_flows,
        "trust_boundaries": trust_boundaries,
    }
