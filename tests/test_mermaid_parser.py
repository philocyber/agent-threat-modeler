"""Tests para el Mermaid parser."""

import pytest

from agentictm.parsers.mermaid_parser import (
    MermaidParseResult,
    parse_mermaid,
    mermaid_to_system_model,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SIMPLE_DIAGRAM = """
flowchart TD
    U([User]) -->|HTTPS| GW[API Gateway]
    GW --> AUTH[Auth Service]
    GW --> API[Order Service]
    API --> DB[(PostgreSQL)]
    API --> CACHE[(Redis)]
    API -->|Webhook| STRIPE([Stripe])

    subgraph Internal
        GW
        AUTH
        API
        DB
        CACHE
    end
"""

MINIMAL_DIAGRAM = """
graph LR
    A[Service A] --> B[Service B]
"""

DASHED_EDGE_DIAGRAM = """
flowchart TD
    A[Web] -.->|async| B[Queue]
    B ==> C[Worker]
"""


# ---------------------------------------------------------------------------
# Tests: parse_mermaid
# ---------------------------------------------------------------------------

class TestParseMermaid:
    """Tests para la función parse_mermaid."""

    def test_returns_parse_result(self):
        result = parse_mermaid(SIMPLE_DIAGRAM)
        assert isinstance(result, MermaidParseResult)

    def test_extracts_all_nodes(self):
        result = parse_mermaid(SIMPLE_DIAGRAM)
        node_ids = {n.id for n in result.nodes}
        assert node_ids == {"U", "GW", "AUTH", "API", "DB", "CACHE", "STRIPE"}

    def test_node_count(self):
        result = parse_mermaid(SIMPLE_DIAGRAM)
        assert len(result.nodes) == 7

    def test_inferred_types(self):
        result = parse_mermaid(SIMPLE_DIAGRAM)
        type_map = {n.id: n.inferred_type for n in result.nodes}
        assert type_map["U"] == "external_entity"
        assert type_map["GW"] == "process"
        assert type_map["AUTH"] == "process"
        assert type_map["DB"] == "data_store"
        assert type_map["CACHE"] == "data_store"
        assert type_map["STRIPE"] == "external_entity"

    def test_node_labels(self):
        result = parse_mermaid(SIMPLE_DIAGRAM)
        label_map = {n.id: n.label for n in result.nodes}
        assert label_map["U"] == "User"
        assert label_map["GW"] == "API Gateway"
        assert label_map["DB"] == "PostgreSQL"

    def test_extracts_all_edges(self):
        result = parse_mermaid(SIMPLE_DIAGRAM)
        assert len(result.edges) == 6

    def test_edge_labels(self):
        result = parse_mermaid(SIMPLE_DIAGRAM)
        labeled = {(e.source, e.target): e.label for e in result.edges if e.label}
        assert labeled[("U", "GW")] == "HTTPS"
        assert labeled[("API", "STRIPE")] == "Webhook"

    def test_edge_sources_and_targets(self):
        result = parse_mermaid(SIMPLE_DIAGRAM)
        edge_pairs = [(e.source, e.target) for e in result.edges]
        assert ("U", "GW") in edge_pairs
        assert ("GW", "AUTH") in edge_pairs
        assert ("GW", "API") in edge_pairs
        assert ("API", "DB") in edge_pairs
        assert ("API", "CACHE") in edge_pairs
        assert ("API", "STRIPE") in edge_pairs

    def test_subgraph_detected(self):
        result = parse_mermaid(SIMPLE_DIAGRAM)
        assert len(result.subgraphs) == 1

    def test_subgraph_label(self):
        result = parse_mermaid(SIMPLE_DIAGRAM)
        assert result.subgraphs[0].label == "Internal"

    def test_subgraph_node_ids(self):
        result = parse_mermaid(SIMPLE_DIAGRAM)
        sg = result.subgraphs[0]
        assert set(sg.node_ids) == {"GW", "AUTH", "API", "DB", "CACHE"}

    def test_minimal_diagram(self):
        result = parse_mermaid(MINIMAL_DIAGRAM)
        assert len(result.nodes) == 2
        assert len(result.edges) == 1
        assert result.edges[0].source == "A"
        assert result.edges[0].target == "B"

    def test_dashed_and_thick_edges(self):
        result = parse_mermaid(DASHED_EDGE_DIAGRAM)
        assert len(result.edges) == 2
        styles = {(e.source, e.target): e.style for e in result.edges}
        assert styles[("A", "B")] == "dotted"
        assert styles[("B", "C")] == "thick"

    def test_edge_label_dashed(self):
        result = parse_mermaid(DASHED_EDGE_DIAGRAM)
        labels = {(e.source, e.target): e.label for e in result.edges}
        assert labels[("A", "B")] == "async"

    def test_empty_input(self):
        result = parse_mermaid("")
        assert len(result.nodes) == 0
        assert len(result.edges) == 0

    def test_no_subgraphs(self):
        result = parse_mermaid(MINIMAL_DIAGRAM)
        assert len(result.subgraphs) == 0


# ---------------------------------------------------------------------------
# Tests: mermaid_to_system_model
# ---------------------------------------------------------------------------

class TestMermaidToSystemModel:
    """Tests para la conversión a system model."""

    def _parse_and_convert(self, code: str) -> dict:
        parsed = parse_mermaid(code)
        return mermaid_to_system_model(parsed)

    def test_returns_dict(self):
        model = self._parse_and_convert(SIMPLE_DIAGRAM)
        assert isinstance(model, dict)

    def test_has_components(self):
        model = self._parse_and_convert(SIMPLE_DIAGRAM)
        assert "components" in model
        assert len(model["components"]) == 7

    def test_component_types(self):
        model = self._parse_and_convert(SIMPLE_DIAGRAM)
        comps = {c["name"]: c["type"] for c in model["components"]}
        assert comps["User"] == "external_entity"
        assert comps["API Gateway"] == "process"
        assert comps["PostgreSQL"] == "data_store"

    def test_has_data_flows(self):
        model = self._parse_and_convert(SIMPLE_DIAGRAM)
        assert "data_flows" in model
        assert len(model["data_flows"]) == 6

    def test_data_flow_protocol(self):
        model = self._parse_and_convert(SIMPLE_DIAGRAM)
        flows = model["data_flows"]
        https_flow = [f for f in flows if f["protocol"] == "HTTPS"]
        assert len(https_flow) == 1
        assert https_flow[0]["source"] == "User"
        assert https_flow[0]["destination"] == "API Gateway"

    def test_has_trust_boundaries(self):
        model = self._parse_and_convert(SIMPLE_DIAGRAM)
        assert "trust_boundaries" in model
        assert len(model["trust_boundaries"]) == 1

    def test_trust_boundary_contents(self):
        model = self._parse_and_convert(SIMPLE_DIAGRAM)
        tb = model["trust_boundaries"][0]
        assert tb["name"] == "Internal"
        assert "API Gateway" in tb["components_inside"]
        assert "Auth Service" in tb["components_inside"]
