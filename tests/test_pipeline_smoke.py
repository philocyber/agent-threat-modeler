"""Full pipeline smoke test + per-node contract validation.

Runs the compiled LangGraph with MockChatModel to validate that every node
produces the expected state keys and types — without hitting any real LLM.
"""

from __future__ import annotations

import json

import pytest

from agentictm.config import AgenticTMConfig, PipelineConfig
from agentictm.graph.builder import build_graph
from tests.conftest import MockLLMFactory
from tests.fixtures.canned_responses import (
    ARCHITECTURE_PARSER_RESPONSE,
    STRIDE_RESPONSE,
    PASTA_RESPONSE,
    ATTACK_TREE_RESPONSE,
    SYNTHESIZER_RESPONSE,
    DREAD_VALIDATOR_RESPONSE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_cascade_config(**overrides) -> AgenticTMConfig:
    """Config that uses cascade mode (sequential) for deterministic ordering."""
    pipeline_kw = {
        "analyst_execution_mode": "cascade",
        "max_parallel_analysts": 1,
        "max_debate_rounds": 2,
        "skip_debate": True,
        "skip_enriched_attack_tree": True,
        "skip_dread_validator": False,
        "skip_output_localizer": True,
        "output_language": "en",
        **overrides,
    }
    return AgenticTMConfig(pipeline=PipelineConfig(**pipeline_kw))


def _initial_state() -> dict:
    return {
        "system_name": "SmokeTest",
        "analysis_date": "2025-01-01",
        "raw_input": (
            "A web application with an API gateway fronted by a CDN. "
            "Backend microservice connects to PostgreSQL over TLS. "
            "Users authenticate via OAuth 2.0 / JWT tokens."
        ),
        "debate_round": 1,
        "max_debate_rounds": 0,
        "iteration_count": 0,
        "methodology_reports": [],
        "debate_history": [],
        "threat_categories": ["base", "web"],
        "executive_summary": "",
    }


# ---------------------------------------------------------------------------
# End-to-end smoke test
# ---------------------------------------------------------------------------

class TestFullPipelineSmoke:
    """Run the entire compiled graph with mock LLMs."""

    def test_full_pipeline_produces_required_outputs(self):
        """The graph must produce system_description, components, data_flows,
        methodology_reports, threats_final, csv_output, and report_output."""
        config = _build_cascade_config()
        factory = MockLLMFactory()
        graph = build_graph(config, factory)
        app = graph.compile()

        result = app.invoke(_initial_state())

        assert isinstance(result["system_description"], str)
        assert len(result["system_description"]) > 0

        assert isinstance(result["components"], list)
        assert len(result["components"]) > 0

        assert isinstance(result["data_flows"], list)
        assert len(result["data_flows"]) > 0

        assert isinstance(result["methodology_reports"], list)
        assert len(result["methodology_reports"]) >= 2

        assert isinstance(result["threats_final"], list)
        assert len(result["threats_final"]) > 0

        assert result.get("csv_output"), "csv_output should be non-empty"
        assert result.get("report_output"), "report_output should be non-empty"

    def test_no_errors_accumulated(self):
        """The pipeline should run without any nodes recording errors."""
        config = _build_cascade_config()
        factory = MockLLMFactory()
        graph = build_graph(config, factory)
        app = graph.compile()

        result = app.invoke(_initial_state())
        errors = result.get("_errors", [])
        assert errors == [], f"Pipeline accumulated errors: {errors}"


# ---------------------------------------------------------------------------
# Per-node contract tests
# ---------------------------------------------------------------------------

class TestArchitectureParserNode:
    """Validate the architecture_parser node output contract."""

    def test_writes_all_required_keys(self):
        config = _build_cascade_config()
        factory = MockLLMFactory()
        graph = build_graph(config, factory)
        app = graph.compile()

        result = app.invoke(_initial_state())

        required_keys = [
            "system_description", "components", "data_flows",
            "trust_boundaries", "external_entities", "data_stores",
        ]
        for key in required_keys:
            assert key in result, f"Missing key: {key}"

    def test_components_have_name_and_type(self):
        config = _build_cascade_config()
        factory = MockLLMFactory()
        graph = build_graph(config, factory)
        app = graph.compile()

        result = app.invoke(_initial_state())

        for comp in result["components"]:
            assert "name" in comp, f"Component missing 'name': {comp}"
            assert "type" in comp, f"Component missing 'type': {comp}"

    def test_data_flows_have_source_destination(self):
        config = _build_cascade_config()
        factory = MockLLMFactory()
        graph = build_graph(config, factory)
        app = graph.compile()

        result = app.invoke(_initial_state())

        for flow in result["data_flows"]:
            assert "source" in flow, f"DataFlow missing 'source': {flow}"
            assert "destination" in flow, f"DataFlow missing 'destination': {flow}"


class TestStrideNode:
    """Validate STRIDE analyst node output contract."""

    def test_appends_methodology_report(self):
        config = _build_cascade_config()
        factory = MockLLMFactory()
        graph = build_graph(config, factory)
        app = graph.compile()

        result = app.invoke(_initial_state())

        stride_reports = [
            r for r in result["methodology_reports"]
            if r.get("methodology") == "STRIDE"
        ]
        assert len(stride_reports) >= 1, "No STRIDE methodology report found"
        report = stride_reports[0]
        assert report["agent"] == "stride_analyst"
        assert isinstance(report["threats_raw"], list)
        assert len(report["threats_raw"]) > 0


class TestSynthesizerNode:
    """Validate threat_synthesizer node output contract."""

    def test_threats_final_has_required_fields(self):
        config = _build_cascade_config()
        factory = MockLLMFactory()
        graph = build_graph(config, factory)
        app = graph.compile()

        result = app.invoke(_initial_state())

        assert len(result["threats_final"]) > 0
        for threat in result["threats_final"]:
            assert "id" in threat, f"Threat missing 'id': {threat}"
            assert "component" in threat, f"Threat missing 'component': {threat}"
            assert "description" in threat, f"Threat missing 'description': {threat}"


class TestDreadValidatorNode:
    """Validate DREAD validator node output contract."""

    def test_dread_scores_in_valid_range(self):
        config = _build_cascade_config(skip_dread_validator=False)
        factory = MockLLMFactory()
        graph = build_graph(config, factory)
        app = graph.compile()

        result = app.invoke(_initial_state())

        dread_fields = ["damage", "reproducibility", "exploitability",
                        "affected_users", "discoverability"]
        for threat in result["threats_final"]:
            for field in dread_fields:
                val = threat.get(field)
                if val is not None:
                    assert 0 <= val <= 10, (
                        f"Threat {threat.get('id')}: {field}={val} out of 0-10 range"
                    )

    def test_priority_is_set(self):
        config = _build_cascade_config(skip_dread_validator=False)
        factory = MockLLMFactory()
        graph = build_graph(config, factory)
        app = graph.compile()

        result = app.invoke(_initial_state())

        valid_priorities = {"Critical", "High", "Medium", "Low"}
        for threat in result["threats_final"]:
            priority = threat.get("priority")
            if priority is not None:
                assert priority in valid_priorities, (
                    f"Threat {threat.get('id')}: invalid priority '{priority}'"
                )


class TestReportGeneratorNode:
    """Validate report_generator node output contract."""

    def test_csv_and_markdown_generated(self):
        config = _build_cascade_config()
        factory = MockLLMFactory()
        graph = build_graph(config, factory)
        app = graph.compile()

        result = app.invoke(_initial_state())

        assert isinstance(result.get("csv_output"), str)
        assert len(result["csv_output"]) > 10, "CSV output too short"
        assert isinstance(result.get("report_output"), str)
        assert len(result["report_output"]) > 10, "Report output too short"


class TestDebateSkipFastMode:
    """Verify that fast mode correctly skips debate and wires to enriched tree."""

    def test_fast_mode_skips_debate(self):
        config = _build_cascade_config(
            skip_debate=True,
            max_debate_rounds=0,
        )
        factory = MockLLMFactory()
        graph = build_graph(config, factory)
        app = graph.compile()

        result = app.invoke(_initial_state())

        assert result.get("debate_history") == [] or result.get("debate_history") is None or len(result.get("debate_history", [])) == 0
        assert len(result.get("threats_final", [])) > 0

    def test_debate_enabled_produces_entries(self):
        config = _build_cascade_config(
            skip_debate=False,
            max_debate_rounds=2,
        )
        factory = MockLLMFactory()
        graph = build_graph(config, factory)
        app = graph.compile()

        state = _initial_state()
        state["max_debate_rounds"] = 2
        result = app.invoke(state)

        assert len(result.get("debate_history", [])) >= 2, (
            "Debate should have produced at least 2 entries (1 red + 1 blue)"
        )
