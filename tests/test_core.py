"""Tests para config, state, LLM factory y core."""

import json
import pytest
from pathlib import Path

from agentictm.config import AgenticTMConfig, LLMConfig, RAGConfig, PipelineConfig
from agentictm.state import (
    ThreatModelState,
    Component,
    DataFlow,
    TrustBoundary,
    Threat,
    DebateEntry,
)


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------

class TestAgenticTMConfig:
    """Tests para la configuración Pydantic."""

    def test_default_config_creates(self):
        config = AgenticTMConfig()
        assert isinstance(config, AgenticTMConfig)

    def test_default_llm_provider(self):
        config = AgenticTMConfig()
        assert config.quick_thinker.provider == "ollama"
        assert config.deep_thinker.provider == "ollama"

    def test_default_models(self):
        config = AgenticTMConfig()
        assert config.quick_thinker.model == "qwen3:4b"
        assert config.deep_thinker.model == "qwen3.5:9b"
        assert config.rag.embedding_model == "nomic-embed-text-v2-moe"

    def test_default_pipeline(self):
        config = AgenticTMConfig()
        assert config.pipeline.max_debate_rounds == 4
        assert config.pipeline.output_language == "en"

    def test_default_rag(self):
        config = AgenticTMConfig()
        assert config.rag.chunk_size == 1000
        assert config.rag.chunk_overlap == 200
        assert config.rag.retrieval_top_k == 5

    def test_custom_config(self):
        config = AgenticTMConfig(
            quick_thinker=LLMConfig(model="llama3:8b"),
            pipeline=PipelineConfig(max_debate_rounds=5),
        )
        assert config.quick_thinker.model == "llama3:8b"
        assert config.pipeline.max_debate_rounds == 5

    def test_to_json(self):
        config = AgenticTMConfig()
        json_str = config.model_dump_json()
        data = json.loads(json_str)
        assert "quick_thinker" in data
        assert "pipeline" in data
        assert "rag" in data

    def test_save_and_load(self, tmp_path):
        config = AgenticTMConfig(
            quick_thinker=LLMConfig(model="test-model"),
        )
        path = tmp_path / "config.json"
        config.save(path)
        loaded = AgenticTMConfig.load(path)
        assert loaded.quick_thinker.model == "test-model"


# ---------------------------------------------------------------------------
# State tests
# ---------------------------------------------------------------------------

class TestThreatModelState:
    """Tests para los tipos de state."""

    def test_component_type(self):
        comp: Component = {
            "name": "API Gateway",
            "type": "process",
            "description": "Routes traffic",
            "scope": "internal",
        }
        assert comp["name"] == "API Gateway"
        assert comp["type"] == "process"

    def test_data_flow_type(self):
        flow: DataFlow = {
            "source": "Client",
            "destination": "Server",
            "protocol": "HTTPS",
            "data_type": "JSON",
            "bidirectional": False,
        }
        assert flow["source"] == "Client"
        assert flow["protocol"] == "HTTPS"

    def test_trust_boundary_type(self):
        tb: TrustBoundary = {
            "name": "DMZ",
            "components_inside": ["Web Server"],
            "components_outside": ["Internet"],
        }
        assert tb["name"] == "DMZ"
        assert "Web Server" in tb["components_inside"]

    def test_threat_type(self):
        threat: Threat = {
            "id": "TM-001",
            "component": "API Gateway",
            "description": "JWT bypass",
            "methodology": "STRIDE",
            "stride_category": "S",
            "damage": 8,
            "reproducibility": 7,
            "exploitability": 6,
            "affected_users": 9,
            "discoverability": 5,
            "dread_total": 35,
            "priority": "High",
            "mitigation": "Validate JWT expiry",
            "status": "Open",
        }
        assert threat["dread_total"] == 35
        assert threat["priority"] == "High"

    def test_debate_entry_type(self):
        entry: DebateEntry = {
            "round": 1,
            "side": "red",
            "argument": "The JWT has no expiry check",
        }
        assert entry["side"] == "red"
        assert entry["round"] == 1

    def test_state_can_be_created(self):
        state: ThreatModelState = {
            "system_name": "Test System",
            "raw_input": "A simple web app",
            "input_type": "text",
        }
        assert state["system_name"] == "Test System"


# ---------------------------------------------------------------------------
# LLM Factory tests (basic — no actual Ollama needed)
# ---------------------------------------------------------------------------

class TestLLMFactory:
    """Tests para LLMFactory (solo creación, no invocación)."""

    def test_factory_creates(self):
        from agentictm.llm import LLMFactory
        config = AgenticTMConfig()
        factory = LLMFactory(config.quick_thinker, config.deep_thinker, config.vlm, config.stride_thinker)
        assert factory is not None

    def test_quick_property(self):
        from agentictm.llm import LLMFactory
        config = AgenticTMConfig()
        factory = LLMFactory(config.quick_thinker, config.deep_thinker, config.vlm, config.stride_thinker)
        llm = factory.quick
        assert llm is not None

    def test_deep_property(self):
        from agentictm.llm import LLMFactory
        config = AgenticTMConfig()
        factory = LLMFactory(config.quick_thinker, config.deep_thinker, config.vlm, config.stride_thinker)
        llm = factory.deep
        assert llm is not None

    def test_stride_property(self):
        from agentictm.llm import LLMFactory
        config = AgenticTMConfig()
        factory = LLMFactory(config.quick_thinker, config.deep_thinker, config.vlm, config.stride_thinker)
        llm = factory.stride
        assert llm is not None


# ---------------------------------------------------------------------------
# Graph compilation tests
# ---------------------------------------------------------------------------

class TestGraphBuilder:
    """Tests para la construcción del grafo."""

    def _make_factory(self):
        from agentictm.llm import LLMFactory
        config = AgenticTMConfig()
        return config, LLMFactory(config.quick_thinker, config.deep_thinker, config.vlm, config.stride_thinker)

    def test_graph_builds(self):
        from agentictm.graph.builder import build_graph
        config, factory = self._make_factory()
        graph = build_graph(config, factory)
        assert graph is not None

    def test_graph_has_17_nodes(self):
        from agentictm.graph.builder import build_graph
        config, factory = self._make_factory()
        graph = build_graph(config, factory)
        assert len(graph.nodes) == 17

    def test_graph_node_names(self):
        from agentictm.graph.builder import build_graph
        config, factory = self._make_factory()
        graph = build_graph(config, factory)
        expected = {
            "architecture_parser",
            "arch_clarifier",
            "architecture_reviewer",
            "stride_analyst",
            "pasta_analyst",
            "attack_tree_analyst",
            "maestro_analyst",
            "ai_threat_analyst",
            "red_team",
            "blue_team",
            "attack_tree_enriched",
            "threat_synthesizer",
            "quality_judge",
            "dread_validator",
            "hallucination_detector",
            "output_localizer",
            "report_generator",
        }
        assert set(graph.nodes.keys()) == expected

    def test_graph_compiles(self):
        from agentictm.graph.builder import compile_graph
        config, factory = self._make_factory()
        compiled = compile_graph(config, factory)
        assert compiled is not None


# ---------------------------------------------------------------------------
# Agent base tests
# ---------------------------------------------------------------------------

class TestAgentBase:
    """Tests para funciones utilitarias de agents/base.py."""

    def test_extract_json_from_code_block(self):
        from agentictm.agents.base import extract_json_from_response
        text = 'Here is the result:\n```json\n{"key": "value"}\n```'
        result = extract_json_from_response(text)
        assert result == {"key": "value"}

    def test_extract_json_plain(self):
        from agentictm.agents.base import extract_json_from_response
        text = '{"key": "value"}'
        result = extract_json_from_response(text)
        assert result == {"key": "value"}

    def test_extract_json_with_surrounding_text(self):
        from agentictm.agents.base import extract_json_from_response
        text = 'Some text before {"key": "value"} and after'
        result = extract_json_from_response(text)
        assert result == {"key": "value"}

    def test_extract_json_returns_none_for_invalid(self):
        from agentictm.agents.base import extract_json_from_response
        text = "No JSON here at all"
        result = extract_json_from_response(text)
        assert result is None

    def test_build_messages(self):
        from agentictm.agents.base import build_messages
        msgs = build_messages("You are an assistant.", "Hello!")
        assert len(msgs) == 2
        assert msgs[0].content == "You are an assistant."
        assert msgs[1].content == "Hello!"

    def test_strip_think_tags(self):
        from agentictm.agents.base import _strip_think_tags
        text = '<think>\nReasoning about the problem...\n</think>\n{"key": "value"}'
        result = _strip_think_tags(text)
        assert "<think>" not in result
        assert '{"key": "value"}' in result

    def test_strip_think_tags_preserves_content_without_tags(self):
        from agentictm.agents.base import _strip_think_tags
        text = '{"key": "value"}'
        result = _strip_think_tags(text)
        assert result == '{"key": "value"}'

    def test_extract_json_with_think_tags(self):
        from agentictm.agents.base import extract_json_from_response
        text = '<think>\nLet me think...\n</think>\n```json\n{"threats": [{"id": "TM-001"}]}\n```'
        result = extract_json_from_response(text)
        assert result is not None
        assert "threats" in result

    def test_extract_json_with_think_tags_no_code_block(self):
        from agentictm.agents.base import extract_json_from_response
        text = '<think>\nAnalyzing...\n</think>\n{"methodology": "STRIDE", "threats": []}'
        result = extract_json_from_response(text)
        assert result is not None
        assert result["methodology"] == "STRIDE"

    def test_extract_json_returns_none_for_empty(self):
        from agentictm.agents.base import extract_json_from_response
        assert extract_json_from_response("") is None
        assert extract_json_from_response("   ") is None
