"""Shared fixtures for AgenticTM tests.

Provides a MockChatModel that returns canned JSON for each agent,
an LLMFactory-compatible mock, and realistic pipeline state fixtures.
"""

from __future__ import annotations

from typing import Any, List, Optional
from unittest.mock import MagicMock

import pytest
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from tests.fixtures.canned_responses import (
    AGENT_RESPONSE_MAP,
    ARCHITECTURE_PARSER_RESPONSE,
    SYSTEM_PROMPT_PATTERNS,
)


# ---------------------------------------------------------------------------
# MockChatModel
# ---------------------------------------------------------------------------

class MockChatModel(BaseChatModel):
    """A fake LLM that returns canned JSON based on distinctive phrases in
    the system prompt.  Falls back to the architecture parser response when
    no agent is recognised.

    Implements the minimum ``BaseChatModel`` contract so LangChain
    invocations (``invoke``, ``generate``, tool-binding) work seamlessly.
    """

    model_name: str = "mock-model"

    model_config = {"arbitrary_types_allowed": True}

    @property
    def _llm_type(self) -> str:
        return "mock-chat-model"

    def _generate(
        self,
        messages: List[BaseMessage],
        stop: Optional[List[str]] = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        response_text = self._pick_response(messages)
        message = AIMessage(content=response_text)
        return ChatResult(generations=[ChatGeneration(message=message)])

    def _pick_response(self, messages: List[BaseMessage]) -> str:
        """Match on system-prompt-specific patterns first, then fall back to
        combined-text keyword matching."""
        system_text = ""
        combined_text = ""
        for m in messages:
            content = m.content if isinstance(m.content, str) else ""
            combined_text += " " + content
            if m.type == "system":
                system_text += " " + content
        system_lower = system_text.lower()
        combined_lower = combined_text.lower()

        for pattern, response in SYSTEM_PROMPT_PATTERNS.items():
            if pattern in system_lower:
                return response

        for key, response in AGENT_RESPONSE_MAP.items():
            if key in combined_lower:
                return response

        return ARCHITECTURE_PARSER_RESPONSE

    def bind_tools(self, tools: Any, **kwargs: Any) -> "MockChatModel":
        """No-op tool binding — returns self so ``llm.bind_tools(...)`` works."""
        return self


# ---------------------------------------------------------------------------
# MockLLMFactory — drop-in replacement for agentictm.llm.LLMFactory
# ---------------------------------------------------------------------------

class MockLLMFactory:
    """LLMFactory-compatible object where every property returns MockChatModel."""

    def __init__(self) -> None:
        self._llm = MockChatModel()

    @property
    def quick(self) -> BaseChatModel:
        return self._llm

    @property
    def quick_json(self) -> BaseChatModel:
        return self._llm

    @property
    def deep(self) -> BaseChatModel:
        return self._llm

    @property
    def deep_json(self) -> BaseChatModel:
        return self._llm

    @property
    def stride(self) -> BaseChatModel:
        return self._llm

    @property
    def stride_json(self) -> BaseChatModel:
        return self._llm

    @property
    def vlm(self) -> BaseChatModel:
        return self._llm


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_llm():
    """A single MockChatModel instance."""
    return MockChatModel()


@pytest.fixture
def mock_llm_factory():
    """An LLMFactory-compatible object backed by MockChatModel."""
    return MockLLMFactory()


@pytest.fixture
def sample_initial_state() -> dict:
    """Minimal ThreatModelState ready to enter the pipeline."""
    return {
        "system_name": "TestSystem",
        "analysis_date": "2025-01-01",
        "raw_input": (
            "A web application with an API gateway fronted by a CDN. "
            "Backend microservice connects to PostgreSQL over TLS. "
            "Users authenticate via OAuth 2.0 / JWT tokens."
        ),
        "debate_round": 1,
        "max_debate_rounds": 2,
        "iteration_count": 0,
        "methodology_reports": [],
        "debate_history": [],
        "threat_categories": ["base", "web"],
        "executive_summary": "",
    }


@pytest.fixture
def sample_parsed_state(sample_initial_state) -> dict:
    """State as it looks after architecture_parser has run."""
    import json
    parsed = json.loads(ARCHITECTURE_PARSER_RESPONSE)
    return {
        **sample_initial_state,
        "input_type": "text",
        "system_description": parsed["system_description"],
        "components": parsed["components"],
        "data_flows": parsed["data_flows"],
        "trust_boundaries": parsed["trust_boundaries"],
        "external_entities": parsed["external_entities"],
        "data_stores": parsed["data_stores"],
        "scope_notes": json.dumps(parsed["assumptions"]),
        "mermaid_dfd": "graph TD\n  C0[CDN] --> C1[API Gateway]",
    }


@pytest.fixture
def sample_analyzed_state(sample_parsed_state) -> dict:
    """State after all analysts + synthesizer have run (pre-report)."""
    import json
    from tests.fixtures.canned_responses import (
        STRIDE_RESPONSE,
        PASTA_RESPONSE,
        ATTACK_TREE_RESPONSE,
        SYNTHESIZER_RESPONSE,
    )

    stride_threats = json.loads(STRIDE_RESPONSE)["threats"]
    pasta_threats = json.loads(PASTA_RESPONSE)["threats"]
    at_threats = json.loads(ATTACK_TREE_RESPONSE)["threats"]
    synth = json.loads(SYNTHESIZER_RESPONSE)

    return {
        **sample_parsed_state,
        "methodology_reports": [
            {"methodology": "STRIDE", "agent": "stride_analyst", "report": STRIDE_RESPONSE, "threats_raw": stride_threats},
            {"methodology": "PASTA", "agent": "pasta_analyst", "report": PASTA_RESPONSE, "threats_raw": pasta_threats},
            {"methodology": "ATTACK_TREE", "agent": "attack_tree_analyst", "report": ATTACK_TREE_RESPONSE, "threats_raw": at_threats},
        ],
        "debate_history": [],
        "threats_final": synth["threats"],
        "executive_summary": synth["executive_summary"],
    }
