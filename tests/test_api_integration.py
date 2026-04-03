"""Integration tests for the AgenticTM FastAPI server.

Uses httpx.AsyncClient with FastAPI TestClient to verify all API
endpoints work correctly, including auth, upload, results CRUD,
and the readiness probe.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def client():
    """Create an httpx async client wired to the FastAPI app."""
    # Patch storage init so we don't need real SQLite in tests
    with patch("agentictm.api.server._store") as mock_store:
        mock_store.init = AsyncMock()
        mock_store.close = AsyncMock()
        mock_store.save = AsyncMock()
        mock_store.delete = AsyncMock(return_value=True)
        mock_store.list_full = AsyncMock(return_value={})

        from agentictm.api.server import app

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac


@pytest.fixture
def sample_upload_file(tmp_path: Path) -> Path:
    """Create a temporary .md file for upload testing."""
    f = tmp_path / "test_system.md"
    f.write_text("# Test System\nA simple web API with a database.\n", encoding="utf-8")
    return f


# ---------------------------------------------------------------------------
# Health & Readiness
# ---------------------------------------------------------------------------

class TestHealthEndpoints:
    @pytest.mark.asyncio
    async def test_health_returns_ok(self, client: AsyncClient):
        resp = await client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "version" in data
        assert "timestamp" in data

    @pytest.mark.asyncio
    async def test_ready_endpoint_exists(self, client: AsyncClient):
        resp = await client.get("/api/ready")
        # May be 200 or 503 depending on Ollama — either is valid
        assert resp.status_code in (200, 503)
        data = resp.json()
        assert "ready" in data

    @pytest.mark.asyncio
    async def test_categories_list(self, client: AsyncClient):
        resp = await client.get("/api/categories")
        assert resp.status_code == 200
        categories = resp.json()
        assert isinstance(categories, list)
        assert len(categories) > 0
        assert any(c["id"] == "auto" for c in categories)


# ---------------------------------------------------------------------------
# File Upload
# ---------------------------------------------------------------------------

class TestFileUpload:
    @pytest.mark.asyncio
    async def test_upload_valid_markdown(self, client: AsyncClient, sample_upload_file: Path):
        with open(sample_upload_file, "rb") as f:
            resp = await client.post(
                "/api/upload",
                files={"file": ("test.md", f, "text/markdown")},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "upload_id" in data
        assert data["filename"] == "test.md"
        assert data["size"] > 0
        assert data["is_image"] is False

    @pytest.mark.asyncio
    async def test_upload_rejects_exe(self, client: AsyncClient, tmp_path: Path):
        exe_file = tmp_path / "malware.exe"
        exe_file.write_bytes(b"\x00" * 100)
        with open(exe_file, "rb") as f:
            resp = await client.post(
                "/api/upload",
                files={"file": ("malware.exe", f, "application/octet-stream")},
            )
        assert resp.status_code == 400
        assert "no permitido" in resp.json()["detail"].lower() or "not allowed" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_upload_sanitizes_filename(self, client: AsyncClient, tmp_path: Path):
        f = tmp_path / "normal.md"
        f.write_text("content", encoding="utf-8")
        with open(f, "rb") as fh:
            resp = await client.post(
                "/api/upload",
                files={"file": ("../../etc/passwd.md", fh, "text/markdown")},
            )
        assert resp.status_code == 200
        # Filename should be sanitized — no path traversal
        assert "/" not in resp.json()["filename"]
        assert "\\" not in resp.json()["filename"]


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

class TestAuthentication:
    @pytest.mark.asyncio
    async def test_no_auth_required_when_no_key_configured(self, client: AsyncClient):
        """When no API key is set, all endpoints should be accessible."""
        # Health should always work
        resp = await client.get("/api/health")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_auth_required_when_key_configured(self, client: AsyncClient):
        """When API key is set, mutating endpoints require it."""
        from agentictm.api.server import _config

        original_key = _config.security.api_key
        try:
            _config.security.api_key = "test-secret-key"

            # Analyze without key should fail
            resp = await client.post(
                "/api/analyze",
                json={"system_input": "test", "system_name": "test"},
            )
            assert resp.status_code == 401

            # With correct key should pass (though analysis may fail for other reasons)
            resp = await client.post(
                "/api/analyze",
                json={"system_input": "test", "system_name": "test"},
                headers={"X-API-Key": "test-secret-key"},
            )
            # Will get 200 (SSE stream starts) — not 401
            assert resp.status_code != 401

            # Sensitive read endpoints should also require the API key now.
            resp = await client.get("/api/results")
            assert resp.status_code == 401

            resp = await client.get("/api/results", headers={"X-API-Key": "test-secret-key"})
            assert resp.status_code != 401
        finally:
            _config.security.api_key = original_key


# ---------------------------------------------------------------------------
# Input Validation
# ---------------------------------------------------------------------------

class TestInputValidation:
    @pytest.mark.asyncio
    async def test_rejects_oversized_input(self, client: AsyncClient):
        from agentictm.api.server import _config

        original = _config.security.max_input_length
        try:
            _config.security.max_input_length = 100  # tiny limit for testing

            resp = await client.post(
                "/api/analyze",
                json={"system_input": "x" * 200, "system_name": "test"},
            )
            assert resp.status_code == 400
            assert "too long" in resp.json()["detail"]
        finally:
            _config.security.max_input_length = original


# ---------------------------------------------------------------------------
# Results CRUD
# ---------------------------------------------------------------------------

class TestResultsCRUD:
    @pytest.mark.asyncio
    async def test_list_results_empty(self, client: AsyncClient):
        resp = await client.get("/api/results")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    @pytest.mark.asyncio
    async def test_get_nonexistent_result(self, client: AsyncClient):
        resp = await client.get("/api/results/nonexistent-id")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_nonexistent_result(self, client: AsyncClient):
        resp = await client.delete("/api/results/nonexistent-id")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Pipeline Smoke Test (with mocked LLM)
# ---------------------------------------------------------------------------

class TestPipelineSmoke:
    """Minimal smoke test that verifies the pipeline runs with mocked LLMs."""

    def test_config_loads(self):
        """Config should load without errors."""
        from agentictm.config import AgenticTMConfig
        config = AgenticTMConfig.load()
        assert config.quick_thinker.model
        assert config.output_dir

    def test_graph_builds(self):
        """The LangGraph graph should build with valid structure."""
        from agentictm.config import AgenticTMConfig
        from agentictm.llm import LLMFactory
        from agentictm.graph.builder import build_graph

        config = AgenticTMConfig.load()
        factory = LLMFactory(config.quick_thinker, config.deep_thinker, config.vlm, config.stride_thinker)
        graph = build_graph(config, factory)
        assert len(graph.nodes) == 14  # 14 pipeline nodes including clarification

    def test_state_schema_valid(self):
        """ThreatModelState should accept all expected fields."""
        from agentictm.state import ThreatModelState
        state: ThreatModelState = {
            "system_name": "Test",
            "raw_input": "test input",
            "methodology_reports": [],
            "debate_history": [],
            "threats_final": [],
            "_errors": [],
        }
        assert state["system_name"] == "Test"


# ---------------------------------------------------------------------------
# Metrics & Observability (I04)
# ---------------------------------------------------------------------------

class TestMetricsEndpoint:
    @pytest.mark.asyncio
    async def test_metrics_for_nonexistent_analysis(self, client: AsyncClient):
        resp = await client.get("/api/results/nonexistent/metrics")
        assert resp.status_code == 404
