"""Live inference tests — calls real Ollama models per agent and validates output.

Requires a running Ollama instance with the configured models.
Each test class isolates a single agent: builds input state, runs the agent
function with a real LLM, and asserts quality criteria on the output.

Run with:  python -m pytest tests/test_live_agents.py -v -s --timeout=600
Skip with: python -m pytest tests/ --ignore=tests/test_live_agents.py
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time

import pytest

os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

from agentictm.config import AgenticTMConfig
from agentictm.llm import create_llm, LLMFactory

# ─── Configuration ──────────────────────────────────────────────────────────
config = AgenticTMConfig()
llm_factory = LLMFactory(config)

# ─── Shared Fixtures ────────────────────────────────────────────────────────

ECOMMERCE_INPUT = (
    "E-Commerce Platform on AWS.\n\n"
    "Architecture:\n"
    "- Frontend: React SPA hosted on S3, served via CloudFront CDN\n"
    "- API: REST API behind AWS API Gateway with Lambda functions (Node.js)\n"
    "- Authentication: AWS Cognito with OAuth2/OIDC\n"
    "- Database: DynamoDB for product catalog and orders\n"
    "- Payments: Stripe integration via HTTPS API from Lambda\n"
    "- Orchestration: Step Functions for order processing workflows\n"
    "- Storage: S3 buckets for product images and user uploads\n"
    "- Monitoring: CloudWatch logs and metrics\n\n"
    "Data flows:\n"
    "- Users -> CloudFront -> API Gateway -> Lambda -> DynamoDB\n"
    "- Lambda -> Stripe API (payment processing)\n"
    "- Lambda -> S3 (file storage)\n"
    "- Step Functions orchestrate: order creation -> payment -> fulfillment\n\n"
    "Trust boundaries:\n"
    "- Internet boundary: between users/CloudFront and API Gateway\n"
    "- AWS VPC boundary: between API Gateway and internal services\n"
    "- Third-party boundary: between Lambda and Stripe API"
)

AI_AGENT_INPUT = (
    "Multi-Agent AI Threat Modeling System.\n\n"
    "Architecture:\n"
    "- Orchestrator: LangGraph-based agent orchestrator managing 6 specialized AI agents\n"
    "- LLM Backend: Ollama running local models (qwen3, qwen3.5) for inference\n"
    "- RAG Pipeline: ChromaDB vector store with document embeddings for knowledge retrieval\n"
    "- Tool Executor: Agents can call tools (search, RAG query, code analysis)\n"
    "- Web UI: FastAPI backend serving a React frontend on localhost\n"
    "- Database: SQLite for storing analysis results and session state\n"
    "- Knowledge Base: PDF documents indexed into PageIndex trees and vector embeddings\n\n"
    "Data flows:\n"
    "- User -> Web UI -> FastAPI API -> LangGraph Orchestrator\n"
    "- Orchestrator -> Ollama LLM API (inference requests)\n"
    "- Agents -> ChromaDB (RAG queries for threat knowledge)\n"
    "- Agents -> Tool Executor -> External tools\n"
    "- Results -> SQLite database -> Report Generator -> User\n\n"
    "AI/ML Components:\n"
    "- 4 LLM models running locally via Ollama\n"
    "- Embedding model for vector search\n"
    "- Multi-agent orchestration with autonomous decision-making\n"
    "- RAG pipeline with retrieval-augmented generation\n"
    "- Tool-use agents with code execution capabilities"
)


def _parsed_architecture_state(raw_input: str, system_name: str) -> dict:
    """Build a minimal state with parsed architecture (bypasses arch parser)."""
    return {
        "system_name": system_name,
        "analysis_date": "2025-01-15",
        "raw_input": raw_input,
        "input_type": "text",
        "system_description": raw_input,
        "components": [],
        "data_flows": [],
        "trust_boundaries": [],
        "external_entities": [],
        "data_stores": [],
        "scope_notes": "",
        "mermaid_dfd": "",
        "methodology_reports": [],
        "rag_context": {},
        "previous_tm_context": "",
        "threat_categories": ["base", "web"],
        "debate_history": [],
        "debate_round": 0,
        "max_debate_rounds": 0,
        "threats_final": [],
        "executive_summary": "",
        "csv_output": "",
        "report_output": "",
        "iteration_count": 0,
        "validation_result": {},
        "_errors": [],
        "feedback_context": "",
    }


def _ollama_available() -> bool:
    try:
        import urllib.request
        req = urllib.request.Request("http://localhost:11434/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception:
        return False


skip_no_ollama = pytest.mark.skipif(
    not _ollama_available(),
    reason="Ollama not running on localhost:11434",
)


def _validate_threats(threats: list[dict], *, min_count: int, agent_name: str):
    """Shared quality assertions applied to all agent outputs."""
    assert len(threats) >= min_count, \
        f"[{agent_name}] Expected >= {min_count} threats, got {len(threats)}"

    for i, t in enumerate(threats):
        desc = t.get("description", "")
        assert len(desc) >= 30, \
            f"[{agent_name}] Threat {i} description too short ({len(desc)} chars): {desc[:80]}"

        assert "|" not in desc[:50] or "table" not in desc.lower(), \
            f"[{agent_name}] Threat {i} looks like a markdown table: {desc[:100]}"

        garbage_phrases = [
            "General Description",
            "The system is a",
            "Architecture Overview",
            "Implement robust",
            "Attack Tree Construction",
            "Risk Assessment",
        ]
        for phrase in garbage_phrases:
            assert phrase not in desc, \
                f"[{agent_name}] Threat {i} contains garbage phrase '{phrase}': {desc[:100]}"

    logger.info("[%s] PASS: %d threats, all meet quality bar", agent_name, len(threats))


# ═══════════════════════════════════════════════════════════════════════════
# 1. Architecture Parser
# ═══════════════════════════════════════════════════════════════════════════

@skip_no_ollama
class TestArchitectureParserLive:

    def test_ecommerce_parsing(self):
        from agentictm.agents.architecture_parser import run_architecture_parser

        state = {
            "raw_input": ECOMMERCE_INPUT,
            "input_type": "text",
            "threat_categories": ["base", "web", "aws"],
            "methodology_reports": [],
            "_errors": [],
        }
        t0 = time.perf_counter()
        result = run_architecture_parser(state, llm=llm_factory.deep, vlm=llm_factory.vlm)
        elapsed = time.perf_counter() - t0
        logger.info("[ArchParser] Completed in %.1fs", elapsed)

        assert result.get("system_description"), "Missing system_description"
        assert len(result.get("system_description", "")) > 50, "system_description too short"

        components = result.get("components", [])
        assert len(components) >= 3, f"Expected >= 3 components, got {len(components)}"
        for c in components:
            assert c.get("name"), f"Component missing name: {c}"

        data_flows = result.get("data_flows", [])
        assert len(data_flows) >= 2, f"Expected >= 2 data_flows, got {len(data_flows)}"

        logger.info("[ArchParser] PASS: %d components, %d data_flows",
                    len(components), len(data_flows))

        self.__class__._result = result

    def test_ai_system_parsing(self):
        from agentictm.agents.architecture_parser import run_architecture_parser

        state = {
            "raw_input": AI_AGENT_INPUT,
            "input_type": "text",
            "threat_categories": ["base", "web", "ai"],
            "methodology_reports": [],
            "_errors": [],
        }
        t0 = time.perf_counter()
        result = run_architecture_parser(state, llm=llm_factory.deep, vlm=llm_factory.vlm)
        elapsed = time.perf_counter() - t0
        logger.info("[ArchParser-AI] Completed in %.1fs", elapsed)

        components = result.get("components", [])
        assert len(components) >= 3, f"Expected >= 3 components, got {len(components)}"

        comp_names = " ".join(c.get("name", "").lower() for c in components)
        ai_keywords = ["llm", "ai", "agent", "orchestrat", "rag", "vector", "embedding", "ollama", "chroma"]
        found_ai = any(kw in comp_names for kw in ai_keywords)
        assert found_ai, f"No AI-related components found in: {comp_names}"

        logger.info("[ArchParser-AI] PASS: %d components (AI components detected)", len(components))


# ═══════════════════════════════════════════════════════════════════════════
# 2. STRIDE Analyst
# ═══════════════════════════════════════════════════════════════════════════

@skip_no_ollama
class TestStrideAnalystLive:

    def test_ecommerce_stride(self):
        from agentictm.agents.stride_analyst import run_stride_analyst

        state = _parsed_architecture_state(ECOMMERCE_INPUT, "E-Commerce Platform")
        t0 = time.perf_counter()
        result = run_stride_analyst(state, llm=llm_factory.stride)
        elapsed = time.perf_counter() - t0
        logger.info("[STRIDE] Completed in %.1fs", elapsed)

        reports = result.get("methodology_reports", [])
        assert len(reports) == 1
        assert reports[0]["methodology"] == "STRIDE"

        threats = reports[0].get("threats_raw", [])
        _validate_threats(threats, min_count=3, agent_name="STRIDE")

        stride_cats = {t.get("stride_category", "") for t in threats}
        valid_stride = {"S", "T", "R", "I", "D", "E"}
        has_stride = any(s in valid_stride for s in stride_cats)
        assert has_stride, f"No valid STRIDE categories found: {stride_cats}"

        self.__class__._threats = threats


# ═══════════════════════════════════════════════════════════════════════════
# 3. PASTA Analyst
# ═══════════════════════════════════════════════════════════════════════════

@skip_no_ollama
class TestPastaAnalystLive:

    def test_ecommerce_pasta(self):
        from agentictm.agents.pasta_analyst import run_pasta_analyst

        state = _parsed_architecture_state(ECOMMERCE_INPUT, "E-Commerce Platform")
        t0 = time.perf_counter()
        result = run_pasta_analyst(state, llm=llm_factory.quick)
        elapsed = time.perf_counter() - t0
        logger.info("[PASTA] Completed in %.1fs", elapsed)

        reports = result.get("methodology_reports", [])
        assert len(reports) == 1
        assert reports[0]["methodology"] == "PASTA"

        threats = reports[0].get("threats_raw", [])
        _validate_threats(threats, min_count=1, agent_name="PASTA")

        self.__class__._threats = threats


# ═══════════════════════════════════════════════════════════════════════════
# 4. Attack Tree Analyst
# ═══════════════════════════════════════════════════════════════════════════

@skip_no_ollama
class TestAttackTreeAnalystLive:

    def test_ecommerce_attack_tree(self):
        from agentictm.agents.attack_tree_analyst import run_attack_tree_analyst

        state = _parsed_architecture_state(ECOMMERCE_INPUT, "E-Commerce Platform")
        t0 = time.perf_counter()
        result = run_attack_tree_analyst(state, llm=llm_factory.quick)
        elapsed = time.perf_counter() - t0
        logger.info("[AttackTree] Completed in %.1fs", elapsed)

        reports = result.get("methodology_reports", [])
        assert len(reports) == 1
        assert reports[0]["methodology"] == "ATTACK_TREE"

        threats = reports[0].get("threats_raw", [])
        _validate_threats(threats, min_count=1, agent_name="ATTACK_TREE")

        self.__class__._threats = threats


# ═══════════════════════════════════════════════════════════════════════════
# 5. MAESTRO Analyst (AI scenario)
# ═══════════════════════════════════════════════════════════════════════════

@skip_no_ollama
class TestMaestroAnalystLive:

    def test_ai_system_maestro(self):
        from agentictm.agents.maestro_analyst import run_maestro_analyst

        state = _parsed_architecture_state(AI_AGENT_INPUT, "AI Agent System")
        state["threat_categories"] = ["base", "ai"]
        t0 = time.perf_counter()
        result = run_maestro_analyst(state, llm=llm_factory.quick)
        elapsed = time.perf_counter() - t0
        logger.info("[MAESTRO] Completed in %.1fs", elapsed)

        reports = result.get("methodology_reports", [])
        assert len(reports) == 1
        assert reports[0]["methodology"] == "MAESTRO"

        threats = reports[0].get("threats_raw", [])
        if any("not applicable" in t.get("description", "").lower() for t in threats):
            pytest.skip("MAESTRO returned N/A (no AI components detected)")

        _validate_threats(threats, min_count=1, agent_name="MAESTRO")

        self.__class__._threats = threats


# ═══════════════════════════════════════════════════════════════════════════
# 6. AI Threat Analyst (AI scenario)
# ═══════════════════════════════════════════════════════════════════════════

@skip_no_ollama
class TestAiThreatAnalystLive:

    def test_ai_system_threat_analysis(self):
        from agentictm.agents.ai_threat_analyst import run_ai_threat_analyst

        state = _parsed_architecture_state(AI_AGENT_INPUT, "AI Agent System")
        state["threat_categories"] = ["base", "ai"]
        t0 = time.perf_counter()
        result = run_ai_threat_analyst(state, llm=llm_factory.quick)
        elapsed = time.perf_counter() - t0
        logger.info("[AiThreat] Completed in %.1fs", elapsed)

        reports = result.get("methodology_reports", [])
        assert len(reports) == 1
        assert reports[0]["methodology"] == "AI_THREAT_ANALYSIS"

        threats = reports[0].get("threats_raw", [])
        if any("not applicable" in t.get("description", "").lower() for t in threats):
            pytest.skip("AI Threat returned N/A")

        _validate_threats(threats, min_count=1, agent_name="AI_THREAT")

        self.__class__._threats = threats


# ═══════════════════════════════════════════════════════════════════════════
# 7. Threat Synthesizer (using real STRIDE + PASTA output)
# ═══════════════════════════════════════════════════════════════════════════

@skip_no_ollama
class TestThreatSynthesizerLive:

    def test_synthesizer_with_real_methodology_input(self):
        """Run STRIDE + PASTA live, then feed their output to Synthesizer."""
        from agentictm.agents.stride_analyst import run_stride_analyst
        from agentictm.agents.pasta_analyst import run_pasta_analyst
        from agentictm.agents.threat_synthesizer import run_threat_synthesizer

        state = _parsed_architecture_state(ECOMMERCE_INPUT, "E-Commerce Platform")

        logger.info("[Synth] Running STRIDE analyst...")
        stride_result = run_stride_analyst(state, llm=llm_factory.stride)

        logger.info("[Synth] Running PASTA analyst...")
        pasta_result = run_pasta_analyst(state, llm=llm_factory.quick)

        state["methodology_reports"] = (
            stride_result.get("methodology_reports", [])
            + pasta_result.get("methodology_reports", [])
        )

        stride_count = len(stride_result.get("methodology_reports", [{}])[0].get("threats_raw", []))
        pasta_count = len(pasta_result.get("methodology_reports", [{}])[0].get("threats_raw", []))
        logger.info("[Synth] Input: STRIDE=%d threats, PASTA=%d threats", stride_count, pasta_count)

        logger.info("[Synth] Running Threat Synthesizer...")
        t0 = time.perf_counter()
        synth_result = run_threat_synthesizer(state, llm=llm_factory.deep_json, config=config)
        elapsed = time.perf_counter() - t0
        logger.info("[Synth] Completed in %.1fs", elapsed)

        threats = synth_result.get("threats_final", [])
        assert len(threats) >= 3, f"Expected >= 3 synthesized threats, got {len(threats)}"

        for t in threats:
            assert t.get("id"), f"Threat missing ID: {t.get('description', '')[:60]}"
            assert t["id"].count("-") >= 1, f"Malformed ID: {t['id']}"

            stride = t.get("stride_category", "")
            assert stride in {"S", "T", "R", "I", "D", "E"}, \
                f"{t['id']} missing STRIDE category: '{stride}'"

            assert (t.get("component") or "").strip(), f"{t['id']} has no component"
            assert len(t.get("description", "")) >= 50, \
                f"{t['id']} description too short: {t.get('description', '')[:60]}"
            assert (t.get("mitigation") or "").strip(), f"{t['id']} has no mitigation"
            assert t.get("priority") in {"Critical", "High", "Medium", "Low"}, \
                f"{t['id']} invalid priority: {t.get('priority')}"
            assert 5 <= t.get("dread_total", 0) <= 50, \
                f"{t['id']} invalid dread_total: {t.get('dread_total')}"

        ids = [t["id"] for t in threats]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {ids}"

        prefixes = {t["id"].split("-")[0] for t in threats}
        assert "TM" not in prefixes, f"Found TM- prefix in IDs: {ids}"

        logger.info("[Synth] PASS: %d threats, all pass quality contract. IDs: %s",
                    len(threats), ", ".join(ids))

        self.__class__._threats = threats


# ═══════════════════════════════════════════════════════════════════════════
# 8. DREAD Validator
# ═══════════════════════════════════════════════════════════════════════════

@skip_no_ollama
class TestDreadValidatorLive:

    def test_dread_validation_on_synthesized_threats(self):
        """Feed Synthesizer output to DREAD Validator and verify corrections."""
        from agentictm.agents.stride_analyst import run_stride_analyst
        from agentictm.agents.threat_synthesizer import run_threat_synthesizer
        from agentictm.agents.dread_validator import run_dread_validator

        state = _parsed_architecture_state(ECOMMERCE_INPUT, "E-Commerce Platform")

        logger.info("[DREAD] Running STRIDE analyst...")
        stride_result = run_stride_analyst(state, llm=llm_factory.stride)
        state["methodology_reports"] = stride_result.get("methodology_reports", [])

        logger.info("[DREAD] Running Synthesizer...")
        synth_result = run_threat_synthesizer(state, llm=llm_factory.deep_json, config=config)
        state["threats_final"] = synth_result.get("threats_final", [])

        pre_count = len(state["threats_final"])
        assert pre_count >= 1, "Synthesizer produced 0 threats"

        logger.info("[DREAD] Running DREAD Validator on %d threats...", pre_count)
        t0 = time.perf_counter()
        dread_result = run_dread_validator(state, llm=llm_factory.deep_json)
        elapsed = time.perf_counter() - t0
        logger.info("[DREAD] Completed in %.1fs", elapsed)

        threats = dread_result.get("threats_final", state["threats_final"])
        assert len(threats) >= 1

        for t in threats:
            for dim in ("damage", "reproducibility", "exploitability", "affected_users", "discoverability"):
                val = t.get(dim, 0)
                assert 1 <= val <= 10, f"{t.get('id')} {dim}={val} out of range"

            total = t.get("dread_total", 0)
            expected = sum(t.get(d, 0) for d in
                          ("damage", "reproducibility", "exploitability", "affected_users", "discoverability"))
            assert total == expected, f"{t.get('id')} dread_total={total}, expected={expected}"

            assert t.get("stride_category") in {"S", "T", "R", "I", "D", "E"}, \
                f"{t.get('id')} has empty STRIDE after DREAD validation"

        logger.info("[DREAD] PASS: %d threats, all DREAD scores valid", len(threats))


# ═══════════════════════════════════════════════════════════════════════════
# 9. Full E2E Pipeline (all agents)
# ═══════════════════════════════════════════════════════════════════════════

@skip_no_ollama
class TestFullPipelineLive:
    """Full pipeline: analysts → synthesizer → report.

    Runs STRIDE + PASTA with real LLMs, feeds output to the Synthesizer
    (qwen3.5:9b via deep_json), then validates the quality contract on the final output.
    Skips ArchParser (tested separately) and DREAD (tested separately) to
    keep runtime under 15 min.
    """

    @pytest.mark.timeout(1200)
    def test_ecommerce_full_pipeline(self):
        from agentictm.agents.stride_analyst import run_stride_analyst
        from agentictm.agents.pasta_analyst import run_pasta_analyst
        from agentictm.agents.attack_tree_analyst import run_attack_tree_analyst
        from agentictm.agents.threat_synthesizer import run_threat_synthesizer
        from agentictm.agents.report_generator import generate_csv, generate_markdown_report

        state = _parsed_architecture_state(ECOMMERCE_INPUT, "E-Commerce Platform")
        t0_total = time.perf_counter()

        # Phase 1: Methodology Analysts
        logger.info("=" * 70)
        logger.info("[E2E] Phase 1: STRIDE Analyst")
        stride_result = run_stride_analyst(state, llm=llm_factory.stride)
        stride_threats = stride_result["methodology_reports"][0].get("threats_raw", [])
        logger.info("[E2E] STRIDE: %d threats", len(stride_threats))

        logger.info("[E2E] Phase 1: PASTA Analyst")
        pasta_result = run_pasta_analyst(state, llm=llm_factory.quick)
        pasta_threats = pasta_result["methodology_reports"][0].get("threats_raw", [])
        logger.info("[E2E] PASTA: %d threats", len(pasta_threats))

        logger.info("[E2E] Phase 1: Attack Tree Analyst")
        at_result = run_attack_tree_analyst(state, llm=llm_factory.quick)
        at_threats = at_result["methodology_reports"][0].get("threats_raw", [])
        logger.info("[E2E] AttackTree: %d threats", len(at_threats))

        state["methodology_reports"] = (
            stride_result.get("methodology_reports", [])
            + pasta_result.get("methodology_reports", [])
            + at_result.get("methodology_reports", [])
        )

        total_raw = len(stride_threats) + len(pasta_threats) + len(at_threats)
        assert total_raw >= 3, f"Only {total_raw} raw threats across all analysts"

        # Phase 2: Threat Synthesizer
        logger.info("=" * 70)
        logger.info("[E2E] Phase 2: Threat Synthesizer (qwen3.5:9b)")
        synth_result = run_threat_synthesizer(state, llm=llm_factory.deep_json, config=config)
        state.update(synth_result)
        threats_final = state.get("threats_final", [])
        logger.info("[E2E] Synthesizer: %d threats", len(threats_final))

        # Phase 3: Report Generation (no LLM call)
        logger.info("=" * 70)
        logger.info("[E2E] Phase 3: Report Generation")
        csv_output = generate_csv(state)
        md_output = generate_markdown_report(state)
        elapsed_total = time.perf_counter() - t0_total
        logger.info("[E2E] Reports generated. Total time: %.1fs", elapsed_total)

        # ── Quality Contract ────────────────────────────────────────────
        logger.info("=" * 70)
        logger.info("[E2E] QUALITY VALIDATION")

        assert len(threats_final) >= 3, \
            f"Final threat count {len(threats_final)} is below minimum"

        valid_prefixes = {"WEB", "INF", "PRI", "LLM", "HUM", "GEN", "AGT"}
        for t in threats_final:
            prefix = t["id"].split("-")[0]
            assert prefix in valid_prefixes, \
                f"Invalid ID prefix '{prefix}' on {t['id']}: {t['description'][:50]}"

        for t in threats_final:
            assert t.get("stride_category") in {"S", "T", "R", "I", "D", "E"}, \
                f"{t['id']} missing STRIDE: '{t.get('stride_category')}'"

        for t in threats_final:
            assert (t.get("component") or "").strip(), f"{t['id']} empty component"
            assert len(t.get("description", "")) >= 50, f"{t['id']} description too short"
            assert (t.get("mitigation") or "").strip(), f"{t['id']} empty mitigation"
            assert t.get("priority") in {"Critical", "High", "Medium", "Low"}, \
                f"{t['id']} bad priority: {t.get('priority')}"

        for t in threats_final:
            for dim in ("damage", "reproducibility", "exploitability", "affected_users", "discoverability"):
                assert 1 <= t.get(dim, 0) <= 10, f"{t['id']} {dim}={t.get(dim)} OOB"

        ids = [t["id"] for t in threats_final]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {[x for x in ids if ids.count(x) > 1]}"

        stride_cats = {t["stride_category"] for t in threats_final}
        assert len(stride_cats) >= 2, f"Only {len(stride_cats)} STRIDE categories: {stride_cats}"

        assert len(csv_output) > 200, f"CSV too short: {len(csv_output)} chars"
        assert len(md_output) > 500, f"Markdown too short: {len(md_output)} chars"

        # ── Summary ─────────────────────────────────────────────────────
        logger.info("-" * 70)
        logger.info("[E2E] RESULTS SUMMARY")
        logger.info("  Raw threats:      STRIDE=%d  PASTA=%d  AT=%d  Total=%d",
                    len(stride_threats), len(pasta_threats), len(at_threats), total_raw)
        logger.info("  Final threats:    %d", len(threats_final))
        logger.info("  STRIDE coverage:  %s", stride_cats)
        logger.info("  ID prefixes:      %s", {t['id'].split('-')[0] for t in threats_final})
        logger.info("  Total time:       %.1fs", elapsed_total)
        logger.info("-" * 70)
        for t in threats_final:
            logger.info("  %s [%s] %s — %s",
                        t["id"], t["stride_category"], t["priority"],
                        t["description"][:80])
        logger.info("=" * 70)
        logger.info("[E2E] ALL CHECKS PASSED")
