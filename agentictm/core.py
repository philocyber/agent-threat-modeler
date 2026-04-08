"""AgenticTM — Main entry point."""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncIterator

from agentictm.logging import set_correlation_id, PipelineFileHandler, TimingContext

from agentictm.config import AgenticTMConfig
from agentictm.llm import LLMFactory
from agentictm.memory import MemoryManager
from agentictm.rag import RAGStoreManager
from agentictm.rag.categories import resolve_categories
from agentictm.rag.tools import set_store_manager, set_active_categories
from agentictm.state import ThreatModelState

logger = logging.getLogger(__name__)


class AgenticTM:
    """Main class for running threat modeling analysis."""

    def __init__(self, config: AgenticTMConfig | None = None):
        self.config = config or AgenticTMConfig.load()

        # LLM Factory
        self.llm_factory = LLMFactory(
            quick_cfg=self.config.quick_thinker,
            deep_cfg=self.config.deep_thinker,
            vlm_cfg=self.config.vlm,
            stride_cfg=self.config.stride_thinker,
        )

        # RAG Store Manager
        try:
            self.store_manager = RAGStoreManager(
                persist_dir=self.config.rag.vector_store_path,
                embedding_model=self.config.rag.embedding_model,
                embedding_provider=self.config.rag.embedding_provider,
                base_url=self.config.quick_thinker.base_url,
                tree_index_dir=self.config.rag.page_index_path,
            )
        except Exception:
            raise

        # Use quick_thinker LLM for tree navigation at query time
        try:
            self.store_manager.set_tree_llm(self.llm_factory.quick)
        except Exception:
            raise
        set_store_manager(self.store_manager)

        # Validate that configured Ollama models actually exist before building
        # the graph. This catches model-not-found errors early with a clear message
        # instead of failing deep inside the pipeline.
        self._validate_ollama_models()

        # Memory system
        self._memory: MemoryManager | None = None
        if self.config.memory.enabled:
            try:
                self._memory = MemoryManager(self.config.memory.db_path)
                logger.info("Memory system enabled: %s", self.config.memory.db_path)
            except Exception as exc:
                logger.warning("Could not initialise memory system: %s", exc)

        # Compile the graph
        from agentictm.graph.builder import compile_graph
        try:
            self._app = compile_graph(self.config, self.llm_factory)
        except Exception:
            raise

    def _validate_ollama_models(self) -> None:
        """Check that all configured Ollama models are available.

        Queries the local Ollama server and warns (or raises) if a configured
        model does not exist, preventing cryptic 404 errors mid-pipeline.
        """
        ollama_configs = [
            ("quick_thinker", self.config.quick_thinker),
            ("deep_thinker", self.config.deep_thinker),
            ("stride_thinker", self.config.stride_thinker),
            ("vlm", self.config.vlm),
        ]

        ollama_models = {
            name: cfg.model
            for name, cfg in ollama_configs
            if cfg.provider == "ollama"
        }
        if not ollama_models:
            return

        base_url = next(
            cfg.base_url for _, cfg in ollama_configs if cfg.provider == "ollama"
        )

        try:
            import httpx
            resp = httpx.get(f"{base_url}/api/tags", timeout=10)
            resp.raise_for_status()
            available = {m["name"] for m in resp.json().get("models", [])}
        except Exception as exc:
            logger.warning(
                "Could not reach Ollama at %s to validate models: %s",
                base_url, exc,
            )
            return

        missing = {
            role: model
            for role, model in ollama_models.items()
            if model not in available
        }
        if missing:
            details = ", ".join(f"{role}={model}" for role, model in missing.items())
            available_list = ", ".join(sorted(available)) or "(none)"
            msg = (
                f"Ollama models not found: {details}. "
                f"Available models: {available_list}. "
                f"Pull missing models with: ollama pull <model>"
            )
            logger.error(msg)
            raise RuntimeError(msg)

        logger.info(
            "Ollama model validation passed: %s",
            ", ".join(f"{r}={m}" for r, m in ollama_models.items()),
        )

        # RAM vs model size warning
        ram_gb = AgenticTMConfig._detect_ram_gb()
        _model_sizes_gb = {
            "qwen3:4b": 2.7,
            "qwen3.5:9b": 6.6,
        }
        for role, model in ollama_models.items():
            size_gb = _model_sizes_gb.get(model)
            if size_gb and size_gb > ram_gb * 0.80:
                logger.warning(
                    "Model %s (%s, %.1f GB) exceeds 80%% of system RAM (%.1f GB). "
                    "Consider using a smaller model or run: python -m agentictm.diagnostics",
                    model, role, size_gb, ram_gb,
                )

    def index_knowledge_base(self, force: bool = False) -> dict[str, int]:
        """Index (or re-index) all RAG stores + PageIndex trees.

        Args:
            force: If True, re-index everything regardless of cache.
        """
        from agentictm.rag.indexer import index_all

        logger.info("Indexing RAG sources from: %s", self.config.rag.knowledge_base_path)

        # Use quick_thinker for generating tree node summaries
        tree_llm = self.llm_factory.quick if self.config.rag.tree_summaries else None

        results = index_all(
            self.store_manager,
            self.config.rag.knowledge_base_path,
            chunk_size=self.config.rag.chunk_size,
            chunk_overlap=self.config.rag.chunk_overlap,
            tree_dir=self.config.rag.page_index_path,
            llm=tree_llm,
            force=force,
        )
        # Keep in-memory tree retriever aligned with newly generated trees.
        self.store_manager.reload_trees()
        return results

    def _sync_knowledge_base_if_needed(self) -> dict[str, Any]:
        """Auto-index any new/changed RAG documents before the analysis runs.

        Performs an *incremental* index (only new/changed docs) so analysis
        always has the freshest RAG data without requiring a manual reindex.

        Returns:
            Dict with sync metadata for logging/diagnostics.
        """
        from agentictm.rag.indexer import get_index_status

        status = get_index_status(self.config.rag.knowledge_base_path)
        docs = [d for store_docs in status.values() for d in store_docs]
        has_changes = any((not d.get("indexed", False)) or d.get("changed", False) for d in docs)

        if not docs:
            logger.info("RAG sources are empty; skipping index sync.")
            return {"checked": True, "changes_detected": False, "documents": 0, "indexed_now": False}

        if not has_changes:
            logger.info("RAG sources unchanged (%d docs); using existing indices.", len(docs))
            return {"checked": True, "changes_detected": False, "documents": len(docs), "indexed_now": False}

        changed_count = sum(1 for d in docs if (not d.get("indexed", False)) or d.get("changed", False))
        indexed_count = len(docs) - changed_count
        changed_names = [
            d["name"] for d in docs
            if (not d.get("indexed", False)) or d.get("changed", False)
        ][:5]

        logger.info(
            "RAG sources: %d/%d docs indexed. Auto-indexing %d new/changed docs (%s%s)...",
            indexed_count, len(docs), changed_count,
            ", ".join(changed_names),
            "..." if changed_count > 5 else "",
        )

        try:
            results = self.index_knowledge_base(force=False)
            logger.info(
                "Auto-index completed: %s",
                {k: len(v) if isinstance(v, list) else v for k, v in results.items()} if isinstance(results, dict) else results,
            )
            return {
                "checked": True,
                "changes_detected": True,
                "documents": len(docs),
                "changed_documents": changed_count,
                "indexed_now": True,
            }
        except Exception as exc:
            logger.warning(
                "Auto-index failed (%s); analysis proceeds with existing indices.", exc,
            )
            return {
                "checked": True,
                "changes_detected": True,
                "documents": len(docs),
                "changed_documents": changed_count,
                "indexed_now": False,
            }

    def analyze(
        self,
        system_input: str,
        system_name: str = "System",
        threat_categories: list[str] | None = None,
        max_debate_rounds: int = 4,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """Run the full threat modeling analysis.

        Args:
            system_input: System description, Mermaid diagram, or path to image.
            system_name: System name for the report.
            threat_categories: Category override. None = use config.
            max_debate_rounds: Number of Red vs Blue debate rounds (3–9).

        Returns:
            dict with keys: csv_output, report_output, threats_final, and full state.
        """
        # Keep RAG indices fresh on every run (incremental; only changed docs are reindexed).
        try:
            self._sync_knowledge_base_if_needed()
        except Exception:
            raise

        # Resolve threat categories
        cats = threat_categories or self.config.pipeline.threat_categories
        resolved = resolve_categories(cats, system_input)
        set_active_categories(resolved)

        # Recall past analysis context from memory
        feedback_context = ""
        if self._memory:
            try:
                feedback_context = self._memory.recall_relevant(
                    system_name, system_input, top_k=5,
                )
            except Exception as exc:
                logger.warning("Memory recall failed: %s", exc)

        initial_state: ThreatModelState = {
            "system_name": system_name,
            "analysis_date": datetime.now().strftime("%Y-%m-%d"),
            "raw_input": system_input,
            "debate_round": 1,
            "max_debate_rounds": max(0, min(9, max_debate_rounds)),
            "iteration_count": 0,
            "methodology_reports": [],
            "debate_history": [],
            "threat_categories": resolved,
            "executive_summary": "",
            "feedback_context": feedback_context,
        }

        # Set correlation ID for structured logging
        correlation_id = correlation_id or uuid.uuid4().hex[:12]
        set_correlation_id(correlation_id)

        # Attach per-analysis JSONL file handler
        pipeline_log = PipelineFileHandler(correlation_id)
        pipeline_log.attach()

        logger.info("Starting threat model analysis for: %s (cid=%s)", system_name, correlation_id)
        logger.info("Active categories: %s", ", ".join(resolved))

        # Clear RAG query cache from previous runs
        self.store_manager.clear_cache()

        # Clear agent metrics from previous runs
        from agentictm.agents.base import clear_agent_metrics
        clear_agent_metrics()

        try:
            # Run the full graph with timing
            with TimingContext("full_pipeline", logger):
                result = self._app.invoke(initial_state)

            threats_count = len(result.get("threats_final", []))
            logger.info(
                "Analysis completed -- %d threats (cid=%s) -- log: %s",
                threats_count, correlation_id, pipeline_log.log_path,
                extra={"threats_count": threats_count},
            )

            # Persist analysis outcome in memory
            if self._memory:
                try:
                    self._memory.store_analysis_outcome(
                        system_name,
                        result.get("threats_final", []),
                        feedback=result.get("validation_result"),
                    )
                except Exception as exc:
                    logger.warning("Memory store failed: %s", exc)

            return result
        finally:
            pipeline_log.detach()

    async def analyze_stream(
        self,
        system_input: str,
        system_name: str = "System",
        threat_categories: list[str] | None = None,
        max_debate_rounds: int = 4,
        correlation_id: str | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        """Stream analysis events including token-level output.

        Yields dicts with at least a ``type`` key. Event types include:
        - ``on_chain_start`` / ``on_chain_end`` — node lifecycle
        - ``on_chat_model_stream`` — individual LLM token chunks
        - ``on_chain_stream`` — partial state updates
        """
        cats = threat_categories or self.config.pipeline.threat_categories
        resolved = resolve_categories(cats, system_input)
        set_active_categories(resolved)

        initial_state: ThreatModelState = {
            "system_name": system_name,
            "analysis_date": datetime.now().strftime("%Y-%m-%d"),
            "raw_input": system_input,
            "debate_round": 1,
            "max_debate_rounds": max(0, min(9, max_debate_rounds)),
            "iteration_count": 0,
            "methodology_reports": [],
            "debate_history": [],
            "threat_categories": resolved,
            "executive_summary": "",
        }

        correlation_id = correlation_id or uuid.uuid4().hex[:12]
        set_correlation_id(correlation_id)

        pipeline_log = PipelineFileHandler(correlation_id)
        pipeline_log.attach()

        logger.info("Starting streaming analysis for: %s (cid=%s)", system_name, correlation_id)
        self.store_manager.clear_cache()

        from agentictm.agents.base import clear_agent_metrics
        clear_agent_metrics()

        try:
            async for event in self._app.astream_events(initial_state, version="v2"):
                yield event
        finally:
            pipeline_log.detach()

    def save_output(self, result: dict, output_dir: Path | None = None) -> Path:
        """Save outputs (CSV + Markdown) to disk.

        Returns:
            Path to the output directory.
        """
        system_name = result.get("system_name", "system").replace(" ", "_").lower()
        date = result.get("analysis_date", datetime.now().strftime("%Y-%m-%d"))

        base_dir = output_dir or self.config.output_dir
        out_dir = Path(base_dir) / f"{system_name}_{date}"
        out_dir.mkdir(parents=True, exist_ok=True)

        # CSV
        csv_output = result.get("csv_output", "")
        if csv_output:
            csv_path = out_dir / "threat_model.csv"
            csv_path.write_text(csv_output, encoding="utf-8")
            logger.info("CSV saved: %s", csv_path)

        # Markdown report
        report_output = result.get("report_output", "")
        if report_output:
            report_path = out_dir / "complete_report.md"
            report_path.write_text(report_output, encoding="utf-8")
            logger.info("Report saved: %s", report_path)

        # DFD Mermaid
        mermaid_dfd = result.get("mermaid_dfd", "")
        if mermaid_dfd:
            dfd_path = out_dir / "dfd.mermaid"
            dfd_path.write_text(mermaid_dfd, encoding="utf-8")
            logger.info("DFD saved: %s", dfd_path)

        return out_dir
