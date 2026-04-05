"""Configuración global de AgenticTM."""

from __future__ import annotations

import logging
import os
import platform
import subprocess
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

_config_logger = logging.getLogger(__name__)


class LLMConfig(BaseModel):
    """Configuración de un proveedor LLM.

    Modelos recomendados para Ollama (16 GB RAM):
    ┌────────────────┬────────────────────────────┬───────┬──────────────────────────────────┐
    │ Rol            │ Modelo                     │  VRAM │ Notas                            │
    ├────────────────┼────────────────────────────┼───────┼──────────────────────────────────┤
    │ quick_thinker  │ qwen3:4b                   │ ~2.7GB│ Fast analysts (PASTA/AT/MAESTRO) │
    │ deep_thinker   │ qwen3.5:9b                 │ ~6.6GB│ Synthesizer (32K ctx, temp=0.2)  │
    │ stride_thinker │ qwen3.5:9b                 │ ~6.6GB│ STRIDE/debate (structured)       │
    │ vlm            │ qwen3.5:9b                 │ ~6.6GB│ Native multimodal (text+image)   │
    └────────────────┴────────────────────────────┴───────┴──────────────────────────────────┘

    Qwen3.5:9b supports 256K context, native text+image input, and structured JSON.
    Shared model between deep/stride/vlm — zero swap overhead, fits 100% in GPU.
    """

    provider: str = "ollama"
    model: str = "qwen3.5:9b"
    temperature: float = 0.3
    base_url: str = "http://localhost:11434"
    api_key: str | None = None
    timeout: int = 300  # seconds — Ollama HTTP client timeout
    format: str | None = None  # "json" to force structured JSON output
    num_gpu: int | None = None  # Ollama GPU layers (None = auto, -1 = all GPU, 0 = all CPU)
    num_ctx: int | None = None  # Context window size (None = model default; lower = less VRAM for KV cache)
    num_predict: int | None = None  # Max tokens to generate (None = no limit; prevents runaway generation)
    think: bool | None = None  # Enable/disable thinking mode (None = model default; False = /nothink suffix)
    vlm_image_timeout: int = 600  # per-image VLM timeout in seconds (0 = no limit)
    max_retries: int = 3  # max retries for cloud API calls (reduces compounding wait on timeout)


class RAGConfig(BaseModel):
    """Configuración del sistema RAG."""

    knowledge_base_path: Path = Path("./knowledge_base")
    vector_store_path: Path = Path("./data/vector_stores")
    page_index_path: Path = Path("./data/page_indices")  # PageIndex tree JSON files
    embedding_provider: str = "ollama"
    embedding_model: str = "nomic-embed-text-v2-moe"
    chunk_size: int = 1000
    chunk_overlap: int = 200
    retrieval_top_k: int = 5
    tree_summaries: bool = True     # generate LLM summaries for tree nodes
    max_summary_nodes: int = 50     # max nodes to summarize per PDF


class PipelineConfig(BaseModel):
    """Configuración del pipeline de análisis."""

    max_debate_rounds: int = 4  # max rounds; debate can end early via convergence
    max_validation_iterations: int = 2
    enable_maestro: bool = True  # Solo se activa si el sistema tiene componentes AI
    output_format: str = "both"  # "csv" | "markdown" | "both"
    output_language: str = "es"
    csv_schema: str = "auto"  # "auto" (detectar de previos) | "default"

    # Self-reflection: agents critique + revise their own output (improves quality)
    self_reflection_enabled: bool = False
    self_reflection_rounds: int = 1  # number of critique→revise cycles (0 = disabled)

    # Configurable threat count targets (I13)
    min_threats: int = 8      # minimum threats expected from synthesizer
    max_threats: int = 40     # maximum threats before dedup is aggressive
    target_threats: int = 20  # ideal target for synthesizer prompt

    # Threat categories to activate (filters risks_mitigations RAG context)
    # Available: "base", "aws", "azure", "gcp", "ai", "mobile", "web", "iot",
    #            "privacy", "memory", "supply_chain"
    # "base" is always included. Use ["auto"] to auto-detect from input.
    threat_categories: list[str] = Field(
        default=["auto"],
        description="Threat categories to include in analysis",
    )

    # ── Analyst Execution Mode ──────────────────────────────────────────────
    # Controls how the 5 methodology analysts (STRIDE, PASTA, Attack Tree,
    # MAESTRO, AI Threat) are scheduled against local GPU/CPU resources.
    #
    #   "parallel"  — All 5 dispatched concurrently (LangGraph fan-out).
    #                 max_parallel_analysts limits simultaneous LLM loads.
    #                 Best coverage; bad if VRAM < sum of all models at once.
    #
    #   "cascade"   — Analysts run sequentially: STRIDE → PASTA → Attack Tree
    #                 → MAESTRO → AI Threat. Each analyst sees the accumulated
    #                 state of all previous, enabling context inheritance.
    #                 Lower diversity (bias-drag risk), but minimal peak VRAM.
    #
    #   "hybrid"    — (RECOMMENDED) Analysts run in parallel but throttled to
    #                 max_parallel_analysts slots via a threading semaphore.
    #                 Preserves independent thinking while capping peak memory.
    #                 With max=2: no more than 2 LLMs active simultaneously.
    #
    analyst_execution_mode: str = Field(
        default="hybrid",
        description="How analysts execute: 'parallel' | 'cascade' | 'hybrid'",
    )

    # Maximum concurrent analyst LLM calls (applies to "parallel" and "hybrid").
    # On a single GPU with 16-32 GB VRAM, 2 keeps quality high without OOM.
    max_parallel_analysts: int = Field(
        default=2,
        description="Max simultaneous analyst LLM calls (1-5)",
        ge=1,
        le=5,
    )

    # ── Fast-mode phase skip flags ───────────────────────────────────────────
    # Which methodology analysts to run. Valid names:
    #   "stride", "pasta", "attack_tree", "maestro", "ai_threat"
    enabled_analysts: list[str] = Field(
        default_factory=lambda: ["stride", "pasta", "attack_tree", "maestro", "ai_threat"],
        description="Analysts to execute (others become instant pass-through)",
    )

    skip_debate: bool = Field(
        default=False,
        description="Skip Red/Blue Team debate entirely (pass-through nodes)",
    )
    skip_enriched_attack_tree: bool = Field(
        default=False,
        description="Skip the post-debate enriched Attack Tree pass",
    )
    skip_dread_validator: bool = Field(
        default=False,
        description="Skip DREAD score validation/correction step",
    )
    skip_output_localizer: bool = Field(
        default=False,
        description="Skip output translation (keeps original language)",
    )


class MemoryConfig(BaseModel):
    """Configuración de memoria persistente."""

    enabled: bool = True
    db_path: Path = Path("./data/memory.db")
    journal_path: Path = Path("./data/journal.db")


class SecurityConfig(BaseModel):
    """Security configuration for the API server."""

    # API key authentication (MVP). Set to None or "" to disable auth.
    api_key: str | None = None

    # Input validation
    max_input_length: int = 100_000  # max characters for system description
    max_upload_size_mb: int = 10     # max file upload size in MB

    # Allowed file extensions for uploads
    allowed_extensions: list[str] = Field(default_factory=lambda: [
        ".txt", ".md", ".pdf", ".doc", ".docx", ".csv", ".json",
        ".yaml", ".yml", ".png", ".jpg", ".jpeg", ".gif",
        ".bmp", ".webp", ".svg", ".tiff",
    ])


class AgenticTMConfig(BaseModel):
    """Configuración completa de AgenticTM."""

    # LLM configs
    quick_thinker: LLMConfig = Field(
        default_factory=lambda: LLMConfig(
            model="qwen3:4b",
            num_ctx=16384,  # qwen3 supports 128K; 16K suffices for analyst prompts
            think=False,  # nothink -> faster, cleaner JSON, forces RAG pre-invoke
        )
    )
    deep_thinker: LLMConfig = Field(
        default_factory=lambda: LLMConfig(
            model="qwen3.5:9b",
            temperature=0.2,
            timeout=600,
            num_gpu=-1,
            num_ctx=16384,  # 16K keeps KV cache small → 100% GPU on 8GB VRAM
            think=False,  # nothink → faster, cleaner JSON output
        )
    )
    stride_thinker: LLMConfig = Field(
        default_factory=lambda: LLMConfig(
            model="qwen3.5:9b",
            temperature=0.3,
            timeout=600,
            num_gpu=-1,
            num_ctx=16384,  # 16K keeps KV cache small → 100% GPU on 8GB VRAM
            think=False,  # nothink → faster, forces RAG pre-invoke
        )
    )
    vlm: LLMConfig = Field(
        default_factory=lambda: LLMConfig(
            model="qwen3.5:9b",
            temperature=0.1,
            timeout=600,
            vlm_image_timeout=300,  # 5 min is enough; falls back to text-only
            num_gpu=-1,
        )
    )

    # Sub-configs
    rag: RAGConfig = Field(default_factory=RAGConfig)
    pipeline: PipelineConfig = Field(default_factory=PipelineConfig)
    memory: MemoryConfig = Field(default_factory=MemoryConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)

    # Output
    output_dir: Path = Path("./output")

    @classmethod
    def for_hardware(cls) -> "AgenticTMConfig":
        """Auto-detect system RAM and return config defaults sized for this machine.

        | RAM      | deep_thinker  | stride_thinker | quick_thinker | vlm          |
        |----------|---------------|----------------|---------------|--------------|
        | <=16 GB  | qwen3:4b      | qwen3:4b       | qwen3:4b      | qwen3:4b     |
        | 16-32 GB | qwen3.5:9b    | qwen3.5:9b     | qwen3:4b      | qwen3.5:9b   |
        | 32-64 GB | qwen3.5:9b    | qwen3.5:9b     | qwen3:4b      | qwen3.5:9b   |
        | 64+ GB   | qwen3.5:9b    | qwen3.5:9b     | qwen3:4b      | qwen3.5:9b   |
        """
        ram_gb = cls._detect_ram_gb()
        _config_logger.info("Detected system RAM: %.1f GB -- selecting model profile", ram_gb)

        if ram_gb <= 16:
            profile = ("qwen3:4b", "qwen3:4b", "qwen3:4b", "qwen3:4b")
        elif ram_gb <= 32:
            profile = ("qwen3.5:9b", "qwen3.5:9b", "qwen3:4b", "qwen3.5:9b")
        elif ram_gb <= 64:
            profile = ("qwen3.5:9b", "qwen3.5:9b", "qwen3:4b", "qwen3.5:9b")
        else:
            profile = ("qwen3.5:9b", "qwen3.5:9b", "qwen3:4b", "qwen3.5:9b")

        deep_model, stride_model, quick_model, vlm_model = profile
        _config_logger.info(
            "Hardware profile: deep=%s, stride=%s, quick=%s, vlm=%s",
            deep_model, stride_model, quick_model, vlm_model,
        )

        return cls(
            quick_thinker=LLMConfig(model=quick_model, think=False),
            deep_thinker=LLMConfig(model=deep_model, temperature=0.2, timeout=600, num_gpu=-1, think=False),
            stride_thinker=LLMConfig(model=stride_model, temperature=0.3, timeout=600, num_gpu=-1, think=False),
            vlm=LLMConfig(model=vlm_model, temperature=0.1, timeout=600, vlm_image_timeout=300, num_gpu=-1),
        )

    @staticmethod
    def _detect_ram_gb() -> float:
        """Detect total system RAM in GB. Returns 16.0 as safe fallback."""
        try:
            system = platform.system()
            if system == "Darwin":
                out = subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True)
                return int(out.strip()) / (1024 ** 3)
            elif system == "Linux":
                with open("/proc/meminfo") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            return int(line.split()[1]) * 1024 / (1024 ** 3)
        except Exception:
            pass
        return 16.0

    @classmethod
    def load(cls, path: Path | None = None) -> "AgenticTMConfig":
        """Carga configuración desde archivo JSON, con env-var overrides.

        When config.json is absent (first run), uses ``for_hardware()`` to
        auto-detect appropriate model sizes for this machine's RAM.

        Environment variable overrides (take precedence over config.json):
            AGENTICTM_API_KEY          → security.api_key
            AGENTICTM_OLLAMA_URL       → base_url for all Ollama LLMs
            AGENTICTM_OUTPUT_DIR       → output_dir
            AGENTICTM_MAX_INPUT_LENGTH → security.max_input_length
            AGENTICTM_MAX_UPLOAD_MB    → security.max_upload_size_mb
        """
        if path is None:
            path = Path("config.json")
        if path and path.exists():
            import json

            data = json.loads(path.read_text(encoding="utf-8"))
            config = cls.model_validate(data)
        else:
            config = cls.for_hardware()

        # --- Environment variable overrides ---
        if env_key := os.environ.get("AGENTICTM_API_KEY"):
            config.security.api_key = env_key
        if env_url := os.environ.get("AGENTICTM_OLLAMA_URL"):
            for llm_cfg in (config.quick_thinker, config.deep_thinker, config.stride_thinker, config.vlm):
                llm_cfg.base_url = env_url
        if env_out := os.environ.get("AGENTICTM_OUTPUT_DIR"):
            config.output_dir = Path(env_out)
        if env_max_input := os.environ.get("AGENTICTM_MAX_INPUT_LENGTH"):
            try:
                config.security.max_input_length = int(env_max_input)
            except ValueError:
                pass
        if env_max_upload := os.environ.get("AGENTICTM_MAX_UPLOAD_MB"):
            try:
                config.security.max_upload_size_mb = int(env_max_upload)
            except ValueError:
                pass

        # --- AGENTICTM_DATA_DIR: redirect all writable data paths (packaged app) ---
        if env_data_dir := os.environ.get("AGENTICTM_DATA_DIR"):
            data_base = Path(env_data_dir)
            config.rag.vector_store_path = data_base / "vector_stores"
            config.rag.page_index_path = data_base / "page_indices"
            config.memory.db_path = data_base / "memory.db"
            config.memory.journal_path = data_base / "journal.db"
            if not os.environ.get("AGENTICTM_OUTPUT_DIR"):
                config.output_dir = data_base / "output"
        if env_kb_dir := os.environ.get("AGENTICTM_KB_DIR"):
            config.rag.knowledge_base_path = Path(env_kb_dir)

        return config

    def save(self, path: Path) -> None:
        """Guarda la configuración actual a disco."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            self.model_dump_json(indent=2), encoding="utf-8"
        )

    def validate_startup(self) -> list[str]:
        """Validate configuration at startup. Returns list of warnings.

        Raises ValueError for critical misconfigurations.
        """
        import logging as _logging
        _logger = _logging.getLogger(__name__)
        warnings: list[str] = []

        # -- Check paths --
        for label, path in [
            ("knowledge_base_path", self.rag.knowledge_base_path),
            ("vector_store_path", self.rag.vector_store_path),
            ("output_dir", self.output_dir),
        ]:
            p = Path(path)
            if not p.exists():
                p.mkdir(parents=True, exist_ok=True)
                _logger.info("  Created directory: %s", p)

        if self.rag.page_index_path:
            p = Path(self.rag.page_index_path)
            if not p.exists():
                p.mkdir(parents=True, exist_ok=True)
                _logger.info("  Created page_index directory: %s", p)

        # -- Check Ollama connectivity --
        ollama_url = self.quick_thinker.base_url
        if self.quick_thinker.provider == "ollama":
            try:
                import urllib.request
                req = urllib.request.Request(f"{ollama_url}/api/tags", method="GET")
                with urllib.request.urlopen(req, timeout=5) as resp:
                    if resp.status == 200:
                        import json as _json
                        data = _json.loads(resp.read())
                        available_models = {m["name"] for m in data.get("models", [])}
                        _logger.info("  [OK] Ollama connected at %s (%d models available)", ollama_url, len(available_models))

                        # Check each configured model
                        for role, cfg in [
                            ("quick_thinker", self.quick_thinker),
                            ("deep_thinker", self.deep_thinker),
                            ("stride_thinker", self.stride_thinker),
                            ("vlm", self.vlm),
                        ]:
                            model_name = cfg.model
                            # Ollama model names may or may not include ":latest"
                            found = (
                                model_name in available_models
                                or f"{model_name}:latest" in available_models
                                or any(m.startswith(model_name.split(":")[0] + ":") for m in available_models)
                            )
                            if found:
                                _logger.info("    [OK] %s: %s", role, model_name)
                            else:
                                warnings.append(f"Model '{model_name}' ({role}) not found in Ollama. Available: {', '.join(sorted(available_models)[:10])}")
                                _logger.warning("    [MISS] %s: %s NOT FOUND", role, model_name)
                    else:
                        warnings.append(f"Ollama returned status {resp.status}")
            except Exception as e:
                warnings.append(f"Cannot connect to Ollama at {ollama_url}: {e}")
                _logger.warning("  [FAIL] Ollama not reachable at %s: %s", ollama_url, e)

        # -- Check security --
        if not self.security.api_key:
            warnings.append("No API key configured (security.api_key). API endpoints are unprotected.")
            _logger.warning("  [!] No API key configured -- endpoints are unprotected")

        # -- Check vector stores --
        vs_path = Path(self.rag.vector_store_path)
        if vs_path.exists():
            stores = [d.name for d in vs_path.iterdir() if d.is_dir()]
            _logger.info("  [OK] %d vector stores found", len(stores))
        else:
            _logger.info("  ○ No vector stores yet (run index_knowledge_base)")

        # -- Check tree indices --
        tree_path = Path(self.rag.page_index_path) if self.rag.page_index_path else None
        if tree_path and tree_path.exists():
            trees = list(tree_path.glob("*.json"))
            _logger.info("  [OK] %d tree indices found", len(trees))
        else:
            _logger.info("  ○ No tree indices yet")

        return warnings
