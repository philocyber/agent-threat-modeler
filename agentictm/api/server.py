"""AgenticTM FastAPI Backend — SSE streaming + file upload.

Endpoints:
  POST /api/analyze        — Inicia análisis (SSE stream)
  POST /api/upload         — Upload de archivos
  GET  /api/categories     — Lista categorías disponibles
  GET  /api/health         — Health check
  GET  /api/ready          — Readiness probe (Ollama + stores)
  GET  /api/results/{id}   — Obtiene resultado completo
"""

from __future__ import annotations

import asyncio
import csv
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import time
import unicodedata
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from agentictm import __version__
from agentictm.config import AgenticTMConfig
from agentictm.api.storage import ResultStore
from agentictm.api.security import check_prompt_injection, get_analysis_limiter

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lifespan — ensures the server releases its socket and cleans up threads on exit
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle hook.

    On shutdown (Ctrl-C or SIGTERM) we:
    • Remove any lingering SSE log handlers from the root logger so threads
      that are still emitting records don’t keep the process alive.
    • Cancel all pending asyncio tasks.
    """
    logger.info("[AgenticTM] Server starting up on PID %d", os.getpid())

    # ---- startup validation ----
    try:
        warnings = _config.validate_startup()
        for w in warnings:
            logger.warning("[Startup] %s", w)
        if not warnings:
            logger.info("[Startup] All configuration checks passed")
    except Exception as exc:
        logger.error("[Startup] Configuration validation failed: %s", exc)

    # ---- persistent storage ----
    await _store.init()
    try:
        persisted = await _store.list_full()
        _results.update(persisted)
        logger.info("[Startup] Loaded %d results from SQLite", len(persisted))
    except Exception as exc:
        logger.error("[Startup] Failed to load persisted results: %s", exc)

    # ---- load disk results AFTER SQLite so slug-deduplication works ----
    _reload_results_from_disk()
    logger.info("[Startup] %d total results in memory (SQLite + disk)", len(_results))

    yield

    # ---- shutdown path ----
    logger.info("[AgenticTM] Server shutting down -- cleaning up")

    # Close persistent store
    await _store.close()
    # Remove all SSELogCapture handlers so their internal queues/loops are freed
    agentictm_logger = logging.getLogger("agentictm")
    sse_handlers = [h for h in agentictm_logger.handlers if isinstance(h, SSELogCapture)]
    for h in sse_handlers:
        agentictm_logger.removeHandler(h)
    # Cancel any outstanding background tasks (analysis runs)
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    logger.info("[AgenticTM] Cleanup complete")

# ---------------------------------------------------------------------------
# Console logging — ensures agent logs are visible in the server terminal
# ---------------------------------------------------------------------------


def _setup_console_logging():
    """Attach a StreamHandler to 'agentictm' logger so all pipeline logs
    appear in the server terminal (uvicorn only shows HTTP access logs)."""
    root = logging.getLogger("agentictm")
    # Avoid duplicate handlers on reload
    if any(isinstance(h, logging.StreamHandler) and getattr(h, "_agentictm_console", False) for h in root.handlers):
        return
    console = logging.StreamHandler(sys.stdout)
    console._agentictm_console = True  # type: ignore[attr-defined]
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-5s | %(message)s",
        datefmt="%H:%M:%S",
    ))
    root.addHandler(console)
    root.setLevel(logging.DEBUG)


_setup_console_logging()

# ---------------------------------------------------------------------------
# Global config — loaded once, used for auth & validation settings
# ---------------------------------------------------------------------------

_config = AgenticTMConfig.load()

# ---------------------------------------------------------------------------
# API Key Authentication (MVP)
# ---------------------------------------------------------------------------


async def verify_api_key(
    x_api_key: str | None = Header(None),
    api_key: str | None = Query(None),
):
    """Dependency that checks X-API-Key header.

    If no API key is configured in security.api_key (or it's empty/None),
    authentication is DISABLED and all requests pass through.
    """
    configured_key = _config.security.api_key
    if not configured_key:
        return  # Auth disabled — no key configured
    provided_key = x_api_key or api_key
    if provided_key != configured_key:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key. Provide X-API-Key header or api_key query parameter.",
            headers={"WWW-Authenticate": "ApiKey"},
        )


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AgenticTM API",
    description=(
        "Multi-agent Threat Modeling System powered by LangChain/LangGraph + Ollama.\n\n"
        "## Features\n"
        "- **14-node LangGraph pipeline** with 5 parallel methodology analysts\n"
        "- **Hybrid RAG** (ChromaDB vectors + PageIndex trees)\n"
        "- **STRIDE + DREAD** scoring with Red/Blue Team debate\n"
        "- **SSE streaming** for real-time analysis progress\n"
        "- **Threat justification** workflow for audit compliance\n"
    ),
    version=__version__,
    lifespan=lifespan,
    openapi_tags=[
        {"name": "Health", "description": "Liveness and readiness probes"},
        {"name": "Analysis", "description": "Start and manage threat model analyses"},
        {"name": "Results", "description": "CRUD operations for completed analyses"},
        {"name": "Knowledge Base", "description": "Document management and RAG indexing"},
        {"name": "Observability", "description": "Metrics, telemetry, and agent performance"},
    ],
)

_cors_env = os.environ.get("AGENTICTM_CORS_ORIGINS", "").strip()
if _cors_env:
    _cors_origins = [o.strip() for o in _cors_env.split(",") if o.strip()]
    _cors_allow_credentials = "*" not in _cors_origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=_cors_allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    # Safe default for local-first use: only localhost origins are allowed.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[],
        allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# In-memory cache for results, backed by SQLite via _store
_results: dict[str, dict[str, Any]] = {}

# Analysis status tracking (I11)
# {analysis_id: {status: "queued"|"running"|"completed"|"failed", started_at, ...}}
_analysis_status: dict[str, dict[str, Any]] = {}
_uploads: dict[str, Any] = {}  # upload_id → {path, filename, is_image}
_store = ResultStore(Path("data/results.db"))

# Output directory for persistent results
_OUTPUT_DIR = Path(os.environ.get("AGENTICTM_OUTPUT", "./output"))


def _slugify(text: str) -> str:
    txt = unicodedata.normalize("NFKD", text or "")
    txt = txt.encode("ascii", "ignore").decode("ascii")
    txt = re.sub(r"[^a-zA-Z0-9]+", "-", txt).strip("-").lower()
    return txt or "analysis"


def _build_project_slug(result: dict[str, Any], analysis_id: str) -> str:
    system_name = str(result.get("system_name") or "analysis")
    timestamp = str(result.get("analysis_timestamp") or "")
    if timestamp:
        try:
            dt = datetime.fromisoformat(timestamp)
            suffix = dt.strftime("%d-%m-%Y-%H%M")
        except Exception:
            suffix = analysis_id[:8]
    else:
        suffix = analysis_id[:8]
    return f"{_slugify(system_name)}-{suffix}"


def _sanitize_debate_history(debate: list) -> list:
    """Clean debate entries before sending to frontend.

    Fixes:
    1. Filters out entries without proper side/round keys (e.g., 'speaker' schema from
       hallucinated output_localizer translations).
    2. Strips orphaned </think> tags and reasoning remnants (qwen3 chat template puts
       <think> in assistant prefix, so only </think> appears in content).
    3. Deduplicates entries by (side, round) — keeps first occurrence.
    """
    seen: set[str] = set()
    sanitized: list[dict] = []

    for entry in debate:
        if not isinstance(entry, dict):
            continue
        side = entry.get("side")
        rnd = entry.get("round")
        # Skip entries without proper debate schema (e.g., output_localizer hallucinations)
        if not side or rnd is None:
            continue

        # Deduplicate by (side, round)
        key = f"{side}-{rnd}"
        if key in seen:
            continue
        seen.add(key)

        # Clean argument text — strip orphaned think tags and reasoning remnants
        arg = entry.get("argument", "")
        if arg:
            # Strip complete pairs first
            arg = re.sub(r"<think>.*?</think>", "", arg, flags=re.DOTALL)
            # Strip orphaned </think> and everything before it
            arg = re.sub(r"^.*?</think>", "", arg, flags=re.DOTALL)
            # Strip orphaned <think> at the end
            arg = re.sub(r"<think>.*$", "", arg, flags=re.DOTALL)
            arg = arg.strip()

        sanitized.append({
            **entry,
            "argument": arg,
        })

    return sanitized


def _legacy_analysis_id(out_dir: Path) -> str:
    return f"legacy-{out_dir.name}"


def _build_legacy_result(out_dir: Path) -> dict[str, Any] | None:
    """Build a minimal result object from legacy output files.

    Legacy folders may only contain: threat_model.csv, complete_report.md, dfd.mermaid.
    """
    csv_path = out_dir / "threat_model.csv"
    report_path = out_dir / "complete_report.md"
    dfd_path = out_dir / "dfd.mermaid"

    if not csv_path.exists() and not report_path.exists() and not dfd_path.exists():
        return None

    csv_output = csv_path.read_text(encoding="utf-8") if csv_path.exists() else ""
    report_output = report_path.read_text(encoding="utf-8") if report_path.exists() else ""
    mermaid_dfd = dfd_path.read_text(encoding="utf-8") if dfd_path.exists() else ""

    threats_final: list[dict[str, Any]] = []
    if csv_output.strip():
        try:
            reader = csv.DictReader(csv_output.splitlines())
            for row in reader:
                threat: dict[str, Any] = dict(row)
                if "dread_total" in threat:
                    try:
                        threat["dread_total"] = float(threat.get("dread_total") or 0)
                    except Exception:
                        threat["dread_total"] = 0
                threats_final.append(threat)
        except Exception as e:
            logger.warning("Could not parse legacy CSV in %s: %s", out_dir, e)

    system_name = out_dir.name
    analysis_date = ""
    m = re.match(r"(.+)_((?:19|20)\d{2}-\d{2}-\d{2})$", out_dir.name)
    if m:
        system_name = m.group(1).replace("_", " ")
        analysis_date = m.group(2)

    return {
        "_analysis_id": _legacy_analysis_id(out_dir),
        "system_name": system_name,
        "analysis_date": analysis_date,
        "threat_categories": [],
        "threats_final": threats_final,
        "executive_summary": "",
        "csv_output": csv_output,
        "report_output": report_output,
        "mermaid_dfd": mermaid_dfd,
        "methodology_reports": [],
        "debate_history": [],
        "raw_input": "",
        "system_description": "",
        "output_dir": str(out_dir),
        "_legacy": True,
    }


def _reload_results_from_disk():
    """Scan output/ and load persisted analyses into _results.

    Supports both current format (result.json) and legacy folders without result.json.
    Deduplicates by project_slug: if a result with the same slug is already loaded
    (e.g. from SQLite), the disk version is skipped to avoid sidebar duplicates.
    """
    if not _OUTPUT_DIR.exists():
        return
    loaded = 0
    loaded_legacy = 0

    # Build a set of project_slugs already in _results to avoid duplicates
    def _existing_slugs() -> set[str]:
        slugs = set()
        for aid, r in _results.items():
            slug = r.get("project_slug") or _build_project_slug(r, aid)
            slugs.add(slug)
        return slugs

    # 1) Current persisted format
    for result_file in _OUTPUT_DIR.rglob("result.json"):
        try:
            data = json.loads(result_file.read_text(encoding="utf-8"))
            aid = data.get("_analysis_id") or _legacy_analysis_id(result_file.parent)
            if not aid:
                continue
            # Skip if already in memory (loaded from SQLite or previous disk pass)
            if aid in _results:
                continue
            # Skip if same project_slug already loaded (prevents casing duplicates)
            data["_analysis_id"] = aid
            candidate_slug = data.get("project_slug") or _build_project_slug(data, aid)
            if candidate_slug in _existing_slugs():
                logger.debug("Skipping disk result %s -- slug '%s' already loaded", result_file, candidate_slug)
                continue
            _results[aid] = data
            loaded += 1
        except Exception as e:
            logger.warning("Could not load %s: %s", result_file, e)

    # 2) Legacy output folders (without result.json)
    for entry in _OUTPUT_DIR.iterdir():
        if not entry.is_dir():
            continue
        aid = _legacy_analysis_id(entry)
        if aid in _results:
            continue
        legacy = _build_legacy_result(entry)
        if legacy is None:
            continue
        # Deduplicate by slug
        candidate_slug = _build_project_slug(legacy, aid)
        if candidate_slug in _existing_slugs():
            logger.debug("Skipping legacy folder %s -- slug '%s' already loaded", entry.name, candidate_slug)
            continue
        _results[aid] = legacy
        loaded_legacy += 1

    if loaded:
        logger.info("Reloaded %d past analyses from disk", loaded)
    if loaded_legacy:
        logger.info("Reloaded %d legacy analyses from disk", loaded_legacy)




# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class AnalyzeRequest(BaseModel):
    system_input: str
    system_name: str = "System"
    categories: list[str] = ["auto"]
    upload_ids: list[str] = []
    max_debate_rounds: int = Field(default=4, ge=0, le=9)
    cloud_providers: dict | None = None
    scan_mode: str = Field(default="deep", pattern=r"^(fast|quick|deep|custom)$", description="fast=~2min demo, quick=~15min, deep=quality ~25min, custom=user-defined model size")
    # Custom model size in billions of parameters (only used when scan_mode='custom')
    custom_model_size: float | None = Field(default=None, ge=0.5, le=235, description="Model size in billion parameters for custom mode (e.g. 4, 8, 14, 30, 72)")
    # GitHub/GitLab token for private repo analysis
    github_token: str | None = Field(default=None, description="GitHub/GitLab PAT for private repo analysis")
    # Per-analysis threat count override (I13)
    target_threats: int | None = Field(default=None, ge=5, le=100, description="Override target threat count for this analysis")
    # Version comparison — re-analyze with baseline
    baseline_id: str | None = Field(default=None, description="Previous analysis ID for diff comparison")


class CategoryInfo(BaseModel):
    id: str
    label: str
    description: str


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = Field(json_schema_extra={"example": "ok"})
    version: str = Field(json_schema_extra={"example": __version__})
    timestamp: str = Field(json_schema_extra={"example": "2025-01-01T00:00:00"})


class ReadinessResponse(BaseModel):
    """Readiness probe response."""
    ready: bool
    ollama: str
    timestamp: str


class AnalysisRequest(BaseModel):
    """Request body for starting an analysis."""
    system_description: str = Field(
        ...,
        description="System description text (architecture, data flows, components)",
        min_length=10,
    )
    system_name: str = Field(default="System", description="Human-readable system name")
    categories: list[str] = Field(default=["auto"], description="Threat categories to activate")
    upload_ids: list[str] = Field(default_factory=list, description="IDs of previously uploaded files")
    max_debate_rounds: int = Field(default=4, ge=1, le=20, description="Max Red/Blue debate rounds")


class AnalysisSummaryResponse(BaseModel):
    """Summary of a completed analysis."""
    analysis_id: str
    project_slug: str
    system_name: str
    analysis_date: str = ""
    analysis_timestamp: str = ""
    categories: list[str] = Field(default_factory=list)
    threats_count: int = 0


class UploadResponse(BaseModel):
    """Response after uploading a file."""
    upload_id: str
    filename: str
    size_bytes: int
    is_image: bool


class MetricsResponse(BaseModel):
    """Global observability metrics."""
    global_stats: dict = Field(alias="global")
    per_agent: dict
    timestamp: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

AVAILABLE_CATEGORIES = [
    CategoryInfo(id="auto", label="Auto-detect", description="Detecta automáticamente categorías del texto"),
    CategoryInfo(id="base", label="Base / General", description="Amenazas base (siempre activo)"),
    CategoryInfo(id="aws", label="AWS", description="Amenazas específicas de Amazon Web Services"),
    CategoryInfo(id="azure", label="Azure", description="Amenazas específicas de Microsoft Azure"),
    CategoryInfo(id="gcp", label="GCP", description="Amenazas específicas de Google Cloud Platform"),
    CategoryInfo(id="ai", label="AI / LLM", description="Amenazas de Inteligencia Artificial y LLMs"),
    CategoryInfo(id="mobile", label="Mobile", description="Amenazas de aplicaciones móviles"),
    CategoryInfo(id="web", label="Web", description="Amenazas de aplicaciones web"),
    CategoryInfo(id="iot", label="IoT", description="Amenazas de Internet of Things"),
    CategoryInfo(id="privacy", label="Privacy", description="Amenazas de privacidad y datos personales"),
    CategoryInfo(id="supply_chain", label="Supply Chain", description="Amenazas de cadena de suministro"),
]


def _apply_cloud_overrides(config, cloud_providers: dict | None):
    """Override LLM config tiers with the chosen cloud provider."""
    if not cloud_providers:
        return config
    import copy
    from agentictm.config import LLMConfig
    cfg = copy.deepcopy(config)
    provider_map = {'gemini': 'google', 'anthropic': 'anthropic', 'openai': 'openai'}
    for p_name, p_cfg in cloud_providers.items():
        if not p_cfg.get('enabled') or not p_cfg.get('api_key'):
            continue
        lc       = provider_map.get(p_name, p_name)
        api_key  = p_cfg['api_key']
        qm       = p_cfg.get('quick_model', '')
        dm       = p_cfg.get('deep_model', qm)
        if qm:
            cfg.quick_thinker  = LLMConfig(provider=lc, model=qm, api_key=api_key, temperature=0.3)
            cfg.stride_thinker = LLMConfig(provider=lc, model=qm, api_key=api_key, temperature=0.3)
            cfg.vlm            = LLMConfig(
                provider=lc, model=qm, api_key=api_key, temperature=0.1,
                timeout=120, vlm_image_timeout=150, max_retries=0,
            )
        cfg.deep_thinker = LLMConfig(provider=lc, model=dm, api_key=api_key, temperature=0.2)
        break  # only first enabled provider
    return cfg


# ---------------------------------------------------------------------------
# Ollama model resolution for Custom scan mode
# ---------------------------------------------------------------------------

# Known Ollama model sizes (billion params -> model tag)
_OLLAMA_MODEL_MAP: list[tuple[float, str]] = [
    (4, "qwen3:4b"),
    (9, "qwen3.5:9b"),
    (14, "qwen3.5:14b"),
    (9, "qwen3.5:9b"),
    (27, "qwen3.5:27b"),
    (32, "qwen3.5:32b"),
    (72, "qwen3.5:72b"),
]


def _resolve_ollama_model(billion_params: float) -> str:
    """Pick the closest available Ollama model for a given parameter count."""
    best_model = _OLLAMA_MODEL_MAP[0][1]
    best_diff = float("inf")
    for size, tag in _OLLAMA_MODEL_MAP:
        diff = abs(size - billion_params)
        if diff < best_diff:
            best_diff = diff
            best_model = tag
    return best_model


def _create_agentictm(config=None):
    """Create fresh AgenticTM instance, optionally with an overridden config."""
    from agentictm.config import AgenticTMConfig
    from agentictm.core import AgenticTM
    return AgenticTM(config if config is not None else AgenticTMConfig.load())


# ---------------------------------------------------------------------------
# Custom logging handler → SSE bridge
# ---------------------------------------------------------------------------


class SSELogCapture(logging.Handler):
    """Captures log records and feeds them to an async queue."""

    def __init__(self, queue: asyncio.Queue):
        super().__init__()
        self._queue = queue
        self._loop: asyncio.AbstractEventLoop | None = None

    def set_loop(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop

    def emit(self, record: logging.LogRecord):
        try:
            msg = self.format(record)
            event_data = {
                "type": "log",
                "level": record.levelname,
                "message": msg,
                "agent": _extract_agent_name(msg),
                "timestamp": datetime.now().isoformat(),
            }
            if self._loop and self._loop.is_running():
                self._loop.call_soon_threadsafe(
                    self._queue.put_nowait, event_data
                )
        except RuntimeError:
            # Queue full or loop closed — expected during shutdown
            pass
        except Exception as exc:
            # Log to stderr so we can diagnose lost events
            import sys
            print(f"[SSELogCapture] emit error: {exc}", file=sys.stderr)


def _extract_agent_name(msg: str) -> str | None:
    """Try to extract agent name from log message."""
    agent_markers = {
        "[Architecture Parser]": "architecture_parser",
        "[Parser]": "architecture_parser",
        "[STRIDE]": "stride_analyst",
        "[PASTA]": "pasta_analyst",
        "[Attack Tree Initial]": "attack_tree_analyst",
        "[Attack Tree Enriched]": "attack_tree_enriched",
        "[Attack Tree]": "attack_tree_analyst",
        "[MAESTRO]": "maestro_analyst",
        "[AI Threat Analyst]": "ai_threat_analyst",
        "[AI Threat]": "ai_threat_analyst",
        "[Red Team]": "red_team",
        "[Blue Team]": "blue_team",
        "[Synthesizer]": "threat_synthesizer",
        "[DREAD Validator]": "dread_validator",
        "[Report]": "report_generator",
        "[Graph]": None,
        "[PageIndex]": None,
        "[Incremental]": None,
    }
    for marker, name in agent_markers.items():
        if marker in msg:
            return name
    return None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/api/health", tags=["Health"], response_model=HealthResponse, summary="Liveness probe")
async def health():
    return HealthResponse(
        status="ok",
        version=__version__,
        timestamp=datetime.now().isoformat(),
    )


@app.get("/api/ready", tags=["Health"], summary="Readiness probe (checks Ollama connectivity)")
async def readiness():
    """Deep readiness check — verifies Ollama is reachable."""
    import httpx
    ollama_url = _config.quick_thinker.base_url.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{ollama_url}/api/tags")
            resp.raise_for_status()
        return {"ready": True, "ollama": "connected", "timestamp": datetime.now().isoformat()}
    except Exception as exc:
        return JSONResponse(
            status_code=503,
            content={"ready": False, "ollama": str(exc), "timestamp": datetime.now().isoformat()},
        )


@app.get("/api/categories", tags=["Analysis"], summary="List available threat categories")
async def get_categories():
    return AVAILABLE_CATEGORIES


@app.get("/api/scan-modes", tags=["Analysis"], summary="List scan modes and available model sizes")
async def get_scan_modes():
    """Return available scan modes and model size presets for the Custom mode."""
    return {
        "modes": [
            {
                "id": "fast",
                "label": "Fast",
                "icon": "⚡",
                "description": "qwen3:4b, solo STRIDE + Attack Tree, sin debate. Ideal para demos (~2 min).",
            },
            {
                "id": "deep",
                "label": "Deep",
                "icon": "search",
                "description": "Parser y Synthesizer usan modelo 30B con razonamiento. Máxima calidad (~25 min).",
            },
            {
                "id": "custom",
                "label": "Custom",
                "icon": "⚙",
                "description": "Elegí el tamaño del modelo en billones de parámetros.",
            },
        ],
        "model_sizes": [s for s, _ in _OLLAMA_MODEL_MAP],
    }


# ---------------------------------------------------------------------------
# Global Observability & Metrics (I04)
# ---------------------------------------------------------------------------

# Track analysis-level metrics across all runs
_global_metrics: dict[str, Any] = {
    "total_analyses": 0,
    "completed_analyses": 0,
    "failed_analyses": 0,
    "total_duration_seconds": 0.0,
    "analyses_by_status": {"running": 0, "completed": 0, "failed": 0},
}


def _record_global_analysis(duration: float, success: bool) -> None:
    """Record metrics for a completed analysis run."""
    _global_metrics["total_analyses"] += 1
    if success:
        _global_metrics["completed_analyses"] += 1
        _global_metrics["analyses_by_status"]["completed"] += 1
    else:
        _global_metrics["failed_analyses"] += 1
        _global_metrics["analyses_by_status"]["failed"] += 1
    _global_metrics["total_duration_seconds"] += duration


@app.get("/api/metrics", tags=["Observability"])
async def global_metrics(_auth=Depends(verify_api_key)):
    """Global observability dashboard — agent timing, error rates, analysis stats."""
    from agentictm.agents.base import get_agent_metrics

    agent_data = get_agent_metrics()

    # Compute per-agent summaries
    per_agent: dict[str, dict] = {}
    for agent_name, runs in agent_data.items():
        times = [r.get("execution_time_seconds", 0) for r in runs]
        errors = sum(1 for r in runs if r.get("max_rounds_exhausted"))
        per_agent[agent_name] = {
            "invocations": len(runs),
            "avg_time_seconds": round(sum(times) / len(times), 2) if times else 0,
            "max_time_seconds": round(max(times), 2) if times else 0,
            "min_time_seconds": round(min(times), 2) if times else 0,
            "total_tool_calls": sum(r.get("tool_calls", 0) for r in runs),
            "self_reflections": sum(1 for r in runs if r.get("self_reflection_applied")),
            "error_count": errors,
        }

    avg_duration = (
        round(_global_metrics["total_duration_seconds"] / _global_metrics["completed_analyses"], 2)
        if _global_metrics["completed_analyses"] > 0 else 0
    )

    return {
        "global": {
            "total_analyses": _global_metrics["total_analyses"],
            "completed_analyses": _global_metrics["completed_analyses"],
            "failed_analyses": _global_metrics["failed_analyses"],
            "average_duration_seconds": avg_duration,
            "stored_results": len(_results),
        },
        "per_agent": per_agent,
        "timestamp": datetime.now().isoformat(),
    }


@app.get("/api/results/{analysis_id}/quality", tags=["Observability"], summary="Quality evaluation of a threat model")
async def quality_evaluation(analysis_id: str, _auth=Depends(verify_api_key)):
    """Run LLM-as-Judge quality evaluation on a completed analysis.

    Returns a quality score (0-100), verdict (PASS/NEEDS_REVIEW/FAIL),
    per-criterion scores, and actionable recommendations.
    """
    result = _results.get(analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")

    from agentictm.agents.quality_judge import evaluate_threat_model
    threats = result.get("threats_final", [])
    system_desc = result.get("system_description", result.get("raw_input", ""))

    report = evaluate_threat_model(threats, system_desc)

    return {
        "analysis_id": analysis_id,
        "overall_score": report.overall_score,
        "verdict": report.verdict,
        "summary": report.summary,
        "threats_evaluated": report.threats_evaluated,
        "criteria": [
            {
                "name": c.name,
                "score": round(c.score, 2),
                "max_score": c.max_score,
                "passed": c.passed,
                "details": c.details,
            }
            for c in report.criteria
        ],
        "recommendations": report.recommendations,
    }


@app.get("/api/results/{analysis_id}/compliance", tags=["Observability"], summary="Map threats to compliance controls")
async def compliance_mapping(analysis_id: str, _auth=Depends(verify_api_key)):
    """Map threats from a completed analysis to regulatory framework controls.

    Supports NIST 800-53, ISO 27001, CIS Controls v8, and OWASP ASVS.
    """
    result = _results.get(analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")

    from agentictm.agents.compliance_mapper import map_threats_to_controls, generate_compliance_summary

    threats = result.get("threats_final", [])
    mappings = map_threats_to_controls(threats)
    summary = generate_compliance_summary(mappings)

    return {
        "analysis_id": analysis_id,
        "mappings": mappings,
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# Input Triage — Interactive Pre-Analysis
# ---------------------------------------------------------------------------

# Session storage for triage conversations
_triage_sessions: dict[str, dict[str, Any]] = {}


class TriageRequest(BaseModel):
    """Request body for input triage."""
    system_input: str = Field(..., min_length=1, description="System description to evaluate")
    system_name: str = Field(default="System", description="System name")


class TriageReplyRequest(BaseModel):
    """Request body for triage follow-up answers."""
    session_id: str = Field(..., description="Triage session ID from initial triage")
    answers: list[str] = Field(..., description="User answers to the triage questions")


@app.post("/api/triage", tags=["Analysis"], summary="Evaluate input quality before analysis")
async def triage_input_endpoint(request: TriageRequest, _auth=Depends(verify_api_key)):
    """Evaluate the quality of a system description before running the full analysis.

    Returns a quality score, verdict (ready/needs_info), and clarifying questions
    if the input needs improvement. This helps users provide better descriptions
    for more accurate threat modeling.
    """
    from agentictm.agents.input_triage import triage_input

    # Try to use the quick LLM for question generation
    llm = None
    try:
        tm = _create_agentictm()
        llm = tm.llm_factory.quick
    except Exception:
        pass  # Fall back to rule-based questions

    result = triage_input(request.system_input, llm)

    # Store session for follow-up replies
    _triage_sessions[result.session_id] = {
        "original_input": request.system_input,
        "system_name": request.system_name,
        "questions": result.questions,
        "quality_score": result.quality_score,
        "created_at": datetime.now().isoformat(),
    }

    return {
        "session_id": result.session_id,
        "verdict": result.verdict,
        "quality_score": result.quality_score,
        "dimensions": result.dimensions,
        "questions": result.questions,
        "suggestions": result.suggestions,
    }


@app.post("/api/triage/reply", tags=["Analysis"], summary="Answer triage questions and re-evaluate")
async def triage_reply_endpoint(request: TriageReplyRequest, _auth=Depends(verify_api_key)):
    """Submit answers to triage questions and get an updated evaluation.

    If the enriched input is now sufficient, returns verdict=ready with the
    enriched_input that should be used for the analysis.
    """
    from agentictm.agents.input_triage import triage_input, enrich_with_answers

    session = _triage_sessions.get(request.session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Triage session not found or expired")

    # Enrich original input with user answers
    enriched = enrich_with_answers(
        session["original_input"],
        session["questions"],
        request.answers,
    )

    # Re-evaluate with enriched input
    llm = None
    try:
        tm = _create_agentictm()
        llm = tm.llm_factory.quick
    except Exception:
        pass

    result = triage_input(enriched, llm)

    # Update session
    _triage_sessions[request.session_id]["enriched_input"] = enriched
    _triage_sessions[request.session_id]["final_score"] = result.quality_score

    return {
        "session_id": request.session_id,
        "verdict": result.verdict,
        "quality_score": result.quality_score,
        "dimensions": result.dimensions,
        "questions": result.questions,
        "suggestions": result.suggestions,
        "enriched_input": enriched,
    }


# ---------------------------------------------------------------------------
# Threat Model Diff
# ---------------------------------------------------------------------------

@app.get("/api/results/diff", tags=["Analysis"], summary="Compare two threat models")
async def diff_threat_models_endpoint(a: str, b: str, _auth=Depends(verify_api_key)):
    """Compare two analysis results and produce a structured diff.

    Args:
        a: Analysis ID of the older / baseline threat model
        b: Analysis ID of the newer threat model
    """
    result_a = _results.get(a)
    result_b = _results.get(b)
    if not result_a:
        raise HTTPException(status_code=404, detail=f"Analysis '{a}' not found")
    if not result_b:
        raise HTTPException(status_code=404, detail=f"Analysis '{b}' not found")

    from agentictm.agents.diff_engine import diff_threat_models

    threats_a = result_a.get("threats_final", [])
    threats_b = result_b.get("threats_final", [])

    diff = diff_threat_models(threats_a, threats_b)

    return {
        "analysis_a": a,
        "analysis_b": b,
        **diff,
    }


# ---------------------------------------------------------------------------
# Knowledge Base Auto-Update
# ---------------------------------------------------------------------------

@app.post("/api/knowledge-base/auto-update", tags=["Knowledge Base"], summary="Update knowledge base from public sources")
async def kb_auto_update(force: bool = False, _auth=Depends(verify_api_key)):
    """Download latest OWASP, MITRE ATT&CK, and CWE data into the knowledge base.

    Set force=true to re-download even if files already exist.
    """
    from agentictm.agents.kb_updater import update_knowledge_base

    stats = update_knowledge_base(force=force)
    return stats


# ---------------------------------------------------------------------------
# Analysis Status Tracking (I11)
# ---------------------------------------------------------------------------

@app.get("/api/analysis/{analysis_id}/status", tags=["Analysis"], summary="Poll analysis status")
async def get_analysis_status(analysis_id: str, _auth=Depends(verify_api_key)):
    """Get the current status of an analysis run.

    Status values: queued → running → completed / failed
    """
    status = _analysis_status.get(analysis_id)
    if not status:
        # Check if it's a completed result we loaded from storage
        if analysis_id in _results:
            return {
                "analysis_id": analysis_id,
                "status": "completed",
                "system_name": _results[analysis_id].get("system_name", ""),
                "threats_count": len(_results[analysis_id].get("threats_final", [])),
            }
        raise HTTPException(status_code=404, detail="Analysis not found")
    return {"analysis_id": analysis_id, **status}


@app.get("/api/analyses/active", tags=["Analysis"], summary="List active/queued analyses")
async def list_active_analyses(_auth=Depends(verify_api_key)):
    """List all analyses that are currently queued or running."""
    active = [
        {"analysis_id": aid, **st}
        for aid, st in _analysis_status.items()
        if st.get("status") in ("queued", "running")
    ]
    return {"active": active, "count": len(active)}


# ---------------------------------------------------------------------------
# Knowledge Base Management API (I12)
# ---------------------------------------------------------------------------

@app.get("/api/knowledge-base", tags=["Knowledge Base"], summary="List knowledge base documents")
async def list_knowledge_base(_auth=Depends(verify_api_key)):
    """List all documents in the knowledge base with index status."""
    from agentictm.rag.indexer import get_index_status
    kb_path = _config.rag.knowledge_base_path
    status = get_index_status(kb_path)
    total_docs = sum(len(docs) for docs in status.values())
    total_indexed = sum(1 for docs in status.values() for d in docs if d["indexed"])
    return {
        "knowledge_base_path": str(kb_path),
        "total_documents": total_docs,
        "indexed_documents": total_indexed,
        "stores": status,
    }


@app.post("/api/knowledge-base/upload", tags=["Knowledge Base"], summary="Upload document to knowledge base")
async def upload_to_knowledge_base(
    file: UploadFile = File(...),
    category: str = Form("research"),
    _auth=Depends(verify_api_key),
):
    """Upload a new document to the knowledge base.

    Categories: books, research, risks_mitigations, previous_threat_models, ai_threats
    """
    from agentictm.rag import ALL_STORES
    if category not in ALL_STORES:
        raise HTTPException(status_code=400, detail=f"Invalid category. Must be one of: {ALL_STORES}")

    filename = _sanitize_filename(file.filename or "document.pdf")
    target_dir = Path(_config.rag.knowledge_base_path) / category
    target_dir.mkdir(parents=True, exist_ok=True)

    target_path = target_dir / filename
    content = await file.read()
    target_path.write_bytes(content)

    return {
        "filename": filename,
        "category": category,
        "size_bytes": len(content),
        "path": str(target_path),
        "message": f"Document uploaded. Run POST /api/knowledge-base/reindex to index it.",
    }


@app.delete("/api/knowledge-base/{category}/{filename}", tags=["Knowledge Base"], summary="Remove a KB document")
async def delete_knowledge_base_document(
    category: str,
    filename: str,
    _auth=Depends(verify_api_key),
):
    """Remove a document from the knowledge base."""
    from agentictm.rag import ALL_STORES
    if category not in ALL_STORES:
        raise HTTPException(status_code=400, detail=f"Invalid category: {category}")

    safe_name = _sanitize_filename(filename)
    target = Path(_config.rag.knowledge_base_path) / category / safe_name
    if not target.exists():
        raise HTTPException(status_code=404, detail=f"Document not found: {safe_name}")

    target.unlink()
    return {"deleted": safe_name, "category": category}


@app.post("/api/knowledge-base/reindex", tags=["Knowledge Base"], summary="Trigger knowledge base reindexing")
async def reindex_knowledge_base(
    force: bool = False,
    _auth=Depends(verify_api_key),
):
    """Reindex the knowledge base. Use force=true to rebuild all indices."""
    loop = asyncio.get_event_loop()

    def _reindex():
        tm = _create_agentictm()
        return tm.index_knowledge_base(force=force)

    try:
        result = await loop.run_in_executor(None, _reindex)
        return {
            "status": "completed",
            "force": force,
            "result": result,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Reindexing failed: {exc}")


@app.get("/api/knowledge-base/categories", tags=["Knowledge Base"], summary="List KB categories with doc counts")
async def knowledge_base_categories(_auth=Depends(verify_api_key)):
    """List auto-detected categories from the knowledge base."""
    from agentictm.rag import ALL_STORES
    kb_path = Path(_config.rag.knowledge_base_path)
    cats = []
    for store_name in ALL_STORES:
        store_dir = kb_path / store_name
        doc_count = 0
        if store_dir.exists():
            doc_count = sum(1 for f in store_dir.rglob("*") if f.is_file() and not f.name.startswith("."))
        cats.append({
            "category": store_name,
            "document_count": doc_count,
            "path": str(store_dir),
        })
    return {"categories": cats}


_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".bmp"}


def _is_image_file(filename: str) -> bool:
    return Path(filename).suffix.lower() in _IMAGE_EXTENSIONS



# Upload hardening constants — sourced from config, with sensible fallbacks
MAX_UPLOAD_SIZE = _config.security.max_upload_size_mb * 1024 * 1024
ALLOWED_MIME_PREFIXES = ("text/", "application/pdf", "image/")
ALLOWED_MIME_EXACT = {
    "text/plain",
    "text/markdown",
    "application/pdf",
    "application/json",
    "application/yaml",
    "application/x-yaml",
    "application/octet-stream",  # common browser fallback; gated by extension
}
ALLOWED_EXTENSIONS = set(_config.security.allowed_extensions)


def _sanitize_filename(filename: str) -> str:
    """Strip directory traversal components and keep only the basename."""
    # Remove any path components — only keep the leaf name
    name = Path(filename).name
    # Remove null bytes and other control chars
    name = re.sub(r'[\x00-\x1f]', '', name)
    # Collapse multiple dots (prevent ..hidden tricks)
    name = re.sub(r'\.{2,}', '.', name)
    return name or "upload"


@app.post("/api/upload", tags=["Analysis"], summary="Upload a file for analysis")
async def upload_file(file: UploadFile = File(...), _auth=Depends(verify_api_key)):
    """Upload a file (system description, diagram, image, etc.)."""
    # -- Sanitize & validate filename --
    filename = _sanitize_filename(file.filename or "unknown")
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Tipo de archivo no permitido: {ext}. Extensiones admitidas: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
        )

    # -- Validate MIME type (if provided) --
    content_type = file.content_type or ""
    mime_ok = (
        not content_type
        or content_type in ALLOWED_MIME_EXACT
        or any(content_type.startswith(p) for p in ALLOWED_MIME_PREFIXES)
    )
    # Some browsers send application/octet-stream for .md/.txt/.pdf uploads.
    # Keep it allowed only if extension already passed whitelist.
    if content_type == "application/octet-stream" and ext not in ALLOWED_EXTENSIONS:
        mime_ok = False

    if not mime_ok:
        raise HTTPException(
            status_code=400,
            detail=f"MIME type no permitido: {content_type}",
        )

    # -- Read with size limit --
    content = await file.read()
    if len(content) > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"Archivo demasiado grande: {len(content) / (1024*1024):.1f} MB. Máximo: {MAX_UPLOAD_SIZE / (1024*1024):.0f} MB",
        )

    upload_id = str(uuid.uuid4())[:8]

    # Save to temp directory
    tmp_dir = Path(tempfile.gettempdir()) / "agentictm_uploads"
    tmp_dir.mkdir(exist_ok=True)

    file_path = tmp_dir / f"{upload_id}_{filename}"
    file_path.write_bytes(content)

    is_image = _is_image_file(filename)
    _uploads[upload_id] = {
        "path": str(file_path),
        "filename": filename,
        "is_image": is_image,
    }

    return {
        "upload_id": upload_id,
        "filename": filename,
        "size": len(content),
        "is_image": is_image,
    }


@app.post("/api/analyze", tags=["Analysis"], summary="Start threat model analysis (SSE stream)")
async def analyze(request: AnalyzeRequest, raw_request: Request, _auth=Depends(verify_api_key)):
    """Start analysis — returns SSE stream of progress events."""

    # --- Rate limiting (P5) ---
    rate_limiter = get_analysis_limiter()
    rate_limiter.check(raw_request)

    # --- C08: Input length validation ---
    max_len = _config.security.max_input_length
    if len(request.system_input) > max_len:
        raise HTTPException(
            status_code=400,
            detail=f"system_input too long ({len(request.system_input):,} chars). Maximum: {max_len:,}.",
        )

    # --- P4: Prompt injection detection ---
    injection_scan = check_prompt_injection(request.system_input)
    if injection_scan.risk_level == "high":
        raise HTTPException(
            status_code=400,
            detail=(
                f"Input rejected: potential prompt injection detected "
                f"(patterns: {[d['pattern'] for d in injection_scan.detections]}). "
                f"Please remove manipulative instructions from your system description."
            ),
        )
    # Use sanitised text (strips chat template markers, script tags, etc.)
    request.system_input = injection_scan.sanitised_text

    analysis_id = str(uuid.uuid4())[:12]

    # Track analysis status (I11)
    _analysis_status[analysis_id] = {
        "status": "queued",
        "started_at": datetime.now().isoformat(),
        "system_name": request.system_name,
        "categories": request.categories,
    }

    system_input = request.system_input

    # Combine input with uploaded files
    image_paths: list[str] = []

    for uid in request.upload_ids:
        upload_meta = _uploads.get(uid)
        if not upload_meta:
            continue
        # Support both old str format and new dict format
        if isinstance(upload_meta, str):
            fpath = upload_meta
            is_image = Path(fpath).suffix.lower() in _IMAGE_EXTENSIONS
        else:
            fpath = upload_meta["path"]
            is_image = upload_meta.get("is_image", False)

        if not Path(fpath).exists():
            continue

        if is_image:
            # For images: pass the file path so VLM can process it
            image_paths.append(fpath)
        else:
            # For text/markdown/pdf/etc: read content and append
            try:
                suffix = Path(fpath).suffix.lower()
                if suffix == ".pdf":
                    # Use PyPDFLoader for proper PDF text extraction
                    try:
                        from langchain_community.document_loaders import PyPDFLoader
                        pages = PyPDFLoader(fpath).load()
                        file_content = "\n\n".join(p.page_content for p in pages)
                    except ImportError:
                        logger.warning("PyPDFLoader not available, falling back to text read for %s", fpath)
                        file_content = Path(fpath).read_text(encoding="utf-8", errors="replace")
                else:
                    file_content = Path(fpath).read_text(encoding="utf-8", errors="replace")
                fname = Path(fpath).name
                system_input += f"\n\n--- Attached file: {fname} ---\n{file_content}"
            except Exception as e:
                logger.warning("Could not read uploaded file %s: %s", fpath, e)

    # Append image paths at the end on separate lines so architecture parser can find them
    if image_paths:
        system_input += "\n\n--- Architecture Diagram Images ---\n" + "\n".join(image_paths)

    async def event_stream():
        queue: asyncio.Queue = asyncio.Queue()
        loop = asyncio.get_event_loop()
        live_events: list[dict[str, Any]] = []

        # Setup log capture
        handler = SSELogCapture(queue)
        handler.set_loop(loop)
        handler.setLevel(logging.DEBUG)
        root_logger = logging.getLogger("agentictm")
        root_logger.addHandler(handler)
        root_logger.setLevel(logging.DEBUG)

        # Send start event
        start_event = {
            "type": "start",
            "analysis_id": analysis_id,
            "system_name": request.system_name,
            "categories": request.categories,
            "timestamp": datetime.now().isoformat(),
        }
        live_events.append(start_event)
        yield _sse_event(start_event)

        # Run analysis in thread pool
        result_future: asyncio.Future = loop.run_in_executor(
            None,
            _run_analysis_sync,
            system_input,
            request.system_name,
            request.categories,
            analysis_id,
            request.max_debate_rounds,
            request.cloud_providers,
            request.scan_mode,
            getattr(request, "custom_model_size", None),
        )

        # Stream logs while analysis runs
        try:
            while not result_future.done():
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=0.5)
                    if isinstance(event, dict) and event.get("type") != "heartbeat":
                        live_events.append(event)
                    yield _sse_event(event)
                except asyncio.TimeoutError:
                    # Send heartbeat
                    yield _sse_event({"type": "heartbeat"})

            # Drain remaining log events
            while not queue.empty():
                event = queue.get_nowait()
                if isinstance(event, dict) and event.get("type") != "heartbeat":
                    live_events.append(event)
                yield _sse_event(event)

            # Get result
            result = result_future.result()
            threats_count = len(result.get("threats_final", []))
            # Persist full live execution timeline in analysis result
            result["live_execution"] = list(live_events)

            # If clarification is needed, send a special event and save partial result
            if result.get("clarification_needed") and not result.get("user_answers"):
                clarify_event = {
                    "type": "clarification_needed",
                    "analysis_id": analysis_id,
                    "questions": result.get("clarification_questions", []),
                    "quality_score": result.get("quality_score", 0),
                    "timestamp": datetime.now().isoformat(),
                }
                live_events.append(clarify_event)
                result["live_execution"] = list(live_events)
                _results[analysis_id] = result
                await _store.save(analysis_id, result)
                yield _sse_event(clarify_event)
                return # Stop SSE stream here; user needs to reply
            _results[analysis_id] = result
            await _store.save(analysis_id, result)

            # Persist uploaded files for this analysis (for later re-download)
            persisted_uploads: list[dict[str, Any]] = []
            output_dir_str = result.get("output_dir")
            if output_dir_str:
                attachments_dir = Path(output_dir_str) / "attachments"
                attachments_dir.mkdir(parents=True, exist_ok=True)

                for uid in request.upload_ids:
                    upload_meta = _uploads.get(uid)
                    if not upload_meta:
                        continue
                    if isinstance(upload_meta, dict):
                        src_path = Path(upload_meta.get("path", ""))
                        original_name = upload_meta.get("filename") or src_path.name
                        is_image = bool(upload_meta.get("is_image", False))
                    else:
                        src_path = Path(upload_meta)
                        original_name = src_path.name
                        is_image = _is_image_file(original_name)

                    if not src_path.exists():
                        continue

                    base_name = Path(original_name).name
                    target = attachments_dir / base_name
                    n = 1
                    while target.exists():
                        target = attachments_dir / f"{Path(base_name).stem}_{n}{Path(base_name).suffix}"
                        n += 1

                    try:
                        shutil.copy2(src_path, target)
                        persisted_uploads.append({
                            "name": base_name,
                            "stored_name": target.name,
                            "type": "image" if is_image else "document",
                            "size": target.stat().st_size,
                        })
                    except Exception as copy_exc:
                        logger.warning("Could not persist uploaded file %s: %s", src_path, copy_exc)

            if persisted_uploads:
                result["uploaded_files"] = persisted_uploads
                _results[analysis_id] = result
                await _store.save(analysis_id, result)
                try:
                    out_dir = Path(result.get("output_dir", ""))
                    if out_dir.exists():
                        (out_dir / "result.json").write_text(
                            json.dumps(result, ensure_ascii=False, default=str),
                            encoding="utf-8",
                        )
                except Exception as save_exc:
                    logger.warning("Could not update persisted result.json with attachments: %s", save_exc)

            # Send completion event with summary
            complete_event = {
                "type": "complete",
                "analysis_id": analysis_id,
                "threats_count": threats_count,
                "categories": result.get("threat_categories", []),
                "timestamp": datetime.now().isoformat(),
            }
            live_events.append(complete_event)
            result["live_execution"] = list(live_events)
            _results[analysis_id] = result
            await _store.save(analysis_id, result)
            try:
                out_dir = Path(result.get("output_dir", ""))
                if out_dir.exists():
                    (out_dir / "result.json").write_text(
                        json.dumps(result, ensure_ascii=False, default=str),
                        encoding="utf-8",
                    )
            except Exception as save_live_exc:
                logger.warning("Could not persist live execution timeline: %s", save_live_exc)
            yield _sse_event(complete_event)

        except Exception as exc:
            import traceback
            tb_str = traceback.format_exc()
            logger.error("Analysis failed with exception:\n%s", tb_str)
            yield _sse_event({
                "type": "error",
                "message": f"{type(exc).__name__}: {exc}",
                "traceback": tb_str,
                "timestamp": datetime.now().isoformat(),
            })
            _record_global_analysis(0, success=False)
            # Update status (I11)
            if analysis_id in _analysis_status:
                _analysis_status[analysis_id].update({
                    "status": "failed",
                    "error": str(exc),
                    "completed_at": datetime.now().isoformat(),
                })

        finally:
            root_logger.removeHandler(handler)

            # Cleanup uploaded temp files used in this analysis
            for uid in request.upload_ids:
                upload_meta = _uploads.pop(uid, None)
                if upload_meta:
                    fpath = upload_meta["path"] if isinstance(upload_meta, dict) else upload_meta
                    try:
                        Path(fpath).unlink(missing_ok=True)
                    except Exception:
                        pass  # best-effort cleanup

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


def _run_analysis_sync(
    system_input: str,
    system_name: str,
    categories: list[str],
    analysis_id: str,
    max_debate_rounds: int = 4,
    cloud_providers: dict | None = None,
    scan_mode: str = "deep",
    custom_model_size: float | None = None,
) -> dict:
    """Run the analysis synchronously (called from thread pool)."""
    # ── Summary banner ─────────────────────────────────────────────
    input_kb = len(system_input) / 1024
    has_images = "--- Architecture Diagram Images ---" in system_input
    img_count = 0
    if has_images:
        img_section = system_input.split("--- Architecture Diagram Images ---")[-1]
        img_count = len([l for l in img_section.strip().splitlines() if l.strip()])

    logger.info("=" * 70)
    logger.info("  ANALYSIS STARTED  [%s]  %s  (scan=%s)", analysis_id, system_name, scan_mode)
    logger.info("  Input: %.1f KB | Images: %d | Categories: %s",
                input_kb, img_count, ", ".join(categories))
    logger.info("=" * 70)

    t0 = time.perf_counter()
    # Update status to running (I11)
    if analysis_id in _analysis_status:
        _analysis_status[analysis_id]["status"] = "running"
    from agentictm.config import AgenticTMConfig
    base_cfg = AgenticTMConfig.load()
    final_cfg = _apply_cloud_overrides(base_cfg, cloud_providers)

    # ── Scan mode overrides ────────────────────────────────────────
    if scan_mode == "fast":
        from agentictm.config import LLMConfig
        fast_llm = LLMConfig(
            model="qwen3:4b",
            temperature=0.3,
            timeout=120,
            num_ctx=16384,
            num_predict=4096,
            think=False,
        )
        final_cfg.quick_thinker = fast_llm
        final_cfg.deep_thinker = fast_llm.model_copy(update={"temperature": 0.2})
        final_cfg.stride_thinker = fast_llm.model_copy()
        final_cfg.vlm.vlm_image_timeout = 60
        final_cfg.pipeline.enabled_analysts = ["stride", "attack_tree"]
        final_cfg.pipeline.skip_debate = True
        final_cfg.pipeline.skip_enriched_attack_tree = True
        max_debate_rounds = 0
        logger.info("  Fast scan: qwen3:4b, stride+attack_tree only, no debate, VLM timeout=60s")
    elif scan_mode == "custom" and custom_model_size is not None:
        from agentictm.config import LLMConfig
        custom_tag = _resolve_ollama_model(custom_model_size)
        custom_llm = LLMConfig(model=custom_tag)
        final_cfg.quick_thinker = custom_llm
        final_cfg.deep_thinker = custom_llm
        final_cfg.stride_thinker = custom_llm
        logger.info("  Custom scan: Using %s (%.1fB params)", custom_tag, custom_model_size)
    elif scan_mode == "quick":
        final_cfg.deep_thinker = final_cfg.quick_thinker.model_copy(update={"timeout": 180})
        final_cfg.vlm.vlm_image_timeout = 180
        max_debate_rounds = min(max_debate_rounds, 2)
        logger.info("  Quick scan: Parser/Synthesizer using quick model, debate capped at %d rounds, VLM timeout=180s", max_debate_rounds)
    try:
        tm = _create_agentictm(config=final_cfg)
    except Exception:
        raise
    try:
        result = tm.analyze(system_input, system_name, threat_categories=categories, max_debate_rounds=max_debate_rounds)
    except Exception:
        raise
    result["analysis_timestamp"] = datetime.now().isoformat()
    result["max_debate_rounds"] = max_debate_rounds
    result["scan_mode"] = scan_mode
    elapsed = time.perf_counter() - t0

    threats_count = len(result.get("threats_final", []))

    logger.info("=" * 70)
    logger.info("  ANALYSIS COMPLETE [%s]  in %.1fs", analysis_id, elapsed)
    logger.info("  Threats: %d | Categories: %s",
                threats_count, ", ".join(result.get("threat_categories", [])))
    logger.info("=" * 70)

    # Record global observability metrics (I04)
    _record_global_analysis(elapsed, success=True)
    result["duration_seconds"] = round(elapsed, 2)

    # Update status (I11)
    if analysis_id in _analysis_status:
        _analysis_status[analysis_id].update({
            "status": "completed",
            "completed_at": datetime.now().isoformat(),
            "threats_count": threats_count,
            "duration_seconds": round(elapsed, 2),
        })

    # Also save to disk
    result["_analysis_id"] = analysis_id
    result["project_slug"] = _build_project_slug(result, analysis_id)
    try:
        out_dir = tm.save_output(result)
        result["output_dir"] = str(out_dir)
        # Persist full result as JSON for reload on restart
        result_json_path = Path(out_dir) / "result.json"
        result_json_path.write_text(
            json.dumps(result, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        logger.info("  Output saved to: %s", out_dir)
    except Exception as e:
        logger.warning("Could not save output: %s", e)

    return result


class AnalyzeResumeRequest(BaseModel):
    analysis_id: str
    answers: list[str] = Field(default_factory=list)


@app.post("/api/analyze/resume", tags=["Analysis"], summary="Resume analysis with user answers (SSE stream)")
async def analyze_resume(request: AnalyzeResumeRequest, _auth=Depends(verify_api_key)):
    """Resume a paused analysis with user answers."""
    from agentictm.agents.input_triage import enrich_with_answers

    # Get partial result
    partial = _results.get(request.analysis_id)
    if not partial:
        raise HTTPException(status_code=404, detail="Analysis not found or not in a resumable state")

    # Enrich description with answers
    enriched_input = enrich_with_answers(
        partial.get("system_description", ""),
        partial.get("clarification_questions", []),
        request.answers,
    )

    # Prepare for resume: update state
    partial["user_answers"] = request.answers
    partial["system_description"] = enriched_input
    # Clear clarification flag so it doesn't loop
    partial["clarification_needed"] = False

    # Technically we should resume the graph from where it left off.
    # For now, a simple way is to re-run the analysis with the enriched input
    # and a special flag to skip the parser's own assessment.
    
    # We reuse the existing 'analyze' logic but pass the enriched input
    # and mark it as 'already parsed' in some way, OR we just let it run
    # and since it now has enough keywords/components, the parser will 
    # give it a high score and proceed.
    
    # Let's create a new 'AnalyzeRequest' and redirect internally or 
    # just return the same SSE stream logic.
    
    # For a robust implementation, we should refactor the SSE stream part 
    # into a shared function.
    
    # TODO: Refactor server.py SSE logic to avoid duplication.
    # For this iteration, I will assume the user provides enough info 
    # that a fresh /api/analyze call with the enriched text is sufficient,
    # OR the frontend just calls /api/analyze with the new text.
    
    # However, the user wants it to be a "resume".
    return {"message": "RESUME NOT FULLY IMPLEMENTED - Redirecting to /api/analyze with enriched input", "enriched_input": enriched_input}


@app.get("/api/results", tags=["Results"], summary="List all completed analyses")
async def list_results(_auth=Depends(verify_api_key)):
    """List all completed analyses (summary only)."""
    items = []
    for aid, r in _results.items():
        slug = r.get("project_slug") or _build_project_slug(r, aid)
        items.append({
            "analysis_id": aid,
            "project_slug": slug,
            "system_name": r.get("system_name", ""),
            "analysis_date": r.get("analysis_date", ""),
            "analysis_timestamp": r.get("analysis_timestamp", ""),
            "categories": r.get("threat_categories", []),
            "threats_count": len(r.get("threats_final", [])),
        })
    # Newest first
    items.sort(key=lambda x: x.get("analysis_date", ""), reverse=True)
    return items


@app.get("/api/results/{analysis_id}", tags=["Results"], summary="Get full analysis result")
async def get_result(analysis_id: str, _auth=Depends(verify_api_key)):
    """Get the full result of a completed analysis."""
    result = _results.get(analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")

    threats = result.get("threats_final", [])

    # Extract attack tree mermaid diagrams from methodology reports
    attack_tree_mermaid = []
    for report in result.get("methodology_reports", []):
        methodology = report.get("methodology", "")
        if "ATTACK_TREE" in methodology:
            raw_report = report.get("report", "")
            parsed = None
            try:
                import json as _json
                parsed = _json.loads(raw_report) if isinstance(raw_report, str) else raw_report
            except Exception:
                # Try to extract JSON from the response
                from agentictm.agents.base import extract_json_from_response
                parsed = extract_json_from_response(raw_report)

            if isinstance(parsed, dict) and parsed.get("attack_trees"):
                for tree in parsed.get("attack_trees", []):
                    mermaid_code = tree.get("tree_mermaid", "")
                    if mermaid_code:
                        attack_tree_mermaid.append({
                            "methodology": methodology,
                            "root_goal": tree.get("root_goal", "Attack Tree"),
                            "mermaid": mermaid_code,
                        })
            else:
                # FALLBACK: If JSON parsing completely failed (e.g. truncation),
                # try to extract mermaid code directly from the raw text via regex.
                import re
                # Match "graph TD" or "flowchart LR" until the end of the string or the next JSON key quote
                mermaid_matches = re.finditer(r'(?:graph|flowchart)\s+(?:TD|LR|TB|RL|BT).*?(?="|\Z)', raw_report, re.IGNORECASE | re.DOTALL)
                for i, match in enumerate(mermaid_matches):
                    # Clean up escaped newlines if it was part of a JSON string
                    mermaid_code = match.group(0).replace('\\n', '\n').strip()
                    if mermaid_code:
                        attack_tree_mermaid.append({
                            "methodology": methodology,
                            "root_goal": f"Fallback Tree {i+1}",
                            "mermaid": mermaid_code,
                        })

    raw_input = result.get("raw_input", "")
    uploaded_files = []

    # Prefer persisted uploaded files metadata
    persisted = result.get("uploaded_files", [])
    if isinstance(persisted, list) and persisted:
        for f in persisted:
            if not isinstance(f, dict):
                continue
            name = f.get("name") or f.get("filename") or f.get("stored_name") or "archivo"
            stored_name = f.get("stored_name") or Path(str(name)).name
            uploaded_files.append({
                "name": name,
                "filename": name,
                "stored_name": stored_name,
                "type": f.get("type", "document"),
                "size": f.get("size", 0),
                "download_url": f"/api/results/{analysis_id}/attachments/{quote(str(stored_name))}",
            })
    else:
        # Legacy fallback from raw_input markers
        if "--- Attached file:" in raw_input:
            for line in raw_input.split("\n"):
                if line.strip().startswith("--- Attached file:"):
                    fname = line.replace("--- Attached file:", "").replace("---", "").strip()
                    if fname:
                        uploaded_files.append({"name": fname, "filename": fname, "type": "document", "size": 0})
        if "--- Architecture Diagram Images ---" in raw_input:
            img_section = raw_input.split("--- Architecture Diagram Images ---")[-1]
            for line in img_section.strip().splitlines():
                line = line.strip()
                if line:
                    fname = Path(line).name
                    uploaded_files.append({"name": fname, "filename": fname, "type": "image", "size": 0})

    return {
        "analysis_id": analysis_id,
        "project_slug": result.get("project_slug") or _build_project_slug(result, analysis_id),
        "system_name": result.get("system_name", ""),
        "analysis_date": result.get("analysis_date", ""),
        "analysis_timestamp": result.get("analysis_timestamp", ""),
        "duration_seconds": result.get("duration_seconds", 0),
        "categories": result.get("threat_categories", []),
        "threats_count": len(threats),
        "threats": threats,
        "executive_summary": result.get("executive_summary", ""),
        "csv_output": result.get("csv_output", ""),
        "report_output": result.get("report_output", ""),
        "mermaid_dfd": result.get("mermaid_dfd", ""),
        "methodology_reports": result.get("methodology_reports", []),
        "debate_history": _sanitize_debate_history(
            result.get("debate_history_localized") or result.get("debate_history", [])
        ),
        "live_execution": result.get("live_execution", []),
        "raw_input": raw_input,
        "uploaded_files": uploaded_files,
        "system_description": result.get("system_description", ""),
        "attack_tree_mermaid": attack_tree_mermaid,
        "components": result.get("components", []),
        "data_flows": result.get("data_flows", []),
        "trust_boundaries": result.get("trust_boundaries", []),
    }



@app.get("/api/results/{analysis_id}/attachments/{stored_name}", tags=["Results"], summary="Download uploaded attachment")
async def download_attachment(analysis_id: str, stored_name: str, _auth=Depends(verify_api_key)):
    """Download a persisted uploaded attachment for an analysis."""
    result = _results.get(analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")

    output_dir = result.get("output_dir")
    if not output_dir:
        raise HTTPException(status_code=404, detail="No output directory for this analysis")

    safe_name = Path(stored_name).name
    attach_path = Path(output_dir) / "attachments" / safe_name
    if not attach_path.exists() or not attach_path.is_file():
        raise HTTPException(status_code=404, detail="Attachment not found")

    return FileResponse(path=attach_path, filename=safe_name)


@app.delete("/api/results/{analysis_id}", tags=["Results"], summary="Delete an analysis")
async def delete_result(analysis_id: str, _auth=Depends(verify_api_key)):
    """Delete an analysis and associated files on disk.

    Graceful: if the analysis is not in the in-memory cache (e.g. it was created
    in a different session / Electron instance), we still purge it from the SQLite
    store and any matching output directory, then return 200 so the client can
    cleanly remove the entry from its local state.
    """
    result = _results.pop(analysis_id, None)

    # Always try to purge from the persistent store regardless of memory state
    await _store.delete(analysis_id)

    removed_dir = None
    output_dir = result.get("output_dir") if result else None

    # If not in memory, try to find the output dir by scanning the output directory
    if not output_dir and _OUTPUT_DIR.exists():
        for candidate in _OUTPUT_DIR.iterdir():
            if not candidate.is_dir():
                continue
            rj = candidate / "result.json"
            if rj.exists():
                try:
                    data = json.loads(rj.read_text(encoding="utf-8"))
                    if data.get("_analysis_id") == analysis_id:
                        output_dir = str(candidate)
                        break
                except Exception:
                    pass
            # Legacy folder whose ID matches
            if _legacy_analysis_id(candidate) == analysis_id:
                output_dir = str(candidate)
                break

    if output_dir:
        out_path = Path(output_dir)
        try:
            # Safety: only remove inside configured output directory
            _ = out_path.resolve().relative_to(_OUTPUT_DIR.resolve())
            if out_path.exists() and out_path.is_dir():
                shutil.rmtree(out_path, ignore_errors=True)
                removed_dir = str(out_path)
        except Exception as e:
            logger.warning("Could not remove output dir %s: %s", out_path, e)

    logger.info(
        "[Delete] analysis_id=%s | was_in_memory=%s | removed_dir=%s",
        analysis_id, result is not None, removed_dir,
    )

    return {
        "status": "deleted",
        "analysis_id": analysis_id,
        "removed_output_dir": removed_dir,
    }


# ---------------------------------------------------------------------------
# Threat Justification — user dispositioning of individual threats
# ---------------------------------------------------------------------------

class _JustifyRequest(BaseModel):
    """Request body for threat justification."""
    decision: str = Field(
        description="FALSE_POSITIVE | MITIGATED_BY_INFRA | ACCEPTED_RISK | NOT_APPLICABLE"
    )
    reason_text: str = Field(min_length=50, description="Justification reason (min 50 chars)")
    justified_by: str = ""
    context_snapshot: dict = Field(default_factory=dict)


_VALID_DECISIONS = {
    "FALSE_POSITIVE", "MITIGATED_BY_INFRA", "ACCEPTED_RISK", "NOT_APPLICABLE",
}


@app.put("/api/results/{analysis_id}/threats/{threat_id}/justify", tags=["Results"], summary="Justify a threat finding")
async def justify_threat(analysis_id: str, threat_id: str, body: _JustifyRequest, _auth=Depends(verify_api_key)):
    """Add or update a user justification for a specific threat."""
    result = _results.get(analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")

    if body.decision not in _VALID_DECISIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid decision. Must be one of: {', '.join(sorted(_VALID_DECISIONS))}",
        )

    threats = result.get("threats_final", [])
    target = None
    for t in threats:
        if t.get("id", "") == threat_id:
            target = t
            break

    if target is None:
        raise HTTPException(status_code=404, detail=f"Threat '{threat_id}' not found")

    justification = {
        "decision": body.decision,
        "reason_text": body.reason_text,
        "justified_by": body.justified_by,
        "justified_at": datetime.now().isoformat(),
        "context_snapshot": body.context_snapshot,
    }
    target["justification"] = justification

    # Persist to disk
    output_dir = result.get("output_dir")
    if output_dir:
        try:
            result_path = Path(output_dir) / "result.json"
            if result_path.exists():
                with open(result_path, "r", encoding="utf-8") as f:
                    disk_data = json.load(f)
                disk_threats = disk_data.get("threats_final", [])
                for dt in disk_threats:
                    if dt.get("id", "") == threat_id:
                        dt["justification"] = justification
                        break
                with open(result_path, "w", encoding="utf-8") as f:
                    json.dump(disk_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning("Could not persist justification to disk: %s", e)

    # Persist to SQLite
    await _store.save(analysis_id, result)

    return {
        "threat_id": threat_id,
        "decision": body.decision,
        "justified_at": justification["justified_at"],
        "message": "Justification saved successfully",
    }


@app.delete("/api/results/{analysis_id}/threats/{threat_id}/justify", tags=["Results"], summary="Remove threat justification")
async def remove_justification(analysis_id: str, threat_id: str, _auth=Depends(verify_api_key)):
    """Remove a justification from a threat."""
    result = _results.get(analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")

    threats = result.get("threats_final", [])
    target = None
    for t in threats:
        if t.get("id", "") == threat_id:
            target = t
            break

    if target is None:
        raise HTTPException(status_code=404, detail=f"Threat '{threat_id}' not found")

    target["justification"] = None

    # Persist to disk
    output_dir = result.get("output_dir")
    if output_dir:
        try:
            result_path = Path(output_dir) / "result.json"
            if result_path.exists():
                with open(result_path, "r", encoding="utf-8") as f:
                    disk_data = json.load(f)
                for dt in disk_data.get("threats_final", []):
                    if dt.get("id", "") == threat_id:
                        dt["justification"] = None
                        break
                with open(result_path, "w", encoding="utf-8") as f:
                    json.dump(disk_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning("Could not persist justification removal: %s", e)

    # Persist to SQLite
    await _store.save(analysis_id, result)

    return {"threat_id": threat_id, "message": "Justification removed"}


class ThreatFieldUpdate(BaseModel):
    field: str
    value: str


@app.put("/api/results/{analysis_id}/threats/{threat_id}/field", tags=["Results"], summary="Update a threat field")
async def update_threat_field(analysis_id: str, threat_id: str, body: ThreatFieldUpdate, _auth=Depends(verify_api_key)):
    """Update a custom field (estado, tratamiento, evidence_notes) on a threat."""
    if body.field not in ("estado", "tratamiento", "evidence_notes"):
        raise HTTPException(status_code=400, detail="Invalid field")

    result = _results.get(analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")

    threats = result.get("threats_final", [])
    target = None
    for t in threats:
        if t.get("id", "") == threat_id:
            target = t
            break
    if target is None:
        raise HTTPException(status_code=404, detail=f"Threat '{threat_id}' not found")

    target[body.field] = body.value

    # Persist to disk
    output_dir = result.get("output_dir")
    if output_dir:
        try:
            result_path = Path(output_dir) / "result.json"
            if result_path.exists():
                with open(result_path, "r", encoding="utf-8") as f:
                    disk_data = json.load(f)
                for dt in disk_data.get("threats_final", []):
                    if dt.get("id", "") == threat_id:
                        dt[body.field] = body.value
                        break
                with open(result_path, "w", encoding="utf-8") as f:
                    json.dump(disk_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning("Could not persist field update: %s", e)

    # Persist to SQLite
    await _store.save(analysis_id, result)

    return {"threat_id": threat_id, "field": body.field, "value": body.value}


@app.get("/api/results/{analysis_id}/csv-justified", tags=["Results"], summary="Download justified CSV")
async def download_justified_csv(analysis_id: str, _auth=Depends(verify_api_key)):
    """Download CSV with justification columns included."""
    import io as _io

    result = _results.get(analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")

    threats = result.get("threats_final", [])
    if not threats:
        raise HTTPException(status_code=404, detail="No threats found")

    system_name = result.get("system_name", "Sistema")

    output = _io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    writer.writerow([
        "ID", "Escenario de Amenaza", "STRIDE", "Control de Amenaza",
        "D", "R", "E", "A", "D", "DREAD Avg", "Prioridad",
        "Estado", "Tratamiento de Riesgo", "Jira Ticket", "Observaciones",
        "Confianza", "Fuentes de Evidencia",
        "Decisión Justificación", "Razón Justificación",
        "Justificado por", "Fecha Justificación",
    ])

    _PRIO_ES = {"Critical": "CRÍTICO", "High": "ALTO", "Medium": "MEDIO", "Low": "BAJO"}

    for t in threats:
        d = t.get("damage", 0)
        r = t.get("reproducibility", 0)
        e2 = t.get("exploitability", 0)
        a = t.get("affected_users", 0)
        disc = t.get("discoverability", 0)
        vals = [d, r, e2, a, disc]
        avg = sum(vals) / 5 if any(vals) else 0
        avg_str = f"{avg:.1f}"

        # Confidence
        confidence = t.get("confidence_score", 0)
        conf_str = f"{confidence:.0%}" if confidence else ""

        # Evidence sources
        evidence = t.get("evidence_sources", [])
        evidence_str = "; ".join(
            f"{es.get('source_name', '')} ({es.get('source_type', '')})"
            for es in evidence
            if isinstance(es, dict)
        ) if evidence else ""

        # Justification
        justif = t.get("justification")
        justif_decision = ""
        justif_reason = ""
        justif_by = ""
        justif_at = ""
        if isinstance(justif, dict):
            _DECISION_ES = {
                "FALSE_POSITIVE": "Falso Positivo",
                "MITIGATED_BY_INFRA": "Mitigado por Infraestructura",
                "ACCEPTED_RISK": "Riesgo Aceptado",
                "NOT_APPLICABLE": "No Aplica",
            }
            justif_decision = _DECISION_ES.get(justif.get("decision", ""), justif.get("decision", ""))
            justif_reason = justif.get("reason_text", "")
            justif_by = justif.get("justified_by", "")
            justif_at = justif.get("justified_at", "")

        prio = _PRIO_ES.get(t.get("priority", "Medium"), "MEDIO")

        writer.writerow([
            t.get("id", ""),
            t.get("description", ""),
            t.get("stride_category", ""),
            t.get("mitigation", ""),
            d, r, e2, a, disc,
            avg_str,
            prio,
            t.get("estado", ""),
            t.get("tratamiento", ""),
            "",
            t.get("observations", ""),
            conf_str,
            evidence_str,
            justif_decision,
            justif_reason,
            justif_by,
            justif_at,
        ])

    # Footer
    writer.writerow([])
    writer.writerow(["Sistema", system_name])
    writer.writerow(["Total Threats", str(len(threats))])
    justified_count = sum(1 for t in threats if t.get("justification"))
    writer.writerow(["Threats Justificados", str(justified_count)])
    writer.writerow(["Generado por", f"AgenticTM v{__version__}"])

    return StreamingResponse(
        iter(['\ufeff' + output.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="threat_model_justified_{analysis_id}.csv"',
        },
    )


@app.get("/api/results/{analysis_id}/metrics", tags=["Observability"], summary="Get per-analysis metrics")
async def get_analysis_metrics(analysis_id: str, _auth=Depends(verify_api_key)):
    """Get quality metrics for an analysis run."""
    from agentictm.agents.base import get_agent_metrics

    result = _results.get(analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")

    return {
        "analysis_id": analysis_id,
        "agent_metrics": get_agent_metrics(),
        "threats_count": len(result.get("threats_final", [])),
        "justified_count": sum(
            1 for t in result.get("threats_final", [])
            if t.get("justification")
        ),
    }


@app.get("/api/results/{analysis_id}/csv", tags=["Results"], summary="Download CSV output")
async def download_csv(analysis_id: str, _auth=Depends(verify_api_key)):
    """Download the CSV output for an analysis."""
    result = _results.get(analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")

    csv_output = result.get("csv_output", "")
    if not csv_output:
        raise HTTPException(status_code=404, detail="No CSV output available")

    return StreamingResponse(
        iter(['\ufeff' + csv_output]),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="threat_model_{analysis_id}.csv"',
        },
    )


@app.get("/api/results/{analysis_id}/report", tags=["Results"], summary="Download Markdown report")
async def download_report(analysis_id: str, _auth=Depends(verify_api_key)):
    """Download the Markdown report for an analysis."""
    result = _results.get(analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")

    report = result.get("report_output", "")
    if not report:
        raise HTTPException(status_code=404, detail="No report output available")

    return StreamingResponse(
        iter([report]),
        media_type="text/markdown",
        headers={
            "Content-Disposition": f'attachment; filename="report_{analysis_id}.md"',
        },
    )


@app.get("/api/results/{analysis_id}/latex", tags=["Results"], summary="Download LaTeX report")
async def download_latex(analysis_id: str, _auth=Depends(verify_api_key)):
    """Download the LaTeX report for an analysis."""
    result = _results.get(analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")

    # Generate LaTeX on the fly from the stored state
    from agentictm.agents.report_generator import generate_latex_report
    try:
        latex_output = generate_latex_report(result)
    except Exception as e:
        logger.warning("LaTeX generation failed: %s", e)
        raise HTTPException(status_code=500, detail="LaTeX generation failed")

    return StreamingResponse(
        iter([latex_output]),
        media_type="application/x-latex",
        headers={
            "Content-Disposition": f'attachment; filename="threat_model_{analysis_id}.tex"',
        },
    )


# ---------------------------------------------------------------------------
# Per-analysis logs endpoint
# ---------------------------------------------------------------------------

@app.get("/api/logs/{analysis_id}", tags=["Observability"], summary="Get per-analysis pipeline log")
async def get_analysis_log(analysis_id: str, _auth=Depends(verify_api_key)):
    """Return the JSONL pipeline log for a given analysis.

    Each line is a structured JSON object with ``ts``, ``level``, ``node``,
    ``msg``, and optional ``data`` fields.  The ``analysis_id`` matches the
    correlation ID from ``logs/{analysis_id}.jsonl``.
    """
    log_path = Path("logs") / f"{analysis_id}.jsonl"
    if not log_path.exists():
        raise HTTPException(status_code=404, detail=f"No log found for analysis {analysis_id}")

    lines = []
    for raw in log_path.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if raw:
            try:
                lines.append(json.loads(raw))
            except json.JSONDecodeError:
                lines.append({"raw": raw})

    return JSONResponse(content={"analysis_id": analysis_id, "entries": lines})


# ---------------------------------------------------------------------------
# SSE helper
# ---------------------------------------------------------------------------


def _sse_event(data: dict) -> str:
    """Format a dict as an SSE event string."""
    return f"data: {json.dumps(data, ensure_ascii=False)}\n\n"


# ---------------------------------------------------------------------------
# Static files & SPA
# ---------------------------------------------------------------------------

_STATIC_DIR = Path(__file__).parent / "static"

# SPA routes — serve index.html for all frontend paths
_SPA_ROUTES = ["/home", "/prompt", "/live", "/threats", "/dfd", "/debate", "/report", "/diagrams", "/editor"]


@app.get("/")
async def root():
    """Serve the SPA."""
    return FileResponse(
        _STATIC_DIR / "index.html",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/logo-philocyber.png")
async def root_logo():
    """Serve PhiloCyber logo from project root for desktop/web branding."""
    # Try multiple locations: static dir (always works), project root, CWD
    candidates = [
        _STATIC_DIR / "logo-philocyber.png",
        Path(__file__).resolve().parent / "static" / "logo-philocyber.png",
        Path("logo-philocyber.png").resolve(),
    ]
    for p in candidates:
        if p.exists():
            return FileResponse(p, headers={"Cache-Control": "no-store"})
    raise HTTPException(status_code=404, detail="Logo not found")


for _route in _SPA_ROUTES:
    app.add_api_route(_route, root, methods=["GET"])


# Mount static files BEFORE the catch-all project route
if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


@app.get("/{project_slug}/{tab}")
async def project_tab_route(project_slug: str, tab: str):
    """Serve SPA for project-scoped URLs like /mi-sistema-24-02-2026-2130/diagrams."""
    if tab not in {"prompt", "live", "threats", "dfd", "debate", "report", "diagrams", "editor"}:
        raise HTTPException(status_code=404, detail="Route not found")
    return FileResponse(
        _STATIC_DIR / "index.html",
        headers={"Cache-Control": "no-store"},
    )
