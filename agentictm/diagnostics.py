"""AgenticTM Diagnostics — standalone system health checker.

Usage:
    python -m agentictm.diagnostics            # full check
    python -m agentictm.diagnostics --dry-run  # also run pipeline with mock LLMs
"""

from __future__ import annotations

import argparse
import json
import logging
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_system_memory_bytes() -> int | None:
    """Return total physical memory in bytes, or None if unavailable."""
    system = platform.system()
    try:
        if system == "Darwin":
            out = subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True)
            return int(out.strip())
        elif system == "Linux":
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        return int(line.split()[1]) * 1024
    except Exception:
        pass
    return None


def _bytes_to_gb(b: int) -> float:
    return b / (1024 ** 3)


def _query_ollama(base_url: str, path: str, timeout: float = 10) -> dict | None:
    """GET a JSON endpoint from Ollama, return parsed dict or None."""
    try:
        import httpx
        resp = httpx.get(f"{base_url}{path}", timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.debug("Ollama query %s%s failed: %s", base_url, path, exc)
        return None


# Model sizes (approximate VRAM in bytes) for default model stack
_MODEL_SIZES: dict[str, int] = {
    "qwen3:4b": int(2.7 * 1024**3),
    "qwen3.5:9b": int(6.6 * 1024**3),
    "qwen3.5:9b": int(6.6 * 1024**3),
}


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_ollama_connectivity(base_url: str) -> dict[str, Any]:
    """Check 1: Ollama reachable?"""
    t0 = time.monotonic()
    data = _query_ollama(base_url, "/api/tags")
    latency_ms = (time.monotonic() - t0) * 1000
    if data is None:
        return {"status": "FAIL", "message": f"Cannot reach Ollama at {base_url}", "latency_ms": None}
    model_count = len(data.get("models", []))
    return {
        "status": "OK",
        "message": f"Ollama reachable at {base_url} ({model_count} models)",
        "latency_ms": round(latency_ms, 1),
        "model_count": model_count,
    }


def check_model_availability(base_url: str, config: Any) -> dict[str, Any]:
    """Check 2: All configured models exist in Ollama?"""
    data = _query_ollama(base_url, "/api/tags")
    if data is None:
        return {"status": "FAIL", "message": "Cannot reach Ollama", "models": {}}

    available = {m["name"] for m in data.get("models", [])}
    roles = {
        "quick_thinker": config.quick_thinker.model,
        "deep_thinker": config.deep_thinker.model,
        "stride_thinker": config.stride_thinker.model,
        "vlm": config.vlm.model,
    }
    results: dict[str, Any] = {}
    all_ok = True
    for role, model in roles.items():
        found = model in available
        results[role] = {"model": model, "found": found}
        if not found:
            all_ok = False

    return {
        "status": "OK" if all_ok else "WARN",
        "message": "All models available" if all_ok else "Some models missing",
        "models": results,
    }


def check_vram_usage(base_url: str) -> dict[str, Any]:
    """Check 3: Query loaded models and their VRAM from Ollama /api/ps."""
    data = _query_ollama(base_url, "/api/ps")
    if data is None:
        return {"status": "SKIP", "message": "Cannot query Ollama /api/ps"}

    loaded = []
    total_vram = 0
    for m in data.get("models", []):
        name = m.get("name", "unknown")
        size_vram = m.get("size_vram", 0)
        total_vram += size_vram
        loaded.append({"name": name, "vram_gb": round(_bytes_to_gb(size_vram), 2)})

    return {
        "status": "OK",
        "message": f"{len(loaded)} model(s) loaded, {_bytes_to_gb(total_vram):.1f} GB VRAM in use",
        "loaded_models": loaded,
        "total_vram_gb": round(_bytes_to_gb(total_vram), 2),
    }


def check_config(config: Any) -> dict[str, Any]:
    """Check 4: Report config summary."""
    return {
        "status": "OK",
        "message": "Configuration loaded",
        "models": {
            "quick_thinker": config.quick_thinker.model,
            "deep_thinker": config.deep_thinker.model,
            "stride_thinker": config.stride_thinker.model,
            "vlm": config.vlm.model,
        },
        "timeouts": {
            "quick": config.quick_thinker.timeout,
            "deep": config.deep_thinker.timeout,
            "stride": config.stride_thinker.timeout,
            "vlm_image": config.vlm.vlm_image_timeout,
        },
        "context_sizes": {
            "quick": config.quick_thinker.num_ctx,
            "deep": config.deep_thinker.num_ctx,
            "stride": config.stride_thinker.num_ctx,
        },
        "pipeline": {
            "execution_mode": config.pipeline.analyst_execution_mode,
            "max_parallel": config.pipeline.max_parallel_analysts,
            "max_debate_rounds": config.pipeline.max_debate_rounds,
            "skip_debate": config.pipeline.skip_debate,
            "enabled_analysts": config.pipeline.enabled_analysts,
        },
    }


def check_memory(config: Any) -> dict[str, Any]:
    """Check 5: Compare system memory against model sizes."""
    mem_bytes = _get_system_memory_bytes()
    if mem_bytes is None:
        return {"status": "SKIP", "message": "Cannot determine system memory"}

    mem_gb = _bytes_to_gb(mem_bytes)
    warnings: list[str] = []

    for role, model in [
        ("deep_thinker", config.deep_thinker.model),
        ("stride_thinker", config.stride_thinker.model),
        ("quick_thinker", config.quick_thinker.model),
        ("vlm", config.vlm.model),
    ]:
        model_size = _MODEL_SIZES.get(model)
        if model_size and model_size > mem_bytes * 0.80:
            warnings.append(
                f"{role}={model} ({_bytes_to_gb(model_size):.1f} GB) exceeds "
                f"80% of available RAM ({mem_gb:.1f} GB)"
            )

    return {
        "status": "WARN" if warnings else "OK",
        "message": f"System RAM: {mem_gb:.1f} GB" + (f" -- {len(warnings)} warning(s)" if warnings else ""),
        "ram_gb": round(mem_gb, 1),
        "warnings": warnings,
    }


def check_prompt_budgets(config: Any) -> dict[str, Any]:
    """Check 6: Estimate prompt budgets for each role."""
    budgets: dict[str, dict[str, Any]] = {}
    for role, cfg in [
        ("quick_thinker", config.quick_thinker),
        ("deep_thinker", config.deep_thinker),
        ("stride_thinker", config.stride_thinker),
    ]:
        num_ctx = cfg.num_ctx or 32768
        num_predict = cfg.num_predict or 8192
        available_tokens = num_ctx - num_predict
        approx_chars = available_tokens * 3
        budgets[role] = {
            "model": cfg.model,
            "num_ctx": num_ctx,
            "num_predict": num_predict,
            "available_input_tokens": available_tokens,
            "approx_input_chars": approx_chars,
        }

    return {
        "status": "OK",
        "message": "Prompt budgets estimated",
        "budgets": budgets,
    }


def run_dry_run() -> dict[str, Any]:
    """Check 7: Run the full pipeline with mock LLMs."""
    try:
        from agentictm.config import AgenticTMConfig, PipelineConfig
        from agentictm.graph.builder import build_graph

        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from tests.conftest import MockLLMFactory

        config = AgenticTMConfig(
            pipeline=PipelineConfig(
                analyst_execution_mode="cascade",
                max_parallel_analysts=1,
                max_debate_rounds=0,
                skip_debate=True,
                skip_enriched_attack_tree=True,
                skip_dread_validator=True,
                skip_output_localizer=True,
            )
        )
        factory = MockLLMFactory()
        graph = build_graph(config, factory)
        app = graph.compile()

        state = {
            "system_name": "DiagnosticsDryRun",
            "analysis_date": "2025-01-01",
            "raw_input": "A simple web app with a REST API and PostgreSQL database.",
            "debate_round": 1,
            "max_debate_rounds": 0,
            "iteration_count": 0,
            "methodology_reports": [],
            "debate_history": [],
            "threat_categories": ["base", "web"],
            "executive_summary": "",
        }

        t0 = time.monotonic()
        result = app.invoke(state)
        elapsed_ms = (time.monotonic() - t0) * 1000

        threats = result.get("threats_final", [])
        errors = result.get("_errors", [])

        return {
            "status": "OK" if not errors and threats else "WARN",
            "message": f"Dry run completed in {elapsed_ms:.0f}ms: {len(threats)} threats, {len(errors)} error(s)",
            "elapsed_ms": round(elapsed_ms),
            "threats_count": len(threats),
            "errors": [e.get("error", str(e)) for e in errors],
        }
    except Exception as exc:
        return {
            "status": "FAIL",
            "message": f"Dry run failed: {exc}",
        }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_diagnostics(*, dry_run: bool = False) -> dict[str, Any]:
    """Execute all diagnostic checks and return a structured report."""
    from agentictm.config import AgenticTMConfig

    report: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "python_version": sys.version,
        "platform": platform.platform(),
        "checks": {},
    }

    try:
        config = AgenticTMConfig.load()
    except Exception as exc:
        report["checks"]["config_load"] = {"status": "FAIL", "message": f"Failed to load config: {exc}"}
        return report

    base_url = config.quick_thinker.base_url

    report["checks"]["ollama_connectivity"] = check_ollama_connectivity(base_url)
    report["checks"]["model_availability"] = check_model_availability(base_url, config)
    report["checks"]["vram_usage"] = check_vram_usage(base_url)
    report["checks"]["config"] = check_config(config)
    report["checks"]["memory"] = check_memory(config)
    report["checks"]["prompt_budgets"] = check_prompt_budgets(config)

    if dry_run:
        report["checks"]["dry_run"] = run_dry_run()

    return report


def _print_report(report: dict[str, Any]) -> None:
    """Pretty-print the diagnostic report to the console."""
    STATUS_ICONS = {"OK": "\u2705", "WARN": "\u26a0\ufe0f ", "FAIL": "\u274c", "SKIP": "\u23ed\ufe0f "}

    print()
    print("=" * 70)
    print("  AgenticTM Diagnostics")
    print(f"  {report['timestamp']}")
    print(f"  Python {report['python_version'].split()[0]} | {report['platform']}")
    print("=" * 70)
    print()

    for check_name, check_data in report.get("checks", {}).items():
        status = check_data.get("status", "?")
        icon = STATUS_ICONS.get(status, "?")
        message = check_data.get("message", "")
        print(f"  {icon} {check_name}: {message}")

        if check_name == "model_availability":
            for role, info in check_data.get("models", {}).items():
                found_icon = "\u2705" if info["found"] else "\u274c"
                print(f"       {found_icon} {role}: {info['model']}")

        if check_name == "vram_usage":
            for m in check_data.get("loaded_models", []):
                print(f"       - {m['name']}: {m['vram_gb']} GB")

        if check_name == "memory":
            for w in check_data.get("warnings", []):
                print(f"       \u26a0\ufe0f  {w}")

        if check_name == "prompt_budgets":
            for role, b in check_data.get("budgets", {}).items():
                print(f"       {role}: ~{b['approx_input_chars']:,} chars ({b['available_input_tokens']:,} tokens)")

        if check_name == "config":
            models = check_data.get("models", {})
            for role, model in models.items():
                print(f"       {role}: {model}")

        if check_name == "dry_run":
            if check_data.get("errors"):
                for e in check_data["errors"]:
                    print(f"       \u274c {e}")

        print()

    # Summary
    statuses = [c.get("status", "?") for c in report.get("checks", {}).values()]
    if "FAIL" in statuses:
        print("  Result: FAILURES detected. Fix the issues above before running analysis.")
    elif "WARN" in statuses:
        print("  Result: Warnings present. System may work but with limitations.")
    else:
        print("  Result: All checks passed. System is ready for analysis.")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="AgenticTM Diagnostics")
    parser.add_argument("--dry-run", action="store_true", help="Also run pipeline with mock LLMs")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of pretty print")
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING)

    report = run_diagnostics(dry_run=args.dry_run)

    # Save to logs/
    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = logs_dir / f"diagnostics-{ts}.json"
    log_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        _print_report(report)
        print(f"  Full report saved to: {log_path}")
        print()


if __name__ == "__main__":
    main()
