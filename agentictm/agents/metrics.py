"""Agent quality metrics — collected per-agent invocation."""

from __future__ import annotations

import threading

_agent_metrics: dict[str, list[dict]] = {}
_metrics_lock = threading.Lock()


def get_agent_metrics() -> dict[str, list[dict]]:
    """Return all collected agent quality metrics."""
    with _metrics_lock:
        return dict(_agent_metrics)


def clear_agent_metrics() -> None:
    """Reset agent metrics (e.g., at the start of a new analysis)."""
    with _metrics_lock:
        _agent_metrics.clear()


def _record_metric(agent_name: str, metric: dict) -> None:
    """Record a quality metric for an agent."""
    with _metrics_lock:
        _agent_metrics.setdefault(agent_name, []).append(metric)
