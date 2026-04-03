"""YAML/JSON System Model Parser — structured input for threat modeling.

Allows users to define their system architecture in a structured YAML or JSON
format instead of free-form text. This bypasses the architecture parser LLM
and produces deterministic results.

Example YAML input::

    system_name: My E-Commerce Platform
    components:
      - name: Web Frontend
        type: process
        technology: React
        scope: external
      - name: API Server
        type: process
        technology: Node.js/Express
        scope: internal
      - name: PostgreSQL
        type: datastore
        technology: PostgreSQL 15
        scope: internal
    data_flows:
      - source: Web Frontend
        destination: API Server
        protocol: HTTPS
        data_type: JSON
      - source: API Server
        destination: PostgreSQL
        protocol: TCP/5432
        data_type: SQL queries
    trust_boundaries:
      - name: Internet <-> DMZ
        components_inside: [API Server]
        components_outside: [Web Frontend]
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def detect_structured_input(raw_input: str) -> str | None:
    """Detect if the input is structured YAML or JSON.

    Returns:
        "yaml", "json", or None if not structured
    """
    stripped = raw_input.strip()

    # JSON detection
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            json.loads(stripped)
            return "json"
        except json.JSONDecodeError:
            pass

    # YAML detection — look for YAML-like structure
    yaml_indicators = [
        re.search(r"^system_name\s*:", stripped, re.MULTILINE),
        re.search(r"^components\s*:", stripped, re.MULTILINE),
        re.search(r"^data_flows\s*:", stripped, re.MULTILINE),
        re.search(r"^---\s*\n", stripped),
    ]
    if sum(1 for x in yaml_indicators if x) >= 2:
        return "yaml"

    return None


def parse_structured_input(raw_input: str) -> dict[str, Any] | None:
    """Parse structured YAML/JSON input into canonical architecture schema.

    Returns:
        Dict with keys: system_description, components, data_flows,
        trust_boundaries, or None if parsing fails.
    """
    fmt = detect_structured_input(raw_input)
    if fmt is None:
        return None

    try:
        if fmt == "json":
            data = json.loads(raw_input.strip())
        elif fmt == "yaml":
            if not HAS_YAML:
                logger.warning("YAML input detected but PyYAML not installed. Falling back to LLM parser.")
                return None
            data = yaml.safe_load(raw_input.strip())
        else:
            return None
    except Exception as e:
        logger.warning("Failed to parse %s input: %s", fmt, e)
        return None

    if not isinstance(data, dict):
        return None

    return _normalize_to_canonical(data)


def _normalize_to_canonical(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize parsed YAML/JSON to the canonical architecture schema.

    Handles multiple naming conventions:
    - components / services / nodes
    - data_flows / flows / connections
    - trust_boundaries / boundaries / zones
    """
    result: dict[str, Any] = {}

    # System description
    result["system_name"] = data.get("system_name", data.get("name", "System"))
    result["system_description"] = data.get(
        "system_description",
        data.get("description", f"Architecture for {result['system_name']}"),
    )

    # Components (multiple possible keys)
    raw_components = (
        data.get("components")
        or data.get("services")
        or data.get("nodes")
        or []
    )
    result["components"] = [_normalize_component(c) for c in raw_components]

    # Data flows
    raw_flows = (
        data.get("data_flows")
        or data.get("flows")
        or data.get("connections")
        or []
    )
    result["data_flows"] = [_normalize_flow(f) for f in raw_flows]

    # Trust boundaries
    raw_boundaries = (
        data.get("trust_boundaries")
        or data.get("boundaries")
        or data.get("zones")
        or []
    )
    result["trust_boundaries"] = [_normalize_boundary(b) for b in raw_boundaries]

    # External entities
    result["external_entities"] = data.get("external_entities", [])

    # Data stores (extract from components)
    result["data_stores"] = [
        c for c in result["components"]
        if c.get("type") in ("datastore", "data_store", "database", "storage")
    ]

    logger.info(
        "[YAML Parser] Parsed: %d components, %d flows, %d boundaries",
        len(result["components"]), len(result["data_flows"]), len(result["trust_boundaries"]),
    )

    return result


def _normalize_component(c: dict[str, Any] | str) -> dict[str, Any]:
    """Normalize a component entry."""
    if isinstance(c, str):
        return {"name": c, "type": "process", "description": "", "scope": "internal"}

    return {
        "name": c.get("name", "Unknown"),
        "type": c.get("type", "process"),
        "description": c.get("description", ""),
        "technology": c.get("technology", c.get("tech", "")),
        "scope": c.get("scope", "internal"),
        "interfaces": c.get("interfaces", c.get("endpoints", [])),
        "dependencies": c.get("dependencies", c.get("depends_on", [])),
    }


def _normalize_flow(f: dict[str, Any]) -> dict[str, Any]:
    """Normalize a data flow entry."""
    return {
        "source": f.get("source", f.get("from", "")),
        "destination": f.get("destination", f.get("to", f.get("dest", ""))),
        "protocol": f.get("protocol", f.get("proto", "unknown")),
        "data_type": f.get("data_type", f.get("data", "")),
        "bidirectional": f.get("bidirectional", False),
        "description": f.get("description", ""),
        "authentication": f.get("authentication", f.get("auth", "unknown")),
    }


def _normalize_boundary(b: dict[str, Any] | str) -> dict[str, Any]:
    """Normalize a trust boundary entry."""
    if isinstance(b, str):
        return {"name": b, "components_inside": [], "components_outside": []}

    return {
        "name": b.get("name", "Unknown"),
        "components_inside": b.get("components_inside", b.get("inside", [])),
        "components_outside": b.get("components_outside", b.get("outside", [])),
    }
