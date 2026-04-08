"""Agent: Architecture Parser -- Phase I: Ingestion and Modeling.

Transforms any input (free text, Mermaid, attached files, diagram images)
into a structured system model.

For diagram images (PNG, JPG, etc.) uses a Vision Language Model (VLM)
to extract components, flows, and trust boundaries directly from the image.
"""

from __future__ import annotations

import base64
import concurrent.futures
import json
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from agentictm.agents.base import invoke_agent, extract_json_from_response
from agentictm.agents.input_triage import _score_dimensions
from agentictm.state import ThreatModelState
from agentictm.logging import with_logging_context

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel

logger = logging.getLogger(__name__)


def _model_name(model: "BaseChatModel") -> str:
    return getattr(model, "model", getattr(model, "model_name", "unknown"))

SYSTEM_PROMPT = """\
You are a world-class principal engineer with deep expertise across software
architecture, cloud infrastructure (AWS/Azure/GCP), database systems, networking,
DevOps/CI-CD pipelines, and distributed systems design.

Your ONLY task is to thoroughly understand and document the system architecture
presented to you. Combine ALL provided information — user description, technical
documents, diagrams, and any attached files — into a single, comprehensive,
factual architecture model.

You are NOT a security analyst. Do NOT identify threats, attacks, vulnerabilities,
STRIDE categories, or security controls. Leave that for specialized agents downstream.

Focus on deeply UNDERSTANDING the system:
- What is the system's purpose and business domain?
- What are ALL the components, services, microservices, and modules?
- How do they communicate (protocols, APIs, message queues, event buses)?
- What are the trust boundaries and network segmentation (internet/DMZ/internal/VPC)?
- What data stores exist, what technology, and what data sensitivity?
- Who or what are the external actors (users, admins, third-party APIs, partners)?
- What is the end-to-end information flow for key use cases?
- What is the deployment model (cloud, on-prem, hybrid, edge, containers, serverless)?
- Are there any ML/AI components, agents, or model-serving endpoints?

Extract as JSON:

1. **system_description**: 3-4 paragraph executive summary explaining what the system
   does, its business purpose, the overall architecture pattern (monolith, microservices,
   event-driven, etc.), how it works end-to-end, and its deployment model. Be detailed.

2. **components**: list of ALL components/services/modules. For each:
    - name: exact name from the documentation/diagram
    - type: "process" | "data_store" | "external_entity" | "api_gateway" | "ml_model" | "message_queue" | "cache" | "cdn" | "load_balancer" | "edge_device" | "ci_cd"
    - description: what this component does (2-3 sentences, detailed)
    - technology: specific technology if known (e.g., "PostgreSQL 15", "Redis 7", "Kafka", "LangChain", "FastAPI")
    - scope: "internal" | "dmz" | "public" | "cloud" | "edge" | "on_prem"
    - interfaces: list of APIs/ports/endpoints this component exposes
    - dependencies: list of other component names this depends on

3. **data_flows**: list of ALL data flows/connections. For each:
    - source: component name
    - destination: component name
    - protocol: (HTTPS, gRPC, SQL, AMQP, WebSocket, SSH, TCP, etc.)
    - data_type: what kind of data flows (PII, credentials, financial, logs, telemetry, etc.)
    - description: what this flow does (1-2 sentences)
    - authentication: how this flow is authenticated if known (JWT, mTLS, API key, none, unknown)

4. **trust_boundaries**: list of trust boundaries / network zones. For each:
    - name (e.g., "Internet <-> DMZ", "Cloud VPC <-> On-prem", "Internal <-> Partner API")
    - components_inside
    - components_outside
    - boundary_type: "network" | "process" | "machine" | "trust_level"

5. **external_entities**: list of external actors/services. For each:
    - name, type ("end_user" | "admin" | "third_party_api" | "partner" | "iot_device"), description

6. **data_stores**: list of data stores. For each:
    - name, type (database, cache, file_system, object_storage, vector_db, event_store, ledger),
      technology, sensitivity (PII/financial/public/internal/secrets), encryption (yes/no/unknown)

7. **api_endpoints**: list of notable API endpoints. For each:
    - path, method, description, authentication (yes/no/unknown), data_classification

8. **deployment_info**: deployment model
    - environment: cloud/on-prem/hybrid/edge
    - cloud_provider: AWS/Azure/GCP/other/unknown
    - orchestration: kubernetes/docker-compose/serverless/ecs/etc.
    - ci_cd: pipeline details if mentioned
    - monitoring: observability tools if mentioned

IMPORTANT RULES:
- Extract ONLY what is explicitly stated or clearly visible. Do NOT invent components.
- Cross-reference ALL inputs: diagrams, text docs, and user description may complement each other.
- If something is ambiguous, include it in an "assumptions" field.
- Do NOT analyze security, threats, or vulnerabilities — only architecture.
- Be EXHAUSTIVE: capture every component, flow, boundary, and endpoint.
- Prefer specificity: "PostgreSQL 15" over "database", "Kafka" over "message queue".

Respond ONLY with structured JSON.
"""

VLM_SYSTEM_PROMPT = """\
You are a world-class principal engineer with deep expertise in software
architecture, cloud infrastructure, database systems, and distributed systems.
You specialize in reading and interpreting architecture diagrams, data-flow
diagrams (DFDs), network diagrams, and system design visuals.

Your ONLY task is to extract the system architecture from this diagram.
You are NOT a security analyst — do NOT identify threats, attacks,
vulnerabilities, STRIDE categories, attack scenarios, or security controls.

Carefully inspect the diagram for:
- All boxes/circles/cylinders/shapes → these are COMPONENTS (name + type)
- All arrows/lines/connections → these are DATA FLOWS (source, destination, protocol)
- All labels/text annotations/protocol names → read them EXACTLY as written
- Any dashed lines/colored zones/boundary markers → TRUST BOUNDARIES
- Database symbols/cloud shapes/user icons → type hints
- API endpoint paths if visible (e.g., /api/v1/users)
- Technology names (PostgreSQL, Redis, Kafka, gRPC, etc.)
- Deployment indicators (Kubernetes, Docker, AWS, etc.)

Extract as JSON:
1. **system_description**: 2-3 paragraphs explaining what the system does, its
   architecture pattern, and how it works end-to-end based on what you see.
2. **components**: name, type, description, technology (if visible), scope, interfaces, dependencies
3. **data_flows**: source, destination, protocol, data_type, description, authentication
4. **trust_boundaries**: name, components_inside, components_outside, boundary_type
5. **external_entities**: name, type, description
6. **data_stores**: name, type, technology, sensitivity, encryption
7. **api_endpoints**: path, method, description (if visible in the diagram)
8. **deployment_info**: environment, cloud_provider, orchestration, ci_cd (if visible)

IMPORTANT RULES:
- Extract ONLY what is visible in the diagram. Do NOT invent components or flows.
- If text is partially legible, provide your best interpretation and note it.
- Do NOT analyze security, threats, or vulnerabilities. Only architecture.
- Do NOT produce STRIDE analysis, threat actors, attack scenarios, or controls.
- Be EXHAUSTIVE: capture EVERY visible component, connection, and annotation.

Respond ONLY with structured JSON.
"""


def _ensure_str(val: object) -> str:
    """Coerce any value to a plain string; joins dict values or list items."""
    if isinstance(val, str):
        return val
    if isinstance(val, dict):
        parts = [str(v) for v in val.values() if v]
        return " ".join(parts) if parts else json.dumps(val, ensure_ascii=False)
    if isinstance(val, list):
        return " ".join(str(item) for item in val)
    return str(val) if val else ""


def _extract_app_context_notes(raw_input: str, parsed: dict[str, Any] | None = None) -> list[str]:
    """Extract explicit business/workflow context without turning it into threats."""
    parsed = parsed or {}
    corpus_parts = [
        raw_input,
        _ensure_str(parsed.get("system_description", "")),
        _ensure_str(parsed.get("assumptions", [])),
        _ensure_str(parsed.get("api_endpoints", [])),
    ]
    corpus = " ".join(part for part in corpus_parts if part).lower()
    notes: list[str] = []

    identifiers = [
        token for token in (
            "tenant_id", "doc_id", "user_id", "account_id", "org_id",
            "status", "created_at", "share_token", "object_id",
        )
        if token in corpus
    ]
    if identifiers:
        notes.append(
            "Explicit business/data identifiers mentioned: "
            + ", ".join(sorted(set(identifiers)))
            + "."
        )

    if any(term in corpus for term in ("multi-tenant", "tenant isolation", "cross-tenant", "authorized tenant")):
        notes.append(
            "Multi-tenant boundaries are explicitly described, including tenant-scoped access expectations."
        )

    if any(term in corpus for term in ("presigned", "pre-signed", "shareable link", "share link", "secure shareable link")):
        notes.append(
            "Link-based access flows are explicitly described (presigned URLs or shareable links)."
        )

    if any(term in corpus for term in ("upload", "uploaded", "object-created", "directly to s3")) and any(
        term in corpus for term in ("scan", "scanner", "clamav", "quarantine", "clean status", "status update", "updates dynamodb")
    ):
        notes.append(
            "The workflow includes explicit upload-to-scan state transitions before downstream access or sharing."
        )

    if any(term in corpus for term in ("sqs", "queue", "event", "asynchronous", "async")) and any(
        term in corpus for term in ("download", "share", "linkgenerator", "link generator", "authorized tenant users")
    ):
        notes.append(
            "An asynchronous processing pipeline is explicitly described between ingestion, validation, and later download/share actions."
        )

    api_endpoints = parsed.get("api_endpoints", [])
    if isinstance(api_endpoints, list) and api_endpoints:
        named_paths = [
            f"{ep.get('method', 'UNKNOWN')} {ep.get('path', '').strip()}".strip()
            for ep in api_endpoints
            if isinstance(ep, dict) and ep.get("path")
        ]
        if named_paths:
            notes.append(
                "Notable API endpoints mentioned: " + ", ".join(named_paths[:8]) + "."
            )

    return notes


def _build_scope_notes(parsed: dict[str, Any] | None, raw_input: str, fallback: str = "") -> str:
    """Compose parser assumptions plus explicit business/workflow context."""
    parsed = parsed or {}
    sections: list[str] = []

    assumptions = parsed.get("assumptions", [])
    if assumptions:
        sections.append("Parser assumptions: " + json.dumps(assumptions, ensure_ascii=False))

    app_notes = _extract_app_context_notes(raw_input, parsed)
    if app_notes:
        sections.append("Explicit application/workflow context:\n- " + "\n- ".join(app_notes))

    if fallback:
        sections.append(fallback)

    return "\n\n".join(section for section in sections if section).strip()


def _regex_extract_architecture(response: str) -> dict:
    """Extract architecture components from semi-broken JSON via individual object parsing.

    When the full JSON is malformed (broken keys from LLM token artifacts),
    this extracts individual component/flow objects that ARE valid JSON.
    """
    import re as _re

    result: dict = {"components": [], "data_flows": [], "trust_boundaries": [], "data_stores": [], "system_description": ""}

    # Try extracting system_description via regex
    sd_match = _re.search(r'"system_description"\s*:\s*"((?:[^"\\]|\\.)*)"', response, _re.DOTALL)
    if sd_match:
        result["system_description"] = sd_match.group(1).replace('\\"', '"').replace("\\n", "\n")

    # Find all individual JSON objects and classify them
    depth = 0
    in_string = False
    escape = False
    start_idx = -1
    objects: list[dict] = []

    for i, ch in enumerate(response):
        if escape:
            escape = False
            continue
        if ch == '\\' and in_string:
            escape = True
            continue
        if ch == '"' and not escape:
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == '{':
            if depth == 2:
                start_idx = i
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 2 and start_idx >= 0:
                snippet = response[start_idx:i + 1]
                try:
                    obj = json.loads(snippet)
                    if isinstance(obj, dict):
                        objects.append(obj)
                except json.JSONDecodeError:
                    try:
                        from json_repair import repair_json
                        obj = repair_json(snippet, return_objects=True)
                        if isinstance(obj, dict):
                            objects.append(obj)
                    except Exception:
                        pass
                start_idx = -1

    for obj in objects:
        if "name" in obj and ("type" in obj or "technology" in obj or "description" in obj):
            if "source" not in obj and "destination" not in obj:
                result["components"].append(obj)
        elif "source" in obj and "destination" in obj:
            result["data_flows"].append(obj)
        elif "boundary" in obj or "trust" in obj.get("name", "").lower():
            result["trust_boundaries"].append(obj)

    return result


def _detect_input_type(raw_input: str) -> str:
    """Detect the input type: text, mermaid, image, drawio, mixed."""
    stripped = raw_input.strip()
    lower = stripped.lower()
    if lower.startswith(("graph ", "flowchart ", "sequencediagram", "classdiagram")):
        return "mermaid"
    if lower.startswith("<?xml") or "<mxfile" in lower:
        return "drawio"
    # Check for image file paths embedded in input
    image_exts = (".png", ".jpg", ".jpeg", ".svg", ".webp", ".gif", ".bmp")
    has_images = False
    for line in stripped.split("\n"):
        line = line.strip()
        if any(line.lower().endswith(ext) for ext in image_exts):
            if Path(line).exists():
                has_images = True
                break
    # Check for base64 image data
    if "data:image/" in lower or stripped.startswith("/9j/") or stripped.startswith("iVBOR"):
        return "image"
    if has_images:
        # If there is also substantial text (description), treat as mixed
        # Remove image lines and check remaining content length
        non_image_lines = [
            l for l in stripped.split("\n")
            if not any(l.strip().lower().endswith(ext) for ext in image_exts)
            and "--- Architecture Diagram Images ---" not in l
            and l.strip()
        ]
        if len("\n".join(non_image_lines).strip()) > 100:
            return "mixed"
        return "image"
    return "text"


def _find_image_paths(raw_input: str) -> list[Path]:
    """Extract valid image file paths from the input."""
    image_exts = (".png", ".jpg", ".jpeg", ".svg", ".webp", ".gif", ".bmp")
    paths = []
    for line in raw_input.strip().split("\n"):
        line = line.strip()
        if any(line.lower().endswith(ext) for ext in image_exts):
            p = Path(line)
            if p.exists():
                paths.append(p)
    return paths


_MAX_IMAGE_BYTES = 2 * 1024 * 1024  # 2 MB — above this we auto-resize
_MAX_IMAGE_DIMENSION = 1920  # longest side after resize
_JPEG_QUALITY = 85


def _maybe_resize_image(image_path: Path) -> tuple[bytes, str]:
    """Return (image_bytes, mime_type), auto-resizing if the file is too large.

    Uses Pillow when the image exceeds ``_MAX_IMAGE_BYTES`` so the VLM receives
    a manageably-sized payload instead of a 6 MB+ PNG.
    """
    raw_bytes = image_path.read_bytes()
    mime = _get_image_mime(image_path)

    if len(raw_bytes) <= _MAX_IMAGE_BYTES:
        return raw_bytes, mime

    try:
        from PIL import Image as PILImage
        import io

        original_mb = len(raw_bytes) / (1024 * 1024)
        img = PILImage.open(io.BytesIO(raw_bytes))

        # Downscale so the longest side is at most _MAX_IMAGE_DIMENSION
        w, h = img.size
        scale = min(_MAX_IMAGE_DIMENSION / max(w, h), 1.0)
        if scale < 1.0:
            new_w, new_h = int(w * scale), int(h * scale)
            img = img.resize((new_w, new_h), PILImage.LANCZOS)
            logger.info(
                "[Architecture Parser] Resized %s from %dx%d to %dx%d",
                image_path.name, w, h, new_w, new_h,
            )

        # Re-encode as JPEG (much smaller than PNG for photos/diagrams)
        if img.mode in ("RGBA", "P", "LA"):
            img = img.convert("RGB")
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=_JPEG_QUALITY, optimize=True)
        resized_bytes = buf.getvalue()
        resized_mb = len(resized_bytes) / (1024 * 1024)
        logger.info(
            "[Architecture Parser] Compressed %s: %.2f MB -> %.2f MB (%.0f%% reduction)",
            image_path.name, original_mb, resized_mb,
            (1 - resized_mb / original_mb) * 100,
        )
        return resized_bytes, "image/jpeg"

    except ImportError:
        logger.warning(
            "[Architecture Parser] Pillow not installed -- sending %.2f MB image as-is. "
            "Install Pillow (`pip install Pillow`) for automatic resize.",
            len(raw_bytes) / (1024 * 1024),
        )
        return raw_bytes, mime
    except Exception as exc:
        logger.warning(
            "[Architecture Parser] Image resize failed for %s: %s -- sending original",
            image_path.name, exc,
        )
        return raw_bytes, mime


def _encode_image_base64(image_path: Path) -> str:
    """Read an image file and return base64-encoded string."""
    with open(image_path, "rb") as f:
        return base64.b64encode(f.read()).decode("utf-8")


def _get_image_mime(image_path: Path) -> str:
    """Get MIME type from image extension."""
    ext = image_path.suffix.lower()
    mime_map = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".webp": "image/webp",
        ".svg": "image/svg+xml",
        ".bmp": "image/bmp",
    }
    return mime_map.get(ext, "image/png")


# Retry prompts — progressively simpler for VLMs that struggle with complex prompts
_VLM_RETRY_PROMPTS = [
    # Attempt 0: full prompt (used in normal path)
    None,
    # Attempt 1: shorter, more direct
    (
        "Look at this diagram. List every box, arrow, and label you see. "
        "For each box, give its name and type (service, database, user, etc.). "
        "For each arrow, give source, destination, and the label text. "
        "Output as JSON with keys: components (list), data_flows (list), system_description (string)."
    ),
    # Attempt 2: absolute minimal
    (
        "Describe everything visible in this diagram: every shape, every label, "
        "every arrow and connection. Be exhaustive. Output as JSON."
    ),
]


def _abort_ollama_generation(model_name: str) -> None:
    """Send a trivial request to Ollama to flush the stuck VLM generation.

    Ollama processes requests serially per model. When a VLM call times out
    in the Python thread-pool the actual HTTP request keeps running on the
    Ollama side, blocking every subsequent call.  Sending a minimal
    ``/api/generate`` with ``keep_alive=0`` forces Ollama to finish (or
    discard) the current generation and unload the model from VRAM.
    """
    import os
    try:
        import requests as _req
        base = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
        logger.info(
            "[Architecture Parser] Sending abort/flush request to Ollama for model=%s",
            model_name,
        )
        _req.post(
            f"{base}/api/generate",
            json={"model": model_name, "prompt": "", "keep_alive": 0},
            timeout=15,
        )
        logger.info("[Architecture Parser] Ollama abort/flush completed for %s", model_name)
    except Exception as exc:
        logger.warning("[Architecture Parser] Ollama abort/flush failed: %s", exc)


def _invoke_vlm_for_image(
    vlm: BaseChatModel, image_path: Path, additional_context: str = "",
    *, image_timeout: int = 300, max_retries: int = 2,
) -> str:
    """Invoke the VLM with an image to extract architecture information.

    Includes automatic retry with progressively simpler prompts when the VLM
    returns empty or very short responses (common with some vision models).

    Args:
        vlm: Vision Language Model instance.
        image_path: Path to the image file.
        additional_context: Extra text context for the VLM.
        image_timeout: Max seconds to wait for VLM response per image.
                       0 means no limit.
        max_retries: Number of retries with simpler prompts on empty response.

    Raises:
        TimeoutError: If VLM takes longer than image_timeout.
    """
    model_name = getattr(vlm, "model", getattr(vlm, "model_name", "unknown"))
    file_size_mb = image_path.stat().st_size / (1024 * 1024)
    logger.info(
        "[Architecture Parser] VLM starting | model=%s | image=%s | file_size=%.2f MB",
        model_name, image_path.name, file_size_mb,
    )

    encode_start = time.perf_counter()
    img_bytes, mime = _maybe_resize_image(image_path)
    img_b64 = base64.b64encode(img_bytes).decode("utf-8")
    encode_elapsed = time.perf_counter() - encode_start
    logger.info(
        "[Architecture Parser] Image encoded to base64 in %.2fs | b64_size=%.1f KB",
        encode_elapsed, len(img_b64) / 1024,
    )

    primary_text = (
        "Analyze this architecture/system diagram thoroughly. "
        "Extract ALL components, services, data flows, trust boundaries, "
        "and connections visible in the diagram. "
        "Read ALL text labels, technology names, and protocol annotations. "
        "Do NOT identify threats, attacks, or vulnerabilities — only architecture. "
        f"{additional_context}"
        "\nRespond with the complete structured JSON architecture model."
    )

    def _do_vlm_call(prompt_text: str, attempt: int) -> str:
        human_content = [
            {
                "type": "image_url",
                "image_url": {"url": f"data:{mime};base64,{img_b64}"},
            },
            {
                "type": "text",
                "text": prompt_text,
            },
        ]
        messages = [
            SystemMessage(content=VLM_SYSTEM_PROMPT),
            HumanMessage(content=human_content),
        ]

        invoke_start = time.perf_counter()
        timeout_label = f"{image_timeout}s" if image_timeout else "unlimited"
        logger.info(
            "[Architecture Parser] VLM invoke attempt %d starting (timeout=%s)...",
            attempt + 1, timeout_label,
        )

        if image_timeout and image_timeout > 0:
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            try:
                future = executor.submit(with_logging_context(lambda: vlm.invoke(messages)))
                try:
                    response: AIMessage = future.result(timeout=image_timeout)
                except concurrent.futures.TimeoutError:
                    elapsed = time.perf_counter() - invoke_start
                    logger.error(
                        "[Architecture Parser] VLM TIMEOUT after %.0fs for %s "
                        "(limit=%ds, attempt %d) | model=%s",
                        elapsed, image_path.name, image_timeout, attempt + 1, model_name,
                    )
                    _abort_ollama_generation(model_name)
                    raise TimeoutError(
                        f"VLM timed out after {image_timeout}s for {image_path.name}"
                    ) from None
            finally:
                executor.shutdown(wait=False, cancel_futures=True)
        else:
            response = vlm.invoke(messages)

        invoke_elapsed = time.perf_counter() - invoke_start
        from agentictm.agents.base import ensure_str_content
        content = ensure_str_content(response.content)
        logger.info(
            "[Architecture Parser] VLM invoke attempt %d completed in %.1fs | response=%d chars",
            attempt + 1, invoke_elapsed, len(content),
        )
        return content

    # ── Main attempt ──
    result = _do_vlm_call(primary_text, 0)

    # ── Retry if empty / too short ──
    # A valid JSON architecture extraction should be at least ~50 chars
    for retry_num in range(1, max_retries + 1):
        if len(result.strip()) >= 50:
            break
        retry_prompt = _VLM_RETRY_PROMPTS[min(retry_num, len(_VLM_RETRY_PROMPTS) - 1)]
        if not retry_prompt:
            break
        logger.warning(
            "[Architecture Parser] VLM returned empty/short response (%d chars) for %s. "
            "Retrying with simpler prompt (attempt %d/%d)...",
            len(result.strip()), image_path.name, retry_num + 1, max_retries + 1,
        )
        try:
            result = _do_vlm_call(retry_prompt, retry_num)
        except (TimeoutError, Exception) as retry_exc:
            logger.warning(
                "[Architecture Parser] VLM retry %d failed for %s: %s",
                retry_num, image_path.name, retry_exc,
            )
            break

    if len(result.strip()) < 10:
        logger.warning(
            "[Architecture Parser] VLM returned empty after all attempts for %s",
            image_path.name,
        )

    return result


def _enrich_with_mermaid_parser(raw_input: str) -> str:
    """If the input is Mermaid, parse the components to assist the LLM."""
    try:
        from agentictm.parsers.mermaid_parser import parse_mermaid, mermaid_to_system_model

        result = parse_mermaid(raw_input)
        model = mermaid_to_system_model(result)
        return (
            f"The user provided a Mermaid diagram. The parser extracted:\n"
            f"{json.dumps(model, indent=2, ensure_ascii=False)}\n\n"
            f"Original Mermaid code:\n```mermaid\n{raw_input}\n```\n\n"
            f"Based on this information, complete and enrich the system model."
        )
    except Exception as exc:
        logger.warning("Mermaid parser failed, using raw text: %s", exc)
        return raw_input


# ---------------------------------------------------------------------------
# VLM output normalizer — converts free-form VLM JSON to canonical schema
# ---------------------------------------------------------------------------

def _normalize_vlm_output(raw: dict) -> dict:
    """Normalize a VLM JSON response into the canonical system-model schema.

    VLMs return wildly different formats, including threat-analysis-focused
    structures (threat_model.overview.key_components, stride_analysis.components,
    api_endpoints, etc.). This normalizer digs into ALL known structures to
    extract architecture information regardless of the VLM output format.

    Canonical output:
      components: list[{name, type, description, scope}]
      data_flows: list[{source, destination, protocol, data_type}]
      trust_boundaries: list[{name, components_inside, components_outside}]
      external_entities: list[...]
      data_stores: list[...]
      system_description: str
    """
    # ── Flatten nested structures first ──
    # VLMs often wrap everything under "threat_model", "architecture", etc.
    flat = raw
    for wrapper_key in ("threat_model", "architecture", "system_model", "model",
                        "system_architecture", "analysis"):
        if wrapper_key in raw and isinstance(raw[wrapper_key], dict):
            # Merge wrapper contents into top level (don't overwrite existing)
            for k, v in raw[wrapper_key].items():
                if k not in flat or not flat[k]:
                    flat[k] = v
            break  # only unwrap one level

    # Also look into overview/overview-like sub-objects
    for overview_key in ("overview", "threat_model_overview", "system_overview"):
        overview = flat.get(overview_key)
        if isinstance(overview, dict):
            for k, v in overview.items():
                if k not in flat or not flat[k]:
                    flat[k] = v

    normalized: dict = {}

    # ── system_description ──
    _raw_sd = (
        flat.get("system_description")
        or flat.get("description")
        or flat.get("purpose")
        or flat.get("title")
        or ""
    )
    if isinstance(_raw_sd, dict):
        _parts = [str(v) for v in _raw_sd.values() if v]
        _raw_sd = " ".join(_parts) if _parts else json.dumps(_raw_sd, ensure_ascii=False)
    elif isinstance(_raw_sd, list):
        _raw_sd = " ".join(str(item) for item in _raw_sd)
    normalized["system_description"] = str(_raw_sd)

    # ── components — mine from EVERY possible VLM structure ──
    raw_comps = (
        flat.get("components")
        or flat.get("nodes")
        or flat.get("entities")
        or []
    )
    components: list[dict] = []
    seen_names: set[str] = set()

    def _add_component(name: str, ctype: str = "process", desc: str = "", scope: str = "internal", **extra: Any):
        """Deduplicated component addition."""
        norm_name = name.strip()
        if not norm_name or norm_name.lower() in seen_names:
            return
        seen_names.add(norm_name.lower())
        entry = {"name": norm_name, "type": ctype, "description": desc, "scope": scope}
        entry.update(extra)
        components.append(entry)

    # Source 1: direct components list/dict
    if isinstance(raw_comps, dict):
        for name, info in raw_comps.items():
            if isinstance(info, dict):
                _add_component(name, info.get("type", "process"), info.get("description", ""), info.get("scope", "internal"))
            else:
                _add_component(name)
    elif isinstance(raw_comps, list):
        for item in raw_comps:
            if isinstance(item, dict):
                cname = item.get("name") or item.get("component") or item.get("type", "Unknown")
                _add_component(cname, item.get("type", "process"), item.get("description", ""), item.get("scope", "internal"))
            elif isinstance(item, str):
                _add_component(item)

    # Source 2: key_components (plain list of names)
    for kc_key in ("key_components", "critical_components", "main_components"):
        kc = flat.get(kc_key, [])
        if isinstance(kc, list):
            for item in kc:
                if isinstance(item, str):
                    _add_component(item)
                elif isinstance(item, dict):
                    _add_component(item.get("name", item.get("component", "")))

    # Source 3: stride_analysis.components (VLM threat-format)
    stride_comps = flat.get("stride_analysis", {})
    if isinstance(stride_comps, dict):
        for item in stride_comps.get("components", []):
            if isinstance(item, dict):
                _add_component(item.get("component", item.get("name", "")))

    # Source 4: threats_by_component (dict keys are component names)
    tbc = flat.get("threats_by_component", {})
    if isinstance(tbc, dict):
        for comp_name in tbc:
            clean = comp_name.replace("_", " ").title()
            _add_component(clean)

    # Source 5: api_endpoints (each endpoint group may name a component)
    api_eps = flat.get("api_endpoints", {})
    if isinstance(api_eps, dict):
        for key, val in api_eps.items():
            if key not in ("critical_endpoints",):
                clean = key.replace("_", " ").title()
                _add_component(clean, "process", f"Subsystem: {key}")
            if isinstance(val, dict):
                for ep in val.get("features", val.get("endpoints", [])):
                    pass  # features are just strings, not components
            elif isinstance(val, list):
                for ep in val:
                    if isinstance(ep, dict) and ep.get("endpoint"):
                        pass  # individual endpoints, not components
        # critical_endpoints
        for ep in api_eps.get("critical_endpoints", []):
            if isinstance(ep, dict) and ep.get("endpoint"):
                pass  # these are endpoints, not components

    # Source 6: existing_controls (may reference components)
    # (skip — controls are security artifacts, not architecture)

    normalized["components"] = components

    # ── data_flows ──
    raw_flows = (
        flat.get("data_flows")
        or flat.get("flows")
        or flat.get("edges")
        or flat.get("connections")
        or flat.get("critical_paths")
        or []
    )
    data_flows: list[dict] = []
    if isinstance(raw_flows, dict):
        # Nested dict format: {"flow_name": {edges: [...]}} or similar
        for _flow_name, flow_info in raw_flows.items():
            if isinstance(flow_info, dict):
                for edge in flow_info.get("edges", flow_info.get("sequence", [])):
                    if isinstance(edge, dict):
                        data_flows.append({
                            "source": edge.get("source_node", edge.get("source", "")),
                            "destination": edge.get("target_node", edge.get("destination", edge.get("target", ""))),
                            "protocol": edge.get("protocol", edge.get("action", "")),
                            "data_type": edge.get("data_type", ""),
                        })
            elif isinstance(flow_info, list):
                for edge in flow_info:
                    if isinstance(edge, dict):
                        data_flows.append({
                            "source": edge.get("source_node", edge.get("source", "")),
                            "destination": edge.get("target_node", edge.get("destination", edge.get("target", ""))),
                            "protocol": edge.get("protocol", edge.get("action", "")),
                            "data_type": edge.get("data_type", ""),
                        })
    elif isinstance(raw_flows, list):
        for item in raw_flows:
            if isinstance(item, dict):
                # Might be a high-level flow with nested edges
                if "edges" in item or "sequence" in item:
                    for edge in item.get("edges", item.get("sequence", [])):
                        if isinstance(edge, dict):
                            data_flows.append({
                                "source": edge.get("source_node", edge.get("source", "")),
                                "destination": edge.get("target_node", edge.get("destination", edge.get("target", ""))),
                                "protocol": edge.get("protocol", edge.get("action", "")),
                                "data_type": edge.get("data_type", ""),
                            })
                elif "source" in item or "source_node" in item:
                    data_flows.append({
                        "source": item.get("source", item.get("source_node", "")),
                        "destination": item.get("destination", item.get("target_node", item.get("target", ""))),
                        "protocol": item.get("protocol", item.get("action", "")),
                        "data_type": item.get("data_type", ""),
                    })
    normalized["data_flows"] = data_flows

    # ── trust_boundaries ──
    raw_tb = (
        flat.get("trust_boundaries")
        or flat.get("trustBoundaries")
        or flat.get("boundaries")
        or []
    )
    trust_boundaries: list[dict] = []
    if isinstance(raw_tb, list):
        for item in raw_tb:
            if isinstance(item, dict):
                tb_name = item.get("name") or item.get("type") or "Boundary"
                trust_boundaries.append({
                    "name": tb_name,
                    "description": item.get("description", ""),
                    "components_inside": item.get("components_inside", []),
                    "components_outside": item.get("components_outside", []),
                })
    normalized["trust_boundaries"] = trust_boundaries

    # ── external_entities ──
    raw_ext = flat.get("external_entities") or flat.get("externalEntities") or flat.get("threat_actors") or []
    if isinstance(raw_ext, list):
        normalized["external_entities"] = [
            e if isinstance(e, dict) else {"name": str(e)} for e in raw_ext
        ]
    else:
        normalized["external_entities"] = []

    # ── data_stores ──
    raw_ds = flat.get("data_stores") or flat.get("dataStores") or []
    if isinstance(raw_ds, list):
        normalized["data_stores"] = [
            d if isinstance(d, dict) else {"name": str(d)} for d in raw_ds
        ]
    else:
        normalized["data_stores"] = []

    # ── assumptions ──
    normalized["assumptions"] = flat.get("assumptions", [])

    logger.info(
        "[Architecture Parser] Normalized VLM output: "
        "components=%d | data_flows=%d | trust_boundaries=%d | external_entities=%d | data_stores=%d",
        len(normalized["components"]),
        len(normalized["data_flows"]),
        len(normalized["trust_boundaries"]),
        len(normalized["external_entities"]),
        len(normalized["data_stores"]),
    )

    return normalized


# ---------------------------------------------------------------------------
# Consolidation pass — text LLM merges VLM findings with user docs
# ---------------------------------------------------------------------------

_CONSOLIDATION_PROMPT = """\
You are a world-class principal architect.

Below is a system architecture model extracted by a Vision AI from diagrams,
plus the user's written system description / documentation.

The Vision AI may have MISSED some components, flows, or boundaries that are
described in the text documentation but not visible in the diagrams (or the
Vision AI failed on some images). Your job:

1. KEEP everything the Vision AI already found (do not remove components).
2. ADD any components, data_flows, trust_boundaries, external_entities, and
   data_stores that are described in the text documentation but MISSING from
   the Vision AI model.
3. ENRICH descriptions with details from the text documentation.
4. Produce a COMPLETE, UNIFIED architecture model.

Do NOT invent components not mentioned anywhere. Do NOT produce security/threat analysis.

Output full JSON with: system_description, components, data_flows,
trust_boundaries, external_entities, data_stores, deployment_info.
"""


def _consolidation_pass(
    llm: BaseChatModel,
    vlm_parsed: dict,
    text_context: str,
    vlm_failures: int,
    total_images: int,
) -> dict:
    """Run text LLM to merge VLM architecture model with user text docs.

    This ensures components described only in text (not in diagrams) are captured,
    and that partial VLM failures don't lose information.
    """
    from agentictm.agents.prompt_budget import PromptBudget

    has_vlm = bool(vlm_parsed.get("components") or vlm_parsed.get("data_flows"))

    pb = PromptBudget.from_llm(llm, system_prompt_chars=len(_CONSOLIDATION_PROMPT))
    vlm_budget = pb.section_budget("components")
    text_budget = pb.available_chars - vlm_budget - 500

    if has_vlm:
        vlm_summary = json.dumps(vlm_parsed, indent=2, ensure_ascii=False)
        vlm_summary = pb.truncate(vlm_summary, vlm_budget)
        vlm_block = f"## Vision AI Model (from diagrams)\n```json\n{vlm_summary}\n```\n\n"
    else:
        vlm_block = "## Vision AI Model\n(No components found in diagrams or no diagrams provided. Extract EVERYTHING from the User Documentation.)\n\n"

    failure_note = ""
    if vlm_failures > 0:
        failure_note = (
            f"\nNOTE: {vlm_failures}/{total_images} diagram images could NOT be analyzed "
            f"by the Vision AI. The text documentation may contain information about "
            f"components visible only in those failed diagrams — capture them."
        )

    human_prompt = (
        f"{vlm_block}"
        f"## User Documentation\n{pb.truncate(text_context, text_budget)}\n"
        f"{failure_note}\n\n"
        f"Produce the COMPLETE merged architecture model as JSON."
    )

    logger.info(
        "[Architecture Parser] Consolidation pass starting | "
        "VLM components=%d | text_context=%.1f KB | vlm_failures=%d/%d | "
        "budget=%d chars (vlm=%d, text=%d)",
        len(vlm_parsed.get("components", [])),
        len(text_context) / 1024,
        vlm_failures, total_images,
        pb.available_chars, vlm_budget, text_budget,
    )
    logger.info(
        "[Architecture Parser] Text LLM (consolidation) starting | model=%s",
        _model_name(llm),
    )

    t0 = time.perf_counter()
    response = invoke_agent(llm, _CONSOLIDATION_PROMPT, human_prompt, agent_name="Architecture Parser (consolidation)")
    elapsed = time.perf_counter() - t0

    consolidated = extract_json_from_response(response)
    if consolidated and isinstance(consolidated, dict):
        # Normalize in case the LLM returned different field names
        consolidated = _normalize_vlm_output(consolidated)

        old_count = len(vlm_parsed.get("components", []))
        new_count = len(consolidated.get("components", []))
        logger.info(
            "[Architecture Parser] Consolidation completed in %.1fs | "
            "components: %d -> %d | data_flows: %d -> %d",
            elapsed,
            old_count, new_count,
            len(vlm_parsed.get("data_flows", [])),
            len(consolidated.get("data_flows", [])),
        )
        return consolidated

    logger.warning(
        "[Architecture Parser] Consolidation pass failed to produce JSON (%.1fs), keeping VLM-only model",
        elapsed,
    )
    return vlm_parsed


def _assess_architecture_quality(model: dict) -> tuple[int, bool]:
    """Evaluate the quality of the parsed architecture model.

    Returns (score, clarification_needed).
    """
    # Use the existing triage scoring logic but on the reconstructed description
    # plus a weight for structured components found.
    desc = model.get("system_description", "")
    components = model.get("components", [])
    flows = model.get("data_flows", [])

    # Base score from text description (0-100)
    text_score, _ = _score_dimensions(desc)

    # Structured bonus (each component/flow adds to confidence)
    # A "good" model should have at least 4 components and 3 flows
    comp_score = min(40, len(components) * 10)
    flow_score = min(30, len(flows) * 10)

    # Final combined score (max 100)
    # 40% text depth, 60% structured richness
    final_score = int((text_score * 0.4) + (comp_score + flow_score))
    final_score = min(100, final_score)

    # Needs clarification if overall score is low OR we found almost nothing
    clarification_needed = final_score < 50 or len(components) < 3

    logger.info(
        "[Architecture Parser] Quality assessment: score=%d | components=%d | flows=%d | clarification_needed=%s",
        final_score, len(components), len(flows), clarification_needed
    )

    return final_score, clarification_needed


def run_architecture_parser(
    state: ThreatModelState,
    llm: BaseChatModel,
    vlm: BaseChatModel | None = None,
    *,
    vlm_image_timeout: int = 300,
) -> dict:
    """LangGraph node: Architecture Parser.

    Reads: raw_input
    Writes: system_description, components, data_flows, trust_boundaries,
            external_entities, data_stores, input_type, scope_notes, mermaid_dfd

    Args:
        state: Current graph state.
        llm: Quick thinker LLM for text analysis.
        vlm: Vision Language Model for image diagram analysis (optional).
        vlm_image_timeout: Max seconds per image for VLM (0 = no limit).
    """
    raw_input = state.get("raw_input", "")
    input_type = _detect_input_type(raw_input)

    logger.info("[Architecture Parser] Input type: %s | raw_input=%.1f KB", input_type, len(raw_input) / 1024)

    # Extract the text portion (strips image path lines) to use as context for VLM
    image_exts = (".png", ".jpg", ".jpeg", ".svg", ".webp", ".gif", ".bmp")
    text_lines = [
        l for l in raw_input.split("\n")
        if not any(l.strip().lower().endswith(ext) for ext in image_exts)
        and "--- Architecture Diagram Images ---" not in l
    ]
    text_context = "\n".join(text_lines).strip()
    logger.info("[Architecture Parser] Text context: %.1f KB | has_vlm=%s",
                len(text_context) / 1024, vlm is not None)

    phase_start = time.perf_counter()

    fast_mode = state.get("max_debate_rounds", 1) == 0

    if input_type in ("image", "mixed") and vlm:
        # Use VLM for image diagrams — also pass any text description as context
        image_paths = _find_image_paths(raw_input)
        logger.info("[Architecture Parser] Found %d image paths: %s",
                    len(image_paths), [p.name for p in image_paths])
        if image_paths:
            additional_context = (
                f"\nAdditional system description provided by the user:\n{text_context}\n"
                if text_context else ""
            )
            # Analyze each image and combine results
            all_responses = []
            vlm_failures = 0
            for img_path in image_paths:
                try:
                    vlm_response = _invoke_vlm_for_image(
                        vlm, img_path, additional_context,
                        image_timeout=vlm_image_timeout,
                    )
                    all_responses.append(vlm_response)
                    logger.info(
                        "[Architecture Parser] VLM analyzed: %s (%d chars)",
                        img_path.name, len(vlm_response),
                    )
                    # Log the full VLM output (visible in live panel)
                    logger.info("[Architecture Parser] VLM output:\n%s", vlm_response)
                except TimeoutError:
                    vlm_failures += 1
                    file_mb = img_path.stat().st_size / (1024 * 1024)
                    logger.warning(
                        "[Architecture Parser] VLM TIMEOUT - Image '%s' (%.1f MB) "
                        "skipped after %ds timeout. Consider using a smaller VLM "
                        "model or smaller images. %d/%d images failed so far.",
                        img_path.name, file_mb, vlm_image_timeout,
                        vlm_failures, len(image_paths),
                    )
                except Exception as exc:
                    vlm_failures += 1
                    logger.warning(
                        "[Architecture Parser] VLM failed for %s: %s", img_path.name, exc
                    )

            if vlm_failures > 0:
                logger.warning(
                    "[Architecture Parser] %d/%d VLM image calls failed/returned empty. "
                    "Successfully analyzed: %d images.",
                    vlm_failures, len(image_paths), len(all_responses),
                )

            if not all_responses and vlm_failures > 0:
                logger.warning(
                    "[Architecture Parser] ALL %d VLM image calls failed/timed out. "
                    "Falling back to text-only analysis. Tip: use a smaller VLM "
                    "model (e.g., llava:7b) or increase vlm_image_timeout.",
                    vlm_failures,
                )

            if all_responses:
                # Parse each VLM response individually and merge
                all_parsed: list[dict] = []
                for i, resp in enumerate(all_responses):
                    single = extract_json_from_response(resp)
                    if single and isinstance(single, dict):
                        all_parsed.append(single)
                    else:
                        logger.warning(
                            "[Architecture Parser] VLM response #%d could not be parsed as JSON (%d chars)",
                            i + 1, len(resp),
                        )

                if all_parsed:
                    # Merge multiple parsed JSONs (first one as base, append others' lists)
                    merged = all_parsed[0]
                    for extra in all_parsed[1:]:
                        for key in ("components", "data_flows", "trust_boundaries",
                                    "external_entities", "data_stores", "flows",
                                    "edges", "trustBoundaries", "threats",
                                    "threat_scenarios"):
                            existing = merged.get(key)
                            incoming = extra.get(key)
                            if incoming:
                                if isinstance(existing, list) and isinstance(incoming, list):
                                    merged[key] = existing + incoming
                                elif isinstance(existing, dict) and isinstance(incoming, dict):
                                    merged[key] = {**existing, **incoming}
                                elif incoming and not existing:
                                    merged[key] = incoming
                        # Prefer longer system_description
                        for desc_key in ("system_description", "description", "title"):
                            new_desc = extra.get(desc_key, "")
                            old_desc = merged.get(desc_key, "")
                            if len(str(new_desc)) > len(str(old_desc)):
                                merged[desc_key] = new_desc

                    logger.info(
                        "[Architecture Parser] Merged %d VLM JSON responses",
                        len(all_parsed),
                    )

                    # Normalize to canonical schema (handles dict-components,
                    # camelCase keys, missing fields, etc.)
                    parsed = _normalize_vlm_output(merged)
                    elapsed = time.perf_counter() - phase_start

                    comp_names = [c.get("name", "?") for c in parsed.get("components", [])]
                    logger.info(
                        '[Architecture Parser] VLM understood: "%s"',
                        parsed.get("system_description", "(no description)"),
                    )
                    logger.info(
                        "[Architecture Parser] VLM found components: %s",
                        ", ".join(comp_names) if comp_names else "(none)",
                    )
                    logger.info(
                        "[Architecture Parser] VLM JSON parsing SUCCESS | "
                        "components=%d | data_flows=%d | total_time=%.1fs",
                        len(parsed.get("components", [])),
                        len(parsed.get("data_flows", [])),
                        elapsed,
                    )

                    # ── Consolidation pass ──────────────────────────────
                    # Merges VLM findings with user text docs. Skip if VLM
                    # produced nothing (saves a long LLM call that would be
                    # doing the work from scratch anyway — text-only is faster).
                    _vlm_has_content = bool(parsed.get("components")) or bool(parsed.get("data_flows"))

                    if not _vlm_has_content and text_context and len(text_context) > 200:
                        logger.info(
                            "[Architecture Parser] VLM produced 0 components/flows. "
                            "Skipping VLM path entirely — falling through to text-only parsing."
                        )
                        # Do NOT return — fall through to text-only path below
                    else:
                        if fast_mode and _vlm_has_content:
                            logger.info(
                                "[Architecture Parser] Fast mode detected (max_debate_rounds=0). "
                                "Skipping consolidation pass for latency."
                            )
                        elif text_context and len(text_context) > 200 and _vlm_has_content:
                            try:
                                parsed = _consolidation_pass(
                                    llm, parsed, text_context, vlm_failures, len(image_paths),
                                )
                            except Exception as _consol_exc:
                                logger.warning(
                                    "[Architecture Parser] Consolidation pass failed (%s: %s). "
                                    "Using VLM-only data.",
                                    type(_consol_exc).__name__, _consol_exc,
                                )
                        mermaid_dfd = _generate_mermaid_dfd(parsed)
                        return {
                            "input_type": input_type,
                            "system_description": _ensure_str(parsed.get("system_description", "")),
                            "components": parsed.get("components", []),
                            "data_flows": parsed.get("data_flows", []),
                            "trust_boundaries": parsed.get("trust_boundaries", []),
                            "external_entities": parsed.get("external_entities", []),
                            "data_stores": parsed.get("data_stores", []),
                            "scope_notes": _build_scope_notes(parsed, raw_input),
                            "mermaid_dfd": mermaid_dfd,
                        }

                # None of the individual responses parsed as JSON;
                # combine raw text and let the text LLM restructure it
                combined = "\n\n".join(all_responses)
                logger.info("[Architecture Parser] VLM outputs not JSON, re-processing with text LLM...")
                human_prompt = (
                    f"A Vision AI analyzed architecture diagrams and provided these descriptions:\n\n"
                    f"{combined[:30000]}\n\n"
                    f"User also provided this system description:\n{text_context[:30000]}\n\n"
                    f"Based on ALL of the above, extract the complete structured JSON system model."
                )
                logger.info(
                    "[Architecture Parser] Text LLM (re-structure VLM output) starting | model=%s",
                    _model_name(llm),
                )
                try:
                    response = invoke_agent(llm, SYSTEM_PROMPT, human_prompt, agent_name="Architecture Parser")
                except Exception as _restruct_exc:
                    logger.warning(
                        "[Architecture Parser] VLM re-structure LLM failed (%s). Falling through to text-only.",
                        _restruct_exc,
                    )
                    response = ""
                parsed = extract_json_from_response(response) if response else None
                if parsed and isinstance(parsed, dict):
                    parsed = _normalize_vlm_output(parsed)
                    mermaid_dfd = _generate_mermaid_dfd(parsed)
                    return {
                        "input_type": input_type,
                        "system_description": _ensure_str(parsed.get("system_description", "")),
                        "components": parsed.get("components", []),
                        "data_flows": parsed.get("data_flows", []),
                        "trust_boundaries": parsed.get("trust_boundaries", []),
                        "external_entities": parsed.get("external_entities", []),
                        "data_stores": parsed.get("data_stores", []),
                        "scope_notes": _build_scope_notes(parsed, raw_input),
                        "mermaid_dfd": mermaid_dfd,
                    }
        else:
            logger.warning("[Architecture Parser] Input detected as %s but no valid image file paths found", input_type)
    elif input_type in ("image", "mixed") and not vlm:
        logger.warning("[Architecture Parser] Image/mixed input detected but no VLM configured. "
                   "Set vlm model in config (e.g., llava:7b) for diagram analysis. "
                       "Falling back to text analysis.")
        # Fall through to text analysis using the text portion
        raw_input = text_context if text_context else raw_input

    # Text-based analysis (text, mermaid, drawio, or fallback)
    logger.info("[Architecture Parser] Text-based analysis path | input_type=%s", input_type)
    if input_type == "mermaid":
        human_prompt = _enrich_with_mermaid_parser(raw_input)
    else:
        from agentictm.agents.prompt_budget import PromptBudget
        _pb = PromptBudget.from_llm(llm, system_prompt_chars=len(SYSTEM_PROMPT))
        _max_input_chars = _pb.available_chars - 200
        _truncated = _pb.truncate(raw_input, _max_input_chars) if len(raw_input) > _max_input_chars else raw_input
        if len(raw_input) > _max_input_chars:
            logger.warning(
                "[Architecture Parser] Input too large (%d chars). Truncating to %d chars for LLM (budget=%d).",
                len(raw_input), _max_input_chars, _pb.available_chars,
            )
        human_prompt = (
            f"Analyze the following system description and extract the complete model:\n\n"
            f"{_truncated}"
        )

    logger.info(
        "[Architecture Parser] Text LLM (primary parse) starting | model=%s | prompt=%.1f KB",
        _model_name(llm), len(human_prompt) / 1024,
    )

    try:
        response = invoke_agent(llm, SYSTEM_PROMPT, human_prompt, agent_name="Architecture Parser")
    except Exception as _text_llm_exc:
        elapsed = time.perf_counter() - phase_start
        logger.error(
            "[Architecture Parser] Text LLM FAILED after %.1fs (%s: %s). "
            "Returning minimal model from raw input.",
            elapsed, type(_text_llm_exc).__name__, _text_llm_exc,
        )
        _fallback_desc = raw_input[:5000] if len(raw_input) > 5000 else raw_input
        return {
            "input_type": input_type,
            "system_description": _fallback_desc,
            "components": [],
            "data_flows": [],
            "trust_boundaries": [],
            "external_entities": [],
            "data_stores": [],
            "scope_notes": _build_scope_notes(
                {},
                raw_input,
                f"Architecture parser LLM timed out ({type(_text_llm_exc).__name__}). Using raw input as description.",
            ),
        }

    parsed = extract_json_from_response(response)
    if parsed is None:
        elapsed = time.perf_counter() - phase_start
        logger.warning("[Architecture Parser] Could not extract valid JSON in %.1fs, trying regex component extraction", elapsed)
        extracted = _regex_extract_architecture(response)
        if extracted and len(extracted.get("components", [])) > 0:
            logger.info(
                "[Architecture Parser] Regex fallback recovered %d components, %d data_flows",
                len(extracted.get("components", [])),
                len(extracted.get("data_flows", [])),
            )
            return {
                "input_type": input_type,
                "system_description": extracted.get("system_description", _ensure_str(response)),
                "components": extracted.get("components", []),
                "data_flows": extracted.get("data_flows", []),
                "trust_boundaries": extracted.get("trust_boundaries", []),
                "external_entities": [],
                "data_stores": extracted.get("data_stores", []),
                "scope_notes": _build_scope_notes(extracted, raw_input, "Recovered via regex fallback from semi-broken JSON"),
            }
        logger.warning("[Architecture Parser] Regex fallback also failed, using raw response")
        return {
            "input_type": input_type,
            "system_description": _ensure_str(response),
            "components": [],
            "data_flows": [],
            "trust_boundaries": [],
            "external_entities": [],
            "data_stores": [],
            "scope_notes": _build_scope_notes({}, raw_input, "Parser could not extract structured JSON"),
        }

    if isinstance(parsed, dict):
        n_comp = len(parsed.get('components', []))
        n_flows = len(parsed.get('data_flows', []))
        quality_score, needs_clarification = _assess_architecture_quality(parsed)

        # ── Retry if the parse is severely incomplete ────────────────
        # The input clearly describes multiple components but the LLM
        # returned too few — often happens with MoE models in nothink mode.
        if needs_clarification and n_comp < 3 and len(raw_input) > 300:
            logger.warning(
                "[Architecture Parser] Low component count (%d) for %d-char input. "
                "Retrying with explicit extraction instructions...",
                n_comp, len(raw_input),
            )
            retry_prompt = (
                f"The following system description clearly mentions multiple components, "
                f"services, databases, and external entities. Your FIRST attempt only "
                f"extracted {n_comp} components — this is too few.\n\n"
                f"Re-analyze carefully and extract EVERY component, service, database, "
                f"queue, CDN, API gateway, function, and external entity mentioned.\n\n"
                f"System description:\n{raw_input[:30000]}"
            )
            try:
                retry_response = invoke_agent(llm, SYSTEM_PROMPT, retry_prompt, agent_name="Architecture Parser")
                retry_parsed = extract_json_from_response(retry_response)
                if isinstance(retry_parsed, dict):
                    retry_n = len(retry_parsed.get("components", []))
                    if retry_n > n_comp:
                        logger.info(
                            "[Architecture Parser] Retry improved: %d -> %d components",
                            n_comp, retry_n,
                        )
                        parsed = retry_parsed
                        n_comp = retry_n
                        n_flows = len(parsed.get("data_flows", []))
                        quality_score, needs_clarification = _assess_architecture_quality(parsed)
                    else:
                        logger.info("[Architecture Parser] Retry did not improve (%d components)", retry_n)
            except Exception as retry_exc:
                logger.warning("[Architecture Parser] Retry failed: %s", retry_exc)

        mermaid_dfd = _generate_mermaid_dfd(parsed) if input_type != "mermaid" else raw_input
        elapsed = time.perf_counter() - phase_start

        logger.info(
            "[Architecture Parser] COMPLETED in %.1fs | components=%d | data_flows=%d | score=%d | clarification=%s",
            elapsed, n_comp, n_flows, quality_score, needs_clarification,
        )

        return {
            "input_type": input_type,
            "system_description": _ensure_str(parsed.get("system_description", "")),
            "components": parsed.get("components", []),
            "data_flows": parsed.get("data_flows", []),
            "trust_boundaries": parsed.get("trust_boundaries", []),
            "external_entities": parsed.get("external_entities", []),
            "data_stores": parsed.get("data_stores", []),
            "scope_notes": _build_scope_notes(parsed, raw_input),
            "mermaid_dfd": mermaid_dfd,
            "quality_score": quality_score,
            "clarification_needed": needs_clarification,
        }

    return {"input_type": input_type}


def _generate_mermaid_dfd(model: dict) -> str:
    """Generate a Mermaid DFD from the parsed model."""
    try:
        lines = ["graph TD"]
        node_ids: dict[str, str] = {}

        # Create nodes
        for i, comp in enumerate(model.get("components", [])):
            if not isinstance(comp, dict):
                continue
            nid = f"C{i}"
            name = comp.get("name", f"Component_{i}")
            node_ids[name] = nid
            ctype = comp.get("type", "process")

            # Sanitize name for Mermaid (quote if special chars)
            safe_name = name.replace('"', "'")
            if ctype == "data_store":
                lines.append(f'    {nid}[("{safe_name}")]')
            elif ctype == "external_entity":
                lines.append(f'    {nid}(["{safe_name}"])')
            else:
                lines.append(f'    {nid}["{safe_name}"]')

        # Create edges
        for flow in model.get("data_flows", []):
            if not isinstance(flow, dict):
                continue
            src = node_ids.get(flow.get("source", ""), "?")
            dst = node_ids.get(flow.get("destination", ""), "?")
            proto = flow.get("protocol", "")
            if src != "?" and dst != "?":
                if proto:
                    safe_proto = str(proto).replace('"', "'")[:40]
                    lines.append(f'    {src} -->|"{safe_proto}"| {dst}')
                else:
                    lines.append(f"    {src} --> {dst}")

        # Create subgraphs for trust boundaries
        for tb in model.get("trust_boundaries", []):
            if not isinstance(tb, dict):
                continue
            tb_name = tb.get("name", "boundary")
            tb_id = tb_name.replace(" ", "_").replace("↔", "_").replace("<->", "_")
            inside = tb.get("components_inside", [])
            if inside:
                lines.append(f'    subgraph {tb_id}["{tb_name}"]')
                for comp_name in inside:
                    nid = node_ids.get(comp_name)
                    if nid:
                        lines.append(f"        {nid}")
                lines.append("    end")

        return "\n".join(lines)
    except Exception as exc:
        logger.warning("[Architecture Parser] Mermaid DFD generation failed: %s", exc)
        return "graph TD\n    A[System] --> B[Error generating DFD]"
