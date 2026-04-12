# ─────────────────────────────────────────────────────────────
# AgenticTM — Multi-Agent Threat Modeling System
# ─────────────────────────────────────────────────────────────
FROM python:3.13-slim AS base

LABEL maintainer="AgenticTM Team"
LABEL description="Multi-agent threat modeling system with RAG-enhanced analysis"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libgl1 libglib2.0-0 curl && \
    rm -rf /var/lib/apt/lists/*

# ── Install deps first (layer cache: only re-runs when pyproject.toml changes) ──
COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir ".[cloud]"

# ── Copy application source + data ──
COPY agentictm/ ./agentictm/
COPY config.json.example ./config.json
COPY run.py cli.py main.py ./
COPY rag/ ./rag/

# ── Non-root user for defense-in-depth ──
RUN groupadd -r agentictm && useradd -r -g agentictm -s /sbin/nologin agentictm && \
    mkdir -p /app/output /app/data/vector_stores /app/data/page_indices /app/logs && \
    chown -R agentictm:agentictm /app

ENV AGENTICTM_OLLAMA_URL=http://ollama:11434 \
    AGENTICTM_OUTPUT_DIR=/app/output \
    AGENTICTM_OUTPUT=/app/output

EXPOSE 8000

USER agentictm

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "agentictm.api.server:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
