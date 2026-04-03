# ─────────────────────────────────────────────────────────────
# AgenticTM — Multi-Agent Threat Modeling System
# ─────────────────────────────────────────────────────────────
FROM python:3.13-slim AS base

LABEL maintainer="AgenticTM Team"
LABEL description="Multi-agent threat modeling system with RAG-enhanced analysis"

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# ── Install system deps (for PyMuPDF / fitz) ──
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libgl1 libglib2.0-0 curl && \
    rm -rf /var/lib/apt/lists/*

# ── Install Python deps first (cache-friendly layer) ──
COPY pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# ── Copy application code ──
COPY agentictm/ ./agentictm/
COPY config.json.example ./config.json
COPY run.py cli.py main.py ./

# ── Copy data directories ──
COPY knowledge_base/ ./knowledge_base/
COPY rag/ ./rag/

# ── Create writable directories ──
RUN mkdir -p /app/output /app/data/vector_stores

# ── Default environment (override via docker-compose or -e) ──
ENV AGENTICTM_OLLAMA_URL=http://ollama:11434 \
    AGENTICTM_OUTPUT_DIR=/app/output

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "agentictm.api.server:app", "--host", "0.0.0.0", "--port", "8000"]
