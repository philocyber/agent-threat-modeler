<p align="center">
  <img src="logo-philocyber.png" alt="PhiloCyber" width="120" />
</p>

<h1 align="center">AgenticTM</h1>

<p align="center">
  <strong>Multi-agent threat modeling platform with LangGraph orchestration and local LLM support.</strong>
</p>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white" alt="Python" /></a>
  <a href="https://fastapi.tiangolo.com/"><img src="https://img.shields.io/badge/FastAPI-API-009688?logo=fastapi&logoColor=white" alt="FastAPI" /></a>
  <a href="https://github.com/langchain-ai/langgraph"><img src="https://img.shields.io/badge/LangGraph-Orchestration-121212" alt="LangGraph" /></a>
  <a href="https://ollama.com/"><img src="https://img.shields.io/badge/Ollama-Local%20LLMs-000000" alt="Ollama" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-A874C0" alt="License MIT" /></a>
</p>

<p align="center">
  <img src="agenticTM.gif" alt="AgenticTM — end-to-end threat modeling pipeline dataflow" width="860" />
</p>

<p align="center">
  <em>Full pipeline dataflow: from architecture input to prioritized threat report, across 6 phases and 14 specialized agents.</em>
</p>

---

## Table of Contents

- [What is AgenticTM?](#what-is-agentictm)
- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [RAG Sources](#rag-sources)
- [Usage](#usage)
- [Outputs](#outputs)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## What is AgenticTM?

AgenticTM is an open-source, multi-agent system that performs **end-to-end threat modeling** on software architectures. Drop in a system description — plain text, Mermaid diagram, Draw.io file, or architecture image — and a coordinated pipeline of specialized AI agents produces a prioritized threat report with STRIDE classification and DREAD scoring.

The platform is **local-first**: it runs entirely on your machine using [Ollama](https://ollama.com/) with no data leaving your network. Cloud LLM providers (OpenAI, Anthropic, Google) are also supported when needed.

Built and maintained by [PhiloCyber](https://philocyber.com).

---

## Features

| Capability | Description |
|---|---|
| **6-phase, 14-node pipeline** | Architecture parsing → multi-methodology analysis → adversarial debate → synthesis → validation → reporting |
| **5 threat methodologies** | STRIDE, PASTA, Attack Trees, MAESTRO (AI systems), and dedicated AI/ML threat analysis |
| **Red Team ↔ Blue Team debate** | Adversarial rounds with automatic convergence detection |
| **DREAD scoring** | Asymmetric, realistic score distribution with validation |
| **RAG-enhanced analysis** | Security books, research papers, past threat models, and AI threat databases |
| **Three execution modes** | `cascade`, `parallel`, or `hybrid` analyst orchestration |
| **Multiple interfaces** | Web UI, REST API, and CLI |
| **Electron desktop app** | Native macOS / Windows / Linux experience |
| **Fully local or cloud** | Ollama for privacy-first use; OpenAI / Anthropic / Google when needed |

---

## Architecture

The pipeline runs in six sequential phases, each handled by one or more dedicated agents:

```text
Phase I     Architecture Parser (text + optional VLM for images)
              └─ Arch Clarifier (conditional, if quality is low)
Phase II    STRIDE | PASTA | Attack Tree | MAESTRO | AI Threat  (conditional)
Phase III   Red Team <-> Blue Team (N rounds, convergence cutoff)
Phase II.5  Attack Tree Enriched (post-debate)
Phase IV    Threat Synthesizer -> DREAD Validator
Phase V     Output Localizer -> Report Generator
```

<details>
<summary>Detailed documentation</summary>

| Document | Contents |
|---|---|
| [Pipeline architecture](docs/03_arquitectura_pipeline.md) | Phase-by-phase breakdown, state flow, conditional edges |
| [Agent details](docs/04_agentes.md) | Per-agent prompts, inputs, outputs, and dependencies |
| [RAG system](docs/05_sistema_rag.md) | Indexing strategy, retrievers, knowledge base layout |
| [Configuration reference](docs/08_configuracion.md) | All config keys, types, and defaults |

</details>

---

## Quick Start

### Option A — One-liner with Make (macOS)

```bash
git clone https://github.com/PhiloCyber/agent-threat-modeler.git
cd agent-threat-modeler
make setup    # installs Ollama, pulls models, creates venv, installs deps, indexes KB
make run      # starts the server at http://localhost:8000
```

### Option B — Manual setup (all platforms)

<details>
<summary>Step-by-step instructions</summary>

#### 1. Prerequisites

- **Python 3.11+** — [python.org](https://www.python.org/downloads/)
- **Ollama** — the local LLM runtime (system-level binary, not a pip package)

Install Ollama:

```bash
# macOS
brew install ollama
brew services start ollama

# Linux
curl -fsSL https://ollama.com/install.sh | sh
systemctl start ollama    # or: ollama serve

# Windows — download from https://ollama.com/download
```

Verify Ollama is running:

```bash
curl http://localhost:11434/api/tags
```

#### 2. Pull models

```bash
# Chat models
ollama pull qwen3:4b         # ~2.7 GB  — Quick Thinker (fast scans)
ollama pull qwen3.5:9b       # ~6.6 GB  — Deep + Stride/VLM (9B; synthesis shares weights with STRIDE)

# Embedding model for RAG (required)
ollama pull nomic-embed-text-v2-moe   # 8K context, multilingual MoE
```

**Model selection by available RAM:**

| RAM | Recommended config | Models |
|-----|-------------------|--------|
| 8 GB | Single model for all tiers | `qwen3:4b` |
| 16 GB | Full stack | `qwen3:4b` + `qwen3.5:9b` |
| 32 GB | Full stack, max parallelism | `qwen3:4b` + `qwen3.5:9b` |
| 64 GB+ | Full stack, max parallelism | All models, `max_parallel_analysts: 5` |

#### 3. Clone and install

```bash
git clone https://github.com/PhiloCyber/agent-threat-modeler.git
cd agent-threat-modeler

python -m venv .venv
source .venv/bin/activate    # Linux/macOS
.venv\Scripts\activate       # Windows

pip install -r requirements.txt
```

#### 4. Initialize and index

```bash
python cli.py init     # creates config.json tuned to your hardware
python cli.py index    # indexes the knowledge base for RAG
```

#### 5. Run

```bash
python run.py
```

Open [http://localhost:8000](http://localhost:8000) in your browser.

</details>

### Option C — Docker

```bash
git clone https://github.com/PhiloCyber/agent-threat-modeler.git
cd agent-threat-modeler
docker compose up
```

This starts both the Ollama service and the AgenticTM API. The UI is available at `http://localhost:8000`.

> [!NOTE]
> You still need to pull models inside the Ollama container after first launch:
> ```bash
> docker exec -it agent-threat-modeler-ollama-1 ollama pull qwen3:4b
> docker exec -it agent-threat-modeler-ollama-1 ollama pull nomic-embed-text-v2-moe
> ```

---

## Configuration

AgenticTM uses a `config.json` file for all settings. Running `python cli.py init` generates one automatically based on your system RAM.

To configure manually, copy the example:

```bash
cp config.json.example config.json
```

### Key configuration sections

| Section | Purpose |
|---------|---------|
| `quick_thinker` | Fast model for lightweight analysis steps |
| `deep_thinker` | Powerful model for synthesis and complex reasoning |
| `stride_thinker` | Model dedicated to STRIDE analysis |
| `vlm` | Vision-language model for architecture diagrams |
| `rag` | Knowledge base paths, embedding model, chunking parameters |
| `pipeline` | Debate rounds, execution mode, threat count targets |
| `memory` | Persistent memory database paths |
| `security` | Input size limits, API key |

### Environment variables

<details>
<summary>All supported environment variables</summary>

All settings can be overridden via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `AGENTICTM_OLLAMA_URL` | Ollama API base URL | `http://localhost:11434` |
| `AGENTICTM_OUTPUT_DIR` | Directory for analysis output | `./output` |
| `AGENTICTM_DATA_DIR` | Directory for vector stores, memory DBs | `./data` |
| `AGENTICTM_KB_DIR` | RAG sources directory | `./rag` |
| `AGENTICTM_API_KEY` | API authentication key (optional) | none |
| `AGENTICTM_MAX_INPUT_LENGTH` | Max characters for input text | `100000` |
| `AGENTICTM_MAX_UPLOAD_MB` | Max upload file size in MB | `10` |
| `AGENTICTM_LOG_JSON` | Enable JSON-formatted logging | `false` |
| `AGENTICTM_HOST` | Server bind address | `127.0.0.1` |
| `AGENTICTM_CORS_ORIGINS` | Comma-separated allowed CORS origins | none |

</details>

---

## RAG Sources

AgenticTM uses a Retrieval-Augmented Generation (RAG) system that enriches every agent's analysis with context from security literature, previous threat models, and AI threat databases.

### Directory structure

```text
rag/
├── books/                     # Security textbooks (PDF)
├── research/                  # Research papers and notes (MD, PDF)
├── ai_threats/                # AI/ML threat databases (PDF, JSON)
│   └── plot4ai_deck.json      # PLOT4ai threat catalog
├── previous_threat_models/    # Your past threat model CSVs
├── risks_mitigations/         # Threat control catalogs (CSV)
│   └── threats.csv
```

### Adding your own documents

1. Place PDF, Markdown, CSV, or JSON files into the appropriate subdirectory under `rag/`
2. Re-index:

```bash
python cli.py index
# or:
make index
```

The indexer uses incremental hashing — only new or changed files are re-indexed. Analysis runs also auto-check for RAG source changes and re-index only what changed.

> [!IMPORTANT]
> Keep customer threat models, local IDE logs, and secrets out of git. The repository should contain only public sample or reference material.

### Supported file types

| Format | Handled by |
|--------|------------|
| PDF | PyMuPDF (fitz) with page-level extraction |
| Markdown / Text | Direct text splitting |
| CSV | Row-level + full-file ingestion |
| JSON | Smart key extraction + PLOT4ai deck support |

---

## Usage

### Web UI

Navigate to `http://localhost:8000` after starting the server. The UI provides:

- New analysis creation with text input, file upload, or image upload
- Real-time progress tracking with per-agent status
- Interactive threat results with filtering and sorting
- DFD (Data Flow Diagram) visual editor
- Report export (CSV, Markdown, PDF)
- Analysis history and management

### CLI

```bash
# Analyze from text
python cli.py analyze -n "My System" -i "REST API with PostgreSQL, Redis, and JWT auth"

# Analyze from file
python cli.py analyze -n "My System" -f architecture.md

# With specific categories and output directory
python cli.py analyze -n "AWS App" -f desc.md --categories aws,ai,web -o ./results

# Fast mode (optimized prompts, fewer debate rounds)
python cli.py analyze -n "My System" -f architecture.md --mode fast

# Verbose output
python cli.py analyze -n "My System" -f architecture.mmd -v
```

### API

```bash
# Health check
curl http://localhost:8000/api/health

# Readiness probe (checks Ollama + vector stores)
curl http://localhost:8000/api/ready

# Start analysis (returns SSE stream)
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"system_name": "My API", "input": "REST API with auth and payments"}'

# Get results
curl http://localhost:8000/api/results/{analysis_id}
```

---

## Outputs

Each analysis produces artifacts in `output/<system_name>_<date>/`:

| File | Content |
|------|---------|
| `threat_model.csv` | Threat matrix with STRIDE categories and DREAD scores |
| `complete_report.md` | Full Markdown report including debate transcripts |
| `dfd.mermaid` | Generated Data Flow Diagram |
| `attachments/` | Uploaded input files |

Results are also persisted in `data/results.db` for the web UI history. Full structured results (JSON) are available via the API at `GET /api/results/{id}`.

---

## Development

### Running tests

```bash
python -m pytest tests/ -v

# Skip integration tests that require a running Ollama instance
python -m pytest tests/ -v --ignore=tests/test_api_integration.py
```

### Dev mode (auto-reload)

```bash
python run.py --reload
# or
make dev
```

### Check system status

```bash
make status    # shows Python, Ollama, models, and server status
```

### Project structure

<details>
<summary>Full directory layout</summary>

```text
agentictm/
├── agents/        # Analysis, debate, synthesis, validation, and output agents
├── api/           # FastAPI server + static frontend
│   └── static/    # Web UI (HTML/CSS/JS)
├── graph/         # LangGraph StateGraph construction and compilation
├── llm/           # LLM factory (quick/deep/stride/vlm model management)
├── rag/           # Indexing, vector stores, retrievers, and LangChain tools
├── parsers/       # Mermaid and Draw.io input parsers
├── state.py       # ThreatModelState (shared TypedDict)
├── config.py      # Configuration loading and validation
├── core.py        # Main orchestrator (AgenticTM class)
├── models.py      # UnifiedThreat and API response schemas
├── diagnostics.py # System diagnostics (Ollama, models, vector stores)
└── logging.py     # Structured logging setup

electron/          # Electron desktop app shell
docs/              # Detailed documentation (17 chapters)
tests/             # Unit and integration tests
rag/               # RAG source documents (gitignored data)
```

</details>

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `Connection refused` when analyzing | Ollama is not running. Start it: `brew services start ollama` (macOS) or `ollama serve` (Linux). Verify with `curl http://localhost:11434/api/tags` |
| `ollama: command not found` | Ollama is not installed — it's a system-level binary, not a pip package. See [Prerequisites](#1-prerequisites) |
| `model not found` | The model hasn't been pulled. Run `ollama pull <model>` (e.g., `ollama pull qwen3:4b`) |
| Analysis is slow | Use `cascade` mode with a smaller model, or `hybrid` with `max_parallel_analysts: 2` |
| No RAG context in results | Run `python cli.py index` after adding documents to `rag/` |
| Port 8000 already in use | Kill the process: `lsof -ti :8000 \| xargs kill -9`, or start on another port with `python run.py --port 8001` |
| Empty threat list from synthesizer | Verify the LLM model is loaded. Run a simpler analysis first to confirm Ollama connectivity |

> [!TIP]
> Run `make status` to get a full diagnostic snapshot: Python version, Ollama status, loaded models, and server health in one command.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Acknowledgments

AgenticTM is built and maintained by [PhiloCyber](https://philocyber.com) (Richie Prieto) — a Cybersecurity and AI security professional focused on practical, research-backed approaches to application security. If you have improvements ideas, suggestions, ways of doing this better please do not hesitate to contact me on linkedin or via [email](https://philocyber.com/contact).

Built with [LangChain](https://langchain.com/), [LangGraph](https://github.com/langchain-ai/langgraph), [Ollama](https://ollama.com/), [FastAPI](https://fastapi.tiangolo.com/), and [ChromaDB](https://www.trychroma.com/).
