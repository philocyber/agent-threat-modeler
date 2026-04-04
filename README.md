<p align="center">
  <img src="logo-philocyber.png" alt="PhiloCyber" width="120" />
</p>

<h1 align="center">AgenticTM</h1>

<p align="center">
  Multi-agent threat modeling platform with LangGraph orchestration and local LLM support.
</p>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white" alt="Python" /></a>
  <a href="https://fastapi.tiangolo.com/"><img src="https://img.shields.io/badge/FastAPI-API-009688?logo=fastapi&logoColor=white" alt="FastAPI" /></a>
  <a href="https://github.com/langchain-ai/langgraph"><img src="https://img.shields.io/badge/LangGraph-Orchestration-121212" alt="LangGraph" /></a>
  <a href="https://ollama.com/"><img src="https://img.shields.io/badge/Ollama-Local%20LLMs-000000" alt="Ollama" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-A874C0" alt="License MIT" /></a>
</p>

---

## What is AgenticTM?

AgenticTM is an open-source, multi-agent system that performs end-to-end threat modeling on software architectures. It ingests system descriptions (text, Mermaid diagrams, Draw.io files, or architecture images), runs them through a coordinated pipeline of specialized AI agents, and produces prioritized threat reports with STRIDE classification and DREAD scoring.

The platform is **local-first** -- it runs entirely on your machine using [Ollama](https://ollama.com/) with no data leaving your network -- while also supporting cloud LLM providers (OpenAI, Anthropic, Google) when needed.

Built and maintained by [PhiloCyber](https://philocyber.com).

---

## Features

- **6-phase, 14-node analysis pipeline** -- architecture parsing, multi-methodology threat analysis, adversarial debate, synthesis, validation, and reporting
- **Multiple threat methodologies** -- STRIDE, PASTA, Attack Trees, MAESTRO (AI systems), and dedicated AI/ML threat analysis
- **Adversarial Red Team / Blue Team debate** with automatic convergence detection
- **DREAD scoring and validation** with asymmetric, realistic score distribution
- **RAG-enhanced analysis** -- retrieves context from security books, research papers, previous threat models, and AI threat databases
- **Three execution modes** -- `cascade`, `parallel`, or `hybrid` analyst orchestration
- **Web UI, REST API, and CLI** -- choose how you interact
- **Electron desktop app** for native macOS/Windows/Linux experience
- **Fully local** with Ollama, or connect to cloud providers

---

## Architecture

```text
Phase I     Architecture Parser (text + optional VLM for images)
              └─ Arch Clarifier (conditional, if quality is low)
Phase II    STRIDE | PASTA | Attack Tree | MAESTRO | AI Threat  (conditional)
Phase III   Red Team <-> Blue Team (N rounds, convergence cutoff)
Phase II.5  Attack Tree Enriched (post-debate)
Phase IV    Threat Synthesizer -> DREAD Validator
Phase V     Output Localizer -> Report Generator
```

For detailed documentation, see the [docs/](docs/) directory:
- [Pipeline architecture](docs/03_arquitectura_pipeline.md)
- [Agent details](docs/04_agentes.md)
- [RAG system](docs/05_sistema_rag.md)
- [Configuration reference](docs/08_configuracion.md)

---

## Quick Start

### Option A: One-liner with Make (macOS)

```bash
git clone https://github.com/PhiloCyber/agent-threat-modeler.git
cd agent-threat-modeler
make setup    # installs Ollama, pulls models, creates venv, installs deps, indexes KB
make run      # starts the server at http://localhost:8000
```

### Option B: Manual setup (all platforms)

#### 1. Prerequisites

- **Python 3.11+** ([python.org](https://www.python.org/downloads/))
- **Ollama** -- the local LLM runtime (not a pip package, installed at the system level)

Install Ollama:

```bash
# macOS
brew install ollama
brew services start ollama

# Linux
curl -fsSL https://ollama.com/install.sh | sh
systemctl start ollama    # or: ollama serve

# Windows
# Download from https://ollama.com/download
```

Verify Ollama is running:

```bash
curl http://localhost:11434/api/tags
```

#### 2. Pull models

```bash
# Chat models
ollama pull qwen3:4b         # ~2.7 GB, Quick Thinker (fast scans)
ollama pull qwen3.5:9b       # ~6.6 GB, Stride/VLM (multimodal, STRIDE/debate)
ollama pull gemma4:26b       # ~10 GB, Deep Thinker (MoE, synthesis)

# Embedding model for RAG (required)
ollama pull nomic-embed-text-v2-moe   # 8K context, multilingual MoE
```

**Model selection by available RAM:**

| RAM | Recommended config | Models |
|-----|-------------------|--------|
| 8 GB | Single model for all tiers | `qwen3:4b` |
| 16 GB | Quick + Stride/VLM | `qwen3:4b` + `qwen3.5:9b` |
| 32 GB | Full differentiated stack | `qwen3:4b` + `qwen3.5:9b` + `gemma4:26b` |
| 64 GB+ | Full stack, max parallelism | All models, `max_parallel_analysts: 5` |

#### 3. Clone and install

```bash
git clone https://github.com/PhiloCyber/agent-threat-modeler.git
cd agent-threat-modeler

python -m venv .venv
source .venv/bin/activate    # Linux/macOS
.venv\Scripts\activate     # Windows

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

### Option C: Docker

```bash
git clone https://github.com/PhiloCyber/agent-threat-modeler.git
cd agent-threat-modeler
docker compose up
```

This starts both the Ollama service and the AgenticTM API. The UI is available at `http://localhost:8000`.

> **Note:** You still need to pull models inside the Ollama container:
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

All settings can be overridden via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `AGENTICTM_OLLAMA_URL` | Ollama API base URL | `http://localhost:11434` |
| `AGENTICTM_OUTPUT_DIR` | Directory for analysis output | `./output` |
| `AGENTICTM_DATA_DIR` | Directory for vector stores, memory DBs | `./data` |
| `AGENTICTM_KB_DIR` | Knowledge base directory | `./knowledge_base` |
| `AGENTICTM_API_KEY` | API authentication key (optional) | none |
| `AGENTICTM_MAX_INPUT_LENGTH` | Max characters for input text | `100000` |
| `AGENTICTM_MAX_UPLOAD_MB` | Max upload file size in MB | `10` |
| `AGENTICTM_LOG_JSON` | Enable JSON-formatted logging | `false` |
| `AGENTICTM_HOST` | Server bind address | `127.0.0.1` |
| `AGENTICTM_CORS_ORIGINS` | Comma-separated allowed CORS origins | none |

---

## Knowledge Base and RAG

AgenticTM uses a Retrieval-Augmented Generation (RAG) system that enriches every agent's analysis with context from security literature, previous threat models, and AI threat databases.

### Directory structure

```text
knowledge_base/
├── books/                     # Security textbooks (PDF)
├── research/                  # Research papers and notes (MD, PDF)
├── ai_threats/                # AI/ML threat databases (PDF, JSON)
│   └── plot4ai_deck.json      # PLOT4ai threat catalog
├── previous_threat_models/    # Your past threat model CSVs
├── risks_mitigations/         # Threat control catalogs (CSV)
│   └── threats.csv
```

### Adding your own documents

1. Place PDF, Markdown, CSV, or JSON files into the appropriate subdirectory under `knowledge_base/`
2. Re-index manually if you want to pre-build everything up front:

```bash
python cli.py index

# or with Make:
make index
```

The indexer uses incremental hashing -- only new or changed files are re-indexed.
Analysis runs also auto-check for knowledge-base changes and incrementally re-index only what changed.

> **Public repo hygiene:** keep customer threat models, generated `rag/` outputs, local IDE logs, and secrets out of git. The repository should contain only public sample or reference material.

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

# With specific categories and output dir
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

### Project structure

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
knowledge_base/    # RAG source documents (gitignored data)
```

### Check system status

```bash
make status    # shows Python, Ollama, models, and server status
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `Connection refused` when analyzing | Ollama is not running. Start it with `brew services start ollama` (macOS) or `ollama serve` (Linux). Verify with `curl http://localhost:11434/api/tags` |
| `ollama: command not found` | Ollama is not installed. It's a system-level binary, not a pip package. See [Prerequisites](#1-prerequisites) |
| `model not found` | The model hasn't been pulled. Run `ollama pull <model>` (e.g., `ollama pull qwen3:4b`) |
| Analysis is slow | Use `cascade` mode with a smaller model, or try `hybrid` with `max_parallel_analysts: 2` |
| No RAG context in results | Run `python cli.py index` after adding documents to `knowledge_base/` |
| Port 8000 already in use | Kill the existing process: `lsof -ti :8000 \| xargs kill -9`, or use `python run.py --port 8001` |
| Empty threat list from synthesizer | Check that the LLM model is properly loaded. Try a simpler analysis first to verify connectivity |

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Acknowledgments

AgenticTM is built and maintained by [PhiloCyber](https://philocyber.com) -- a cybersecurity and AI security practice focused on practical, research-backed approaches to application security.

Built with [LangChain](https://langchain.com/), [LangGraph](https://github.com/langchain-ai/langgraph), [Ollama](https://ollama.com/), [FastAPI](https://fastapi.tiangolo.com/), and [ChromaDB](https://www.trychroma.com/).
