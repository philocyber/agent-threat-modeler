# Electron Migration Plan — AgenticTM Desktop

> Target: M4 MacBook Pro (16GB) with local Ollama

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Electron App                          │
│  ┌─────────────────┐    ┌───────────────────────────┐   │
│  │  Renderer (UI)   │    │   Main Process            │   │
│  │  React/Vite      │◄──►│   - App lifecycle          │   │
│  │  Current SPA     │    │   - Ollama health monitor  │   │
│  │  (index.html)    │    │   - Native menus/dialogs   │   │
│  └────────┬─────────┘    │   - Auto-updater           │   │
│           │ IPC/fetch    │   - Tray icon               │   │
│           ▼              └───────────┬───────────────┘   │
│  ┌─────────────────────────────────┐ │                   │
│  │     FastAPI Backend (sidecar)    │◄┘                   │
│  │     python run.py :8765          │                     │
│  │     - All existing API endpoints │                     │
│  │     - SSE streaming              │                     │
│  │     - RAG + LangGraph pipeline   │                     │
│  └────────────┬────────────────────┘                     │
└───────────────┼──────────────────────────────────────────┘
                │ HTTP :11434
                ▼
         ┌─────────────┐
         │   Ollama     │
         │   (system)   │
         └─────────────┘
```

## Migration Strategy: Sidecar Pattern

The simplest and most reliable approach: **keep the FastAPI backend as-is** and spawn it as a sidecar process from Electron. The existing SPA frontend becomes the Electron renderer.

### Why Sidecar (not full rewrite)?

1. **Zero Python rewrite** — all 13 agents, RAG, LangGraph work unchanged
2. **SSE streaming already works** — the UI already consumes SSE events
3. **SQLite persistence already works** — results.db is file-based
4. **Tested codebase** — no regression risk from rewriting in Node.js
5. **Gradual migration** — can still run as web app in parallel

### Implementation Steps

#### Phase 1: Electron Shell (1-2 days)

```
electron-app/
├── package.json
├── main.js              # Electron main process
├── preload.js           # IPC bridge
├── forge.config.js      # electron-forge for packaging
└── src/
    └── index.html       # Copy of current SPA (or load from sidecar)
```

**main.js** responsibilities:
- Check Ollama is running (`http://localhost:11434/api/tags`)
- Spawn Python FastAPI sidecar (`python run.py --port 8765`)
- Create BrowserWindow pointing to `http://localhost:8765`
- Monitor sidecar health, restart on crash
- Handle app lifecycle (quit, minimize to tray)

#### Phase 2: Python Bundling (2-3 days)

Options for bundling Python with the Electron app:

| Approach | Pros | Cons |
|----------|------|------|
| **PyInstaller** | Single binary, no Python required | Large (~200MB), slow startup |
| **Embedded Python** | Small, fast, pip-installable | Needs Python framework bundled |
| **System Python + venv** | Simplest, smallest app | Requires Python pre-installed |
| **conda-pack** | Reproducible env | Large bundle |

**Recommended for M4 Mac**: Use `python-build-standalone` (prebuilt Python binaries) bundled inside the `.app`. The venv is created at first launch.

#### Phase 3: Ollama Management (1 day)

The Electron app should:
1. Detect if Ollama is installed (`which ollama`)
2. Check if Ollama is running (`http://localhost:11434/api/tags`)
3. If not running, prompt user to start it (or auto-start)
4. Verify required models are pulled
5. Show model download progress in the UI

#### Phase 4: Native Features (1-2 days)

- **Native menus**: File > Open, Export, etc.
- **Drag & drop**: Architecture files onto the app
- **System tray**: Show analysis progress
- **Notifications**: Alert when analysis completes
- **Auto-updater**: electron-updater for seamless updates

---

## Performance Optimizations for M4 16GB

Based on runtime profiling, these changes are critical:

### Already Implemented

| Change | Impact | Evidence |
|--------|--------|----------|
| `num_ctx: 8192` (reduced from 40960) | VRAM: 11.4GB → 6.55GB (43% reduction) | Ollama API `size_vram` confirmed |
| `reasoning: false` (disable thinking) | Standalone: 179s → 7s (25x faster) | Direct Ollama API test |
| `cascade` mode | No concurrent model loading | Prevents OOM on 16GB |
| `tree_summaries: false` | Faster RAG indexing | No LLM calls during index |
| Pre-invoke RAG tools | Preserves format="json" | Prevents 37K char markdown outputs |
| `num_predict: 4096/8192` | Caps runaway generation | Attack Tree was 37K chars |

### Recommended Next Steps

1. **Use qwen3:1.7b for quick tasks**: ~80-100 tok/s vs ~25 tok/s (3-4x faster)
2. **Optimize prompts**: Current prompts are 2-12KB; compress for 8K context
3. **Warm model pre-loading**: `ollama run qwen3:8b ""` at startup
4. **Skip non-applicable agents**: If no AI components, skip MAESTRO + AI Threat entirely

### Projected Analysis Times (M4 16GB, single model)

| Configuration | Estimated Time | Notes |
|--------------|---------------|-------|
| Before optimization | 50-60 min | 40K ctx, thinking on, 11.4GB VRAM |
| After optimization (qwen3:8b) | 15-20 min | 8K ctx, thinking off, 6.55GB VRAM |
| With qwen3:1.7b quick tier | 8-12 min | 1.7b for analysts, 8b for synth |
| Fully optimized | 5-8 min | Smaller prompts, skip unused agents |

---

## Config for M4 16GB Electron App

```json
{
  "quick_thinker": {
    "provider": "ollama",
    "model": "qwen3:8b",
    "num_ctx": 8192,
    "num_predict": 4096,
    "think": false,
    "num_gpu": -1
  },
  "deep_thinker": {
    "provider": "ollama",
    "model": "qwen3:8b",
    "num_ctx": 16384,
    "num_predict": 8192,
    "think": false,
    "num_gpu": -1
  },
  "pipeline": {
    "analyst_execution_mode": "cascade",
    "max_parallel_analysts": 1,
    "max_debate_rounds": 2,
    "self_reflection_enabled": false
  }
}
```

---

## Ollama Models for M4 16GB

Minimum required (disk: ~5.5GB):
```bash
ollama pull qwen3:8b           # 5.2 GB
ollama pull nomic-embed-text    # 274 MB
```

Full recommended (disk: ~12.7GB):
```bash
ollama pull qwen3:8b           # 5.2 GB
ollama pull qwen3-vl:8b        # 6.1 GB  (only if image analysis needed)
ollama pull nomic-embed-text    # 274 MB
```

Note: `qwen3:30b-a3b` and `deepseek-r1:14b` are NOT recommended for 16GB.
They cause severe memory pressure and model swapping overhead.
