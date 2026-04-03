# 06 — Modelos LLM

> Arquitectura de 4 tiers, LLMFactory, 5 providers, y recomendaciones de hardware.

---

## Arquitectura de 4 Tiers

AgenticTM organiza sus modelos LLM en **4 tiers funcionales**, cada uno optimizado para un tipo de tarea:

```mermaid
graph LR
    subgraph "Tier 1 — Quick"
        Q["qwen3:8b<br/>~5 GB VRAM<br/>Rápido, JSON"]
    end
    subgraph "Tier 2 — Deep"
        D["qwen3:30b-a3b<br/>~8 GB VRAM (MoE)<br/>Largo contexto"]
    end
    subgraph "Tier 3 — Stride/CoT"
        S["deepseek-r1:14b<br/>~9 GB VRAM<br/>Chain-of-Thought"]
    end
    subgraph "Tier 4 — VLM"
        V["qwen3-vl:8b<br/>~5 GB VRAM<br/>Vision"]
    end

    Q -->|"Analistas, Validator,<br/>Localizer"| PIPELINE["Pipeline"]
    D -->|"Synthesizer,<br/>Tree Enriched"| PIPELINE
    S -->|"STRIDE, Debate<br/>(Red/Blue)"| PIPELINE
    V -->|"Architecture Parser<br/>(imágenes)"| PIPELINE

    style Q fill:#1a3c34,stroke:#10b981,color:#fff
    style D fill:#2d1b4e,stroke:#8b5cf6,color:#fff
    style S fill:#1e3a5f,stroke:#4a90d9,color:#fff
    style V fill:#3b1d1d,stroke:#ef4444,color:#fff
```

### Detalle por Tier

| Tier | Config Key | Modelo Default | Parámetros | VRAM | Temperatura | Propósito |
|------|-----------|----------------|------------|------|-------------|-----------|
| **Quick** | `quick_thinker` | `qwen3:8b` | 8B densas | ~5 GB | 0.3 | Triage rápido, JSON estructurado |
| **Deep** | `deep_thinker` | `qwen3:30b-a3b` | 30B MoE (3.3B activos) | ~8 GB | 0.2 | Síntesis compleja, contexto largo (15-30K tokens) |
| **Stride/CoT** | `stride_thinker` | `deepseek-r1:14b` | 14B densas | ~9 GB | 0.3 | Chain-of-Thought visible, audit trail |
| **VLM** | `vlm` | `qwen3-vl:8b` | 8B + vision encoder | ~5 GB | 0.1 | Análisis de diagramas e imágenes |

### ¿Por Qué Qwen3:30b-a3b para Deep?

El modelo `qwen3:30b-a3b` usa **Mixture of Experts (MoE)**: tiene 30B de parámetros totales pero solo activa 3.3B en cada forward pass. Esto le da:
- **Capacidad** comparable a un modelo de ~30B (amplia knowledge base)
- **Velocidad** comparable a un modelo de ~4B (solo 3.3B activos)
- **VRAM** de ~8 GB (carga todo pero solo computa una fracción)

Es ideal para el Synthesizer, que recibe 15-30K tokens de contexto de 5 analistas + debate.

### ¿Por Qué DeepSeek-R1 para STRIDE y Debate?

DeepSeek-R1 es un modelo **always-on Chain-of-Thought**: genera su razonamiento de forma nativa (visible en tags `<think>...</think>`). Esto proporciona:
- **Audit trail** para STRIDE — se puede ver cómo el modelo razonó cada categoría
- **Transparencia en el debate** — el CoT del Red/Blue Team muestra la lógica detrás de escalaciones y disputas

`_strip_think_tags()` en `base.py` limpia estos tags del output final.

---

## LLMFactory (`agentictm/llm/__init__.py`, 165 líneas)

### Propiedades Cacheadas

La factory crea y cachea 7 instancias de LLM:

```python
class LLMFactory:
    @property
    def quick(self) -> BaseChatModel:
        """LLM rápido para analistas (free-text)."""
        
    @property
    def quick_json(self) -> BaseChatModel:
        """LLM rápido con format=json."""
        
    @property
    def deep(self) -> BaseChatModel:
        """LLM deep para Synthesizer (free-text)."""
        
    @property
    def deep_json(self) -> BaseChatModel:
        """LLM deep con format=json."""
        
    @property
    def stride(self) -> BaseChatModel:
        """LLM CoT para STRIDE/debate (free-text)."""
        
    @property
    def stride_json(self) -> BaseChatModel:
        """LLM CoT con format=json."""
        
    @property
    def vlm(self) -> BaseChatModel:
        """Vision Language Model."""
```

Cada property usa `_get_or_create(key, cfg, format_override)` para crear la instancia una sola vez.

### `format_override="json"`

Para los tiers `*_json`, se pasa `format="json"` a Ollama, lo que fuerza al modelo a producir JSON válido. Esto es **significativamente más confiable** que depender del prompt para obtener JSON.

---

## 5 Providers Soportados

| Provider | Import | Config |
|----------|--------|--------|
| **Ollama** (default) | `langchain_ollama.ChatOllama` | `provider: "ollama"`, `base_url: "http://localhost:11434"` |
| **Anthropic** | `langchain_anthropic.ChatAnthropic` | `provider: "anthropic"`, `api_key: "sk-..."` |
| **Google** | `langchain_google_genai.ChatGoogleGenerativeAI` | `provider: "google"`, `api_key: "AIza..."` |
| **OpenAI** | `langchain_openai.ChatOpenAI` | `provider: "openai"`, `api_key: "sk-..."` |
| **Azure OpenAI** | `langchain_openai.AzureChatOpenAI` | `provider: "azure"`, `base_url: "https://xxx.openai.azure.com"`, `api_key: "..."` |

### Instalación de Providers Cloud

Los providers cloud son **dependencias opcionales**:

```bash
# Solo Ollama (default, ya incluido)
pip install .

# Con providers cloud
pip install ".[cloud]"
# Instala: langchain-anthropic, langchain-google-genai, langchain-openai
```

### Ejemplo: Configuración Híbrida

```json
{
  "quick_thinker": {
    "provider": "ollama",
    "model": "qwen3:8b",
    "base_url": "http://localhost:11434"
  },
  "deep_thinker": {
    "provider": "anthropic",
    "model": "claude-sonnet-4-20250514",
    "api_key": "sk-ant-..."
  },
  "stride_thinker": {
    "provider": "ollama",
    "model": "deepseek-r1:14b",
    "base_url": "http://localhost:11434"
  },
  "vlm": {
    "provider": "google",
    "model": "gemini-2.0-flash",
    "api_key": "AIza..."
  }
}
```

En este ejemplo, los analistas rápidos corren local (Ollama), el Synthesizer usa Claude (Anthropic) y el VLM usa Gemini.

---

## Modelos Ollama Requeridos

### Descarga

```bash
# Requeridos
ollama pull qwen3:8b           # Quick Thinker — ~4.9 GB download
ollama pull qwen3:30b-a3b      # Deep Thinker — ~17.7 GB download
ollama pull deepseek-r1:14b    # Stride/CoT    — ~9.0 GB download
ollama pull qwen3-vl:8b        # Vision LLM    — ~5.2 GB download
ollama pull nomic-embed-text   # Embeddings    — ~274 MB download

# Total: ~37 GB de disco
```

### Verificación

```bash
# Ver modelos instalados
ollama list

# Probar un modelo
ollama run qwen3:8b "Hola, ¿funciona?"
```

### Control de GPU

El campo `num_gpu` controla cuántas capas se cargan en GPU:

```json
{
  "deep_thinker": {
    "model": "qwen3:30b-a3b",
    "num_gpu": -1    // -1 = todas las capas en GPU (100% VRAM)
  },
  "quick_thinker": {
    "model": "qwen3:8b",
    "num_gpu": null  // null = Ollama decide automáticamente
  }
}
```

| Valor | Significado |
|-------|-------------|
| `null` | Ollama decide automáticamente (default) |
| `-1` | Todas las capas en GPU (máxima velocidad, máxima VRAM) |
| `0` | Todas las capas en CPU (sin GPU, más lento) |
| `N > 0` | Exactamente N capas en GPU (rest en CPU) |

---

## Recomendaciones de Hardware

### GPU por Presupuesto

| VRAM | Configuración Recomendada |
|------|---------------------------|
| **8 GB** | `quick_thinker` = qwen3:8b, `deep_thinker` = qwen3:8b (sin diferenciación real), `max_parallel_analysts` = 1, `analyst_execution_mode` = cascade |
| **16 GB** | `quick_thinker` = qwen3:8b, `deep_thinker` = qwen3:30b-a3b, `max_parallel_analysts` = 2, `analyst_execution_mode` = hybrid |
| **24 GB** | Mismo que 16 GB pero con `max_parallel_analysts` = 3 |
| **32+ GB** | Full parallel, `max_parallel_analysts` = 5 |

### Consumo Estimado por Fase

| Fase | Modelos Activos | VRAM Pico (hybrid, max=2) |
|------|----------------|---------------------------|
| I | quick_json + vlm (si hay imágenes) | ~10 GB |
| II | 2× quick_json (throttled) | ~10 GB |
| III | stride | ~9 GB |
| II.5 | deep_json | ~8 GB |
| IV | deep_json → quick_json | ~8 GB → ~5 GB |
| V | quick_json (localizer) | ~5 GB |

> **Nota**: Ollama gestiona la carga/descarga de modelos automáticamente. Cuando un modelo no se usa, Ollama lo puede descargar de VRAM para hacer espacio.

### Configuraciones Probadas

| Hardware | Tiempo típico (sistema mediano) | Config |
|----------|-------------------------------|--------|
| RTX 4090 (24 GB) | 15-25 min | hybrid, max=2, todos los modelos |
| RTX 3080 (10 GB) | 25-40 min | hybrid, max=1, quick=deep=qwen3:8b |
| Apple M2 Ultra (64 GB unified) | 10-20 min | hybrid, max=3, todos los modelos |
| CPU only (32 GB RAM) | 60-120 min | cascade, quick=deep=qwen3:4b |

---

## Timeouts

| Configuración | Default | Descripción |
|---------------|---------|-------------|
| `timeout` (por LLM) | 300s (quick), 600s (deep/stride/vlm) | HTTP client timeout para Ollama |
| `vlm_image_timeout` | 600s (quick), 1200s (vlm) | Per-image VLM timeout (imágenes grandes 6+ MB) |

Si un modelo tarda más que el timeout, la request falla y `_safe_node` maneja el error (degradación graciosa para nodos no-críticos).

---

*[← 05 — Sistema RAG](05_sistema_rag.md) · [07 — API y Frontend →](07_api_y_frontend.md)*
