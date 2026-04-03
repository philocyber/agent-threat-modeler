# 12 — Troubleshooting

> Errores comunes, FAQ, glosario, y tips de performance.

---

## Errores Comunes

### Ollama

| Error | Causa | Solución |
|-------|-------|----------|
| `Cannot connect to Ollama at http://localhost:11434` | Ollama no está corriendo | Iniciar Ollama: `ollama serve` o abrir la app |
| `Model 'qwen3:8b' not found` | Modelo no descargado | `ollama pull qwen3:8b` |
| `CUDA out of memory` / OOM kill | VRAM insuficiente para el modelo | Reducir `num_gpu`, usar modelos más chicos, o cambiar a `cascade` mode |
| `Connection reset by peer` | Ollama crasheó durante inferencia | Revisar logs de Ollama (`ollama logs`), reiniciar Ollama |
| `Request timeout after 300s` | Modelo muy lento (CPU-only, modelo grande) | Aumentar `timeout` en config.json, usar modelos más chicos |
| `too many open files` | Muchos modelos cargados simultáneamente | Reducir `max_parallel_analysts` a 1, reiniciar Ollama |

#### Verificar Ollama

```bash
# ¿Está corriendo?
curl http://localhost:11434/api/tags

# ¿Qué modelos hay?
ollama list

# ¿Funciona un modelo?
ollama run qwen3:8b "test"
```

### Pipeline

| Error | Causa | Solución |
|-------|-------|----------|
| `Architecture Parser failed` (pipeline aborta) | Input incompleto o formato no reconocido | Mejorar la descripción del sistema. Incluir componentes y flujos de datos explícitos |
| `JSON parse error in agent X` | LLM no produjo JSON válido | Verificar que el agente use `*_json` tier. Reintentar — es estocástico |
| `No threats generated` | Synthesizer recibió poco contexto | Dar más detalle en el input. Verificar que los analistas no fallaron (ver logs) |
| `Debate stuck in loop` | `max_debate_rounds` muy alto + sistema complejo | Reducir `max_debate_rounds` a 4 |
| Amenazas en inglés | `output_language` no es `"es"` | Verificar `pipeline.output_language: "es"` en config.json |
| Pocas amenazas (<8) | Input insuficiente o categorías incorrectas | Mejorar input, usar `"auto"` como categoría, aumentar `target_threats` |

### API / Frontend

| Error | Causa | Solución |
|-------|-------|----------|
| `Port 8000 already in use` | Proceso previo no se cerró | `python run.py` auto-kill en Windows. O manualmente: `netstat -ano \| findstr :8000` → `taskkill /F /PID {pid}` |
| `401 Unauthorized` | API key incorrecta o no configurada | Verificar `X-API-Key` header. Si no querés auth, dejar `security.api_key: null` |
| Frontend muestra datos del análisis anterior | Cache stale | Hacer hard refresh (Ctrl+Shift+R). En v0.3.2 `_clearResultPanels()` resuelve esto |
| Mermaid diagram no renderiza | Código Mermaid inválido | El sanitizer intenta arreglarlo automáticamente. Si falla, muestra el código fuente como fallback |
| SSE se desconecta | Proxy nginx/Cloudflare buffering | Agregar header `X-Accel-Buffering: no` (ya incluido en server) |
| Upload rechazado | Extensión no permitida o tamaño excedido | Verificar `security.allowed_extensions` y `security.max_upload_size_mb` |

### RAG / Indexación

| Error | Causa | Solución |
|-------|-------|----------|
| `No vector stores found` | Knowledge base no indexada | Ejecutar: `python cli.py index` |
| Indexación muy lenta | PDFs grandes, tree summaries habilitados | Desactivar `tree_summaries: false` para acelerar. Reducir `max_summary_nodes` |
| `nomic-embed-text not found` | Modelo de embeddings no descargado | `ollama pull nomic-embed-text` |
| RAG retorna resultados irrelevantes | Chunks muy grandes, top_k muy bajo | Reducir `chunk_size` a 500, aumentar `retrieval_top_k` a 10 |

---

## FAQ

### General

**¿Cuánto tarda un análisis típico?**
> 15-40 minutos dependiendo del hardware, complejidad del sistema, y número de debate rounds. Con GPU de 24 GB y hybrid mode, un sistema mediano tarda ~20 minutos.

**¿Necesito GPU?**
> Technically no. Puede correr 100% en CPU con modelos chicos (`qwen3:4b`), pero el tiempo sube a 60-120 minutos. Con GPU es 3-5x más rápido.

**¿Qué pasa si Ollama se queda sin VRAM?**
> Ollama automáticamente descarga modelos inactivos de VRAM cuando necesita espacio. Si aún así hay OOM, reducí `max_parallel_analysts` a 1 y usá `cascade` mode.

**¿Puedo usar modelos de OpenAI/Anthropic/Google?**
> Sí. Configurá el provider en config.json para cada tier. Ver [08 — Configuración](08_configuracion.md).

**¿Es necesario indexar la knowledge base?**
> No es obligatorio, pero mejora significativamente la calidad de las mitigaciones y la relevancia de las amenazas detectadas.

### Modelos

**¿Puedo usar un solo modelo para todo?**
> Sí. Poné el mismo modelo en los 4 tiers. Funciona, pero pierde las ventajas de especialización.

**¿Qué modelo es el mínimo viable?**
> `qwen3:8b` o incluso `qwen3:4b` para todo. La calidad baja pero el pipeline funciona end-to-end.

**¿Por qué DeepSeek-R1 para STRIDE/debate?**
> Su Chain-of-Thought siempre visible genera un audit trail — se puede ver exactamente cómo razonó cada categoría STRIDE.

**¿Puedo usar Llama, Mistral u otros modelos?**
> Sí, cualquier modelo disponible en Ollama funciona. Los prompts están diseñados para modelos instruction-following genéricos.

### Pipeline

**¿Qué hace el debate exactamente?**
> Red Team ataca (busca amenazas no cubiertas, escalaciones, cadenas de ataque). Blue Team defiende (propone controles, rebate). El resultado enriquece la síntesis final con perspectivas adversariales.

**¿MAESTRO siempre se activa?**
> No. Solo si el input contiene keywords de AI/ML (~30 términos como "LLM", "model", "agent", "prompt", "neural", etc.).

**¿Puedo desactivar agentes?**
> MAESTRO y AI Threat se activan condicionalmente basados en el input. Los otros 3 (STRIDE, PASTA, Attack Tree) siempre corren.

---

## Glosario

| Término | Definición |
|---------|------------|
| **STRIDE** | Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege — framework de Microsoft para threat modeling |
| **PASTA** | Process for Attack Simulation and Threat Analysis — framework de 7 etapas orientado a ataques |
| **DREAD** | Damage, Reproducibility, Exploitability, Affected Users, Discoverability — scoring de riesgo (0-50) |
| **MAESTRO** | CSA's Multi-Agent Environment Security Threat, Risk, and Opportunity — 7 capas para sistemas AI |
| **MoE** | Mixture of Experts — arquitectura que solo activa una fracción de los parámetros por forward pass |
| **CoT** | Chain-of-Thought — técnica donde el modelo genera su razonamiento paso a paso |
| **VLM** | Vision Language Model — modelo que puede procesar texto + imágenes |
| **DFD** | Data Flow Diagram — diagrama de flujo de datos entre componentes |
| **RAG** | Retrieval-Augmented Generation — técnica que complementa el LLM con información recuperada de documentos |
| **SSE** | Server-Sent Events — protocolo de streaming unidireccional server→client |
| **Fan-out** | Patrón donde un nodo dispara múltiples nodos concurrentemente |
| **Fan-in** | Patrón donde múltiples nodos convergen y sus outputs se fusionan |
| **Trust Boundary** | Frontera lógica entre componentes con diferente nivel de confianza |
| **CAPEC** | Common Attack Pattern Enumeration and Classification |
| **CWE** | Common Weakness Enumeration |
| **ATT&CK** | MITRE Adversarial Tactics, Techniques, and Common Knowledge |
| **PLOT4ai** | Privacy Library of Threats for Artificial Intelligence |
| **WEI** | Weighted Exploitability Index — métrica de AI Agent Protocol Security |
| **RPS** | Risk Priority Score — métrica de AI Agent Protocol Security |
| **PageIndex** | Índice jerárquico en árbol para documentos largos (alternativa a chunking plano) |

---

## Tips de Performance

### Reducir Tiempo de Análisis

1. **Usar `cascade` mode** si tenés poca VRAM — evita intercambio de modelos
2. **Reducir `max_debate_rounds`** a 2-3 para análisis rápidos
3. **Desactivar self-reflection** (`self_reflection_enabled: false`)
4. **Usar modelos más chicos** si la calidad es suficiente (qwen3:4b)
5. **Pre-cargar modelos**: `ollama run qwen3:8b ""` antes del análisis carga el modelo en VRAM

### Mejorar Calidad

1. **Más contexto en el input** — describir componentes, tecnologías, flujos, trust boundaries
2. **Subir diagramas de arquitectura** — el VLM extrae información adicional
3. **Indexar knowledge base** — mejora mitigaciones con contexto real
4. **Usar categorías específicas** — `aws,ai,web` es mejor que `auto` si conocés tu stack
5. **Aumentar debate rounds** a 6-8 para análisis profundos
6. **Usar deep_thinker diferenciado** — qwen3:30b-a3b o un modelo cloud para el Synthesizer

### Monitorear Recursos

```bash
# GPU usage (Windows)
nvidia-smi -l 1

# GPU usage (Linux)
watch -n 1 nvidia-smi

# Ollama process info
ollama ps
```

---

## Estructura de Archivos de Referencia

```
AgenticTM/
├── cli.py                          # CLI Typer (analyze, index, init)
├── run.py                          # Server launcher (uvicorn + SO_REUSEADDR)
├── main.py                         # Entrypoint alternativo
├── config.json                     # Configuración del proyecto
├── pyproject.toml                  # Python project metadata + deps
├── requirements.txt                # Pinned dependencies
├── Dockerfile                      # Python 3.13-slim container
├── docker-compose.yml              # App + Ollama services
├── agentictm/
│   ├── __init__.py
│   ├── config.py                   # Pydantic config models
│   ├── core.py                     # AgenticTM orchestrator class
│   ├── models.py                   # UnifiedThreat, API schemas
│   ├── state.py                    # ThreatModelState TypedDict
│   ├── agents/
│   │   ├── base.py                 # BaseAgent (invoke_agent, JSON extraction)
│   │   ├── architecture_parser.py  # Phase I — structure extraction
│   │   ├── stride_analyst.py       # Phase II — STRIDE per-element
│   │   ├── pasta_analyst.py        # Phase II — 7-stage PASTA
│   │   ├── attack_tree_analyst.py  # Phase II/II.5 — dual-mode trees
│   │   ├── maestro_analyst.py      # Phase II — CSA MAESTRO (conditional)
│   │   ├── ai_threat_analyst.py    # Phase II — 6 frameworks (conditional)
│   │   ├── debate.py               # Phase III — Red/Blue Team
│   │   ├── threat_synthesizer.py   # Phase IV — unification + dedup
│   │   ├── dread_validator.py      # Phase IV — scoring + 80% guardrail
│   │   ├── output_localizer.py     # Phase V — ES translation
│   │   └── report_generator.py     # Phase VI — CSV + MD + LaTeX
│   ├── graph/
│   │   └── builder.py              # LangGraph graph construction
│   ├── llm/
│   │   └── __init__.py             # LLMFactory (7 cached properties)
│   ├── api/
│   │   ├── server.py               # FastAPI (28+ routes, SSE, auth)
│   │   ├── storage.py              # SQLite ResultStore
│   │   └── static/
│   │       └── index.html          # SPA (2235 lines)
│   ├── rag/
│   │   ├── __init__.py             # RAGStoreManager
│   │   ├── tools.py                # 5 RAG tools, 6 tool sets
│   │   └── categories.py           # 9 categories with keyword detection
│   └── parsers/                    # Mermaid parser utilities
├── knowledge_base/
│   ├── books/                      # Security PDFs
│   ├── research/                   # Academic papers
│   ├── risks_mitigations/          # CAPEC/CWE/NIST by category
│   ├── previous_threat_models/     # Team's prior TMs (.csv)
│   └── ai_threats/                 # PLOT4ai deck.json, AI papers
├── data/
│   ├── vector_stores/              # ChromaDB collections
│   ├── page_indices/               # PageIndex tree JSON files
│   ├── results.db                  # SQLite result store
│   └── memory.db                   # Session memory
├── output/                         # Analysis outputs
│   └── {project-slug}/
│       ├── result.json
│       ├── threat_model.csv
│       ├── complete_report.md
│       ├── dfd.mermaid
│       └── attachments/
├── rag/                            # Example CSVs for RAG
├── docs/                           # This documentation
└── tests/                          # pytest test suite
```

---

*[← 11 — Mejoras y Roadmap](11_mejoras_roadmap.md) · [← Índice](00_indice.md)*
