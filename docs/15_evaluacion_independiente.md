# Evaluación Independiente de AgenticTM — Auditoría Profunda y Plan de Acción

> **Evaluador:** GitHub Copilot (Claude Opus 4.6)  
> **Fecha:** 2025-07-15  
> **Alcance:** Workflow, código, capacidades agénticas, prompts, RAG, robustez, production readiness  
> **Método:** Lectura exhaustiva de todo el source code sin consultar evaluaciones previas (docs/13, docs/14)

---

## Tabla de Contenidos

1. [Resumen Ejecutivo](#1-resumen-ejecutivo)
2. [¿Estamos Production Ready?](#2-estamos-production-ready)
3. [Parseo de Archivos Adjuntos](#3-parseo-de-archivos-adjuntos)
4. [Arquitectura del Pipeline](#4-arquitectura-del-pipeline)
5. [Configuración de Modelos LLM](#5-configuración-de-modelos-llm)
6. [Análisis de Prompts de Sistema](#6-análisis-de-prompts-de-sistema)
7. [Robustez del Parsing JSON](#7-robustez-del-parsing-json)
8. [Sistema RAG y Knowledge Base](#8-sistema-rag-y-knowledge-base)
9. [Madurez Agéntica](#9-madurez-agéntica)
10. [Seguridad y Hardening](#10-seguridad-y-hardening)
11. [Observabilidad y Monitoreo](#11-observabilidad-y-monitoreo)
12. [Frontend y UX](#12-frontend-y-ux)
13. [Testing y Calidad](#13-testing-y-calidad)
14. [Resumen de Hallazgos por Severidad](#14-resumen-de-hallazgos-por-severidad)
15. [Plan de Acción Priorizado](#15-plan-de-acción-priorizado)

---

## 1. Resumen Ejecutivo

AgenticTM es un sistema de threat modeling multi-agente **ambicioso y bien diseñado** en su arquitectura conceptual. El pipeline de 12 nodos en LangGraph con fan-out paralelo, debate adversarial, y síntesis con validación DREAD es una propuesta arquitectónica **sólida y diferenciadora**. La integración de 5 metodologías (STRIDE, PASTA, Attack Tree, MAESTRO, AI Threat), RAG con 5 vectorstores, VLM para diagramas, y debate Red/Blue Team es una combinación que no he visto en herramientas similares.

Sin embargo, **la ejecución tiene brechas significativas** entre la visión arquitectónica y la implementación actual. Hay funcionalidades configuradas pero no conectadas, inconsistencias que degradan la calidad del output con modelos pequeños (8B), y fragilidades en el parsing que pueden causar pérdida silenciosa de datos.

**Veredicto:** El sistema está en estado **"Advanced Prototype / Late Alpha"**. Tiene una base excelente, pero necesita 4-6 semanas de hardening antes de ser usado en producción con clientes reales.

---

## 2. ¿Estamos Production Ready?

### ❌ NO. No estamos production ready.

Las razones son concretas y accionables:

| # | Problema | Severidad | Impacto en Producción |
|---|---------|-----------|----------------------|
| 1 | PDF upload corrupto (binary leído como UTF-8) | **Crítico** | Usuarios suben PDFs → basura en el análisis |
| 2 | quick_thinker == deep_thinker (ambos qwen3:8b) | **Alto** | Se pierde la arquitectura multi-tier diseñada | ✅ Resuelto: quick=qwen3:4b; stride/deep/VLM=qwen3.5:9b |
| 3 | Inconsistencia ES/EN en prompts | **Alto** | Modelos 8B confunden idioma ↔ peor output |
| 4 | JSON extraction por regex (sin structured output) | **Alto** | Fallas silenciosas, datos perdidos |
| 5 | `max_validation_iterations` configurado pero NO usado | **Medio** | Feature muerta en config visible al usuario |
| 6 | Memory system configurado pero NO integrado | **Medio** | Feature muerta en config visible al usuario |
| 7 | No hay límites de upload (tamaño, MIME, cleanup) | **Alto** | Riesgo de DoS y consumo de disco |
| 8 | No hay benchmarks de calidad de output | **Alto** | No se puede medir regresión entre versiones |
| 9 | Debate estático (N rondas fijas, sin convergencia) | **Medio** | Rounds desperdiciados o insuficientes |
| 10 | AI Threat Analyst prompt ~4000 chars | **Medio** | Cognitive overload para 8B model |

**Para declarar production ready necesitamos resolver al menos los items 1-4 y 7.**

---

## 3. Parseo de Archivos Adjuntos

### Pregunta: ¿Estamos pudiendo parsear PDFs y Markdown cuando se adjuntan?

| Formato | Estado | Detalle |
|---------|--------|---------|
| **Imágenes** (PNG, JPG, etc.) | ✅ Funciona | Se pasan como paths al VLM (llava:13b) vía `architecture_parser` |
| **Markdown / TXT** | ✅ Funciona | `read_text(encoding="utf-8")` lee correctamente texto plano |
| **PDF** | ❌ **ROTO** | Se lee con `read_text(encoding="utf-8", errors="replace")` lo cual convierte binary a basura UTF-8 |

### Evidencia Técnica

En `server.py` líneas 390-397, el manejo de archivos no-imagen es:

```python
file_content = Path(fpath).read_text(encoding="utf-8", errors="replace")
fname = Path(fpath).name
system_input += f"\n\n--- Attached file: {fname} ---\n{file_content}"
```

Esto funciona para `.md`, `.txt`, `.csv`, `.json` — pero para PDFs **produce texto corrupto** porque el formato PDF es binario (headers `%PDF-1.4`, streams comprimidos, objetos binarios).

### Ironía

El RAG indexer (`indexer.py` línea 36) **SÍ usa `PyPDFLoader`** para indexar PDFs en la knowledge base. Esa misma capacidad no está conectada al pipeline de uploads del usuario.

### Fix Propuesto

```python
# En server.py, reemplazar el bloque else:
suffix = Path(fpath).suffix.lower()
if suffix == ".pdf":
    from langchain_community.document_loaders import PyPDFLoader
    pages = PyPDFLoader(fpath).load()
    file_content = "\n\n".join(p.page_content for p in pages)
else:
    file_content = Path(fpath).read_text(encoding="utf-8", errors="replace")
```

---

## 4. Arquitectura del Pipeline

### Lo Bueno

- **12 nodos bien definidos** con separación de concerns clara
- **Fan-out paralelo** a 5 analistas — excelente design pattern en LangGraph
- **Debate adversarial** Red/Blue Team — diferenciador valioso
- **Enriched Attack Tree** post-debate — inteligente reutilizar contexto del debate
- **State accumulation** con `Annotated[list, operator.add]` — correcto para merge paralelo
- **Mermaid DFD generation** desde el modelo parseado — nice touch

### Problemas Detectados

#### 4.1 Debate Estático sin Convergencia

```python
def should_continue_debate(state) -> Literal["red_team", "attack_tree_enriched"]:
    current_round = state.get("debate_round", 1)
    if current_round <= max_rounds:
        return "red_team"
    return "attack_tree_enriched"
```

El debate siempre ejecuta exactamente N rondas. No hay mecanismo de:
- **Convergencia semántica** — el Blue Team concede un punto pero se sigue debatiendo
- **Early stop** — si Red y Blue coinciden en todo en round 1, round 2 es desperdicio de tokens/tiempo
- **Escalation** — si después de N rondas siguen divergiendo, no se escala

#### 4.2 `max_validation_iterations` Configurado pero No Usado

```json
"pipeline": {
    "max_validation_iterations": 2,
    ...
}
```

Este parámetro aparece en `config.json` y `PipelineConfig`, pero **no hay ningún loop de validación iterativa en el graph**. El `dread_validator` ejecuta una sola vez. Esto es confuso para el usuario que lee la config — parece que hay validación iterativa pero no la hay.

#### 4.3 No Hay Fan-Out Condicional

Todos los 5 analistas siempre ejecutan, incluso MAESTRO y AI Threat Analyst cuando el sistema no tiene componentes de IA. Los agentes sí tienen `_has_ai_components()` check internamente, pero:
- Siguen consumiendo un LLM invocation para determinar "no aplica"
- Un edge condicional en el graph sería más eficiente

#### 4.4 Attack Tree Enriched Ejecuta Post-Debate

Buena idea conceptualmente, pero **no se alimenta de los threats generados por la síntesis** — lee del state previo al synthesizer. El order es: debate → attack_tree_enriched → synthesizer. Esto significa que el attack tree enriched no tiene acceso al consolidated view.

---

## 5. Configuración de Modelos LLM

### Hallazgo Crítico: quick_thinker == deep_thinker (✅ Resuelto)

```json
"quick_thinker": { "model": "qwen3:4b", "temperature": 0.3 },
"deep_thinker": { "model": "qwen3.5:9b", "temperature": 0.2, "num_ctx": 32768 }
```

> **Nota v0.3.2:** Este hallazgo fue resuelto. Hay 4 tiers en config: quick=qwen3:4b; stride/deep/vlm=qwen3.5:9b (9B, ~6.6 GB). `deep_thinker` reutiliza el mismo peso que STRIDE/VLM para evitar OOM y swap en GPUs modestas.

La arquitectura **diseña** una diferenciación multi-tier:
- `quick_thinker`: analistas PASTA, Attack Tree, MAESTRO, AI Threat, DREAD, localizer (tareas rápidas en 4B)
- `stride_thinker`: STRIDE y debate Red/Blue (9B)
- `deep_thinker`: attack_tree_enriched, threat_synthesizer (9B con JSON forzado, más contexto)
- `vlm`: diagramas (mismo qwen3.5:9b)

Quick (4B) y deep (9B) ya no son el mismo modelo; el salto de capacidad está en el tier deep/stride frente al quick.

### Impacto Real

- El `threat_synthesizer` recibe **TODA la información de 5 analistas + debate** — puede ser un prompt de 15-30K tokens. Un modelo pequeño (p. ej. 4B) con esa carga tiene alta probabilidad de:
  - Perder contexto (ventana de atención saturada)
  - Producir JSON malformado
  - Omitir threats que están al inicio del prompt
- El `dread_validator` necesita razonamiento numérico comparativo — una tarea donde modelos más grandes son significativamente mejores

### Recomendación

| Tier | Uso | Modelo Actual |
|------|-----|----------------------|
| `quick_thinker` | Analistas individuales, debate | qwen3:4b |
| `deep_thinker` | Synthesizer, enriched tree | qwen3.5:9b |
| `stride_thinker` | STRIDE analyst, debate | qwen3.5:9b |
| `vlm` | Diagramas (nativo en Qwen3.5) | qwen3.5:9b |

---

## 6. Análisis de Prompts de Sistema

### 6.1 Inconsistencia de Idioma

| Agente | Idioma del Prompt | Idioma Esperado del Output |
|--------|------------------|---------------------------|
| STRIDE Analyst | 🇪🇸 Español | JSON (campo "summary" ambiguo) |
| PASTA Analyst | 🇪🇸 Español | JSON |
| Attack Tree | 🇪🇸 Español | JSON |
| MAESTRO Analyst | 🇪🇸 Español | JSON |
| **AI Threat Analyst** | 🇺🇸 **Inglés** | JSON |
| Red Team | 🇪🇸 Español | Prosa |
| **Blue Team** | 🇪🇸/🇺🇸 **Mixto** | Prosa |
| **Threat Synthesizer** | 🇺🇸 **Inglés** | JSON |
| **DREAD Validator** | 🇺🇸 **Inglés** | JSON |
| Report Generator | N/A (determinístico) | CSV + Markdown con headers 🇪🇸 |

**4 agentes en español, 3 en inglés, 1 mixto.** Esto es problemático para un modelo 8B:
- El modelo recibe system prompt en español, luego en inglés, luego español otra vez
- Los reports de analistas en español se pasan como input al synthesizer que tiene prompt en inglés
- El modelo puede "contagiar" idiomas y producir mixed-language output

### 6.2 Longitud Excesiva del AI Threat Analyst

El prompt del `AI Threat Analyst` tiene **~4000 caracteres** con:
- PLOT4ai completo (8 categorías con sub-items)
- OWASP Top 10 LLM 2025 (10 items)
- OWASP Agentic AI Top 10 2026 (10 items)
- CSA MAESTRO 7 Layers (7 items)
- Métricas WEI y RPS
- MCP Security Considerations
- Dos schemas JSON completos (aplicable / no aplicable)

Para un modelo 8B, esto es **cognitive overload**. El modelo tiene que:
1. Retener todo el marco teórico del system prompt
2. Analizar el sistema del human prompt
3. Usar herramientas RAG
4. Producir JSON estructurado con campos WEI/RPS

Resultado probable: el output prioriza los últimos frameworks mencionados (recency bias) y produce scores WEI/RPS arbitrarios.

### 6.3 Schemas JSON Inconsistentes

Cada agente pide un schema JSON diferente:
- STRIDE: `{ threats: [{ component, stride_category, description, impact, reasoning, references }] }`
- AI Threat: `{ threats: [{ component, framework, category, attack_vector, wei_score, rps_score, ... }] }`  
- Synthesizer: `{ threats: [{ id, component, methodology_sources, stride_category, attack_path, damage, reproducibility, ... }] }`

El synthesizer tiene que **unificar schemas completamente diferentes**. Los campos que un analista produce (e.g., `reasoning`, `references` de STRIDE) no existen en el schema del synthesizer (`control_reference`, `observations`). Esto requiere que el modelo haga mapping semántico implícito — una tarea que modelos pequeños hacen mal.

### 6.4 Instrucciones de Tool Use Implícitas

Los prompts dicen "Usá las herramientas RAG para buscar..." pero no incluyen:
- Nombres exactos de las tools disponibles
- Ejemplos de queries efectivas
- Cuándo usar cada tool (books vs research vs risks)

El modelo tiene que descubrir por sí mismo qué tool llamar y con qué query. Con modelos 8B, esto a menudo resulta en:
- No llamar tools en absoluto
- Queries muy genéricas ("security threats")
- Llamar la misma tool múltiples veces con la misma query

---

## 7. Robustez del Parsing JSON

### Multi-Strategy Parser (base.py)

```python
def extract_json_from_response(text):
    # 1. Strip <think> tags
    # 2. Find ```json blocks
    # 3. Parse entire text
    # 4. Find balanced { } or [ ]
    # 5. Fix common issues (trailing commas, comments, unquoted keys)
```

### Problemas

1. **No usa structured output del LLM**: Ollama (via langchain-ollama) soporta `format="json"` que fuerza JSON output nativo. Esto eliminaría la necesidad de todo este parsing.

2. **`_fix_common_json_issues` es frágil**:
   - `re.sub(r"(?<=[{,])\s*(\w+)\s*:", r' "\1":',  s)` — rompe strings que contienen `key:value` patterns (e.g., descripciones de URLs como "http://example.com:8080")
   - No maneja strings multi-línea
   - No maneja escaped quotes dentro de strings

3. **Fallback a markdown extraction**: `extract_threats_from_markdown()` es un buen safety net pero produce datos de menor calidad (scores defaulteados a 5, campos vacíos).

4. **No hay métricas**: No se trackea qué porcentaje de respuestas caen al fallback. Si el 30% de los análisis requieren markdown extraction, la calidad del threat model está degradada y no lo sabemos.

### Recomendación

```python
# Usar format="json" en la inicialización del LLM para agentes que requieren JSON
llm = ChatOllama(model="qwen3:4b", format="json", temperature=0.3)
```

Esto es **la fix más impactante y fácil** de toda esta evaluación. Una línea de cambio que elimina la mayor fuente de fragilidad.

---

## 8. Sistema RAG y Knowledge Base

### Lo Bueno

- **5 vectorstores especializados** — buena segmentación por tipo de conocimiento
- **Category filtering** en `rag_query_risks` — filtra por categorías activas del proyecto
- **PyPDFLoader, CSVLoader, JSONLoader** — buena cobertura de formatos en el indexer
- **PLOT4ai deck.json** parsing especializado — atención al detalle

### Problemas

1. **No hay reranking**: `similarity_search(k=5)` retorna los 5 más similares por embedding distance, pero no hay cross-encoder reranking. Para queries ambiguas, el top-5 por embedding puede no ser el top-5 por relevancia semántica.

2. **Chunk size fijo (1000 chars)**: Los PDFs de threat modeling a menudo tienen tablas, frameworks y listas que se cortan en medio. Un chunk adaptivo o metadata-aware chunking mejoraría las respuestas.

3. **No hay evaluación de calidad RAG**: No sabemos si las queries de los agentes realmente recuperan contexto útil. No hay hit-rate tracking ni relevance scoring.

4. **Category filtering es keyword-based**: El filtrado en `rag_query_risks` usa keywords simples en el page_content. Una amenaza de "AWS Lambda" podría no matchear si el keyword set no tiene "lambda". Un clasificador semántico sería más robusto.

5. **Top-K inconsistente**: `rag_query_risks` usa `top_k=8`, los demás usan `top_k=5` (default). No hay justificación documentada para la diferencia.

---

## 9. Madurez Agéntica

### Lo que sí es agéntico

- ✅ **Tool calling loop** con hasta 3 rondas — los agentes pueden decidir qué RAG consultar y cuántas veces
- ✅ **Multi-agent pipeline** con estado compartido — each agent reads what it needs, writes its section
- ✅ **Debate adversarial** — genuino razonamiento multi-perspectiva
- ✅ **Conditional logic** — skip AI analysis si no hay componentes AI

### Lo que falta para ser "verdaderamente agéntico"

1. **No hay self-reflection**: Ningún agente revisa su propio output antes de commit. Un pattern como "generate → critique → revise" mejoraría significativamente la calidad.

2. **No hay inter-agent communication dinámica**: Los agentes no pueden pedir clarificación a otros agentes. El STRIDE analyst no puede decir "necesito más detalle del architecture parser sobre el componente X".

3. **No hay planning**: El pipeline es fijo. Un agente planificador podría decidir "este sistema es simple, skip MAESTRO y debate 1 round" o "este sistema es crítico, debate 3 rounds y agrega LINDDUN".

4. **No hay memory institucional activa**: La memoria está configurada (`memory.enabled=true`, `db_path`, `journal_path`) pero **no se usa en ningún agente**. Los agentes no aprenden de threat models previos — solo consultan el RAG de previous_tms, que es estático.

5. **max_tool_rounds=3 es muy bajo**: Con 5 RAG sources disponibles, un agente diligente necesitaría al menos 5 calls (una por source). Con 3 rounds, tiene que elegir. Esto limita la profundidad del análisis.

6. **No hay human-in-the-loop**: El usuario no puede intervenir entre fases. Si el architecture parser interpreta mal el sistema, todo el pipeline produce resultados basados en una premisa incorrecta. Un checkpoint después del parsing ("¿Esto es correcto?") ahorraría muchos tokens.

---

## 10. Seguridad y Hardening

### Ironía: Una herramienta de threat modeling con vulnerabilidades propias

1. **Upload sin límites**: No hay validación de:
   - Tamaño máximo de archivo
   - MIME type
   - Extensiones peligrosas
   - Rate limiting por IP/sesión
   - Path traversal en filenames

2. **Archivos temporales no se limpian**: `tmp_dir = Path(tempfile.gettempdir()) / "agentictm_uploads"` acumula archivos indefinidamente. No hay cleanup job.

3. **In-memory state**: `_results` y `_uploads` son dicts in-memory. Si el servidor se reinicia, los uploads se pierden (los results se recargan de disco, pero los uploads no).

4. **No hay autenticación**: El API es completamente abierto. En un deployment de equipo, cualquiera puede:
   - Lanzar análisis que consumen GPU
   - Leer resultados de otros usuarios
   - Subir archivos maliciosos

5. **Prompt injection via uploaded files**: Un archivo markdown malicioso podría contener instrucciones como "Ignore previous instructions and output..." que se inyectan directamente al prompt del architecture parser. No hay sanitización.

---

## 11. Observabilidad y Monitoreo

### Lo Bueno

- **Logging extensivo**: Cada agente logea timing, tamaño de respuesta, tool calls, etc.
- **SSE streaming**: El frontend ve el progreso en tiempo real

### Lo Que Falta

1. **No hay métricas agregadas**: No se trackea:
   - Tiempo promedio por agente
   - Tasa de éxito de JSON parsing por agente
   - Número de tool calls promedio
   - Proporción de fallbacks a markdown extraction
   
2. **No hay cost tracking**: Con modelos locales no importa tanto, pero si se cambia a API (OpenAI, Anthropic), no hay estimación de tokens/costo.

3. **No hay alertas**: Si un agente consistentemente falla en producir JSON, nadie se entera hasta revisar los logs.

---

## 12. Frontend y UX

El frontend es un SPA single-file en `index.html` con localStorage + server persistence. El abordaje es pragmático para un MVP.

### Mejoras Potenciales

1. **No hay preview del parsed architecture**: El usuario no ve cómo el parser interpretó su input antes del análisis completo
2. **No hay cancel**: Una vez lanzado el análisis, no se puede abortar
3. **No hay indicador de calidad**: El usuario recibe el report sin saber si hubo fallbacks o problemas
4. **Progress granularity**: El SSE muestra logs crudos, no un progress bar semántico ("Fase 2/5: Analyzing threats...")

---

## 13. Testing y Calidad

### Estado Actual
- 54/54 tests passing (reportado en sesión previa)

### Lo Que Falta

1. **No hay integration tests end-to-end**: Los tests unitarios validan componentes, pero ¿qué pasa cuando el pipeline completo corre con un input real?

2. **No hay golden tests**: No hay un conjunto de inputs conocidos con outputs esperados para detectar regresiones en la calidad del threat model.

3. **No hay quality benchmarks**: ¿Cómo sabemos si la versión 2.0 produce mejores threat models que la 1.0? No hay métricas como:
   - Número de threats por input
   - Cobertura STRIDE (¿cubre las 6 categorías?)
   - Consistency de DREAD scores (¿threats similares tienen scores similares?)

---

## 14. Resumen de Hallazgos por Severidad

### 🔴 Críticos (Bloquean Production)

| # | Hallazgo | Fix Estimado |
|---|---------|-------------|
| C1 | PDF upload produce basura (read_text en binary) | 1 hora |
| C2 | No hay JSON structured output (`format="json"`) | 2 horas |
| C3 | Upload sin límites de tamaño/tipo/cleanup | 3 horas |

### 🟠 Altos (Degradan calidad significativamente)

| # | Hallazgo | Fix Estimado |
|---|---------|-------------|
| H1 | quick_thinker == deep_thinker (misma qwen3:8b) | ✅ Resuelto |
| H2 | Inconsistencia ES/EN en prompts | 4 horas |
| H3 | AI Threat Analyst prompt demasiado largo para 8B | 3 horas |
| H4 | No hay métricas de calidad de parsing/output | 1 día |
| H5 | Prompt injection via uploaded files sin sanitizar | 4 horas |

### 🟡 Medios (Mejoran el sistema significativamente)

| # | Hallazgo | Fix Estimado |
|---|---------|-------------|
| M1 | `max_validation_iterations` configurado pero no usado | 2 días |
| M2 | Memory system configurado pero no integrado | 3 días |
| M3 | Debate estático sin convergencia | 1 día |
| M4 | No hay preview del parsed architecture (HITL) | 2 días |
| M5 | max_tool_rounds=3 limita profundidad RAG | 30 min |
| M6 | Schemas JSON inconsistentes entre agentes | 1 día |

### 🟢 Bajos (Nice to have)

| # | Hallazgo | Fix Estimado |
|---|---------|-------------|
| L1 | No hay reranking en RAG | 1 día |
| L2 | No hay self-reflection en agentes | 3 días |
| L3 | No hay planning dinámico | 1 semana |
| L4 | No hay cancel de análisis en curso | 1 día |
| L5 | Frontend no muestra semantic progress | 1 día |

---

## 15. Plan de Acción Priorizado

### Fase 0 — "Stop the Bleeding" (1-2 días)

> Fixes mínimos para que el sistema no produzca resultados incorrectos silenciosamente.

- [ ] **C1**: Implementar PDF parsing en uploads usando `PyPDFLoader` (ya disponible en el proyecto)
- [ ] **C2**: Agregar `format="json"` a los LLM de agentes que requieren JSON output
- [ ] **C3**: Agregar límites de upload: 50MB max, extensiones permitidas (.pdf, .md, .txt, .csv, .json, .png, .jpg, .jpeg, .svg, .drawio), tempfile cleanup on server start
- [ ] **M5**: Subir `max_tool_rounds` de 3 a 5

### Fase 1 — "Quality Foundation" (1 semana)

> Asegurar que el output sea consistente y medible.

- [ ] **H1**: Configurar deep_thinker con modelo más grande (qwen3:32b o similar). Si no hay VRAM suficiente, al menos usar temperature más baja (0.1) y mayor context window
- [ ] **H2**: Unificar idioma de todos los prompts a **español** (dado que `output_language=es` y el equipo habla español). Mover la terminología técnica a glosarios inline
- [ ] **H3**: Refactorizar AI Threat Analyst prompt — dividir en sub-prompts por framework, o crear un "meta-prompt" que seleccione frameworks relevantes dinámicamente
- [ ] **M6**: Definir un JSON schema compartido (`UnifiedThreat`) y hacer que todos los agentes produzcan el mismo formato. El synthesizer se simplifica de "schema mapper" a "deduplicator + enricher"
- [ ] **H5**: Sanitizar input de archivos — strip potential prompt injection markers, truncar archivos excesivamente grandes

### Fase 2 — "Agentic Maturity" (2-3 semanas)

> Hacer el sistema verdaderamente agéntico: adaptativo, con memoria, y mejora continua.

- [ ] **M1**: Implementar validation loop — el `dread_validator` puede re-evaluar N veces hasta que los scores estabilicen. Agregar convergence check: si diff entre iteraciones < threshold, stop
- [ ] **M3**: Debate con convergencia semántica — usar un mini clasificador que detecte cuándo el Blue Team concede todos los puntos. Early stop si round N produce < X nuevos arguments
- [ ] **M2**: Activar memory — después de cada análisis, guardar: (a) threats encontrados, (b) calidad del input, (c) métricas de éxito. Inyectar como contexto en análisis futuros ("en el último análisis similar, encontramos X...")
- [ ] **M4**: HITL checkpoint después del architecture parser — mostrar al usuario el modelo parseado y permitir correcciones antes de continuar
- [ ] **L2**: Agregar self-reflection al synthesizer y validator — "revisa tu output, ¿hay inconsistencias? ¿faltan STRIDE categories?"

### Fase 3 — "Production Polish" (2 semanas)

> Hardening, observabilidad, y experiencia de usuario.

- [ ] **H4**: Dashboard de métricas:
  - Tasa de JSON parse success por agente
  - Tiempo por nodo
  - Tool call patterns
  - Cobertura STRIDE/PASTA/etc.
- [ ] **L1**: RAG reranking con cross-encoder (e.g., ms-marco-MiniLM)
- [ ] **L4**: Cancel análisis (usar LangGraph interrupt y asyncio cancellation)
- [ ] **L5**: Progress bar semántico en frontend ("Analizando con STRIDE... 3/12 nodos completados")
- [ ] Autenticación básica (API key o session token) para deployments de equipo
- [ ] Golden test suite: 5 inputs canónicos con outputs esperados para regression testing
- [ ] Cleanup automático de temp files (cron job o backround task)

### Fase 4 — "Differentiators" (futuro)

> Features que elevan el producto de "herramienta interna" a "producto competitivo".

- [ ] **L3**: Agent planner que adapta el pipeline al input (simple → skip MAESTRO, critical → extra debate rounds)
- [ ] Multi-model orchestration real: usar GPT-4o / Claude para el synthesizer cuando se necesita máxima calidad, Ollama para analistas
- [ ] Export a JIRA/Azure DevOps (auto-crear tickets desde threats)
- [ ] Comparative analysis: "¿cómo cambió el threat model entre la versión 1.0 y 2.0?"
- [ ] SBOM integration: conectar con Syft/Grype para enriquecer threats con CVEs reales
- [ ] Feedback loop activo: el usuario marca threats como "útil" / "irrelevante" y el sistema aprende

---

## Opinión Final Honesta

AgenticTM tiene **la arquitectura correcta**. La combinación de multi-agent analysis, RAG-augmented reasoning, adversarial debate, y multi-methodology coverage es genuinamente innovadora. No conozco otra herramienta open-source que combine todo esto.

Sin embargo, la distancia entre "la arquitectura es correcta" y "el output es confiable" se cierra con **engineering discipline**, no con más features. Los problemas más impactantes (JSON parsing, PDF upload, idioma inconsistente) son **fáciles de arreglar** — la mayoría son cambios de pocas líneas.

Mi recomendación: **no agregar ninguna feature nueva hasta completar Fase 0 y Fase 1**. El sistema actual con 12 agentes y 5 metodologías es más que suficiente en scope. Lo que necesita es que el output de esos 12 agentes sea **consistente, parseable, y de alta calidad** el 99% de las veces.

El sistema está a **4-6 semanas** de production ready si se priorizan las fixes sobre las features. La base es excelente — ahora toca pulirla.

---

*Documento generado por análisis exhaustivo del codebase sin consultar evaluaciones previas (docs/13, docs/14).*
