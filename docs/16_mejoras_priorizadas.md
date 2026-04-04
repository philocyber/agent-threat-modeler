# AgenticTM — Lista Priorizada de Mejoras

> Consolidación de las mejoras identificadas en los documentos de evaluación:
> - `docs/13_*` — Evaluación técnica
> - `docs/14_*` — Análisis de mejoras
> - `docs/15_evaluacion_independiente.md` — Evaluación independiente
>
> **Fecha:** 2025-01-XX | **Versión:** v0.3.1

---

## Leyenda de Prioridad

| Nivel | Significado | Criterio |
|-------|-------------|----------|
| **C** (Crítico) | Bloquea uso profesional | Bug funcional, output corrupto |
| **H** (Alto) | Impacta calidad significativamente | Calidad de amenazas, fiabilidad |
| **M** (Medio) | Mejora notable | Performance, UX, consistencia |
| **L** (Bajo) | Nice-to-have | Polish, documentación, futuro |

---

## Críticos (C) — Requieren acción inmediata

### ✅ C1: PDF Upload Parsing Bug
- **Estado:** IMPLEMENTADO (v0.3.1)
- **Archivo:** `agentictm/api/server.py`
- **Cambio:** `PyPDFLoader` para extracción de texto en archivos PDF (antes leía binario como UTF-8)
- **Impacto:** Uploads de PDF ahora funcionan correctamente

### ✅ C2: Structured JSON Output (format="json")
- **Estado:** IMPLEMENTADO (v0.3.1)
- **Archivos:** `config.py`, `llm/__init__.py`, `graph/builder.py`
- **Cambio:** Creados variantes `quick_json` y `deep_json` en LLMFactory. Agentes que producen output JSON (analistas, sintetizador, validador DREAD) ahora usan `format="json"` de Ollama, forzando output JSON válido. Debate (Red/Blue Team) mantiene modo free-text.
- **Impacto:** Elimina fallos de parseo JSON que provocaban pérdida de amenazas

### ⬜ C3: Upload Hardening
- **Estado:** PENDIENTE
- **Descripción:** Añadir límites de tamaño (max 10MB), whitelist MIME types, cleanup de archivos temporales tras análisis
- **Esfuerzo:** Bajo (~30 min)

---

## Altos (H) — Mejoran calidad significativamente

### ✅ H1: Diferenciación Real quick_thinker vs deep_thinker
- **Estado:** ✅ RESUELTO (v0.3.2)
- **Descripción:** ~~Actualmente ambos usan `qwen3:8b`.~~ Resuelto: 4 tiers diferenciados — quick=`qwen3:4b`, stride=`qwen3.5:9b`, deep=`gemma4:26b`, vlm=`qwen3.5:9b`. Además `cli.py init` auto-configura según RAM disponible.
- **Impacto:** Mejora drástica en calidad de síntesis y puntuación DREAD
- **Esfuerzo:** ~~Bajo (cambio de config)~~ Completado

### ⬜ H2: Unificación de Idioma en Prompts
- **Estado:** PARCIAL
- **Descripción:** 4 agentes usan prompts en español (STRIDE, PASTA, MAESTRO, debate), 6 en inglés. Unificar a español (idioma de salida profesional del equipo)
- **Agentes en inglés a traducir:**
  - Architecture Parser (system prompt + VLM prompt)
  - Attack Tree Initial/Enriched
  - AI Threat Analyst
  - Threat Synthesizer
  - DREAD Validator
- **Esfuerzo:** Medio (~2h, requiere testing de calidad post-traducción)

### ⬜ H3: Mejorar Prompt del Sintetizador para ≥15 Amenazas
- **Estado:** PENDIENTE
- **Descripción:** El sintetizador actual produce ~11 amenazas. Los TMs profesionales del equipo tienen 12-16. El prompt debe instruir explícitamente un mínimo de 15 amenazas con descripciones verbose y controles detallados
- **Impacto:** Cierra la brecha de calidad con output profesional
- **Esfuerzo:** Medio (~1h prompt engineering + testing)

### ⬜ H4: Schema Unificado de Amenazas
- **Estado:** PENDIENTE
- **Descripción:** Definir un Pydantic schema para `Threat` y usarlo en todos los agentes. Actualmente cada agente usa dicts libres con campos inconsistentes
- **Impacto:** Elimina campos faltantes y inconsistencias entre agentes
- **Esfuerzo:** Alto (~3h)

### ⬜ H5: Validación DREAD con Criterios Calibrados
- **Estado:** PENDIENTE
- **Descripción:** El validador DREAD debe usar criterios de scoring calibrados (no solo "1-10"). Ejemplo: D=9 si afecta datos de producción, D=3 si es solo logs
- **Impacto:** Scores DREAD más precisos y reproducibles
- **Esfuerzo:** Medio (~1h prompt engineering)

### ⬜ H6: RAG con Reranking
- **Estado:** PENDIENTE
- **Descripción:** Añadir cross-encoder reranking al RAG para mejorar relevancia de context retrieved
- **Esfuerzo:** Medio (~2h)

### ⬜ H7: Error Handling Robusto en Pipeline
- **Estado:** PENDIENTE
- **Descripción:** Si un agente falla, el pipeline debería continuar con los demás en vez de abortar. Implement try/except por nodo con graceful degradation
- **Esfuerzo:** Medio (~2h)

---

## Medios (M) — Mejoras notables

### ⬜ M1: Iteraciones de Validación (usar max_validation_iterations)
- **Estado:** PENDIENTE
- **Descripción:** `config.pipeline.max_validation_iterations = 2` está configurado pero no se usa en código. Implementar re-validación del DREAD validator si detecta scores inconsistentes
- **Esfuerzo:** Medio (~1h)

### ✅ M2: Debate con Criterio de Convergencia
- **Estado:** IMPLEMENTADO (v0.3.2)
- **Archivo:** `agentictm/agents/debate.py`, `agentictm/graph/builder.py`, `agentictm/config.py`
- **Cambio:** Red Team ahora emite `[CONVERGENCIA]` si no hay nuevos vectores de ataque, o `[NUEVOS VECTORES]` si los hay. `should_continue_debate` detecta la señal y termina el debate anticipadamente. Hard cap subido de 2 a 10 rondas máximo.
- **Impacto:** Debates cortos (2 rondas) cuando no hay nada nuevo; hasta 10 rondas cuando el sistema es complejo

### ✅ M3: max_tool_rounds 3→5
- **Estado:** IMPLEMENTADO (v0.3.1)
- **Archivo:** `agentictm/agents/base.py`
- **Cambio:** Default de `max_tool_rounds` incrementado de 3 a 5, permitiendo más iteraciones de tool-calling
- **Impacto:** Agentes con tools no se quedan cortos en análisis complejos

### ⬜ M4: Markdown Report con Tablas DREAD Desglosadas
- **Estado:** PENDIENTE
- **Descripción:** El reporte Markdown actual muestra DREAD como total. Mostrar columnas individuales (D, R, E, A, D) como en la tabla HTML y CSV
- **Esfuerzo:** Bajo (~30min)

### ⬜ M5: Meta-Prompt con Contexto de TMs Previos
- **Estado:** PENDIENTE
- **Descripción:** Usar los CSVs de TMs anteriores (previous_threat_models/) como few-shot examples en el prompt del sintetizador. Esto calibra el formato, verbosidad y estilo
- **Esfuerzo:** Medio (~2h)

### ⬜ M6: Exportar Resultado como JSON Completo
- **Estado:** PENDIENTE
- **Descripción:** Endpoint `/api/results/{id}/json` para descargar el estado completo del análisis como JSON
- **Esfuerzo:** Bajo (~15min)

---

## Frontend — Implementados en v0.3.1

### ✅ F1: Tabla de Amenazas Profesional
- Agrupada por categorías (INF, PRI, WEB, AGE, LLM, HUM)
- Columnas DREAD individuales (D, R, E, A, D) + promedio
- Descripciones y controles completos (sin truncar)
- IDs con prefijo por categoría
- Prioridades en español

### ✅ F2: URL Routing (History API)
- `pushState` al cambiar tabs
- Rutas: `/threats`, `/dfd`, `/report`, `/diagrams`, `/debate`, `/prompt`, `/live`
- `popstate` listener para back/forward del navegador

### ✅ F3: Renderizado Mermaid (DFD + Diagramas)
- CDN mermaid.js v11 con tema dark personalizado (accent #a773bf)
- DFD se renderiza como diagrama interactivo
- Attack Trees Initial + Enriched renderizados
- Fallback a código fuente si el render falla

### ✅ F4: Reporte con marked.js
- Reemplazado `simpleMarkdown()` por `marked.parse()` con GFM
- CSS profesional para reportes (typography, blockquotes, tables, code)
- Detección automática de bloques mermaid embebidos → render
- Botones de acción: Print/PDF, Download .md, Download .tex

### ✅ F5: LaTeX Report Generation
- Backend genera LaTeX profesional con longtable, booktabs, fancyhdr
- Endpoint `/api/results/{id}/latex`
- Tabla de amenazas agrupada por categoría en LaTeX
- Detalle por amenaza con description lists

### ✅ F6: SPA Routes en Server
- Server devuelve index.html para todas las rutas frontend
- Deep-link support (refresh en /threats no da 404)

### ✅ F7: Print CSS
- Estilos de impresión optimizados para exportar como PDF
- Oculta sidebar, topbar, botones en modo print

---

## Bajos (L) — Nice-to-have

### ⬜ L1: Dashboard de Métricas
- Gráficos de distribución de amenazas por STRIDE, por prioridad, por categoría
- Heatmap de DREAD scores

### ⬜ L2: Comparación entre Análisis
- Diff visual entre dos TMs del mismo sistema
- Detectar amenazas nuevas/resueltas

### ⬜ L3: Integración Jira
- Crear tickets automáticamente desde amenazas
- Sincronizar estado de tickets

### ⬜ L4: Multi-idioma en Output
- Switch entre español/inglés para reportes y CSVs
- Prompts bilingües

### ⬜ L5: Rate Limiting y Auth
- Autenticación básica para el endpoint de análisis
- Rate limiting para prevenir abuse

### ⬜ L6: Streaming de Resultados Parciales
- Mostrar amenazas en la tabla conforme van siendo generadas por cada analista
- No esperar al sintetizador para ver output parcial

### ⬜ L7: Tests de Integración End-to-End
- Test que ejecuta un análisis completo con un sistema de ejemplo
- Verifica que CSV, report, LaTeX se generen correctamente

### ⬜ L8: Documentación de API (OpenAPI)
- Swagger UI accesible en `/docs`
- Ejemplos de request/response

### ⬜ L9: Knowledge Base Auto-Update
- Descargar y actualizar CVEs, OWASP Top 10, MITRE ATT&CK automáticamente
- Scheduler periódico

### ⬜ L10: Plugin System para Nuevas Metodologías
- Framework para añadir nuevos agentes analistas sin modificar el graph builder
- Hot-loading de plugins

---

## Resumen de Implementación v0.3.1

| ID | Mejora | Estado |
|----|--------|--------|
| C1 | PDF Upload Fix | ✅ |
| C2 | format="json" Structured Output | ✅ |
| M3 | max_tool_rounds 3→5 | ✅ |
| F1 | Threats Table Professional | ✅ |
| F2 | URL Routing | ✅ |
| F3 | Mermaid Rendering | ✅ |
| F4 | Report with marked.js | ✅ |
| F5 | LaTeX Report | ✅ |
| F6 | SPA Server Routes | ✅ |
| F7 | Print CSS | ✅ |

**10 mejoras implementadas** en esta iteración. Las siguientes prioridades para v0.3.2:
1. **H1** — Diferenciar models (quick vs deep)
2. **H3** — Prompt del sintetizador para ≥15 amenazas
3. **C3** — Upload hardening
4. **H2** — Unificar idioma de prompts
5. **M1** — Implementar validation iterations
