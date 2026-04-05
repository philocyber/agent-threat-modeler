# Evaluación Profunda de AgenticTM y Plan de Acción

Fecha: 2026-02-24

## 1) Respuesta directa a tu pregunta (adjuntos PDF/Markdown)

### Estado actual real
- **Markdown (.md)**: **sí**, se incorpora al prompt final como texto plano.
- **TXT/RST**: **sí**, también se incorporan como texto plano.
- **PDF**: **no se parsea correctamente** en el flujo de upload de usuario.
- **Imágenes (png/jpg/svg/etc.)**: **sí**, se pasan por path al parser de arquitectura y luego al VLM.

### Evidencia técnica
En el backend de upload/analyze, para cualquier adjunto que no sea imagen se ejecuta:
- lectura con `Path(fpath).read_text(encoding="utf-8", errors="replace")`

Eso significa:
- Markdown funciona bien (es texto).
- PDF binario no: se fuerza lectura UTF-8 con reemplazos, produciendo texto corrupto/inútil.

## 2) Opinión honesta y profunda del sistema

## Veredicto corto
El sistema es **muy bueno como prototipo avanzado** de threat modeling multi-agente (arquitectura sólida, cobertura metodológica alta, salida útil), pero todavía está en un estado **"research-grade"** y no "production-grade" en 4 ejes críticos:
1. Ingesta documental robusta
2. Gobernanza/calidad del output (validación estructurada fuerte)
3. Observabilidad y métricas operativas
4. Evaluación sistemática de calidad (benchmarking)

## Lo que está muy bien
1. **Diseño de pipeline**: parser → analistas paralelos → debate → enriquecimiento → síntesis → validación DREAD → reporte.
2. **Cobertura metodológica**: STRIDE, PASTA, Attack Tree, MAESTRO, AI Threat Analysis.
3. **RAG por dominios**: separación en stores (books/research/risks/previous_tms/ai_threats).
4. **UX de ejecución**: SSE con streaming de logs y vista por tabs.
5. **Salida operativa**: CSV + Report + Mermaid.

## Deudas técnicas y oportunidades de mejora (priorizadas)

### P0 (alto impacto inmediato)
1. **Parsing real de PDF adjunto de usuario**
   - Problema: hoy no hay extracción semántica real para PDF en upload.
   - Impacto: pérdida de contexto crítico en análisis.

2. **Unificación de contrato JSON por agente + validación estricta**
   - Problema: cada agente devuelve esquemas ligeramente distintos; fallbacks tapan errores.
   - Impacto: inconsistencias y calidad variable en `threats_final`.

3. **Parámetros de pipeline parcialmente no usados**
   - `max_validation_iterations` está configurado pero no orquesta iteraciones reales.
   - Impacto: sensación de robustez mayor a la real.

4. **Modelo quick/deep idéntico (`qwen3:8b`)** — ✅ **Resuelto en v0.3.2**: ahora 4 tiers diferenciados (quick=qwen3:4b; stride/deep/VLM=qwen3.5:9b)
   - Problema: no había verdadera diferenciación cognitiva por fase.
   - Impacto: costo/latencia sin ganancia clara de calidad entre etapas.

### P1 (alto valor en 2-4 semanas)
5. **Prompt engineering inconsistente (ES/EN mixto, longitud excesiva)**
   - Problema: mezcla de idiomas y prompts muy extensos sin plantillas comunes.
   - Impacto: deriva de estilo, mayor variabilidad, más tokens.

6. **RAG sin reranking/citación estructurada**
   - Problema: retrieval directo sin re-ranker ni score calibration por fase.
   - Impacto: evidencia menos precisa y trazabilidad débil.

7. **Upload endpoint sin hardening de seguridad**
   - Falta: límites de tamaño por tipo, whitelist estricta MIME/extensión, antivirus hook opcional, limpieza de temp files.

8. **Ausencia de scorecard de calidad automática**
   - Falta: suite de regresión de calidad de amenazas (precision/recall/consistencia DREAD).

### P2 (madurez 1-3 meses)
9. **Memoria operativa no integrada en decisiones agenticas**
   - Hay configuración de memory, pero su uso no está acoplado a mejoras adaptativas del pipeline.

10. **Orquestación estática del debate**
    - Rondas fijas, sin criterio de convergencia/confianza.

11. **Falta de “confidence score” por amenaza**
    - `dread_total` existe, pero no hay score de confianza ni trazabilidad por fuente.

12. **Falta de segmentación por tipo de sistema en prompts**
    - Un SaaS simple y un sistema crítico regulado comparten plantilla base demasiado general.

## 3) Evaluación de habilidades agenticas (estado actual)

### Fortalezas agenticas
- Buen patrón de especialización por agente.
- Debate Red/Blue agrega valor de contraste.
- Synthesis + DREAD Validator reduce ruido final.

### Limitaciones agenticas
- Persisten “hallucinations controladas” cuando RAG no es suficientemente preciso.
- No hay verificación cruzada automática por evidencia obligatoria por amenaza.
- El sistema no castiga formalmente afirmaciones sin soporte (solo instrucción por prompt).

## 4) Recomendación de arquitectura objetivo

## Objetivo
Pasar de “pipeline multiagente útil” a “motor de threat modeling confiable y auditable”.

## Principios
1. **Evidence-first**: toda amenaza debe tener fuente(s).
2. **Schema-first**: toda salida validada con contrato formal.
3. **Risk-first**: scoring consistente, explicable, reproducible.
4. **Ops-first**: observabilidad por agente (latencia, tool calls, calidad).

## 5) Plan de acción propuesto

## Fase 0 — Quick Wins (3-5 días)
1. Implementar extracción de adjuntos por tipo:
   - `.md/.txt/.rst`: lectura texto (actual).
   - `.pdf`: extractor real (PyPDF / Unstructured / pdfplumber).
2. Agregar `source_type` y `source_name` en cada bloque adjunto inyectado al prompt.
3. Añadir métricas simples por run:
   - tiempo total, tiempo por agente, cantidad tool-calls, threats generadas.
4. Corregir `max_validation_iterations` (usar o remover).

## Fase 1 — Robustez de output (1-2 semanas)
1. Definir schemas Pydantic por agente (STRIDE/PASTA/AT/MAESTRO/AI/DREAD).
2. Validar y normalizar en cada nodo antes de append a `methodology_reports`.
3. Crear “normalizador canónico” único de amenazas antes del synthesizer.
4. Reducir prompts: plantilla base + deltas por metodología.

## Fase 2 — Calidad de RAG (2-4 semanas)
1. Añadir reranker (cross-encoder o similar) para top-k final.
2. Guardar evidencia citada por amenaza (`evidence_refs`).
3. Configurar estrategias de query por fase (analyst vs debate vs validator).
4. Añadir tests de regresión de retrieval por categoría.

## Fase 3 — Inteligencia adaptativa (1-2 meses)
1. Debate con criterio de convergencia (no rondas fijas).
2. Confidence score por amenaza (calidad de evidencia + consenso entre agentes).
3. Calibración de DREAD con histórico de `previous_threat_models`.
4. Política de abstención: si falta evidencia, marcar “needs-review”.

## Fase 4 — Operación y producto (continuo)
1. Dashboard de calidad (run quality KPIs).
2. Versionado de prompts y AB testing controlado.
3. Lote de sistemas benchmark (10-20 arquitecturas patrón).
4. Guía de hardening para deploy productivo.

## 6) KPIs sugeridos para medir mejora

1. **Coverage útil**: amenazas válidas por componente crítico.
2. **Signal/Noise**: % amenazas aceptadas por revisor humano.
3. **Consistency DREAD**: desviación intra-categoría.
4. **Evidence Rate**: % amenazas con evidencia explícita.
5. **Latency SLA**: p95 por análisis.
6. **Reproducibility**: estabilidad de resultados en corridas repetidas.

## 7) Mi opinión final (sincera)

Tu sistema ya está en un nivel muy superior a un MVP básico: tiene diseño multi-fase real, RAG segmentado y pipeline razonablemente maduro. Pero para transformarlo en una plataforma confiable de seguridad (no solo demostrable), hay que atacar ya la parte de **ingesta documental robusta**, **contratos de salida estrictos** y **métrica de calidad**.

Si tuviera que elegir solo 3 prioridades para maximizar impacto en el corto plazo:
1. Parsing real de PDF + hardening de uploads
2. Validación estructural estricta de outputs de todos los agentes
3. Citas/evidencia obligatoria por amenaza + score de confianza

Con eso, la calidad percibida y la confiabilidad técnica subirían de forma muy visible en pocas semanas.
