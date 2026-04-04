# Análisis Objetivo y Roadmap de Evolución (AgenticTM)

Fecha: 2026-02-24

## 1. Estado Actual del Parsing de Adjuntos (Respuesta Directa)

Actualmente, el sistema **SÍ** puede parsear archivos **Markdown (.md)** y texto plano (.txt) correctamente cuando se adjuntan en el prompt, ya que el código en `server.py` los lee directamente como texto UTF-8 y los inyecta en el contexto. Las **imágenes** también funcionan correctamente a través del VLM (`llava`).

Sin embargo, los archivos **PDF NO se están parseando correctamente** en el flujo de usuario. 
* **El problema técnico:** El endpoint `/api/analyze` asume que cualquier archivo que no sea una imagen es texto plano y ejecuta `Path(fpath).read_text(encoding="utf-8", errors="replace")`. Al hacer esto con un binario PDF, el resultado es una cadena de caracteres corruptos e ilegibles que confunde a los agentes.
* **La ironía:** El sistema ya tiene la capacidad de leer PDFs en la base de conocimiento (RAG) usando `PyPDFLoader` en `indexer.py`, pero esta lógica no se aplicó a los uploads del usuario.

---

## 2. Evaluación Profunda del Sistema

He analizado la arquitectura, el código, el flujo de LangGraph, las habilidades agénticas y los prompts. Aquí está mi evaluación honesta y sin filtros:

### A. Flujo de Trabajo (Workflow & LangGraph)
* **Fortalezas:** La arquitectura de "Fan-out / Fan-in" (ejecutar STRIDE, PASTA, Attack Tree, MAESTRO y AI Threat en paralelo, y luego sintetizar) es brillante y muy eficiente. El validador DREAD al final actúa como un excelente control de calidad.
* **Debilidades:** El debate entre el Red Team y el Blue Team es **estático** (basado en un número fijo de rondas configurado en `config.json`). Un verdadero flujo agéntico debería ser **dinámico**: debatir hasta que se alcance un consenso o un agente "Juez" determine que no hay más valor en continuar.

### B. Código y Robustez
* **Fortalezas:** El uso de Server-Sent Events (SSE) en FastAPI para streamear los logs de los agentes a la UI en tiempo real proporciona una experiencia de usuario excepcional.
* **Debilidades:** El archivo `base.py` contiene una función masiva (`extract_json_from_response`) llena de expresiones regulares y heurísticas para intentar arreglar JSONs rotos generados por los LLMs. Esto es un "code smell" (síntoma de un problema subyacente). En 2026, depender de regex para parsear JSON de LLMs es frágil.

### C. Habilidades Agénticas
* **Fortalezas:** Los agentes tienen acceso a herramientas RAG muy bien segmentadas (libros, investigaciones, riesgos, modelos previos).
* **Debilidades:** Los agentes actuales son en realidad "LLMs con herramientas" (Tool Calling), no agentes verdaderamente autónomos. Carecen de un ciclo de **auto-reflexión (Self-Correction)**. Si el *Threat Synthesizer* genera un reporte pobre, no hay un mecanismo interno donde él mismo lo lea, se dé cuenta de que le faltan mitigaciones, y lo re-escriba antes de pasarlo al siguiente nodo.

### D. Prompts de Sistema (System Prompts)
* **Fortalezas:** Los roles están muy bien definidos y las instrucciones metodológicas (ej. las 7 capas de MAESTRO o las 8 categorías de PLOT4ai) son exhaustivas.
* **Debilidades:** 
  1. **Spanglish:** Los prompts mezclan español e inglés ("Sos un analista... Your task is..."). Esto degrada el rendimiento de modelos más pequeños (como los de 8B parámetros), que funcionan mucho mejor cuando el System Prompt es 100% en inglés (su idioma nativo de entrenamiento), indicándoles al final que la *salida* debe ser en español.
  2. **Sobrecarga Cognitiva:** Se les pide a los modelos que razonen, usen herramientas, y además formateen la salida en esquemas JSON gigantescos y complejos en un solo paso.

### E. Configuración de Modelos (El "Elefante en la Habitación")
* **Problema Crítico:** La arquitectura está diseñada para tener un `quick_thinker` (rápido/barato para tareas simples) y un `deep_thinker` (lento/inteligente para síntesis y validación). Sin embargo, en `config.json`, **ambos apuntan exactamente al mismo modelo** (`qwen3:8b`). Esto anula por completo la ventaja de la arquitectura multi-tier. Un modelo de 8B parámetros no tiene la capacidad de razonamiento profundo necesaria para el *Threat Synthesizer* o el *DREAD Validator*.

> **✅ Resuelto en v0.3.2:** Ahora hay 4 tiers diferenciados: quick=`qwen3:4b`, stride=`qwen3.5:9b`, deep=`gemma4:26b`, vlm=`qwen3.5:9b`. Además, `cli.py init` auto-configura los modelos según el RAM disponible.

---

## 3. Plan de Acción Futuro (Roadmap)

Basado en esta evaluación, propongo el siguiente plan de acción priorizado para llevar a AgenticTM al siguiente nivel de madurez (Production-Grade):

### Fase 1: Estabilidad y Correcciones Inmediatas (Corto Plazo)
1. **Arreglar el Parsing de PDF en Uploads:** Importar `PyPDFLoader` (o `pdfplumber`/`pymupdf`) en `server.py` para extraer el texto real de los PDFs adjuntos por el usuario antes de inyectarlos al prompt.
2. **Refactorización de Prompts (English-First):** Traducir todos los System Prompts a 100% inglés para maximizar la comprensión del LLM, añadiendo una instrucción estricta: `"All generated content, descriptions, and reasoning MUST be in Spanish."`
3. **Diferenciación Real de Modelos:** Actualizar `config.json` para que el `deep_thinker` use un modelo de mayor capacidad (ej. `qwen3:32b`, `llama3:70b`, o APIs externas como GPT-4o/Claude 3.5 Sonnet si hay presupuesto), reservando el `8b` solo para los analistas paralelos.

### Fase 2: Robustez Estructural (Mediano Plazo)
4. **Migrar a Structured Outputs:** Eliminar el frágil `extract_json_from_response`. Utilizar `with_structured_output(PydanticModel)` de LangChain. Esto obliga al LLM a nivel de API/Inferencia a devolver un JSON que cumpla estrictamente con el esquema definido, eliminando el 99% de los errores de parseo.
5. **Mejorar el RAG con Re-ranking:** Actualmente el RAG trae los top-K documentos basados solo en similitud de embeddings. Implementar un modelo de *Cross-Encoder (Re-ranker)* mejorará drásticamente la relevancia de la evidencia que los agentes usan para justificar las amenazas.

### Fase 3: Autonomía Agéntica Avanzada (Largo Plazo)
6. **Debate Dinámico con Juez:** Modificar el grafo de LangGraph para el debate Red/Blue. En lugar de rondas fijas, introducir un nodo "Juez" que evalúe después de cada ronda si se ha llegado a un consenso o si los argumentos se están repitiendo, cortando el ciclo dinámicamente.
7. **Ciclos de Auto-Reflexión (Self-Correction):** Añadir un paso de validación interna en el *Threat Synthesizer*. Antes de emitir el JSON final, el agente debe evaluar su propio trabajo contra una rúbrica (ej. "¿Tienen todas las amenazas mitigaciones accionables?"). Si falla, se auto-corrige.
8. **Trazabilidad de Evidencia (Citations):** Obligar a los agentes a incluir un campo `"evidence_source"` en cada amenaza generada, apuntando exactamente a qué documento del RAG o qué parte del diagrama justificó la creación de esa amenaza.