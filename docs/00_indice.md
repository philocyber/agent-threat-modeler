# 📖 AgenticTM — Documentación Completa

> **Versión:** 0.3.2 · **Última actualización:** Febrero 2026
> **Motor:** Pipeline multi-agente de Threat Modeling con LangGraph + Ollama

---

## Índice General

| N° | Documento | Descripción |
|----|-----------|-------------|
| 01 | [Introducción y Visión](01_introduccion.md) | Origen del proyecto, qué problema resuelve, diferenciadores, requisitos de sistema |
| 02 | [Fundamentos Académicos](02_fundamentos_academicos.md) | Frameworks y papers de investigación: STRIDE, PASTA, DREAD, MAESTRO, OWASP, PLOT4ai, Agent Protocol Security |
| 03 | [Arquitectura del Pipeline](03_arquitectura_pipeline.md) | Las 6 fases del grafo LangGraph, topología del grafo, estado compartido, modos de ejecución hybrid/cascade/parallel |
| 04 | [Agentes en Profundidad](04_agentes.md) | Los 13 nodos del pipeline: prompts, entradas/salidas, herramientas RAG, tier de LLM, algoritmos internos |
| 05 | [Sistema RAG](05_sistema_rag.md) | Arquitectura dual ChromaDB + PageIndex, 5 vector stores, categorías, indexador, herramientas de consulta |
| 06 | [Modelos LLM](06_modelos_llm.md) | Arquitectura de 4 tiers, LLMFactory, 5 providers soportados, recomendaciones de hardware |
| 07 | [API y Frontend](07_api_y_frontend.md) | 28+ endpoints FastAPI, SSE streaming, SPA frontend, autenticación, persistencia SQLite |
| 08 | [Configuración Completa](08_configuracion.md) | Referencia de config.json, variables de entorno, Pydantic models, seguridad |
| 09 | [Guía de Uso](09_guia_de_uso.md) | Instalación paso a paso, CLI, interfaz web, carga de archivos, selección de categorías |
| 10 | [Flujo de Datos](10_flujo_de_datos.md) | Diagramas de flujo de datos, transiciones de estado, qué lee y escribe cada agente |
| 11 | [Mejoras y Roadmap](11_mejoras_roadmap.md) | Estado actual MVP/POC, mejoras implementadas, backlog priorizado |
| 12 | [Troubleshooting](12_troubleshooting.md) | Errores comunes, FAQ, glosario, tips de rendimiento |

---

## Navegación Rápida por Rol

### 🔧 Soy Developer — quiero entender el código
1. [Arquitectura del Pipeline](03_arquitectura_pipeline.md) → visión general
2. [Agentes en Profundidad](04_agentes.md) → cada agente con su prompt y lógica
3. [Flujo de Datos](10_flujo_de_datos.md) → qué lee y escribe cada nodo

### 🧠 Soy Investigador — quiero entender la teoría
1. [Fundamentos Académicos](02_fundamentos_academicos.md) → frameworks y papers
2. [Agentes en Profundidad](04_agentes.md) → cómo cada agente implementa cada metodología
3. [Sistema RAG](05_sistema_rag.md) → retrieval híbrido y knowledge base

### 🚀 Soy Usuario — quiero usar la herramienta
1. [Guía de Uso](09_guia_de_uso.md) → instalación y primeros pasos
2. [Configuración Completa](08_configuracion.md) → cómo personalizar el sistema
3. [Troubleshooting](12_troubleshooting.md) → solución de problemas

### 📊 Soy Security Engineer — quiero evaluar outputs
1. [Introducción y Visión](01_introduccion.md) → qué produce el sistema
2. [Agentes en Profundidad](04_agentes.md) → cómo se generan las amenazas
3. [Mejoras y Roadmap](11_mejoras_roadmap.md) → limitaciones conocidas

---

## Stack Tecnológico

```
┌──────────────────────────────────────────────────────┐
│                    AgenticTM v0.3.2                   │
├──────────────────────────────────────────────────────┤
│  Frontend   │ SPA HTML/JS · Mermaid v11 · marked.js  │
│  API        │ FastAPI · SSE · aiosqlite · uvicorn     │
│  Pipeline   │ LangGraph · 13 nodos · 6 fases          │
│  LLMs       │ Ollama (local) · 4 tiers de modelo      │
│  RAG        │ ChromaDB · PageIndex trees · nomic-embed │
│  Lenguaje   │ Python 3.13 · Pydantic v2 · Typer CLI   │
│  Deploy     │ Docker · docker-compose · CI/CD GitHub   │
└──────────────────────────────────────────────────────┘
```

---

## Convenciones de Esta Documentación

- **Idioma**: Español neutro/rioplatense
- **Diagramas**: Mermaid (renderizables en GitHub, VS Code, y la propia UI de AgenticTM)
- **Código**: Bloques con syntax highlighting de Python, JSON, YAML, bash
- **Tablas**: Para inventarios de agentes, configuraciones, endpoints, modelos
- **Navegación**: Links relativos entre documentos (`[texto](archivo.md)`)
- **Íconos**: 📖 docs, 🧠 concepto, 🔧 técnico, ⚠️ advertencia, ✅ implementado, ⬜ pendiente

---

*Siguiente: [01 — Introducción y Visión →](01_introduccion.md)*
