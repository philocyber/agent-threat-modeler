# 10 — Flujo de Datos

> State transitions, qué lee y escribe cada agente, y cómo los datos fluyen por las 6 fases.

---

## `ThreatModelState` — El Bus de Datos

Todos los agentes comparten un único `ThreatModelState` (TypedDict) que funciona como bus de datos. LangGraph gestiona la fusión de updates parciales al state.

```mermaid
classDiagram
    class ThreatModelState {
        +str system_input
        +str system_name
        +list~str~ threat_categories
        +list~str~ upload_paths
        +str dfd_mermaid
        +list~Component~ components
        +list~DataFlow~ data_flows
        +list~TrustBoundary~ trust_boundaries
        +list~str~ input_images
        +list~dict~ stride_analysis
        +list~dict~ pasta_analysis
        +list~dict~ attack_trees
        +list~dict~ maestro_analysis
        +list~dict~ ai_threat_analysis
        +list~DebateEntry~ debate_history
        +list~dict~ threats_unified
        +list~dict~ threats_validated
        +list~dict~ threats_final
        +str csv_output
        +str report_output
        +str latex_output
        +dict agent_metrics
        +dict config
        +int debate_round
        +int max_debate_rounds
    }
```

### Campos con `Annotated[list, operator.add]`

Los campos de tipo lista usan `Annotated[list, operator.add]` — esto significa que cuando dos nodos escriben al mismo campo, LangGraph **concatena** las listas en lugar de sobrescribir:

```python
# Nodo 1 retorna: {"stride_analysis": [threat_A, threat_B]}
# Nodo 2 retorna: {"pasta_analysis": [threat_C, threat_D]}
# Al fan-in: state tiene ambas listas completas
```

Esto es lo que permite el **fan-out** de analistas en parallel/hybrid — cada analista escribe a su propio campo sin conflictos.

---

## Mapa Lectura/Escritura por Agente

### Tabla Completa

| Agente | Lee | Escribe |
|--------|-----|---------|
| **Architecture Parser** | `system_input`, `upload_paths`, `input_images`, `config` | `components`, `data_flows`, `trust_boundaries`, `dfd_mermaid`, `input_images` |
| **STRIDE Analyst** | `system_input`, `components`, `data_flows`, `trust_boundaries`, `dfd_mermaid` | `stride_analysis` |
| **PASTA Analyst** | `system_input`, `components`, `data_flows` | `pasta_analysis` |
| **Attack Tree Analyst** (initial) | `system_input`, `components`, `data_flows`, `stride_analysis`, `pasta_analysis` | `attack_trees` |
| **MAESTRO Analyst** | `system_input`, `components`, `data_flows` | `maestro_analysis` |
| **AI Threat Analyst** | `system_input`, `components`, `data_flows` | `ai_threat_analysis` |
| **Red Team** | `system_input`, `components`, `stride_analysis`, `pasta_analysis`, `attack_trees`, `debate_history` | `debate_history` |
| **Blue Team** | `system_input`, `components`, `stride_analysis`, `debate_history` | `debate_history` |
| **Attack Tree Analyst** (enriched) | `system_input`, `components`, `attack_trees`, `debate_history` | `attack_trees` (append) |
| **Threat Synthesizer** | `stride_analysis`, `pasta_analysis`, `attack_trees`, `maestro_analysis`, `ai_threat_analysis`, `debate_history`, `components` | `threats_unified` |
| **DREAD Validator** | `threats_unified` OR `threats_validated` | `threats_validated` |
| **Output Localizer** | `threats_validated`, `config` | `threats_final` |
| **Report Generator** | `threats_final`, `dfd_mermaid`, `attack_trees`, `debate_history`, `system_input`, `system_name`, `components` | `csv_output`, `report_output`, `latex_output` |

---

## Flujo por Fase

### Fase I — Análisis de Arquitectura

```mermaid
flowchart LR
    INPUT["system_input<br/>upload_paths<br/>input_images"] --> AP["Architecture<br/>Parser"]
    AP --> STATE1["components ✓<br/>data_flows ✓<br/>trust_boundaries ✓<br/>dfd_mermaid ✓"]

    style INPUT fill:#1e3a5f,stroke:#4a90d9,color:#fff
    style AP fill:#2d1b4e,stroke:#a773bf,color:#fff
    style STATE1 fill:#1a3c34,stroke:#10b981,color:#fff
```

**Input**: Texto del sistema + archivos subidos + imágenes
**Output**: Componentes estructurados, flujos de datos, trust boundaries, DFD en Mermaid

### Fase II — Analistas en Paralelo/Hybrid/Cascade

```mermaid
flowchart TB
    STATE1["components<br/>data_flows<br/>trust_boundaries"] --> FAN["Fan-Out"]
    
    FAN --> STRIDE["STRIDE"]
    FAN --> PASTA["PASTA"]
    FAN --> AT["Attack Tree<br/>(initial)"]
    FAN --> MAESTRO["MAESTRO<br/>(condicional)"]
    FAN --> AI["AI Threat<br/>(condicional)"]

    STRIDE --> MERGE["Fan-In<br/>operator.add"]
    PASTA --> MERGE
    AT --> MERGE
    MAESTRO --> MERGE
    AI --> MERGE

    MERGE --> STATE2["stride_analysis ✓<br/>pasta_analysis ✓<br/>attack_trees ✓<br/>maestro_analysis ✓<br/>ai_threat_analysis ✓"]

    style FAN fill:#3b2a1a,stroke:#f59e0b,color:#fff
    style MERGE fill:#3b2a1a,stroke:#f59e0b,color:#fff
    style STATE2 fill:#1a3c34,stroke:#10b981,color:#fff
```

**Input**: Arquitectura parseada (componentes, flujos, boundaries)
**Output**: 5 análisis independientes de metodologías diferentes

**Nota**: MAESTRO solo se activa si el input contiene ~30 keywords de AI/ML. AI Threat solo se activa si detecta protocolos agénticos.

### Fase III — Debate Adversarial

```mermaid
flowchart LR
    STATE2["stride_analysis<br/>pasta_analysis<br/>attack_trees"] --> RED["Red Team"]
    RED --> BLUE["Blue Team"]
    BLUE --> CHECK{"¿Convergencia<br/>o max rounds?"}
    CHECK -->|No| RED
    CHECK -->|Sí| STATE3["debate_history ✓"]

    style RED fill:#3b1d1d,stroke:#ef4444,color:#fff
    style BLUE fill:#1e3a5f,stroke:#4a90d9,color:#fff
    style STATE3 fill:#1a3c34,stroke:#10b981,color:#fff
```

**Input**: Los 5 análisis + debate history acumulado
**Output**: `debate_history` con rondas de argumentos Red/Blue

El debate termina cuando:
1. Se alcanza `max_debate_rounds`, o
2. El Blue Team emite señal de convergencia (`CONVERGENCE_REACHED`)

### Fase II.5 — Attack Trees Enriquecidos

```mermaid
flowchart LR
    STATE3["attack_trees (initial)<br/>debate_history"] --> ATE["Attack Tree<br/>(enriched)"]
    ATE --> STATE35["attack_trees ✓<br/>(initial + enriched)"]

    style ATE fill:#2d1b4e,stroke:#a773bf,color:#fff
    style STATE35 fill:#1a3c34,stroke:#10b981,color:#fff
```

**Input**: Attack trees iniciales + insights del debate
**Output**: Attack trees enriquecidos (appended a la lista existente)

### Fase IV — Síntesis y Validación

```mermaid
flowchart LR
    ALL["stride + pasta +<br/>attack_trees +<br/>maestro + ai_threat +<br/>debate_history"] --> SYN["Threat<br/>Synthesizer"]
    SYN --> UNIFIED["threats_unified ✓"]
    UNIFIED --> DREAD["DREAD<br/>Validator"]
    DREAD --> VALIDATED["threats_validated ✓"]

    style SYN fill:#2d1b4e,stroke:#a773bf,color:#fff
    style DREAD fill:#1a3c34,stroke:#10b981,color:#fff
```

**Input Synthesizer**: Todos los análisis + debate (15-30K tokens de contexto)
**Output Synthesizer**: Lista unificada con categorías, STRIDE inferido, mitigaciones

**Input DREAD**: `threats_unified` (primera pasada) o `threats_validated` (re-validación)
**Output DREAD**: Scores calibrados con 80% guardrail

### Fase V — Localización

```mermaid
flowchart LR
    VALIDATED["threats_validated"] --> LOC["Output<br/>Localizer"]
    LOC --> FINAL["threats_final ✓"]

    style LOC fill:#2d1b4e,stroke:#a773bf,color:#fff
    style FINAL fill:#1a3c34,stroke:#10b981,color:#fff
```

**Input**: `threats_validated` + `config.pipeline.output_language`
**Output**: `threats_final` con campos traducidos al español (si `output_language == "es"`)

**Qué traduce**: description, mitigation, attack_vector
**Qué NO traduce**: id, STRIDE category, DREAD scores, component names, technical terms

### Fase VI — Generación de Reportes

```mermaid
flowchart LR
    FINAL["threats_final<br/>dfd_mermaid<br/>attack_trees<br/>debate_history<br/>system_name"] --> REP["Report<br/>Generator"]
    REP --> OUT["csv_output ✓<br/>report_output ✓<br/>latex_output ✓"]

    style REP fill:#1a3c34,stroke:#10b981,color:#fff
    style OUT fill:#1e3a5f,stroke:#4a90d9,color:#fff
```

**Input**: Todos los resultados finales
**Output**: Tres formatos de reporte (CSV 16 columnas, Markdown, LaTeX)

---

## Diagrama Completo: Estado a lo Largo del Pipeline

```mermaid
graph TD
    subgraph "State Accumulation"
        S0["Initial State<br/>system_input ✓<br/>system_name ✓<br/>threat_categories ✓"]
        
        S1["After Phase I<br/>+ components<br/>+ data_flows<br/>+ trust_boundaries<br/>+ dfd_mermaid"]
        
        S2["After Phase II<br/>+ stride_analysis<br/>+ pasta_analysis<br/>+ attack_trees<br/>+ maestro_analysis<br/>+ ai_threat_analysis"]
        
        S3["After Phase III<br/>+ debate_history"]
        
        S35["After Phase II.5<br/>+ attack_trees_enriched"]
        
        S4["After Phase IV<br/>+ threats_unified<br/>+ threats_validated"]
        
        S5["After Phase V<br/>+ threats_final"]
        
        S6["After Phase VI<br/>+ csv_output<br/>+ report_output<br/>+ latex_output"]
    end

    S0 --> S1 --> S2 --> S3 --> S35 --> S4 --> S5 --> S6

    style S0 fill:#1e3a5f,stroke:#4a90d9,color:#fff
    style S6 fill:#1a3c34,stroke:#10b981,color:#fff
```

---

## Volumen de Datos por Fase

| Fase | Input (tokens aprox.) | Output (tokens aprox.) | Campos State Nuevos |
|------|----------------------|------------------------|---------------------|
| I | 1-5K (input) | 2-8K (architecture) | 4 campos |
| II | 2-8K × 5 agents | 2-5K × 5 outputs | 5 campos |
| III | 10-25K (all analyses) × rounds | 2-5K × round | 1 campo (append) |
| II.5 | 5-10K (trees + debate) | 2-5K | 1 campo (append) |
| IV | 15-30K (all + debate) | 3-8K (unified) → 3-8K (validated) | 2 campos |
| V | 3-8K (validated) | 3-8K (translated) | 1 campo |
| VI | 5-10K (final + context) | 5-15K (reports) | 3 campos |

**Total acumulado en state final**: ~50-100K tokens de datos estructurados.

---

## Manejo de Errores en el Flujo

```mermaid
flowchart TD
    NODE["Cualquier nodo"] --> SAFE{"_safe_node()"}
    SAFE -->|"Éxito"| OK["Return state update"]
    SAFE -->|"Excepción"| CRIT{"¿Nodo<br/>crítico?"}
    CRIT -->|"Sí (architecture_parser)"| RAISE["Re-raise → pipeline falla"]
    CRIT -->|"No (resto)"| DEGRADE["Return {} → state no cambia<br/>Pipeline continúa"]

    style RAISE fill:#3b1d1d,stroke:#ef4444,color:#fff
    style DEGRADE fill:#3b2a1a,stroke:#f59e0b,color:#fff
```

| Tipo de Nodo | Comportamiento si falla |
|--------------|------------------------|
| **Crítico** (`architecture_parser`) | Pipeline aborta — sin arquitectura no hay análisis posible |
| **No-crítico** (todos los demás) | Degradación graciosa — ese campo queda vacío, el pipeline continúa |

El Synthesizer puede producir resultados útiles incluso si uno o dos analistas fallaron, porque tiene datos de los otros 3-4 metodologías.

---

*[← 09 — Guía de Uso](09_guia_de_uso.md) · [11 — Mejoras y Roadmap →](11_mejoras_roadmap.md)*
