# Threat Modeling Agéntico: Sistemas Multi-Agente para Automatizar el Modelado de Amenazas en Ciberseguridad

## Resumen

El Threat Modeling tradicional enfrenta limitaciones críticas: es manual, estático, dependiente de expertos y lento frente a la velocidad del cambio en arquitecturas modernas. La convergencia de Large Language Models (LLMs), sistemas multi-agente y técnicas como Retrieval-Augmented Generation (RAG) está habilitando una nueva generación de herramientas que automatizan parcial o totalmente el proceso de modelado de amenazas — desde la ingesta de descripciones de arquitectura hasta la generación de diagramas interactivos con amenazas documentadas y mitigaciones sugeridas.[^1][^2]

Esta investigación cubre el estado del arte en:
- Papers académicos y frameworks teóricos
- Herramientas open-source y repositorios GitHub existentes
- Técnicas de generación automática de diagramas de arquitectura y grafos de amenazas
- Frameworks de orquestación multi-agente aplicables (LangGraph, CrewAI, AutoGen)
- El nuevo panorama de amenazas para sistemas agénticos (OWASP Agentic Top 10, MAESTRO)

***

## Fundamentos: Por Qué Automatizar el Threat Modeling

Los métodos convencionales de threat modeling — STRIDE, DREAD, OCTAVE, PASTA, Trike — fueron diseñados para análisis manual con participación de expertos humanos. Si bien categorías como Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service y Elevation of Privilege siguen siendo relevantes, estos frameworks presentan gaps significativos cuando se aplican a sistemas modernos:[^3]

- **Escalabilidad**: Organizaciones con cientos de microservicios y pipelines CI/CD no pueden realizar threat modeling manual para cada cambio.[^4]
- **Falta de especificidad AI**: Frameworks tradicionales no capturan amenazas como prompt injection, data poisoning, model inversion, agent collusion o goal misalignment.[^5][^3]
- **Tiempo**: Un threat model manual exhaustivo puede tomar días o semanas, mientras que herramientas automatizadas generan modelos iniciales en minutos.[^6]
- **Accesibilidad**: Equipos sin expertos dedicados en seguridad quedan excluidos del proceso.[^7]

***

## Papers Académicos y Frameworks de Referencia

### CORAS Threat Modeler: Multi-Agent Pipeline con RAG

El trabajo más avanzado en threat modeling multi-agente es el **CORAS Threat Modeler**, desarrollado por SINTEF (Noruega) y publicado en IEEE DSA 2025. Es un pipeline open-source que transforma descripciones en lenguaje natural en modelos de amenazas CORAS completos (grafos acíclicos dirigidos).[^1][^7]

**Arquitectura multi-agente:**

| Agente | Función | Modelo LLM | Detalle |
|--------|---------|------------|---------|
| **Summarizer** | Transforma texto libre en descripción estructurada | llama3:70b-instruct | Prompt fijo, temperatura 0 |
| **RAG Module** | Busca contexto en CAPEC/CWE vía FAISS vector DB | llama3:8b (re-ranking) | Euclidean similarity + re-ranking contextual |
| **Assessor** | Genera tabla de riesgos + descripción detallada | llama3:70b-instruct | Two-phase assessment (tabla + detalles) |
| **Formatter** | Convierte risk assessment en JSON CORAS DAG | llama3:70b-instruct | Schema-constrained generation + few-shot prompting |
| **Navigator** | Orquestador central del pipeline | — | Coordina secuencialmente Summarizer→RAG→Assessor→Formatter |

El output final se renderiza como un diagrama CORAS interactivo vía **JointJS** en el navegador, con layout BFS (breadth-first search) jerárquico. Los vértices representan threat actors, threat scenarios, vulnerabilities (CWE), unwanted incidents, assets y mitigations, conectados por edges causales.[^7]

Fue evaluado en tres case studies de healthcare con resultados positivos: modelos sintácticamente correctos, riesgos contextualmente relevantes, y reducción de la barrera de entrada para no-expertos. Las limitaciones incluyen cobertura limitada de riesgos de safety (vs. security), y UI que necesita mejoras de UX.[^7]

Repositorio: [CORAS-The-Explorer (GitHub)](https://github.com/stverdal/CORAS-The-Explorer/tree/navigator).[^7]

### ThreatModeling-LLM: Fine-Tuning para Banca

Este framework, publicado en arXiv (2024), automatiza threat modeling para sistemas bancarios usando un pipeline de tres etapas: creación de dataset (50 sistemas bancarios modelados en Microsoft TMT), prompt engineering (Chain of Thought + OPRO), y fine-tuning con LoRA sobre Llama-3.1-8B. Logró mejorar la precisión de identificación de mitigaciones de 0.36 a 0.69, alineadas con NIST 800-53.[^2][^8]

### ASTRIDE: Threat Modeling Visual para Sistemas Agénticos

ASTRIDE (diciembre 2025) es la primera plataforma que extiende STRIDE con una categoría "A" para AI Agent-Specific Attacks y utiliza un **consorcio de Vision-Language Models (VLMs) fine-tuned** junto con un reasoning LLM (OpenAI-gpt-oss) para automatizar threat modeling directamente desde diagramas de arquitectura visuales (DFDs). Los LLM agents orquestan el proceso end-to-end coordinando VLMs y el LLM de razonamiento.[^5]

### ThreatFinderAI: Knowledge Graph para AI Systems

Desarrollado por la Universidad de Zúrich y presentado en IEEE CNSM 2024, ThreatFinderAI transforma knowledge bases de amenazas AI en un **grafo de conocimiento queryable** con 96 amenazas distintas. Incluye una stencil library AI-based para extracción automatizada de assets, y el modelo puede exportarse a draw.io. Su enfoque asset-centric permite mapear amenazas específicas de AI systems a través de 7 pasos alineados con el diseño de sistemas AI.[^9][^10][^11]

### Multi-Agent Framework for Threat Mitigation

Un framework empírico publicado en arXiv (2025) analiza 93 amenazas ML extraídas de MITRE ATLAS (26), AI Incident Database (12) y literatura (55), complementadas con 854 repositorios GitHub. Propone un pipeline de tres pasos que combina retrieval-augmented reasoning, ontology alignment y **heterogeneous Graph Neural Networks (GNNs)** para estimar severidad de amenazas.[^12]

### PriMod4AI: Privacy Threat Modeling para AI

Este trabajo introduce un enfoque híbrido que unifica amenazas LINDDUN clásicas con ataques de privacidad específicos de AI, usando LLMs para automatizar la identificación de amenazas de privacidad en sistemas AI.[^13]

### Integrated Approach: ISO 42001 + NIST AI RMF + MITRE ATLAS + MAESTRO + OWASP

Un paper publicado en Cybersecurity and Information Security Journal (2025) propone un enfoque integrado que combina ISO/IEC 42001:2023 (governance), NIST AI RMF 1.0 (Govern–Map–Measure–Manage), MITRE ATLAS (escenarios de ataque realistas), CSA MAESTRO (descomposición multi-capa), y OWASP GenAI Security Project (artifacts operacionales). El threat modeling se vuelve continuo y evidence-based, integrado con CI/CD pipelines.[^4]

***

## Herramientas Open-Source y Repositorios GitHub

### Herramientas con AI/LLM Integration

| Herramienta | GitHub Stars | Enfoque | AI/Multi-Agent | Diagramas | Licencia |
|-------------|-------------|---------|----------------|-----------|----------|
| **STRIDE GPT** | 852⭐ | STRIDE + DREAD + Gherkin | LLM single-agent (multi-provider) | Mermaid attack trees | MIT |
| **Arrows** | 13⭐ | STRIDE + whitebox analysis | AI Agent (LLM-driven) | Network graph interactivo | Open-source |
| **CORAS Threat Modeler** | Nuevo | CORAS risk assessment | Multi-agent pipeline (4 agents + RAG) | CORAS DAG (JointJS) | Open-source |
| **Threagile** | 725⭐ | YAML-based risk rules (~40) | No AI (rule-based) | Data flow + data mapping graphs | Open-source |
| **OWASP pytm** | Activo | Threat modeling as code | No AI (rule-based) | DFD + sequence (Graphviz/PlantUML) | OWASP |
| **Threat Thinker** | PoC | Diagram parsing + threats | LLM hybrid (parsing + inference) | Parsea Mermaid/draw.io/Threat Dragon | PoC |

### STRIDE GPT (mrwadams/stride-gpt)

La herramienta más madura y popular en su categoría. Soporta múltiples proveedores de LLM (OpenAI, Anthropic, Google AI, Mistral, Groq, Ollama, LM Studio), incluyendo modelos de razonamiento avanzado (GPT-5 series, Claude 4, Magistral).[^14][^6]

**Capacidades clave:**
- **Multi-modal**: Acepta diagramas de arquitectura como input para threat modeling usando vision-capable models[^14]
- **Attack trees**: Genera árboles de ataque en formato Mermaid con visualización interactiva[^6]
- **DREAD scoring**: Asigna scores de riesgo (Damage, Reproducibility, Exploitability, Affected Users, Discoverability) para priorización[^6]
- **Gherkin test cases**: Genera test cases BDD integrables en pipelines de testing automatizado[^6]
- **GitHub repo analysis**: Analiza README y archivos clave de repositorios GitHub para generar threat models más comprehensivos[^14]
- **Docker deployment**: Disponible como imagen de container[^14]

Repositorio: [mrwadams/stride-gpt](https://github.com/mrwadams/stride-gpt)[^14]

### Arrows (yacwagh/arrows)

Un AI Agent para threat modeling que combina análisis basado en descripción textual con **whitebox analysis de codebases**. Produce un threat model con componentes, data flows, assets, trust boundaries y un **grafo de red interactivo** que visualiza las relaciones entre componentes.[^15][^16]

El análisis whitebox es language-agnostic: sube un codebase como ZIP, el sistema extrae la arquitectura, ejecuta STRIDE, y genera visualizaciones interactivas más reportes detallados de amenazas. Procesa hasta 30 archivos por run con estrategias de chunking para archivos grandes.[^15]

Repositorio: [yacwagh/arrows](https://github.com/yacwagh/arrows)

### Threat Thinker

Una herramienta PoC (presentada en CyberTAMAGO) que parsea diagramas de arquitectura escritos en Mermaid, draw.io, o Threat Dragon, combinando **parsing sintáctico con inferencia LLM** para extraer componentes, data flows y trust boundaries. Genera una lista priorizada de amenazas con scoring de impacto y likelihood.[^17][^18]

### Threagile

El toolkit open-source más establecido para threat modeling declarativo (725⭐). Modela el sistema completo como un archivo YAML que incluye Data Assets, Technical Assets, Communication Links y Trust Boundaries. Analiza el YAML como un grafo de componentes conectados y genera:

- **Model Graphs / Diagrams** (data flow y data mapping)
- **~40 reglas de riesgo coded** (DoS across trust boundary, XSS, missing build infrastructure, etc.)
- **Reports** en PDF, Excel y JSON (para automatización DevSecOps)
- **Relative Attacker Attractiveness (RAA)** por componente
- **Data Breach Probability (DBP)** por data asset[^19]

Se integra con CI/CD pipelines vía GitHub Actions y ofrece validación de schema YAML en IDEs con auto-completion.[^19]

Repositorio: [Threagile/threagile](https://github.com/Threagile/threagile)

### OWASP pytm

Framework Pythonic de OWASP para threat modeling as code. Permite definir actors, componentes, trust boundaries y data flows como objetos Python, y automáticamente genera DFDs (via Graphviz), sequence diagrams (via PlantUML), y reportes de amenazas STRIDE.[^20][^21][^22]

```bash
python3 model.py --dfd | dot -Tpng -o model-dfd.png
python3 model.py --seq | plantuml -tpng -pipe > model-seq.png
python3 model.py --report basic_template.md > model-report.md
```

Es ideal para integración en CI/CD pipelines: el "meta file" se checkea en el repo y genera DFD + threat model automáticamente en cada build.[^20]

***

## Frameworks de Amenazas para Sistemas Agénticos

### MAESTRO (CSA)

**Multi-Agent Environment, Security, Threat, Risk, & Outcome** es el framework de threat modeling de la Cloud Security Alliance diseñado específicamente para Agentic AI. Propone una **arquitectura de 7 capas**:[^3]

1. Foundation Models (core AI capabilities)
2. Data Operations (information management)
3. Agent Frameworks (development tools)
4. Deployment Infrastructure
5. Security Layer
6. Agent Ecosystem
7. Business Applications

Cada capa tiene su propio threat landscape, y el framework enfatiza **cross-layer threat identification** — cómo vulnerabilidades en una capa impactan otras. MAESTRO aborda gaps que STRIDE no cubre, como:[^3]

- **Agent unpredictability**: Acciones impredecibles de agentes autónomos
- **Goal misalignment**: Objetivos del agente desalineados del propósito original
- **Agent collusion**: Agentes coordinándose secretamente para fines maliciosos
- **Sybil attacks**: Identidades falsas de agentes para influencia desproporcionada[^3]

### OWASP Top 10 for Agentic Applications (2026)

El framework más reciente, con prefijo ASI (Agentic Security Issue), mapea vulnerabilidades al flujo agéntico: inputs, model processing, tool integrations, inter-agent communication, y outputs:[^23][^24]

| Rank | Vulnerabilidad | Descripción |
|------|---------------|-------------|
| ASI01 | Agent Goal Hijacking | Manipulación de objetivos vía inputs envenenados (emails, PDFs, RAG docs) |
| ASI02 | Tool Misuse | Agentes invocando herramientas de forma insegura o no autorizada |
| ASI03 | Identity & Privilege Abuse | Abuso de credenciales y privilegios del agente |
| ASI04 | Supply Chain Vulnerabilities | Dependencias y frameworks comprometidos (ej: Langflow CVE-2025-34291) |
| ASI05 | Unexpected Code Execution | Ejecución de código no anticipada por el agente |
| ASI06 | Memory & Context Poisoning | Envenenamiento de la memoria y contexto del agente |
| ASI07 | Insecure Inter-Agent Communication | Comunicaciones inseguras entre agentes |
| ASI08 | Cascading Failures | Fallos en cascada a través del sistema multi-agente |
| ASI09 | Human-Agent Trust Exploitation | Explotación de la confianza humana en el agente |
| ASI10 | Rogue Agents | Agentes comprometidos que actúan de forma adversaria mientras parecen normales |

Incidentes reales documentados incluyen: Langflow RCE (CVE-2025-34291) explotado por múltiples threat actors, OpenAI Operator data exposure demostrada por investigadores, y el compromiso de 230,000+ clusters Ray en diciembre 2025.[^23]

***

## Generación Automatizada de Diagramas de Arquitectura y Amenazas

### Estrategias de Visualización

La generación automática de diagramas estéticos y funcionales de arquitectura es un componente crítico del threat modeling agéntico. El output ideal incluye: componentes del sistema, data flows direccionales, trust boundaries (interno/web/público), y amenazas mapeadas visualmente a los componentes afectados.

### Herramientas de Diagram-as-Code

| Herramienta | Mejor Para | Syntax | Rendering |
|------------|-----------|--------|-----------|
| **Mermaid.js** | Flowcharts, architecture diagrams, GitHub READMEs | Markdown-like | GitHub nativo, browser |
| **D2** | Diagramas complejos de arquitectura, microservicios | Declarativo moderno | SVG, con AI assistant |
| **Graphviz** | Dependency graphs grandes (100+ nodos), layouts matemáticos | DOT language | PNG/SVG |
| **PlantUML** | UML, sequence diagrams, class diagrams | Text-based | PNG/SVG |
| **Python Diagrams** | Cloud architecture (AWS/GCP/Azure icons nativos) | Python code | PNG |

**Mermaid Architecture Diagrams (v11.1.0+)**: Soporte nativo para diagramas de arquitectura con services (nodos), edges direccionales, y groups para organizar servicios relacionados. Sintaxis declarativa con keyword `architecture-beta`.[^25]

**D2**: Lenguaje moderno de diagramas con AI assistant integrado. Permite describir arquitecturas en lenguaje natural y genera código D2 completo. Soporta 8+ tipos de shapes, containers anidados, y estilos avanzados. Ideal para diagramas de microservicios y cloud infrastructure.[^26]

**Python Diagrams**: Permite crear diagramas de arquitectura cloud usando Python puro con iconos nativos de AWS, GCP, Azure, Kubernetes, etc. Define nodos y edges programáticamente con clusters para trust boundaries.[^27]

### Integración con Threat Modeling

Las herramientas más avanzadas ya integran generación de diagramas con threat analysis:

- **STRIDE GPT**: Genera attack trees en formato Mermaid renderizados interactivamente en el browser[^6][^14]
- **Arrows**: Produce network graphs interactivos con componentes, data flows, assets y trust boundaries anotados con amenazas[^16][^15]
- **CORAS Threat Modeler**: Renderiza CORAS threat diagrams como DAGs interactivos vía JointJS con layout BFS jerárquico[^7]
- **Threagile**: Genera data flow diagrams y data mapping diagrams desde YAML con risk annotations[^19]
- **pytm**: Genera DFDs via Graphviz y sequence diagrams via PlantUML automáticamente desde definiciones Python[^20]
- **Apiiro Software Graph**: Visualización en tiempo real del grafo de software con overlay de riesgo, exploración interactiva, y filtros por properties (internet-exposed, risk score, PII, etc.)[^28]

### Apiiro Software Graph Visualization

Esta es la solución más avanzada para visualización continua de threat modeling a nivel enterprise. Está powered by Deep Code Analysis (DCA) y runtime context, creando un **grafo interactivo en tiempo real** de toda la arquitectura de software enriquecido con insights de riesgo.[^28]

Capacidades:
- **Nodes** representan entities (APIs, secrets, databases, generative AI usage)
- **Edges** reflejan relaciones reales (qué módulo contiene qué API, qué componente usa qué secret)
- **Filtros**: Solo entidades que matcheen properties específicas (internet-exposed APIs con critical risk scores)
- **Size dinámico**: Nodos ajustados por número de conexiones o risk level
- **Badges**: Overlay de metadata (risk score, lenguaje, deployment status, presencia de PII)
- **Export**: GraphML (para herramientas externas) y PDF[^28]

***

## Arquitectura Propuesta para un Sistema Multi-Agente de Threat Modeling End-to-End

Basándose en la investigación analizada, un sistema completo de threat modeling agéntico podría implementarse con la siguiente arquitectura:

### Componentes del Pipeline

**Fase 1 — Ingesta y Parsing de Arquitectura**
- **Input Agent**: Acepta múltiples formatos (texto libre, Mermaid diagrams, IaC/Terraform/CloudFormation, OpenAPI specs, código fuente, Docker Compose, Kubernetes manifests)
- **Architecture Parser Agent**: Extrae componentes, data flows, trust boundaries, y scope (interno/web/público) usando VLMs para inputs visuales y NLP para texto[^18][^5]
- Similar a lo que hacen Threat Thinker y ASTRIDE con parsing de diagramas Mermaid/draw.io[^18][^5]

**Fase 2 — Enrichment y Contexto**
- **RAG Module**: Vector DB (FAISS/ChromaDB) con CAPEC, CWE, MITRE ATT&CK, MITRE ATLAS embeddings[^7]
- **Threat Intelligence Agent**: Integra feeds de CTI para amenazas emergentes y zero-days relevantes
- Similar a CORAS Threat Modeler con CAPEC/CWE RAG[^7]

**Fase 3 — Threat Assessment**
- **STRIDE Analyzer Agent**: Categoriza amenazas por STRIDE (+ "A" para AI-specific threats si aplica)[^5]
- **Risk Scorer Agent**: DREAD scoring automatizado con priorización[^6]
- **Mitigation Agent**: Sugiere mitigaciones basadas en controles conocidos (NIST 800-53, ASVS, etc.)
- Similar a la two-phase assessment de CORAS Assessor[^7]

**Fase 4 — Generación de Diagramas y Output**
- **Diagram Generator Agent**: Produce diagramas de arquitectura estéticos con:
  - Componentes del sistema como nodos con iconos/shapes apropiados
  - Data flows direccionales con labels de protocolos
  - Trust boundaries visuales (colores/borders para scope: interno, DMZ, público, cloud)
  - Amenazas anotadas como badges o overlays en componentes afectados
  - Output en Mermaid (para GitHub), D2, o SVG interactivo (vía JointJS o similar)
- **Report Generator Agent**: Genera reporte completo en Markdown/PDF con tabla de riesgos, threat model, mitigaciones, y DREAD scores

### Frameworks de Orquestación Recomendados

| Framework | Ventaja Principal | Mejor Para |
|-----------|------------------|-----------|
| **LangGraph** | Control explícito con DAG, conditional branching, parallel processing | Pipelines complejos con lógica condicional y pasos paralelos[^29] |
| **CrewAI** | Roles/goals naturales, task hand-off, multi-agent collaboration | Equipos de agentes con roles claros (Parser, Assessor, Formatter)[^29] |
| **AutoGen** (Microsoft) | Agent-to-agent cooperation con human-in-the-loop | Flujos donde se necesita revisión humana intermedia[^30] |

LangGraph es particularmente adecuado porque permite modelar el pipeline de threat modeling como un grafo dirigido donde cada agente es un nodo, con decision nodes para routing condicional (ej: si el input es visual → VLM parser; si es código → whitebox analyzer).[^29]

***

## Knowledge Graphs y Grafos de Amenazas

La representación de amenazas como knowledge graphs ofrece ventajas significativas sobre listas planas: permite visualizar cadenas de ataque, relaciones entre vulnerabilidades y assets, y paths de explotación multi-hop.[^31][^32]

### Aplicaciones en Threat Modeling

- **Attack path mapping**: Conectar eventos aparentemente aislados (failed login + PowerShell execution + outbound request) en una cadena unificada de movimiento lateral[^31]
- **Threat intelligence integration**: Vincular threat actors, TTPs, y ataques observados en un grafo queryable[^32]
- **Predictive analytics**: AI detecta patrones históricos para anticipar incidentes[^32]
- **Natural language queries**: Analistas pueden preguntar en lenguaje natural y AI convierte a query language del grafo[^32]

Herramientas como **ThreatKG** (Persistent Systems) integran CMDB data con un labeled property graph de enterprise assets, vulnerabilidades, amenazas e incidentes, continuamente actualizado vía log parsing y LLMs. **MultiKG** automatiza la construcción de knowledge graphs de ataque fusionando CTI reports, logs dinámicos, y código estático en un grafo unificado usando LLMs.[^33][^34]

***

## Gaps Actuales y Oportunidades de Investigación

### Limitaciones Identificadas

- **Cobertura de riesgos**: Herramientas actuales tienden a generar pocos escenarios (CORAS Threat Modeler limitado a top-5 por diseño). Se necesita un mecanismo de expansión/selección interactiva.[^7]
- **Safety vs. Security**: La mayoría de herramientas se enfocan en cybersecurity pero no capturan impactos de safety (daño físico causado por cyber risks), especialmente relevante en healthcare y IoT.[^7]
- **Validación de output**: Los threat models generados por LLMs pueden producir resultados inestables (STRIDE GPT reportado con outputs inconsistentes). Se necesitan benchmarks robustos de evaluación.[^2]
- **Agentic AI threats**: Solo MAESTRO y OWASP Agentic Top 10 abordan las amenazas específicas de sistemas multi-agente (collusion, goal hijacking, rogue agents), pero no hay herramientas que automaticen threat modeling para estos patterns.[^23][^3]
- **Diagramas estéticos**: La generación automática de diagramas de alta calidad visual sigue siendo un desafío. Las soluciones actuales producen grafos funcionales pero no siempre estéticamente publicables.[^7]
- **Integración CI/CD real**: Threagile y pytm lo soportan bien, pero las herramientas LLM-based aún no tienen integración madura con pipelines.[^20][^19]

### Oportunidades

1. **Pipeline multi-agente end-to-end** que acepte cualquier formato de input (IaC, código, diagramas visuales, texto) y produzca threat models completos con diagramas interactivos — combinando lo mejor de CORAS, STRIDE GPT, Arrows, y Threagile.
2. **Knowledge graph dinámico** que se actualice automáticamente con cada cambio en la arquitectura, integrando CAPEC, CWE, MITRE ATT&CK/ATLAS, y feeds de CTI.
3. **Diagramas generados con LLM** usando D2 o Mermaid con trust boundaries claramente delineadas, scope annotations (interno/web/público), y threat badges overlayed en componentes.
4. **Benchmarks de evaluación** para threat models generados por AI, comparando contra threat models creados por expertos humanos.
5. **Threat modeling continuo** integrado con CI/CD donde cada merge trigger genera un diff del threat model, similar a cómo Apiiro hace continuous risk assessment.[^28]

***

## Conclusión

El threat modeling agéntico está emergiendo como una disciplina viable con herramientas funcionales ya disponibles. CORAS Threat Modeler demuestra que un pipeline multi-agente (Summarizer→RAG→Assessor→Formatter) puede automatizar la generación de threat models completos desde texto libre. STRIDE GPT prueba que LLMs pueden generar análisis STRIDE comprehensivos con attack trees visuales. ASTRIDE muestra que VLMs pueden parsear diagramas de arquitectura visuales para threat modeling automatizado.[^5][^14][^7]

La oportunidad más grande está en construir un sistema que combine ingesta multi-formato (código, IaC, diagramas, texto) con un pipeline multi-agente robusto, knowledge graph dinámico con RAG sobre CAPEC/CWE/ATLAS, y generación de diagramas de alta calidad usando herramientas como D2 o Mermaid con trust boundaries, scope annotations, y threat overlays — todo integrado en workflows CI/CD para threat modeling continuo y automatizado.

---

## References

1. [From Manual to Automated Cyber Risk Assessment: LLM ...](https://www.sintef.no/en/publications/publication/10341837/) - This paper presents the CORAS Threat Modeler, an open-source tool that leverages large language mode...

2. [ThreatModeling-LLM: Automating Threat Modeling using ...](https://arxiv.org/html/2411.17058v2) - In this paper, we introduce ThreatModeling-LLM, a novel and adaptable framework that automates threa...

3. [Agentic AI Threat Modeling Framework: MAESTRO | CSA](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro) - MAESTRO (Multi-Agent Environment, Security, Threat, Risk, & Outcome) is a novel threat modeling fram...

4. [INTEGRATED APPROACH TO THREAT MODELING IN ARTIFICIAL INTELLIGENCE SYSTEMS](https://csecurity.kubg.edu.ua/index.php/journal/article/view/993) - This paper substantiates the relevance of threat modeling for artificial intelligence (AI) systems i...

5. [ASTRIDE: A Security Threat Modeling Platform for Agentic-AI Applications](https://arxiv.org/abs/2512.04785) - AI agent-based systems are becoming increasingly integral to modern software architectures, enabling...

6. [Automate Threat Modeling with STRIDE GPT – Hackers Arise](https://hackers-arise.com/using-artificial-intelligence-ai-in-cybersecurity-automate-threat-modeling-with-stride-gpt/) - STRIDE GPT makes threat modeling easier for everyone by using AI to automate the analysis while keep...

7. [and RAG-Driven Multi-Agent Threat Modeling with CORAS ...](https://gencer.no/wp-content/uploads/2025/12/2025.IEEE_.DSA_.pdf) - We introduced the CORAS Threat Modeler, an open-source tool [9] that combines LLMs, RAG, and multi-a...

8. [ThreatModeling-LLM: Automating Threat Modeling using Large Language
  Models for Banking System](https://arxiv.org/pdf/2411.17058.pdf) - ...models to handle
complex banking system architectures, and (3) the requirement for real-time,
ada...

9. [ThreatFinderAI: Automated Threat Modeling Applied to LLM System Integration](https://ieeexplore.ieee.org/document/10814632/) - Artificial Intelligence (AI) is a rapidly integrated technology, significantly contributing to advan...

10. [Asset-Centric Threat Modeling for AI-Based Systems](https://ieeexplore.ieee.org/document/10679445/) - Threat modeling for systems relying on Artificial In-telligence is not well explored. While conventi...

11. [Asset-driven Threat Modeling for AI-based Systems - arXiv](https://arxiv.org/html/2403.06512v1) - Threat modeling is a popular method to securely develop systems by achieving awareness of potential ...

12. [Multi-Agent Framework for Threat Mitigation and ...](https://arxiv.org/html/2512.23132) - Unfortunately, there is a lack of concrete applications of threat assessment in the ML field that pr...

13. [[PDF] Lifecycle-Aware Privacy Threat Modeling for AI Systems using LLM](https://www.ndss-symposium.org/wp-content/uploads/lastx2026-80.pdf) - To address both classical LINDDUN threats and additional AI-driven privacy attacks, PriMod4AI introd...

14. [mrwadams/stride-gpt: An AI-powered threat modeling tool ... - GitHub](https://github.com/mrwadams/stride-gpt) - STRIDE GPT is an AI-powered threat modelling tool that leverages Large Language Models (LLMs) to gen...

15. [AI-Driven Threat Modeling - LLMs For Automated STRIDE ...](https://fuzzinglabs.com/ai-threat-modeling-arrows/) - Its goal is to map out the threats of a web application, producing a final report with an interactiv...

16. [yacwagh/arrows: AI Agent for Threat Modeling](https://github.com/yacwagh/arrows) - Arrows : AI Agent for Threat Modeling. AI-driven threat modeling tool that helps identify and analyz...

17. [Trying LLM-Based Threat Modeling](https://dev.to/melonattacker/threat-thinker-trying-llm-based-threat-modeling-17o3) - Threat Thinker is a tool that performs automatic threat modeling from system architecture diagrams u...

18. [Tools - CyberTAMAGO](http://www.cybertamago.org/tools.php) - Threat Thinker analyzes architecture diagrams written in formats such as Mermaid, combining syntacti...

19. [[PDF] Agile Threat Modeling with Threagile - DeepSec](https://deepsec.net/docs/Slides/2020/How_To_Combat_Risks_Directly_From_Within_Your_IDE_Christian_Schneider.pdf) - Threagile analyzes the model YAML file as a graph of connected components with data flowing between ...

20. [Threat Modeling as Code via pytm](https://www.linkedin.com/pulse/threat-modeling-code-via-pytm-chuck-nelson-0a8nc) - In this article, I will describe how to use 'threat modeling as code' via the OWASP Pythonic Threat ...

21. [pytm skill by rohunj/claude-build-workflow - playbooks](https://playbooks.com/skills/rohunj/claude-build-workflow/pytm) - How do I avoid irrelevant/false-positive threats? Set accurate component and dataflow properties (en...

22. [Securing Applications with Threat Modelling:A Developer's ...](https://dev.to/sirtreggy/a-developers-guide-to-pytm-2e91) - returns a sequence diagram of the threat model. ... returns a generated textual report of the identi...

23. [OWASP Agentic AI Top 10: Threats in the Wild](https://labs.lares.com/owasp-agentic-top-10/) - This post aims to provide a comprehensive overview of each security risk. While it doesn't dive into...

24. [OWASP Top 10 for Agentic AI Security Risks (2026)](https://www.startupdefense.io/blog/owasp-top-10-agentic-ai-security-risks-2026) - ASI01 — Agent Goal Hijacking — is ranked as the top risk. It occurs when attackers manipulate an age...

25. [Architecture Diagrams Documentation (v11.1.0+) - Mermaid](https://mermaid.ai/open-source/syntax/architecture.html) - In an architecture diagram, services (nodes) are connected by edges. Related services can be placed ...

26. [D2 Diagrams Online Complete Architecture Diagram Guide](https://www.tools-online.app/blog/D2-Diagrams-Online-Complete-Architecture-Diagram-Guide) - Master D2 diagram language for creating professional architecture diagrams, microservices maps, and ...

27. [Simplify Software architecture with Diagrams as Code DaC - Blog](https://seifrajhi.github.io/blog/python-diagrams-as-code-architecture/) - The Diagrams tool is a great solution for implementing DaC. It allows you to draw cloud system archi...

28. [Continuous, Accurate Threat Modeling Is Now a Reality ...](https://apiiro.com/blog/software-graph-visualization/) - Generate threats and mitigations on ... Continuous, Accurate Threat Modeling Is Now a Reality with A...

29. [LangGraph vs CrewAI vs AutoGen: Top 10 AI Agent Frameworks](https://o-mega.ai/articles/langgraph-vs-crewai-vs-autogen-top-10-agent-frameworks-2026) - Compare the best multi-agent AI frameworks for 2026. Discover LangGraph, CrewAI, AutoGen and 7 more ...

30. [Agentic AI Trends 2025: From Assistants to Agents | Svitla Systems](https://svitla.com/blog/agentic-ai-trends-2025/) - Agentic AI trends in 2025 are reshaping how enterprises design and run digital operations. Unlike tr...

31. [Cybersecurity Knowledge Graph: Smarter Threat Detection](https://www.puppygraph.com/blog/cybersecurity-knowledge-graphs) - 100%

32. [How to Use Data Visualization in Cybersecurity - Apriorit](https://www.apriorit.com/dev-blog/threat-visualization-in-cybersecurity) - Knowledge graphs are advanced visualization tools that map relationships among system components, th...

33. [MultiKG: Multi-Source Threat Intelligence Aggregation for High-Quality
  Knowledge Graph Representation of Attack Techniques](https://arxiv.org/html/2411.08359v1) - ...graphs.
  We propose MultiKG, a fully automated framework that integrates multiple
threat knowled...

34. [Knowledge Graphs for Smarter, Stronger Cybersecurity](https://www.persistent.com/blogs/navigating-the-cyber-web-how-knowledge-graphs-empower-smarter-cybersecurity/) - This blog explains how the graph-based approach enables prioritized context-driven responses to impr...

