# Threat Modeling: El Proceso — Investigación Académica y Práctica Integral

## Resumen Ejecutivo

El threat modeling (modelado de amenazas) es una familia de procesos estructurados y repetibles que permiten tomar decisiones racionales para asegurar aplicaciones, software y sistemas. No existe un único "mejor" proceso de threat modeling; en cambio, las metodologías modernas convergen en un marco de cuatro preguntas fundamentales propuesto por Adam Shostack: (1) ¿En qué estamos trabajando? (2) ¿Qué puede salir mal? (3) ¿Qué vamos a hacer al respecto? (4) ¿Hicimos un buen trabajo?. Este reporte sintetiza las fuentes más relevantes — libros seminales, papers académicos, frameworks de la industria, herramientas, y guías prácticas — para ofrecer una comprensión profunda y accionable del proceso de threat modeling.[^1][^2][^3]

***

## Fundamentos Filosóficos: El Threat Modeling Manifesto

En 2020, quince expertos reconocidos en threat modeling publicaron el **Threat Modeling Manifesto**, siguiendo el formato del Agile Manifesto. Este documento establece los valores y principios fundamentales de la disciplina.[^4]

### Valores

El Manifesto establece cinco valores donde se prioriza el lado izquierdo sobre el derecho:[^5][^4]

| Se valora más... | ...sobre |
|---|---|
| Una cultura de encontrar y corregir problemas de diseño | Cumplimiento tipo checkbox |
| Personas y colaboración | Procesos, metodologías y herramientas |
| Un viaje de comprensión | Una foto instantánea de seguridad/privacidad |
| Hacer threat modeling | Hablar sobre hacerlo |
| Refinamiento continuo | Una entrega única |

### Principios Fundamentales

Los principios incluyen que el mejor uso del threat modeling es mejorar la seguridad y privacidad de un sistema mediante análisis temprano y frecuente; que debe alinearse con las prácticas de desarrollo de la organización y seguir los cambios de diseño en iteraciones manejables; que los resultados son significativos cuando aportan valor a los stakeholders; y que el diálogo es clave para establecer entendimientos comunes.[^4]

### Patrones y Anti-Patrones

El Manifesto identifica patrones beneficiosos como el **enfoque sistemático**, la **creatividad informada**, los **puntos de vista variados**, el **toolkit útil** y la **teoría llevada a la práctica**. Los anti-patrones a evitar incluyen el **"Hero Threat Modeler"** (depender de una sola persona con habilidades únicas), la **"Admiración por el Problema"** (analizar sin llegar a soluciones prácticas), la **tendencia a sobre-enfocarse** (perder la visión del panorama completo) y la **representación perfecta** (buscar un modelo único ideal cuando múltiples representaciones iluminan diferentes problemas).[^6][^4]

***

## El Framework de las Cuatro Preguntas de Shostack

El framework más ampliamente adoptado para organizar el proceso de threat modeling fue propuesto por Adam Shostack en su libro *Threat Modeling: Designing for Security* (2014). Las cuatro preguntas han evolucionado desde su formulación original:[^7][^2]

### Pregunta 1: ¿En qué estamos trabajando?

Se enfoca en la deconstrucción del sistema o aplicación en sus componentes para ser modelados individual o colectivamente. En esta fase se debe definir el alcance (scope) para asegurar que los límites del threat model estén bien definidos. Marcar algo como "fuera de alcance" no significa que nunca será modelado, solo que no lo será en esta iteración. Los artefactos principales incluyen Data Flow Diagrams (DFDs), diagramas de secuencia, diagramas de proceso, y la identificación de trust boundaries.[^8][^9][^1]

Shostack enfatiza que la pregunta usa "working on" en lugar de "building" deliberadamente: el frame "building" empuja hacia un enfoque waterfall, mientras que "working on" permite threat modeling en cualquier punto del ciclo de vida.[^2]

### Pregunta 2: ¿Qué puede salir mal?

Esta fase se enfoca en la evaluación de amenazas. Frameworks como STRIDE, TRIKE, OWASP, MITRE ATT&CK, MITRE CWE, OCTAVE y PASTA pueden usarse para determinar las amenazas, debilidades o métodos de ataque potenciales. La fortaleza del framework de cuatro preguntas es que permite la incorporación de frameworks adicionales.[^3][^1]

### Pregunta 3: ¿Qué vamos a hacer al respecto?

Fue reformulada de "What *can* we do about it?" a "What *are* we going to do about it?" para reflejar un enfoque más proactivo. Las opciones incluyen mitigar, eliminar, transferir o aceptar la amenaza. Esta fase debe seguir un proceso de priorización establecido basado en políticas y procedimientos internos.[^10][^1]

### Pregunta 4: ¿Hicimos un buen trabajo?

Originalmente significaba "validación" — el análisis mecánico de "¿tenemos un diagrama?", "¿encontramos amenazas?", "¿registramos bugs/tickets?", "¿corregimos los problemas?". Shostack a veces agrega "enough" (suficientemente) — "Did we do a good *enough* job?" — apreciando la menor presión pero extrañando la aspiración.[^7][^2]

***

## Metodologías Principales de Threat Modeling

### STRIDE

Desarrollado por Microsoft en 1999, STRIDE categoriza amenazas en seis tipos:[^11][^8]

| Categoría | Propiedad Violada | Descripción |
|---|---|---|
| **S**poofing | Autenticación | Pretender ser algo o alguien distinto |
| **T**ampering | Integridad | Modificar datos o código |
| **R**epudiation | No-repudio | Negar haber realizado una acción |
| **I**nformation Disclosure | Confidencialidad | Exponer información a quien no debería verla |
| **D**enial of Service | Disponibilidad | Negar o degradar servicio a usuarios |
| **E**levation of Privilege | Autorización | Obtener capacidades sin autorización |

Existen tres variantes principales de aplicación:[^8][^11]

- **STRIDE-per-element**: Se aplica cada categoría STRIDE a cada elemento del DFD (procesos, data stores, data flows, entidades externas). Es la variante usada en el Microsoft SDL. Los DFDs típicamente tienen entre 10 y 150 elementos.[^11]
- **STRIDE-per-interaction**: Se aplica STRIDE a cada interacción (tupla origen-data flow-destino) en lugar de elementos individuales. Esto reduce el número de amenazas a analizar pero puede ser más complejo conceptualmente.[^9][^8]
- **STRIDE clásico**: Se usan las categorías como una checklist general sin mapearlas a elementos específicos del diagrama.

### PASTA (Process for Attack Simulation and Threat Analysis)

PASTA es una metodología de siete etapas, centrada en riesgo y en el atacante, que incorpora contexto de negocio y colaboración entre profesionales de gobernanza, operaciones, arquitectura y desarrollo:[^12][^9]

1. **Definir Objetivos**: Establecer objetivos de negocio y requisitos de seguridad/compliance
2. **Definir Alcance Técnico**: Documentar la arquitectura, componentes técnicos y dependencias
3. **Descomponer la Aplicación**: Analizar funcionalmente cómo los atacantes podrían explotar debilidades
4. **Analizar Amenazas**: Identificar escenarios de ataque importantes usando threat intelligence
5. **Analizar Vulnerabilidades**: Correlacionar vulnerabilidades con los escenarios de ataque
6. **Analizar Ataques**: Simular caminos de ataque (attack paths)
7. **Analizar Riesgo e Impacto**: Priorizar y mitigar las amenazas identificadas

La diferencia fundamental con STRIDE es que PASTA es **risk-centric** (centrado en riesgo) y **attacker-focused** (enfocado en el atacante), mientras que STRIDE es **model-centric** (centrado en el modelo del sistema). PASTA incorpora threat intelligence sobre capacidades del atacante, exploits recientes y campañas de la industria.[^13][^14][^12]

### VAST (Visual, Agile, and Simple Threat)

VAST es un framework diseñado para ser escalable, ágil e integrable en entornos DevSecOps modernos. Se distingue por su enfoque dual que modela amenazas de aplicación y amenazas operacionales en paralelo usando diagramas de flujo de proceso y diagramas de flujo de datos. Sus tres pilares son:[^15][^16]

- **Visual**: Uso de diagramas de flujo de proceso para representar arquitecturas e interacciones
- **Agile**: Principios de mejora iterativa y continua integrados en el SDLC
- **Simple**: Metodología directa que fomenta participación de stakeholders técnicos y no técnicos[^15]

### LINDDUN

Framework especializado en amenazas de privacidad que complementa a STRIDE en el dominio de protección de datos personales. Sus categorías son: Linkability, Identifiability, Non-repudiation, Detectability, Disclosure of information, Unawareness y Non-compliance. Es especialmente relevante para sistemas que procesan datos personales bajo regulaciones como GDPR.[^17][^8]

### Trike

Utiliza un "modelo de requisitos" para identificar stakeholders, activos y acciones permitidas, combinado con un "modelo de implementación" y DFDs para identificar amenazas y asignar riesgos. Proporciona una manera estructurada de modelar el sistema e integra un proceso de evaluación de riesgos para priorizar amenazas.[^18][^17]

### OCTAVE (Operationally Critical Threat, Asset, and Vulnerability Evaluation)

Framework de gestión de riesgos que se enfoca en riesgos organizacionales usando un proceso de tres fases: construir perfiles de amenaza basados en activos, identificar vulnerabilidades de infraestructura, y desarrollar estrategias y planes de seguridad.[^17][^18]

### hTMM (Hybrid Threat Modeling Method)

Desarrollado por el SEI de Carnegie Mellon, combina STRIDE, Security Cards y Persona non Grata (PnG). El proceso identifica el sistema, aplica Security Cards basadas en sugerencias de desarrolladores, elimina personas de amenaza poco realistas, resume los resultados del análisis y procede a una evaluación formal de riesgos.[^3][^17]

***

## Comparación de Metodologías

| Característica | STRIDE | PASTA | VAST | LINDDUN | Trike | OCTAVE |
|---|---|---|---|---|---|---|
| **Enfoque** | Modelo del sistema | Riesgo y atacante | Ágil y visual | Privacidad | Requisitos | Organizacional |
| **Complejidad** | Media | Alta (7 etapas) | Baja | Media | Media-Alta | Alta |
| **Basado en** | DFDs + categorías | Negocio + técnico | Process flows | Privacy threats | Stakeholders | Activos críticos |
| **Mejor para** | Software/aplicaciones | Empresas con compliance | DevSecOps enterprise | Sistemas con datos personales | Sistemas con muchos stakeholders | Evaluación organizacional |
| **Escalabilidad** | Media | Media | Alta | Media | Baja | Baja-Media |
| **Automatizable** | Sí | Parcialmente | Sí | Parcialmente | Parcialmente | No fácilmente |

Fuentes:[^19][^9][^17][^15]

***

## El Proceso de Diagramación: Data Flow Diagrams (DFDs)

Los DFDs son el artefacto central del threat modeling, proporcionando una vista detallada de cómo se manejan los datos dentro de un sistema. Un DFD para threat modeling incluye:[^20][^8]

### Elementos del DFD

- **Procesos**: Representan código que transforma datos (círculos o rectángulos redondeados)
- **Data Stores**: Almacenes de datos como bases de datos, archivos, registros (líneas paralelas)
- **Data Flows**: Movimiento de datos entre elementos (flechas)
- **Entidades Externas**: Actores o sistemas fuera del control directo (rectángulos)
- **Trust Boundaries**: Fronteras donde el nivel de confianza cambia (líneas punteadas)[^8][^11]

### Mejores Prácticas para DFDs

Un DFD efectivo para threat modeling debe concentrarse en las superficies de ataque/amenaza y ser robusto en consolidar múltiples componentes del sistema en un solo componente del threat model. Esto mantiene el número de componentes y flujos de datos manejable y enfoca la discusión en lo que más importa: actores maliciosos tratando de subvertir el sistema. La brevedad es fundamental — es fácil crear un threat model que se parece demasiado a un diagrama de sistema, con muchos componentes y flujos de datos, pero eso no es un modelo específico a la amenaza de exploits.[^10]

***

## Actores, Acciones y Escenarios

### Actores

Un aspecto fundamental del threat modeling es enumerar los "actores" — las partes en el sistema que realizan acciones y que podrían ser erróneas, comprometidas o maliciosas. En sistemas modernos distribuidos, el número de actores puede ser muy grande. Por ejemplo, para un proyecto como Sigstore integrado con PyPI, los actores incluyen el servidor PyPI, sus administradores, las CAs de confianza, partes que controlan BGP/routers, partes que controlan DNS, los desarrolladores, el CDN, los usuarios descargando software, y outsiders.[^20]

Sin embargo, técnicas de agrupación permiten categorizar grupos de actores como equivalentes. Por ejemplo, una parte que puede controlar la red tiene capacidades similares independientemente de si controla routers, BGP o DNS.[^20]

### Definición de Escenarios

Un aspecto fundamental es la capacidad de enmarcar y entender los diversos escenarios en los que un sistema operará. La pregunta guía es: "¿Cuáles son los casos de uso previstos del sistema, y dónde NO debería usarse?". Desafiarse a identificar escenarios fuera del alcance puede revelar suposiciones implícitas y debilidades potenciales.[^20]

### Asunciones Comunes y Misconceptions

Cappos (en "Open and Secure") cataloga asunciones comunes legítimas y misconceptions frecuentes:[^20]

**Asunciones razonables:**
- El gobierno/management no forzará acciones que violen los objetivos de seguridad
- Los algoritmos criptográficos ampliamente considerados seguros, son seguros
- Los mecanismos de protección de memoria hardware funcionan como fueron diseñados

**Misconceptions peligrosas:**
- "Un atacante no puede hackear un componente específico" — los sistemas modernos tienen tanto código y dependencias que esto no es razonable
- "Una clave o secreto nunca será filtrado" — incidentes violando esta asunción son comunes
- "MFA con SMS es barrera suficiente" — sistemas SMS-based han demostrado ser vulnerables
- "El firewall detiene a los malos" — los firewalls son herramientas para aumentar la dificultad, no barreras absolutas
- "Los usuarios pueden manejar contraseñas seguras" — patentemente falso

***

## Scoring y Priorización de Amenazas

### DREAD

El modelo DREAD evalúa cuantitativamente la severidad de amenazas usando cinco factores, cada uno puntuado de 0 a 10:[^21][^22]

| Factor | Qué mide |
|---|---|
| **D**amage Potential | Cuánto daño puede causar la amenaza |
| **R**eproducibility | Facilidad de reproducir el ataque |
| **E**xploitability | Esfuerzo y habilidad requeridos para explotar |
| **A**ffected Users | Número y tipo de usuarios impactados |
| **D**iscoverability | Facilidad de descubrir la vulnerabilidad |

El score total (máximo 50) categoriza la prioridad:[^22][^23]

| Score | Nivel | Acción recomendada |
|---|---|---|
| 40–50 | Crítico | Resolver en 72 horas |
| 25–39 | Alto | Resolver en 2 semanas |
| 11–24 | Medio | Resolver en 1 mes |
| 1–10 | Bajo | Monitorear y reevaluar trimestralmente |

### TARA (Threat Assessment and Remediation Analysis)

Utiliza un modelo de scoring con 12 mediciones para evaluar amenazas, proporcionando una cuantificación más granular que DREAD.[^9]

### Scoring en PASTA

PASTA incluye tablas de scoring propias que correlacionan impacto de negocio con probabilidad técnica, alineando la priorización con objetivos organizacionales.[^12][^9]

***

## Matrices de Ataque y Attack Trees

### Matrices de Ataque (Threat Matrices)

Las matrices de ataque son herramientas para razonar sobre qué puede pasar cuando diferentes combinaciones de actores son comprometidos. Cada fila representa un conjunto mínimo de actores comprometidos y cada celda describe el impacto resultante. Reglas clave:[^20]

- Un superset de actores maliciosos puede hacer al menos la unión de lo que hacen todos los subsets
- Las matrices se ordenan con los ataques más impactantes en la parte inferior
- Si manager+teller comprometidos ya tienen control total, agregar customer no cambia el impacto
- Si diferentes conjuntos disjuntos tienen el mismo impacto, se pueden combinar filas con OR[^20]

### Attack Trees

Los attack trees organizan ataques en estructuras jerárquicas de tareas y subtareas, representando los diferentes caminos que un atacante podría tomar para alcanzar un objetivo. Son especialmente útiles para:[^3][^8]

- Visualizar cómo un atacante podría encadenar múltiples vulnerabilidades
- Identificar los caminos de ataque más probables o de menor costo
- Comunicar riesgos a stakeholders no técnicos

***

## Respuestas a Amenazas: Mitigación, Detección, Recuperación y Prevención

### Estrategias de Respuesta

Las cuatro respuestas clásicas a una amenaza identificada son:[^10][^20]

1. **Mitigar**: Reducir la probabilidad o impacto de la amenaza
2. **Eliminar**: Rediseñar para remover la amenaza por completo
3. **Transferir**: Trasladar el riesgo a un tercero (ej: seguros, SLAs)
4. **Aceptar**: Reconocer el riesgo y documentar la decisión

### Capacidades Defensivas

Cappos identifica cuatro capacidades que un defensor puede retener incluso bajo ataque:[^20]

- **Detección**: Cualquier medio por el cual se puede saber que se ha sido atacado (logging, monitoreo de red, detección de anomalías)
- **No-repudio / Trazabilidad Forense**: Capacidad de probar que una parte específica realizó una acción (firmas criptográficas, logs inmutables)
- **Recuperación**: Capacidad de expulsar al atacante y restaurar el sistema a un estado seguro
- **Prevención**: Mecanismos que impiden directamente que el ataque tenga éxito

Un principio fundamental es diseñar sistemas que **degraden gracefully** bajo ataque — donde un atacante debe comprometer muchas partes bien protegidas y compartimentalizadas para causar daño sustancial, en lugar de tener solo estados "seguro" e "inseguro".[^20]

***

## Herramientas de Threat Modeling

### Herramientas Open-Source

| Herramienta | Descripción | Metodología | Características Clave |
|---|---|---|---|
| **OWASP Threat Dragon** | Aplicación web/desktop gratuita | STRIDE, LINDDUN, CIA, DIE, PLOT4ai | Interfaz intuitiva, indicación visual de componentes y superficies de amenaza[^24] |
| **Microsoft Threat Modeling Tool** | Herramienta gratuita de Microsoft | STRIDE-per-element | Integración con productos Microsoft, plantillas DFD, generación automática de amenazas[^25] |
| **pytm (OWASP)** | Threat modeling "as code" en Python | STRIDE | Genera DFDs y threat models desde código, integrable en CI/CD pipelines[^26] |
| **Threagile** | Toolkit ágil de threat modeling | STRIDE + reglas propias (~40+) | Modelos declarativos en YAML, genera diagramas, riesgos, reportes en PDF/Excel/JSON[^27] |
| **STRIDE GPT** | AI-powered threat modeling | STRIDE + DREAD | Genera threat models, attack trees, test cases Gherkin, soporta múltiples LLM providers[^28] |

### Herramientas Comerciales

| Herramienta | Enfoque | Diferenciador |
|---|---|---|
| **IriusRisk** | Automatización enterprise | AI-powered threat library, workflows customizables, compliance reporting, integración con Threat Dragon[^25][^29] |
| **ThreatModeler** | Enterprise scalable | Framework VAST, integración con desarrollo, modelado visual[^15] |
| **SD Elements** | Continuous threat modeling | Automatización basada en cuestionarios, integración DevSecOps[^29] |

### Threat Modeling "as Code"

El paradigma de "threat modeling as code" permite versionar modelos de amenazas junto con el código fuente. **pytm** permite definir actores, componentes técnicos, trust boundaries y flujos en un archivo Python meta, que puede ser versionado y usado para generar tanto el DFD como el threat model en un pipeline CI/CD. **Threagile** usa archivos YAML declarativos que son diff-able, colaborativos, testeables y verificables, con ~40 reglas de riesgo codificadas que analizan el grafo de componentes conectados.[^26][^27]

***

## Threat Modeling Continuo y DevSecOps

### Integración con el SDLC

El threat modeling alcanza su mayor valor cuando se integra en los pipelines de desarrollo y release. Los puntos clave de integración incluyen:[^30]

- **Planificación Agile**: Agregar tareas de threat modeling al backlog e incluirlas en sprint reviews
- **Automatización CI/CD**: Disparar actualizaciones del modelo cuando se despliegan nuevos componentes o APIs
- **Shift-left testing**: Aplicar insights del modelo temprano en diseño y code review
- **Gobernanza continua**: Alimentar hallazgos a dashboards de riesgo y compliance enterprise

### El Modelo de Autodesk: Continuous Threat Modeling (CTM)

Tarandach y Coles describen el enfoque CTM de Autodesk que incluye una metodología de "dual-speed": threat modeling comprehensivo para cambios arquitectónicos mayores y threat modeling ligero ("Threat Model Every Story") para cambios incrementales en sprints. Las preguntas guía del CTM incluyen evaluación de cambios en superficies de ataque, nuevos flujos de datos, y modificaciones en trust boundaries.[^9]

### Prácticas Recomendadas de OWASP SAMM

El OWASP SAMM define tres niveles de madurez para threat modeling:[^31]

- **Nivel 1**: Threat modeling ad-hoc para aplicaciones de alto riesgo usando checklists simples como STRIDE. Evitar workshops largos y listas detalladas de amenazas irrelevantes.
- **Nivel 2**: Metodología estandarizada que incluye diagramación, identificación de amenazas, mitigaciones de fallas de diseño y validación de artefactos. Entrenamiento de arquitectos y security champions.
- **Nivel 3**: Threat modeling integrado en el SDLC como parte de la cultura de seguridad del desarrollador. Patrones de riesgo reutilizables. Automatización parcial con herramientas. Prácticas de "threat modeling as code".

***

## La Experiencia de Microsoft: Lecciones de una Década

Microsoft tiene la experiencia más documentada en threat modeling a escala enterprise. Shostack describe la evolución desde un documento de 1999 ("Threats to our products") hasta la metodología actual del SDL:[^11]

### Evolución Histórica

- **1999**: Primer documento interno sobre amenazas a productos Microsoft
- **2002**: *Writing Secure Code* (Howard & LeBlanc) — primera metodología publicada
- **2004**: *Threat Modeling* (Swiderski & Snyder) — enfoque en attack patterns
- **2006**: Artículo "Reinvigorate your Threat Modeling Process" — simplificación del proceso
- **2008**: Proceso de cuatro pasos explícito: diagramar → enumerar amenazas → mitigar → verificar[^11]

### Metodología Actual del SDL

El proceso actual de Microsoft SDL sigue cuatro pasos:[^11]

1. **Diagramar**: Crear DFDs con trust boundaries
2. **Enumerar amenazas**: Usar STRIDE-per-element aplicado a cada componente del DFD
3. **Mitigar**: Determinar controles para cada amenaza identificada
4. **Verificar**: Validar que el modelo refleja la realidad y que las mitigaciones son adecuadas

Los DFDs en Microsoft típicamente contienen entre 10 y 150 elementos. Los tres objetivos declarados son: mejorar la seguridad del producto, documentar el análisis de seguridad, y entrenar a las personas en pensamiento de seguridad.[^11]

***

## Security Assessments vs Security Audits

Cappos hace una distinción fundamental entre assessments y audits que es relevante para el threat modeling:[^20]

| Aspecto | Security Assessment | Security Audit |
|---|---|---|
| **Enfoque** | Arquitectura y postura de seguridad | Instancias específicas de fallas |
| **Analogía** | Examinar planos, tipos de bóveda, políticas de personal | Intentar abrir cerraduras, smash chisel en mortero |
| **Duración de validez** | Años (mientras no haya cambios sustanciales) | Momentánea (solo la release auditada) |
| **Fortaleza** | Identifica problemas sistémicos y de diseño | Encuentra bugs específicos explotables |
| **Debilidad** | Valor más difícil de cuantificar | No revela deficiencias subyacentes |
| **Portabilidad** | Se traslada a múltiples implementaciones/deployments | Específico a implementación y deployment |

La recomendación es que las mejores firmas de seguridad realizan ambos tipos de análisis a diferentes niveles de detalle.[^20]

***

## Gamificación del Threat Modeling

### Elevation of Privilege (EoP)

Creado por Shostack en Microsoft, es un juego de cartas donde cada carta representa una amenaza STRIDE específica. Los jugadores aplican las amenazas al sistema siendo modelado y ganan puntos por identificar amenazas válidas.[^8][^9]

### Cornucopia

Juego de OWASP similar a EoP pero enfocado en amenazas de aplicaciones web, usando las categorías del OWASP Top 10.[^9]

### LINDDUN GO

Versión gamificada del framework LINDDUN para identificación de amenazas de privacidad.[^9]

La gamificación ha demostrado ser efectiva para hacer el threat modeling más accesible a equipos de desarrollo que no tienen experiencia profunda en seguridad, cumpliendo con el valor del Manifesto de "personas y colaboración".[^9]

***

## Threat Modeling para Dominios Específicos

### Cloud Native y Open Source

El proceso de TAG-Security de la CNCF proporciona un framework especializado para assessments de seguridad en el ecosistema cloud native. El proceso incluye self-assessments del proyecto, joint assessments con reviewers de TAG-Security, y el programa Security Pals para proyectos que necesitan asistencia. Los threat matrices son especialmente útiles en este dominio debido al gran número de actores en proyectos cloud native distribuidos.[^20]

### IoT e ICS/OT

Para sistemas industriales y de IoT, se han propuesto frameworks híbridos que combinan PASTA, STRIDE y attack trees para visualizar el perfil de riesgo completo de la infraestructura. La continuidad y estabilidad de infraestructura crítica depende fuertemente de equipos legacy, lo que introduce complejidades adicionales.[^32]

### Sistemas AI/ML

Frameworks como STRIDE-AI adaptan STRIDE al pipeline de ML, mapeando modos de falla de assets generados y usados en diferentes etapas del ciclo de vida de ML a amenazas y propiedades de seguridad. Frameworks más recientes como MAESTRO (Multi-Agent Environment, Security, Threat, Risk, and Outcome) abordan específicamente las complejidades de sistemas de IA agéntica.[^33][^18]

***

## Principios de Diseño Seguro y Red Flags

### Principios Fundamentales de Saltzer y Schroeder

Cappos enfatiza que entender los principios de diseño de seguridad es esencial para cualquier persona que piense sobre seguridad:[^20]

- **Principio de simplicidad**: Cuanto más simple el componente, más fácil es razonar sobre él y asegurarlo
- **Privilegio mínimo (Least Privilege)**: Una parte debe tener la menor cantidad de privilegio posible
- **Valores seguros por defecto (Fail-safe defaults)**: En caso de falla, el sistema debe defaultear al estado más seguro
- **Mecanismo menos común (Least common mechanism)**: Minimizar mecanismos compartidos entre partes
- **Minimizar secretos**: Reducir la dependencia de secretos compartidos
- **Diseño abierto (Open design)**: La seguridad no debe depender de la oscuridad del diseño
- **Mediación completa (Complete mediation)**: Todo acceso a algo sensible debe ser verificado — si TrashPanda Bank tiene una entrada fortificada pero una ventana sin llave en la bóveda, el atacante usará la ventana
- **Menor asombro (Least astonishment)**: Los mecanismos de seguridad no deben sorprender al usuario

### Red Flags en Proyectos

Shostack y Cappos identifican señales de alerta al evaluar proyectos:[^20]

- **Falta de threat modeling**: Ingenieros en empresas importantes que planean "descifrar el threat model después de construirlo"
- **Ver mecanismos de seguridad como features**: Creer que se puede "bolt on" AES encryption al final y declarar el sistema seguro — "como poner un candado de bicicleta en el asiento, importa dónde se pone"
- **Falta general de comprensión de seguridad**: Equipos de seguridad que malentienden conceptos básicos sin deseo de aprender
- **Hacer preguntas es un superpoder**: Cuestionar asunciones no obvias y ver qué se rompe es una habilidad de seguridad que cualquiera puede aprender rápidamente[^20]

***

## Recursos Educativos Destacados

### Libros Fundamentales

| Libro | Autor(es) | Año | Enfoque Principal |
|---|---|---|---|
| *Threat Modeling: Designing for Security* | Adam Shostack | 2014 | Framework de 4 preguntas, STRIDE, attack trees, privacidad, adopción organizacional[^8] |
| *Threat Modeling: A Practical Guide for Development Teams* | Izar Tarandach & Matthew Coles | 2020 | Guía práctica: 10+ metodologías, automatización, CTM, gamificación[^9] |
| *Threats: What Every Engineer Should Learn from Star Wars* | Adam Shostack | 2023 | Threat modeling accesible para ingenieros |
| *Open and Secure* | Justin Cappos (CNCF) | 2023 | Security assessments, threat modeling para open source y cloud native[^20] |
| *Threat Modeling: A Summary of Available Methods* | Shevchenko et al. (SEI/CMU) | 2018 | Resumen comparativo de 12 métodos con tabla de características[^17] |

### Videos YouTube Recomendados

- [Threat Modeling with Adam Shostack (#148)](https://www.youtube.com/watch?v=xWqgaeCXUPc) — Entrevista profunda cubriendo las 4 preguntas, DFDs, y LLMs en threat modeling[^34]
- [Adam Shostack: Publish Your Threat Models (OSTIF Meetup 2025)](https://www.youtube.com/watch?v=P8WD7R10UIw) — Sobre publicar threat models y por qué open source debería liderar[^35]
- [Master Threat Modeling: OWASP Guide](https://www.youtube.com/watch?v=RlKf3un7Uho) — Guía concisa y comprehensiva por OWASP[^36]
- [STRIDE and PASTA Explained (CSSLP)](https://www.youtube.com/watch?v=cUFRl8JJ7RE) — Aplicación práctica de STRIDE y PASTA con ejemplos[^13]
- [PASTA vs STRIDE: Tony UV (VerSprite)](https://www.youtube.com/watch?v=oIeF3HkdYcU) — Diferencias entre PASTA y STRIDE por el creador de PASTA[^14]
- [CISSP: STRIDE, DREAD, PASTA, VAST Explained](https://www.youtube.com/watch?v=VoiHRBaV8Xk) — Overview para certificación CISSP[^37]

### Papers Académicos Clave

- Shostack, A. (2008). "Experiences Threat Modeling at Microsoft" — Década de experiencia en Microsoft SDL[^11]
- Shevchenko et al. (2018). "Threat Modeling: A Summary of Available Methods" (SEI/CMU) — Comparación de 12 métodos[^17]
- IEEE (2025). "The Science of Threat Modeling in Complex Industrial Systems" — Análisis de limitaciones de enfoques clásicos y avances emergentes[^38]
- Cappos et al. (2024). "Introducing Systems Thinking as a Framework for Teaching and Assessing Threat Modeling Competency" — Rubrics para enseñanza de threat modeling[^39]

### Guías y Frameworks Online

- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling) — Guía comunitaria comprehensive[^40]
- [OWASP Threat Modeling in Practice](https://owasp.org/www-project-developer-guide/release/design/threat_modeling/practical_threat_modeling/) — Guía práctica del OWASP Developer Guide[^10]
- [OWASP SAMM: Threat Assessment](https://owaspsamm.org/model/design/threat-assessment/stream-b/) — Modelo de madurez para threat modeling organizacional[^31]
- [Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org) — Valores y principios fundamentales[^4]
- [Shostack's Four Question Framework](https://github.com/adamshostack/4QuestionFrame) — Repositorio oficial del framework[^2]
- [Shostack's Beginner Guide](https://shostack.org/resources/threat-modeling) — Guía para principiantes[^3]

***

## Conclusiones y Recomendaciones Prácticas

El threat modeling es fundamentalmente un proceso de ingeniería que busca anticipar y mitigar problemas de seguridad antes de que sean explotados. Las recomendaciones clave para implementar un programa efectivo de threat modeling son:

1. **Empezar simple**: Usar las cuatro preguntas de Shostack como marco organizador y STRIDE como primera metodología. No buscar perfección en la primera iteración — "doing threat modeling" es más valioso que "talking about it".[^4]

2. **Invertir en diagramación**: Los DFDs con trust boundaries son el artefacto más importante. Mantenerlos concisos y enfocados en superficies de ataque, no en replicar diagramas de arquitectura.[^10]

3. **Integrar en el SDLC**: El threat modeling debe ser continuo e iterativo, no un evento único. Incorporar en sprints, CI/CD, y backlogs de desarrollo.[^30][^31]

4. **Diversificar el equipo**: El anti-patrón "Hero Threat Modeler" es real — threat modeling requiere perspectivas diversas incluyendo desarrollo, operaciones, negocio y seguridad.[^4]

5. **Automatizar lo automatizable**: Herramientas como pytm, Threagile y STRIDE GPT pueden acelerar el proceso, pero no reemplazan el juicio humano en la identificación de amenazas contextuales.[^28][^27][^26]

6. **Priorizar con método**: Usar DREAD, PASTA scoring, o modelos de riesgo cuantitativos para convertir listas de amenazas en acciones priorizadas.[^22][^9]

7. **Documentar y versionar**: Tratar threat models como artefactos vivos que se actualizan con el sistema, idealmente versionados junto con el código fuente.[^27][^30]

8. **Cuestionar asunciones**: "Asking good questions is an important security superpower that anyone can quickly learn" — la habilidad más valiosa en threat modeling es cuestionar asunciones no obvias.[^20]

---

## References

1. [The Four Questions](https://www.threatmodelingconnect.com/blog/shostacks-four-question-framework-for-threat-modeling) - This 4 step framework, originally proposed by Adam Shostack, was created to provide a process for sy...

2. [GitHub - adamshostack/4QuestionFrame: Shostack's 4 Question Frame for Threat Modeling](https://github.com/adamshostack/4QuestionFrame) - Shostack's 4 Question Frame for Threat Modeling. Contribute to adamshostack/4QuestionFrame developme...

3. [The Ultimate Beginner's Guide to Threat Modeling](https://shostack.org/resources/threat-modeling) - Threat modeling is a family of structured, repeatable processes that allows you to make rational dec...

4. [Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org) - Documents the values, principles and key characteristics as an industry guidance for conducting thre...

5. [Using the Threat Modeling Manifesto](https://www.securitycompass.com/blog/using-the-threat-modeling-manifesto/) - We have written before about what threat modeling entails and its many forms. Organizations can take...

6. [An annotated read of the Threat Modeling Manifesto](https://simoneonsecurity.com/2020/11/26/threat-modeling-manifesto/) - Some of the most famous Threat Modeling practicians have joined forces to publish the Threat Modelin...

7. [[PDF] The Four-Question Framework for Threat Modeling](https://shostack.org/files/papers/The_Four_Question_Framework.pdf)

8. Threat Modeling: Designing for Security (Adam Shostack) - canonical book reference; use a stable publisher or bookseller URL instead of temporary file-sharing links.

9. Threat Modeling: A Practical Guide for Development Teams (Izar Tarandach, Matthew J. Coles) - reference only; avoid temporary pre-signed storage URLs in public documents.

10. [Threat Modeling in Practice](https://owasp.org/www-project-developer-guide/release/design/threat_modeling/practical_threat_modeling/) - Threat Modeling in Practice on the main website for The OWASP Foundation. OWASP is a nonprofit found...

11. Experiences Threat Modeling at Microsoft (Adam Shostack) - keep as bibliographic reference only unless you can link to a stable public source.

12. [STRIDE vs PASTA: A...](https://www.aptori.com/blog/stride-vs-pasta-a-comparison-of-threat-modeling-methodologies) - Explore the world of threat modeling with an in-depth look at two popular methodologies: STRIDE and ...

13. [Episode 29 — Model Threats Effectively Using STRIDE and PASTA](https://www.youtube.com/watch?v=cUFRl8JJ7RE) - Threat modeling is one of the most powerful analytical tools in the CSSLP toolkit, and structured me...

14. [PASTA Threat Modeling vs STRIDE: How Are They Different?](https://www.youtube.com/watch?v=oIeF3HkdYcU) - Download the PASTA ebook: 
https://versprite.com/security-resources/risk-based-threat-modeling/  

I...

15. [VAST Threat Methodology](https://threatmodeler.com/glossary/vast-threat-methodology/) - VAST is a threat modeling framework for detecting, categorizing, and prioritizing potential threats ...

16. [VAST Threat Modeling](https://www.linkedin.com/pulse/vast-threat-modeling-james-rabe-tvcfe) - VAST (Visual, Agile, and Simple Threat) is a threat modeling methodology designed to be scalable, ag...

17. Threat Modeling: A Summary of Available Methods - retain as a title reference and replace with a stable public URL if one is available.

18. [Agentic AI Threat Modeling Framework: MAESTRO | CSA](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro) - MAESTRO (Multi-Agent Environment, Security, Threat, Risk, & Outcome) is a novel threat modeling fram...

19. [Threat Modeling Methodologies: STRIDE, PASTA & ...](https://destcert.com/resources/threat-modeling-methodologies/) - Master STRIDE, PASTA, and DREAD threat modeling methodologies. Learn how to identify and mitigate ri...

20. Open and Secure - A Manual for Practicing Threat Modeling to Assess and Fortify Open Source Systems (reference only; do not publish temporary credentialed storage links).

21. [Common Threat Modelling Techniques - Fidelis Security](https://fidelissecurity.com/cybersecurity-101/threat-detection-response/threat-modelling-techniques/) - While STRIDE focuses on threat identification, DREAD determines which threats demand immediate resou...

22. [DREAD Model: Basics of Risk Assessment](https://www.cycoresecure.com/blogs/dread-model-basics-of-risk-assessment) - Learn how the DREAD model simplifies risk assessment in cybersecurity by evaluating threats based on...

23. [DREAD Threat Modeling: An Introduction to Qualitative ...](https://www.eccouncil.org/cybersecurity-exchange/threat-intelligence/dread-threat-modeling-intro/) - DREAD is a risk analysis framework used to qualitatively assess cyberthreats. Learn how understandin...

24. [11 Recommended Threat Modeling Tools](https://www.iriusrisk.com/resources-blog/recommended-threat-modeling-tools) - Free threat modeling tools · OWASP Threat Dragon · Microsoft Threat Modeling Tool · Threagile · AWS ...

25. [Pros and Cons](https://daily.dev/blog/top-10-threat-modeling-tools-compared-2024) - Compare the top 10 threat modeling tools of 2024, their features, integrations, and methodologies to...

26. [Threat Modeling as Code via pytm](https://www.linkedin.com/pulse/threat-modeling-code-via-pytm-chuck-nelson-0a8nc) - In this article, I will describe how to use 'threat modeling as code' via the OWASP Pythonic Threat ...

27. [[PDF] Agile Threat Modeling with Threagile - DeepSec](https://deepsec.net/docs/Slides/2020/How_To_Combat_Risks_Directly_From_Within_Your_IDE_Christian_Schneider.pdf) - Threagile analyzes the model YAML file as a graph of connected components with data flowing between ...

28. [mrwadams/stride-gpt: An AI-powered threat modeling tool ... - GitHub](https://github.com/mrwadams/stride-gpt) - STRIDE GPT is an AI-powered threat modelling tool that leverages Large Language Models (LLMs) to gen...

29. [Microsoft threat modeling tool vs OWASP threat dragon](https://www.reddit.com/r/cybersecurity/comments/15fjfp4/microsoft_threat_modeling_tool_vs_owasp_threat/) - Microsoft threat modeling tool vs OWASP threat dragon

30. [What Is Threat Modeling and Why It's Essential ...](https://snyk.io/de/articles/what-is-threat-modeling-why-its-essential-for-devsecops/) - Learn how continuous threat modeling strengthens DevSecOps by identifying, prioritizing, and mitigat...

31. [Threat Modeling - OWASP SAMM](https://owaspsamm.org/model/design/threat-assessment/stream-b/) - Design / Threat Assessment

32. [Legacy ICS Cybersecurity Assessment Using Hybrid Threat Modeling—An Oil and Gas Sector Case Study](https://www.mdpi.com/2076-3417/14/18/8398) - As security breaches are increasingly widely reported in today’s culture, cybersecurity is gaining a...

33. [Modeling Threats to AI-ML Systems Using STRIDE](https://www.mdpi.com/1424-8220/22/17/6662) - ...incorporating ML components become increasingly pervasive, the need to provide security practitio...

34. [#148 - Threat Modeling (with Adam Shostack)](https://www.youtube.com/watch?v=xWqgaeCXUPc) - On this episode we bring on the leading expert of threat modeling (Adam Shostack) to discuss the fou...

35. [Meetup 007: Threat Modeling with Adam Shostack](https://www.youtube.com/watch?v=P8WD7R10UIw) - Topic 
​Publish your threat models! This talk will cover the idea of publishing threat models, the d...

36. [Master Threat Modeling: Clear and Concise Guide by OWASP](https://www.youtube.com/watch?v=RlKf3un7Uho) - Dive into our comprehensive yet concise guide on threat modeling, brought to you by OWASP. In this v...

37. [CISSP Threat Modeling Explained: STRIDE, DREAD, PASTA, VAST](https://www.youtube.com/watch?v=VoiHRBaV8Xk) - CISSP Threat Modeling Explained: STRIDE, DREAD, PASTA, VAST - In this video, we break down Threat Mo...

38. [The Science of Threat Modeling in Complex Industrial Systems](https://ieeexplore.ieee.org/document/11337795/) - As modern computing environments evolve into intricate, distributed ecosystems that span native clou...

39. [Introducing Systems Thinking as a Framework for Teaching and Assessing
  Threat Modeling Competency](http://arxiv.org/pdf/2404.16632.pdf) - ...for teaching and assessing threat modeling competency.
Prior studies suggest a holistic approach,...

40. [Threat Modeling | OWASP Foundation](https://owasp.org/www-community/Threat_Modeling) - Threat modeling works to identify, communicate, and understand threats and mitigations within the co...

