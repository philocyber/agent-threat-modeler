# **El Modelado de Amenazas Agéntico: Automatización de la Ciberseguridad mediante Sistemas Multi-Agente y Marcos de Trabajo Evolutivos**

La evolución de la ciberseguridad en la era de la inteligencia artificial ha superado la fase de la mera asistencia algorítmica para adentrarse en el dominio de la autonomía operativa. El surgimiento de la IA agéntica, definida como sistemas de software autónomos que perciben, razonan y actúan en entornos digitales para alcanzar objetivos en nombre de principios humanos, ha transformado radicalmente la superficie de ataque y los paradigmas de defensa.1 A diferencia de los modelos generativos tradicionales, que operan de forma reactiva y puntual, los agentes de IA exhiben comportamientos dinámicos, orientados a metas y con capacidad de ejecutar flujos de trabajo multi-etapa de manera independiente.1 Esta capacidad de agencia introduce una complejidad sin precedentes en la identificación de riesgos, lo que hace que el modelado de amenazas tradicional, de carácter estático y manual, resulte insuficiente ante sistemas que aprenden, se adaptan y operan a la velocidad de la máquina.

## **Ontología y Evolución de la IA Agéntica en el Ecosistema de Ciberseguridad**

El cambio hacia sistemas agénticos representa un hito en la arquitectura de software. Mientras que la adopción de agentes de IA alcanzó un 35% en 2023, con proyecciones de crecimiento masivo para los años siguientes, las implicaciones de seguridad apenas comienzan a ser comprendidas en su totalidad.1 La agencia no es simplemente una función adicional; es una propiedad emergente de la integración de modelos de lenguaje de gran tamaño (LLM) con herramientas externas, memoria persistente y capacidades de razonamiento iterativo. En este contexto, un agente no solo genera una respuesta, sino que formula un plan, selecciona las herramientas necesarias (como APIs o comandos de terminal), observa los resultados de sus acciones y ajusta su estrategia en consecuencia.2

Este ciclo de "pensar-actuar-observar" crea una cadena de ejecución que puede ser explotada en múltiples puntos. Las vulnerabilidades ya no se limitan a entradas de datos malformadas, sino que se extienden a la manipulación de la intención, el secuestro de objetivos y la corrupción de la memoria lógica del sistema.2 La naturaleza multi-paso, orientada a objetivos y con estado de los ataques agénticos requiere una reevaluación de cómo definimos las fronteras de confianza. Los límites tradicionales entre lo "externo" y lo "interno" se vuelven difusos cuando un agente interactúa con una base de datos vectorial mediante Generación Aumentada por Recuperación (RAG) o se comunica con otros agentes para completar una tarea compleja.3

## **La Crisis de los Marcos de Trabajo Tradicionales frente a la Autonomía de la IA**

Durante décadas, la industria ha confiado en metodologías como STRIDE, PASTA y OCTAVE para sistematizar el modelado de amenazas. Sin embargo, estas herramientas fueron concebidas para aplicaciones con flujos de control deterministas y arquitecturas de n-capas bien definidas.4 STRIDE, por ejemplo, es excelente para identificar amenazas por elemento (Spoofing, Tampering, etc.), pero su enfoque centrado en componentes individuales falla al capturar las propiedades emergentes de un sistema autónomo.6 Un ataque de inyección de instrucciones puede no violar ninguna regla de integridad de datos en el punto de entrada, pero puede desviar el razonamiento del agente para que ejecute acciones legítimas con una intención maliciosa, lo que STRIDE no está diseñado para detectar eficazmente de forma aislada.3

| Marco de Trabajo | Enfoque Principal | Limitaciones Críticas en Entornos Agénticos |
| :---- | :---- | :---- |
| **STRIDE** | Identificación de vulnerabilidades técnicas por categorías (Spoofing, Tampering, etc.). | Naturaleza estática; no modela la autonomía, el no-determinismo ni el secuestro de objetivos a largo plazo.5 |
| **PASTA** | Enfoque centrado en el riesgo empresarial y la simulación de ataques. | Los límites del sistema son fijos; dificultad para adaptarse a entornos de IA donde el "comportamiento" es la vulnerabilidad.8 |
| **OCTAVE** | Gestión de riesgos operativos y organizacionales. | Escaso nivel de detalle técnico para analizar interacciones complejas entre microservicios de agentes.4 |
| **LINDDUN** | Privacidad de los datos y protección de la información personal. | Enfoque exclusivo en privacidad, ignorando la integridad del razonamiento y el control del flujo operativo del agente.4 |
| **TRIKE** | Gestión de riesgos basada en activos y niveles de confianza. | Requiere modificaciones sustanciales para incluir los riesgos internos del razonamiento de la IA y el uso dinámico de herramientas.4 |

La insuficiencia de estos modelos radica en su incapacidad para abordar el no-determinismo intrínseco de los LLMs. En el software tradicional, una entrada A siempre produce una salida B; en un sistema agéntico, la salida depende no solo de la entrada, sino del estado de la memoria, el contexto del sistema y la probabilidad estadística del modelo en un momento dado.3 Esta variabilidad introduce brechas en la validación de controles y en el análisis forense, exigiendo un enfoque que considere el comportamiento del agente como una capa de seguridad en sí misma.10

## **El Marco MAESTRO: Anatomía de una Defensa Agéntica Multicapa**

Para llenar el vacío dejado por las metodologías convencionales, el marco de trabajo MAESTRO (Multi-Agent Environment, Security, Threat, Risk, and Outcome) propone un enfoque estructurado en siete capas arquitectónicas. Esta descomposición permite a los equipos de seguridad localizar amenazas en diferentes niveles del ecosistema agéntico, desde el modelo fundacional hasta las interacciones externas.10

### **Descomposición de las Siete Capas de MAESTRO**

El valor intelectual de MAESTRO reside en forzar un análisis exhaustivo de cada componente del sistema, reconociendo que una vulnerabilidad en una capa puede amplificarse en las capas subsiguientes.10

1. **Capa 1: Modelos Fundacionales (L1):** Esta capa comprende el núcleo de inteligencia, ya sea un modelo pre-entrenado o ajustado. Las amenazas incluyen el envenenamiento del modelo, ataques de extracción para robar propiedad intelectual y vulnerabilidades inherentes que permiten el bypass de guardrails mediante técnicas de jailbreaking avanzadas.8  
2. **Capa 2: Operaciones de Datos (L2):** Se enfoca en la gestión de datos para el entrenamiento, ajuste fino y, crucialmente, la infraestructura RAG. El envenenamiento de la base de datos vectorial mediante la inserción de documentos maliciosos es una de las mayores preocupaciones aquí, ya que puede corromper el conocimiento del agente de forma persistente.10  
3. **Capa 3: Marcos de Trabajo de Agentes (L3):** Incluye las bibliotecas de orquestación como LangChain, AutoGen o Semantic Kernel. Las vulnerabilidades en esta capa suelen estar relacionadas con la lógica de planificación, el manejo inadecuado del contexto y fallos en el parsing de las salidas del modelo que se traducen en acciones del sistema.10  
4. **Capa 4: Despliegue e Infraestructura (L4):** Comprende el entorno de nube, contenedores, redes y sistemas operativos. El aislamiento de la memoria y la protección de los canales de comunicación son críticos para prevenir el movimiento lateral si un agente es comprometido.8  
5. **Capa 5: Evaluación y Observabilidad (L5):** Se encarga del monitoreo del rendimiento y la seguridad. Una observabilidad deficiente permite que ataques sutiles, como la manipulación gradual de objetivos (goal drift), pasen desapercibidos para los administradores humanos.10  
6. **Capa 6: Seguridad y Cumplimiento (L6):** Define las políticas de gobernanza y los controles de acceso. En los sistemas agénticos, el desafío es aplicar el principio de menor privilegio a identidades que pueden cambiar de rol o escalar tareas de forma autónoma.10  
7. **Capa 7: Ecosistema de Agentes (L7):** Analiza las interacciones entre múltiples agentes y sistemas de terceros, como servidores de Model Context Protocol (MCP). La colusión entre agentes para evadir la supervisión y la propagación de alucinaciones son riesgos emergentes en esta capa.7

La aplicación de MAESTRO no es estática; requiere un análisis de amenazas cruzadas. Por ejemplo, un atacante puede explotar una vulnerabilidad en la Capa 4 (infraestructura) para inyectar datos en la Capa 2 (datos), lo que eventualmente corrompe el razonamiento en la Capa 3 (framework) y produce un resultado malicioso en la Capa 7 (ecosistema).12 Esta visión holística es esencial para diseñar sistemas que no solo sean seguros individualmente, sino resilientes como un todo.

## **Taxonomía de Amenazas Agénticas y Vectores de Ataque Emergentes**

La integración de la IA generativa en flujos de trabajo autónomos ha dado lugar a una nueva taxonomía de amenazas, muchas de las cuales han sido codificadas por iniciativas como el OWASP Top 10 para Aplicaciones Agénticas.14 Comprender estos vectores es el primer paso para automatizar su detección y mitigación.

### **Secuestro de Objetivos y Manipulación de la Intención**

El secuestro de objetivos (Goal Hijacking) ocurre cuando un atacante utiliza inyecciones de prompts (directas o indirectas) para desviar el plan de ejecución del agente hacia fines maliciosos.3 A diferencia de un jailbreak tradicional, donde el objetivo es obtener una respuesta prohibida, en el secuestro de objetivos se busca que el agente utilice sus herramientas legítimas para realizar acciones perjudiciales, como transferir fondos o borrar archivos, creyendo que está cumpliendo con su misión original.3

### **Envenenamiento de Memoria y Contexto**

Los agentes agénticos a menudo poseen memoria de corto plazo (ventana de contexto) y de largo plazo (bases de datos vectoriales o logs de sesiones anteriores).2 El envenenamiento de memoria implica la inserción de información falsa o instrucciones maliciosas que el agente recuperará en interacciones futuras, alterando su base de conocimientos de manera persistente.2 Este vector es particularmente insidioso porque el ataque puede permanecer latente durante semanas hasta que una consulta específica active el contenido envenenado.3

### **Abuso de Identidad y Privilegios en Sistemas Multi-Agente**

En arquitecturas donde múltiples agentes colaboran, la gestión de la identidad se vuelve crítica. Un atacante puede comprometer a un agente de baja prioridad y utilizarlo para enviar mensajes fraudulentos a un agente con mayores privilegios (como un agente administrador de nube), explotando la confianza implícita entre los componentes del sistema.2 La falta de una verificación de identidad fuerte entre agentes y la delegación de tareas sin una validación de seguridad rigurosa son brechas comunes en las implementaciones actuales.10

| Amenaza Agéntica | Descripción Breve | Capa MAESTRO Afectada | Ejemplo de Escenario |
| :---- | :---- | :---- | :---- |
| **Inyección Indirecta de Prompts** | Instrucciones maliciosas ocultas en datos externos (PDF, correos). | L2, L3 | Un agente resume un currículum que contiene una instrucción para enviar las credenciales del usuario a un servidor externo.3 |
| **Secuestro de Objetivos** | Redirección de la lógica de planificación del agente. | L3 | Un atacante convence a un agente de compras de que su nuevo objetivo es "maximizar las pérdidas" en lugar del ahorro.7 |
| **Abuso de Herramientas** | Manipulación del agente para usar APIs de forma dañina. | L4, L7 | Un agente de calendario es engañado para borrar todas las reuniones del CEO como parte de un ataque de denegación de servicio.2 |
| **Colapso del Razonamiento** | Degradación de la capacidad de juicio del modelo ante entradas conflictivas. | L1 | Un agente de seguridad ignora una alerta crítica porque un atacante inundó su contexto con falsos positivos sutiles.8 |
| **Exfiltración por Canal Lateral** | Uso de herramientas permitidas para sacar datos de forma encubierta. | L4 | Un agente envía datos sensibles codificados en consultas de búsqueda de un buscador web permitido.3 |

## **Automatización del Modelado de Amenazas mediante Sistemas Multi-Agente (MAS)**

El núcleo de la innovación en ciberseguridad moderna es el uso de sistemas multi-agente para automatizar el propio proceso de modelado de amenazas. Esta estrategia permite que la seguridad sea tan dinámica y escalable como las aplicaciones que protege, transformando una tarea manual de días o semanas en un proceso continuo integrado en el ciclo de vida del desarrollo de software (SDLC).19

### **Orquestación de Agentes para la Defensa: El Patrón Planificador-Ejecutor-Revisor**

La automatización efectiva no se logra con un solo agente omnisciente, sino mediante una orquestación de roles especializados que colaboran para analizar un sistema. Este enfoque imita la estructura de un equipo de seguridad humano, pero a una escala y velocidad infinitamente mayores.21

* **Agente Planificador:** Analiza la documentación de la arquitectura, los diagramas y el código fuente para identificar los activos, los flujos de datos y los límites de confianza. Su tarea es descomponer el sistema en componentes manejables y definir el alcance del análisis.21  
* **Agente Investigador (Analista de Inteligencia):** Utiliza herramientas como el Model Context Protocol (MCP) para realizar búsquedas en tiempo real de CVEs, tácticas de MITRE ATT\&CK y vulnerabilidades recientes en las tecnologías identificadas por el planificador.19  
* **Agente de Ejecución de Amenazas (Analista STRIDE/MAESTRO):** Toma cada componente y flujo de datos y aplica sistemáticamente metodologías de modelado de amenazas. Por ejemplo, para un microservicio de autenticación, este agente simulará ataques de Spoofing o Elevation of Privilege, evaluando la robustez de los controles actuales.22  
* **Agente Revisor (Validador de Resultados):** Evalúa los hallazgos de los agentes anteriores para reducir los falsos positivos. Su función es asegurar que las amenazas identificadas sean plausibles y que las mitigaciones sugeridas sean técnicamente viables y alineadas con las políticas de la organización.22

### **Patrones de Interacción Multi-Agente en Modelado de Amenazas**

La forma en que estos agentes interactúan determina la eficacia del sistema. Se han identificado tres patrones principales de orquestación que las organizaciones pueden implementar 26:

1. **Patrón de Supervisor (Control Centralizado):** Un agente orquestador central coordina todas las actividades. Recibe la entrada inicial, asigna tareas específicas a los agentes trabajadores y sintetiza sus respuestas en un informe final de modelado de amenazas. Es ideal para garantizar la consistencia y la trazabilidad del razonamiento.26  
2. **Red de Agentes Adaptativos (Colaboración Descentralizada):** Los agentes colaboran de forma más flexible, transfiriendo tareas entre sí según sea necesario sin pasar siempre por un supervisor central. Por ejemplo, si el agente de análisis de código encuentra una vulnerabilidad de red, puede invocar directamente al agente de infraestructura para evaluar el impacto.22  
3. **Patrón Jerárquico:** Los agentes se organizan en capas. Los agentes de alto nivel gestionan objetivos estratégicos (como "asegurar el despliegue en AWS"), mientras que los agentes de bajo nivel se encargan de tareas tácticas (como "escanear configuraciones de S3").27

Este enfoque de MAS permite abordar problemas de gran escala mediante la descomposición recursiva del trabajo, haciendo que el modelado de amenazas sea una operación asíncrona, resiliente y altamente adaptable a los cambios en la topología del sistema.23

## **Análisis de Herramientas y Ecosistemas de Automatización Agéntica**

Varias plataformas han surgido para materializar el concepto de modelado de amenazas automatizado por IA, cada una con enfoques técnicos distintos que van desde el análisis de diagramas hasta la auditoría profunda de código fuente.

### **AWS Threat Designer: Modelado Basado en Visión y Razonamiento Adaptativo**

AWS Threat Designer es una aplicación de IA generativa que funciona como un agente autónomo para simplificar el diseño de sistemas seguros. Utiliza modelos de la familia Claude 3.x para analizar diagramas de arquitectura subidos por los usuarios y generar modelos de amenazas detallados.24

Una de las innovaciones más críticas de esta herramienta es su **mecanismo de iteración adaptativa**. Implementado a través de LangGraph, el servicio de agentes puede operar en dos modos 20:

* **Iteración Controlada por el Usuario:** El profesional de seguridad especifica el número de pasadas que el agente debe realizar, permitiendo una exploración profunda de casos de borde en cada ciclo.20  
* **Análisis de Brechas Autónomo:** El agente evalúa su propio catálogo de amenazas generado y, si detecta áreas poco desarrolladas o inconsistencias, dispara automáticamente iteraciones adicionales hasta alcanzar un criterio de completitud predefinido. Esto representa un sistema de control de calidad autónomo integrado en el flujo de trabajo.20

### **Arrows (FuzzingLabs): Automatización de STRIDE desde el Código Fuente**

A diferencia de las herramientas que dependen de diagramas manuales, Arrows se enfoca en un análisis de "caja blanca" (whitebox). Este agente de IA navega por el código fuente de una aplicación web, identificando automáticamente componentes como rutas, controladores, middlewares y bases de datos.25

El proceso de Arrows es notable por su sistematicidad:

1. **Identificación de Componentes:** Realiza un barrido agnóstico del lenguaje (JavaScript, Python, Go, Java, etc.) para mapear la arquitectura real implementada.25  
2. **Análisis STRIDE Especializado:** Despliega agentes analistas específicos para cada una de las seis categorías de STRIDE. Por ejemplo, el analizador de "Tampering" utiliza prompts diseñados para detectar riesgos de inyección SQL o manipulación de datos, mientras que el de "Information Disclosure" busca fugas de secretos o logs excesivos.25  
3. **Visualización Dinámica:** Genera diagramas interactivos que no son estáticos, sino que reflejan la complejidad real del sistema, permitiendo a los equipos de seguridad interactuar con los hallazgos directamente sobre el mapa de la arquitectura.25

### **Vertice Cyber y el Protocolo de Contexto del Modelo (MCP)**

Vertice Cyber representa la vanguardia de las plataformas de seguridad nativas en MCP. MCP es un protocolo que permite a los agentes de IA descubrir y utilizar herramientas de forma estandarizada y segura.14 Vertice orquesta agentes para tareas ofensivas (simulaciones de ataque en sandbox), defensivas (revisión de parches en PRs de GitHub) y de gobernanza.28

Su sistema de **Magistrado Ético** es un componente de gobernanza de siete fases que valida cada acción de los agentes de IA antes de su ejecución, asegurando que las simulaciones de ataque o los cambios de configuración se mantengan dentro de los límites éticos y operativos establecidos. Este nivel de control es indispensable para desplegar agentes autónomos en infraestructuras de producción críticas.28

## **Cuantificación del Riesgo y Métricas de Explotación Agéntica**

El modelado de amenazas académico requiere pasar de lo cualitativo a lo cuantitativo. La tesis de Gabbita (2025) introduce dos métricas fundamentales diseñadas para evaluar la seguridad en flujos de trabajo agénticos que utilizan protocolos como MCP y Agent-to-Agent (A2A).29

### **Índice de Explotabilidad del Flujo de Trabajo (WEI)**

El WEI cuantifica la facilidad con la que un atacante puede explotar las vulnerabilidades identificadas en un flujo de trabajo agéntico. A diferencia de las puntuaciones de vulnerabilidad tradicionales (como CVSS), el WEI es una métrica estructural que captura las características de la superficie de ataque del sistema completo.29

La computación del WEI para una capa específica de MAESTRO se basa en un algoritmo de ponderación determinista:

![][image1]  
En esta ecuación:

* ![][image2] es la media aritmética de la Complejidad del Ataque (Attack Complexity) para todas las vulnerabilidades detectadas en esa capa.  
* ![][image3] representa el Impacto Empresarial (Business Impact) promedio.  
* ![][image4] asigna una importancia relativa a cada capa de MAESTRO (por ejemplo, la Capa 3 de Frameworks suele tener un peso mayor de 0.20 debido a su papel central en el razonamiento).29

El WEI tiende a mantenerse estable incluso cuando aumenta el número de vulnerabilidades, lo que indica que mide la susceptibilidad intrínseca del diseño más que la densidad de errores.29

### **Puntuación de Propagación del Riesgo (RPS)**

El RPS mide el potencial de riesgo en cascada o amplificación sistémica. En un entorno agéntico, un fallo en un agente puede propagarse rápidamente a otros debido al acoplamiento de protocolos y la interconexión de sistemas.29

![][image5]  
Donde:

* ![][image6] es la Severidad de la Vulnerabilidad (Vulnerability Severity) en una escala de 1 a 10\.  
* ![][image7] es el Factor de Acoplamiento del Protocolo (Protocol Coupling), medido de 1 a 3, que refleja la intensidad de la interacción entre los agentes y las herramientas externas.29

A diferencia del WEI, el RPS exhibe un crecimiento lineal fuerte con la acumulación de vulnerabilidades. Una puntuación de RPS superior a 3.0 suele ser un indicador primario de una exposición de seguridad crítica que requiere intervención inmediata.29

## **Modelado de Amenazas en Aplicaciones GenAI e Infraestructuras Nativas de IA**

El modelado de amenazas para aplicaciones GenAI (como copilotos empresariales o agentes de atención al cliente) presenta desafíos que los sistemas tradicionales no contemplaban, principalmente debido a la integración de RAG y la ejecución dinámica de código.19

### **Riesgos en Tuberías RAG y Bases de Datos Vectoriales**

Las arquitecturas RAG permiten que los LLMs consulten datos externos para mejorar la precisión. Sin embargo, esto crea un vector de ataque donde el contenido recuperado actúa como una instrucción maliciosa inyectada. El modelado de amenazas agéntico debe analizar:

* **Integridad de la Fuente:** ¿Cómo validamos que los documentos en el almacén de datos no han sido alterados?.3  
* **Aislamiento del Contexto:** ¿Puede un documento recuperado de un usuario A filtrarse en el contexto de la consulta del usuario B?.3  
* **Normalización de Entradas:** El uso de homoglifos Unicode o payloads codificados en base64 para evadir escáneres de instrucciones es una táctica común que debe ser modelada y mitigada mediante la normalización canónica antes del procesamiento.3

### **Seguridad de los Servidores MCP y el Ecosistema de Herramientas**

El Model Context Protocol (MCP) se ha convertido en el estándar para conectar agentes con herramientas. El modelado de amenazas debe tratar a cada servidor MCP como un límite de confianza potencial.14 Los riesgos incluyen:

* **Ataques de "Rug Pull":** Un servidor MCP legítimo que muta su comportamiento o definiciones de herramientas después de haber sido aprobado por el equipo de seguridad.3  
* **Exfiltración por Canales Encubiertos:** Herramientas de red que permiten consultas DNS o tráfico HTTP aparentemente inofensivo que se utiliza para sacar datos sensibles fragmentados.3  
* **Colusión de Herramientas:** Un escenario donde dos herramientas independientes (por ejemplo, una que lee archivos y otra que envía correos) son utilizadas de forma coordinada por un agente comprometido para exfiltrar información sin activar alertas individuales.3

## **Visualización Avanzada y Modelado Basado en Código: D2 y Mermaid**

Un modelo de amenazas es solo tan útil como la claridad con la que se comunica. La transición hacia diagramas como código (Diagrams as Code) permite que los agentes de IA no solo identifiquen amenazas, sino que generen visualizaciones arquitectónicas complejas y árboles de ataque actualizados automáticamente.32

### **Uso de D2 para Visualización de Escenarios y Capas de Seguridad**

D2 (D2lang) destaca por su capacidad de manejar la complejidad mediante "Escenarios" y "Capas". Esto es invaluable para el modelado de amenazas agéntico porque permite superponer vistas de ataque sobre la arquitectura normal.34

* **Capas para el Alcance Arquitectónico:** Se pueden definir capas para distinguir entre componentes públicos e internos. Un agente de seguridad puede generar un diagrama base y luego usar capas para resaltar los componentes que tienen acceso a datos sensibles.36  
* **Escenarios de Amenazas:** Los escenarios en D2 permiten visualizar estados alternativos del sistema. Por ejemplo, se puede crear un escenario de "Brecha en el Agente de Triage" donde las conexiones comprometidas cambien de color o grosor, y se añadan nodos que representen al atacante y los puntos de exfiltración, todo sin duplicar el código del diagrama principal.36

### **Árboles de Ataque Dinámicos en Mermaid.js**

Mermaid.js es una herramienta de marcado declarativo que facilita la creación de árboles de ataque dinámicos integrados en la documentación técnica.33 Un sistema multi-agente puede generar automáticamente estos árboles a partir de sus análisis:

* **Nodos y Bordes Significativos:** Los nodos representan pasos del atacante (por ejemplo, "Inyección de prompt en PDF"), vulnerabilidades o mitigaciones. Los bordes definen el camino lógico del ataque.37  
* **Enriquecimiento con Metadatos:** Los agentes pueden incluir notas en el código de Mermaid para detallar puntuaciones de riesgo, niveles de impacto o referencias a OWASP directamente en el diagrama.3

| Característica de Visualización | Beneficio para el Modelado de Amenazas | Herramienta Recomendada |
| :---- | :---- | :---- |
| **Escenarios de Ataque** | Visualiza el estado del sistema bajo una brecha específica sin alterar el diagrama base. | D2 36 |
| **Árboles de Ataque** | Muestra la ruta lógica de un atacante desde el punto de entrada hasta el objetivo final. | Mermaid.js 37 |
| **Mapeo de Nube Automático** | Genera diagramas de infraestructura (AWS, Azure) a partir de descripciones de recursos. | Diagrams (Python) 32 |
| **Límites de Confianza Dinámicos** | Resalta visualmente las zonas de confianza que cambian según el rol asumido por el agente. | D2 / Architecture-beta 36 |

## **Gobernanza, Ética y el Futuro de la Defensa Autónoma**

La automatización total del modelado de amenazas no está exenta de desafíos operativos y éticos. La autonomía de los agentes introduce riesgos de comportamiento poco ético o decisiones de seguridad erróneas que pueden causar daños significativos si no hay una supervisión adecuada.1

### **El Rol de la Supervisión Humana (Human-in-the-loop)**

A medida que los sistemas de modelado de amenazas se vuelven más autónomos, la función del profesional de seguridad evoluciona de "ejecutor" a "supervisor y auditor". Las organizaciones deben implementar umbrales de aprobación adaptativos: si el sistema identifica una amenaza de alto impacto o propone una mitigación crítica, se requiere una validación humana secundaria (L3 approval) antes de proceder.3 El peligro del "rubber-stamping" (aprobación automática por fatiga) debe ser mitigado mediante sistemas que presenten el razonamiento de la IA de forma clara y rastreable.3

### **Resiliencia y Auto-Corrección**

El futuro del modelado de amenazas agéntico se dirige hacia sistemas auto-sanadores (self-healing). En este paradigma, un sistema multi-agente no solo identifica una amenaza en la arquitectura, sino que propone y valida un parche de código o una reconfiguración de infraestructura en un entorno de pruebas, solicitando la aprobación final para desplegar la defensa.19 Esto reduce drásticamente el tiempo medio de detección (MTTD) y de respuesta (MTTR). Experiencias preliminares en entornos de salud han demostrado reducciones del MTTD de 72.3 horas a 0.8 horas utilizando marcos de monitoreo agéntico basados en aprendizaje por refuerzo.10

### **Conclusiones Estratégicas para el Modelado de Amenazas Agéntico**

La adopción de sistemas multi-agente para la automatización del modelado de amenazas es un imperativo para las organizaciones que operan en entornos de alta complejidad y rápida evolución. Las conclusiones clave de esta investigación son:

1. **Sustitución de Modelos Estáticos:** Las metodologías tradicionales como STRIDE deben ser complementadas o reemplazadas por marcos específicos de IA como MAESTRO para capturar riesgos de razonamiento, memoria y autonomía.7  
2. **Orquestación MAS como Estándar:** La automatización no debe depender de un solo agente, sino de una arquitectura MAS (Planificador-Ejecutor-Revisor) que garantice la segregación de funciones y la validación cruzada de hallazgos.22  
3. **Cuantificación Rigurosa:** El uso de métricas como WEI (explotabilidad) y RPS (propagación) es esencial para transformar el modelado de amenazas en una herramienta de decisión basada en datos objetivos y comparables.29  
4. **Integración de Protocolos Modernos:** La seguridad debe ser nativa a protocolos como MCP y A2A, reconociendo a los servidores de herramientas y a los agentes colaboradores como nuevos perímetros de confianza dinámicos.14  
5. **Visualización Basada en Código:** La capacidad de generar y versionar modelos de amenazas mediante D2 y Mermaid permite mantener la documentación de seguridad sincronizada con la realidad operativa del sistema.36

El modelado de amenazas agéntico no es simplemente una mejora incremental; es un cambio fundamental en la forma en que concebimos la seguridad de los sistemas inteligentes. Al permitir que la IA piense como un atacante y actúe como un defensor, las organizaciones pueden anticipar vulnerabilidades antes de que sean explotadas, construyendo una infraestructura digital que no solo sea segura por diseño, sino resiliente por autonomía.17

#### **Fuentes citadas**

1. Agentic AI, explained | MIT Sloan, acceso: febrero 24, 2026, [https://mitsloan.mit.edu/ideas-made-to-matter/agentic-ai-explained](https://mitsloan.mit.edu/ideas-made-to-matter/agentic-ai-explained)  
2. Threat Modeling the AI Agent: Architecture, Threats & Monitoring \- Cloud Security Podcast, acceso: febrero 24, 2026, [https://www.cloudsecuritypodcast.tv/videos/threat-modeling-the-ai-agent-architecture-threats-monitoring](https://www.cloudsecuritypodcast.tv/videos/threat-modeling-the-ai-agent-architecture-threats-monitoring)  
3. Threat modeling agentic AI: a scenario-driven approach, acceso: febrero 24, 2026, [https://christian-schneider.net/blog/threat-modeling-agentic-ai/](https://christian-schneider.net/blog/threat-modeling-agentic-ai/)  
4. 5 Threat Modeling Methodologies | Pros & Use Cases Explained \- IriusRisk, acceso: febrero 24, 2026, [https://www.iriusrisk.com/threat-modeling-methodologies](https://www.iriusrisk.com/threat-modeling-methodologies)  
5. Threat modeling STRIDE methodology \- IriusRisk, acceso: febrero 24, 2026, [https://www.iriusrisk.com/resources-blog/threat-modeling-methodology-stride](https://www.iriusrisk.com/resources-blog/threat-modeling-methodology-stride)  
6. What Is STRIDE Threat Model? Limitations & Modern Adaptations \- Apiiro, acceso: febrero 24, 2026, [https://apiiro.com/glossary/stride-threat-model/](https://apiiro.com/glossary/stride-threat-model/)  
7. Agentic AI Threat Modeling Framework: MAESTRO | CSA \- Cloud Security Alliance, acceso: febrero 24, 2026, [https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro)  
8. Threat Modeling and Risk Analysis for Network Monitoring Agentic AI System \- arXiv.org, acceso: febrero 24, 2026, [https://arxiv.org/html/2508.10043v1](https://arxiv.org/html/2508.10043v1)  
9. What is threat modeling? \- GitHub, acceso: febrero 24, 2026, [https://github.com/resources/articles/what-is-threat-modeling](https://github.com/resources/articles/what-is-threat-modeling)  
10. Agentic AI Threat Modeling \- ResearchGate, acceso: febrero 24, 2026, [https://www.researchgate.net/publication/396047356\_Agentic\_AI\_Threat\_Modeling](https://www.researchgate.net/publication/396047356_Agentic_AI_Threat_Modeling)  
11. Threat Modeling of AI Applications Is Mandatory | Optiv | \[Learn More\], acceso: febrero 24, 2026, [https://www.optiv.com/insights/discover/blog/threat-modeling-ai-applications-mandatory](https://www.optiv.com/insights/discover/blog/threat-modeling-ai-applications-mandatory)  
12. MAESTRO Agentic AI Threat Modeling Framework | by Tahir \- Medium, acceso: febrero 24, 2026, [https://medium.com/@tahirbalarabe2/maestro-agentic-ai-threat-modeling-framework-791e52ed9bbd](https://medium.com/@tahirbalarabe2/maestro-agentic-ai-threat-modeling-framework-791e52ed9bbd)  
13. raphabot/awesome-cybersecurity-agentic-ai \- GitHub, acceso: febrero 24, 2026, [https://github.com/raphabot/awesome-cybersecurity-agentic-ai](https://github.com/raphabot/awesome-cybersecurity-agentic-ai)  
14. Resources Archive \- OWASP Gen AI Security Project, acceso: febrero 24, 2026, [https://genai.owasp.org/resources/?e-filter-3b7adda-initiative\_name=agentic-security](https://genai.owasp.org/resources/?e-filter-3b7adda-initiative_name=agentic-security)  
15. Home \- OWASP Gen AI Security Project, acceso: febrero 24, 2026, [https://genai.owasp.org/](https://genai.owasp.org/)  
16. Agents Under Attack: Threat Modeling Agentic AI \- CyberArk, acceso: febrero 24, 2026, [https://www.cyberark.com/resources/threat-research-blog/agents-under-attack-threat-modeling-agentic-ai](https://www.cyberark.com/resources/threat-research-blog/agents-under-attack-threat-modeling-agentic-ai)  
17. Agentic AI Security – Part 2: Threat Modeling \- REBELADMIN, acceso: febrero 24, 2026, [https://www.rebeladmin.com/agentic-ai-threat-modeling/](https://www.rebeladmin.com/agentic-ai-threat-modeling/)  
18. \[2508.09815\] Extending the OWASP Multi-Agentic System Threat Modeling Guide: Insights from Multi-Agent Security Research \- arXiv.org, acceso: febrero 24, 2026, [https://arxiv.org/abs/2508.09815](https://arxiv.org/abs/2508.09815)  
19. LLM based Threat Modeling: Let AI Think Like a Hacker, So You Don't Have To \- evoailabs, acceso: febrero 24, 2026, [https://evoailabs.medium.com/llm-based-threat-modeling-let-ai-think-like-a-hacker-so-you-dont-have-to-43d1960e1b31](https://evoailabs.medium.com/llm-based-threat-modeling-let-ai-think-like-a-hacker-so-you-dont-have-to-43d1960e1b31)  
20. Accelerate threat modeling with generative AI | Artificial Intelligence, acceso: febrero 24, 2026, [https://aws.amazon.com/blogs/machine-learning/accelerate-threat-modeling-with-generative-ai/](https://aws.amazon.com/blogs/machine-learning/accelerate-threat-modeling-with-generative-ai/)  
21. The Orchestration of Multi-Agent Systems: Architectures, Protocols, and Enterprise Adoption, acceso: febrero 24, 2026, [https://arxiv.org/html/2601.13671v1](https://arxiv.org/html/2601.13671v1)  
22. Multi-Agent Interaction Patterns using Microsoft Agent Framework \- Medium, acceso: febrero 24, 2026, [https://medium.com/@vin4tech/multi-agent-interaction-patterns-using-microsoft-agent-framework-4c557a335184](https://medium.com/@vin4tech/multi-agent-interaction-patterns-using-microsoft-agent-framework-4c557a335184)  
23. AI Agent Orchestration Patterns \- Azure Architecture Center \- Microsoft Learn, acceso: febrero 24, 2026, [https://learn.microsoft.com/en-us/azure/architecture/ai-ml/guide/ai-agent-design-patterns](https://learn.microsoft.com/en-us/azure/architecture/ai-ml/guide/ai-agent-design-patterns)  
24. awslabs/threat-designer: Threat Designer is a GenerativeAI ... \- GitHub, acceso: febrero 24, 2026, [https://github.com/awslabs/threat-designer](https://github.com/awslabs/threat-designer)  
25. AI-Driven Threat Modeling \- LLMs For Automated STRIDE Analysis, acceso: febrero 24, 2026, [https://fuzzinglabs.com/ai-threat-modeling-arrows/](https://fuzzinglabs.com/ai-threat-modeling-arrows/)  
26. Choosing the right orchestration pattern for multi agent systems \- Kore.ai, acceso: febrero 24, 2026, [https://www.kore.ai/blog/choosing-the-right-orchestration-pattern-for-multi-agent-systems](https://www.kore.ai/blog/choosing-the-right-orchestration-pattern-for-multi-agent-systems)  
27. Four Design Patterns for Event-Driven, Multi-Agent Systems \- Confluent, acceso: febrero 24, 2026, [https://www.confluent.io/blog/event-driven-multi-agent-systems/](https://www.confluent.io/blog/event-driven-multi-agent-systems/)  
28. JuanCS-Dev/vertice-cyber: MCP-native multi-agent cybersecurity platform with FastAPI bridge, Go TUI, React dashboard, and end-to-end runtime validation. \- GitHub, acceso: febrero 24, 2026, [https://github.com/JuanCS-Dev/vertice-cyber](https://github.com/JuanCS-Dev/vertice-cyber)  
29. a MAESTRO-based assessment framework for Model Context ..., acceso: febrero 24, 2026, [https://repository.lib.umassd.edu/view/pdfCoverPage?instCode=01MA\_DM\_INST\&filePid=13177549070001301\&download=true](https://repository.lib.umassd.edu/view/pdfCoverPage?instCode=01MA_DM_INST&filePid=13177549070001301&download=true)  
30. ThreatModeling-LLM: Automating Threat Modeling using Large Language Models for Banking System \- arXiv.org, acceso: febrero 24, 2026, [https://arxiv.org/html/2411.17058v2](https://arxiv.org/html/2411.17058v2)  
31. I made a visual guide breaking down EVERY LangChain component (with architecture diagram) \- Reddit, acceso: febrero 24, 2026, [https://www.reddit.com/r/LangChain/comments/1p9fpp2/i\_made\_a\_visual\_guide\_breaking\_down\_every/](https://www.reddit.com/r/LangChain/comments/1p9fpp2/i_made_a_visual_guide_breaking_down_every/)  
32. Diagrams · Diagram as Code, acceso: febrero 24, 2026, [https://diagrams.mingrammer.com/](https://diagrams.mingrammer.com/)  
33. Create diagrams as code using Mermaid \- Documentation starter pack, acceso: febrero 24, 2026, [https://canonical-starter-pack.readthedocs-hosted.com/stable/how-to/diagrams-as-code-mermaid/](https://canonical-starter-pack.readthedocs-hosted.com/stable/how-to/diagrams-as-code-mermaid/)  
34. Using D2 to draw Software Architecture Diagrams | by Aditya Ramaswamy | Medium, acceso: febrero 24, 2026, [https://medium.com/@raditya.mit/using-d2-to-draw-software-architecture-diagrams-300576a7f128](https://medium.com/@raditya.mit/using-d2-to-draw-software-architecture-diagrams-300576a7f128)  
35. Terrastruct | Diagramming tools crafted to visualize software architecture, acceso: febrero 24, 2026, [https://terrastruct.com/](https://terrastruct.com/)  
36. Scenarios | D2 Documentation, acceso: febrero 24, 2026, [https://d2lang.com/tour/scenarios/](https://d2lang.com/tour/scenarios/)  
37. Developing Attack Trees with Mermaid – Ryan Straight, Ph.D, acceso: febrero 24, 2026, [https://ryanstraight.com/posts/attack-trees-in-mermaid/](https://ryanstraight.com/posts/attack-trees-in-mermaid/)  
38. Architecture diagrams as code: Mermaid vs Architecture as Code | by Kevin O'Shea, acceso: febrero 24, 2026, [https://medium.com/@koshea-il/architecture-diagrams-as-code-mermaid-vs-architecture-as-code-d7f200842712](https://medium.com/@koshea-il/architecture-diagrams-as-code-mermaid-vs-architecture-as-code-d7f200842712)  
39. Architecture Diagrams Documentation (v11.1.0+) \- Mermaid, acceso: febrero 24, 2026, [https://mermaid.js.org/syntax/architecture](https://mermaid.js.org/syntax/architecture)

[image1]: <data:image/png;base64,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>

[image2]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAD8AAAAYCAYAAABN9iVRAAADGUlEQVR4Xu2Y2avNURTHlwyZ50iGIsqYByFjN2MRD3hQeJQ5ImMeruTBEBIlERIiQzIVHi4KUfIH8EBKkTx5QIbvx/ptv332Oaf7IvecnG99cvZav9++e+299t7rx6ymmmoqo15im+icOsqopRgmFog60TqzNxMDRfOsXfFiwDvFW9En8aXqKA6Jr6JB7BC7xHMxW2wSB8PD1aBR4nMGv8tpivggrlnxJHUTj8RPMS/xVazaiDPijfgmJha6/4iAWO1j5ilfSsvERzEkdVSqCGqv2GK+anMK3b/F3mbFH4hOiS8W7z4UHVJHJaqHuCz6is3mwS8qeMJX+aL4YY2nM8FzHlSFNorF2W8GTvBMQqxx4ot4JrokvlSc+O1TYyWKVGavh8GG4Dm5Y4WMqJoVbUyk8mExKbJx0HHgnY5siHap7VC1mi6+mweVctPyggWF4EsdhLFGig2psdLEaX3evAqLRYX32rxwifct26Cx4CmStptPakVrvfl9nCoE/0r0jOx15lnCNiHIUhor9ll+//cX58xL3wnignnV11tsFbfFfMv7oxSeJU5lhAIKO89dEUvEeNHCyvdf9hrmD7GvX4h+iQ/x4mPzCWAiggiIwuaTmBbZEX3OFGct/8PY1ogZ4qX5bYHYPgTNc4PM6wEmmf6PmN88vDtaLDUPEvvqzM53x6Xs+XL9l8xODjYGH/b1OzE08u83r96Cn98nRKvMTxVIIUQGNIiV5jU8ATBo/EEMmuDIrpPmA2cb3bK8euRf2tiZ0PdiuVghjpuvPEE9tTwLuW3I2nL937HixfmrYtWYcdJtjBUejLEYEAMLN8QA84ki7VF9BuIqvWrFJTN2MqrU5KX9Dxf3Rfes3aSiGLpr+UfSXHHdfLLwNZjvX9J3nRVer0zwYPPgQ8FFcE/Ms2GhFffPcxzMU8XkzNZk4tpjpcI5UG95INhumH9C8wlMmy1G2q8Su0VXMcJ8j2M/Ku6JPeYfTWn/XLEHxForzqB/Lk7ptlGbAcX/uUG7XdQmjfkkTrcR74SPJN4JZ1DaP6I/+qmppv9dvwAi4ZPfWyn9RwAAAABJRU5ErkJggg==>

[image3]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADsAAAAYCAYAAABEHYUrAAACq0lEQVR4Xu2WS6hOURTH//II1yOP6EZ5hCgykIHnhJQrJhSSoZArIomJWxgwIVESYUApXQPPMLgykYEMyIRCIiQTKfL6/7+1l2+ffc8x+3S+2/nXr/udvfZedz/WWnsDlSpVambNJa/J74gv5G34/ZNcJ1N8QKRJ5DGyY9X/EmmJ+pVOx8hXMjtpn0xekGdkbGJzrYAtVD5Kr0GkizwlI7Omms7DFrM8NQQdhNm16NJrInlHzpJeic034huZkzXV5HaNl5/Sy8NwY2qgVsPy8Djpk9gk36i7KHmeuhSGOrmlpDUwjuwj78la0vtv76x8o+Sj9PIw/AgL41OBM7AcPkCGeOcceb5qo0qvf+XreFglfkRGZU019ah8lbwS551c0+Vr0f0qDSC3yC+yOLFJTZmvRffrAljhug3rm6rofp1ALpJVZB7sRXWUjCF7yE2yEvW0UfFrI+cC/nhRu/p1kvWw155uhCL/Q21YvqaRT+QCsvmqf6Kw/UyewCpzqqJ8lZ+tZAl5jvrdrHTQIjUhvcruk9GkLzlBdsHGKsI2wBal9vbQvpdcDv2L/Oc+enRir5B9z76BvZH19wd5CXOqUI6lN7IK1nfUx+strQ0bCJukFqMa4EVPG3ODzIdJf/WtdqXHB7KJbCanYSerRTyEbYikdNuBYv+KvrxUa7g0AU1kXfjWyeskFcZSR0DaTa7ATiyW2j3i0s1K/U8n95Cfig3XMHKHzArfyumrpH+wdcHyT5GzHRaCLoX5VNhihaTFPICd9hp0969+qh+LyMLQ9t80E3YSXjA6UJ+42q6R/WRZ+NYDRmG8hRwiw8kMWI6q/STsejsMqzOp/53kCNmG7hHScKnAKX9dmkD83NR3fC8rLEfATj6WxgwOvzWmX9Qe+5fkLy6ylSr1FP0BrC2Ya8SL+eAAAAAASUVORK5CYII=>

[image4]: <data:image/png;base64,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>

[image5]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAmwAAAAmCAYAAAB5yccGAAAFQ0lEQVR4Xu3dW6htUxzH8b9QFAlFQkquuXaEiEiceCC5RFEe1CFJuaekHSlRkltCOR54QCSUS7FE5PJCpEThgSgpRbkb38YcrbHGuuy1srcz9znfT/0787bXZc6H9es/xpwnQpIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZKkTe6mVP+k+rbdMcGhqb6IfPzS6C5JkiStlp0iBzCK5eVsleqUVJ+1OyRJktaqbVOdHTnosNxH56b6q6t57ROjAe/IVI9V64tan+rkbnme4LhSuCbnxfC990u1TaqrywGSJKm/6Djd3i0fkerrGA0SbPs58o87to/xwPN5qkO65dtS/VLt65vSaSN0LRosCaNLzbZBqqOabcelOrDZ9mrkc1MwNMvrrZQ/quV1kd9vh8hdwudT7VXtfyfVOd0yw797V/skSVIPEV7OqNYfb9b5YeeYGuvbdcsEoCurfUenerda76OfIn+Ha9sdyyDcUDXO1wnVOiHwoWq9+DTV7tX6E9Xyf7Vjqi+rdYLa36lOTfV7jAfTy1Id3C0TxJeGuyRJUt/smeqlGIYvOkO/Rf7BLwYxGgb4ga8D3JmpXk+1S7fOvwy39RkBpsxn27XZNwvnqnVNqhur9Wdj/PtzPulKXlBtO7xarj3XrN+S6vpmW+usyJ+j4Dq+F/m1SietxjWr0VUlaEuSpB4iaHwcOZT9meqwGB+mI9R8mOrhGIa3resDkh9iGIDaMLAavplRL1fHzXJi5HBKkGJu2zy+bzdE7q7RLeO8MSxch90ax5RzRE07Dq9EnjtHWGuvR4vXGUR+fa4RHT+Ge7m2bWd0mkGMhk5JktQjdIz27ZaPTXVPjAcEhtbOT7VH5G5Uu79guO+TGHbs7oocAvuK73FD5FAzz6M+QCBsMcdvEDk4PTK6awydPUIVw5QMV07DjQ10LZfrrIGhzR8jBzyuEQWC2yKBrcxjlCRJPUMYKwhuH6TaudpGGKiHTFsMj5bAB0LLM912Ok9vVvtWUgkmk2q36rh50B0kuM1jUmBj/th3qU6K6e99c7NOF7Ke99Yi7BLWJg3Btu6N0etYEMAmBTaC6mnNtkHYYZMkqbfqH3Q6PoMYHapj/tOsH3LmwJXJ62DuVpkzxcR2wgQYcmRu1/GR57jdF7nbdGHkv+eOyhcjB4kNkSft04kqd6a2eDzFtKpvmFhO6Xi1k/KnmdSJI8z+GvnOy2nKeQCBibtFpw2J8lkIaxzHuaFzNstbqb5qN0Z+fAfDvW1HlE5q+30J6vUcOEmS1AOvRR6WI7A9EHlOGsGAyec8S40huY3dfn70p3XKCBZ01OhQXRWjweSNyIGDCfDl7khCwf6RJ8kTxhj2I+TdHTmknZ7qgFRvx/Su3krhzlbCziKYGzYJQa690aAg1PK9N6a6JPLdonTjpuE81njdW5ttBdeLa0Rd2uxDeQTLFZGvEdeLbS0+E59TkiRtYQhvdLtKh47HYRDe6Cy9ELnzc1HkUMdQJuvrInfmHu3+ZrUc09WimMNHqNyc8J24AUOSJG2Bnozc1eHO08sjd9DujBzM6PQsRZ6wz/odkYdJeQAtQ5QMla6mj9oNM/D56uenPR2Tu1Rr1cUxPkQqSZK2cA+muj/VU+2O/wEP+WU4uJ3XNUt7owHh5rpm21rFDRP1/4AgSZK0STFP7/1UB8X4naWlCC/rI8/rK3PDps1bkyRJ0gorz1xbtDa3OWuSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSpLXhX+5u3Fai3mJ2AAAAAElFTkSuQmCC>

[image6]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB0AAAAYCAYAAAAGXva8AAAB1ElEQVR4Xu2VTSilURjH/xo0E6WkkVhcHyVZSZMFNpONBcmWncVsZKGQ2UkWVvKxmmZBiiYmK1spC1ZWipRQakpZsqDM/P/vc4857/G+3C3dX/0W9zzPvefrec4F8rxBimgz7aMZWpAdq3cJFXSP/vW8p10ugRTT9SBn3Iv7fKXndIEO0A36m/6i37y8iB7Yj62EgSwf6Br9Dlt1Er30FLZLh3Y5TW9pqzceoQEFNmlhEBNtdJV+CgNZyugBHQ4D5Avdh51qjDr6h+7S0ngommiZtgTjPh30gfaHAdiG5mG7jlFJz+glrQpig3QKCV/ycNezQ8uDmD43BGMR2t0uvaFN3niGbtHP3lgStfQK/wvthM4gZTKH7lH3eQe7A6GdzcIKJBe66TWed4JOIZWfsESX1EmXkF6taeiqhugR7Pe26cdYhscELGkUVo3qzRePJ0sNLQkHYZMfI7k4n1DlaVLdhSZ+1swJ6FoWYdUf4uokrQ0j9Ao9wlannkxdnUc1rD/94nPolC6Q3EZPuAdC6jHIBdefk4i3lHpbNfIDr9SE+lN9qmfrpZ70GaNzsCM8hL3JI7DT0vubdNcxtKJ25JDo0Qj7nhaZgf2zqPpVRHnyvDP+AaB2VIaLWbmDAAAAAElFTkSuQmCC>

[image7]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABwAAAAYCAYAAADpnJ2CAAABsklEQVR4Xu2VzStFQRiHX6EoH8lComxsRCkLUtQlHwuxkJ0sZKEsCSUbCysWkpWULOyULGywOFFKyn+g2FCEjQ3y8fv1ztzOnTvnXCl1F/epp+6Zd87MvPPOnCuSI8sphI1wBCZgkWnPg/Uw3zwn6YL38DvkM3wwv1/hGiyzLxj4vA7fYQCX4DK8ggNwTvS9SLbgB+xw2ltEJz+CJaatGz7CA1hr2iyV8Fx0scNOLEkpPIPXsMqJcZIAfsEe0UGY1abodvqYhE+wwQ1YGGCHPVjgxCrgpWj2Y6KZncLycCeHQdEEmIiXIdEtmHYDoB2+wQu4L5pp5FYZOCHrGwmDvvoxixPRrMZFJ2a2zDoOnlRb7zRsjTjYrmht6A68g9uiB2NedBdiV/4bbP2OYR2sDmnvFOECOOFoqO1P2PotuAEHOyHrE0cznHEbw3CL7JGPg5c604T8uizCXjdgsffvBtakhtJIwE+4ITqwjza4KtH3U5rgCzyU1Hr54CA8TOzv7gYX0C966Lz3sxPeSvr3cyLcyUMxXBHNNIBTot9M7tKsif8LzKJP9B+iVTLvTo4cWc4P47dZ/Jd6WXAAAAAASUVORK5CYII=>