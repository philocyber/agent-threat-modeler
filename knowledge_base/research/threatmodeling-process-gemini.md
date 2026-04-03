# **El Modelado de Amenazas: Un Proceso Estratégico para la Seguridad por Diseño**

El modelado de amenazas es un proceso estratégico orientado a considerar posibles escenarios de ataque y vulnerabilidades dentro de un entorno de aplicación (existente o propuesto) con el fin de identificar niveles de riesgo e impacto.1 En lugar de ser un control aislado, se define como un proceso colaborativo que revitaliza los esfuerzos de seguridad de datos al integrar a múltiples partes interesadas —desde administradores de bases de datos hasta objetivos de negocio— en una reacción en cadena de eventos tácticos.1

A diferencia de las auditorías de seguridad, que se centran en lo que alguien encontró en un momento determinado, el modelado de amenazas busca un enfoque proactivo, identificando fallas en el diseño antes de que se escriba una sola línea de código, lo que reduce drásticamente los costos de remediación post-implementación.1

## **El Marco de las Cuatro Preguntas Fundamentales**

La industria, liderada por figuras como Adam Shostack, ha convergido en un marco simplificado de cuatro preguntas para estructurar cualquier ejercicio de modelado de amenazas 2:

1. **¿Qué estamos construyendo?** Implica crear un modelo o abstracción del sistema que se va a analizar.  
2. **¿Qué puede salir mal?** Es la fase de identificación y enumeración de amenazas contra ese modelo.  
3. **¿Qué vamos a hacer al respecto?** Se refiere a la definición de mitigaciones, contramedidas o la aceptación del riesgo.  
4. **¿Hicimos un buen trabajo?** Una fase de validación y retrospectiva para asegurar que el análisis fue completo y efectivo.

Este ciclo permite descomponer sistemas complejos en partes manejables, asegurando que la seguridad no sea un pensamiento de último momento.1

## **Modelado del Sistema: Diagramas de Flujo de Datos (DFD)**

La base técnica del modelado de amenazas es la creación de una representación visual del sistema. Los Diagramas de Flujo de Datos (DFD) son la herramienta estándar para este propósito, ya que permiten visualizar cómo se gestionan los datos, dónde entran, salen y se procesan.1

### **Elementos Clave de un DFD de Seguridad**

Un DFD típico para modelado de amenazas se compone de elementos específicos que deben ser analizados individualmente 3:

* **Entidades Externas:** Actores (humanos o sistemas) fuera del control directo de la aplicación que interactúan con ella.  
* **Procesos:** Cualquier pieza de código o servicio que realiza una acción sobre los datos.  
* **Flujos de Datos:** Los canales por los cuales viaja la información (redes, memorias compartidas, llamadas RPC).  
* **Almacenes de Datos:** Datos en reposo, como bases de datos, archivos de registro (logs) o sistemas de archivos.  
* **Límites de Confianza (Trust Boundaries):** El elemento más crítico en seguridad. Representan puntos donde el nivel de privilegio o el control sobre los datos cambia (por ejemplo, entre la red pública e interna, o entre diferentes cuentas de usuario).1

## **Metodologías de Enumeración y Categorización**

Existen múltiples enfoques para identificar amenazas, cada uno con fortalezas dependiendo del tipo de organización y el objetivo del análisis.1

| Metodología | Enfoque Principal | Características |
| :---- | :---- | :---- |
| **STRIDE** | Centrado en el Software | Categoriza amenazas en: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service y Elevation of Privilege.1 |
| **PASTA** | Centrado en el Riesgo | Proceso de 7 etapas que alinea los objetivos de negocio con los requisitos técnicos de seguridad y simulaciones de ataque.2 |
| **OCTAVE** | Centrado en la Organización | Se enfoca en riesgos organizacionales, activos críticos y la evaluación de vulnerabilidades operativas.1 |
| **LINDDUN** | Centrado en la Privacidad | Utiliza un acrónimo para identificar amenazas de privacidad: Linkability, Identifiability, Non-repudiation, Detectability, Disclosure, Unawareness, Non-compliance.5 |
| **TRIKE** | Centrado en la Defensa | Enfoque basado en la gestión de riesgos y auditoría desde la perspectiva de la defensa del sistema.6 |

### **El modelo STRIDE**

STRIDE es la metodología más madura y utilizada.1 Su valor reside en que permite a ingenieros con conocimientos mínimos de seguridad encontrar amenazas importantes mediante un proceso de "STRIDE por elemento", donde cada componente del DFD se somete a las seis preguntas de la categoría.7

## **Análisis de Riesgo y Priorización**

Una vez identificadas las amenazas, es crucial cuantificarlas para decidir qué mitigar primero. Tradicionalmente se ha utilizado el modelo **DREAD** (Damage, Reproducibility, Exploitability, Affected users, Discoverability), aunque su uso ha disminuido en favor de sistemas más consistentes como **CVSS** (Common Vulnerability Scoring System).1

La gestión del riesgo se resume en cuatro estrategias clásicas 1:

1. **Mitigar:** Cambiar el diseño o añadir controles (como criptografía o autenticación avanzada).  
2. **Aceptar:** Reconocer el riesgo por razones de negocio, a menudo documentándolo en guías de operaciones de seguridad.8  
3. **Transferir:** Pasar el riesgo a un tercero (por ejemplo, mediante seguros o delegando servicios a un proveedor de nube).  
4. **Evitar:** Eliminar la funcionalidad que causa la amenaza.

## **El Rol de los Árboles de Ataque (Attack Trees)**

Los árboles de ataque proporcionan una forma estructurada y jerárquica de pensar en las metas de un atacante.1 Un nodo raíz representa el objetivo final del atacante (por ejemplo, "Leer datos confidenciales de la DB"), y las ramas representan los diferentes caminos o combinaciones de pasos necesarios para alcanzarlo.9 Esta técnica ayuda a visualizar ataques de múltiples etapas y a identificar puntos únicos de falla en los controles de seguridad.9

## **Integración en el Ciclo de Vida de Desarrollo (SDLC)**

Para que el modelado de amenazas sea efectivo, no puede ser una actividad de una sola vez. Debe integrarse de las siguientes formas 2:

* **Temprano:** Durante la fase de requisitos para clarificar qué se necesita proteger realmente.1  
* **Continuo:** Adoptando enfoques como "Threat Model Every Story", donde cada nueva funcionalidad en un entorno Ágil es analizada en términos de su impacto en el modelo existente.4  
* **Basado en Bugs:** Las amenazas identificadas deben convertirse en tickets dentro del sistema de gestión de errores (backlog) de la organización para asegurar que sean rastreadas y resueltas como cualquier otro defecto de software.1

## **Conclusiones del Proceso**

El éxito de un modelo de amenazas no se mide por la "perfección" o la exhaustividad total, sino por su utilidad para el equipo de desarrollo.1 Un buen modelo es aquel que permite a los defensores anticipar ataques, mejorar la arquitectura y tomar decisiones de compromiso (trade-offs) informadas, transformando la seguridad de un obstáculo en una propiedad intrínseca del sistema.1

#### **Fuentes citadas**

1. Threat Modeling \- Shostack, Adam.pdf  
2. What is threat modeling? \- GitHub, acceso: febrero 24, 2026, [https://github.com/resources/articles/what-is-threat-modeling](https://github.com/resources/articles/what-is-threat-modeling)  
3. Uncover Security Design Flaws Using The STRIDE Approach | Microsoft Learn, acceso: febrero 24, 2026, [https://learn.microsoft.com/en-us/archive/msdn-magazine/2006/november/uncover-security-design-flaws-using-the-stride-approach](https://learn.microsoft.com/en-us/archive/msdn-magazine/2006/november/uncover-security-design-flaws-using-the-stride-approach)  
4. Threat Modeling Process \- OWASP Foundation, acceso: febrero 24, 2026, [https://owasp.org/www-community/Threat\_Modeling\_Process](https://owasp.org/www-community/Threat_Modeling_Process)  
5. Resources Archive \- OWASP Gen AI Security Project, acceso: febrero 24, 2026, [https://genai.owasp.org/resources/?e-filter-3b7adda-initiative\_name=agentic-security](https://genai.owasp.org/resources/?e-filter-3b7adda-initiative_name=agentic-security)  
6. 5 Threat Modeling Methodologies | Pros & Use Cases Explained \- IriusRisk, acceso: febrero 24, 2026, [https://www.iriusrisk.com/threat-modeling-methodologies](https://www.iriusrisk.com/threat-modeling-methodologies)  
7. Threat modeling STRIDE methodology \- IriusRisk, acceso: febrero 24, 2026, [https://www.iriusrisk.com/resources-blog/threat-modeling-methodology-stride](https://www.iriusrisk.com/resources-blog/threat-modeling-methodology-stride)  
8. What Is STRIDE Threat Model? Limitations & Modern Adaptations \- Apiiro, acceso: febrero 24, 2026, [https://apiiro.com/glossary/stride-threat-model/](https://apiiro.com/glossary/stride-threat-model/)  
9. Threat modeling agentic AI: a scenario-driven approach, acceso: febrero 24, 2026, [https://christian-schneider.net/blog/threat-modeling-agentic-ai/](https://christian-schneider.net/blog/threat-modeling-agentic-ai/)  
10. Agentic AI Security – Part 2: Threat Modeling \- REBELADMIN, acceso: febrero 24, 2026, [https://www.rebeladmin.com/agentic-ai-threat-modeling/](https://www.rebeladmin.com/agentic-ai-threat-modeling/)