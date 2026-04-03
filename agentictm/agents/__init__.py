"""Agentes de AgenticTM.

Arquitectura de agentes (1 por metodología + debate + AI specialist):

Phase I  — Ingestion:
    1. Architecture Parser    → parsea input → SystemModel estructurado

Phase II — Methodology Analysts (paralelo):
    2. STRIDE Analyst         → STRIDE-per-element
    3. PASTA Analyst          → business-risk + simulación de ataques
    4. Attack Tree Analyst    → descomposición de objetivos de ataque
    5. MAESTRO Analyst        → amenazas AI/Agentic (condicional, MAESTRO framework)
    6. AI Threat Analyst      → amenazas AI (PLOT4ai + OWASP LLM/Agentic + MAESTRO)

Phase III — Debate & Synthesis:
    7. Red Team Debater       → argumenta severidad, busca gaps
    8. Blue Team Debater      → argumenta defensas, propone mitigaciones
    9. Threat Synthesizer     → combina lo mejor de cada metodología, DREAD scores

Phase IV — Output:
   10. Report Generator       → CSV + Markdown
"""
