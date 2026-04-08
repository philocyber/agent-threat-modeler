"""AgenticTM agents.

Agent architecture (1 per methodology + debate + AI specialist):

Phase I  — Ingestion:
    1. Architecture Parser    → parses input → structured SystemModel

Phase II — Methodology Analysts (parallel):
    2. STRIDE Analyst         → STRIDE-per-element
    3. PASTA Analyst          → business-risk + attack simulation
    4. Attack Tree Analyst    → attack goal decomposition
    5. MAESTRO Analyst        → AI/Agentic threats (conditional, MAESTRO framework)
    6. AI Threat Analyst      → AI threats (PLOT4ai + OWASP LLM/Agentic + MAESTRO)

Phase III — Debate & Synthesis:
    7. Red Team Debater       → argues severity, finds gaps
    8. Blue Team Debater      → argues defenses, proposes mitigations
    9. Threat Synthesizer     → combines best of each methodology, DREAD scores

Phase IV — Output:
   10. Report Generator       → CSV + Markdown
"""
