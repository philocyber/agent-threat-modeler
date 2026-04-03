# Security Policy

## Supported deployment model

AgenticTM is designed as a local-first tool. Before exposing it to any shared or public network, you should:

- set `AGENTICTM_API_KEY`
- restrict `AGENTICTM_CORS_ORIGINS`
- avoid binding to non-local interfaces unless you have a reverse proxy and access controls

## Reporting a vulnerability

Please do not open a public issue for sensitive security reports.

- Email: `security@philocyber.com`
- Subject: `AgenticTM security report`

Include:

- affected version or commit
- reproduction steps
- impact assessment
- suggested mitigation if available

## Sensitive data hygiene

Do not commit:

- customer threat models
- generated `rag/` artifacts
- local IDE logs
- `config.json`, `.env`, API keys, or credentials
