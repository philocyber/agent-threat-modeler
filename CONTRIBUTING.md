# Contributing to AgenticTM

Thank you for your interest in improving AgenticTM! This document explains how to get started, the workflow we follow, and what to expect during review.

## Code of Conduct

Be respectful, constructive, and inclusive. Cybersecurity is a serious domain; treat fellow contributors the way you would want to be treated during a code review.

## Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:

```bash
git clone https://github.com/<your-user>/agent-threat-modeler.git
cd agent-threat-modeler
```

3. **Create a branch** from `main`:

```bash
git checkout -b feat/my-improvement
```

4. **Set up the development environment** following the [README](README.md#quick-start).

## Development Workflow

### Branch Naming

| Prefix     | Purpose                          |
|------------|----------------------------------|
| `feat/`    | New feature or capability        |
| `fix/`     | Bug fix                          |
| `refactor/`| Code restructuring (no behavior change) |
| `docs/`    | Documentation only               |
| `test/`    | Adding or updating tests         |

### Commit Messages

Write clear, concise commit messages. Prefer present tense ("Add STRIDE keyword expansion") over past tense. Keep the first line under 72 characters and add a blank line before any extended description.

### Running Locally

```bash
# Start the backend (requires Ollama running)
make run
# or manually
python run.py
```

The web UI will be available at `http://localhost:8000`.

### Linting and Formatting

- Python: we recommend `ruff` for linting and formatting.
- JavaScript/HTML: keep formatting consistent with the existing codebase.

Run linting before committing:

```bash
ruff check agentictm/
ruff format agentictm/
```

## Submitting a Pull Request

1. Push your branch to your fork.
2. Open a Pull Request against `main` on the upstream repository.
3. Fill out the PR template (if one exists) or provide:
   - **Summary** of what changed and why.
   - **Test plan** describing how you verified the change.
4. Ensure CI passes.
5. A maintainer will review your PR. Be open to feedback and iterate.

## What We Look For in Reviews

- **Correctness**: Does the change do what it claims?
- **Security**: Threat modeling is a security tool. No hardcoded secrets, no debug telemetry, no data leakage.
- **Clarity**: Is the code readable without excessive comments?
- **Scope**: Small, focused PRs are easier to review and merge.

## Reporting Issues

Open an issue on [GitHub Issues](https://github.com/PhiloCyber/agent-threat-modeler/issues) with:

- A clear title and description.
- Steps to reproduce (if it's a bug).
- Expected vs. actual behavior.
- Environment details (OS, Python version, Ollama model).

## RAG / Knowledge Base Contributions

The `knowledge_base/` directory is **not tracked** in Git (only `.gitkeep` files are). If you want to suggest improvements to the RAG content or indexing strategy, open an issue describing the enhancement and the sources involved.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
