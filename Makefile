SHELL        := /bin/zsh
.DEFAULT_GOAL := help

PYTHON       := python3
VENV         := .venv
PIP          := $(VENV)/bin/pip
PY           := $(VENV)/bin/python
PORT         := 8000
OLLAMA_URL   := http://localhost:11434

MODEL        ?= qwen3.5:4b

MODEL_EMBED  := nomic-embed-text

_GREEN  := \033[32m
_CYAN   := \033[36m
_YELLOW := \033[33m
_RED    := \033[31m
_BOLD   := \033[1m
_RESET  := \033[0m

.PHONY: help all setup check-macos brew ollama ollama-start \
        models venv pip init index run dev \
        status clean nuke

help: ## Show this help
	@echo ""
	@echo "$(_BOLD)AgenticTM$(_RESET) — Makefile targets"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(_CYAN)%-16s$(_RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(_BOLD)Quick start:$(_RESET)"
	@echo "  $(_GREEN)make all$(_RESET)                  Full setup + start server (asks which model)"
	@echo "  $(_GREEN)make setup$(_RESET)                Setup only (asks which model)"
	@echo "  $(_GREEN)make setup MODEL=qwen3.5:9b$(_RESET) Setup with a specific model (no prompt)"
	@echo "  $(_GREEN)make run$(_RESET)                   Start server (after setup)"
	@echo ""
	@echo "$(_BOLD)Available Qwen3.5 models:$(_RESET)"
	@echo "  $(_CYAN)qwen3.5:4b$(_RESET)   ~3.4 GB   Light  $(_GREEN)(default — ideal for Fast demos)$(_RESET)"
	@echo "  $(_CYAN)qwen3.5:9b$(_RESET)   ~6.6 GB   Standard"
	@echo "  $(_CYAN)qwen3.5:14b$(_RESET)  ~9 GB     Medium"
	@echo "  $(_CYAN)qwen3.5:27b$(_RESET)  ~17 GB    Large"
	@echo "  $(_CYAN)qwen3.5:32b$(_RESET)  ~19 GB    Large dense"
	@echo "  $(_CYAN)qwen3.5:72b$(_RESET)  ~45 GB    Extra large"
	@echo ""

all: setup run ## Full setup + start server

setup: check-macos brew ollama ollama-start models venv pip init index ## Complete setup
	@echo ""
	@echo "$(_GREEN)$(_BOLD)✓ Setup complete!$(_RESET) (model: $(MODEL))"
	@echo "  Run $(_CYAN)make run$(_RESET) to start the server"
	@echo "  Then open $(_CYAN)http://localhost:$(PORT)$(_RESET)"

check-macos: ## Verify running on macOS
	@if [ "$$(uname)" != "Darwin" ]; then \
		echo "$(_RED)Error: This Makefile is designed for macOS.$(_RESET)"; \
		exit 1; \
	fi
	@echo "$(_GREEN)✓$(_RESET) macOS detected ($$(sw_vers -productVersion))"

brew: ## Install Homebrew if missing
	@if command -v brew >/dev/null 2>&1; then \
		echo "$(_GREEN)✓$(_RESET) Homebrew already installed"; \
	else \
		echo "$(_CYAN)→$(_RESET) Installing Homebrew..."; \
		/bin/bash -c "$$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"; \
	fi

ollama: brew ## Install Ollama via Homebrew if missing
	@if command -v ollama >/dev/null 2>&1; then \
		echo "$(_GREEN)✓$(_RESET) Ollama already installed ($$(ollama --version 2>/dev/null || echo 'unknown'))"; \
	else \
		echo "$(_CYAN)→$(_RESET) Installing Ollama..."; \
		brew install ollama; \
	fi

ollama-start: ollama ## Start Ollama service
	@if curl -sf $(OLLAMA_URL)/api/tags >/dev/null 2>&1; then \
		echo "$(_GREEN)✓$(_RESET) Ollama is already running"; \
	else \
		echo "$(_CYAN)→$(_RESET) Starting Ollama service..."; \
		brew services start ollama 2>/dev/null || ollama serve &>/dev/null & \
		echo "  Waiting for Ollama to be ready..."; \
		for i in $$(seq 1 30); do \
			if curl -sf $(OLLAMA_URL)/api/tags >/dev/null 2>&1; then \
				echo "$(_GREEN)✓$(_RESET) Ollama is ready"; \
				break; \
			fi; \
			sleep 1; \
			if [ $$i -eq 30 ]; then \
				echo "$(_RED)✗ Ollama did not start after 30s. Try manually: ollama serve$(_RESET)"; \
				exit 1; \
			fi; \
		done; \
	fi

models: ollama-start ## Pull the selected model + embeddings (interactive)
	@if [ "$(MODEL)" = "qwen3.5:4b" ] && [ -z "$(MAKEFLAGS:M--no-print-directory=)" ]; then \
		echo ""; \
		echo "$(_BOLD)¿Qué modelo Qwen3.5 querés usar?$(_RESET)"; \
		echo ""; \
		echo "  1) qwen3.5:4b   ~3.4 GB   Light $(_GREEN)(default)$(_RESET)"; \
		echo "  2) qwen3.5:9b   ~6.6 GB   Standard"; \
		echo "  3) qwen3.5:14b  ~9 GB     Medium"; \
		echo "  4) qwen3.5:27b  ~17 GB    Large"; \
		echo "  5) qwen3.5:32b  ~19 GB    Large dense"; \
		echo "  6) qwen3.5:72b  ~45 GB    Extra large"; \
		echo ""; \
		printf "  Elegí [1-6] (default: 1): "; \
		read choice; \
		case "$$choice" in \
			2) selected="qwen3.5:9b" ;; \
			3) selected="qwen3.5:14b" ;; \
			4) selected="qwen3.5:27b" ;; \
			5) selected="qwen3.5:32b" ;; \
			6) selected="qwen3.5:72b" ;; \
			*) selected="qwen3.5:4b" ;; \
		esac; \
		echo ""; \
		echo "$(_CYAN)→$(_RESET) Pulling $$selected..."; \
		ollama pull $$selected; \
		echo "$(_GREEN)✓$(_RESET) $$selected ready"; \
	else \
		echo "$(_CYAN)→$(_RESET) Pulling $(MODEL)..."; \
		ollama pull $(MODEL); \
		echo "$(_GREEN)✓$(_RESET) $(MODEL) ready"; \
	fi
	@echo "$(_CYAN)→$(_RESET) Pulling $(MODEL_EMBED) (embeddings for RAG)..."
	@ollama pull $(MODEL_EMBED)
	@echo "$(_GREEN)✓$(_RESET) $(MODEL_EMBED) ready"

venv: ## Create Python virtual environment
	@if [ -d "$(VENV)" ]; then \
		echo "$(_GREEN)✓$(_RESET) Virtual environment already exists"; \
	else \
		echo "$(_CYAN)→$(_RESET) Creating virtual environment..."; \
		$(PYTHON) -m venv $(VENV); \
		echo "$(_GREEN)✓$(_RESET) Virtual environment created at $(VENV)/"; \
	fi

pip: venv ## Install Python dependencies
	@echo "$(_CYAN)→$(_RESET) Installing Python dependencies..."
	@$(PIP) install --upgrade pip -q
	@$(PIP) install -r requirements.txt -q
	@echo "$(_GREEN)✓$(_RESET) Python dependencies installed"

init: pip ## Initialize project structure and config
	@echo "$(_CYAN)→$(_RESET) Initializing project structure..."
	@$(PY) cli.py init
	@echo "$(_GREEN)✓$(_RESET) Project initialized"

index: init ## Index the knowledge base for RAG
	@if curl -sf $(OLLAMA_URL)/api/tags >/dev/null 2>&1; then \
		echo "$(_CYAN)→$(_RESET) Indexing knowledge base (this may take a few minutes)..."; \
		$(PY) cli.py index || echo "$(_YELLOW)⚠ Indexing had issues — analysis will still work but without RAG context$(_RESET)"; \
	else \
		echo "$(_YELLOW)⚠$(_RESET) Ollama not running — skipping index. Run 'make index' later."; \
	fi

run: venv ollama-start ## Start the AgenticTM server
	@echo ""
	@echo "$(_BOLD)Starting AgenticTM server...$(_RESET)"
	@echo "  UI:  $(_CYAN)http://localhost:$(PORT)$(_RESET)"
	@echo "  API: $(_CYAN)http://localhost:$(PORT)/api/health$(_RESET)"
	@echo ""
	@$(PY) run.py --port $(PORT)

dev: venv ollama-start ## Start server in dev mode (auto-reload)
	@echo ""
	@echo "$(_BOLD)Starting AgenticTM server (dev mode)...$(_RESET)"
	@echo "  UI:  $(_CYAN)http://localhost:$(PORT)$(_RESET)"
	@echo ""
	@$(PY) run.py --port $(PORT) --reload

status: ## Check status of all dependencies
	@echo ""
	@echo "$(_BOLD)AgenticTM Status$(_RESET)"
	@echo "─────────────────────────────────────────"
	@if [ -f "$(PY)" ]; then \
		echo "$(_GREEN)✓$(_RESET) Python venv     $$($(PY) --version)"; \
	else \
		echo "$(_RED)✗$(_RESET) Python venv     not created (run: make venv)"; \
	fi
	@if [ -f "$(PY)" ] && $(PY) -c "import fastapi" 2>/dev/null; then \
		echo "$(_GREEN)✓$(_RESET) Python deps     installed"; \
	else \
		echo "$(_RED)✗$(_RESET) Python deps     not installed (run: make pip)"; \
	fi
	@if command -v ollama >/dev/null 2>&1; then \
		echo "$(_GREEN)✓$(_RESET) Ollama binary   installed"; \
	else \
		echo "$(_RED)✗$(_RESET) Ollama binary   not found (run: make ollama)"; \
	fi
	@if curl -sf $(OLLAMA_URL)/api/tags >/dev/null 2>&1; then \
		echo "$(_GREEN)✓$(_RESET) Ollama service  running at $(OLLAMA_URL)"; \
	else \
		echo "$(_RED)✗$(_RESET) Ollama service  not running (run: make ollama-start)"; \
	fi
	@echo "─────────────────────────────────────────"
	@echo "$(_BOLD)Installed models:$(_RESET)"
	@if command -v ollama >/dev/null 2>&1 && curl -sf $(OLLAMA_URL)/api/tags >/dev/null 2>&1; then \
		ollama list 2>/dev/null | tail -n +2 | while read -r name rest; do \
			echo "  $(_GREEN)✓$(_RESET) $$name"; \
		done; \
		if [ $$(ollama list 2>/dev/null | tail -n +2 | wc -l) -eq 0 ]; then \
			echo "  $(_YELLOW)⚠ No models installed (run: make models)$(_RESET)"; \
		fi; \
	else \
		echo "  $(_YELLOW)⚠ Cannot check models — Ollama not available$(_RESET)"; \
	fi
	@echo "─────────────────────────────────────────"
	@if curl -sf http://localhost:$(PORT)/api/health >/dev/null 2>&1; then \
		echo "$(_GREEN)✓$(_RESET) AgenticTM       running at http://localhost:$(PORT)"; \
	else \
		echo "  AgenticTM       not running (run: make run)"; \
	fi
	@echo ""

clean: ## Remove Python cache files
	@echo "$(_CYAN)→$(_RESET) Cleaning cache files..."
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@echo "$(_GREEN)✓$(_RESET) Cache cleaned"

nuke: clean ## Remove venv + data (keeps knowledge_base & config)
	@echo "$(_YELLOW)This will remove:$(_RESET)"
	@echo "  - $(VENV)/ (virtual environment)"
	@echo "  - data/ (vector stores, results DB)"
	@echo ""
	@read -q "REPLY?Are you sure? [y/N] " || (echo "" && exit 1)
	@echo ""
	@rm -rf $(VENV)
	@rm -rf data/
	@echo "$(_GREEN)✓$(_RESET) Nuked. Run 'make setup' to rebuild."
