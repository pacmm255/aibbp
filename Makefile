.PHONY: build test lint docker-build migrate clean help

# Go binaries
GO_CMD=go
GO_BUILD=$(GO_CMD) build
GO_TEST=$(GO_CMD) test
GO_LINT=golangci-lint

# Python
PY=python3
PIP=pip3

# Docker
DOCKER_COMPOSE=docker compose

# Binary output
BIN_DIR=bin

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ── Build ─────────────────────────────────────────────────────────────

build: build-scanner build-preprocessor build-cli ## Build all Go binaries

build-scanner: ## Build scanner worker
	$(GO_BUILD) -o $(BIN_DIR)/scanner ./cmd/scanner

build-preprocessor: ## Build preprocessor worker
	$(GO_BUILD) -o $(BIN_DIR)/preprocessor ./cmd/preprocessor

build-cli: ## Build CLI
	$(GO_BUILD) -o $(BIN_DIR)/aibbp ./cmd/cli

# ── Test ──────────────────────────────────────────────────────────────

test: test-go test-python ## Run all tests

test-go: ## Run Go tests
	$(GO_TEST) -race -cover ./...

test-python: ## Run Python tests
	$(PY) -m pytest tests/python/ -v --cov=ai_brain --cov-report=term-missing

# ── Lint ──────────────────────────────────────────────────────────────

lint: lint-go lint-python ## Run all linters

lint-go: ## Lint Go code
	$(GO_LINT) run ./...

lint-python: ## Lint Python code
	$(PY) -m ruff check ai_brain/ tests/python/
	$(PY) -m mypy ai_brain/

# ── Infrastructure ────────────────────────────────────────────────────

infra-up: ## Start infrastructure (PostgreSQL, Redis, NATS)
	$(DOCKER_COMPOSE) up -d postgres redis nats

infra-down: ## Stop infrastructure
	$(DOCKER_COMPOSE) down

# ── Database ──────────────────────────────────────────────────────────

migrate: ## Run database migrations
	$(GO_CMD) run ./cmd/cli migrate up

migrate-down: ## Rollback last migration
	$(GO_CMD) run ./cmd/cli migrate down

migrate-create: ## Create new migration (usage: make migrate-create NAME=description)
	migrate create -ext sql -dir migrations -seq $(NAME)

# ── Docker ────────────────────────────────────────────────────────────

docker-build: ## Build all Docker images
	$(DOCKER_COMPOSE) build

docker-up: ## Start all services
	$(DOCKER_COMPOSE) up -d

docker-down: ## Stop all services
	$(DOCKER_COMPOSE) down

docker-logs: ## Tail logs from all services
	$(DOCKER_COMPOSE) logs -f

# ── Python ────────────────────────────────────────────────────────────

py-install: ## Install Python dependencies
	$(PIP) install -e ".[dev]"

py-install-playwright: ## Install Playwright browsers
	$(PY) -m playwright install chromium

# ── Active Testing ───────────────────────────────────────────────────

active-test: ## Run scan with active testing enabled
	$(PY) -m ai_brain --active-test --program-file $(PROGRAM_FILE)

active-test-dry: ## Run active testing in dry-run mode (AI only, no real actions)
	$(PY) -m ai_brain --active-test --active-dry-run --program-file $(PROGRAM_FILE)

active-kill: ## Trigger active testing kill switch via Redis
	$(PY) -c "import redis; r=redis.Redis(); r.set('aibbp:kill_switch:global', 'manual'); print('Kill switch activated')"

docker-up-active: ## Start all services including active testing infrastructure
	$(DOCKER_COMPOSE) --profile active up -d

docker-build-active: ## Build active testing Docker images
	$(DOCKER_COMPOSE) --profile active build

# ── Clean ─────────────────────────────────────────────────────────────

clean: ## Remove build artifacts
	rm -rf $(BIN_DIR)/
	rm -rf __pycache__ .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
