.PHONY: help build test lint run-server run-worker up down logs psql clean

GO      ?= go
BACKEND := backend

help: ## Show available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

build: ## Compile both binaries
	cd $(BACKEND) && $(GO) build ./...

test: ## Run the test suite (database tests skip without TEST_DATABASE_URL)
	cd $(BACKEND) && $(GO) test ./... -race

test-integration: ## Run every test against the compose database
	docker compose up -d postgres
	cd $(BACKEND) && TEST_DATABASE_URL='postgres://sbomdelta:sbomdelta@localhost:5432/sbomdelta?sslmode=disable' \
		$(GO) test ./... -race -count=1

lint: ## Vet and check formatting
	cd $(BACKEND) && $(GO) vet ./...
	@cd $(BACKEND) && test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }

run-server: ## Run the API server against the compose stack
	cd $(BACKEND) && $(GO) run ./cmd/server

run-worker: ## Run a scan worker against the compose stack
	cd $(BACKEND) && $(GO) run ./cmd/worker

up: ## Start the full stack in Docker
	docker compose up --build -d
	@echo "API      http://localhost:8080/healthz"
	@echo "MinIO    http://localhost:9001 (minioadmin / minioadmin)"

down: ## Stop the stack
	docker compose down

logs: ## Tail server and worker logs
	docker compose logs -f server worker

psql: ## Open a shell on the development database
	docker compose exec postgres psql -U sbomdelta -d sbomdelta

clean: ## Stop the stack and delete its volumes
	docker compose down -v
