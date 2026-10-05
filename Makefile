.DEFAULT_GOAL := help
SHELL := /bin/bash
COMPOSE := docker compose
BASE_URL ?= http://localhost:8080

.PHONY: help up down logs ps migrate seed harden test attack detect clean
DATABASE_URL ?= postgres://bazaar:bazaar@127.0.0.1:5432/bazaar?sslmode=disable

help: ## Show this help
	@echo "BrokenBazaar — deliberately vulnerable. Localhost only."
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

up: ## Start the stack (vulnerable mode)
	HARDENED=false $(COMPOSE) up -d --build
	@$(MAKE) --no-print-directory wait
	@echo ""
	@echo "  BrokenBazaar is up (VULNERABLE mode) -> $(BASE_URL)/healthz"
	@echo "  Switch with: make harden"

harden: ## Restart the stack with every defense enabled
	HARDENED=true $(COMPOSE) up -d --build
	@$(MAKE) --no-print-directory wait
	@echo ""
	@echo "  BrokenBazaar is up (HARDENED mode) -> $(BASE_URL)/healthz"

wait: ## Block until the API answers /healthz
	@echo -n "  waiting for api "
	@for i in $$(seq 1 60); do \
		if curl -fsS $(BASE_URL)/healthz >/dev/null 2>&1; then echo " ok"; exit 0; fi; \
		echo -n "."; sleep 1; \
	done; \
	echo " FAILED"; $(COMPOSE) logs --tail=40 api; exit 1

down: ## Stop the stack and remove volumes
	$(COMPOSE) down -v

logs: ## Tail all logs
	$(COMPOSE) logs -f --tail=100

ps: ## Show stack status
	$(COMPOSE) ps

migrate: ## Apply SQL schema migrations against the stack's Postgres  (M1)
	cd app && DATABASE_URL=$(DATABASE_URL) go run ./cmd/migrate

seed: ## Seed orgs, users and documents  (M1)
	cd app && DATABASE_URL=$(DATABASE_URL) go run ./cmd/seed

test: ## Run unit + policy tests  (M1+)
	@echo "  not yet implemented — arrives with M1"

attack: ## Run the full attack suite in both modes  (M1+)
	@echo "  not yet implemented — arrives with M1"
	@echo "  contract: attacks/NN-name/exploit.py --base-url $(BASE_URL)"

detect: ## Replay PoCs and measure detect vs. miss  (M1+)
	@echo "  not yet implemented — arrives with M1"

clean: down ## Stop everything and prune build cache
	docker builder prune -f
