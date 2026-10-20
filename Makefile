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

test: ## Run the regression suite (attack harness, both modes)
	@echo "  attack harness (both modes) -- go unit tests arrive with M2"
	$(MAKE) --no-print-directory attack

attack: ## Run the full attack suite in both modes
	@echo "== VULNERABLE mode: every exploit must SUCCEED =="
	HARDENED=false $(COMPOSE) up -d --build
	@$(MAKE) --no-print-directory wait
	cd attacks && ./run.py --mode vulnerable --base-url $(BASE_URL)
	@echo ""
	@echo "== HARDENED mode: every exploit must be BLOCKED =="
	HARDENED=true $(COMPOSE) up -d --build
	@$(MAKE) --no-print-directory wait
	cd attacks && ./run.py --mode hardened --base-url $(BASE_URL)
	@echo ""
	@echo "attack suite: both modes behaved as their mode demands"

detect: ## Replay PoCs and measure detect vs. miss (both modes)
	@echo "== VULNERABLE mode: detection replay =="
	HARDENED=false $(COMPOSE) up -d --build
	@$(MAKE) --no-print-directory wait
	python3 detections/replay.py --base-url $(BASE_URL)
	@echo ""
	@echo "== HARDENED mode: detection replay (needs JWT_SECRET) =="
	JWT_SECRET=$(JWT_SECRET) HARDENED=true $(COMPOSE) up -d --build
	@$(MAKE) --no-print-directory wait
	python3 detections/replay.py --hardened --base-url $(BASE_URL)
	@echo ""
	@echo "detection replay: both modes matched expectations"

clean: down ## Stop everything and prune build cache
	docker builder prune -f
