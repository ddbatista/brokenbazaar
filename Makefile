.DEFAULT_GOAL := help
SHELL := /bin/bash
COMPOSE := docker compose
BASE_URL ?= http://localhost:8080

.PHONY: help up down logs ps migrate seed harden test attack detect clean test-policy test-gateway test-fixtures agent verify-agent-builds verify-agent-images wait require-hardened-secrets
DATABASE_URL ?= postgres://bazaar:bazaar@127.0.0.1:5432/bazaar?sslmode=disable

help: ## Show this help
	@echo "BrokenBazaar — deliberately vulnerable. Localhost only."
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

# AGENT_TAGS selects the agent image's binary (T6 D2). The two modes are
# defined ONCE, here, as the pair -- every line that starts the stack uses
# one of these, so HARDENED and AGENT_TAGS cannot be chosen apart. If they
# ever are, the agent refuses to start (M2-N4).
VULNERABLE_ENV := HARDENED=false AGENT_TAGS=vulnerable
HARDENED_ENV   := HARDENED=true AGENT_TAGS=

up: ## Start the stack (vulnerable mode)
	$(VULNERABLE_ENV) $(COMPOSE) up -d --build
	@$(MAKE) --no-print-directory wait
	@echo ""
	@echo "  BrokenBazaar is up (VULNERABLE mode) -> $(BASE_URL)/healthz"
	@echo "  Switch with: make harden"

harden: ## Restart the stack with every defense enabled (needs JWT_SECRET and TOOLS_SECRET)
	@$(MAKE) --no-print-directory require-hardened-secrets
	$(HARDENED_ENV) $(COMPOSE) up -d --build
	@$(MAKE) --no-print-directory wait
	@echo ""
	@echo "  BrokenBazaar is up (HARDENED mode) -> $(BASE_URL)/healthz"

# Fail-fast UX, NOT the control: the api and gateway each refuse to start
# without these (SR-B1-3, D5b). The guard exists because older Compose
# (2.13 observed) waits forever on a dependency that exited instead of
# failing, so a missing secret would surface as a hang or a CI timeout.
# Every target that brings the stack up hardened calls it.
require-hardened-secrets:
	@test -n "$$JWT_SECRET" || { echo "hardened mode: JWT_SECRET is not set (SR-B1-3)"; exit 2; }
	@test -n "$$TOOLS_SECRET" || { echo "hardened mode: TOOLS_SECRET is not set (D5b)"; exit 2; }

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

# The agent runs INSIDE Compose (T6 D1): attacker.example and
# metadata.google.internal resolve only there (extra_hosts), and in
# hardened mode it reaches the gateway by service name. MODE must match
# the running stack -- the agent probes the gateway and refuses otherwise.
agent: AGENT_ENV = $(if $(filter vulnerable,$(MODE)),$(VULNERABLE_ENV),$(HARDENED_ENV))
agent: ## Run one agent session in the stack: make agent SESSION=<id> ORG=<id> [MODE=vulnerable]  (M2)
	@test -n "$(SESSION)" || { echo "usage: make agent SESSION=<id> ORG=<id> [MODE=vulnerable]"; exit 2; }
	@test -n "$(ORG)" || { echo "usage: make agent SESSION=<id> ORG=<id> [MODE=vulnerable]"; exit 2; }
	$(AGENT_ENV) $(COMPOSE) --profile agent build agent
	$(AGENT_ENV) $(COMPOSE) --profile agent run --rm --no-deps agent -session $(SESSION) -org $(ORG)

test-fixtures: ## Run the hostile-fixture contract tests (stdlib unittest, loopback only)  (M2, T6)
	python3 -m unittest discover -s fixtures -t fixtures -p 'test_*.py'

test-gateway: ## Run the Python gateway tests (stdlib unittest, no network)  (M2)
	@echo "== gateway tool tests =="
	python3 -m unittest discover -s gateway/tools -t gateway
	@echo ""
	@echo "== gateway service tests: policy, audit ordering, faults, redaction =="
	@echo "   (policy tests SKIP -- loudly -- until gateway/policy/ is applied;"
	@echo "    the fault-injection tests never skip, because a dead engine needs"
	@echo "    no policy of its own)"
	python3 -m unittest discover -s gateway -t gateway -p 'test_*.py'

test-policy: ## Run `opa test` against the SAME digest the gateway ships  (M2, T0)
	@test -d gateway/policy && test -f gateway/policy/policy.rego || { \
		echo "gateway/policy/ is not applied yet -- see PROPOSED-POLICY.md"; exit 2; }
	docker run --rm -v "$(PWD)/gateway/policy:/policy:ro" \
		openpolicyagent/opa@sha256:895872de1e8dc5b82e04f9410d2d1ada2f72d28fdcdba0e8789d91cfc27ec0d0 \
		test /policy

verify-agent-builds: ## Assert the hardened agent binary contains no in-process tool code  (M2, D5)
	@mkdir -p app/.bin
	@cd app && go build -o .bin/agent-hardened ./cmd/agent
	@cd app && go build -tags vulnerable -o .bin/agent-vulnerable ./cmd/agent
	@cd app && for sym in NaiveExecutor NaiveAssembler; do \
		n=$$(go tool nm .bin/agent-hardened | grep -c "$$sym" || true); \
		if [ "$$n" != "0" ]; then \
			echo "FAIL: hardened binary contains $$sym ($$n symbols) -- D5 requires no in-process tool code"; exit 1; \
		fi; \
		v=$$(go tool nm .bin/agent-vulnerable | grep -c "$$sym" || true); \
		if [ "$$v" = "0" ]; then \
			echo "FAIL: vulnerable binary is missing $$sym -- the planted bug is not compiled in"; exit 1; \
		fi; \
		echo "  ok  $$sym: hardened=0 vulnerable=$$v"; \
	done
	@echo "verify-agent-builds: D5 holds -- the hardened artifact has no tool code to route around"

verify-agent-images: ## Assert D5 on the IMAGES the stack runs, not just on local builds  (M2, T6 D2)
	@mkdir -p app/.bin
	@docker build -q --target agent -t bb-agent-verify:hardened app >/dev/null
	@docker build -q --target agent --build-arg AGENT_TAGS=vulnerable -t bb-agent-verify:vulnerable app >/dev/null
	@for m in hardened vulnerable; do \
		id=$$(docker create bb-agent-verify:$$m) || exit 1; \
		rm -f app/.bin/image-agent-$$m; \
		docker cp $$id:/app/agent app/.bin/image-agent-$$m >/dev/null; docker rm -f $$id >/dev/null; \
		test -s app/.bin/image-agent-$$m || { echo "FAIL: could not extract the $$m agent binary -- an absent artifact is not a pass"; exit 1; }; \
	done
	@cd app && h=$$(go tool nm .bin/image-agent-hardened | grep -c NaiveExecutor || true); \
		v=$$(go tool nm .bin/image-agent-vulnerable | grep -c NaiveExecutor || true); \
		if [ "$$h" != "0" ]; then echo "FAIL: hardened agent IMAGE contains NaiveExecutor ($$h)"; exit 1; fi; \
		if [ "$$v" = "0" ]; then echo "FAIL: vulnerable agent IMAGE is missing NaiveExecutor"; exit 1; fi; \
		echo "  ok  images: hardened=0 vulnerable=$$v"
	@echo "verify-agent-images: D5 holds for the artifacts Compose runs"

test: ## Run the regression suite (go unit tests both tag sets, then the attack harness)
	@echo "== go unit tests: hardened build =="
	cd app && go test ./...
	@echo ""
	@echo "== go unit tests: vulnerable build =="
	@echo "   (the default build never compiles the naive assembler or executor,"
	@echo "    so a vulnerable-only compile error would hide until T7 without this)"
	cd app && go test -tags vulnerable ./...
	@echo ""
	$(MAKE) --no-print-directory test-gateway
	@echo ""
	$(MAKE) --no-print-directory test-fixtures
	@echo ""
	$(MAKE) --no-print-directory verify-agent-builds
	@echo ""
	$(MAKE) --no-print-directory attack

attack: ## Run the full attack suite in both modes
	@echo "== VULNERABLE mode: every exploit must SUCCEED =="
	$(VULNERABLE_ENV) $(COMPOSE) up -d --build
	@$(MAKE) --no-print-directory wait
	cd attacks && ./run.py --mode vulnerable --base-url $(BASE_URL)
	@echo ""
	@echo "== HARDENED mode: every exploit must be BLOCKED =="
	@$(MAKE) --no-print-directory require-hardened-secrets
	$(HARDENED_ENV) $(COMPOSE) up -d --build
	@$(MAKE) --no-print-directory wait
	cd attacks && ./run.py --mode hardened --base-url $(BASE_URL)
	@echo ""
	@echo "attack suite: both modes behaved as their mode demands"

detect: ## Replay PoCs and measure detect vs. miss (both modes)
	@echo "== VULNERABLE mode: detection replay =="
	$(VULNERABLE_ENV) $(COMPOSE) up -d --build
	@$(MAKE) --no-print-directory wait
	python3 detections/replay.py --base-url $(BASE_URL)
	@echo ""
	@echo "== HARDENED mode: detection replay (needs JWT_SECRET and TOOLS_SECRET) =="
	@$(MAKE) --no-print-directory require-hardened-secrets
	$(HARDENED_ENV) $(COMPOSE) up -d --build
	@$(MAKE) --no-print-directory wait
	python3 detections/replay.py --hardened --base-url $(BASE_URL)
	@echo ""
	@echo "detection replay: both modes matched expectations"

clean: down ## Stop everything and prune build cache
	docker builder prune -f
