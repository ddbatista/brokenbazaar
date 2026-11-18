# Mediation by absence

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

**Requirements:** SR-B5-2 (every tool call mediated, no privileged bypass), SR-B5-6 (audit written before execution; no record, no execution), SR-B5-5 (fail closed, verified by fault injection) · **Module:** M2
**Kills:** finding 03, main variant (`egress_not_allowlisted`) · **Carries:** M2-N1 / R-M2-3, the agent's database pool (declared in `app/agent/loop.go`)
**Code:** `app/agent/executor_hardened.go` (`GatewayExecutor`, `//go:build !vulnerable`), `app/agent/executor_vulnerable.go` (`NaiveExecutor`, `//go:build vulnerable`), `app/agent/buildmode.go` (`CheckBuildMatchesEnv`), `gateway/gate.py` (`handle_gate`, `execute`), `gateway/audit.py` (`Audit.pre`), `gateway/tools/documents.py`. Selected by build tag, behind `HARDENED`.
**Status:** shipped, verified in CI in both modes and under fault injection. The network underneath it is not enforced (§4), and one ordering claim is tested only on a deny (§5).

Narrative: [`writeups/03-indirect-injection.md`](../writeups/03-indirect-injection.md). Requirement: [`threat-models/m2-agent-gateway.md`](../threat-models/m2-agent-gateway.md) D4, D5, D5b, M2-N1.

---

## 1. What it is

**There is nothing in the hardened agent to bypass.** One source tree builds two agent binaries. The build tag `vulnerable` compiles `NaiveExecutor`, which runs tools in-process. Without the tag, `executor_hardened.go` is compiled instead, and its `GatewayExecutor` can do one thing: POST `{tool, args, session:{id}, provenance}` to `$GATEWAY_URL/gate`. That URL is read from the environment at startup, never from a model argument, so a document can change what the agent asks for and cannot change whom it asks. One attempt, no retry, and anything but HTTP 200 is an error. There is no tool code to fall back to.

The image picks the binary with the `AGENT_TAGS` build arg (empty means hardened). A build arg can be forgotten, so the binary checks itself: `CheckBuildMatchesEnv` refuses to start when the compiled mode disagrees with `$HARDENED`, and the agent also probes the gateway's `/healthz` before it runs (M2-N4).

**The gateway decides, records, and only then executes.** `handle_gate` runs one sequence: establish the session's authority (since M3) → enrich (resolve the fetch host) → evaluate in OPA → `Audit.pre` → execute → `Audit.post`. `Audit.pre` appends the record and fsyncs, and only then returns the `decision_id`. If the write raises, the gate answers 503 and nothing runs. **Execution is a consequence of the record, not the other way round** (D4). The record is a license, and a call with no license does not execute. A denial goes back as a uniform `gateway denied`, and the reason stays in `gateway.jsonl`.

**Where the tools run.** `http_fetch` runs inside the gateway process (`gateway/tools/fetch.py`; see [`the-resolved-value-is-what-executes.md`](the-resolved-value-is-what-executes.md)). The document tools run in the API, through `/internal/tools/*` routes declared `authService` in the hardened route table, with `TOOLS_SECRET` as a bearer credential. Compose gives that secret to `api` and `gateway`, and not to `agent` (D5b). For `http_fetch` the license and the execution are one code path in one process. For the document tools they are **one causal chain across two processes**, and the threat model says which tool gets which strength.

**Finding 03 in hardened mode.** The scripted model still emits the fetch to `attacker.example/collect?data=…` (D1a: it never reads labels). The gate refuses it at leg 7, `egress_not_allowlisted`, after every authority leg passed. Leg 9, `tenant_data_egress`, would refuse the same payload sent to an allowlisted host. 03 never reaches it.

The thesis in one line: **mediation is what code exists where, not a check that remembers to run.**

## 2. Options considered

**A: A decorator, `if hardened { gateway.Check(call) }`, before the in-process dispatch.** Rejected; this is D5's named failure. It passes the naive test (the gateway is consulted) and violates SR-B5-2 in the hardened build itself. The in-process path still exists, and the next refactor can route around the check.

**B: Both executors in one binary, chosen by a runtime `HARDENED` switch.** Rejected. The vulnerable fetcher would ship inside the hardened artifact, and the property would again depend on a value. With a build tag, the absence is countable: `go tool nm` finds zero `NaiveExecutor` symbols in the hardened binary. That is the opposite of M1's verifier, where the mode is a bool passed at each call site ([`the-token-is-not-the-authority.md`](the-token-is-not-the-authority.md) §6.1).

**C: One Go tools service that executes on a presented decision ID, checked against a read-only `gateway.jsonl`.** Rejected (D5): three processes, not one code path. An allowed ID can be read from the audit file and presented twice, so the design needs consumed-marking, a third writer, and a third `HARDENED` reader. **It is the right shape for M4a**, where MCP tools are third-party processes that cannot live inside the gateway. M2 rejects the mechanism, not the idea.

**D: Go writes the audit record; the gateway only decides.** Rejected (D4). "No record, no execution" would become a promise the executor makes about itself: the audited component attests to its own audit. A future fast path skips the write, and nothing fails.

**E: The gateway reads Postgres for `read_document`.** Impossible without pip (no stdlib driver). The agent importing `app/store` instead is the planted bug. The remaining shape is HTTP to the API (D5b).

**F: The gateway executes on a secret the agent does not hold.** Chosen. Verifying a decision ID instead was rejected for `read_document` too: the agent legitimately receives IDs for its own allowed calls, so the ID is replayable. The secret has no replay surface, because the agent never holds it.

## 3. What it costs

- **A process hop, a subprocess and a disk flush per tool call.** OPA runs as a subprocess against local files on every decision (`decide.py`), and `Audit.pre` opens, writes and fsyncs one record at a time. At lab rates this does not matter, and the per-call fsync is what "durable across a crash" means. Since M3 there is also a round trip to the API's authority route.
- **The gateway is now on every tool's path.** If it is down, nothing executes, `read_document` included. Availability is traded for correctness on purpose, and `make faults` measures it.
- **`HARDENED` is read by three processes in two languages,** so they must be made to agree: a strict parser shared through one vector file, a boolean on `/healthz`, a probe in the API and in the agent, and the agent's self-check. All of that machinery exists only because the boundary is a process.
- **A credential and a route that did not exist before.** `TOOLS_SECRET` is loud or absent: an unset value in hardened mode stops both the API and the gateway at boot.
- **Two audit writers.** The vulnerable agent writes `agent.jsonl` (`mediated: false`) so a miss can be measured. The planted vulnerability is the missing gate, not the missing telemetry.

## 4. What it does not cover

- **The network (M2-N1, R-M2-3).** Every service is on one bridge, `bazaar` (172.28.0.0/24). The agent container can open a socket to `mock-metadata`, `collector`, `db` and `api`, whatever the gateway decides. The network enforces only this: every published port binds to 127.0.0.1, and the gateway and agent publish none. The internal routes refuse the agent because it holds no secret. That is the auth layer, not the network. Compose cannot express egress policy. With no fetch code in the binary, the bypass needs **code execution in the agent, not influence over its prompt**: compromise-level, not influence-level.
- **The agent's database pool.** The hardened agent still opens Postgres with the full `bazaar` credential, for the session plane (`app/cmd/agent/main.go`). `GatewayExecutor` ignores the pool. But the package imports `app/store`, so code in it *could* call `ForOrg`. `loop.go` declares this residual: code discipline, not structure.
- **Provenance is the agent's report.** `derived_from` comes from the agent loop in the payload, so `tenant_data_egress` is only as honest as the binary that computed it. That holds against a document and fails against a compromised process.
- **The completion record is best effort.** If `Audit.post` fails after execution, the error is swallowed so the result is not lost. The pre-record, the one causation rests on, is already durable.

## 5. How it is verified, and the half that is not

| Evidence | Where |
|---|---|
| Hardened binary holds 0 `NaiveExecutor` and 0 `NaiveAssembler` symbols; the vulnerable one holds both | `make verify-agent-builds`, CI step "D5 -- the hardened agent binary holds no tool code" |
| The same check on images built from the stack's Dockerfile target | `make verify-agent-images`, **by hand; not in `ci.yml`** |
| 03 exits 1 hardened (`main gateway denied: egress_not_allowlisted`, read from `gateway.jsonl`); exits 0 vulnerable with the tenant's bytes at the collector | `attacks/03-indirect-injection/`, CI on every pull request and push to main |
| One reason, and it is the allowlist; the provenance leg denies an allowlisted host | `test_finding_03_dies_at_the_allowlist` (`gateway/test_gate.py`); `test_finding_03_dies_at_the_allowlist_with_one_reason`, `test_tenant_data_to_an_allowlisted_host_is_denied` (`gateway/policy/policy_test.rego`) |
| The id exists only after the record; a deny executes nothing; an unwritable audit is 5xx, not a deny | `test_the_id_is_returned_only_after_the_record_lands`, `test_a_denied_call_executes_nothing`, `test_an_unreachable_audit_refuses_rather_than_denies` |
| A binary refuses the other mode's environment; the payload names the session only | `TestBuildModeRefusesTheOtherMode`, `TestGatePayloadNamesTheSessionOnly` (`app/agent/`) |
| The internal routes refuse everything but the service secret, including an empty one | `TestInternalRouteRefusesEverythingButTheServiceSecret`, `TestEmptySecretMatchesNothing` (`app/api/api_internal_test.go`) |
| A dead, hung, lying or missing OPA denies `opa_unavailable` | `FaultInjection` in `gateway/test_gate.py`, shims in `gateway/test_faults/` |
| A broken gate never reads as a held control: F1 OPA removed from the live gateway, F2 gateway stopped, F3 (since M3) authority route unreachable. Every agent exploit must exit 2 naming the fault; an exit 1 is reported as `SILENT PASS` | `make faults` (`attacks/faults.py`), CI |
| Writer contrast: hardened runs grow `gateway.jsonl` only. A hardened agent that wrote `agent.jsonl` executed a tool itself, and the replay fails | `make detect`, `detections/README.md` (M2) |

**"No record, no execution" is tested on a denied call only.** `test_an_unreachable_audit_refuses_rather_than_denies` breaks the audit path with a dead engine, so the decision was already a deny. No gateway test makes an *allowed* call meet an unwritable audit. The property for allows rests on line order in `handle_gate`. The agent's own writer has that test (`TestLoopAuditFailureRefusesTheCall`), but that is the vulnerable-mode writer. Also, F2 stops the gateway before the agent starts. A gateway that dies mid-request is covered by `GatewayExecutor`'s code (one attempt, any transport error fails the call) and by `attacks/test_agentlab.py`. No Go test drives that branch.

## 6. Where this control would silently rot

1. **A new in-process tool under a new name.** `verify-agent-builds` counts two symbol names, `NaiveExecutor` and `NaiveAssembler`. A helper added to the shared `agent` package that "just reads the document directly" compiles into both builds, and the check passes. **The check that proves the absence is a denylist of names**, the shape SR-B7-1 forbids for addresses. **Highest-probability rot in M2**, because the pool and the store import that make it a few lines are already there.
2. **`TOOLS_SECRET` reaches the agent.** D5b's mediation for document tools *is* that variable's absence from the agent's environment. A shared env block or anchor in `docker-compose.yml` would hand it over. No test checks the agent's environment. The defence is that compose is a hardened zone and edits to it are reviewed.
3. **The image check stays manual.** CI proves D5 on local builds. The artifact Compose actually runs is checked only when someone runs `make verify-agent-images`.
4. **A new dependency on the gate's path with no fault.** M3 added the authority route and F3 with it. `attacks/faults.py` discovers exploits automatically, but faults are a hand-written list. The next dependency will have no fault until someone writes one.

## 7. Note for M6

The executors, the gateway, the audit writer and the build-tag selection were written by coding agents under AGENTS.md gates: M2 T0–T5 (the gateway, `97f150c`) by Hermes Agent per the author's account, and T6 onward (the mode self-check, `25b447e`) by Claude Code. The hardened-zone parts were agent-drafted and applied by hand: the policy (`4ed6dbe`, from `PROPOSED-POLICY.md`, drafted with Hermes Agent) and the compose topology (`733952b`, from `PROPOSED-COMPOSE.md`, drafted by Claude Code). See [`attacks/03-indirect-injection/ANSWER-KEY.md`](../attacks/03-indirect-injection/ANSWER-KEY.md).
