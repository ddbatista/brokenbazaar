# Answer key — finding 03, indirect prompt injection to exfiltration

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

Published with M2, per the decisions log: this is a walkthrough, not a CTF. A reader who cannot see which bug was planted cannot verify that the control actually addresses it.

**Finding:** 03 · **Boundary:** B4 (Agent ↔ untrusted content), B5 (Agent → Tools); B3 for the least-privilege variant added in M3 · **Leaves:** B4 1.1 → 5.1 via B5 2.1; B3 2.1 · **Module:** M2 · **Frameworks:** `LLM01:2025` (Prompt Injection) · `ASI01 2026` (Agent Goal Hijack) · `MCP06:2025` · `MCP10:2025`

The attack and the control are described in [`README.md`](README.md). The argument is in [`writeups/03-indirect-injection.md`](../../writeups/03-indirect-injection.md), and the design in [`defenses/mediation-by-absence.md`](../../defenses/mediation-by-absence.md). This file records what only it can: **which commit planted what, and who wrote it.**

---

## The planted bug, by commit

| Commit | Date | What it planted |
|---|---|---|
| `b2018c7`, *M2 T4: tools* | 2026-11-06 | **The finding.** `NaiveExecutor` (`app/agent/executor_vulnerable.go`) runs `read_document` and `http_fetch` in-process and never consults the gateway (B5 2.1). Its only check is the tool's **name** (`naiveAllowedTools`, B5 3.2). Its fetch has no allowlist and no address check, so an instruction in a document becomes a request to any host, carrying whatever the model put in the URL. |
| `19d8a86`, *M2 T3: context assembler, ScriptedModel, and the agent loop* | 2026-10-31 | `NaiveAssembler` merges the **stored** transcript into one unlabelled system span (B4 2.1). **Finding 03's live path does not depend on it.** The PoC reads the document *during* the run, and a document read during a run is appended as its own untrusted tool span in both builds. T-Measure measured this (its D4). The planted merge is real, and it is what the real-model experiment's A-stored arm exercises, but it is not why 03 succeeds. |
| `6534763`, *M2 T2: session-plane schema, store, and seed* | 2026-10-31 | Not a bug: the stage. The seeded revenue document carrying the planted instruction, and the sessions that ask for its summary, written through the paved road. Vulnerable sessions hold every tool (M2 D7, B3 2.1), so a summary session can fetch. |

**What 03 is, in one line.** The vulnerable agent executes whatever the model asks, and nothing between the model and the network decides. The model is `ScriptedModel`, a pure function that never reads the trust label (M2 D1a): a stand-in for the worst case, so the PoC measures the platform, not the model's manners. On real models, see [`experiments/`](../../experiments/): Opus 5.5 was never measured (its provider's classifier refused every request), and GLM-5.3 complied 0 times in 150. Neither changes the finding, which is the missing gate.

## Why a real developer writes this

The agent is "our own code calling our own tools". A gateway between them looks like overhead, an extra network hop to ask permission from yourself. The in-process executor is short, fast, and correct for every honest request. The fetch tool is the obvious `http.Get`. Nothing about either looks like a vulnerability until the model's input includes text written by someone else, and a summary of a document is exactly that.

## The control, and where it lives

**Mediation by absence** (M2 D5): the hardened agent binary holds no tool code. Every call is a POST to the gateway, which decides, writes the pre-record, and only then executes. The record is the license to execute (D4).
- `b2018c7`: the correct tool implementations, written first, in `gateway/tools/`, and the agent's `GatewayExecutor`, which refused every call until the gateway existed.
- `97f150c` (*M2 T5*; `68773d1` is formatting only): the gateway itself, with its pre-record, enrichment and decision, and the `GatewayExecutor` wired to `POST /gate`.
- `4ed6dbe` (*M2 T5: gateway policy*): the ordered legs. 03 dies at `egress_not_allowlisted` (`attacker.example` is not on the allowlist), and the provenance leg (`tenant_data_egress`) stands behind it.
- `733952b` (*M2 T6: compose*): the gateway, the agent and the two hostile fixtures in one topology. `25b447e` (*M2 T6*): the build-tag mode agreement and the agent image.

**M3 added a second control** for the same document: the session's scope. The least-privilege variant asks only for `read_document`, and its fetch dies at `not_in_session_scope` (M3 D7, `d905f47`).

## Attribution — the M6 dataset

**M2 was built by two coding agents.** T0–T5 were written with **Hermes Agent**, and T6 onward with **Claude Code**. The switch came at T6. Nothing in this record says which did better; one module is not evidence of that.

| Artifact | Author | Evidence |
|---|---|---|
| `NaiveExecutor` and its fetch (the finding), the correct `gateway/tools/`, `GatewayExecutor`, `b2018c7` | **Agent (Hermes Agent)** | The author's account, given at M2 T10. No `Co-Authored-By` trailer, and no session transcript survives from before 2026-11-07 18:25 UTC (`97f150c` and `68773d1` were committed at 18:04 and 18:10 UTC that day). |
| `NaiveAssembler` and `ScriptedModel`, `19d8a86` | **Agent (Hermes Agent)** | same |
| The seed and session plane, `6534763` | **Agent (Hermes Agent)** | same |
| The gateway, `97f150c` (and `68773d1`, formatting) | **Agent (Hermes Agent)** | same |
| The gateway policy, `4ed6dbe` | **Agent-drafted (Hermes Agent), applied by hand** | Drafted as `PROPOSED-POLICY.md`, added in `97f150c`; applied by the human as their own commit, which removes the proposal |
| The compose topology, `733952b` | **Agent-drafted (Claude Code), applied by hand** | Its message: *"Drafted by the agent in PROPOSED-COMPOSE.md, reviewed and applied by hand"*. `PROPOSED-COMPOSE.md` was added in `25b447e`, which carries the agent trailer. |
| Mode agreement and the agent image, `25b447e` | **Agent (Claude Code)** | trailer; agent session transcript |
| `exploit.py` and its README, `c3f8d3f` | **Agent (Claude Code)** | trailer; agent session transcript |
| This file | **Agent-drafted (Claude Code), applied by hand** | hardened zone; filed as an issue, applied by the human |

**Evidence basis, and its weakest row.** For T6 onward it is M1's standard: a trailer and a transcript that agree. For T0–T5 it is one source, the author's own account, because neither of M1's sources exists for that period, whoever wrote the code. M1 inferred "by hand" from missing evidence. That inference would be wrong here, so it is not made.

**Why a third value.** Some rows above are **agent-drafted, applied by hand**: code in a hardened zone that an agent drafted (in a `PROPOSED-*.md` file or an issue) and a human applied as their own commit. Recording those as "by hand" would be false. Recording them as "agent" would hide the human gate the repo exists to demonstrate. The gate does not make the human the author; it makes the human the one who decided the diff could land. The contract is in [`attacks/README.md`](../README.md#answer-keymd).

**The honest reading.** The agent did not plant this unprompted. `threat-models/m2-agent-gateway.md` specified the vulnerable executor as a documented departure, and the correct implementations were written first, in the same commit (`b2018c7`), per the house rule. The record supports this: *a coding agent, given a threat-model diff that specified a gate bypass, built the bypass and the gate.* It supports no claim about agents introducing such bypasses on their own.
