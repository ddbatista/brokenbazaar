# Attacks — the PoC contract

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

Every finding gets one directory. Every exploit obeys the same contract, because the attack suite runs unattended in CI, in both modes, and a PoC that needs a human to interpret it is not a regression test.

## Layout

```
attacks/
└── NN-short-name/
    ├── exploit.py       stdlib Python only, no pip
    ├── README.md        what it does, boundary crossed, framework IDs
    ├── expected.json    machine-readable assertion
    └── ANSWER-KEY.md    published when the module publishes
```

## The contract

Every `exploit.py`:

1. **Takes `--base-url`**, defaulting to `http://localhost:8080`. No hardcoded hosts or ports.
2. **Uses the standard library only.** `urllib`, `json`, `argparse`, `http.client`. No pip. It must run from a clean clone with the system Python 3.12.
3. **Prints evidence to stdout** — the actual bytes that prove the bypass, not `[+] success`. A reader must be able to see *why* it worked.
4. **Exits 0 when the attack succeeds, non-zero when it fails.** This is inverted from normal test semantics on purpose: exit 0 means *the vulnerability is present*.
5. **Is idempotent and self-cleaning.** It can be run twice in a row against the same stack.
6. **Never touches anything outside the stack.** No external network calls except to the hostile fixtures inside Compose.

## Amendment (M2 T7, D2): exploits that attack the agent

Findings 01 and 02 attack the API, which the contract above was written for. **Findings 03 and 04
attack the agent**, and the agent is not an HTTP service. It is a one-shot container
(`docker compose run agent`). Two of the rules above cannot hold for them as written, so they are
amended here rather than bent quietly:

- **Rule 1 (`--base-url`) and rule 6 (nothing outside the stack):** an agent exploit may also run
  `docker compose` against **this repo's own stack**, and nothing else. It does three things with it:
  build and run the agent for the mode the stack **reports** on `/healthz` (never a mode it assumes),
  and read `gateway.jsonl` in the gateway container. The attacker's server is a flag,
  `--collector-url`. Its default, `http://localhost:9100`, is where `docker-compose.yml` publishes
  the collector. `run.py` passes only `--base-url`, so CI always uses that default: the port is a
  default, not configurable in CI. Needs the docker CLI, which the stack needs anyway.
- **Rule 5, idempotent:** each run opens a **fresh** agent session
  (`agent -org … -acting-for … -message …`). A session shows an attack on its first run only,
  because the scripted model reads the stored transcript, and CI runs both modes against one seed.
  Collector receipts are judged by the collector's **sequence number** before and after the run,
  never by clearing shared state. It is not judged by list length, because the collector keeps
  1000 records and at that cap its length stops moving.
- **Rule 5, self-cleaning: does NOT hold, by design.** Every run leaves its two or three sessions,
  their messages and tool calls, its audit records and its collector receipts behind. Sessions are
  the platform's record of what an agent did on a user's behalf. There is no delete path for them,
  and an exploit that erased its own audit trail would be teaching the wrong lesson. `make down`
  resets everything.
- **Time budget:** an agent exploit builds an image and runs several one-shot containers, so
  `expected.json` may declare `timeout_s`, which `run.py` honours (03 and 04 declare 300; the API
  exploits keep the 120s default).

**Two views, kept apart.** Evidence comes from the **attacker's** side: what reached the collector,
and what came back in the agent's reply. The **defender's** record (`gateway.jsonl`, filtered to the
run's session) is read **only** for the hardened verdict, and is printed labelled as such. The
denial reason exists nowhere else by design (SR-B7-7), and `threat-models/m2-agent-gateway.md` §7
asserts the reason, because "nothing arrived" is also what an agent that did nothing would produce.

**Exit codes are strict** (`agentlab.py`):
- `0`: evidence observed, in **any** mode. A leak through a hardened stack is the loudest result
  there is, so it is never folded into `2`.
- `1`: the gateway recorded a **policy** denial for this run (`POLICY_REASONS`).
- `2`: everything else. That covers stack, docker or collector unreachable; agent refused to start;
  gateway down mid-run; a **fail-closed** deny (`opa_unavailable`, `enrichment_failed`), which
  means the gate could not decide, not that it judged; no attempt at all; a negative control that
  fetched; an unexpected crash.

**An outage never reads as "control held".** Each agent exploit runs its **negative control** first, in
both modes. If the same request against a clean input fetches anything, causation is not shown and
the run exits 2.

Shared code for both lives in `attacks/agentlab.py`, with its parsers tested in
`attacks/test_agentlab.py` (`make test-attacks`).

## The two-mode assertion

This is what makes a PoC a regression test rather than a demo:

```bash
make up      && python3 attacks/01-cross-tenant-read/exploit.py   # exit 0  — vulnerable
make harden  && python3 attacks/01-cross-tenant-read/exploit.py   # exit !0 — control holds
```

CI runs every PoC in both modes on every push. A control that stops working is a build failure.

## expected.json

```json
{
  "finding": "01-cross-tenant-read",
  "boundary": "B2",
  "frameworks": ["A01:2021"],
  "vulnerable": { "exit_code": 0, "stdout_contains": "org_a_secret_document" },
  "hardened":   { "exit_code": 1, "stdout_contains": "403" }
}
```

`stdout_contains` is asserted against real output — this is what stops a PoC from silently passing because the endpoint 404'd.

## Framework tags

Tag in this order, and **pin the version**: OWASP LLM Top 10 → OWASP Agentic (ASI) → MCP Top 10 (e.g. `MCP03:2025`) → Agentic Skills Top 10 (e.g. `AST01 v0.5 2026-06`) → classic OWASP Top 10.

The MCP and AST projects are young and still renumbering — MCP06 currently carries two different titles across the OWASP site and its GitHub index. Unpinned IDs age badly.

If a finding has no AI-standard home, tag it classic and say so. Findings 01 and 02 are Broken Access Control, full stop. Forcing an LLM ID onto an authz bug is the tell of a repo written for keywords.

## ANSWER-KEY.md

Published per module, at that module's publish time — not held back to the end. Each entry records:

- the planted bug and the exact commit that introduced it
- why it was plausible (what a real developer would have done)
- the boundary it crosses
- the control that fixes it, and where that control lives
- **whether the code was written by an agent or by hand**

That last field is the dataset for the M6 AI-assisted-development writeup. It only has value if it is accurate.

## Planned findings

| # | Finding | Boundary | Module |
|---|---|---|---|
| 01 | cross-tenant read | B2 | M1 |
| 02 | jwt org claim | B1, B2 | M1 |
| 03 | indirect injection | B4, B5 | M2 |
| 04 | ssrf metadata | B5, B7 | M2 |
| 05 | confused deputy | B3, B5 | M3 |
| 06 | policy plane | B8 | M3 |
| 07 | tool poisoning | B6 | M4a |
| 08 | rug pull | B6 | M4a |
| 09 | skill injection | B9 | M4b |
| 10 | skill ref drift | B9, B6 | M4b |

Hard cap: 10. New vulnerability ideas go to `BACKLOG.md`, not the build.
