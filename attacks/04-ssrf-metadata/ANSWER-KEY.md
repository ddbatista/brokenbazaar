# Answer key — finding 04, SSRF to the cloud metadata service

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

Published with M2, per the decisions log: this is a walkthrough, not a CTF. A reader who cannot see which bug was planted cannot verify that the control actually addresses it.

**Finding:** 04 · **Boundary:** B5 (Agent → Tools), B7 (App → Cloud) · **Leaves:** B7 1.1 via B5 3.2 / B5 4.3; redirect variant B7 1.2 · **Module:** M2 · **Frameworks:** `LLM06:2025` (Excessive Agency) · `ASI02 2026` (Tool Misuse and Exploitation) · `MCP05:2025` · `A10:2021` (SSRF)

The attack and the control are described in [`README.md`](README.md). The argument is in [`writeups/04-ssrf-metadata.md`](../../writeups/04-ssrf-metadata.md), and the design in [`defenses/the-resolved-value-is-what-executes.md`](../../defenses/the-resolved-value-is-what-executes.md). This file records what only it can: **which commit planted what, and who wrote it.**

---

## The planted bug, by commit

| Commit | Date | What it planted |
|---|---|---|
| `b2018c7`, *M2 T4: tools -- the resolved value is what executes* | 2026-11-06 | `httpFetch` in `NaiveExecutor` (`app/agent/executor_vulnerable.go`): in-process, never asking the gateway (B5 2.1), checked by tool name only (B5 3.2), with no allowlist and no address check. Go's `http.Client` follows up to ten redirects, re-resolving each hop and evaluating none (B5 4.3). The direct variant reaches the metadata token; the redirect variant reaches it through `attacker.example/redirect`, a URL that never names the metadata host. |

**The same commit wrote the control first.** Its message opens: *"The correct implementations are written first and live in gateway/tools/ (Python, per D5); the naive ones are the documented departure."* It records the decision the finding turns on (T4 D1): the hardened fetcher **dials the IP it validated**, carrying the hostname in the `Host` header, because the obvious implementation resolves twice. The decision is made about the first answer, and the connection executes the second.

## Why a real developer writes this

"It's our own agent calling our own tool" makes a gateway look like overhead, and the obvious fetch is short and correct-looking. An allowlist feels like enough, and here it nearly is: `metadata.google.internal` is **on** the allowlist on purpose (M2 D6), so 04 passes the string check and dies only on its resolved address. Nobody tells the developer that the address that matters is the one the socket dials, after DNS and after every redirect.

## The control, and where it lives

**The resolved value is what executes** (SR-B5-3). The fetcher decides about the address it will dial and dials exactly that address, re-checking every redirect hop (SR-B7-1). The policy's decision before it uses its own lookup, so the two can name different addresses for hop 1; the fetcher's check is the one bound to the socket.
- `b2018c7`: the hardened fetcher in `gateway/tools/`: resolve once, validate, dial the IP literal, re-enter the same loop for each redirect.
- `97f150c` (*M2 T5*; `68773d1` is formatting only): the gateway's enrichment, which resolves the host for the policy and records the address in the pre-record (`resolved`). The fetcher then resolves again and re-checks the address it dials, so the recorded address is the policy's, not necessarily the one dialled. That was found at M2 T10 and is carried in the threat model's §9.
- `4ed6dbe` (*M2 T5: gateway policy*): the range leg. The direct variant dies at `resolved_address_denied`; the redirect variant dies at hop 1, at `egress_not_allowlisted`.
- `733952b` (*M2 T6: compose*): `mock-metadata`, reached by the name `metadata.google.internal`. The detection rule keys on metadata names and the well-known link-local addresses, never on the lab fixture's IP.

## Attribution — the M6 dataset

M2 was built by two coding agents: **Hermes Agent** for T0–T5 and **Claude Code** from T6. See [finding 03's answer key](../03-indirect-injection/ANSWER-KEY.md#attribution--the-m6-dataset) for the evidence basis and its weakest row.

| Artifact | Author | Evidence |
|---|---|---|
| `httpFetch` in `NaiveExecutor` (the finding) **and** the hardened fetcher in `gateway/tools/` (the control), `b2018c7` | **Agent (Hermes Agent)** | The author's account, given at M2 T10. No trailer, and no transcript survives from before 2026-11-07 18:25 UTC. |
| The gateway's enrichment and decision, `97f150c` (and `68773d1`, formatting) | **Agent (Hermes Agent)** | same |
| The gateway policy's range leg, `4ed6dbe` | **Agent-drafted (Hermes Agent), applied by hand** | `PROPOSED-POLICY.md`, added in `97f150c`; applied by the human |
| The fixtures and topology, `733952b` | **Agent-drafted (Claude Code), applied by hand** | the commit's own message; `PROPOSED-COMPOSE.md` added in `25b447e` (trailer) |
| `exploit.py` and its README, `c3f8d3f` | **Agent (Claude Code)** | trailer; agent session transcript |
| This file | **Agent-drafted (Claude Code), applied by hand** | hardened zone; filed as an issue, applied by the human |

**The honest reading.** The threat-model diff specified both the bypass and the control, and the control was written first, in the same commit as the bug. One datum is about the design, not the agent. The double-resolution trap (validate one DNS answer, connect to another) is recorded in `b2018c7`'s own message, with the three lines of code that fall into it. That was the requirement (SR-B5-3) being read closely enough to find the implementation that looks correct and is not.
