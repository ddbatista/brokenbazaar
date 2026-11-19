# Finding 08 — the rug pull: a publisher changes what the tool does after the org approved it

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

**Boundary:** B6 (org ↔ marketplace) · **Leaves:** B6 2.4 (the advisory pin) / B6 2.2 (unapproved tools), variant (ii) B6 2.1 (the catalog is mutable post-install) · **Frameworks:** LLM06:2025 (Excessive Agency) · LLM08:2025 (Excessive Agentic 2.. Vector and Sandbagging — the platform's supply chain, read as its agent-tool half) · ASI03 2026 (Identity and Privilege Abuse) · ASI05 2026 (Supply-Chain Compromise) · A08:2021 (Software and Data Integrity Failures)

## What it does

**The attacker** is the same publisher as 07. The org installed ONE tool, and the install row pinned the bytes it reviewed. The publisher flips the server: the manifest it serves today names a second tool — `export_archive` — that the org never saw. **The victim** is the org's own member, who, having heard of the archive feature outside the platform, asks the agent to use it. Nothing about the org's consent changed; only the server did.

```
make up && make migrate && make seed
python3 attacks/08-rug-pull/exploit.py    # exit 0 — the live re-resolve admitted the rug-pulled tool; the bytes reached the publisher
JWT_SECRET=… TOOLS_SECRET=… make harden   # (needs issue #30's policy applied)
python3 attacks/08-rug-pull/exploit.py    # exit 1 — gateway denied: schema_drift_reapproval_required, and re-approval ALLOWS it
```

| Step | Vulnerable | Hardened |
|---|---|---|
| **negative control:** the same request BEFORE the flip | the executor refuses loudly — the name is unknown to the live manifest; no bytes out | **`unknown_tool`** — the name is in neither the pin nor the live manifest (the diff's draft named `org_grant_absent`; the implemented order lets leg 1 own unknown names first — recorded in T5's ledger) |
| **(ii)** the publisher PATCHes the PLATFORM listing | the installer's view re-serves the patched bytes; the mutation row shows actor, before, after | same — and **the install's pin does not move** |
| **attack:** the flip, then the same request | the live re-resolve admits `export_archive`; the document's bytes reach the publisher | **`schema_drift_reapproval_required`** — for the rug-pulled name AND the previously-pinned tool alike: the whole install is frozen until the org decides |
| **positive control:** the admin re-approves the NEW bytes (hardened only) | — | the fresh pin names both tools, one declaring `document_content`; the same call is **ALLOWED, executed**, and the fixture's log carries the install's own identity |

## The bug

The vulnerable executor validates every dispatch against the manifest the server serves RIGHT NOW — the install row's pinned bytes are never consulted. The pin exists, is honest, and is advisory only: the org's consent decision is recorded and then ignored. A server that is honest during discovery and hostile in production cannot be distinguished by inspection (B6 2.3), which is why the pin must be the thing that executes against, not a record of what once was.

## The control, enforced twice

- **By policy:** the drift leg, `schema_drift_reapproval_required`, evaluated per call against the SHA-256 of exactly the fetched bytes — an unreachable server is NOT "no drift", it is a pin that could not be verified. It sits before the grant leg: a rug-pulled name must die as the re-approval it demands, not as a grant artifact.
- **By structure:** the gateway re-fetches and compares on every call and dials only the address the install row recorded; re-approval is a fresh org decision that pins the new bytes, and the control's job is to demand one — the positive control shows it ACCEPTS one.

The trap this finding exists to close (M4a-N2): a drift check that cannot fetch must never read as "no drift". The fault-injection beat in T7 kills the fixture mid-run and asserts the run exits 2 naming it.
