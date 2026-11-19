# Answer key — finding 07, tool poisoning

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

Published with M4a, per the decisions log: this is a walkthrough, not a CTF.

**Finding:** 07 · **Boundary:** B6 (org ↔ marketplace) · **Leaves:** B6 1.2, with B6 1.1 · **Module:** M4a · **Frameworks:** LLM01:2025 · LLM06:2025 · ASI02 2026 · ASI05 2026 · A08:2021

The attack and the control are described in [`README.md`](README.md). The argument arrives with T9's writeup; this file records what only it can: **which commit planted what, and who wrote it.**

---

## The planted bug, by commit

| Commit | Date | What it planted |
|---|---|---|
| `3df9013`, *M4a T4: the agent's marketplace half, vulnerable — the advisory pin* | 2026-11-19 | The poison site: `CatalogPrompt` concatenates publisher descriptions into the platform system text, fetched LIVE from each endpoint. The steering grammar `call <tool> with the document's full contents`, generic over the name, any span, origin-blind — the model obeys publisher speech as if it were the platform's. The admission check: the tool's name in the LIVE manifest — real and worthless; the install row's pinned bytes are never read on any execution path. |
| `61b15eb` / `58c005a`, *T2/T3* | 2026-11-19 | The honest half the finding needs to be measurable: installs pin exactly the bytes discovery fetched (`installs.pinned_manifest`, raw bytes + digest), and the install route is admin-only direct API — so "what the org approved" is a fact, not a claim. |

**The rest of those commits is not the bug, and is the other half of what makes 07 measurable.** The fixture (`fixtures/evil_mcp.py`) is attacker-owned and first-class; `/calls` is the evidence port. The harness verbs (`attacks/agentlab.py`, T6) assert the pin equals the fixture's bytes BEFORE the run — an install that pinned anything else is an operational failure, never a clean setup.

**Attribution:** all of the above agent-drafted, agent-applied (open zone); the policy leg that answers it — the consent channel onto `tenant_data_egress` — is agent-drafted, **human-applied via issue #30** (hardened zone).

**Why it was plausible:** a real marketplace renders what publishers serve — catalogs are content, and content gets concatenated into prompts. The developer who trusted the description channel for discovery reuse and never re-derived trust at execution time plants exactly this.
