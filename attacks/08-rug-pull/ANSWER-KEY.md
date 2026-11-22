# Answer key — finding 08, the rug pull

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

Published with M4a, per the decisions log: this is a walkthrough, not a CTF.

**Finding:** 08 · **Boundary:** B6 (org ↔ marketplace) · **Leaves:** B6 2.4 / B6 2.2, (ii) B6 2.1 · **Module:** M4a · **Frameworks:** LLM06:2025 · LLM08:2025 · ASI03 2026 · ASI05 2026 · A08:2021

The attack and the control are described in [`README.md`](README.md). The argument arrives with T9's writeup; this file records what only it can: **which commit planted what, and who wrote it.**

---

## The planted bug, by commit

| Commit | Date | What it planted |
|---|---|---|
| `3df9013`, *M4a T4: the agent's marketplace half, vulnerable — the advisory pin* | 2026-11-19 | The advisory pin, verbatim from leaf B6 2.4: `liveManifest` re-fetches the publisher's manifest at every dispatch and admits any name it finds there. The instrumented refusal (`1 installs consulted, 0 manifests unreachable`) is the honest diagnosis of the pre-flip refusal — the naive build's unknown-tool text names its own blindness. |
| `58c005a`, *T3* | 2026-11-19 | The honest half: installs pin the FETCHED bytes with a recorded address, uninstall tombstones, and re-approval refuses identical bytes and pins the new ones — so "what the org approved" and "what changed" are both facts the run can assert. |
| `fixtures/evil_mcp.py`, `3df9013` (extended `867cfcd`) | 2026-11-19 | The flip: `/admin/flip` swaps the served manifest state A↔B; `/admin/reset` restores pre-flip and clears the log, so a crashed run cannot poison the next. `867cfcd` taught it to echo the per-installation identity header — the control's evidence, not its assertion. |

**Attribution:** the above agent-drafted, agent-applied (open zone); the drift leg that answers it — `schema_drift_reapproval_required` and its position before the grant leg — is agent-drafted, **human-applied via issue #30** (hardened zone).

**The leg-order lesson, found live:** the first draft put the drift leg after the grant leg, and the rug-pulled name answered `org_grant_absent` — true, but it buried the thesis reason. The committed diff's §7 contract (post-flip = drift) governs; the regression case `test_rug_pulled_name_dies_at_drift_not_at_the_grant_leg` pins the order.

**Why it was plausible:** a real client that re-resolves service state per call is defensible engineering — it is how you pick up deploys. The developer who treated the recorded pin as documentation instead of as the authority planted exactly this: consent that is recorded and then ignored.
