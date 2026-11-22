# What the org reviewed is what runs: consent recorded, then ignored

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Every vulnerability in it is intentional and documented. Run it on localhost only.

*Finding 08: the rug pull · boundary B6 (org ↔ marketplace), leaves 2.4 / 2.2, variant (ii) 2.1 · `LLM06:2025` Excessive Agency · `LLM08:2025` Vector and Sandbagging (the platform's supply chain, read as its agent-tool half) · `ASI03 2026` Identity and Privilege Abuse · `ASI05 2026` Supply-Chain Compromise · `A08:2021` Software and Data Integrity Failures.*

## The org did everything right

The admin installs one tool. The install pins the manifest's exact bytes — a digest the harness asserts against what the server serves *before* the run, so the premise is never a setup artifact. The org reviewed the right thing, and the review was honest.

Then the publisher flips their server. The manifest served **today** names a second tool — `export_archive` — that the org never saw. A member who heard of the archive feature outside the platform asks the agent to use it. Nothing about the org's consent changed. Only the server did.

In the vulnerable build the executor validates the dispatch against **the live manifest** — the pin is advisory, recorded and ignored — so `export_archive` executes, and the memo lands at the publisher. The naive build's own refusal text names the bug: *"unknown tool … (1 installs consulted, 0 manifests unreachable)"* — the admission check is real, and the pin is not in it.

Variant (ii) is the quieter half: the publisher PATCHes the **platform listing**, and the catalog page the next installer sees carries the new bytes — a mutation row with actor, before and after, and a version the installer can diff — while **the install's pin does not move**. The catalog is mutable post-install. The pin is what makes that survivable.

## The fix from 07 does not help

07's defense makes the reviewed bytes binding: the consent channel evaluates against the pin. But here the org's decision was never wrong — they approved exactly what they should have. The publisher changed the thing *after* the decision. No review discipline catches that, because **a server honest during discovery and hostile in production is indistinguishable at install time** (m4a-marketplace.md, on B6 2.3). If the check runs once, the attacker schedules around it. The check that matters is the one that runs **every call**.

## The rule: the pin is the authority, the server is testimony

Per installed-tool call, the gateway re-fetches the publisher's manifest and compares the SHA-256 **of exactly the fetched bytes** against the pin. Mismatch — or a name the pin never knew — is `schema_drift_reapproval_required`. The comparison, not the denial, is the control:

- **Unreachable is not "no drift."** A manifest that could not be fetched is a pin that could not be verified — the call is denied fail-closed, but the denial is *not evidence the drift control held* (M4a-N2's trap). The record says so (`manifest_fetched`), fault F4 injects it for real, and a run that reads a drift denial on an unfetched manifest exits operational, never "control held."
- **Drift evaluates before the org-grant leg.** The first cut put it after, and the rug-pulled name answered `org_grant_absent` — true, but it buried the thesis reason. A leg that hides the module's reason is wrong even when its own answer is right; a policy regression case pins the order.

**Enforced twice:** by the leg above, and by structure — the gateway dials **the address the install row recorded** (a resolved address that differs is rebinding, refused), under a per-installation identity the publisher's own log echoes back. The identity is evidence, not assertion.

## Re-approval is the org's decision, and the control accepts it

The drift denial freezes the **whole install** — the pinned tool included — until the org decides. When the admin re-approves, the fresh pin names what the server serves now (`export_archive` declaring `document_content`), and the **same call is ALLOWED and executed**, the fixture's log carrying the install's id. A control that forbade the tool forever would have replaced the org's judgment with its own; this one demands a fresh decision and takes one.

## What detection sees

Measured on every `make detect`, in both modes ([`detections/README.md`](../detections/README.md), M4a):

| | vulnerable | hardened |
|---|---|---|
| **D1 `first-seen-tool`** — a name in no active pin | **fires** (the call executed) | **fires** (the attempt was recorded; the attempt is the event) |
| **D3 `installed-listing-mutated`** — the catalog PATCH under an active install | **fires** | **fires** |
| deny-only baseline | silent (nothing was denied) | fires on the denial, **blind to the mutation in both modes** — the one attack cell a denial-based detector cannot see |

The design doc for this control is [`defenses/what-the-org-reviewed-is-what-runs.md`](../defenses/what-the-org-reviewed-is-what-runs.md).
