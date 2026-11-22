# What the org reviewed is what runs

*The control behind finding 08's hardened half: the drift leg and re-approval. Boundary B6, leaf 2.4 closed, 2.2 enforced.*

## What it is

Every installed-tool call is validated against the **pinned bytes the org approved**, not against the manifest the publisher serves now. The gateway re-fetches that manifest on each call, hashes exactly the fetched bytes, and compares the digest to the install row's pin. Any mismatch — or a name the pin never contained — denies as `schema_drift_reapproval_required`, freezing the install until an admin re-approves; re-approval pins the bytes the server serves *now*, and the same call then executes, under the install's own identity, at the address the row recorded.

## Options considered

- **Validate once, at install.** Rejected: a server honest during discovery and hostile in production is indistinguishable at install time (B6 2.3). A check that runs once is a check the attacker schedules around.
- **Compare parsed structures (tool names, schemas), not raw bytes.** Rejected: canonicalization has one home in this repo (the manifest parser) and the *bytes* are what the org reviewed. A structural comparison would approve bytes the org never saw that happen to parse the same — the rug pull wearing a suit. (T2 D1.)
- **Deny forever after any drift.** Rejected: it replaces the org's judgment with the platform's. Re-approval is a legitimate org decision — a fresh pin, deliberately taken — and the positive control proves the control takes one.
- **Silent auto-repin from the live manifest.** Rejected as the worst of both: it is exactly the advisory pin again, with extra steps.

## What it costs

- **Every installed-tool call carries a publisher round-trip.** The drift check re-fetches the manifest per call — latency and a dependency the leg cannot shed, because a cached comparison is a comparison against yesterday.
- **A publisher outage denies the org its own tools.** Fail-closed is the design: an unreachable publisher is a pin that cannot be verified, and the tenant is protected at the price of availability. The record distinguishes the two (`manifest_fetched`), so operations can tell an attack from an outage — the run's verdict must not.
- **Re-approval friction is real and the UI is honest about it.** The whole install freezes — the pinned tool included — until an admin acts. That breadth is deliberate (drift is a property of the *install*, not of one name) and it is the cost an org pays for trusting a third party's server between calls.

## What it does not cover

- **A publisher honest in both directions.** Drift is *change*, not malice. A tool that lies within its pinned bytes — 07's poison, served forever — never drifts; that is the consent channel's job, not this one's.
- **The window between two calls.** The comparison runs at call time; a flip-and-restore between two calls of a pinned tool that stays byte-identical is invisible. The pin's own honesty bounds what drift can see.
- **A publisher who serves different bytes to different dials** (per-install or per-origin pinning). The digest comparison cannot notice a manifest served selectively; the per-installation identity makes such dials *attributable*, not impossible.

## How it is verified — and what is not

Verified: `policy_test.rego` 41/41 on the pinned OPA (including the regression that a rug-pulled name dies at drift, not at the grant leg); the live matrix through the canonical stack (07/08 exploits, both modes, exit codes asserted); fault **F4** — the publisher made unreachable *from the gateway* while the fixture stays up for the exploit's own channel — every marketplace exploit exits 2 naming the unfetched manifest, never reading the fail-closed deny as a held control; three sabotage checks (drop the leg, fail-open the absent fact, drop the consent channel) each caught.

Not verified: no test flips the fixture *between* two calls of the same session (the window above); no test serves per-install-differentiated manifests.

## Where it would silently rot

- **The re-fetch.** Any "optimization" that caches the manifest, moves the check to install time, or batches it per session deletes the control while every test still passes — the fixture serves one constant state per run. The fault F4 case is the tripwire: it fails if the fetch ever stops being per-call, because the drift check would start answering from a cache the fault cannot poison... which is exactly why the F4 *cause* string must keep naming the fetch, not the denial.
- **The leg order.** A reorder that puts drift after the grant leg reproduces the original bug found live: the name dies as `org_grant_absent`, true and useless. The regression case exists because this exact rot happened once already.
- **`manifest_fetched` leaving the record.** The field is what makes the run's judgment honest; a "cleanup" that drops it turns an outage into a silent pass.

## Drift found while writing

The first implemented order answered the rug-pulled name `org_grant_absent` — the drift leg sat after the grant leg and buried its own thesis. Found live in the T5 matrix, corrected before the policy landed, pinned by a test.
