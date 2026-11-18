# The session names; it never grants

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

**Requirements:** SR-B3-3 (authority re-derived at action time), SR-B3-8 (the agent never exceeds its user), SR-B3-5 (least-privilege sessions), SR-B3-4 (expiry), SR-B3-9 (the authority relied on is recorded) · **Module:** M3
**Kills:** finding 05, both variants · **Carries:** M3-N2, M3-N5, R-M3-1
**Code:** `app/authz/authority.go` (`Derive`, `Legs.Failing`), `app/api/internal_tools.go` (the authority route and `authorize`), `gateway/authority.py` and `gateway/gate.py` (enrichment), `gateway/policy/policy.rego` (the legs). Behind `HARDENED`.
**Status:** shipped, verified in CI in both modes and under fault injection. The re-check at execution is unit-tested, not replayed; see §5.

Narrative: [`writeups/05-confused-deputy.md`](../writeups/05-confused-deputy.md). Requirement: [`threat-models/m3-delegation.md`](../threat-models/m3-delegation.md) D3, D4, M3-N2, M3-N5.

---

## 1. What it is

On every tool call, the gateway asks the API for the session's authority **now** (`GET /internal/sessions/{id}/authority?tool=…`). The API reads the session row and the requester's **current** membership, and computes three legs with one function, `authz.Derive`:

| leg | true when | from |
|---|---|---|
| `within_time` | now is strictly before the session's expiry | `sessions.expires_at` |
| `in_scope` | the tool is in the scope the session requested when it opened | `sessions.scope` |
| `role_permits` | the requester's role now permits the tool's action | `memberships`, through the **one** permission table the direct routes use |

The policy turns the first failing leg into its own reason (`session_expired`, `not_in_session_scope`, `role_does_not_permit`). The org's grant leg (`org_grant_absent`) comes from policy data, not from this function.

Then the API's execution route, before it touches the store, **derives the same legs again** (`authorize`). A refusal there is recorded by the gateway as the outcome `refused_at_execution`, with the leg as its summary.

The agent's own payload names the session and nothing more. Its `org` and `acting_for` fields are ignored. Both come from the session row.

The thesis in one line: **the agent is a ceiling, never a source.** It may do what its user could do directly, as of the moment it acts.

## 2. Options considered

**A: A per-session capability token.** The plan's original Defend line: mint the intersection of role, grants, scope and time when the session opens, and check it per call. **Rejected, and this is the rejection the module is built on.** A token that carries the capability set caches authority. A demotion after minting does not reach it, which is precisely finding 05's variant (ii). SR-B3-3 already forbade it, and the plan contradicted its own requirement. Caught at planning, before the threat-model diff or any code.

**B: Resolve once at session creation, store the role on the session row.** The same cache with a database instead of a signature. Rejected for the same reason. It is also the build variant (ii) exists to catch: it passes (i) and fails (ii).

**C: Re-derive per action, in the gateway only.** Almost the control, and it has a gap. The gateway decides, then calls the execution route. A demotion landing between the two is allowed by a decision that was correct when made. That is TOCTOU for authority, the same shape as B5 4.3's TOCTOU for URLs. With C, SR-B3-3 holds per **decision**, not per **action**.

**D: Re-derive at the gateway and again at execution, with one function.** Chosen. The execution route's check is the one SR-B3-3 relies on. The gateway's is earlier, cheaper, and the one whose reason the audit record carries. The second check is not defence in depth; without it the requirement is not met.

**E: Rewrite the role semantics in Rego, beside the other legs.** Rejected. Two copies of "what a viewer may do" drift, and the direct API would answer one question while the agent path answered another. The role leg is computed in Go and passed to the policy as a boolean. The one Rego-native leg, org grants, is platform policy, not role semantics.

**F: Check the requested scope against the role at creation.** Rejected (M3-N5). It is "resolved once" again, it reads as if authority were settled, and it would move variant (i)'s denial to the session's birth. Then (i) and (ii) would stop testing the same leg. Scope is consent; it narrows and never authorizes.

**G: Sign a per-session credential so a compromised agent cannot present another session's ID.** Deferred (R-M3-1). The attacker it stops already holds the agent process, which is R-M2-3's severity class.

## 3. What it costs

- **One extra round trip and two extra database reads per tool call.** The round trip is the gateway's authority lookup. The reads are that lookup's and the execution route's re-check, inside the call M2 already made. M2's gateway trusted the agent's payload for the session's org and user, and paid none of it. Stated plainly, because a control doc that pretends its control is free is not evidence of anything.
- **The API is now on the decision path.** If the authority route is unreachable, the gateway fails closed with `enrichment_failed` and the detail `authority route unreachable`. Every agent call is refused, read-only ones included. Availability bought with correctness, and measured: fault F3 in `make faults`.
- **An unknown session masks the policy's reasons.** A call naming a session the API does not know fails enrichment before the policy runs, so even a `set_member_role` call is recorded as `enrichment_failed`, not `control_plane_not_delegable`. Fail closed either way; the pre-record still names the tool.
- **The record can read `allow` then `refused_at_execution`.** Honest, not inconsistent, but a reader has to know that both are true at their moment.

## 4. What it does not cover

- **An in-role, in-scope write steered by a document** (M3-N4, R-M3-3). The ceiling allows it: nothing exceeds anyone's authority. Only session scope limits it today.
- **An admin's agent steered into an admin act.** Finding 06. The role leg *allows* `set_member_role` for an admin, on purpose. The rule that refuses it is a different control: [`the-authority-to-change-the-delegation.md`](the-authority-to-change-the-delegation.md).
- **Session-ID forgery by a compromised agent** (R-M3-1), option G.
- **A role changed by direct SQL** (R-M3-2). The control reads `memberships` faithfully. Whoever can write that table can change the answer, and the agent's database credential can.

## 5. How it is verified, and the half that is not

| Evidence | Where |
|---|---|
| 05 (i) and (ii) exit 1 hardened (`role_does_not_permit` on both), 0 vulnerable; (ii) also requires the session's records to read `role_now` admin first and viewer last | `attacks/05-confused-deputy/`, `attacks/run.py`, CI on every pull request and push to main |
| Positive controls in both modes: an admin's agent delete and a member's agent update are **allowed** and take effect. Without them, a role leg that denied everything would print the exact reason asserted. | `exploit.py`'s `positive_controls` |
| Every leg allows and denies alone; `Failing()` matches the policy's leg order; every policy tool has an action | `app/authz/authority_test.go` |
| The execution routes re-check and never write on a refusal | `TestInternalToolsRecheckAndNeverWriteOnRefusal` |
| A broken gate never reads as "control held": OPA removed, gateway stopped, authority route unreachable; every agent exploit exits 2 naming the fault | `make faults`, CI |
| Detection: R6 alerts on both hardened denials | `detections/README.md` (M3) |

**The re-check at execution is not exercised end to end.** It needs a demotion landing inside the few milliseconds between the gate's decision and the write. No replay can land that deterministically, and a test that sleeps until it does is a flaky test. It is covered by unit tests on the route, and the detection leg that would see it (`refused_at_execution`) is unit-tested only. A reader who assumes 05 (ii) proves the execution check is wrong. (ii) proves per-**decision** re-derivation; the race is a separate claim with separate evidence.

## 6. Where this control would silently rot

1. **A new execution route that forgets `authorize`.** The re-check is a call each handler makes, not a property of the route table. Every current route is tested, but a fourth write tool added with its own handler is not reached by any existing test. **Highest-probability rot in M3.** The structural fix is a route constructor that cannot register an internal tool route without the re-check, which is M1's `ForOrg` argument applied to routes.
2. **`toolActions` grows by hand.** A tool missing from the map fails the role leg, so the failure is closed. But a tool mapped to the wrong action (an admin act mapped to `Update`) would grant a member what an admin may do, and compile. `TestEveryPolicyToolHasAnAction` pins coverage, not correctness.
3. **The org's grants live in policy data, not in this function.** A new tool must be added in three places in two languages: the permission map in Go, and `data.tools` and the org's grants in `gateway/policy/data.json`, a hardened zone. `TestEveryPolicyToolHasAnAction` catches a tool in the policy with no action; nothing catches a tool given an action and no grant, which fails closed.
4. **Multi-org.** A user is a member of one org today. The authority route resolves the role from `(session.org, session.acting_for)`, which stays correct, but every caller that assumed "the user's role" rather than "the user's role **in this org**" becomes wrong the day multi-org ships.

## 7. Note for M6

The control, the vulnerable executor it replaces, and the exploit that measures both were written by the coding agent under AGENTS.md gates. The policy legs were drafted by the agent in an issue (#15) and applied by hand, because `gateway/policy/` is a hardened zone. The decision this document is built on, rejecting the capability token, was made at planning (2026-11-09), when the plan was read against the code and the baseline before any decision was taken. See [`attacks/05-confused-deputy/ANSWER-KEY.md`](../attacks/05-confused-deputy/ANSWER-KEY.md) for what that record does and does not support.
