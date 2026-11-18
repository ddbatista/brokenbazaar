# The authority to change the delegation is not delegable

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

**Requirements:** SR-B3-7 (control-plane actions are not delegable to a session, regardless of the requesting user's role), SR-B8-2 (control-plane actions are refused by an explicit rule), SR-B8-7 (every role change is an audited event with actor, before and after) · **Module:** M3
**Kills:** finding 06 · **Carries:** M3-N1 / R-M3-2, M3-N4 / R-M3-3
**Code:** `gateway/policy/policy.rego` (`non_delegable`, the `control_plane_not_delegable` leg), `app/api/routes.go` (no internal route for the tool, by omission), `app/store/membership_org.go` (`SetMemberRole` and its audit row). The policy refusal and the absent route are hardened mode; the audit row ships in both modes.
**Status:** shipped, verified in CI in both modes. Enforced twice, by two mechanisms that fail differently.

Narrative: [`writeups/06-policy-plane.md`](../writeups/06-policy-plane.md). Requirement: [`threat-models/m3-delegation.md`](../threat-models/m3-delegation.md) D6.

---

## 1. What it is

Some actions change **who holds authority** rather than using it. A role assignment is the input every later authority check reads, so an agent that can change roles can change what every session in the org is allowed to do next. M3 has one such action, `set_member_role`. The rule, which the baseline derived three times (SR-B3-7, SR-B8-2, SR-B9-10) and AGENTS.md states as its B8 line:

> **Authority is delegable; the authority to change the delegation is not.**

**By policy.** The gateway policy carries a constant, not data:

```rego
non_delegable := {"set_member_role"}
```

Its check is the second leg, immediately after `unknown_tool` and before every session, grant and role leg. A call to a listed tool is denied `control_plane_not_delegable` whoever the requester is, whatever the session's scope, and whatever its role. The tool stays in `data.tools`, so it is a *known* tool refused by name, and it is granted to no org.

**By structure.** The API has no internal execution route for `set_member_role`, and the gateway has no client for one. An allow could not execute.

**The human path stays open.** An admin changing a role directly (`PATCH /orgs/{org}/members/{user}`) is allowed. The action is not forbidden; only its delegation is. Both paths, and the vulnerable agent's, write the change and its `role_changes` row in one transaction. The row names the actor user, and the session when an agent made it.

## 2. Options considered

**A: Rely on the ceiling from 05.** Rejected; this is finding 06. The ceiling stops a viewer's agent. An admin's agent steered into an admin act passes every leg: the requester may change roles, and the session asked for the tool. A ceiling bounds *how much*; it cannot say *which acts*.

**B: Do not implement the tool.** Rejected by the requirement's own words: refused by an explicit rule, *"not by the accident of nothing being implemented yet"*. A missing feature is a schedule, not a control. The next sprint implements it, and nothing records that its absence was load-bearing.

**C: Encode it in the role table: admins may change roles, except through an agent.** Rejected. There is one permission table, used by both the direct routes and the agent path (05's control). That clause would be the only entry whose meaning depended on who asks. Delegability is a property of the **action**, not of the role, so it gets its own leg with its own reason. That reason is also what detection reads: `control_plane_not_delegable` is an attempt (R6), distinct from an ordinary role refusal.

**D: Put the denylist in policy data (`data.json`) beside the tool list.** Rejected. Data is the half of the policy a deployment is expected to vary. A constant in the Rego module means changing the list is a change to the policy's logic, reviewed as such. A test pins it: data that tries to empty the list changes nothing.

**E: Policy only, or structure only.** Rejected; both. They fail differently. The policy entry is one line in a hardened, reviewed file. The absent route is a whole handler, a client and a red test away. Either alone is one mistake from gone.

**F: Require a human approval step for agent-proposed role changes.** Not taken in M3. It is the product answer for a real admin console ("your assistant suggests promoting Mallory; approve?"). But an approval issued through the same agent session is the same delegation with an extra click, and the approval path would need its own B8 design. Recorded as the direction a product would go, not built in a lab with one control-plane tool.

## 3. What it costs

- **No agent can help with access administration at all**, not even an admin asking their own agent, in their own words, to make a change they could make directly. That is deliberate, and it is a real cost to a real product. Option F is the way to pay less of it.
- **Two places to keep in step.** A new control-plane tool (an org-grant editor, a policy setting) must be added to the constant **and** kept off the internal route table. The second is enforced by a test that reads the first.
- **An unknown session hides the reason.** A `set_member_role` call naming a session the API does not know fails enrichment before the policy runs, and is recorded `enrichment_failed`. Fail closed either way. The pre-record still names the tool, and R4 (which reads the call, not the reason) still alerts.

## 4. What it does not cover

- **A compromised agent process** (M3-N1, R-M3-2). The agent's database credential can write `memberships` and `role_changes` directly. No gateway rule sees SQL, and no detector sees a change made outside the product. The fix is a database-role split, which touches `docker-compose.yml` and reverses M1 D2 for one principal. Recorded as a follow-up, not claimed.
- **Data-plane acts steered by the same document** (M3-N4, R-M3-3). *"Delete document X"* in a document an admin's agent reads passes this control: deleting a document is not a control-plane act. Only session scope limits it today; argument-level provenance is M4b's.
- **Other control-plane surfaces.** M3 has exactly one control-plane tool. Platform policy has been deploy-only since M2 (SR-B8-3), and org grants live in `data.json`, not in a table the agent can reach through the product (D9). M4a's install flow is the next control-plane surface, and it inherits this document.
- **Removing a member** (M3-N3). No removal path exists. The first one built must tombstone or revoke-and-retain, never cascade, or it erases the record this control's audit relies on.

## 5. How it is verified

| Evidence | Where |
|---|---|
| 06 exits 1 hardened (`control_plane_not_delegable`, decided on `role_now: admin` so the role leg cannot be the reason), 0 vulnerable (mallory logs in again and her direct delete returns 204) | `attacks/06-policy-plane/`, CI on every pull request and push to main |
| Positive control in both modes: the owner's direct role change is allowed, then reverted | `exploit.py` |
| The leg denies even when granted, in scope and admin; it outranks every session leg; no org grants a listed tool; data cannot empty the list | `gateway/policy/policy_test.rego` (`test_non_delegable_even_when_granted_in_scope_and_admin`, `test_delegability_comes_before_every_session_leg`, `test_no_org_is_granted_a_non_delegable_tool`, `test_the_denylist_is_not_policy_data`) |
| No internal route for any listed tool: every method, both route shapes, both modes, the mux's own 404, beside a positive control that the probe reaches document routes | `app/api/non_delegable_test.go` (`TestNonDelegableToolsHaveNoInternalRoute`, which parses the policy's list) |
| An allowed `set_member_role` still cannot execute: the gateway has no client for it | `gateway/test_gate.py` (`test_an_allowed_set_member_role_still_cannot_execute`) |
| Detection, both modes: R4 the call; R5 the agent-made change (vulnerable); R6 the refusal (hardened) | `detections/README.md` (M3) |

## 6. Where this control would silently rot

1. **A second control-plane tool added to `data.tools` and not to the constant.** Nothing knows a tool is control-plane except the list. An org-grant editor exposed as an agent tool would pass delegability, and the role leg would let an admin's agent use it. **Highest-probability rot in M3**, because the tool would look like any other. The defence is that the list is a reviewed edit in a hardened file. It is a review, not a mechanism.
2. **The structural test reads the policy's list.** If a tool is removed from the list, the test stops probing for its route. That removal is a one-line policy diff, and both halves go with it.
3. **The direct role route has no last-admin guard.** An admin can demote the last admin, including themselves. This is not this control's failure, but it is a control-plane footgun on the path this control deliberately leaves open. Recorded as a follow-up.
4. **The vulnerable build's honesty is load-bearing for detection.** Its `set_member_role` writes the audit row with the session. A refactor that "simplifies" the vulnerable executor to call the store without an actor would make R5 blind in exactly the mode where the change happens.

## 7. Note for M6

The tool, its vulnerable path, the absent route and its structural test, and the exploit were written by the coding agent under AGENTS.md gates. The policy constant and its tests were drafted by the agent in an issue (#17) and applied by hand. The re-shape that made 06 this finding was found while the agent was deriving the threat-model diff (T1). The original tenant egress setting could not show causation in a build with no gateway. See [`attacks/06-policy-plane/ANSWER-KEY.md`](../attacks/06-policy-plane/ANSWER-KEY.md).
