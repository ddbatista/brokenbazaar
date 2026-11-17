# Answer key — finding 06, the policy plane

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

Published with M3, per the decisions log: this is a walkthrough, not a CTF. A reader who cannot see which bug was planted cannot verify that the control actually addresses it.

**Finding:** 06 · **Boundary:** B3 (User → Agent), B8 (control plane ↔ data plane) · **Leaves:** B3 4.2 / B8 1.2, via B4 1.1 · **Module:** M3 · **Frameworks:** `LLM01:2025` (Prompt Injection, the vector) · `LLM06:2025` (Excessive Agency) · `ASI01 2026` (Agent Goal Hijack) · `ASI03 2026` (Identity and Privilege Abuse) · `A01:2021` (Broken Access Control)

The attack and the control are described in [`README.md`](README.md). The argument is in [`writeups/06-policy-plane.md`](../../writeups/06-policy-plane.md), and the design in [`defenses/the-authority-to-change-the-delegation.md`](../../defenses/the-authority-to-change-the-delegation.md). This file records what only it can: **which commit planted what, and who wrote it.**

---

## The planted bug, by commit

| Commit | Date | What it planted |
|---|---|---|
| `e566749`, *M3 T5: set_member_role* | 2026-11-16 | `set_member_role` added to the vulnerable executor's `naiveAllowedTools` and run in-process (`setMemberRole` in `app/agent/executor_vulnerable.go`) through the org-bound `SetMemberRole`, on whatever user and role the model asked for. The same commit taught `ScriptedModel` the imperative `set role of user <id> to <role>`. |

**The rest of `e566749` is not the bug, and is half of what makes 06 measurable.**
- **The direct role route** (`PATCH /orgs/{org}/members/{user}`, `app/api/members.go`): admin-only in both modes, so a human admin's change is the positive control.
- **The one store method** (`OrgStore.SetMemberRole`, `app/store/membership_org.go`): it writes the change and its `role_changes` row in one transaction, on an org-bound handle (M3-N1's acceptance criterion).
- **The attribution.** The vulnerable path records the acting user **and** the session (SR-B3-9, SR-B8-7). The vulnerable build is wrong about *whether* to make the change and faithful about *recording* it. That is why detection can measure a hit there rather than a silence (R5).

**What 06 inherits from 05.** The vulnerable executor's gateway bypass and name-only check (B5 2.1 and 3.2, M2's `b2018c7`) and its in-process writes (`34e69e6`, finding 05). 06 adds one tool to that executor. The finding is that this tool must never be on **any** agent's list, whatever the requester's role.

## Why a real developer writes this

The admin console needs a "change role" action, so the route gets built. The assistant should be able to do what the admin can do; that is the product's pitch. So the tool goes on the agent's list beside `update_document`. If someone builds the 05 control first, the admin's agent passes it: an admin may change roles. Nothing looks wrong, because nothing exceeds anyone's authority.

The missing idea is a category, not a check. A role is not data the agent works on. It is the input to every later authority decision.

## The control, and where it lives

`fe8aaee` (*M3 T7: hardened non-delegability*, 2026-11-16): **by structure.** No internal execution route exists for `set_member_role`, and the gateway has no client for one. `app/api/non_delegable_test.go` parses the policy's list and probes every method on both route shapes, in both modes, beside a positive control. `gateway/test_gate.py` checks that an allowed call still cannot execute.

`c7428c3` (*M3 T7: non-delegable denylist in the gateway policy*, 2026-11-16): **by policy.** `non_delegable := {"set_member_role"}` is a Rego constant, not data. Its leg runs right after `unknown_tool`, and it denies `control_plane_not_delegable` whatever the session, scope or role. The commit added 7 policy tests, taking the suite from 24 to 31. They include: data cannot empty the list, no org is granted a listed tool, and the leg outranks every session leg. `gateway/policy/` is a hardened zone. The diff was proposed in issue #17 and applied by hand.

**A recorded departure, and a process slip.** As with 05, the vulnerable tool (`e566749`, T5) landed before its control (`fe8aaee` and `c7428c3`, T7); the design came first (D6). Separately, while producing the policy diff for issue #17, the agent briefly copied the draft into `gateway/policy/` and restored it with `git checkout`. That was a transient write to a hardened zone, recorded in the plan at T7. Since then, hardened-zone diffs are generated with `git diff --no-index` against a scratch copy, never in the tree.

## Attribution — the M6 dataset

| Artifact | Author | Evidence |
|---|---|---|
| `set_member_role` in the vulnerable executor (the planted bug), the role route, `SetMemberRole` and its audit row, `e566749` | **Agent** | `Co-Authored-By` agent trailer; agent session for M3 T5 |
| No internal route and its structural test (the control's structural half), `fe8aaee` | **Agent** | trailer; agent session for M3 T7 |
| The `non_delegable` constant, its leg and its tests (the control's policy half), `c7428c3` | **Agent-drafted, applied by hand** | No trailer. Drafted in the agent session and filed as issue #17; the human applied it as their own commit, and the agent verified the hashes. |
| `exploit.py` and its README, `6bd1e51` | **Agent** | trailer; agent session for M3 T8 |
| This file | **Agent-drafted, applied by hand** | hardened zone; filed as an issue, applied by the human |

The three values, and why the middle one exists, are explained in [finding 05's answer key](../05-confused-deputy/ANSWER-KEY.md#attribution--the-m6-dataset).

**The honest reading.** As with 05: the agent reproduced a finding the threat-model diff specified (D6). The record says nothing about agents inventing control-plane bugs on their own.

**One datum that is about the process, not the instruction.** 06 was originally a different finding: a per-org egress setting that a tenant admin could widen. While deriving the threat-model diff (T1, `7101450`), the agent found that the vulnerable build has no gateway at all (M2 D5). So the setting would "succeed" in vulnerable mode whether or not it changed, and a negative control would prove it was not the cause. The finding was re-shaped into this one before any code existed, and the plan was amended (D6, with the rejected options on record). That was M2 D1a's causation rule, that every finding needs a negative control showing its input is the cause, failing on paper rather than in a PoC.
