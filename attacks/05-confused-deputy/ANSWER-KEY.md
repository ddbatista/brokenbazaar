# Answer key — finding 05, the confused deputy

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

Published with M3, per the decisions log: this is a walkthrough, not a CTF. A reader who cannot see which bug was planted cannot verify that the control actually addresses it.

**Finding:** 05 · **Boundary:** B3 (User → Agent), B5 (Agent → Tools) · **Leaves:** B3 1.2 / 4.1 (variant i), B3 1.3 (variant ii) · **Module:** M3 · **Frameworks:** `LLM06:2025` (Excessive Agency) · `ASI03 2026` (Identity and Privilege Abuse) · `A01:2021` (Broken Access Control)

The attack and the control are described in [`README.md`](README.md). The argument is in [`writeups/05-confused-deputy.md`](../../writeups/05-confused-deputy.md), and the design in [`defenses/the-session-names-it-never-grants.md`](../../defenses/the-session-names-it-never-grants.md). This file records what only it can: **which commit planted what, and who wrote it.**

---

## The planted bug, by commit

| Commit | Date | What it planted |
|---|---|---|
| `34e69e6`, *M3 T4: the confused deputy* | 2026-11-16 | `update_document` and `delete_document` in the vulnerable executor (`app/agent/executor_vulnerable.go`). They run in-process through `store.ForOrg(session org)`, with the agent's own database access. They check the tool's **name** against `naiveAllowedTools` and nothing else: not the requester's role, not the session's scope. The same commit taught `ScriptedModel` the write imperatives (`delete document <id>`). |

**What it builds on, and does not re-plant.** The vulnerable executor arrives with M2: a stub in `19d8a86` (M2 T3), and in-process execution with its name-only allowlist `naiveAllowedTools` in `b2018c7` (M2 T4). That is two baseline leaves: B5 2.1, *"a first-party tool bypasses the gateway because it is internal"*, and B5 3.2, *"allow/deny on the tool name alone"*. They are findings 03 and 04's planted bugs, and M2's answer keys for 03 and 04 own their attribution. M2 gave the agent only `read_document` and `http_fetch`, which any role may use. So until `34e69e6` there was nothing for the deputy to do that its user could not.

**What made it a finding rather than a missing feature.** `ce0183e` (*M3 T3*, 2026-11-13) gave roles teeth on the **direct** API, in **both** modes: a viewer's `DELETE` is a 403 whether or not the build is hardened (M3 D1). From that commit on, the agent path is the only path where a viewer's delete succeeds. The planted bug lives in exactly one place.

**Variant (ii) needed no second bug.** The vulnerable executor never reads a role, so a demotion changes nothing for it. (ii) exists for the hardened build: it fails any design that resolves authority once, when the session opens. To run it, the agent gained `-session S -message M` (a user's next turn in an existing session) in `6bd1e51`, with the exploit.

## Why a real developer writes this

Every piece of it is ordinary. The executor already has an allowlist of tools, so adding two names to it is a two-line change. The writes go through `ForOrg(session org)`, so tenancy is correct: the agent cannot touch another org's documents. That is the property M1 taught everyone to check, and it holds. The session row records `acting_for`, so the audit trail can always say whom the agent acted for.

Nothing reads that field before acting. The reasoning is the same as M1's *"I already verified the user"*. The user was authenticated when they opened the session, so the agent is acting for a real member of the org. Membership is checked; capability is assumed.

## The control, and where it lives

`6e8346e` (*M3 T6: hardened authority*, 2026-11-16):
- `app/authz/authority.go`: `Derive` computes the three legs from the session row and the requester's **current** role, against the one permission table (`authz.Permits`) the direct routes use.
- `app/api/internal_tools.go`: the authority route (`GET /internal/sessions/{id}/authority`), and `authorize`, the execution routes' re-check before any write (M3-N2).
- `gateway/authority.py`, `gateway/gate.py`: the gateway enriches every call from the authority route and ignores the agent's own `org` and `acting_for`. A refusal at execution is recorded as the outcome `refused_at_execution`.

`d905f47` (*M3 T6: per-session authority legs + org grants in the gateway policy*, 2026-11-16): the Rego legs (`session_expired`, `not_in_session_scope`, `org_grant_absent`, `role_does_not_permit`) and the org grants in `data.json`. `gateway/policy/` is a hardened zone. The diff was proposed in issue #15 and applied by hand.

Mode selection is the agent binary's build tag (`GatewayExecutor` posts every call to the gateway; `NaiveExecutor` never does), plus the gateway's own `HARDENED` flag.

**A recorded departure from the house rule.** AGENTS.md's rule is *write the correct implementation before the vulnerable one*. Here the vulnerable write tools (`34e69e6`, T4) landed before their hardened path (`6e8346e`, T6). What existed first was the design (m3-delegation.md D3, D4) and the permission table the control calls (`app/authz`, T3). The executor's doc comment says so, and the plan records the departure at T4.

## Attribution — the M6 dataset

| Artifact | Author | Evidence |
|---|---|---|
| The write tools in the vulnerable executor (the planted bug), `34e69e6` | **Agent** | `Co-Authored-By` agent trailer; agent session for M3 T4 |
| Roles on the direct API, both modes (what makes it a finding), `ce0183e` | **Agent** | trailer; agent session for M3 T3 |
| `authz.Derive`, the authority route, the execution re-check, the gateway's enrichment (the control), `6e8346e` | **Agent** | trailer; agent session for M3 T6 |
| The policy legs and org grants (the control's Rego half), `d905f47` | **Agent-drafted, applied by hand** | No trailer on the commit. The diff and its SHA-256s were drafted in the agent session and filed as issue #15; the human applied them as their own commit, and the agent verified the hashes afterwards. |
| `exploit.py`, its README, and `-session/-message`, `6bd1e51` | **Agent** | trailer; agent session for M3 T8 |
| This file | **Agent-drafted, applied by hand** | `attacks/*/ANSWER-KEY.md` is a hardened zone; drafted in the agent session, filed as an issue, applied by the human |

**Why a third value.** M1's table had two: agent, or by hand. M3 has commits with no agent trailer whose every line was written by the agent, because the repo's hardened zones make a human apply them. Recording those as "by hand" would be false. Recording them as "agent" would erase the human gate the repo exists to demonstrate. The gate does not make the human the author. It makes the human the one who decided the diff could land.

**Evidence basis.** Agent authorship is evidenced by a `Co-Authored-By` trailer and an agent session transcript for the task, which agree. "Applied by hand" is evidenced by the missing trailer, the issue the diff was filed in, and the plan's per-task note naming the issue and the commit.

**The honest reading, and what it constrains.** The agent did not introduce this bug unprompted. `threat-models/m3-delegation.md` specified it (D2, D5), and the agent was told to read that diff before writing. The record supports this: *an agent, given a threat-model diff that specified a confused deputy, reproduced it faithfully, and built and tested the control that kills it.* It does not support any claim about agents introducing authorization bugs on their own.

One datum that is about the process and not the instruction. The plan's own Defend line, a per-session capability token minted at creation, contradicted requirement SR-B3-3. It was caught at planning (2026-11-09), in the step that reads the plan against the existing code and the baseline before any decision is taken. It is recorded there as finding 6 of 7, and D3 amended the plan before the threat-model diff (`7101450`) or any code existed. Variant (ii) is the regression test for that amendment. The catch came from a step designed to make such contradictions visible. It is evidence that the step works, not that an agent would have raised it unasked.
