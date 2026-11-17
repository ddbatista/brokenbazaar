# How I redesigned my way out of a confused deputy

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Every vulnerability in it is intentional and documented. Run it on localhost only.

*Finding 05: the confused deputy · boundaries B3 (User → Agent) and B5 (Agent → Tools) · `LLM06:2025` Excessive Agency · `ASI03 2026` Identity and Privilege Abuse · `A01:2021` Broken Access Control.*

## Nobody attacks anything

A viewer opens the product's agent and types:

```
delete document 7f3c…
```

The document is gone. The org's owner reads it through the API a second later and gets a 404.

A viewer may read documents and nothing else. If the same viewer sends `DELETE /orgs/{org}/documents/7f3c…` to the API directly, it refuses with a 403, **in both builds**. The role check on the direct API is not the thing this finding plants. So the viewer could not do it, asked something that could, and it did.

Nothing was injected and nothing was forged. The user typed what they wanted in their own words. The only question this finding asks is **whose authority the agent acts with**, and in the first design the answer was its own.

## The before

The first agent (M2) was built the way agents usually are: a loop, a model, a set of tools, and a database connection. When the model asked for a tool, the executor checked the tool's name against an allowlist and ran it with the agent's own access.

That is a deputy in the 1988 sense. The agent holds authority its user does not, and it exercises that authority because its user asked. The executor knew the session and the user it was acting for. It never asked what that user was allowed to do. M2 recorded the gap honestly: every audit record carries `acting_for`, so the logs could always say *who* the agent was working for. They just never acted on it.

M3 gave roles teeth (viewer reads; member also creates and updates; admin also deletes and manages roles) and gave the agent two write tools. In the vulnerable build, the roles bind the direct API and nothing else.

## The redesign the plan called for

The plan said: issue the agent a **per-session capability token**, the intersection of the user's permissions, the org's grants, the session's requested scope and a time bound. Mint it when the session opens; check it on every call. It is the standard answer, it reads well in a design review, and it would have passed variant (i) of this finding.

It fails variant (ii):

1. An admin opens a session and asks for a summary. The token is minted: admin, may delete.
2. The owner demotes them to viewer.
3. The same session's next request is *"delete document 7f3c…"*. The token still says admin.

A token that carries the capability set **caches authority**, and a cache is wrong the moment its source changes. The baseline already had the requirement (SR-B3-3: authority is re-derived at action time, never cached at session creation), and the plan contradicted it in its own Defend line. That was caught while the module was being planned, before the threat-model diff or any code existed, and the plan was amended rather than the requirement.

## The design I shipped: the session names, it never grants

The session ID is the agent's identity, and that is all it is. It answers *which session is acting* and nothing else. On **every** tool call the gateway asks the API for that session's authority **now**:

```
GET /internal/sessions/{id}/authority?tool=delete_document
→ {"session": {…from the session row…}, "role_now": "viewer",
   "legs": {"within_time": true, "in_scope": true, "role_permits": false}}
```

Each leg comes from a live record:
- **Time:** the session's expiry.
- **Scope:** what the session asked for when it opened.
- **Role:** the requester's **current** membership, checked against the **same** permission table the direct routes use (`authz.Derive`).

The gateway's policy turns the first failing leg into a reason: `role_does_not_permit`. The agent's own claims about which org it is in, or whom it acts for, are ignored. Both are resolved from the session row.

Two consequences matter more than the mechanism:

- **The agent is a ceiling, never a source.** It may do what its user could do directly, and never more. There is one permission table, so "what a viewer may do" cannot mean one thing on the API and another through the agent.
- **The check that counts is the one at execution.** The gateway decides, then calls the API's execution route. A demotion landing between the two would be allowed by a decision that was correct when it was made. So the execution route re-derives the same legs before it touches the store. The audit record can honestly read `allow`, then `refused_at_execution`: both were true at their moment (M3-N2).

Variant (ii) is the regression test that keeps this decided. Against the vulnerable build it shows nothing variant (i) does not, because that executor never reads a role at all. Its value is against a **future** hardened build that resolves the role once, when the session opens. That build passes (i) and fails (ii), and CI says so on the next push. The hardened records for (ii) read `role_now: admin` on the session's first decision and `viewer` on its last.

## Consent is not authority

Both sessions in this finding **asked** for `delete_document` in their scope. The viewer's request was accepted when the session opened. Scope is the user's consent to what the agent may attempt, and it can only narrow. Refusing the request at creation looks stricter and is worse: it is "resolved once" again, it would read as if authority had been settled, and the per-action check runs anyway. The viewer's request is refused at the action, by the role check, with the role check's own reason.

## What detection sees

Measured on every `make detect`, in both modes. Hardened mode catches both variants: the gateway's `role_does_not_permit` denial is an attempt, and rule R6 alerts on it. **Vulnerable mode catches neither, and that is the finding's second lesson.**

To see 05 without the control, a detector needs to know what the acting user's role permitted **at that moment**. The vulnerable agent records who acted (`acting_for`), never what they were allowed to do. A rule could rebuild that role from the membership table and the role-change history. Then it would need to ask whether the role permits the tool, and that needs a second copy of the permission table, which this design exists to have exactly one of. So the miss is declared, not engineered away.

M2's detectors could judge an exfiltration from the fetch alone; a host off the allowlist is suspicious whoever asked. Authority is a **relation**, between the call and a fact about the caller, and the fact is one the control computes. Without the control, the telemetry knows who and what, but not "may they".

## The generalisable claim

An agent that acts with its own credentials is a confused deputy waiting for a user to ask. Narrowing it with a token minted at session start fixes the demo and keeps the bug, on a delay. The bug resurfaces the first time authority changes mid-session, which is exactly when it matters.

Make the session a name, and make every action ask again.

---
*Planted in `34e69e6` (the vulnerable executor's write tools). Control: `6e8346e` (`app/authz/authority.go`, the authority route, the execution routes' re-check, the gateway's enrichment) and `d905f47` (the per-leg policy, drafted by the agent in an issue and applied by hand). Design: [`defenses/the-session-names-it-never-grants.md`](../defenses/the-session-names-it-never-grants.md). Exploit: [`attacks/05-confused-deputy/`](../attacks/05-confused-deputy/). It exits 0 on the vulnerable stack and 1 on hardened, in CI on every push.*
