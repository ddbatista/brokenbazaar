# Finding 05 — the confused deputy: the agent does what its user cannot

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

**Boundary:** B3 (User → Agent, delegated authority), B5 (Agent → Tools) · **Leaf:** B3 1.2 / 4.1 (variant i), B3 1.3 (variant ii) · **Frameworks:** LLM06:2025 (Excessive Agency) · ASI03 2026 (Identity and Privilege Abuse) · A01:2021 (Broken Access Control)

## What it does

Nothing is injected and nothing is forged. Each user asks the agent, in their own words, for something they may not do themselves. The question is whose authority the agent acts with.

```
make up && make migrate && make seed
python3 attacks/05-confused-deputy/exploit.py   # exit 0 — both deletions take effect
JWT_SECRET=… TOOLS_SECRET=… make harden
python3 attacks/05-confused-deputy/exploit.py   # exit 1 — (i) and (ii): gateway denied: role_does_not_permit
```

| Step | Vulnerable | Hardened |
|---|---|---|
| **negative control:** the viewer asks for a *summary* of the target | read, answer, no delete | read, answer, no delete |
| **positive controls:** the owner's agent deletes; a member's agent updates | both take effect | both **allowed** and take effect |
| **(i)** a **viewer** asks the agent to delete a document | **deleted**; the owner reads 404 | **`role_does_not_permit`**; the owner reads 200 |
| **(ii)** an **admin** opens a session and reads a document; the owner **demotes** them to viewer; the **same session's** next request is the delete | **deleted** | **`role_does_not_permit`**; the records read `role_now` admin, then viewer |

Both sessions ask for `delete_document` in their scope. Scope is consent, not authority (M3-N5), so the hardened denial is the **role** check's, not the scope check's.

## The bug: the agent never asks who it is acting for

The vulnerable executor (`NaiveExecutor`, B5 2.1) runs any tool on its allowlist with the agent's own database access. It reads neither the requester's role nor the session's scope. The direct API refuses a viewer's delete in **both** modes (D1). Only the path *through the agent* is broken, which is what makes the agent a deputy: it holds authority its user does not, and it uses it on their behalf.

## The control

In hardened mode, every call goes to the gateway, which asks the API for the session's authority **now**: the session row, joined to the requester's **current** membership, checked against the same permission table the direct routes use (`authz.Derive`). The agent is a **ceiling, never a source**: it may do only what its user could do directly (SR-B3-8). The execution route re-checks that authority before it touches the store (M3-N2).

## What (ii) is for

Against the vulnerable build, (ii) shows nothing (i) does not: that executor never reads a role at all. Its value is against a hardened build that resolved the role **once, when the session opened**. Such a build passes (i) and fails (ii). (ii) is the regression test that keeps "authority is re-derived per action" (m3-delegation.md D3) decided. It needs the session to take a **second request** after the demotion, which the agent supports with `-session S -message M`: the user's next turn in the same session.

## Evidence contract

- **Vulnerable:** for each variant, the owner reads the target through the **direct API** and gets 404. The deletion is observed by a principal entitled to see the document, never inferred from the agent's report. (ii) also prints the role when the session opened and after the demotion, both from the direct role route's answers.
- **Hardened:** `(i) gateway denied: role_does_not_permit` and `(ii) gateway denied: role_does_not_permit`, from the **defender's** record (`gateway.jsonl`). (ii) also requires the records to show `role_now` admin on the session's first decision and viewer on its last; otherwise it exits 2.
- **A deletion through either variant, in any mode, is exit 0.** A hardened build that held (i) and leaked (ii) is a control failing.
- **Positive controls, in both modes:** without them, a role check that denied everything would print `role_does_not_permit`, the exact string asserted here (plan M3 T0 D3). A positive control that does not take effect exits 2.
- **Exit 2** for anything else, including a fail-closed deny (`enrichment_failed`, `opa_unavailable`) and an agent that made no delete call.
- **Idempotent:** the roles it relies on are set at the start through the owner's direct admin route, and the deputy is restored to admin at the end. Documents are created per run and removed at the end. Sessions and audit records stay, per the contract.

## What this exploit does NOT show (declared)

- **A forged role.** Finding 02's forged token reaches the direct role route in vulnerable mode. That is 02's, not this finding's.
- **In-role, in-scope writes steered by untrusted content** (M3-N4, R-M3-3). A member's agent steered into an update the member may make is not refused by role, and is not this finding.

## Read next

The argument: [`writeups/05-confused-deputy.md`](../../writeups/05-confused-deputy.md). Why this control: [`defenses/the-session-names-it-never-grants.md`](../../defenses/the-session-names-it-never-grants.md). Which commit planted what, and who wrote it: [`ANSWER-KEY.md`](ANSWER-KEY.md).
