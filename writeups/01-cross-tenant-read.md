# Tenant isolation is a data-layer property, not a handler-layer one

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Every vulnerability in it is intentional and documented. Run it on localhost only.

*Finding 01 — cross-tenant read · boundary B2 · A01:2021 (classic Broken Access Control — no AI-standard home, and saying so is the honest tag).*

## The most boring attack in the repo

An admin of Globex logs in — honestly, with the real password — and searches their own organization's documents:

```
GET /orgs/<globex-org-id>/documents?q=confidential
```

A perfectly honest request from a perfectly honest principal. The response contains three documents: Globex's, **and Acme's, and Initech's** — each titled `<Org> — confidential Q3 plan`, each with a body that says *"This document belongs to Acme Corp and must not be readable by any other org."*

No forgery. No privilege escalation. No clever payload. The exploit's entire trick is that there is no trick — and that is the finding: **the distance between "my documents" and "everyone's documents" was one missing `WHERE` clause that nothing forced anyone to write.**

## The bug is sibling-shaped

The vulnerable search runs this statement:

```sql
SELECT … FROM documents WHERE title ILIKE $1 OR body ILIKE $1
```

No org predicate. Its sibling, the *list* handler, remembers the rule — it filters the results in Go after the query. Two paths to the same table, one remembers tenancy, one doesn't.

This is the most common real-world shape of tenancy failure, and it has a property worth sitting with: **the defect is invisible in a code review of the diff that introduced it.** The diff adds a search endpoint; the reviewer reads search logic, not tenancy. The list endpoint nearby already "proves" scoping works. Nothing about the new code is wrong *as search code* — it is wrong as *tenancy code*, and that's not the lens the diff invites.

## Why the fix is not "remember the predicate"

The obvious fix — add `AND org_id = $2` to the query, review harder — is the handler-layer answer, and it fails the same way the bug did: it makes scope a rule someone must remember, per endpoint, forever. M1's control is structural instead:

```go
func ForOrg(pool *pgxpool.Pool, orgID string) *OrgStore
```

`OrgStore` is the only store that can reach documents, and **it cannot be constructed without an org**. Every statement it runs carries that org in its `WHERE` clause because the org is a field of the type, not a parameter a caller supplies per request. The `DocumentStore` interface takes no `org_id` argument on any method — scope is a property of *which implementation, which instance* answers the call.

An endpoint cannot forget a predicate it has no way to omit. That is what "tenant isolation is a data-layer property" means in practice: move the invariant from convention to construction.

Two consequences fall out of the same design, not from extra work:

- **The uniform 404.** "Wrong org" and "no such document" become the same empty result from the same query — an attacker cannot distinguish *doesn't exist* from *not yours* (no existence oracle, no cache-difference oracle), because the two cases never separate in the code.
- **The seed is scoped too.** Even the bootstrap code that creates the first rows goes through `ForOrg`, one handle per org — because an invariant that reads "true except in the seed" was never an invariant.

## What detection sees: nothing, and that is the lesson

We measured it. Replaying this finding against the hardened stack, the attack is blocked — and the detection rule on authz denials **misses it**, by design. The control kills the request inside the scoped query, which is *silent*: no denial is logged, because logging one would reintroduce the very distinction the uniform 404 exists to remove.

In vulnerable mode the detector misses it for the opposite reason: the attack succeeds, and a successful cross-tenant read looks identical to an authorized one.

That is not a rule failure. It is the structural truth that **a denial-based detector is coupled to the control working — and only sees the attacks the control chose to make loud.** Which is why the regression suite (both exploits run in both modes in CI, asserted exit codes) and the detector are complementary mechanisms: the suite catches the day the control stops working; the detector catches the live attacker probing a working system. Neither covers the other's world.

## The generalizable claim

Scope enforced at the handler layer is a rule; scope enforced at the data layer is a fact. Rules are forgotten exactly when attention is elsewhere — the sibling endpoint, the new feature, the 3 a.m. incident patch. Facts are forgotten by no one, because they don't need remembering.

If your tenancy tests live in your handlers, you have as many chances to fail as you have endpoints. If they live in your store constructors, you have one, and everyone's code reviews it.

---
*Planted in `cd44140` (store layer), made reachable in `9ba4b2d` (handlers). Control: `app/store/document_org.go` (SR-B2-1). Exploit: `attacks/01-cross-tenant-read/` — exits 0 on the vulnerable stack, 1 on hardened, asserted in CI on every push.*
