# Scope as a property of the handle

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

**Requirements:** SR-B2-1, SR-B2-5, SR-B2-6 · **Also serves:** SR-B2-4 (second half) · **Module:** M1
**Kills:** finding 01 (cross-tenant read), the IDOR at B2 2.1, and the second half of finding 02
**Code:** `app/store/document.go`, `app/store/document_org.go` — behind `HARDENED`
**Status:** shipped, verified in CI both modes

This file is indexed by **control**, not by finding, because this control is not 1:1 with a finding — it kills leaves across two of them and a third that is not separately numbered. The narrative version for an outside reader is [`writeups/01-cross-tenant-read.md`](../writeups/01-cross-tenant-read.md); the requirement it implements is in [`threat-models/m1-tenancy.md`](../threat-models/m1-tenancy.md) §1 D5 and §3. What is here and nowhere else: the options rejected, the cost, the residual, and **where this control would silently stop working.**

---

## 1. What it is, in one paragraph

`DocumentStore` declares six methods and **not one of them takes an `org_id` parameter**. `OrgStore` holds the org as a struct field, bound once by `ForOrg(pool, orgID)`, and every statement it runs interpolates that field. Scope is therefore a property of *which implementation, and which instance,* answers the call — never a value supplied per call site.

The whole design is the absence in the interface. A parameter can be passed correctly in one call site and omitted in its sibling; that is M1-N3, and it is what finding 01 is. A value baked into a constructor has no call site left where it could be supplied differently.

## 2. Options considered

**A — Add the predicate to each query; review harder.** Rejected. This is the handler-layer answer and it fails the way the bug failed: it makes scope a rule a human must remember, per endpoint, forever. `OrgStore.Search` and `NaiveStore.Search` are one call site each — the bug was never that search is harder to scope, it is that nothing forced it to be scoped twice.

**B — Postgres row-level security with a per-tenant role or `SET LOCAL`.** Rejected deliberately (D2, residual R-M1-1). The lab's thesis is that tenancy is a data-layer property of the *application's* data layer, and a second enforcement mechanism underneath would make it impossible to say which one held when finding 01 failed to reproduce.

  Stated plainly because this doc is not marketing: **in a real product you would want both.** Defence in depth is the correct answer there, and single-mechanism is a pedagogical choice, not a best practice. The honest claim is "we chose one mechanism so the lab can attribute the outcome," not "one mechanism is sufficient."

**C — `org_id` carried in `context.Context`.** Rejected, and this is a divergence from every document that describes the control — all of them say `store.ForOrg(ctx)`. The shipped signature is `ForOrg(pool *pgxpool.Pool, orgID string)`.

  The change is an improvement and the reason is the control's own thesis. A context value is untyped, optional, and retrieved by a lookup that can return nothing — it is forgettable in precisely the way a parameter is forgettable, and a missing one fails at runtime rather than at compile time. A constructor argument cannot be absent. Five documents now describe a signature that does not exist; see §7.

**D — A CI check that fails on `documents` SQL outside `package store`.** Not taken, and it remains the cheapest available answer to the main rot surface in §6. Recorded as a candidate rather than silently dropped.

## 3. What it costs

This section exists because a control doc with no cost section is marketing.

- **`AdminStore` has to sit outside it.** Orgs, users and memberships *define* tenancy rather than live inside it — an org row cannot belong to an org, and a membership *is* the binding every other table is asked to already have. So `AdminStore` holds the pool and runs direct SQL, and the paved road has a documented exception on day one.
- **The seed had to be rewritten to go through it.** Document rows are created via `store.ForOrg` in `app/cmd/seed/main.go`, never by direct SQL (SR-M1-2). The cheaper option — document the exception, add a row-count test — was rejected on the grounds that an invariant reading "true except in the seed" is a thesis that was never true, and that an exception taken at bootstrap is the cheapest to take and the most expensive to remove, because every later broad-access tool cites it as precedent.
- **Cross-org reads have no home.** Any admin dashboard, support tool, analytics job or export that legitimately spans tenants cannot be written against `DocumentStore` at all. M1 ships no such feature, so the cost is currently zero and currently invisible. **The first one is the pressure point**, and the answer must be a second named type with its own authorization story — not a widening of `OrgStore`.
- Per-request allocation of a small struct. Negligible, listed so the list is complete.

## 4. What it does not cover

- **R-M1-1 — nothing underneath it.** No RLS, no per-tenant DB role. A bug in this layer has no second line of defence. This is the deliberate narrowing from option B.
- **R-M1-2 — not constant-time.** Indistinguishability is claimed for status, body and work performed. Wall-clock latency is **not** claimed, and claiming it without measuring it would be a lie in a document whose value is that it does not lie.
- **Membership is not checked here.** `ForOrg` trusts its argument unconditionally, the way a prepared statement trusts its bind parameters. The authorization decision happens upstream in `resolveHardenedStore` (SR-B2-2, its own control — see `the-token-is-not-the-authority.md`). This control makes the decision *unbypassable after it is made*; it does not make it.
- **`documents` only.** See §6.

## 5. How it is verified

| Evidence | Where |
|---|---|
| `attacks/01-cross-tenant-read/exploit.py` exits 1 with `CONTROL HOLDS` in hardened mode, 0 with real leaked bytes in vulnerable mode | `expected.json`, asserted by `attacks/run.py` |
| Both modes run unattended on every push and on the weekly anti-rot cron | `.github/workflows/ci.yml` |
| The harness asserts the *absent* other-mode marker, so a PoC cannot pass by failing | `attacks/run.py` |
| Live side-by-side on real seeded rows, before any handler existed: `OrgStore.ForOrg(acme).Search("confidential")` → 1 row; `NaiveStore.Search("confidential")` → 3 rows | M1 T2 verification |

**Not verified by anything:** that no new raw-pool call site has appeared. See §6.

## 6. Where this control would silently rot

The question that defines this section: *what change would make this control stop being true, while every test still passes and the diff looks unrelated to tenancy?*

1. **`store.Open` returns a raw `*pgxpool.Pool`, and it is exported.** Three callers already hold one (`app/api/main.go`, `cmd/seed`, `cmd/migrate`). Any new code — a new `cmd/`, a new handler, a reporting job — can run arbitrary `documents` SQL without touching the store package. The invariant holds today only because all `documents` SQL happens to live in `store/`, which is a property no compiler checks and no test asserts. **This is the main rot surface, and option D closes it for the price of one grep in CI.**

2. **A `documents`-touching method added to `AdminStore`.** `AdminStore` already holds the pool and already runs direct SQL legitimately. An "admin lists all documents" feature is a plausible, useful product request, and the diff that adds it reads as an admin feature rather than a tenancy change. Reviewers would be looking at admin, not at tenancy — M1-N3's sibling shape, aimed at the next module instead of the last one.

3. **A second caller of `ForOrg` that skips the membership check.** The type cannot tell, by construction (§4). The control's correctness depends on a property of its *callers* that nothing enforces. Today there is exactly one hardened caller.

4. **`NewNaiveStore` is exported.** It is wired only in vulnerable mode, but nothing prevents a future handler from constructing one, and the compiler will be satisfied.

5. **The next org-scoped table.** M2 adds `sessions`, `messages` and `tool_calls`; M3 adds grants. This control covers `documents`. `ForOrg` is named for an *org*, not for documents, so the name already promises more than the type delivers — and the first M2 handler to query `sessions` directly will be doing the correct-looking thing. **Carry this into M2's threat-model diff as an explicit decision, not a discovery.**

## 7. Documentation drift found while writing this

Every document that names the paved road names it `store.ForOrg(ctx)`. The shipped signature is `ForOrg(pool, orgID)`.

| File | Line | What it says |
|---|---|---|
| `threat-models/v0-baseline.md` | 166 | **SR-B2-1's own text** — "`store.ForOrg(ctx)` is the only constructor" |
| `threat-models/m1-tenancy.md` | 85, 129 | the D5 design sketch and the disposition table |
| `AGENTS.md` | 6 | the governance analogy |
| `CLAUDE.md` | 9 | the same analogy |

**Nothing above gets edited.** Both threat models are committed artifacts with dates on them, and the house rule is explicit: a document proven wrong is corrected in the *next version*, with the diff saying what was wrong — a document silently corrected cannot be used as evidence of anything. `AGENTS.md` and `CLAUDE.md` are hardened zones besides. This file is the correction, and `v1` of the baseline carries it forward.

Worth noting what kind of drift this is, because it is the benign kind and they are not all benign: the implementation is *stronger* than the requirement's wording, not weaker. The requirement asked for a constructor that cannot be called without an org context; it illustrated that with a `ctx` signature that would have been weaker than what shipped. The prose aged, the property did not. A drift audit that only diffs text against text would file this as a defect in the code.
