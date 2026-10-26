# Answer key — finding 01, cross-tenant read via unscoped search

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

Published with M1, per the decisions log: this is a walkthrough, not a CTF. A reader who cannot see which bug was planted cannot verify that the control actually addresses it.

**Finding:** 01 · **Boundary:** B2 (Tenant ↔ Tenant) · **Leaves:** B2 2.3, M1-N3 · **Module:** M1 · **Frameworks:** `A01:2021` (Broken Access Control). No AI-standard home, and saying so is the honest tag.

The attack and the control are described in [`README.md`](README.md); the argument is in [`writeups/01-cross-tenant-read.md`](../../writeups/01-cross-tenant-read.md). This file records what only it can: **which commit planted what, and who wrote it.**

---

## The planted bug, by commit

The finding is **not in one commit**. It is the composition of two, written seven days apart by two different authors, and neither one is exploitable alone.

| Commit | Date | What it planted |
|---|---|---|
| `cd44140` — *M1 T3: store layer* | 2026-10-05 | `NaiveStore.Search` in `app/store/document_naive.go`: `WHERE title ILIKE $1 OR body ILIKE $1`, **no org predicate**. Also `NaiveStore.Get`, unscoped — the IDOR at B2 2.1, not separately numbered because the same control kills it. |
| `9ba4b2d` — *M1 T5: handlers* | 2026-10-12 | `resolveVulnerableStore` in `app/api/documents.go` — the single decision that selects `NaiveStore` for every document handler, making the unscoped query reachable from a route. And the **asymmetry itself**: `listOrSearch` calls `filterByOrg(docs, claims.OrgID)` on the `List` path and applies **nothing** on the `Search` path. |

**Why the split matters.** `cd44140` is a store with a missing predicate and no caller — it is dead code on the day it lands, and a reviewer reading that diff sees a type that honestly documents itself as the vulnerable sibling. `9ba4b2d` is the commit that makes it a vulnerability, and it does so with one line (`return store.NewNaiveStore(pool)`) that names no tenancy concern at all.

That is M1-N3's "sibling-path-shaped" defect appearing one level above the code it describes: the threat model predicted that *the defect is invisible in review of the diff that introduced it*, and the finding's own history is an instance of it. The absent predicate and the reachability are in different diffs, in different packages, by different authors.

## Why a real developer writes this

The list path *proves* scoping works — it returns only your org's rows. Search looks like the same endpoint with a `WHERE` clause bolted on. Nothing in Go's type system forces the org predicate to be typed a second time; only remembering to.

And `resolveVulnerableStore`'s comment states the actual reasoning out loud: *"I already verified the user via JWT, so why hit the DB again."* That is not a strawman. It is the standard argument for putting `org_id` in a token, and it is correct about performance.

## The control, and where it lives

`store.ForOrg(pool, orgID)` → `OrgStore` (`app/store/document_org.go`), SR-B2-1. Scope is a property of the **handle**, not of the call site: `OrgStore.Search` carries `WHERE org_id = $1::uuid AND (...)` structurally, because there is no way to obtain the store without naming an org.

The control was **written before the vulnerable version**, in the same commit (`cd44140`), per the AGENTS.md house rule. That ordering is what lets this file argue *why a developer would write `NaiveStore`* instead of dismissing it as a typo.

Mode selection is `docHandlers.resolveStore`, one function pair, so the entire tenancy difference between the two products is readable in one place.

## Attribution — the M6 dataset

| Artifact | Author | Evidence |
|---|---|---|
| `OrgStore` (the control) | By hand | No `Co-Authored-By` trailer on `cd44140`; no agent session transcript for T3 |
| `NaiveStore` (the planted store) | By hand | same |
| `resolveVulnerableStore` + the list/search asymmetry (the planted reachability) | **Agent** | `Co-Authored-By` agent trailer on `9ba4b2d`; two agent session transcripts for T5 (the timeout-and-retry documented in the plan) |
| `exploit.py` | By hand | No trailer on `3004543`; no agent session transcript for T6 |

**Evidence basis, stated because the record is only worth having if it is auditable.** Agent authorship is positively evidenced by two independent sources that agree: a `Co-Authored-By` trailer in the commit, and an agent session transcript for that task. Hand authorship is inferred from the *absence* of both, which is weaker evidence; it is corroborated by the per-task notes in the implementation plan, which name the agent explicitly for T4 and T5 and for no other M1 task.

**The honest reading, and it constrains what M6 may claim.** The agent did not spontaneously introduce this bug. It was instructed to, by `threat-models/m1-tenancy.md`, which it was told to read in full before writing. What the record supports is: *an agent, given a threat-model diff that specified a sibling-path tenancy defect, reproduced that defect faithfully and documented it correctly in the code it wrote.* What the record does **not** support is any claim about agents introducing tenancy bugs unprompted — M1 contains no evidence for that, and asserting it would be the overclaim this repo exists to avoid.

One datum that is genuinely about the agent and not about the instruction: `9ba4b2d` landed across **two agent sessions**, the first of which hit a tool-level timeout and appeared to fail while its subprocess kept running and finished writing `documents.go` and `routes.go`. The retry found uncommitted work in the tree. Both sessions' output was reviewed line by line against AGENTS.md before commit, and the result was verified against a live stack rather than trusted from the agent's own report.
