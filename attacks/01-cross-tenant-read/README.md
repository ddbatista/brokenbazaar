# Finding 01 — cross-tenant read via unscoped search

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

**Boundary:** B2 (Tenant ↔ Tenant) · **Leaf:** B2 2.3 / M1-N3 · **Frameworks:** A01:2021 (Broken Access Control) — no AI-standard home, and saying so is the honest tag.

## What it does

An honestly issued token for **Globex** — no forgery, no escalated privilege, a completely ordinary admin of their own org — searches their own document list and gets back documents belonging to **Acme and Initech**:

```
make up
python3 attacks/01-cross-tenant-read/exploit.py        # exit 0 — vulnerable
make harden
python3 attacks/01-cross-tenant-read/exploit.py        # exit 1 — control holds
```

## The bug

`NaiveStore.Search` (app/store/document_naive.go) runs

```sql
SELECT … FROM documents WHERE title ILIKE $1 OR body ILIKE $1
```

with **no org predicate** — while its sibling `List` *is* filtered in the handler. The search handler added beside the list handler forgot the rule the list handler remembered. This is the most common real-world shape of tenancy failure: **sibling-path-shaped** — the defect is invisible in a code review of the diff that introduced it, because the reviewer is looking at search, not at tenancy.

## Why it is plausible (what a real developer would have done)

The list path "proves" scoping works — it returns only your org's rows. Search looks like the same endpoint with a `WHERE` clause added. Nothing forces the org predicate to be typed a second time except remembering to.

## The control

`OrgStore` (SR-B2-1): scope is a property of the *handle* (`store.ForOrg(pool, orgID)`), not of the call site — `Search` carries `WHERE org_id = $1` structurally, because there is no store without an org. See `defenses/` and `threat-models/m1-tenancy.md` §2.

## Evidence contract

`expected.json` asserts the planted victim title (`Acme Corp — confidential Q3 plan`) appears in stdout on the vulnerable stack — real leaked bytes, not a status code — and `CONTROL HOLDS` on the hardened stack.
