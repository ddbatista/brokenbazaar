# M1 — Tenancy & Identity · threat-model diff

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning
> resource for security practitioners.** Every vulnerability in it is intentional and documented.
> Run it on localhost only.

**Diffs `threat-models/v0-baseline.md`.** Boundaries **B1** (Internet → API) and **B2** (Tenant ↔
Tenant). Committed **before** the M1 feature code, per `CLAUDE.md` house rule 1.

This document does not restate B1 and B2. It cites their leaves by number and records four things
the baseline could not know, because at M0 there was no implementation to know them about:

1. which baseline leaves this module makes **reachable**, with a route and a statement as the address
2. the **disposition of every B1/B2 security requirement** — shipped, flag-gated, deliberately
   violated, or deferred
3. **new leaves the implementation invents** that no reading of the spec would have produced
4. a **verdict** on the baseline assumptions that have now met a schema

---

## 1. The decisions under test

The baseline was derived from spec §8's assumptions. This diff is derived from five implementation
decisions. Each is falsifiable in the same way an assumption is, which is why they are listed before
anything else.

### D1 — Schema

```sql
orgs        (id uuid pk, name, created_at)
users       (id uuid pk, email unique, display_name, password_hash)
memberships (org_id fk, user_id fk, role, pk(org_id, user_id))
documents   (id uuid pk, org_id uuid NOT NULL REFERENCES orgs(id),
             title, body, created_by fk users, created_at)
```

Identifiers are UUIDv4, not serials (SR-B2-4, first half). `documents.org_id` is `NOT NULL` with a
foreign key: ownership is a storage-layer invariant, not a convention.

### D2 — One database role

The API connects as the single Postgres role `bazaar`, which owns every table. There is **no
row-level security and no per-tenant database role.** Consequence, stated plainly because it governs
everything else in M1: **the application's store layer is the only thing standing between tenants.**
There is no second line of defence underneath it. This is what makes the module's thesis testable —
and it is a deliberate narrowing, recorded as residual R-M1-1.

### D3 — Token format

Hand-rolled JWT, HS256, standard library only — `hmac`, `sha256`, `encoding/base64`. No JWT library.

```
header   {"alg":"HS256","typ":"JWT"}
claims   {"sub":<user uuid>, "org_id":<org uuid>, "role":<role>,
          "iss":"brokenbazaar", "iat":<unix>, "exp":<iat+3600>}
```

Hand-rolled on purpose. A library would make the `alg:none` and unverified-signature paths invisible
— they would be the library's bugs, not the repo's, and finding 02 would teach nothing. The verifier
is product code and is read as product code.

Note the `org_id` claim. It exists because a real implementation puts it there to avoid a lookup per
request. It is the entire substrate of finding 02.

### D4 — Routes

| Method | Path | Auth |
|---|---|---|
| `POST` | `/auth/token` | none by design |
| `GET` | `/healthz` | none by design (baseline "accepted exposure") |
| `GET` | `/me` | token |
| `GET` | `/orgs/{org_id}/documents` | token |
| `GET` | `/orgs/{org_id}/documents?q=<term>` | token |
| `POST` | `/orgs/{org_id}/documents` | token |
| `GET` | `/orgs/{org_id}/documents/{doc_id}` | token |
| `PATCH` | `/orgs/{org_id}/documents/{doc_id}` | token |
| `DELETE` | `/orgs/{org_id}/documents/{doc_id}` | token |

### D5 — Two stores behind one interface

```go
type DocumentStore interface { ... }

NaiveStore  // vulnerable: methods take no org context; scope is the caller's problem
OrgStore    // hardened:   store.ForOrg(ctx) is the only constructor; every statement
            //             carries org_id = $1 and it cannot be omitted
```

The flag selects the implementation **once, at startup**, not per request. A per-request choice would
itself be a vulnerability class and would muddy what the PoC proves.

---

## 2. Baseline leaves this module makes reachable

Abstract in v0; addressed here.

| Leaf | Baseline wording | Address in M1 |
|---|---|---|
| **B2 2.3** | *a query path that forgot the scope entirely — list, search, export* | `GET /orgs/{org_id}/documents?q=` → `NaiveStore.SearchDocuments(q)` → `SELECT … WHERE title ILIKE $1 OR body ILIKE $1` **with no org predicate**. The sibling list path *does* filter — in the handler, in Go, over all rows. **→ finding 01** |
| **B2 1.3** | *hold a genuine membership and have the API resolve the acting org from the token rather than the path* | `PATCH /orgs/{org_id}/documents/{doc_id}` resolves the acting org from the `org_id` **claim**, ignoring `{org_id}` in the path and performing no membership lookup. **→ finding 02** |
| **B2 2.2** | *handler trusts `:org_id` in the path without checking membership* | Same handler, same absence. 1.3 and 2.2 are one code defect seen from two directions; one control kills both. |
| **B1 1.1** | *`POST /auth/token` accepts an identifier as sufficient proof* | Vulnerable mode: `{"email": "..."}` alone mints a token. `password_hash` exists in the schema and is not consulted. |
| **B1 1.2** | *token forgery — absent/weak verification, or a committed dev secret* | Vulnerable mode: the verifier reads `alg` **from the token** and accepts `none`; `JWT_SECRET` falls back to the literal `dev-secret`. See M1-N1. |
| **B2 2.1** | *IDOR on the object identifier* | Reachable on `GET /orgs/{org_id}/documents/{doc_id}` — `NaiveStore.DocumentByID(id)` has no org predicate. **Not given its own finding:** the control that kills 2.3 (D5's `OrgStore`) kills 2.1 by the same mechanism. One finding per *control*, not per leaf; the finding cap is 10 and spending two on one control is how a lab inflates its numbers. Recorded here so the omission is visible rather than accidental. |
| **B2 4.1** | *mass assignment — create with an attacker-chosen `org_id`* | `POST /orgs/{org_id}/documents` binds the whole JSON body into the document struct. Reachable, not exploited separately — same reasoning as 2.1; SR-B2-6 covers it. |
| **B2 3.2** | *a seed or system principal with no org binding* | The seed path. See M1-N2 — this one is **not** covered by the M1 controls and is the sharpest thing in this diff. |

**Not reachable in M1**, stated so the next diff does not have to rediscover it: B2 1.2 (replay — no
session binding exists until M3), B2 3.1 (agent sessions — M2), B1 3.1 (publisher registration — M4a),
B1 4 (declared non-coverage, `coverage/`).

---

## 3. Disposition of the B1 and B2 security requirements

`ship` = lands in both modes. `HARDENED` = lands behind the flag; the vulnerable path violates it on
purpose. `defer` = not in M1, with a destination.

| SR | Disposition | Note |
|---|---|---|
| SR-B1-1 deny-by-default at route registration | **HARDENED** | Routes register through a table that requires an explicit `auth: none \| token` field; an unset field is a **startup panic**, not a request-time 401. Vulnerable mode registers on a bare `http.ServeMux`. |
| SR-B1-2 `/auth/token` requires a verifiable credential | **HARDENED** | Hardened verifies `password_hash`. Vulnerable accepts email alone (B1 1.1). |
| SR-B1-3 signing key from env, no default, refuse to start | **HARDENED** | Vulnerable falls back to `dev-secret` (B1 1.2, M1-N1). |
| SR-B1-4 claims derived from server records at issue time | **ship** | True in both modes — the *issuer* is honest in M1. Finding 02 forges a token rather than inflating one at issue, so both modes mint correctly. Worth noticing: an honest issuer is worthless if the verifier is not. |
| SR-B1-5 unauthenticated endpoints return liveness only | **ship** | `/healthz` returns the baseline's accepted-exposure body and nothing more. |
| SR-B1-6 rate limiting on token issuance | **defer → M3** | Nothing in M1 or M2 depends on it and no finding exercises it. Deferring it in writing is the point; silently not building it is how an SR dies. |
| SR-B1-7 declared non-coverage recorded in `coverage/` | **ship (M1 T9)** | Carried over from the M0 open follow-ups. Closes with this module. |
| SR-B2-1 scope in the store layer, `ForOrg(ctx)` the only constructor | **HARDENED** | D5. The module's thesis. |
| SR-B2-2 server-side membership lookup, never a claim | **HARDENED** | Kills finding 02. |
| SR-B2-3 fixed alg, expiry enforced, `alg` never read from the token | **HARDENED** | Kills the forgery half of finding 02. |
| SR-B2-4 non-enumerable ids; authorise against the object's owner | **split** | UUIDs **ship** (both modes). Owner-based authorisation is **HARDENED** — it is what `OrgStore` does. |
| SR-B2-5 denial indistinguishable from not-found | **HARDENED** | 404 for both, identical body. Latency equality is **not** claimed — see R-M1-2. |
| SR-B2-6 `org_id` never client-settable | **HARDENED** | Hardened binds an explicit DTO; vulnerable binds the raw body (B2 4.1). |
| SR-B2-7 every principal carries an org binding, including seed | **violated in both modes** | See M1-N2. This is a finding the diff produced, not one the plan assigned. |
| SR-B2-8 log every authz denial with principal, target org, decision | **ship** | Both modes. Detection (T8) is meaningless if the vulnerable mode is silent — you cannot measure a miss you did not instrument. |

---

## 4. New leaves the implementation invents

Numbered `M1-N*`. These do not exist in the baseline. No reading of the spec would have produced
them, because each is a consequence of a decision in §1.

### M1-N1 — The signing secret has a development default, and the default is in the image

`JWT_SECRET` is read from the environment. In vulnerable mode it falls back to `dev-secret`, which is
committed. B1 1.2 predicted "a default dev signing secret committed to the repository" *in general*;
D3 makes it a specific string in a specific file, and `docker-compose.yml` does not set the variable,
so the fallback is the live path rather than an unused branch.

The leaf the baseline did **not** predict: the fallback is **silent**. A real operator who intends to
set `JWT_SECRET` and typos the variable name gets a working stack signed with a public key, with no
log line. The flag-gated refusal-to-start (SR-B1-3) fixes the hardened path; the generalisable control
is that *a security-relevant default must be loud or absent, never quiet*.

> **SR-M1-1.** A configuration fallback with security effect either refuses to start or logs at
> `WARN` naming the variable and the consequence. "Defaulted quietly" is not an option.
> *Kills: M1-N1 in both modes — the vulnerable path keeps the weak key but loses the silence.*

**Instance observed in this repo's own build, before the product code it describes existed.** Adding
`pgx/v5` ratcheted `app/go.mod` from `go 1.22` to `go 1.25.0`. CI pinned `go-version: "1.22"`. That
combination does not fail: with the default `GOTOOLCHAIN=auto`, the 1.22 toolchain downloads 1.25.0
and builds successfully, so the pinned version in CI silently stops describing what produced the
binary. A version pin that can be superseded without an error is the same defect as a secret that can
be defaulted without a log line — the control is present, the signal is not.

Recorded here rather than in a retrospective because it is evidence for the requirement: the pattern
was found in the toolchain of the lab that was being built to teach it.

### M1-N2 — The seed principal has no org binding and does not use the store

SR-B2-7 says every principal carries an org binding, *including seed and system principals*, and that
a principal without one cannot reach the document store. The seed path as designed writes documents
for all three orgs with direct SQL, before any token exists and outside both store implementations.

So in **hardened mode**, `OrgStore` is still not the only way to reach the table. SR-B2-1's claim —
"there is no code path that can obtain a database handle without an org context" — is **false as
written** the moment seeding exists. The baseline said this at leaf 3.2 in the abstract; the
implementation makes it structural.

This is the M1 analogue of the M0 §5 finding about A8.6. The pattern is worth naming: **an invariant
asserted over "all code paths" is routinely false for the paths that run before the system is up.**
Bootstrap, migration, backup restore, and admin break-glass are where tenancy invariants go to die,
and none of them are in anyone's request-path threat model.

> **SR-M1-2.** The seed runs through `OrgStore`, one `ForOrg(org)` handle per org, with no direct SQL
> for tenant-scoped tables. Schema DDL may bypass the store; **rows in a tenant-scoped table may not.**
> *Kills: B2 3.2, and makes SR-B2-1 true as written.*

**Decision, and the alternative rejected.** The weaker option was available and is what most teams
ship: let the seed use direct SQL, document it as the single exception, and assert correctness with a
test counting rows per org. It is cheaper — bulk insert, one connection, no handle per tenant.

Rejected, because the exception costs more than it saves *here specifically*. M1's entire thesis is
that tenant scope is structural rather than a rule people remember to follow; an invariant that reads
"true except in the seed" in the first week of the module is a thesis that was never true. The
writeup would have to carry the caveat, and the caveat is more memorable than the claim.

The generalisable form: **an exception taken for convenience at bootstrap is the cheapest exception
to take and the most expensive one to remove**, because every later tool that needs broad access —
migration, backfill, export, support tooling — cites it as precedent. The first exception is the only
one that is ever really decided; the rest are inherited.

Recorded in `coverage/` as the first entry where a diff corrected a baseline SR rather than
implementing it.

### M1-N3 — Scope correctness is sibling-path-shaped

D5's vulnerable store makes the *list* path and the *search* path two independent opportunities to
remember the same rule. The list handler filters; the search handler does not. This is not an exotic
bug — it is the single most common shape of real tenancy failure, and it has a property worth stating:
**the defect is invisible in a code review of the diff that introduced it**, because the diff adds a
search endpoint and the reviewer is looking at search, not at tenancy.

> **SR-M1-3.** Tenant scope is a property of the *handle*, not of the call site, so no endpoint can
> be written that forgets it. Where this fails — raw SQL, reporting, export — the statement must be
> reviewed against a list of scope-bearing tables.
> *This is SR-B2-1 restated as the reason it is worth its cost.*

### M1-N4 — The uniform 404 is a decision about ordering, not about status codes

SR-B2-5 reads as "return 404 instead of 403". Implemented, it is about **where the check sits
relative to the lookup**. Look up the document first and then authorise, and existence has already
been observed: cost, cache state and latency differ between "no such id" and "not yours", whatever
the status line says. The hardened path therefore scopes the *query* (`WHERE id=$1 AND org_id=$2`),
which produces an identical empty result for both cases from the same work.

> **SR-M1-4.** Indistinguishability is achieved by making the two cases take the *same code path*,
> not by overwriting the status code after they diverge.
> *Kills: B2 2.4, for cost and cache as well as status.*

### M1-N5 — The `org_id` claim remains in the token after the control lands

The hardened path resolves the acting org by membership lookup (SR-B2-2). The claim is still minted
(SR-B1-4) and still present in the token. A future handler can read it, and it will look authoritative
— it is signed, after all. The control is a convention about which field to trust, and conventions
decay across modules and across authors.

Carried to M2/M3 rather than fixed here, because the right fix is a token type that does not carry
the field at all, and that belongs with the session-capability work in M3.

> **SR-M1-5.** A claim that must not be trusted should not be *present*. Where it must exist, it is
> named so that trusting it is visibly wrong (`org_id_unverified`).
> *Status: raised, deferred to M3. Tracked as residual R-M1-3.*

---

## 5. Verdict on baseline assumptions that have now met an implementation

| Assumption | Verdict |
|---|---|
| **A8.1** — everything acts as exactly one principal, every call resolves to one | **Upheld with an exception.** Every request resolves to a user principal. The **seed** principal does not (M1-N2). The assumption was always false for bootstrap; the spec simply never considered bootstrap a principal. Not a spec PR — a scope note for M3, where agent sessions make "principal" a type rather than a word. |
| **A8.2** — a user's authority comes from membership | **Upheld in hardened mode only, by construction.** In vulnerable mode authority comes from a claim. The honest phrasing is that A8.2 describes the *hardened* product, which is what a security requirement is for. |
| **A8.3** — documents belong to exactly one org and are reachable only within it | **First half upheld structurally** by `NOT NULL REFERENCES orgs(id)` (D1): "belongs to exactly one org" is now enforced by the database and cannot be violated by application code at all. **Second half is not a schema property** — reachability is decided entirely by D2's single database role and D5's store choice. A8.3 is really two claims of very different strength sharing one sentence, and M1 is where that becomes visible. **Disposition: spec PR for `v1`**, splitting it into A8.3a (ownership — a storage invariant) and A8.3b (reachability — an application property), batched with the M0 follow-ups rather than raised on its own. |

---

## 6. Residuals accepted for M1

| ID | Residual | Compensating position |
|---|---|---|
| R-M1-1 | No row-level security and no per-tenant DB role (D2). A store-layer bug has nothing beneath it. | Deliberate: the lab's thesis is that the data layer is where tenancy lives, and a second mechanism would obscure which one held. Stated, not discovered. |
| R-M1-2 | SR-B2-5 is claimed for status, body and *work performed*, **not for wall-clock latency.** No constant-time guarantee. | A timing oracle across a network against a Postgres query is not the attack this lab teaches, and claiming constant time without measuring it would be a lie in a document whose value is that it is not lying. |
| R-M1-3 | The `org_id` claim survives the control (M1-N5). | Deferred to M3 with a named SR. Carried, not dropped. |
| R-M1-4 | Credentials are seeded, static and shared; no rotation, lockout or password policy. | Spec §7 non-goals. `coverage/` records it as declared non-coverage. |

---

## 7. Exploit assignment

| Finding | Leaf | Evidence it must print |
|---|---|---|
| `attacks/01-cross-tenant-read` | B2 2.3 (addressed in §2) | The body of an Org A document, retrieved with a valid Org B token. The seed plants a document whose title is a stable, greppable string so `expected.json`'s `stdout_contains` asserts on real bytes rather than on a status code. |
| `attacks/02-jwt-org-claim` | B2 1.3 / 2.2, via B1 1.2 | The forged token in full — header, claims, signature — then the Org A object it reached. Printing the token is the point: a reader must see *which field* was believed. |

Two-mode assertion per `attacks/README.md`: `make up` → both exit 0. `make harden` → both exit
non-zero, and the authz-denial log lines they produce become T8's detection input.

---

## 8. Open follow-ups from this diff

- [ ] `coverage/` entry for B1 leaf 4 declared non-coverage (SR-B1-7, carried from M0).
- [ ] `coverage/` entry recording M1-N2 as a diff that corrected a baseline SR.
- [ ] SR-B2-1's wording in `v0-baseline.md` is false as written for bootstrap paths — fix in `v1`,
      do not silently edit `v0`. The baseline is an artifact with a date on it.
- [ ] R-M1-3 / SR-M1-5 carried to the M3 diff.

### Queued for one spec revision

Four spec defects are now outstanding, three from M0 §5 and one from §5 of this diff. They land as a
**single PR against `docs/product-spec.md`**, not four — a spec that is amended continuously is a spec
nobody re-reads, and the value of §8 is that it can be read whole.

- [ ] **A8.10 (new)** — the platform's own runtime identity. *(M0 §5)*
- [ ] **A8.5 / A8.6** — narrow as proposed; A8.6 is false as written. *(M0 §5)*
- [ ] **A8.3 → A8.3a / A8.3b** — split ownership from reachability. *(this diff, §5)*

Not yet, and deliberately: the revision happens when M1 ships, so the spec is corrected by things
that were *built*, not by things that were argued about. Each entry above names the module that
produced it.
