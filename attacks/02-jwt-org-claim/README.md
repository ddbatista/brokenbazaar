# Finding 02 — forged `org_id` claim via `alg:none` token

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

**Boundary:** B1 (Internet → API), B2 (Tenant ↔ Tenant) · **Leaves:** B2 1.3 / 2.2 via B1 1.2 · **Frameworks:** A01:2021, A07:2021 (Identification & Authentication Failures) — classic appsec, no AI-standard home.

## What it does

An honest **Globex** admin forges a second token by hand: `alg: none`, their *real* `sub` and `role`, and `org_id` swapped to **Acme's**. The vulnerable verifier reads `alg` from the attacker-controlled header and skips the signature check entirely; the request path then trusts the forged `org_id` claim without any server-side membership check. The forged token **creates a document inside Acme** — and deletes it again, so the PoC is idempotent.

```
make up
python3 attacks/02-jwt-org-claim/exploit.py        # exit 0 — vulnerable
make harden
python3 attacks/02-jwt-org-claim/exploit.py        # exit 1 — control holds
```

## The bug, in two halves

1. **Verifier** (app/auth/jwt.go, `verifyVulnerable`): `alg` is read from the token header and `none` is accepted with no signature check. The code trusts attacker-controlled input to decide *whether to verify at all*.
2. **Request path** (app/api/documents.go, `resolveVulnerableStore`): the acting org comes from `claims.OrgID`, and the path's `{org_id}` is never checked against real membership. A signed-but-unverified org claim is authoritative because it *looks* signed.

## Why it is plausible

Reading `alg` from the header is what the JWT spec literally says the field is for, and special-casing `none` is what the spec defines. "I already verified the user via JWT, so why hit the DB again" is the reasoning that skips the membership lookup.

## The controls

- **SR-B2-3** (fixed-alg verifier): the algorithm is fixed in code; the header is recomputed *over*, never *read*. Kills the forgery.
- **SR-B2-2** (server-side membership): the acting org is resolved from the membership table, never from the claim. Kills the claim-trust even for a genuinely signed token.

## The design detail worth noticing

`sub` is kept **honest** in the forged token — `documents.created_by` has a foreign key to `users(id)`, so a garbage `sub` fails at the *database* with a 500 before any authz question is reached. The FK constraint catches what the handler forgot to check: defense-in-depth at the data layer, observed live. Keeping `sub` real also sharpens the finding: **`org_id` is the only forged field.**

## Evidence contract

The exploit prints the forged token **in full** — header, claims, empty signature segment — before using it, because a reader must see *which field was believed*. `expected.json` asserts "believed the forged org_id claim" on the vulnerable stack and `CONTROL HOLDS` on the hardened stack.
