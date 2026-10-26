# The signature was never checked, and the claim didn't need to be

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Every vulnerability in it is intentional and documented. Run it on localhost only.

*Finding 02 — JWT org-claim forgery via `alg:none` · boundaries B1, B2 · A01:2021 + A07:2021 (classic Broken Access Control and Identification/Authentication Failures — no AI-standard home; forcing an LLM ID onto an authz bug is the tell of a portfolio repo written for keywords).*

## A token nobody signed, believed completely

The attacker is an honest Globex admin. They log in, receive a valid token, read its claims off the wire — and then hand-forge a second one:

```
header   {"alg": "none", "typ": "JWT"}
claims   {"sub": "<their real sub>", "org_id": "<Acme's org>", "role": "admin", …}
token    eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.<payload>.
```

The third segment — the signature — is the empty string. The exploit prints the token **in full** before using it, because the entire finding is visible in those bytes: *the only field that differs from an honest token is `org_id`.* The `sub` is real, the role is real, the issuer is real. One field crossed the tenant boundary, and the API created a document inside Acme with a Globex principal.

## Two half-bugs that only matter together

**Defect 1 — the verifier reads `alg` from the token.** The vulnerable `Verify` decodes the header, sees `alg: none`, and returns the claims with **no signature check at all**. Any other `alg` still gets a real HMAC check. The one-line difference from the hardened verifier is the whole finding:

```go
// hardened:  the header is never decoded to decide anything. The HMAC is
//            recomputed over the token's own bytes; the presented signature
//            must match. `alg` in the header is data, not an instruction.
// vulnerable: if h.Alg == "none" { return decodeClaims(payload) }  ← the hole
```

Why would a real developer write the vulnerable version? Because the JWT *spec* defines `alg` as the field that says how the token was signed, and defines `none` as a real algorithm. The code trusts attacker-controlled input to decide *whether to verify at all*. That confusion — treating a data field as an instruction — is the same root cause as prompt injection, and it is why this lab's B4 and B9 boundaries exist for the agent tiers.

**Defect 2 — the request path trusts the claim.** Even with a perfect verifier, the vulnerable handler resolves the acting org from `claims.OrgID` and never checks the path's org against the membership table. The claim is still present, still signed, still *authoritative-looking* after the control lands — a signed claim that must not be trusted should not be present at all (tracked as M1-N5 → M3).

Neither defect crosses the tenant line alone. A signed but trusted-beyond-its-meaning claim is survivable with a hardened verifier; a forged token is survivable with a membership-checked path. **The attack needed both holes aligned — which is also why the defense needs both controls, not one.**

## The database caught what the handler forgot

An unplanned lesson from building the exploit: the first forgery used a garbage `sub`, and the attack died with a 500 — at the *database*, not at authz. `documents.created_by` has a foreign key to `users(id)`; the INSERT failed on a user that doesn't exist.

The FK constraint enforced something the handler never checked. Defense-in-depth isn't a slide in a deck here — it was observed, live, mid-attack. (It also sharpened the PoC: keeping `sub` honest makes `org_id` provably the *only* forged field.)

## The controls, and where each lives

- **SR-B2-3, fixed-alg verifier** (`app/auth/jwt.go`, `verifyHardened`): the algorithm is fixed in code. The header is recomputed *over*, never *read*. Forgery requires the HMAC secret, which hardened mode refuses to start without (SR-B1-3 — a startup failure naming the variable, not a request-time 401 discovered one token at a time).
- **SR-B2-2, server-side membership** (`app/api/documents.go`, `resolveHardenedStore`): the acting org is resolved from the membership table against the *path's* org — never from the claim. A stale-but-signed claim is now worthless.

## What detection sees: nothing, again, and for the opposite reason

Replayed against the hardened stack, the forged token dies at the *verifier* — a 401 before authorization is ever consulted. No denial is logged, because nothing was denied at the authz layer. The denial-based rule misses it by construction.

In vulnerable mode it misses it because the attack succeeds silently. Same conclusion as finding 01, from the opposite direction: **detection sees the loud attacks; the regression suite is what notices when the loud ones stop being blocked.** The measured matrix is in `detections/README.md`.

## The generalizable claim

A verifier that lets its input choose the verification is not verifying — it is asking permission. And a claim the server re-derives on every request is a claim that can never go stale, never be forged by a signer's mistake, and never survive its own revocation. Trust the records you own, not the tokens you were handed.

---
*Planted in `0fc8fce` (verifier) + `9ba4b2d` (claim-trusting path). Controls: `verifyHardened` (SR-B2-3), `resolveHardenedStore` (SR-B2-2). Exploit: `attacks/02-jwt-org-claim/` — self-cleaning, prints the forged token in full, asserted in CI both modes.*
