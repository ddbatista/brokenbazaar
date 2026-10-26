# The token is not the authority

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

**Requirements:** SR-B2-3 (fixed-algorithm verifier), SR-B2-2 (server-side membership) · **Module:** M1
**Kills:** finding 02 (forged org claim) · **Carries:** M1-N5 / R-M1-3
**Code:** `app/auth/jwt.go` (`verifyHardened`), `app/api/documents.go` (`resolveHardenedStore`) — behind `HARDENED`
**Status:** shipped, verified in CI both modes. One of the two controls is **not** exercised by finding 02 — see §5.

Two controls in one document, because **the composition is the content.** Fix the verifier and leave the path trusting `claims.OrgID`, and an attacker who obtains any valid token for any org still acts in it. Fix the path and leave the verifier reading `alg` from the header, and identity itself is forgeable. Neither alone is the control; finding 02's answer key makes the same point about the two commits that planted it.

Narrative: [`writeups/02-jwt-org-claim.md`](../writeups/02-jwt-org-claim.md). Requirement: [`threat-models/m1-tenancy.md`](../threat-models/m1-tenancy.md) §1 D3, §3.

---

## 1. What it is

**SR-B2-3.** `verifyHardened` recomputes the HMAC over the token's own `header.payload` with our secret and compares constant-time. It never decodes the header to decide *whether or how* to verify. The header is attacker-controlled input, and a verifier that reads it to choose its own behaviour has let the attacker pick the check.

**SR-B2-2.** `resolveHardenedStore` resolves the acting org from `admin.MembershipRole(ctx, pathOrgID, claims.Sub)` — the user's real, current membership in the **path's** org, looked up against records the API owns. `claims.OrgID` is never consulted.

The thesis in one line: **a signed claim is authenticated, not authorized.** The signature proves the issuer minted it. It proves nothing about whether the bearer is still entitled to what it asserts.

## 2. Options considered

**A — Use a JWT library.** Rejected by house rule: hand-roll the mechanism when the mechanism is the lesson. A library would make `alg:none` the library's bug and finding 02 would teach nothing.

  The inverse holds outside this repo and the doc should say so rather than let a reader generalise wrongly: **in a real product, use the library.** The lesson that transfers is "do not let the token choose the algorithm," not "write your own JWT."

**B — Allowlist the algorithms (`alg ∈ {HS256}`).** Rejected, and this is the interesting rejection. It is better than accepting `none`, and it still reads `alg` out of attacker-controlled bytes to make a security decision. The property we want is not *a safer set of attacker inputs*, it is **no attacker input in the decision at all.**

  This is B5's thesis arriving two modules early: the decision derives only from state the platform owns. M2's gateway is the same rule applied to tool calls. Worth noticing that it was reachable from a JWT verifier.

**C — Fixed algorithm in code.** Chosen. The header is recomputed *over*, never *read*.

**D — Remove `org_id` from the token entirely.** The right answer, **not taken in M1**, deferred as R-M1-3 with M3 as the destination. M1-N5 states the residue precisely: a claim that must not be trusted should not be present, because a signed field looks authoritative whether or not anything is entitled to believe it. The control makes the claim worthless; it does not make it absent, and the next developer to read the token cannot tell those apart. Named here as a deferral with an address, not as an oversight.

**E — Trust the claim, but validate it against membership.** This is almost C+SR-B2-2 and differs in one way that matters: validating `claims.OrgID` against membership still makes the claim the *subject* of the question. Resolving from the path makes the claim irrelevant. The second is strictly stronger, because a token with no `org_id` at all behaves identically.

## 3. What it costs

- **A database round trip per request.** The membership lookup is exactly the DB hit that `resolveVulnerableStore`'s reasoning — *"I already verified the user via JWT, so why hit the DB again"* — was written to avoid. Stated plainly: **the vulnerable design was correct about the performance.** It was wrong about what a signature proves. A control doc that pretends its control is free is not evidence of anything.
- **Multi-org login is blocked in M1.** `SoleMembership` errors rather than guessing when a user holds zero or more than one membership, and `/auth/token` returns 501. Deferred to M3 where "principal" becomes a type rather than a word.
- **The role is looked up and thrown away.** `resolveHardenedStore` discards `MembershipRole`'s first return value: M1 authorizes on membership alone, any member does all CRUD, because roles with teeth are M3 scope. Wasted work today, deliberately, and the discard site is the exact line M3 changes.
- **Hardened mode will not start without `JWT_SECRET`** — a cost paid in the build, not at request time, and it cost 16 days of red CI. See [`controls-that-fire-before-a-request-exists.md`](controls-that-fire-before-a-request-exists.md).

## 4. What it does not cover

- **R-M1-3 / M1-N5** — the `org_id` claim survives the control and still looks authoritative (option D). Carried to M3.
- **Token revocation.** Nothing here invalidates an issued token early. A one-hour TTL is the only bound, and demotion mid-token takes effect for *authorization* (membership is re-read per request) but not for the token itself.
- **Credential strength.** Seeded, static, shared password; salted SHA-256, not a KDF. R-M1-4, declared non-coverage.
- **Rate limiting** — SR-B1-6, deferred in the diff.

## 5. How it is verified, and the half that is not

| Evidence | Where |
|---|---|
| `attacks/02-jwt-org-claim/exploit.py` exits 1 with `CONTROL HOLDS` in hardened mode (401 at the verifier), 0 in vulnerable mode with the forged token printed in full | `expected.json`, `attacks/run.py` |
| Both modes on every push and the Monday anti-rot cron | `.github/workflows/ci.yml` |
| Hardened container with no `JWT_SECRET` refuses to start, verified live | M1 T4 |

**SR-B2-2 is not exercised by finding 02.** In hardened mode the exploit dies at the first control — 401 at the verifier — and never reaches the membership check. A reader who assumes a green suite proves both controls is wrong, which is why this is in the document rather than left to be inferred.

What exercises it is the third replay variant — **honest token, foreign org in the path** — added in `detections/replay.py` after M1 T6 found that hardened runs produced zero denial log lines. That variant is the only thing in the repo that drives `resolveHardenedStore`'s denial branch.

Generalisable, and it is this control's real lesson: **in a layered defence, the outer layer hides the inner one from your tests.** Every control after the first needs a test that starts *past* the first.

## 6. Where this control would silently rot

1. **Mode is a parameter, not a property — and that is the thing this repo's other control rejects.** `auth.Verify(token, secret, hardened bool)` threads through `bearerClaims` and `requireToken`, and `registerVulnerable` passes `false` by hand at six call sites. A caller that passes the wrong bool gets the vulnerable verifier and compiles cleanly.

   Hold that against [`scope-as-a-property-of-the-handle.md`](scope-as-a-property-of-the-handle.md), where the whole design was to stop scope being a per-call-site value. **The same repo made the opposite choice one package over**, and the inconsistency is real. The defence is that a lab must run both verifiers from one binary, so the mode has to be *some* kind of value — but it did not have to be a bare bool threaded through three layers. Two constructors returning a `Verifier` would have matched the store's design. Recorded rather than smoothed over; the cheap fix is M2's business if the gateway adds a third mode.

2. **`claims.OrgID` is still there, still signed, still populated honestly.** Any future handler that reads it is doing something that looks completely reasonable and is wrong. There is no type, test or lint keeping it out of a new call site — only this paragraph and M1-N5. **Highest-probability rot in M1.**

3. **One caller.** `resolveHardenedStore` is the single hardened path that resolves a store. A second resolution path added for a new resource re-opens the question from scratch, and nothing connects it to this control.

4. **M2 and M3 change the premise.** `SoleMembership` errors on multi-org today; M3 makes multi-org real, and the org binding on a token stops having a single server-side answer. M2 adds a session principal whose authority is not a membership at all. **Both modules must revisit this document, not just extend it.**

## 7. Note for M6

Both halves of this control, and both halves of the vulnerability it kills, were written by the coding agent under AGENTS.md gates, in two sessions 78 minutes apart. Each commit was individually compliant and individually reviewable; their union was an exploitable cross-tenant write. See [`attacks/02-jwt-org-claim/ANSWER-KEY.md`](../attacks/02-jwt-org-claim/ANSWER-KEY.md) §Attribution for what that does and does not support.
