# Answer key — finding 02, forged org claim via `alg:none`

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

Published with M1, per the decisions log: this is a walkthrough, not a CTF. A reader who cannot see which bug was planted cannot verify that the control actually addresses it.

**Finding:** 02 · **Boundary:** B1 (Internet → API), B2 (Tenant ↔ Tenant) · **Leaves:** B1 1.2, B2 1.3 / 2.2, M1-N5 · **Module:** M1 · **Frameworks:** `A01:2021`, `A07:2021`. No AI-standard home.

The attack is in [`README.md`](README.md); the argument is in [`writeups/02-jwt-org-claim.md`](../../writeups/02-jwt-org-claim.md). This file records what only it can: **which commit planted what, and who wrote it.**

---

## The planted bug, by commit

Two half-bugs. Neither is the finding. Both were written by the agent, in **two separate sessions 78 minutes apart on the same night**, and the exploitable composition exists in neither diff.

| Commit | Date | What it planted |
|---|---|---|
| `0fc8fce` — *M1 T4: auth* | 2026-10-12 02:00 | `verifyVulnerable` in `app/auth/jwt.go`: decodes the header, reads `alg` **from the token**, and returns the claims with **no signature check at all** when `alg == "none"`. Any other `alg` still gets a real HMAC check — the bug is the asymmetry, not the absence of crypto. |
| `9ba4b2d` — *M1 T5: handlers* | 2026-10-12 03:18 | `resolveVulnerableStore` in `app/api/documents.go`: the acting org is `claims.OrgID`, straight from the token, and the path's `{org_id}` is read but never checked against real membership. |

Also planted in `0fc8fce`, same boundary, not separately numbered: the vulnerable `/auth/token` mints a token on **email alone** and never calls `VerifyPassword` (B1 1.1). The PoC deliberately does not use it — it logs in with the real password so login succeeds in both modes and the only variable is the tenancy control under test.

**Why neither commit is the finding.** A verifier that accepts `alg:none` forges *identity* — but in a system that resolves the acting org from server-side membership, a forged `org_id` claim is inert, because nothing reads it. A path that trusts `claims.OrgID` is a weak design — but with a verifier that actually checks signatures, the claim can only ever hold the value the honest issuer minted. The vulnerability is that **one component trusts a field the other component lets an attacker write.** Review either PR in isolation and you see a documented, intentional departure from a control that lives beside it in the same file. The finding exists only in the union.

Same structural point as finding 01's two-commit split, one layer up: the composition, not the component, is the defect.

Note the third component that is *not* a half-bug: `auth.Encode` always signs HS256 and has no code path that signs anything else. The issuer is honest in both modes (SR-B1-4). The forgery is entirely verifier-side, which is why the writeup's token dump shows `org_id` as **the only field that differs from an honest token**.

## Why a real developer writes this

`verifyVulnerable`: they read `alg` out of the header because *that is what the JWT spec says the field is for*, and they special-case `"none"` because the spec defines it. This is not carelessness — it is specification compliance applied to a field that happens to be attacker-controlled.

`resolveVulnerableStore`: putting `org_id` in the token to avoid a membership lookup per request is a normal, correct-about-performance design. M1-N5 names the residue: a claim that must not be trusted *should not be present*, because a signed field looks authoritative whether or not anything is entitled to believe it. The claim survives the control and is carried to M3 as R-M1-3.

## The controls, and where each lives

| Half-bug | Control | Where | SR |
|---|---|---|---|
| `alg` read from the token | Algorithm fixed at HS256 **in code**; the header is recomputed over, never decoded to decide anything; constant-time compare; `exp` enforced | `verifyHardened`, `app/auth/jwt.go` | SR-B2-3 |
| Path trusts `claims.OrgID` | Acting org decided by the user's **real, current membership** in the path's `{org_id}`, looked up server-side; `claims.OrgID` never consulted | `resolveHardenedStore`, `app/api/documents.go` | SR-B2-2 |

Both hardened versions were written **before** their vulnerable counterparts, in the same commits, per the AGENTS.md house rule.

In hardened mode the exploit dies at the first control — 401 at the verifier — and never reaches the second. The second control is therefore not exercised by this PoC; it is exercised by the honest-token/foreign-org-path variant that finding 01's T8 replay added for exactly this reason.

## A defence nobody designed

The PoC's first draft forged a garbage `sub` as well as a forged `org_id`. It died at the **database** with a 500: `documents.created_by` carries a foreign key to `users(id)`, and a non-existent user cannot author a row. A schema constraint, written for referential integrity, caught what the handler forgot to check.

Defence in depth observed live rather than asserted. The PoC now keeps `sub` and `role` honest, which also sharpens the finding to its thesis: **`org_id` is the only forged field.**

## Attribution — the M6 dataset

| Artifact | Author | Evidence |
|---|---|---|
| `verifyHardened` (the control) | **Agent** | `Co-Authored-By` agent trailer on `0fc8fce`; agent session transcript for T4 |
| `verifyVulnerable` (the planted verifier) | **Agent** | same |
| `resolveHardenedStore` (the control) | **Agent** | trailer on `9ba4b2d`; two agent session transcripts for T5 |
| `resolveVulnerableStore` (the planted path) | **Agent** | same |
| `exploit.py` | By hand | No trailer on `3004543`; no agent session transcript for T6 |

**Evidence basis.** Agent authorship is positively evidenced by two independent sources that agree: a `Co-Authored-By` trailer and an agent session transcript for that task. Hand authorship is inferred from the absence of both — weaker evidence — corroborated by the implementation plan's per-task notes, which name the agent explicitly for T4 and T5 and for no other M1 task.

**What the record supports.** Finding 02 is the first fully agent-authored finding in the repo: both halves of the vulnerability *and* both controls that kill them were written by the coding agent under AGENTS.md gates, from a threat-model diff it was instructed to read in full. It implemented the controls correctly, implemented the planted departures correctly, and documented both in comments that cite the SR numbers.

**What it does not support.** Nothing here is evidence that an agent introduces auth bugs unprompted. It was told to plant these, by name, with leaf numbers. The interesting M6 question this *does* open is the composition problem: the agent produced two commits, each individually compliant with its instructions and each individually reviewable as correct-plus-documented-departure, whose union is an exploitable cross-tenant write. **No single artifact the agent was asked to produce contains the finding.** Whether a reviewer — human or agent — would catch that is an M3/M6 question, not one M1 answers.

Verification was independent of the agent's self-report throughout: `go build`/`go vet`, then live runs against the real stack in both modes (wrong-password 200 in vulnerable mode; hardened container with no `JWT_SECRET` correctly refusing to start), then the PoC asserted against captured output twice in each mode.

## Since M3 — what the same forge reaches now (added at M3 T11)

Recorded here because M3 changed what finding 02 teaches without changing finding 02's code. Nothing below is a new planted bug, and the M1 record above is unchanged.

**The forge now also forges a role** (`ce0183e`, *M3 T3*, 2026-11-13). M3 gave roles teeth on the direct API, in both modes. In vulnerable mode the role comes from the token's `role` claim (`resolveStore` in `app/api/documents.go`), by the same *"I already verified the JWT"* reasoning that takes the org from `claims.OrgID`. An honest token carries the user's real role, so the role check holds against it, and finding 05 needs exactly that. But an `alg:none` token can claim `"role": "admin"`, and the vulnerable direct API's role check reads that claim. That is not a new weakness compared with M1, where roles had no effect at all. But the forge now passes the vulnerable direct API's role check too, so it reaches every action the role table gates, delete included.

**And it reaches role changes** (`e566749`, *M3 T5*, 2026-11-16). The direct role route (`PATCH /orgs/{org}/members/{user}`) resolves the caller's role server-side, from `claims.Sub`, in both modes. That is the right design for the role. But in vulnerable mode `sub` is itself attacker-written. A forged token whose `sub` names a real admin of the target org is an admin for this route. So 02 reaches role changes in any org, given one admin's user id. A user id is not a secret, and role changes are the action M3 treats as non-delegable even for an honest admin's agent.

**Hardened mode is unaffected, and M3 removed the residue M1 deferred.** The verifier still rejects the forge (SR-B2-3). Since `ce0183e`, hardened tokens carry neither `org_id` nor `role` (SR-M1-5), which is option D of [`defenses/the-token-is-not-the-authority.md`](../../defenses/the-token-is-not-the-authority.md), deferred from M1 as R-M1-3. *A claim that must not be trusted is no longer present.* `m1-tenancy.md` still records it as "carried to the M3 diff". That file is dated and is not edited; this paragraph and that defenses doc record the delivery.

**Attribution of the M3 changes:** `ce0183e` and `e566749` are **agent** commits (`Co-Authored-By` trailer; agent sessions for M3 T3 and T5). This section was **drafted by the agent and applied by hand**, because this file is a hardened zone. That third value is defined in [finding 05's answer key](../05-confused-deputy/ANSWER-KEY.md#attribution--the-m6-dataset).
