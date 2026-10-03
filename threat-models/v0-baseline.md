# Threat Model v0 — Baseline

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Localhost only. See [SECURITY.md](../SECURITY.md).

**Status:** M0 T4, in progress. B3, B4, B5 and B9 are not yet drafted — see §7.
**Derived from:** [`docs/product-spec.md`](../docs/product-spec.md) at commit `ee14575` and later.
**Rule:** this document is committed *before* the product code it governs. Each module adds a diff
(`threat-models/mN-<module>.md`), never an edit in place.

---

## 1. Method

This threat model is not generated from a component diagram. It is derived from **§8 of the product
spec — the nine stated assumptions** — because an assumption is the only thing in a spec that is
falsifiable, and a threat model that cannot be falsified cannot be tested.

For each assumption:

1. **Name the prize.** If this assumption is false, what does an attacker *get*? That sentence is the
   root of the attack tree. It is not "something could go wrong"; it is a concrete gain.
2. **Decompose into the distinct ways it can be false.** Branches are *mechanisms*, leaves are things
   a PoC can attempt. If a leaf cannot be written as `exploit.py`, it is not a leaf yet.
3. **Invert each leaf into an obligation on the design.** "What would have to be true for this leaf to
   be unreachable?" written as a requirement on the code, is a **security requirement (SR)**.
4. **Assign the leaf to exactly one boundary.** Leaves that belong elsewhere are cross-referenced, not
   duplicated. Without this rule the nine sections converge into nine copies of the same document.

The security requirements are what gets built. The leaves are what gets exploited. Each finding in
`attacks/` therefore traces back to a numbered sentence in the spec, and the writeup's answer to
*"why this control?"* is a citation rather than an opinion.

**STRIDE is used as a completeness check, not as the generator** (§6). The dangerous properties of an
agent platform are authority-flow properties — who decided this action was permitted — not element
properties. STRIDE's value here is the question *"did I miss a repudiation branch?"* asked once per
boundary after the tree exists.

### 1.1 ID stability

IDs are permanent. Never renumber; supersede instead.

| ID form | Meaning |
|---|---|
| `B1`–`B9` | Trust boundary (also listed in `README.md`) |
| `G-Bn` | Root goal of boundary *n*'s attack tree |
| `n.m` / `n.m.k` | Branch / leaf within that tree |
| `SR-Bn-k` | Security requirement derived from that tree |
| `A8.n` | Assumption *n* in product spec §8 |

A leaf that turns out to be unreachable is marked `[retired: reason]` and kept. A requirement replaced
by a stronger one is marked `[superseded by SR-Bn-k]` and kept. The diff history is the artifact; a
clean document that lies about how it got here is worth less than a messy one that doesn't.

---

## 2. Assumption → boundary map

Every assumption is tested by at least one boundary. Every boundary tests at least one assumption —
except where the derivation found a *gap in the spec*, which is itself a finding (§5, B7).

| | Assumption (spec §8) | Tested by |
|---|---|---|
| A8.1 | A user's membership role reflects what they are allowed to do in that org | B2, B3 |
| A8.2 | An agent session acts within the authority of the user it was created for | B3, B5 |
| A8.3 | Documents belong to exactly one org and are reachable only within it | B2 |
| A8.4 | A tool does what its description says it does | B6, B5 |
| A8.5 | A catalog listing behaves the same after installation as at review time | B6 |
| A8.6 | Content the agent reads — documents, pages, tool output — is *data* | B4 |
| A8.7 | Content the agent loads as a skill is *instructions*, and following it is correct | B9 |
| A8.8 | Configuration and policy are changed only by people entitled to change them | B8 |
| A8.9 | The audit record is a faithful account of what the agent did | B7, B8 |
| — | *(unstated)* Every API call resolves to exactly one principal — spec §3 preamble | B1 |
| — | **GAP** — nothing in §8 covers the platform's own runtime identity | B7 (§5) |

---

## 3. Boundaries drafted

### B1 — Internet → API

**Assumption under test:** spec §3 preamble, *"Everything in the system acts as exactly one principal,
and every API call resolves to one."* A8.1 in part.

**Scope note — deliberately thin.** The web tier exists only far enough to make the agent surface
reachable (`README.md`, spec §9). Classic web-tier classes are **declared non-coverage**, not
oversights: reflected/stored XSS in the htmx surface, CSRF, SQL injection, request smuggling, TLS
termination, deserialization. They are well covered by general-purpose vulnerable web applications and
carry no agent-specific teaching value. Recorded in `coverage/` with this rationale. B1 models only
what must hold for the *agent* boundaries to mean anything: that a principal is real, and that its
authority is the authority the server granted it.

**G-B1 — An unauthenticated internet principal obtains an authenticated foothold, or reaches a
privileged operation without one.**

```
1. Obtain a token without presenting a credential
   1.1 POST /auth/token accepts a user id or email as sufficient proof — seeded-user impersonation
   1.2 Token forgery — absent/weak signature verification, or a default dev signing secret
       committed to the repository
   1.3 Scope inflation at issue time — the token is minted with the role or orgs the *request*
       asked for rather than the ones the server's records show
2. Act with no token at all
   2.1 A route ships without the auth middleware attached — authorisation is opt-in, so a new
       handler defaults to open
   2.2 An intentionally-unauthenticated endpoint leaks state (configuration, seed contents,
       counts, identities)
3. Abuse the surfaces that are unauthenticated by design
   3.1 Publisher registration is open by product decision (spec §3.5) — unlimited zero-cost
       identities and listings                                            → owned by B6 (5.2)
   3.2 No rate limit on POST /auth/token — user enumeration, and credential attack at leisure
4. [declared non-coverage] classic web-tier classes — see scope note above
```

**Security requirements**

| ID | Requirement | Kills |
|---|---|---|
| SR-B1-1 | **Deny by default at route registration.** A route with no declared auth policy fails to register and the server refuses to start — not a request-time check that a missing middleware would also skip. | 2.1 |
| SR-B1-2 | `POST /auth/token` requires a verifiable credential. No principal may be assumed from an identifier alone. | 1.1 |
| SR-B1-3 | The signing key is supplied by the environment, has no default, and is never committed. In hardened mode the stack refuses to start without it. | 1.2 |
| SR-B1-4 | Token claims are derived from the server's own membership records at issue time and are never echoed from the request. | 1.3 |
| SR-B1-5 | Unauthenticated endpoints return liveness only. | 2.2 |
| SR-B1-6 | Token issuance is rate-limited per source and per subject; denials are logged with source. | 3.2 |
| SR-B1-7 | Declared non-coverage is recorded in `coverage/` with rationale. The lab does not claim web-tier hardening it has not done. | 4 |

**Accepted exposure.** `/healthz` returns `{"status":"ok","hardened":true|false}`, and the hardened
flag is readable without authentication. This is deliberate: the attack suite and CI must be able to
assert which mode the stack is in from outside (`.github/workflows/ci.yml`). In a real product this
would be an information leak worth closing; in a lab whose entire contract is "the same exploit passes
here and fails there," externally-visible mode is a requirement. Recorded as accepted rather than
silently tolerated.

---

### B2 — Tenant ↔ Tenant

**Assumption under test:** A8.3, *"Documents belong to exactly one org and are reachable only within
it."* Also touches A8.1 and A8.2.

**G-B2 — A principal authenticated to Org B reads, modifies or deletes data owned by Org A.**

```
1. Obtain a token the API will accept as Org A
   1.1 Forge the org_id claim — signature unverified, alg:none accepted, or key confusion
   1.2 Replay a legitimately-issued Org A token (no session binding, no expiry enforced)
   1.3 Hold a genuine membership in both orgs, and have the API resolve the acting org from the
       token rather than from the request path
2. Keep a valid Org B token and reach Org A's rows anyway
   2.1 IDOR on the object identifier — GET /orgs/B/documents/<A's uuid>, handler filters on id only
   2.2 Path/claim mismatch — the handler trusts :org_id in the path without checking membership
   2.3 A query path that forgot the scope entirely — list, search, export, or a JOIN that re-widens
       a scoped subquery
   2.4 Error or timing oracle — 404 vs 403 distinguishes "does not exist" from "exists, not yours"
3. Reach Org A's data through a principal that is not a user
   3.1 An agent session in Org B resolves a document by id with no org scope      → owned by B5
   3.2 A seed or system principal with no org binding (seed script, health check, admin path)
4. Corrupt the ownership record instead of bypassing the check
   4.1 Mass assignment — create or update a document with an attacker-chosen org_id
   4.2 Move an existing document between orgs via a PATCH that accepts org_id
```

**Security requirements**

| ID | Requirement | Kills |
|---|---|---|
| SR-B2-1 | Tenant scope is applied in the **store layer**, not in handlers. There is no code path that can obtain a database handle without an org context — `store.ForOrg(ctx)` is the only constructor. | 2.1, 2.3; makes 2.2 unreachable by construction rather than by review |
| SR-B2-2 | The authoritative org for a request is resolved by a **server-side membership lookup** keyed by (user, org-in-path). Never from a token claim. | 1.1, 1.3, 2.2 |
| SR-B2-3 | Tokens are signature-verified with a fixed algorithm, carry an expiry, and `alg` is never read from the token. | 1.1; bounds 1.2 |
| SR-B2-4 | Object identifiers are non-enumerable, and authorisation is evaluated against the **object's** owner rather than the requested path. | 2.1 (defence in depth) |
| SR-B2-5 | A cross-tenant denial is indistinguishable from a not-found in status, body and latency. | 2.4 |
| SR-B2-6 | `org_id` is never client-settable on any write path. | 4.1, 4.2 |
| SR-B2-7 | Every principal carries an org binding, including seed and system principals. A principal without one cannot reach the document store. | 3.2 |
| SR-B2-8 | Every authorisation denial is logged with principal, target org and decision. | — (makes M1 detection measurable) |

**Planted for M1** (per the implementation plan): scope applied in the handler instead of the query
layer (→ leaf 2.3), and one endpoint that trusts the JWT `org_id` without a membership check
(→ leaves 1.3 / 2.2).

**Exploits:** `attacks/01-cross-tenant-read` → leaf 2.3 · `attacks/02-jwt-org-claim` → leaf 1.3.

---

### B6 — Platform ↔ Publisher (marketplace supply chain)

**Assumptions under test:** A8.4, *"A tool does what its description says it does"*; A8.5, *"A catalog
listing behaves the same after installation as it did at review time."*

**Framing.** Publishers are explicitly trusted by nobody (spec §3.5) and registration is open. B6 is
therefore not about *keeping bad publishers out* — the product decision is that they get in. It is
about what a hostile listing can reach once an org installs it.

**G-B6 — A publisher-controlled artifact causes the platform, or an org's agent, to take an action the
org did not intend.**

```
1. Lie in the listing
   1.1 A description that misstates what the tool does — deception aimed at the human at install time
   1.2 A description aimed at the *model* rather than the human: the tool description is loaded into
       the agent's context, so it is an instruction-delivery channel (tool poisoning)   → see B9
   1.3 Name or publisher-name squatting; impersonating a recognised tool
2. Change after review — the rug pull (A8.5 directly)
   2.1 PATCH /catalog/:id alters the manifest after orgs have installed it
   2.2 An MCP server changes the tool set it exposes between discovery and use
   2.3 The server behaves benignly while being reviewed and maliciously later — time-, tenant- or
       condition-dependent behaviour
   2.4 Version pinning exists but is advisory — the platform re-resolves to latest on reconnect
3. Attack the platform itself at install or connect time
   3.1 A manifest whose endpoint points at an internal address — SSRF *from the platform*  → B7 (1,2)
   3.2 Oversized, deeply-nested or malformed manifest — resource exhaustion, parser abuse
   3.3 The install flow forwards an org credential to the publisher's endpoint
4. Reach across orgs through one shared listing
   4.1 A single malicious listing installed by many orgs gives the publisher a vantage point over
       several tenants at once — impact is B2's, the call itself is B5's
5. Abuse publisher identity
   5.1 Publisher account takeover — the attacker inherits every existing installation
   5.2 Registration is free and unvetted by design: identity carries no provenance signal
```

**Security requirements**

| ID | Requirement | Kills |
|---|---|---|
| SR-B6-1 | Installation pins an **immutable version by content digest**. A changed manifest is a new version requiring explicit adoption, never a silent update. | 2.1, 2.4 |
| SR-B6-2 | Manifests and tool descriptions are **untrusted input to the model**: wrapped and marked as data at context assembly, never concatenated as platform instructions. | 1.2 (with B9) |
| SR-B6-3 | The tool set discovered at install time is the tool set callable. Runtime redefinition requires re-consent and is denied until granted. | 2.2 |
| SR-B6-4 | The platform's own outbound connection to a publisher endpoint is subject to the same egress allowlist as agent tools. The MCP client is not a trusted caller. | 3.1 |
| SR-B6-5 | No org credential is ever forwarded to a publisher endpoint. The platform brokers with a per-installation identity scoped to that installation. | 3.3 |
| SR-B6-6 | Publisher identity is namespaced; display names cannot collide. Provenance (publisher age, install count, version history) is shown at the install decision point. | 1.3, 5.2 |
| SR-B6-7 | Manifest parsing is bounded in size, depth and time, and failure is non-fatal to the platform. | 3.2 |
| SR-B6-8 | Every catalog mutation is recorded immutably with actor, before, after and timestamp, and the diff is visible to orgs that have installed it. | 2.1, 2.3; detection |

**Accepted by design.** Open publisher registration (5.2) is a product decision, not a defect. The lab
keeps it and mitigates downstream — that is the realistic shape of marketplace risk, and removing it
would remove the boundary.

**Residual.** 2.3 (behaviour conditioned on *who is asking*) is not preventable at the boundary. A
server that is honest during discovery and hostile in production cannot be distinguished by
inspection. It is pushed to B5 — every call is mediated regardless of the tool's reputation — and to
detection. Stated here rather than papered over.

---

### B7 — App → Cloud (runtime identity, metadata, egress)

**Assumption under test:** A8.9 in part, for the audit-redaction path.

> **Spec gap found by this derivation.** §8 contains no assumption about the platform's *own* runtime
> identity. The spec says what the agent may reach on behalf of a user, and says nothing about what the
> application itself holds. That silence is the vulnerability's natural habitat. Proposed addition:
> **A8.10 — "The application's runtime identity and internal network position are reachable only by the
> application itself."** Raise as a spec PR; do not patch it silently here — the finding is that the
> spec was incomplete, and that belongs in the history.

**Scope note.** Deployment topology is a non-goal for this revision (spec §9). B7 is exercised against
the `mock-metadata` fixture in Compose, which makes cloud-metadata behaviour reproducible with no
cloud account. The boundary is modelled **now**, before M2, so the controls are derived rather than
retrofitted the week the SSRF PoC lands.

**G-B7 — A code path reachable by an untrusted principal obtains, or acts with, the application's own
runtime identity or network position.**

```
1. Reach the metadata endpoint
   1.1 http_fetch to 169.254.169.254 returns service-account credentials        → entered via B5
   1.2 A naive denylist is bypassed — decimal/octal IP forms, [::ffff:169.254.169.254],
       a 302 redirect to the metadata address, or DNS rebinding between check and connect
2. Use the application's network position rather than its identity
   2.1 Fetch internal-only services reachable from the app container — db, gateway, mock-metadata,
       sibling containers
   2.2 Existence oracle — response timing or error shape reveals what is listening
3. Move data outward
   3.1 Tenant-derived content placed in an outbound URL — query string, path segment, DNS label
   3.2 A callback to an attacker-controlled host confirms otherwise-blind paths
4. Abuse the identity once held
   4.1 One application-wide service account — the token's scope is the union of everything the
       product ever needed
   4.2 The credential is long-lived and not audience-bound, so it is useful long after the fetch
5. Obtain the identity from the platform's own records
   5.1 The audit record is written *before* execution and therefore contains raw tool-call payloads,
       including bearer tokens                                               → control, no finding
```

**Security requirements**

| ID | Requirement | Kills |
|---|---|---|
| SR-B7-1 | Egress is **allowlist-only**, evaluated after DNS resolution against the resolved address, and re-evaluated on every redirect hop. Link-local and private ranges are denied by range, never by string match. | 1.1, 1.2, 2.1, 3.2 |
| SR-B7-2 | Outbound requests carrying tenant-derived content in the URL are denied (link-blocking). | 3.1 |
| SR-B7-3 | Per-component service identity with least privilege. No shared application-wide account. | 4.1 |
| SR-B7-4 | Runtime credentials are short-lived and audience-bound. | 4.2 |
| SR-B7-5 | Secrets are redacted at audit **write** time, not read time, with a regression test asserting that no token pattern survives into the audit store. | 5.1 |
| SR-B7-6 | Denied egress and any hit on the metadata range are emitted as high-signal detection events. | — (detection) |
| SR-B7-7 | Denied fetches return a uniform response regardless of why they were denied. | 2.2 |

**SR-B7-5 is a control without a finding** (per the implementation plan, M2). Audit-log secret leakage
is a known bug class; the ten-finding cap is spent elsewhere. The control ships, CI enforces it, and
it is the repo's answer to MCP01 — no PoC and no writeup of its own. Recorded here so the absence is
visibly a decision.

---

### B8 — Control plane ↔ data plane

**Assumption under test:** A8.8, *"Configuration and policy are changed only by people entitled to
change them."* Also A8.9, for audit integrity.

**Framing.** Every other boundary assumes its control is running as configured. B8 is the boundary an
attacker crosses when they stop fighting the control and start editing it. It is the one that, if
broken, silently invalidates the rest of this document.

**G-B8 — A principal weakens, disables or erases a control rather than defeating it.**

```
1. Change policy through the data plane
   1.1 A tenant admin edits gateway thresholds or grants through the ordinary product API, because
       configuration shares the API's authorisation model
   1.2 The agent calls a tool that mutates configuration — it can rewrite its own guardrails
2. Change policy at rest
   2.1 Policy files or policy data are mounted writable into a container the product can write to
   2.2 Policy lives in the database beside tenant data, reachable with the same credentials
3. Disable rather than edit
   3.1 Flip HARDENED at runtime from inside the product
   3.2 Make the gate fail *open* — crash, time out or overload the judge; an undefined policy
       result is treated as allow
   3.3 Uninstall and reinstall to reset state to a more permissive default
4. Scope confusion
   4.1 Org A's admin changes a setting that is actually global and applies to Org B
5. Erase the evidence
   5.1 Mutate or delete audit records from the data plane
   5.2 The policy change itself is not an audited event
```

**Security requirements**

| ID | Requirement | Kills |
|---|---|---|
| SR-B8-1 | Policy, thresholds and grants are **not writable through the product API**. The control plane is a separate surface with its own authorisation and its own principal set. | 1.1 |
| SR-B8-2 | No tool exposed to the agent can mutate policy, grants or the hardened flag — enforced by an explicit denylist in the gateway, not by the accident of nothing being implemented yet. | 1.2, 3.1 |
| SR-B8-3 | Policy artifacts are read-only at runtime: mounted `ro`, loaded at start, changed only by a deploy. `gateway/policy/` is a hardened zone in the repo for the same reason. | 2.1, 2.2 |
| SR-B8-4 | The gate **fails closed**. An undefined policy result, a judge timeout or an unreachable gateway denies. Verified by fault injection, not by inspection. | 3.2 |
| SR-B8-5 | A tenant-scoped setting cannot widen beyond its tenant; global settings are not tenant-writable. | 4.1 |
| SR-B8-6 | The audit store is append-only to every data-plane principal. | 5.1 |
| SR-B8-7 | Every policy and configuration change is itself an audited event with actor, before and after. | 5.2; detection |
| SR-B8-8 | Reinstalling an item does not restore a previous grant. Grants are re-consented, never resumed. | 3.3 |

**Exploit (M3):** `attacks/06-policy-plane` → leaf 1.1.

---

## 4. Boundaries not yet drafted

Owned, scoped, and deliberately left empty rather than filled with placeholder prose.

| Boundary | Assumption | Owner | Note |
|---|---|---|---|
| B3 — User → Agent | A8.1, A8.2 | joint | Privilege escalation through delegation; drafted after B4/B9 so the context-channel work informs it |
| B4 — Agent ↔ untrusted content | A8.6 | DB | The novel half; no industry template to copy |
| B5 — Agent → Tools | A8.2, A8.4 | joint | The capability boundary; absorbs leaves handed off from B2 (3.1), B6 (4.1), B7 (1.1) |
| B9 — Platform ↔ context supply chain | A8.7 | DB | The reason B9 is its own boundary is in `README.md`; the tree must show it |

---

## 5. Findings from the derivation itself

Things this exercise discovered about the *spec*, not about the product. Recorded because the value of
doing threat modelling before code is mostly in this section.

1. **§8 has no assumption about the platform's own runtime identity.** Found at B7. Proposed A8.10.
   The spec is complete about what the agent may do on a user's behalf and silent about what the
   application itself holds — which is precisely where SSRF-to-metadata lives.
2. **A8.6 and A8.7 are in direct tension.** A8.6 says content the agent reads is data; A8.7 says
   content the agent loads as a skill is instructions. Both are reasonable; together they mean the
   product's safety depends entirely on the *classification step* that decides which bucket a given
   piece of text lands in. No assumption in §8 covers that step. B9 must test it.
3. **A8.5 is unenforceable as stated.** "Behaves the same after installation as at review time" cannot
   be verified for a remote service whose behaviour may be conditioned on the caller (B6, leaf 2.3).
   The honest form is "*the artifact* is the same," which is a digest-pinning claim. The assumption
   should be narrowed in the spec rather than defended in the code.

---

## 6. STRIDE completeness pass

Run once per boundary after its tree exists, as a check for missing branches — never as the generator.
Marked when done.

| | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| B1 | ✅ 1.1–1.3 | ✅ 1.3 | ⬜ | ✅ 2.2 | ⚠️ 3.2 only | ✅ 1.3, 2.1 |
| B2 | ✅ 1.x | ✅ 4.x | ⬜ | ✅ 2.x | n/a | ✅ 1.3 |
| B6 | ✅ 1.3, 5.1 | ✅ 2.x | ✅ 2.1 | ✅ 4.1 | ✅ 3.2 | ✅ 3.3 |
| B7 | ⬜ | ✅ 5.1 | ✅ 5.1 | ✅ 1.x, 2.x, 3.x | ⬜ | ✅ 4.x |
| B8 | ⬜ | ✅ 1.x, 2.x | ✅ 5.x | ⬜ | ✅ 3.2 | ✅ 1.2 |

⬜ = not yet checked, not "no threats exist." ⚠️ = checked, thin by design.
Denial of service is consistently thin across this model: availability is out of scope by declaration
(spec §9, "the lab is about correctness of authority, not availability"), *except* where unavailability
changes an authorisation outcome — which is exactly SR-B8-4, fail-closed.

---

## 7. Open

- [ ] B3, B4, B5, B9 trees and requirements (§4)
- [ ] Spec PR: add A8.10, narrow A8.5 (§5.1, §5.3)
- [ ] Complete the STRIDE pass for the drafted boundaries (§6)
- [ ] `coverage/` entry for B1's declared non-coverage (SR-B1-7)
