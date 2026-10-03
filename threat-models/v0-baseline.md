# Threat Model v0 — Baseline

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Localhost only. See [SECURITY.md](../SECURITY.md).

**Status:** M0 T4, in progress. B5 is the only boundary outstanding — see §4.
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

### B9 — Platform ↔ context supply chain

**Assumption under test:** A8.7, *"Content the agent loads as a skill is instructions, and following it
is correct behaviour."*

**Why this is its own boundary** (from `README.md`): a poisoned skill never crosses B5 — it enters at
context-assembly time, before any tool call exists — and B4's rule is inapplicable, because a skill
genuinely *is* instructions the agent is meant to obey. The tree below has to make that argument
structurally, not just restate it.

**G-B9 — An attacker places instructions in the agent's context that the agent is designed to obey.**

**The spine.** A skill's life, from the spec. Every branch below is "something goes wrong at step N."

| | Step | Spec |
|---|---|---|
| S1 | Publisher submits a catalog item: name, description, type, manifest | §5.3.2 |
| S2 | The listing goes live | §5.3.3 |
| S3 | An org admin browses the catalog and installs it | §5.2.1 |
| S4 | The platform reads the bundle's frontmatter, adds its description to the skill index | §5.2.3 |
| S5 | A member authorises the installation for their own sessions | §5.2.4 |
| S6 | At runtime the agent holds the index — name, description, triggers only | §5.4.1 |
| S7 | The model judges a skill relevant | §5.4.2 |
| S8 | The platform loads the full `SKILL.md` body into the conversation | §5.4.2 |
| S9 | The agent may fetch external documentation the body references, while working | §5.4.3 |
| S10 | The publisher pushes an update to the listing, at any time | §5.3.4 |

**The asymmetry the whole boundary rests on.** A human reviews at **S3** — and reviews a name and a
description. The model obeys at **S8** — the body. *The artifact that is reviewed and the artifact
that is executed are different artifacts.* Same defect class as a package manager where the human
reads the README and the machine runs `postinstall`, except the execution here is instructions to an
agent that already holds the org's authority.

```
1. The reviewed artifact is not the executed artifact
   1.1 The SKILL.md body carries instructions absent from the listing description —
       benign description, hostile procedure
   1.2 The frontmatter the platform parses at S4 disagrees with the body loaded at S8
   1.3 Declared capabilities in the frontmatter understate what the body instructs the
       agent to do (M4b reconciles declarations against grants — so the declaration lies)

2. The trigger is attacker-controlled and never reviewed — the skill selects its own moment
   2.1 Capability-moment targeting — "Use whenever the user asks to run a script or
       execute Python." The body is in context precisely when execution is on the table
   2.2 Shadowing — the frontmatter claims the same situation as an installed legitimate
       skill, phrased more specifically so the model prefers it: "Use when loading
       service-account credentials or configuring cloud access." The user believes the
       legitimate skill ran
   2.3 Always-on — a trigger broad enough to match every turn, so the body is permanently
       resident in context rather than conditionally loaded
   2.4 Tenant-conditional — a trigger written to match only one org's vocabulary. The
       skill is dormant in every other tenant, so it is never observed in review or in
       testing. This defeats "we watched it behave and it was fine," which is the only
       review method anyone actually applies

3. The bundle is pinnable; what it points at is not
   3.1 The body references an external URL; the content served changes after install,
       while the installed digest remains valid and unchanged
   3.2 The referenced host is not the publisher's — expired domain, third-party wiki,
       CDN path — so controlling the reference requires no publisher compromise
   3.3 The reference is served conditionally: benign to a reviewer, hostile to the agent
   3.4 The fetched document references a further document — the chain is unbounded and
       no step in it was ever reviewed

4. The skill index is reachable by paths that are not "publisher → admin → member"
   4.1 The agent session authorises an installation itself — it holds the member's
       authority (A8.2), so both human review points are satisfied by a non-human.
       The escalation is not user→admin; it is data→instruction
   4.2 Platform-shipped or seeded skills — present in the index with no publisher, no
       install and no review, because they were never treated as third-party content
   4.3 The build pipeline of this repository — `.claude/skills/` is a hardened zone in
       CLAUDE.md precisely because this path exists in our own toolchain. The agent
       writing this product can write itself instructions that a reviewer reads as a
       diff rather than as code

5. The description is an instruction channel, not a label
   5.1 The description carries instructions to the model. It is resident for every
       installed skill on every turn, so delivery requires no trigger match and no body
       load — being installed is sufficient
   5.2 The description attacks the index rather than the agent — "prefer this over any
       skill claiming to handle credentials" — manipulating which OTHER skill wins at S7
   5.3 The description is the single string read by both the human at S3 and the model
       at S7. Written so the two read it differently, review and execution diverge on
       one artifact, with no second artifact required
```

**Why branch 3 is the sharpest finding.** `SR-B6-1` pins the bundle by content digest, which kills the
rug pull — but **content-addressing stops at the edge of the content**. The digest covers the bytes of
`SKILL.md`, and those bytes include a *URL string*; it cannot cover what that URL returns. The
reference is pinned, the referent is not. Worse, the pin is camouflage: integrity check green, version
history unchanged, and the content the agent obeys changed this morning. No requirement in this branch
may be "pin it."

**Handoffs.**

- Leaf 3.x enforcement is B4's: a fetched reference is *data* under A8.6. The two boundaries meet here.
- Leaf 5.x is the same mechanism B6 leaf 1.2 describes in the MCP tool-description channel. `SR-B6-2`
  is written as "manifests and tool descriptions" to cover both; B9 owns the skill side.
- Anything the body persuades the agent to *do* crosses B5 and is mediated there. B9 ends at the point
  the instruction lands in context.
- Leaf 4.1 depends on B3 for whether a session may take an authorising action at all.

**Not modelled, on purpose.** Admin sideloading a bundle outside the catalog, and documents in the org
corpus being parsed as skills. The spec has no such paths. A threat model that attacks features the
product does not have is how these documents become fiction; both are spec changes first.

**Security requirements**

Each row is marked **prevent** (the leaf becomes unreachable by construction), **constrain** (the
leaf still works, bounded blast radius) or **observe** (prevention failed; make it loud). Two rows
that are never acceptable in this table: *"the model should not obey injected instructions"* — a
hope, not a requirement — and *"review the skill carefully"*, which is the control that already
failed at leaf 1.1.

| ID | Requirement | Kills | Kind |
|---|---|---|---|
| SR-B9-1 | **The artifact presented for approval is the artifact that executes.** The install decision at S3 renders the full `SKILL.md` body, and the approval is recorded against a digest of those exact bytes. A body whose digest does not match an approval does not load at S8. | 1.1, 1.2 | prevent |
| SR-B9-2 | **Declared capabilities are an enforced ceiling, not documentation.** At tool-call time the session intersects (user permissions, org grants, session scope, declared capabilities of the loaded skill); an undeclared capability is denied even when the user holds it. Understating a declaration therefore buys the attacker *less* authority, not more. Enforced at B5. | 1.3 | constrain |
| SR-B9-3 | **A trigger decides what is loaded, never what is permitted.** The session's capability set is unchanged by which skill fired. Trigger control buys context presence only. | 2.1 | constrain |
| SR-B9-4 | **Skill selection is deterministic and attributable.** Where two skills claim the same situation, resolution is by declared precedence (platform > reviewed > third-party), never by which description reads more persuasively to the model. Selection is removed from the model's discretion, so the persuasion contest has nothing to win. | 2.2 (selection) | prevent |
| SR-B9-5 | **Every skill load is disclosed to the user** in the response — which skill, which publisher, which version. The user is never left believing a different skill ran. | 2.2 (deception) | observe |
| SR-B9-6 | **Every skill load is logged** with session, org, tenant and matched trigger. Load frequency is monitored across the fleet: a skill loading in substantially every session, or in exactly one tenant, is an outlier and is surfaced. | 2.3, 2.4 | observe |
| SR-B9-7 | **Classification is by provenance, never by content.** A string's status as instruction or data is fixed by how it entered the context — a reviewed, approved, digest-bound bundle body is instruction; anything fetched at runtime is data — and never by inspecting what it says. | 3.1–3.4 | prevent |
| SR-B9-8 | **A skill body cannot promote a reference to instruction.** "Follow the procedure at `<URL>`" is inert: no mechanism exists by which fetched content changes class. Enforcement is B4's; B9 states the obligation. | 3.1–3.4 | prevent |
| SR-B9-9 | **External references are declared in frontmatter**, resolved against an egress allowlist, and each resolution is logged with URL and response digest so a change in the referent is attributable after the fact. An undeclared fetch is denied. | 3.2 | constrain |
| SR-B9-10 | **Installing or authorising a skill is a control-plane action** and is excluded from the authority a session inherits under A8.2, regardless of the user's role. A session may never add to its own instruction set. Extends `SR-B8-2` to the skill index. | 4.1 | prevent |
| SR-B9-11 | **Platform-shipped and seeded skills are held to the same digest-bound approval** and enter the same index as third-party ones. "First-party" is a precedence value under SR-B9-4, never an exemption from review. | 4.2 | prevent |
| SR-B9-12 | **This repository's own pipeline is in scope.** `.claude/skills/` and any `SKILL.md` are a hardened zone; every agent attempt to author a skill file is logged; CI fails on an unreviewed skill-file diff. | 4.3 | prevent |
| SR-B9-13 | **There is only one rendering.** The description shown for human review at S3 is byte-identical to the string placed in the model's context at S6 — no markdown rendering, no truncation, no collapsing. Unicode is normalised at submission; non-printing, bidi and homoglyph forms are rejected. | 5.3 | prevent |
| SR-B9-14 | **Descriptions and manifests are untrusted input to the model**: wrapped and marked as data at context assembly (shared with `SR-B6-2`), length-bounded, carrying no authority of their own. | 5.1 | constrain |
| SR-B9-15 | **Selection precedence is not overridable by description content.** A description cannot demote, exclude or outrank another skill, because precedence is a platform property and not a persuasion outcome. | 5.2 | prevent |

**Residual (2.4) — tenant-conditional triggers.** A trigger written to match only the target tenant's
vocabulary cannot be detected before install, because in every other tenant the skill is correct.
SR-B9-6 catches it only across the fleet and only after it has fired somewhere. Accepted: this
boundary cannot close it, and the compensating position is that SR-B9-3 limits what firing is worth.

**Residual (5.1) — the description channel is irreducible.** Selection at S7 requires the description
to be in context, so being installed is sufficient for delivery and no prevention exists. Compensating
position: SR-B9-3 (loading confers no authority), SR-B9-14 (wrapped as data, bounded), SR-B9-6 (loads
logged, outliers surfaced). Accepted.

**Two derivation notes worth keeping.**

1. *Branch 2 has no static test.* A trigger is natural language and maliciousness is not a property of
   the string — "use when the user asks to run a script" is the correct trigger for a legitimate
   Python-helper skill. Any row claiming to detect a malicious trigger by inspection would be a lie in
   this table. The same argument rules out content-based classification at branch 3, which is why
   SR-B9-7 is a provenance rule: **when verification is impossible, look for a classification that
   makes verification unnecessary.**
2. *Branch 4 is not an RBAC problem.* Role is exactly what the session inherits under A8.2, so RBAC
   returns the same answer for the agent as for the user. The distinction is the class of action, not
   the identity of the actor: **authority is delegable; the authority to change the delegation is
   not.** SR-B9-10 is that line applied to the skill index, and it is the same line as SR-B8-2.

---

### B4 — Agent ↔ untrusted content

**Assumption under test:** A8.6, *"Content the agent reads — documents, fetched pages, tool output —
is data."*

**Data to whom?** A8.6 is false as written, and the derivation should say so before the tree starts.
The model has no type system. "This is data" is a *convention the model may honour*, not a boundary
it cannot cross — there is no mechanism by which marking a span changes what the next token can be.
The assumption is salvageable only in a narrower form:

> Content the agent reads is data **to the platform**: it carries no authority, and no privileged
> action is taken because the content asked for it.

That restatement moves the enforcement out of the model's compliance and into the surrounding
machinery, and it is what every requirement below is written against. (Raised as a spec defect in §5.)

**Why this is not a prompt-injection taxonomy.** "Ignore previous instructions", unicode smuggling,
base64 and the rest are payload *encodings*. They are one leaf — whichever leaf describes the channel
they arrive through — and they belong in a PoC, not in a tree. The branches below are **entry points,
the assembly step, class loss over time, effects that need no tool call, and shaping of permitted
actions.**

**G-B4 — Content that entered the system as data is acted on as instruction.**

```
1. Entry points — every channel by which untrusted bytes reach the context
   1.1 A document body in the org's own corpus, returned by read_document. The corpus is
       not trusted content: any member can write to it, and M1's seeded documents arrive
       from outside
   1.2 An HTTP response body returned by http_fetch
   1.3 Tool output from an installed MCP server — publisher-controlled. B6 owns the
       artifact; B4 owns its ingestion
   1.4 Metadata rather than bodies: HTTP headers, redirect targets, content-type,
       document titles, filenames. The "it's only a short string" exemption
   1.5 A tool that quotes its own arguments back — user-supplied text re-entering the
       context wearing the tool's authority
   1.6 The external reference fetched by a skill body                  ← handed from B9 3.x

2. The assembly step has no type system
   2.1 Untrusted content is concatenated into the same string as system instructions with
       no separation at all
   2.2 A delimiter or wrapper exists but is forgeable — the content contains the closing
       sentinel and resumes in the privileged register
   2.3 The wrapper is advisory: the model is *asked* to treat the span as data, and the
       security property depends on it complying
   2.4 A structured channel collapses to text — a JSON tool result stringified into the
       prompt loses whatever typing it had

3. Trust laundering — class is lost as content moves through the agent
   3.1 The agent summarises a poisoned document in turn 3. In turn 7 that summary is
       model output, not retrieved content, and nothing marks it as derived
   3.2 Content is persisted — written as a new document, a note, a memory — and read back
       later with its provenance stripped
   3.3 Content crosses a tool boundary and returns: what was fetched from the web is
       written to the corpus, and is thereafter an org document
   3.4 Conversation compaction or summarisation rewrites marked spans into unmarked
       narrative

4. Effects that need no tool call at all — reachable before B5 exists
   4.1 Alter the answer returned to the user: fabricate, misstate, assert false authority
   4.2 Suppress: instruct the agent to omit a fact, or not to mention the document
   4.3 Influence selection — which skill loads, which tool is chosen       → shares B9 5.2
   4.4 Plant a durable instruction that fires on a later condition, in this session or a
       future one

5. Shaping a permitted action rather than requesting a forbidden one
   5.1 Tenant data placed inside a URL that targets an allowlisted host — the host
       decision is satisfied, the payload is the exfiltration          → B7 3.1
   5.2 Data encoded into an argument of a tool the session legitimately holds: a search
       query, a filename, a commit message
   5.3 The answer contains a model-composed link or image reference, and the *user's
       client* fetches it. Exfiltration with no tool call by the agent whatsoever
```

**Security requirements**

| ID | Requirement | Kills | Kind |
|---|---|---|---|
| SR-B4-1 | **Provenance is a property of the bytes, tracked structurally.** Every span in the context carries an origin label assigned at ingestion. The label lives outside the span's own content and can never be set, altered or terminated by that content. | 1.1–1.6, 2.2 | prevent |
| SR-B4-2 | **Untrusted content is delivered in a channel the model cannot confuse with instruction** — a separate message or structured field, never string-concatenated with system text. Where text framing is unavoidable the sentinel is a per-request nonce. | 2.1, 2.2, 2.4 | prevent |
| SR-B4-3 | **No security property may depend on the model honouring the marking.** The label determines what the *platform* permits downstream — capability, egress, disclosure — not what the model believes. If the model ignores the wrapper entirely, every control below still holds. | 2.3 | prevent |
| SR-B4-4 | **Classification is monotonic and sticky.** Derived content inherits the lowest trust of its inputs; model output produced from untrusted input is itself untrusted. No operation upgrades class — not summarisation, not persistence, not re-reading. | 3.1 | prevent |
| SR-B4-5 | **Persistence preserves provenance.** A document written during a session records the class of what it was derived from, and reading it back does not launder it. | 3.2, 3.3 | prevent |
| SR-B4-6 | **Compaction preserves labels.** A summarised region carries the union of the labels of its sources; a compaction step that cannot preserve a label must drop the content rather than relabel it. | 3.4 | prevent |
| SR-B4-7 | **Tool output is untrusted by default**, including output from installed MCP servers and from first-party tools. A result is never instruction. | 1.3 | prevent |
| SR-B4-8 | **Metadata is ingested through the same labelled path as bodies.** Headers, titles, filenames, redirect targets and error text have no short-string exemption. | 1.4, 1.5 | prevent |
| SR-B4-9 | **Answers disclose their sources and their classes.** The agent may not conceal that it consulted a source, and an answer derived from untrusted content is marked as such to the user. | 4.1, 4.2 | observe |
| SR-B4-10 | **Untrusted content cannot influence selection.** Which skill loads and which tool is chosen is not a function of untrusted text — the precedence rule of SR-B9-4 and SR-B9-15 governs, and untrusted spans are excluded from the selection input. | 4.3 | prevent |
| SR-B4-11 | **Untrusted content cannot create a durable instruction.** Nothing read during a session persists into a later session as instruction; any carried state is data-class on re-entry. | 4.4 | prevent |
| SR-B4-12 | **Allowlisting is a host decision, never a payload decision.** An outbound request carrying tenant-derived content is denied even when the destination is allowlisted (shares `SR-B7-2`). | 5.1, 5.2 | constrain |
| SR-B4-13 | **Model-composed URLs are not auto-fetched by the client.** Links and image references in rendered output are neutralised so that no client-initiated request results from text the model wrote. | 5.3 | prevent |
| SR-B4-14 | **Every ingestion is logged with origin and class**, and any attempt to write a label from within content is a high-signal event. | — | observe |

**Residual (4.1) — influence on the answer.** If untrusted content is in the context at all, it can
shape what the agent says. That is not preventable without removing the product's function: the whole
point is that the agent reads the org's documents. The position taken here is that influence over
*words* is tolerated while influence over *authority* is not — SR-B4-3 ensures no privileged action
follows from content, and SR-B4-9 makes the derivation visible to the reader. Accepted.

**Residual (3.x) — label fidelity through the model.** SR-B4-4 and SR-B4-6 are enforced at the
platform's assembly and persistence steps, where spans are machine-tracked. They cannot cover a
transformation that happens *inside* a single model response — if the model restates poisoned content
mid-answer, the restatement is inside an already-labelled span and inherits its label, which is
correct; but the platform cannot distinguish its parts. Mitigated by SR-B4-4's lowest-trust rule
making the coarse answer the safe one. Accepted.

**Handoffs.**

- 5.1 and 5.2 are enforced at B7 (`SR-B7-1`, `SR-B7-2`). B4 states that the *payload*, not just the
  destination, determines the decision.
- 1.3's artifact is B6's; 1.6's artifact is B9's. B4 owns only what happens at ingestion.
- Anything the content persuades the agent to *do* becomes a tool call and is mediated at B5.
- 4.3 shares enforcement with B9's selection-precedence rows.

**Note on the pairing with B9.** `SR-B9-7` declared the classification rule — provenance, never
content inspection. `SR-B4-1` through `SR-B4-6` are where that rule is actually implemented and kept
true over time. The two boundaries were drafted together because B9 can state the obligation and only
B4 can discharge it.

---

### B3 — User → Agent

**Assumptions under test:** A8.1, *"A user's membership role reflects what they are allowed to do in
that org"*; A8.2, *"An agent session acts within the authority of the user it was created for."*

**Framing.** A8.2 is the assumption that makes the whole product safe to offer, and it is stated as a
fact rather than as a mechanism. B3 asks what has to be true for it to hold. The failure mode here is
not that the agent is tricked — that is B4 — but that the agent *legitimately* holds more authority
than the person asking, and the gap is exploitable without any deception at all.

**G-B3 — A principal obtains, through the agent, authority it does not hold directly.**

```
1. The agent carries more authority than its requester
   1.1 The agent runs with a service identity or a fixed elevated role rather than with
       the requesting user's authority — ambient authority by construction
   1.2 A viewer asks the agent to delete a document and it succeeds, because the delete
       path checks the agent's right to act and not the requester's — confused deputy
   1.3 Role is resolved once at session creation. The user is demoted and the session
       keeps the authority it was minted with
   1.4 The session outlives the membership entirely — the user is removed from the org
       and the session continues to act in it

2. The session's scope is wider than the request that created it
   2.1 Sessions are created with every installed grant in scope, rather than with the
       grants the task needs
   2.2 A session created in one org acts on another org's resources      → owned by B2 (3.1)
   2.3 No time bound: an abandoned or stolen session is durable authority

3. Authority is asserted rather than derived
   3.1 Role and grants are read from the session record as supplied, not from a
       server-side membership lookup                                  → shares SR-B2-2
   3.2 The agent asserts "the user authorised this" with no artifact that proves it

4. Escalation through the asking rather than through the acting
   4.1 The user asks for an admin action and the agent performs it, because the check
       applied is "may the agent do this" rather than "may this user have this done"
   4.2 The user instructs the agent to change a grant, a session scope or the skill index
       — a control-plane action reached through delegation      → shares SR-B8-2, SR-B9-10
   4.3 Self-escalation: the session requests additional grants and the same session's
       authority is what approves them

5. Attribution loss
   5.1 Actions are logged as the user, so an action the agent took while the user was
       absent is indistinguishable from one the user performed
   5.2 No record of which authority was relied on — user permission, org grant, or a
       skill's declared capability — so a later review cannot reconstruct the decision
```

**Security requirements**

| ID | Requirement | Kills | Kind |
|---|---|---|---|
| SR-B3-1 | **The session is its own principal.** It has its own identity and never acts *as* the user. Spec §3.3 already states this; B3 requires it be enforced rather than described. | 1.1, 5.1 | prevent |
| SR-B3-2 | **A session's capability set is an intersection, evaluated per action**: user permissions ∩ org grants ∩ session scope ∩ time bound ∩ declared capabilities of loaded skills. Never a union, never a flag. | 1.1, 2.1 | prevent |
| SR-B3-3 | **Authority is re-derived at action time** from server-side records, never cached at session creation. Demotion or removal of membership takes effect on the next action. | 1.3, 1.4, 3.1 | prevent |
| SR-B3-4 | **Sessions are time-bound** and expiry is enforced server-side, independent of the client. | 2.3 | constrain |
| SR-B3-5 | **Sessions are created least-privilege.** No installation is in scope unless explicitly requested and authorised for that session. | 2.1 | prevent |
| SR-B3-6 | **A session may not widen its own scope.** Any scope change requires a fresh user action taken outside the conversation. | 4.3 | prevent |
| SR-B3-7 | **Control-plane actions are not delegable to a session**, regardless of the requesting user's role. Same rule as `SR-B8-2` and `SR-B9-10`. | 4.2 | prevent |
| SR-B3-8 | **The agent is a ceiling, never a source.** An action requested through the agent is permitted only if the requesting user could perform it directly. The agent can only ever narrow authority, never add to it. | 1.2, 4.1 | prevent |
| SR-B3-9 | **Every action records actor (session), acting-for (user), and which authority was relied on.** An agent-initiated action is distinguishable from a human one in the audit record. | 3.2, 5.1, 5.2 | observe |

**SR-B3-8 is the keystone.** Every confused-deputy failure in a delegated system is a case of the
deputy being treated as a *source* of authority rather than as a *conduit* for someone else's. Written
as a ceiling, the question "may the agent do this?" becomes unaskable — the only question is whether
the requester may, and the agent's own rights never enter the computation.

**Exploits (M3):** `attacks/05-confused-deputy` → leaf 1.2 · `attacks/06-policy-plane` → leaf 4.2
(owned by B8).

---

## 4. Boundaries not yet drafted

Owned, scoped, and deliberately left empty rather than filled with placeholder prose.

| Boundary | Assumption | Owner | Note |
|---|---|---|---|
| B5 — Agent → Tools | A8.2, A8.4 | joint | The capability boundary; absorbs leaves handed off from B2 (3.1), B6 (4.1), B7 (1.1) |


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
3. **A8.6 is false as stated, not merely optimistic.** Found at B4. "Content the agent reads is
   data" describes a property the system cannot have: the model has no type system, and marking a
   span as data is a convention it may honour rather than a boundary it cannot cross. The defensible
   form is *"content the agent reads is data **to the platform** — it carries no authority, and no
   privileged action is taken because the content asked for it,"* which relocates enforcement from
   the model's compliance to the surrounding machinery. Narrow it in the spec.
4. **A8.5 is unenforceable as stated.** "Behaves the same after installation as at review time" cannot
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
| B9 | ✅ 2.2, 5.3 | ✅ 1.x, 3.x | ✅ 2.2, 5.1 | ⬜ | ⚠️ 2.3 | ✅ 4.1 |
| B4 | ✅ 2.2, 1.5 | ✅ 2.x, 3.x | ✅ 4.2, 3.4 | ✅ 5.x | ⬜ | ✅ 4.x |
| B3 | ✅ 3.2 | ✅ 3.1 | ✅ 5.x | ⬜ | ⚠️ 2.3 | ✅ 1.x, 4.x |

⬜ = not yet checked, not "no threats exist." ⚠️ = checked, thin by design.
Denial of service is consistently thin across this model: availability is out of scope by declaration
(spec §9, "the lab is about correctness of authority, not availability"), *except* where unavailability
changes an authorisation outcome — which is exactly SR-B8-4, fail-closed.

---

## 7. Open

- [ ] B5 tree and requirements (§4)
- [ ] Spec PR: add A8.10, narrow A8.5 (§5.1, §5.3)
- [ ] Complete the STRIDE pass for the drafted boundaries (§6)
- [ ] `coverage/` entry for B1's declared non-coverage (SR-B1-7)
