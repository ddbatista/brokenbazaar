# M4b — Skills · threat-model diff

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

**Boundaries:** B9 (platform ↔ context supply chain), with B4's handoff on leaf 3.x (a fetched reference is *data* under A8.6), B5 reopened on the ceiling's payload leg (SR-B9-2 is enforced there), B3's handoff on leaf 4.1, and the description rule shared with B6 (SR-B9-14 ↔ SR-B6-2, M4a-shipped for manifests, extended here to skill descriptions)
**Baseline:** [`v0-baseline.md`](v0-baseline.md) · **Previous diff:** [`m4a-marketplace.md`](m4a-marketplace.md)
**Status:** landed before any M4b feature code, per AGENTS.md house rule 1.

M4a closed with the marketplace mediated: installs pin the fetched bytes, drift evaluates
before the grant leg, the consent channel answers tool poisoning, and both hardened zones
were applied by the maintainer's hand and closed with canonical-run evidence. M4b opens the
second artifact type the spec's marketplace carries: the **skill bundle** — bytes the agent
is *designed to obey*. It records the same four things every diff records: the reachable
leaves with addresses, the disposition of every requirement sent here or shared, the leaves
the implementation invents, and a verdict on the assumptions now meeting code.

**Three derivations changed the module's shape before any code existed, and all three are
the transferable part.**

**First: the plan's capability-token line was stale on arrival, and the survey caught it
before the diff.** The scope block said capabilities are *"intersected into the M3
per-session capability token"* — a token M3's own D3 deleted, because a token caches
authority and finding 05's demotion walks through the cache ([corrections
log](../coverage/README.md), the M3-D3 entry). SR-B9-2's own wording was right all along:
*at tool-call time the session intersects*. So the ceiling is built at the gate — leg 4's
second channel, the loaded skills' declared caps answered by the authority route exactly
as M4a answered installs — and nothing is computed at session creation. The same instrument
as M3-D3, pointing the other way: the survey corrected the plan, the requirement stood.

**Second: the defense is where bytes enter and what verifies them, never what they say.**
The survey's sharpest finding is a pair of addresses: the trust classes
(`app/agent/span.go:31-43`) and the deliberate origin-blindness of the grammar
(`app/agent/model.go:149-154`, *"that single omitted check IS SR-B4-3 in code"*). A fifth
trust class for skill bodies would be a label no code consults — decoration. The body is
**instruction by provenance**: A8.7 is the product's honest design, kept; what failed was
never the assumption but unverified bytes wearing it. The three structural controls, none
of which reads intent: the **digest** (what executes is what was reviewed — SR-B9-1, the
M4a pin reused on SKILL.md bytes: one control, two findings, the evidence the control is at
the right altitude), the **ceiling** (obeying buys strictly less than the org gave —
SR-B9-2), and the **reference bind** (a pointer cannot outlive verification — SR-B9-9). A
control that reads intent would be the thing this module exists to demonstrate cannot work.

**Third: 09's naive bug is the spec's own review surface, not a missing check.** The
baseline's spine says the human at S3 reviews *a name and a description* — the asymmetry
the whole boundary rests on is in the spec. The naive build is spec-faithful: install
renders the description, the body executes at S8, and the description-only variant rides
S6's per-turn residency to fire without a single load. The hardened build is SR-B9-1's
redefinition of the review surface: S3 renders the full body, the approval binds those
exact bytes. A real developer writes the naive version because the catalog shows the
description and the body is an implementation detail — the same mental-model error as
M4a's advisory pin (the server is the source of truth about the tool; the description is
the source of truth about the skill).

---

## §1 — Decisions under test

Ruled **all as recommended, 2026-11-22** (plan ledger, the opening entry). Each decision
with the rejection that shaped it:

- **D0 — the body is instruction, the description is data.** The body enters the
  system-class instruction position after its digest verifies (SR-B9-1); the index and
  description enter wrapped `OriginPublisher` (SR-B9-14 reusing the M4a class — no fifth
  class). *Rejected:* an `OriginSkill` label the origin-blind grammar would ignore —
  decoration; body sanitisation at load — no control reads intent, and sanitising the
  reviewed bytes pretends the review never happened; refusing bodies — a platform that
  cannot load instructions cannot load its own documentation.
- **D1 — the ceiling rides leg 4 as a second channel, intersected at the gate, with its
  own reason `skill_cap_not_declared`.** *Rejected:* union — the scope block's own words;
  a per-skill capability token — M3-D3's deleted shape, cached authority the demotion
  walks through; reason reuse (`not_in_session_scope`) — a leg that hides which decision
  narrowed repeats the M4a leg-order lesson: a reason that buries the thesis is wrong
  even when its answer is right.
- **D2 — SR-B9-1 reuses the drift mechanism wholesale.** Same columns, same re-hash
  before load, same freeze (`schema_drift_reapproval_required`), same accepted
  re-approval. *Rejected:* load-time content scanning — verification is impossible (the
  baseline's own branch-2 note) and provenance makes it unnecessary; trust-the-catalog —
  08's advisory pin, relitigated.
- **D3 — external references: inline at publish, or allowlisted fetch bound to the
  approved digest, enforced on the FETCH channel (`skill_reference_drift`).** *Rejected:*
  banning S9 — kills the feature the finding is about; re-marking fetched content — it
  already *is* B4 data, and the label is not the problem (the platform promising bytes it
  never verified is); publish-time inline only — the mutable-reference feature is the
  finding's premise, and the honest fix is the bind, not the removal.
- **D4 — selection is deterministic, disclosed, and attributed.** The index renders from
  pins (SR-B9-13's single rendering), precedence `platform > reviewed > third-party` is
  the platform's (SR-B9-4), every load is disclosed (SR-B9-5) and logged with
  session/org/tenant/trigger (SR-B9-6). *Rejected:* LLM-judged relevance — SR-B5-1's
  testimony rule, M4a-D9's citation now load-bearing twice.
- **D5 — the fixture family.** `fixtures/evil_skill.py` (poisoned body, description-only
  variant, clean control, reference skill) and `evil-publisher` hosting the **mutable**
  reference document (flip/reset, loopback-only evidence). The compose amendment is a
  hardened zone via issue; the fixture file is open zone, `evil_mcp`'s precedent.
- **D6 — SR-B9-12's dogfood gate is a zone amendment.** `AGENTS.md` names `.claude/skills/`
  and every `SKILL.md` a hardened zone; `ci.yml` fails on an unreviewed skill-file diff —
  issue-filed, human-applied, batched with compose.
- **D7 — the scanner-bypass number (AST08).** `experiments/skill-scanner/` via the
  existing `cmd/measure`: a pattern scanner over the fixture family, n≥20, bootstrap CIs;
  the harness's judge catches what the scanner passes; `10-skill-ref-drift` then defeats
  both, because the payload did not exist at scan time. The claim ships as a number.

## §2 — The B9 leaves this module makes reachable, with addresses

Branch by branch; each leaf names where the module reaches it in code. `model.go` line
numbers are the pre-M4b tree (branch `m4b` parent `fdc5e01`).

**1. The reviewed artifact is not the executed artifact**
- **1.1 benign description, hostile body** — the naive install route renders the
  description (the spec's S3) and never the body; the loader (`app/agent/skills/`, new in
  T4) inserts the body's bytes into context at S8. Finding **09**, primary beat.
- **1.2 frontmatter parsed at S4 disagrees with the body loaded at S8** — the index is
  built from the frontmatter at install; the body is loaded from the install row at
  trigger. The naive build never re-checks one against the other. Finding **09**, the
  frontmatter-variant beat: the description is what S4 indexed and what fires.
- **1.3 declarations understate the body** — the naive build treats `capabilities:` in
  frontmatter as documentation; the body instructs `http_fetch` the declaration omits.
  The hardened ceiling (`skill_cap_not_declared`, leg 4) is the control this leaf exists
  to demand. Finding **09**, the hardened assert.

**2. The trigger is attacker-controlled and never reviewed**
- **2.1 capability-moment targeting** — the fixture's trigger (*"use when the user asks to
  read a document"*) loads the body exactly when a document is in context. Finding **09**.
- **2.2 shadowing** — the fixture ships a second, clean skill claiming the same situation;
  the naive build resolves the collision by description persuasiveness (model discretion),
  the hardened by precedence. Finding **09**, the control beat.
- **2.3 always-on** — rejected for the fixture by design: an always-resident body and the
  description variant are the same channel, and the variant isolates it better.
  Reachable in principle; not driven.
- **2.4 tenant-conditional** — the baseline's accepted residual, restated at §6.

**3. The bundle is pinnable; what it points at is not**
- **3.1 the referent changes after install** — `evil-publisher` flips the hosted reference
  post-install; the install digest remains valid. Finding **10**, primary beat.
- **3.2 the host is not the publisher's** — the reference points at `evil-publisher`
  directly (a third-party host by design — controlling it requires no publisher
  compromise); the fixture makes the baseline's point structurally.
- **3.3 conditional serving** — `evil-publisher` can serve benign bytes to the review
  fetch and hostile bytes to the agent's fetch (User-Agent or path discrimination); shipped
  in the fixture, noted in 10's README as a served-conditional variant, not a separate
  expected.json beat.
- **3.4 chained references** — the flipped reference itself references a further document.
  Declared out of the exploit's scope: the chain's first hop already demonstrates the
  leaf, and every hop is B4 data; recorded at §6 as bounded by the same legs.

**4. The skill index is reachable by paths that are not "publisher → admin → member"**
- **4.1 the session authorises an installation itself** — prevented by construction: M4a
  D8's control-plane exclusion extends verbatim (SR-B9-10); no agent tool, no grammar
  rule, no `data.tools` entry reaches the install or authorise routes. The naive build is
  equally closed here — this leaf's control shipped in M4a and is *asserted*, not driven.
- **4.2 platform-shipped or seeded skills** — the seed ships one (T2); it enters the same
  index, digest-bound (SR-B9-11). *"First-party is a precedence value, never an
  exemption."*
- **4.3 this repository's own pipeline** — the dogfood zone (D6): `AGENTS.md` + `ci.yml`
  via issue. The baseline cites `CLAUDE.md`; this repo's zone file is `AGENTS.md` — a
  citation, not a correction.

**5. The description is an instruction channel, not a label**
- **5.1 delivery by residency** — the naive index concatenates descriptions into context
  every turn (`app/agent/loop.go:157-208`, the M4a catalog channel reused); the
  description-only variant fires with no load. Finding **09**, the required variant.
- **5.2 attacking the index rather than the agent** — prevented by construction
  (SR-B9-15): precedence is a platform property; descriptions cannot demote each other.
  Asserted in the hardened index test, not driven as a separate beat.
- **5.3 one string, two readers** — SR-B9-13's single rendering closes it: the string at
  S3 and at S6 is the same bytes, unicode-normalised at publish, bidi and homoglyph forms
  rejected at publish validation. Asserted in T3's route tests.

**Handoffs, honoured.** Leaf 3.x's fetched reference is B4 data — verified in code: the
reference fetch is a tool result span, `OriginUntrusted`, exactly as `http_fetch` has
always answered. Leaf 5.x shares B6-1.2's mechanism — the M4a `OriginPublisher` wrap,
extended to skill descriptions. Anything the body persuades the agent to *do* crosses B5 —
and the two legs it dies at are the module's thesis asserts (§7). Leaf 4.1 rides B3:
the session's authority is role-inherited under A8.2, which is precisely why the
authorising routes are control-plane (SR-B9-10 extends SR-B8-2).

## §3 — Disposition of every requirement sent here, shared, or reopened

| ID | Requirement, one clause | Disposition | Where |
|---|---|---|---|
| SR-B9-1 | the artifact approved is the artifact that executes | **shipped**: install renders the full body, approval binds `pinned_digest`; hardened load re-hashes, mismatch freezes as `schema_drift_reapproval_required` (D2). Naive: the spec's S3 — the reviewed artifact is the description. | T2/T3 + T5 |
| SR-B9-2 | declared capabilities are an enforced ceiling | **shipped**: leg 4's second channel, `session scope ∩ declared caps`, reason `skill_cap_not_declared` (D1). Naive: declarations are documentation. | T5 |
| SR-B9-3 | a trigger decides what is loaded, never what is permitted | **shipped**: loading changes context presence only; asserted by 09's hardened contract — the *loaded* body's induced call dies at the ceiling, the *never-loaded* description's call dies at the resident legs. | T5, §7 |
| SR-B9-4 | skill selection is deterministic and attributable | **shipped**: platform precedence, tie-broken by install order then name; never the model's. Naive: model discretion (2.2's persuasion contest). | T5 |
| SR-B9-5 | every skill load is disclosed | **shipped**: the response names skill, publisher, version. | T5 |
| SR-B9-6 | every load is logged; fleet outliers surfaced | **shipped**: load events (session, org, tenant, trigger, digest) in the audit log; the cross-tenant/always-on outlier rules are T8's detections. | T5 + T8 |
| SR-B9-7 | classification is by provenance, never content | **shipped**: D0 *is* this requirement — the body's instruction status is provenance-computed (approved + digest-verified), the description's data status is entry-computed (publisher origin); no code path inspects what either says. | T4/T5 |
| SR-B9-8 | a skill body cannot promote a reference to instruction | **shipped**: no mechanism changes a span's class post-entry; the fetch is B4 data forever. Stated honestly: the lab's origin-blind grammar can still be *steered* by data — what is prevented is the class change, and the persuaded action crosses B5's legs like every other action. | T4, §7 |
| SR-B9-9 | references declared, allowlisted, digest-logged; undeclared denied | **shipped**: frontmatter `references:` resolved against the egress allowlist; the fetch must match the approved digest or deny `skill_reference_drift` (D3). | T5 |
| SR-B9-10 | install/authorise is control-plane, excluded from session authority | **shipped**: M4a D8 extended verbatim — admin install, per-member authorise (S5), no agent tool either mode. | T3 |
| SR-B9-11 | platform and seeded skills held to the same digest-bound approval | **shipped**: the seed's skill installs like any other (T2); precedence, not exemption. | T2 |
| SR-B9-12 | this repository's own pipeline is in scope | **shipped as a zone**: `AGENTS.md` + `ci.yml` via issue (D6), human-applied. | T9 batch |
| SR-B9-13 | one rendering; normalised; bidi/homoglyph rejected | **shipped**: publish validation normalises NFC and rejects non-printing/bidi/homoglyph forms; the S3 and S6 strings are the same bytes. | T3 |
| SR-B9-14 | descriptions are untrusted input to the model: wrapped, bounded, no authority | **shipped**: the M4a `OriginPublisher` wrap extended to skill descriptions, length-bounded. Shared with SR-B6-2 — the manifest half shipped in M4a; the skill half is this row. | T5 |
| SR-B9-15 | precedence is not overridable by description content | **shipped**: precedence is platform property (with SR-B9-4); descriptions demote nothing. | T5 |

**Carried items, dispositioned:**
- **Argument-level provenance** (M3-N4 → M4a-N4 → **still carried**): the per-argument
  taint track. M4b does not need it — the ceiling answers the skill channel at the
  capability grain, and the description variant dies at the resident consent leg. The
  over-deny it would remove (a `user_text` tool called with typed text in a
  document-read session) persists; carried to v1.
- **Consent-vocabulary reuse**: the skill caps vocabulary mirrors the manifest `receives`
  design — declared at publish, enforced at one leg, understatement buys less (SR-B9-2's
  own words). The two vocabularies stay distinct columns; one design, two channels.
- **DB-role split** (M3 carry): unchanged, still open, §8.
- **Rate/volume limits** (M4a's declared-not-deferred, SR-B5-7/D10): unchanged — M4b adds
  no rate surface worth a row and does not reopen it.

## §4 — Leaves the implementation invents

- **M4b-N1 — the disclosure is a rendering of untrusted text.** SR-B9-5's disclosure
  renders the skill's *name* into user-visible output; the name is publisher bytes. The
  naive-disclosure bug would be concatenation; the shipped form quotes it in a
  platform-rendered sentence (`skill "NAME" (publisher P, version V) loaded`), so the
  name can never read as platform speech. Bounded, not prevented: a name can still be
  *chosen* to mislead a human who reads the disclosure — the wrap bounds syntax, not
  semantics, the same limit every marking in this repo has.
- **M4b-N2 — index ordering is context-shaping.** Deterministic precedence produces a
  deterministic index order, but *what is resident* is context the model consumes. A
  skill hoarding early positions by install order is a real effect the module does not
  measure. Declared, not solved: precedence is the control, ordering effects are the
  model's to absorb, and no leg reads context position.
- **M4b-N3 — the frozen window is availability, not authority.** Between a drift deny and
  the org's re-approval the skill is unavailable — a publisher can weaponise this (flip
  back and forth, deny the org its own tooling). The window is inherent to re-approval
  being a human decision; recorded so the writeup can name the cost honestly.
- **M4b-N4 — the S5 authorisation surface is member-reachable by design.** A member
  authorises an *installed* skill for their own sessions; the admin's install review
  remains the only entry to the index. The leaf is the *member's* trust decision being
  attackable (a description that reads benign to a member), bounded by the same legs as
  every load. Recorded as the honest edge of SR-B9-10: control-plane excludes the
  *session*, not the human.

## §5 — Verdicts on the baseline's assumptions

- **A8.7 — "content the agent loads as a skill is instructions, and following it is
  correct behaviour."** **Survives as product design, with the trust question relocated.**
  The assumption was never wrong about *what* a skill is; it was wrong about *whose bytes
  get to claim the class*. Following verified, approved, digest-bound instructions IS
  correct behaviour — the product does it in the hardened build on purpose. The naive
  build's failure is that the class is claimed by *entry path* alone (it arrived from the
  catalog) with no verification, and the description wears a class it never had. The
  verdict the module demonstrates: provenance is computable, intent is not, and every
  control that matters is a function of the first.
- **A8.2 (via leaf 4.1)** — role inheritance is exactly why the authorising routes are
  control-plane; the session cannot add to its own instruction set, and neither can the
  member's *session*, though the member themselves can (M4b-N4).
- **A8.6 (via leaf 3.x)** — verified in code: the fetched reference answers as an
  `OriginUntrusted` tool result, the same class `http_fetch` has always produced. The
  handoff is real; no new span class was needed to honour it.
- **Leaf 4.3's `CLAUDE.md` citation** — this repo's zone file is `AGENTS.md`; the
  baseline names the file its authors had. Citation noted, no correction required.

## §6 — Residuals, accepted and compensated

- **(2.4) tenant-conditional triggers** — accepted verbatim from the baseline: a trigger
  matching only the target tenant's vocabulary is undetectable before install. SR-B9-6's
  fleet view is the compensating position, and T8 ships the outlier rules it implies.
- **(5.1) the description channel is irreducible** — accepted verbatim: selection at S7
  requires the description in context, so being installed is sufficient for delivery and
  no prevention exists. Compensating positions shipped: SR-B9-3 (loading confers no
  authority — the *hardened* description variant dies at the resident B5 legs, not at any
  B9 control), SR-B9-14 (wrapped, bounded), SR-B9-6 (logged, outliers surfaced). This is
  why 09's hardened contract asserts two *different* legs for its two variants, and why
  the writeup's claim is scoped: the channel is delivered, not obeyed.
- **(M4b) installed-is-delivered** — the 5.1 residual restated as the module's own
  boundary: the index's presence is the attack's only requirement, and the ceiling is
  the difference between owning context and owning the agent.
- **(3.4) chained references** — bounded, not solved: every hop is B4 data and every
  induced action crosses the same legs; the chain lengthens the context, not the
  authority. Declared rather than measured.
- **(M4b-N3) the frozen window** — accepted above.

## §7 — Exploit assignment (the PoC contract that governs T6)

**`09-skill-injection`** — the description says *helpful notes skill*; the body, loaded at
trigger, instructs the agent to fetch an attacker URL with the document's contents; the
description-only variant carries the same imperative with no body at all. Beats:
(i) naive, body variant: the member asks a benign question about a document, the trigger
loads, the body's imperative fires rule 1, `http_fetch` exfiltrates — **exit 0**;
(ii) naive, description variant: the skill is installed but never invoked; the resident
description's imperative fires on an unrelated turn — **exit 0**, with the beat asserting
the load log is EMPTY (delivery without loading — the S6-residency thesis);
(iii) hardened, body variant: the load happens (disclosed, logged), the body's imperative
fires — and the call dies at **leg 4, `skill_cap_not_declared`** (the ceiling — the
module's own leg, not a reused reason);
(iv) hardened, description variant: no load (the index is wrapped, and the ceiling is not
in effect because nothing was loaded) — the resident imperative fires and dies at **leg 9,
`tenant_data_egress`**, the consent channel 07 asserted;
(v) the control: a member TYPING the same request in a session whose loaded skill
*declares* the fetch-capable tool proceeds or is denied by the ordinary legs — proving the
ceiling forbids the undeclared, never the channel. Evidence port: `evil-publisher`'s
`/calls`, the M4a evidence pattern. **Attribution:** the planted bug is the spec-faithful
naive review surface (§ Third above); the honest halves are the digest (T2/T3), the
ceiling, the disclosure, and the precedence machinery (T5).

**`10-skill-ref-drift`** — the skill's body says *see `evil-publisher`'s reference for
formatting details*; the reference is clean at install, at review, at authorisation.
Beats: (i) naive: the agent fetches the reference at S9, the content is data, the grammar
fires its imperative, the exfil crosses no digest check because none exists — **exit 0**;
(ii) hardened, pre-flip: the reference fetch is allowlisted, digest-matches the approval,
the content enters as data, the session works — **allowed, on purpose** (the control beat:
the feature is real, the bind is invisible to honest use);
(iii) hardened, post-flip: `evil-publisher` flips the referent; the fetch dies — **leg
`skill_reference_drift`**, exit 1, and the payload never enters context;
(iv) hardened, post-re-approval: the org re-approves the new reference bytes (the M4a
re-approval flow reused), the fetch proceeds — and the re-approved poison's induced call
**still dies at the ceiling** (`skill_cap_not_declared`) or at the consent leg if no skill
caps apply: re-approval bought context presence, not authority, which is SR-B9-3's own
sentence demonstrated. The AST08 beat rides this exploit (D7): the scanner passed the
fixture at install; the judge caught what the scanner passed; the flip defeats both,
because the payload did not exist at scan time.

Both exploits obey the standing evidence contract: probes assert presence and
attribution with the recorded bytes; hardened denials assert their reason and the
positive control's ALLOW; no absence-only asserts; the fixture resets in `finally`.

## §8 — Open follow-ups

- The S5 authorisation route's member-facing review surface (M4b-N4) — the member sees
  the description only; a member-scope render of the body is a product decision queued
  for v1.
- The db-role split (M3 carry, unchanged).
- Argument-level provenance (carried; §3's disposition stands).
- The v1 spec queue: A8.2's scope note, A8.10's layer split, M2-N3's testimony line,
  M1-N2's seed wording — the corrections log is the index.
- The frozen window's availability cost (M4b-N3) — a writeup topic, not a control.
- Index ordering effects (M4b-N2) — declared; measurable only with a real model.

*§1–§8 are the committed record. A §9 will be appended at module close, per the
close-out pattern; these sections are never edited after the commit.*
