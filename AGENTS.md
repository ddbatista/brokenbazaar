# Rules for coding agents

This is the **single source of truth** for agent rules in this repository. `CLAUDE.md` points here
and holds no rules of its own, deliberately: two rule files that both define hardened zones will
drift, and the moment they drift an agent can read whichever is more permissive and be technically
compliant. One canonical file is the same argument this repo makes about `store.ForOrg(ctx)` — a rule
that can be satisfied from two places is a rule you cannot enforce.

This repo is a security lab. The product code is *deliberately* vulnerable; the scaffolding around it
is not. Those two categories have different rules.

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource
> for security practitioners.** Localhost only. Never point it at real credentials or data.

---

## Hardened zones — do not modify

You may read these. You may not write to them, and you may not propose changes to them as part of a
feature PR.

- `.github/` — CI workflows, the attack suite, branch protection
- `gateway/policy/` — Rego policy, policy data, policy tests
- `go.mod`, `go.sum`, and any dependency manifest
- `docker-compose.yml` — the stack definition, including the hostile fixtures
- `.claude/skills/` and **any `SKILL.md` anywhere in this repo**
- `SECURITY.md`, `LICENSE`
- Any `ANSWER-KEY.md`
- **`AGENTS.md` and `CLAUDE.md` — these rules themselves.** You may propose changes to your own
  rules in a PR description or an issue. You may not write them.

If a task appears to require a change in a hardened zone, **stop and say so**. Do not work around it,
do not stage an equivalent change elsewhere, and do not disable the check.

### The rules are in the list, and were not at first

This file originally listed seven zones and omitted itself. That omission permitted a fully
compliant sequence: edit `AGENTS.md` to remove `.github/` from the list, then edit the CI workflow,
then land a change that breaks a control into a green build. No rule is broken at any step, because
the rules were changed first and the rules allowed that.

The class matters more than the instance. Most access-control defects let a party do one forbidden
thing; this one lets a party **redefine what forbidden means**, after which every later action is
legitimate and the audit trail shows compliance. **The cheapest attack on a control is not bypassing
it, it is amending it.**

This repo's own threat model had already derived the rule three times from three unrelated
directions — `SR-B8-2`, `SR-B9-10`, `SR-B3-7` reduce to one line: *authority is delegable; the
authority to change the delegation is not.* B8 exists as a boundary for exactly this reason, and
finding 06 is a tenant admin weakening the gate by editing policy instead of attacking it. This was
the fourth rediscovery, and the first one found in the project's governance rather than in the
product it describes.

It was found because an agent attempted the edit and its own runtime — not this file — refused: that
runtime classifies agent-instruction files as protected and requires human approval. The write was
blocked by someone else's control while this policy stayed silent. A lab whose rules are load-bearing
on the strictness of whichever tool happens to be reading them does not have rules. Recorded here
rather than quietly corrected, per the last house rule.

### The test that defines the list

A zone is hardened when the answer to this question is yes:

> *If a change here were subverted, would it remove the ability to detect the subversion?*

CI measures whether controls hold. Policy decides what is allowed. The dependency manifest decides
what code is in the build at all. Answer keys are the record of what was planted. Each one, if
quietly edited, hides the edit. Everything else in the repo is reviewable after the fact, which is
why everything else is open to you.

This is the same thesis as B5, one level up: **a decision must derive only from state the reviewer
owns, never from state the reviewed party can influence.**

### Why the skills zone is listed twice over

M4b demonstrates attacks where a skill file places instructions in an agent's context. That attack
class is live in *this* build pipeline, not only in the product. Every attempt to write a skill file
is logged and becomes data for the M6 AI-assisted-development writeup. An attempt is not a failure —
silently routing around the rule is.

---

## Proposing a dependency

Dependencies are a trust decision, not a code change, and `go.mod` is hardened. The workflow:

1. Add an entry to `PROPOSED-DEPS.md` — what it is for, **what was considered instead**, the pinned
   version, and what it would cost to remove later.
2. Stop. A human applies it and commits the manifest in its **own commit**, separate from feature
   code, so the history shows the trust decision as its own reviewable event.
3. Delete the entry once applied.

**Pin the version explicitly.** `go get x@latest` records a concrete version either way — Go has no
version ranges — so the difference is not pinned-vs-floating, it is whether a human chose the version
or a timestamp did.

**Evaluate the build, not just the library.** A dependency proposal that only evaluates the
dependency is incomplete. pgx/v5 ratcheted this module's `go` directive from 1.22 to 1.25.0, which
moved the CI toolchain pin and the Dockerfile base image — three files, none of them the dependency.
Ask what a new dependency changes about: language floor, toolchain pins, base images, build context,
cache keys.

**Do not run `go mod tidy` to install.** Tidy reconciles requirements with *imports*; run before the
code that imports the dependency exists, it removes the dependency and empties `go.sum`.

---

## Every PR must state

1. **Which trust boundary it touches** (B1–B9, listed in `README.md`). "None" is a valid answer and
   must be explicit.
2. **Whether it plants an intentional vulnerability.** If yes, name the finding number and add the
   entry to that module's `ANSWER-KEY.md` in the same PR.
3. **Whether the change is behind `HARDENED`.** Controls go behind the flag so the vulnerable path
   stays runnable.

---

## House rules

- **Threat-model diff before feature code.** If `threat-models/` has no diff for this module, the
  feature is not ready to write. The diff is not a second threat model — it cites the baseline's
  leaves by number and records what the baseline could not know: which leaves this module makes
  reachable *with a route and a statement as the address*, the disposition of each requirement, the
  new leaves the implementation invents, and a verdict on the assumptions that have now met code.
- **Never retroactively edit a committed threat model.** `v0-baseline.md` is an artifact with a date
  on it. When a diff proves one of its requirements false — this has already happened once, see
  `M1-N2` — the correction lands in the *next version*, and the diff says what was wrong. A document
  that is silently corrected cannot be used as evidence of anything.
- **Write the correct implementation before the vulnerable one.** Where a module ships both (e.g.
  `OrgStore` and `NaiveStore`), build the control first. The vulnerable version is then a documented
  departure from a design that was reasoned out, not an accident later repaired — and the answer key
  can argue *why a real developer would have written it that way*, which is the thing that makes a
  planted bug worth studying.
- **Python is stdlib-only.** No pip installs in `attacks/`. Exploits must run from a clean clone with
  the system Python.
- **Hand-roll the mechanism when the mechanism is the lesson.** JWT verification is hand-rolled here
  on purpose: a library would make `alg:none` the library's bug and finding 02 would teach nothing.
  A Postgres driver is not hand-rolled, because the wire protocol is not the lesson. The line is *is
  this the thing being taught?*, not *can it be written without dependencies?*
- **Exploits follow the PoC contract** in `attacks/README.md`: takes `--base-url`, prints evidence,
  exits 0 on success and non-zero on failure, ships an `expected.json`.
- **Do not fix a planted vulnerability as a drive-by.** If you notice one, say so; do not silently
  repair it. The vulnerable state is the artifact.
- **Do not add dependencies.** Propose them; see above.
- **Do not weaken a test to make it pass.** Report the failure instead.
- **Record the cost you failed to predict.** When a proposal or a design note misses something that
  only showed up on contact, amend the document to say so rather than quietly fixing it. The repo's
  value is that its documents are honest about where they were wrong.

---

## Attribution

Each entry in an `ANSWER-KEY.md` records whether the code was written by an agent or by hand. Answer
honestly when asked to fill that field — the value of the M6 writeup depends entirely on that column
being accurate.
