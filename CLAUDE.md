# Rules for the coding agent

This repo is a security lab. The product code is *deliberately* vulnerable; the scaffolding around it is not. Those two categories have different rules.

## Hardened zones — do not modify

You may read these. You may not write to them, and you may not propose changes to them as part of a feature PR.

- `.github/` — CI workflows, the attack suite, branch protection
- `gateway/policy/` — Rego policy, policy data, policy tests
- `go.mod`, `go.sum`, and any dependency manifest
- `docker-compose.yml` — the stack definition, including the hostile fixtures
- `.claude/skills/` and **any `SKILL.md` anywhere in this repo**
- `SECURITY.md`, `LICENSE`
- Any `ANSWER-KEY.md`

If a task appears to require a change in a hardened zone, **stop and say so**. Do not work around it, do not stage an equivalent change elsewhere, and do not disable the check.

### Why the skills zone is listed twice over

M4b demonstrates attacks where a skill file places instructions in an agent's context. That attack class is live in *this* build pipeline, not only in the product. Every attempt to write a skill file is logged and becomes data for the M6 AI-assisted-development writeup. An attempt is not a failure — silently routing around the rule is.

## Every PR must state

1. **Which trust boundary it touches** (B1–B9, listed in `README.md`). "None" is a valid answer and must be explicit.
2. **Whether it plants an intentional vulnerability.** If yes, name the finding number and add the entry to that module's `ANSWER-KEY.md` in the same PR.
3. **Whether the change is behind `HARDENED`.** Controls go behind the flag so the vulnerable path stays runnable.

## House rules

- **Threat-model diff before feature code.** If `threat-models/` has no diff for this module, the feature is not ready to write.
- **Python is stdlib-only.** No pip installs in `attacks/`. Exploits must run from a clean clone with the system Python.
- **Exploits follow the PoC contract** in `attacks/README.md`: takes `--base-url`, prints evidence, exits 0 on success and non-zero on failure, ships an `expected.json`.
- **Do not fix a planted vulnerability as a drive-by.** If you notice one, say so; do not silently repair it. The vulnerable state is the artifact.
- **Do not add dependencies.** Propose them; a human adds them to the manifest.
- **Do not weaken a test to make it pass.** Report the failure instead.

## Attribution

Each entry in an `ANSWER-KEY.md` records whether the code was written by an agent or by hand. Answer honestly when asked to fill that field — the value of the M6 writeup depends entirely on that column being accurate.
