# BrokenBazaar

[![ci](https://github.com/ddbatista/brokenbazaar/actions/workflows/ci.yml/badge.svg)](https://github.com/ddbatista/brokenbazaar/actions/workflows/ci.yml)

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Every vulnerability in it is intentional and documented. Run it on localhost only — never deploy it to a public network, never point it at real credentials or data, and never reuse its code in a production system. BrokenBazaar is fictional and unaffiliated with any company or product of a similar name.

A multi-tenant **AI agent marketplace**: orgs install third-party agent tools (MCP servers) and skill bundles, and an agent acts on their behalf. It is built to be broken, then fixed, on purpose.

This repo demonstrates the full **Product Security lifecycle** on one product, one module at a time:

```
threat model → build → attack → defend → regression test → detect → publish
```

## What this is not

**This is not a breadth catalogue of web vulnerabilities.** If you want a wide inventory of injection, XSS, CSRF and access-control exercises to drill against, use a general-purpose deliberately-vulnerable web application — that ground is already well covered, and this project does not try to compete there.

BrokenBazaar makes the opposite trade: **few vulnerabilities, complete lifecycles.** Ten findings total, each one carried from threat model → PoC → control → regression test → measured detection → written rationale for *why that control*. Depth per finding is the product; count is not.

The surface that matters here is the **agent**: delegation, tool capability, the context supply chain, and the marketplace that feeds both. The web tier exists only far enough to make those reachable.

## Status

| Module | Boundary | Status |
|---|---|---|
| M0 Foundation | — | ✅ complete |
| M1 Tenancy & Identity | B1, B2 | 🟡 in progress |
| M2 Agent & Tool Gateway | B3, B4, B5 | ⬜ not started |
| M3 Delegation & Confused Deputy | B3, B5, B8 | ⬜ not started |
| M4a Marketplace (MCP) | B6 | ⬜ not started |
| M4b Marketplace (Skills) | B9 | ⬜ not started |
| M6 Publish & Program | — | ⬜ not started |

## Trust boundaries

Every finding names the boundary it crosses.

| | Boundary |
|---|---|
| **B1** | Internet → API |
| **B2** | Tenant ↔ Tenant |
| **B3** | User → Agent (privilege escalation via prompt) |
| **B4** | Agent ↔ untrusted content (documents/web are data, never instructions) |
| **B5** | Agent → Tools (the capability boundary; the gateway) |
| **B6** | Platform ↔ Publisher (marketplace supply chain) |
| **B7** | App → Cloud (SA identity, metadata, egress) |
| **B8** | Control plane ↔ data plane (who can change policy) |
| **B9** | Platform ↔ context supply chain (who may place *instructions* in the agent's context) |

**Why B9 is its own boundary.** B5 is mediated by the gateway: every tool call passes allowlist → judge → policy. B4 says untrusted content is wrapped and marked as data, never concatenated as instructions. A poisoned *skill* defeats both by construction — it never crosses B5 (it enters at context-assembly time, before any tool call exists), and B4's rule is inapplicable because a skill *is* instructions the agent is meant to obey.

## Run it

Requires Docker only.

```bash
make up          # start the stack
curl localhost:8080/healthz
make down        # stop and remove volumes
```

Every defense is behind a `HARDENED` flag, so the same PoC can be shown working, then failing:

```bash
make up          # vulnerable  — attacks exit 0
make harden      # hardened    — the same attacks exit non-zero
```

## Layout

| Path | Contents |
|---|---|
| `app/` | Go: API, agent loop, store, tools |
| `gateway/` | Python: judge + policy (ported from [jev-lab](https://github.com/ddbatista/jev-lab)) |
| `attacks/` | One dir per finding: `exploit.py`, `README.md`, `expected.json`, `ANSWER-KEY.md` |
| `defenses/` | Control design docs — *why* this control, not just what |
| `detections/` | Detection rules + replay harness + coverage report |
| `fixtures/` | Attacker-controlled artifacts (`evil-mcp/`, `evil-skill/`) as first-class test data |
| `threat-models/` | v0 baseline + one diff per module, committed *before* the feature |
| `coverage/` | Framework map + **declared non-coverage** |
| `writeups/` | Blog-grade, one per finding |
| `infra/` | Reserved — deployment topology is out of scope for now |
| `spvs/` | Pipeline self-assessment (M6) |

## Frameworks

Findings are tagged in this order — OWASP LLM Top 10 → OWASP Agentic (ASI) → [MCP Top 10](https://owasp.org/www-project-mcp-top-10/) → [Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/) → classic OWASP Top 10 where it genuinely applies — with the framework version pinned in the tag, because the MCP and AST projects are young and still renumbering.

Where a finding has no AI-standard home it is tagged classic and says so. `coverage/` also lists what this lab **deliberately does not cover**, and why.

## License

MIT — see [LICENSE](LICENSE). Security policy and safe-use terms: [SECURITY.md](SECURITY.md).
