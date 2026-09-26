# Security Policy

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Every vulnerability in it is intentional and documented. Run it on localhost only — never deploy it to a public network, never point it at real credentials or data, and never reuse its code in a production system. BrokenBazaar is fictional and unaffiliated with any company or product of a similar name.

## Intended use

BrokenBazaar exists so that security practitioners can study the full lifecycle of a vulnerability in an AI agent product: how it gets planted, how it is exploited, which control actually fixes it, and whether a detection rule catches it.

It is intended to be run:

- on `localhost`, bound to the loopback interface
- inside the provided Docker Compose stack
- with the seeded fake tenants and fake data it ships with
- disconnected from any real credential, API key, cloud project, or data source

## Do not

- **Do not deploy this to a public network.** It contains working authorization bypasses, injection paths, and SSRF by design.
- **Do not point it at real infrastructure.** The `mock-metadata` service exists precisely so the cloud-metadata attacks are reproducible *without* a cloud account.
- **Do not copy code from `app/` into a production system.** Several files are wrong on purpose, and the wrongness is subtle by design — that is the teaching point.
- **Do not treat a passing `HARDENED=true` run as evidence that a pattern is safe in general.** The controls here are scoped to this product's threat model.

## Reporting

This repo intentionally contains vulnerabilities, so normal vulnerability disclosure does not apply to the planted findings — they are catalogued in `attacks/` and in each module's `ANSWER-KEY.md`.

Two things *are* worth reporting, via a GitHub issue:

1. **An unintended vulnerability** — something exploitable that is not in the bug ledger. That is a genuine finding about this codebase and will be credited.
2. **Anything that makes the lab unsafe to run as documented** — for example a default that binds beyond loopback, a fixture that reaches a real external host, or a container that escapes its intended scope.

## Fixtures are hostile on purpose

`fixtures/evil-mcp/` and `fixtures/evil-skill/` are attacker-controlled artifacts: a malicious MCP server and malicious skill bundles, including a mutable reference host used to demonstrate post-approval content drift. They are test data, they are meant to be hostile, and they are not a supply-chain compromise of this repo.
