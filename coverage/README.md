# Coverage — the framework map and what this lab deliberately does not cover

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

This page grows one module at a time. Rows for findings 03–10 land with their modules (M2–M4); module-scoped non-coverage entries land when the module that would have covered them ships or declines to.

## Findings → standards

Tags are pinned to a framework version, because the young projects (MCP, AST) are still renumbering — MCP06 currently carries two different titles across the OWASP site and its GitHub index, and an unpinned ID silently rots into a claim about nothing.

| # | Finding | Boundary | Module | Standards (pinned) |
|---|---|---|---|---|
| 01 | cross-tenant read | B2 | M1 | **A01:2021** — Broken Access Control. No AI-standard home, stated plainly. |
| 02 | jwt org claim | B1, B2 | M1 | **A01:2021**, **A07:2021** — Broken Access Control + Identification/Authentication Failures. No AI-standard home. |
| 03 | indirect injection | B4, B5 (+ B3, the least-privilege variant) | M2, M3 | **LLM01:2025** Prompt Injection · **ASI01 2026** Agent Goal Hijack · **MCP06:2025** · **MCP10:2025** |
| 04 | ssrf metadata | B5, B7 | M2 | **LLM06:2025** Excessive Agency · **ASI02 2026** Tool Misuse and Exploitation · **MCP05:2025** · **A10:2021** Server-Side Request Forgery |

03 and 04 carry agent-era tags because the agent is the mechanism: the planted bug is the agent executing its tools with no gate.

**The honest-mapping rule.** Findings 01 and 02 are Broken Access Control, full stop. Forcing an LLM-framework ID onto an authz bug is the tell of a portfolio repo written for keywords, not for findings. Where a later finding genuinely answers an agent-era framework, it is tagged there — pinned, and in this order: OWASP LLM Top 10 → OWASP Agentic (ASI) → MCP Top 10 (e.g. `MCP03:2025`) → Agentic Skills Top 10 (e.g. `AST01 v0.5 2026-06`) → classic OWASP Top 10.

## Declared non-coverage — stated, not discovered

Silent gaps read as ignorance; declared gaps read as judgment. Nothing below is an oversight — each is a decision with its reason on record.

| Not covered | Why | Carried by |
|---|---|---|
| **Classic web-tier classes** — XSS in the htmx surface, CSRF, SQL injection, request smuggling, TLS termination, deserialization | Well covered by general-purpose deliberately-vulnerable web applications; no agent-specific teaching value. The web tier here exists only to make the agent boundaries reachable. | SR-B1-7 / B1 leaf 4 — carried from M0's open follow-ups, recorded here per the baseline's own requirement |
| **Credential hygiene** — seeded, static, shared password; salted SHA-256, not a KDF; no rotation, lockout, or password policy | A lab fixture, not a product credential store. The lesson of M1 is tenancy and token verification, not password storage. | R-M1-4 (m1-tenancy.md §6) |
| **Timing side channels** — status, body and work performed are made indistinguishable for wrong-org vs not-found; wall-clock latency is **not** claimed constant | A cross-network timing oracle against Postgres is not the attack this lab teaches, and claiming constant time without measuring it would be a lie in a document whose value is that it does not lie. | R-M1-2 (m1-tenancy.md §6) |

**M2 — the agent and its gateway (findings 03, 04):**

| Not covered | Why | Carried by |
|---|---|---|
| **A compliance *rate* for finding 03 on real models** | The PoC's model is scripted, so detect/miss is a fixed fact, not a rate. Two pre-registered experiments ran once each. On Opus 5.5 the result was **unmeasured**: the provider's classifier refused 150/150. On GLM-5.3, **0/150 complied** (B 0/50, Wilson 95% upper ≈ 7%), so the channel comparison is unresolved. One model and one phrasing; it says nothing about others. | R-M2-1, [`experiments/`](../experiments/) |
| **Network-layer mediation** | Mediation is enforced by the hardened agent holding no tool code, not by the network. Compose cannot express egress policy. | R-M2-3, M2-N1 |
| **Free-form audit redaction** | Redaction is schema-based where the shape is known and pattern-based for free-form payloads; the remainder is declared, so a clean leak scan does not imply coverage. | R-M2-2, M2-N2 |
| **Legitimate-capability aggregation** | Several allowed calls that together leak. The baseline calls it unclosable in the general case; scope and allowlists raise the cost, and the audit record makes it detectable. | R-M2-5, B5 5.1 / 5.3 |
| **An LLM judge in the gate** | M2's gate decides deterministically; no ambiguous call exists to adjudicate. The judge, and its subject-vs-testimony audit, are M4a's. | M2 D2, M2-N3 / M2-N5 |
| **A hostname that resolves to a metadata address, seen by detection in vulnerable mode** | The vulnerable agent records no resolved address, so R3 sees names and redirect targets only there. The control is unaffected; this is detection's limit. | `detections/README.md` (M2) |

The M4-era entries — MCP09 Shadow MCP Servers, AST06 Weak Isolation, AST10 Cross-Platform Reuse, AST02 registry-level compromise — land with M4, where the marketplace exists to make them meaningful or explicitly declined.

## Corrections log — when a diff corrected the baseline

The baseline (`threat-models/v0-baseline.md`) is an artifact with a date on it; it is never retroactively edited. When a module's diff proves one of its requirements wrong, the correction is recorded here and lands in the next baseline version.

- **M1-N2 (m1-tenancy.md §4):** SR-B2-1 — *"no code path can obtain a database handle without an org context"* — was **false as written the moment a seed existed**: bootstrap wrote to all three tenants before any token existed, outside both stores. The pattern: an invariant asserted over "all code paths" is routinely false for the paths that run before the system is up. Corrected by SR-M1-2 (seed goes through `OrgStore`, one `ForOrg` handle per org); the baseline's wording fix lands in `v1`, not by editing `v0`.
- **M2-N3 (m2-agent-gateway.md §4):** SR-B5-1 says no attacker-influenceable value is an input to a decision. But a decision's **subject**, the fully-resolved arguments, is attacker-influenced and *must* be inspected (SR-B5-3). The line SR-B5-1 needs is between that subject and **testimony** about it: the tool's self-description, the model's stated justification, a prior result. Testimony must never be consulted, because each is an assertion by the party being judged. Queued for `v1`, with A8.2's scope note and A8.10's split between the application layer and the network layer.
