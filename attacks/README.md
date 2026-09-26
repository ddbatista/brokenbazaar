# Attacks — the PoC contract

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

Every finding gets one directory. Every exploit obeys the same contract, because the attack suite runs unattended in CI, in both modes, and a PoC that needs a human to interpret it is not a regression test.

## Layout

```
attacks/
└── NN-short-name/
    ├── exploit.py       stdlib Python only, no pip
    ├── README.md        what it does, boundary crossed, framework IDs
    ├── expected.json    machine-readable assertion
    └── ANSWER-KEY.md    published when the module publishes
```

## The contract

Every `exploit.py`:

1. **Takes `--base-url`**, defaulting to `http://localhost:8080`. No hardcoded hosts or ports.
2. **Uses the standard library only.** `urllib`, `json`, `argparse`, `http.client`. No pip. It must run from a clean clone with the system Python 3.12.
3. **Prints evidence to stdout** — the actual bytes that prove the bypass, not `[+] success`. A reader must be able to see *why* it worked.
4. **Exits 0 when the attack succeeds, non-zero when it fails.** This is inverted from normal test semantics on purpose: exit 0 means *the vulnerability is present*.
5. **Is idempotent and self-cleaning.** It can be run twice in a row against the same stack.
6. **Never touches anything outside the stack.** No external network calls except to the hostile fixtures inside Compose.

## The two-mode assertion

This is what makes a PoC a regression test rather than a demo:

```bash
make up      && python3 attacks/01-cross-tenant-read/exploit.py   # exit 0  — vulnerable
make harden  && python3 attacks/01-cross-tenant-read/exploit.py   # exit !0 — control holds
```

CI runs every PoC in both modes on every push. A control that stops working is a build failure.

## expected.json

```json
{
  "finding": "01-cross-tenant-read",
  "boundary": "B2",
  "frameworks": ["A01:2021"],
  "vulnerable": { "exit_code": 0, "stdout_contains": "org_a_secret_document" },
  "hardened":   { "exit_code": 1, "stdout_contains": "403" }
}
```

`stdout_contains` is asserted against real output — this is what stops a PoC from silently passing because the endpoint 404'd.

## Framework tags

Tag in this order, and **pin the version**: OWASP LLM Top 10 → OWASP Agentic (ASI) → MCP Top 10 (e.g. `MCP03:2025`) → Agentic Skills Top 10 (e.g. `AST01 v0.5 2026-06`) → classic OWASP Top 10.

The MCP and AST projects are young and still renumbering — MCP06 currently carries two different titles across the OWASP site and its GitHub index. Unpinned IDs age badly.

If a finding has no AI-standard home, tag it classic and say so. Findings 01 and 02 are Broken Access Control, full stop. Forcing an LLM ID onto an authz bug is the tell of a repo written for keywords.

## ANSWER-KEY.md

Published per module, at that module's publish time — not held back to the end. Each entry records:

- the planted bug and the exact commit that introduced it
- why it was plausible (what a real developer would have done)
- the boundary it crosses
- the control that fixes it, and where that control lives
- **whether the code was written by an agent or by hand**

That last field is the dataset for the M6 AI-assisted-development writeup. It only has value if it is accurate.

## Planned findings

| # | Finding | Boundary | Module |
|---|---|---|---|
| 01 | cross-tenant read | B2 | M1 |
| 02 | jwt org claim | B1, B2 | M1 |
| 03 | indirect injection | B4 | M2 |
| 04 | ssrf metadata | B5, B7 | M2 |
| 05 | confused deputy | B3, B5 | M3 |
| 06 | policy plane | B8 | M3 |
| 07 | tool poisoning | B6 | M4a |
| 08 | rug pull | B6 | M4a |
| 09 | skill injection | B9 | M4b |
| 10 | skill ref drift | B9, B6 | M4b |

Hard cap: 10. New vulnerability ideas go to `BACKLOG.md`, not the build.
