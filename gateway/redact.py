"""Write-time redaction for the gateway's audit records (MCP01, D5.4).

The Python half of a schema shared with two Go writers. The authoritative
list is gateway/policy/redact.json -- a HARDENED ZONE, because what counts
as a secret is a security decision, not a code detail. This module reads
it at runtime; app/redact embeds a byte-copy and a drift test fails the
build if the two ever differ.

Redaction is by field NAME, never by value shape (M2-N2): a pattern is a
denylist, and a regression test against a pattern only proves the pattern
catches what it was written to catch. The consequence is declared rather
than discovered -- see _residual in the schema, and the residual-pinning
tests in test_gate.py and app/redact/redact_test.go, which assert that a
token inside a URL query value SURVIVES. That is not an oversight being
tolerated; it is a known gap held still by a test, so that a future
change which starts mangling URLs has to re-declare it consciously
(and such a change would also blind T9, which reads urls out of the
audit store).

Unlike the Go half -- whose callers pass flat map[string]string arguments
-- the gateway receives arbitrary JSON from the wire, so this walks
nested structures.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

REDACTED = "[REDACTED]"

_DEFAULT_SCHEMA = Path(__file__).resolve().parent / "policy" / "redact.json"


class Schema:
    """A loaded redaction schema.

    Loaded once at gateway start. A missing or malformed schema is a
    STARTUP failure (see gate.py's boot probes): a redaction control that
    silently falls back to "redact nothing" is worse than one that
    refuses to run, because the first failure is invisible in a green
    test run and the second is impossible to miss.
    """

    def __init__(self, headers, fields_exact, fields_suffix):
        self.headers = frozenset(h.lower() for h in headers)
        self.fields_exact = frozenset(fields_exact)
        self.fields_suffix = tuple(fields_suffix)

    @classmethod
    def load(cls, path=None) -> "Schema":
        path = Path(path or os.getenv("REDACT_SCHEMA") or _DEFAULT_SCHEMA)
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        for key in ("headers", "fields_exact", "fields_suffix"):
            if key not in raw or not isinstance(raw[key], list):
                raise ValueError(f"redact: schema {path} is missing the {key!r} list")
        return cls(raw["headers"], raw["fields_exact"], raw["fields_suffix"])

    def matches(self, key: str) -> bool:
        """Is this field name credential-shaped?

        Over-matching is the intended bias: a record that loses a
        harmless field costs nothing, while a record that keeps a
        credential costs everything. Nothing detection needs -- url,
        host, ip, tool, id -- ends in a credential suffix.
        """
        if key in self.fields_exact:
            return True
        return any(key.endswith(suffix) for suffix in self.fields_suffix)

    def fields(self, value):
        """Return a redacted copy of a JSON-shaped value.

        Walks dicts and lists to any depth; scalars pass through. The
        input is never mutated -- the caller keeps the real arguments to
        execute with, and only the copy reaches the audit store.
        """
        if isinstance(value, dict):
            return {
                k: (REDACTED if self.matches(k) else self.fields(v))
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [self.fields(v) for v in value]
        return value

    def headers_of(self, headers: dict) -> dict:
        """Redact a header mapping by lowercased name.

        The gateway does not log outbound headers today; this exists
        because D1b's measurement harness must never write a bearer token
        into experiments/runs/*.jsonl, and that harness shares this
        schema rather than growing its own list.
        """
        return {
            k: (REDACTED if k.lower() in self.headers else v)
            for k, v in headers.items()
        }
