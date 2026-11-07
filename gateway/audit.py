"""The gateway's audit store: D4's pre-record, written before execution.

THE ORDERING IS THE CONTROL, so it is worth stating plainly:

    append the pre-record  ->  fsync  ->  the decision_id becomes usable
                           ->  execute  ->  append the completion record

An id that existed before its record could cite a record that does not
exist. A record written after execution could describe something that
already happened, which is a log; a record written before it is a
LICENSE, and execution is a consequence of it (D4). That difference is
what makes SR-B5-6 -- no record, no execution -- enforceable by ordering
rather than by a reviewer's memory.

Per-record open/write/fsync is slower than a held handle and is chosen on
purpose: durability here is a property of the RECORD, and one line per
file operation leaves no buffering window in which a record is "written"
but not durable.

Schema is D5.2, shared with the agent's writer (app/agent/audit.go):

    pre   ts, phase, decision_id, session, acting_for, org, tool, args,
          provenance, resolved (per-tool enrichment), route, reasons, detail
    post  ts, phase, decision_id, outcome, summary, duration_ms

The pre-record carries the FULL decision inputs, including the
enrichment, because SR-B5-9 says logged with its inputs. Without
resolved.host/ip, finding 04's record cannot say what resolved where --
which is the entire evidence of the SSRF attempt -- and T9's detector
cannot distinguish an allowed fetch to an allowlisted host from any
other. The post record is lean: outcome, a short summary, duration. No
result bodies: tenant data is stored once, in messages, and an audit
store holding free-form bodies would be a second document store with
different access semantics (and unredactable by construction, M2-N2).
"""

from __future__ import annotations

import json
import os
import secrets
import time
from pathlib import Path


def _stamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".%03dZ" % (
        int(time.time() * 1000) % 1000
    )


class Audit:
    """Append-only JSONL writer for gateway decisions."""

    def __init__(self, path, schema):
        self.path = Path(path)
        self.schema = schema

    @classmethod
    def open(cls, path, schema) -> "Audit":
        """Probe the destination at construction.

        An unwritable audit path is a STARTUP failure, not a mid-run
        surprise -- the same loud-or-absent rule the API applies to
        TOOLS_SECRET and the agent applies to DATABASE_URL.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            os.fsync(fh.fileno())
        return cls(path, schema)

    def _write(self, record: dict) -> None:
        line = json.dumps(record, separators=(",", ":"), sort_keys=False)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def pre(self, *, tool, args, session, provenance, resolved, route,
            reasons, detail="") -> str:
        """Write the pre-record and return its id.

        The id is generated, embedded in the record, and written -- and
        only RETURNED, becoming usable and citable, once the write is
        durable. A caller that holds an id therefore holds proof that the
        record exists.

        Gateway-minted ids are d_-prefixed; the agent's own writer mints
        a_ ids for its unmediated calls. Only d_ ids ever reach the
        tool_calls citation column, where the schema CHECK pairs them
        with route != 'unmediated'.
        """
        decision_id = "d_" + secrets.token_hex(8)
        record = {
            "ts": _stamp(),
            "phase": "pre",
            "decision_id": decision_id,
            "session": session.get("id", ""),
            "acting_for": session.get("acting_for", ""),
            "org": session.get("org", ""),
            "tool": tool,
            "args": self.schema.fields(args),
            "provenance": provenance,
            "route": route,
            "reasons": reasons,
        }
        if resolved:
            record["resolved"] = resolved
        if detail:
            record["detail"] = detail
        self._write(record)
        return decision_id

    def post(self, decision_id, *, outcome, summary="", duration_ms=0) -> None:
        self._write({
            "ts": _stamp(),
            "phase": "post",
            "decision_id": decision_id,
            "outcome": outcome,
            "summary": summary,
            "duration_ms": duration_ms,
        })
