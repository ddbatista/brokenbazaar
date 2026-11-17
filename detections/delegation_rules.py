#!/usr/bin/env python3
"""M3 detection rules: delegated authority and the control plane.

M2's rules read a fetch's inputs, and the inputs were enough: a host off
the allowlist, a metadata address, a fetch whose context held untrusted
content. Authority is different. Finding 05 is a user asking their own
agent, in their own words, for something their role does not permit --
nothing is injected, so no input on its own says "attack". The signal is
a RELATION between the call and the acting user's role at that moment,
and only the hardened gateway derives that role (authority.role_now).
That is what the matrix measures (detections/README.md, M3).

Three rules, each one alert per (rule, principal), firing at ONE event.
The threat model names them (threat-models/m3-delegation.md: "agent-
initiated role changes; any role_does_not_permit or control_plane_not_
delegable denial (both are attempts)"):

  R4 control-plane-call  a call to a tool the policy marks non-delegable,
                         read from the pre-record in EITHER writer's
                         schema, whatever happened to it. What was ASKED,
                         so it reads the same in both modes.
  R5 agent-role-change   a role_changes row with actor_session set: a
                         role that actually changed, through an agent
                         session (SR-B8-7, SR-B3-9). A human's change
                         through the direct admin route has no session
                         and never fires.
  R6 authority-refusal   a refusal that names a principal reaching past
                         its authority: a gateway denial for
                         role_does_not_permit or control_plane_not_
                         delegable; any refused_at_execution outcome (the
                         authority changed between the gate and the
                         write, M3-N2); the API's in-org log lines --
                         T3's direct-route 403 and T6's refusal at
                         execution.

DECLARED COUPLINGS -- what blinds each rule:
- R4 reads the gate's own list (policy.rego's non_delegable constant), as
  R2 reads the gate's allowlist. A tool dropped from the list blinds R4
  and the gate together. R5 does not read the list, so the change itself
  is still seen -- in the mode where it happens.
- R5 sees changes made through the product. The agent's database
  credential can write role_changes and memberships directly (R-M3-2);
  a change made by direct SQL is not seen, and a green matrix does not
  claim it.
- R6 is a DENIAL rule, so it is coupled to the control working -- M1's
  lesson. In vulnerable mode the agent is never refused, so R6 sees only
  the direct route's 403 (whose role check ships in both modes, T3).
- Nothing here sees finding 05 in vulnerable mode. The vulnerable agent
  records who acted (acting_for), never what that user may do. The rule
  that would see it -- reconstruct the role at the call's time from
  memberships and the role_changes history, then ask whether the role
  permits the tool -- needs a second copy of the Go permission table,
  and M3 D4 settled on one. Declared, not built (T10 D1).
- A refusal at execution needs a demotion inside the gate-to-write
  window; the replay cannot land one deterministically, so that leg is
  unit-tested only (T10 D2).

Alerts carry the principal and short evidence strings: tool, role names,
reasons, user ids. Never a document body.

Pure functions, no IO except load_non_delegable; replay_delegation.py
feeds them real records from a live stack.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
POLICY_REGO = REPO / "gateway" / "policy" / "policy.rego"

R4, R5, R6 = "control-plane-call", "agent-role-change", "authority-refusal"

# The two policy reasons the threat model counts as attempts. Every other
# denial is someone else's signal: egress and metadata are M2's, a scope
# miss is the session's own consent, and enrichment_failed is the gate
# failing, not a principal reaching.
ATTEMPT_REASONS = frozenset({"role_does_not_permit", "control_plane_not_delegable"})
REFUSED_AT_EXECUTION = "refused_at_execution"  # gateway/gate.py's outcome

# The policy's constant, read the way app/api/non_delegable_test.go reads it.
NON_DELEGABLE_RE = re.compile(r'(?m)^non_delegable := \{([^}]*)\}')

# app/api/documents.go forbidden(): T3's direct-route 403. org=, NOT M1's
# target_org= -- that line is rule.py's cross-tenant probe signal.
ROLE_LINE_RE = re.compile(
    r'authz: deny sub=(\S+) org=(\S+) decision=role-does-not-permit role="?([^"\s]*)"? action=(\S+)')
# app/api/internal_tools.go authorize(): T6's refusal at execution.
EXEC_LINE_RE = re.compile(r"authz: deny session=(\S+) org=(\S+) decision=(\S+) tool=(\S+) at=execution")

# The SELECT replay_delegation.py runs (psql -At: '|'-separated, no header);
# parse_role_changes reads its columns in this order.
ROLE_CHANGE_COLUMNS = ("id", "org", "subject", "role_before", "role_after",
                       "actor_user", "actor_session", "created_at")
ROLE_CHANGES_SQL = ("SELECT id, org_id, subject, role_before, role_after, actor_user, "
                    "coalesce(actor_session::text, ''), created_at FROM role_changes ORDER BY created_at, id")


def session_principal(session_id: str) -> str:
    """The principal an agent session's alerts are keyed on."""
    return f"session {session_id}"


def user_principal(user_id: str) -> str:
    """The principal a direct-route alert is keyed on: the user (sub=)."""
    return f"user {user_id}"


def decision_principal(decision_id: str) -> str:
    """The fallback for a refusal whose pre-record is not in the window."""
    return f"decision {decision_id}"


def load_non_delegable(path) -> frozenset:
    """The policy's non_delegable set. A file without the constant raises:
    an empty set would turn R4 off without a word."""
    match = NON_DELEGABLE_RE.search(Path(path).read_text(encoding="utf-8"))
    tools = frozenset(re.findall(r'"([^"]+)"', match.group(1))) if match else frozenset()
    if not tools:
        raise ValueError(f"{path}: no non_delegable constant with at least one tool")
    return tools


def parse_role_changes(text: str) -> list:
    """role_changes rows from `psql -At` output. A row with the wrong
    number of fields raises, like agent_rules.parse_jsonl."""
    rows = []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        fields = line.split("|")
        if len(fields) != len(ROLE_CHANGE_COLUMNS):
            raise ValueError(f"role_changes row {n} has {len(fields)} fields, "
                             f"expected {len(ROLE_CHANGE_COLUMNS)}")
        rows.append(dict(zip(ROLE_CHANGE_COLUMNS, fields)))
    return rows


def _group(hits) -> list:
    """(rule, principal, evidence) hits -> one alert per (rule, principal)."""
    grouped = defaultdict(list)
    for rule, principal, evidence in hits:
        grouped[(rule, principal)].append(evidence)
    return [{"rule": rule, "principal": principal, "count": len(ev), "evidence": sorted(set(ev))}
            for (rule, principal), ev in grouped.items()]


def _call(rec: dict) -> str:
    args = rec.get("args") or {}
    if rec.get("tool") == "set_member_role":
        return f"set_member_role {args.get('user', '?')} -> {args.get('role', '?')}"
    return rec.get("tool", "?")


def _call_hits(records: list, non_delegable) -> list:
    return [(R4, session_principal(rec.get("session", "")), f"{_call(rec)} ({rec.get('route', '?')})")
            for rec in records
            if rec.get("phase") == "pre" and rec.get("tool") in non_delegable]


def _role_change_hits(rows: list) -> list:
    return [(R5, session_principal(row["actor_session"]),
             f"{row['subject']} {row['role_before']} -> {row['role_after']} (for {row['actor_user']})")
            for row in rows if row.get("actor_session")]


def _refusal_hits(records: list, api_lines) -> list:
    pres = {rec.get("decision_id"): rec for rec in records if rec.get("phase") == "pre"}
    hits = []
    for rec in records:
        if rec.get("phase") == "pre" and rec.get("route") == "deny":
            for reason in (rec.get("reasons") or []):
                if reason in ATTEMPT_REASONS:
                    role = (rec.get("authority") or {}).get("role_now", "?")
                    hits.append((R6, session_principal(rec.get("session", "")),
                                 f"gateway deny {reason} ({rec.get('tool')}, role_now={role})"))
        elif rec.get("phase") == "post" and rec.get("outcome") == REFUSED_AT_EXECUTION:
            did = rec.get("decision_id", "")
            origin = pres.get(did)
            principal = session_principal(origin.get("session", "")) if origin else decision_principal(did)
            tool = origin.get("tool", "?") if origin else "?"
            hits.append((R6, principal, f"{REFUSED_AT_EXECUTION} {rec.get('summary') or '?'} ({tool})"))
    for line in api_lines:
        m = ROLE_LINE_RE.search(line)
        if m:
            sub, _org, role, action = m.groups()
            hits.append((R6, user_principal(sub), f"api 403 role_does_not_permit (role={role} action={action})"))
            continue
        m = EXEC_LINE_RE.search(line)
        if m:
            session, _org, decision, tool = m.groups()
            hits.append((R6, session_principal(session),
                         f"api at=execution {decision.replace('-', '_')} ({tool})"))
    return hits


def find_call_alerts(records: list, non_delegable) -> list:
    """R4 over audit records (either writer)."""
    return _group(_call_hits(records, non_delegable))


def find_role_change_alerts(rows: list) -> list:
    """R5 over role_changes rows."""
    return _group(_role_change_hits(rows))


def find_refusal_alerts(records: list, api_lines) -> list:
    """R6 over audit records and the API's log lines."""
    return _group(_refusal_hits(records, api_lines))


def find_alerts(records: list, role_change_rows: list, api_lines, non_delegable) -> list:
    """All three rules over one window of all three sources."""
    return (find_call_alerts(records, non_delegable)
            + find_role_change_alerts(role_change_rows)
            + find_refusal_alerts(records, api_lines))
