"""Tests for the M3 delegation detection rules (T10).

    python3 -m unittest discover -s detections -t detections -p 'test_*.py' -v

stdlib only, no stack. Every record and log line below has the shape the
real writers produce -- gateway/gate.py and gateway/audit.py,
app/agent/audit.go, app/api/documents.go's and app/api/internal_tools.go's
log lines, and a `role_changes` row as replay_delegation.py reads it --
copied from a live run with ids replaced.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import delegation_rules as r  # noqa: E402

ORG = "0a000000-0000-4000-8000-000000000001"
NON_DELEGABLE = frozenset({"set_member_role"})


def pre(did, session, tool, args, *, route="unmediated", reasons=None, role_now=None):
    """A pre-record. route 'unmediated' = the vulnerable agent's writer."""
    rec = {"ts": "2026-11-17T20:10:16.351Z", "phase": "pre", "decision_id": did,
           "session": session, "acting_for": "u-1", "org": ORG, "tool": tool, "args": args,
           "provenance": {"derived_from": ["user", "untrusted"]}, "route": route, "reasons": reasons}
    if route == "unmediated":
        rec["mediated"] = False
    if role_now:
        rec["authority"] = {"role_now": role_now,
                            "legs": {"within_time": True, "in_scope": True, "role_permits": role_now == "admin"}}
    return rec


def post(did, outcome="ok", summary=""):
    return {"ts": "2026-11-17T20:10:16.360Z", "phase": "post", "decision_id": did,
            "outcome": outcome, "summary": summary, "duration_ms": 3}


def change(subject, before, after, actor_user, actor_session=""):
    return {"id": f"rc-{subject}-{after}", "org": ORG, "subject": subject, "role_before": before,
            "role_after": after, "actor_user": actor_user, "actor_session": actor_session,
            "created_at": "2026-11-17 20:08:31.24+00"}


ROLE_LINE = ("2026/11/17 20:10:20 authz: deny sub=u-viewer org=" + ORG
             + ' decision=role-does-not-permit role="viewer" action=delete')
EXEC_LINE = ("2026/11/17 20:10:21 authz: deny session=s-9 org=" + ORG
             + " decision=role-does-not-permit tool=delete_document at=execution")
M1_LINE = "2026/11/17 20:10:22 authz: deny sub=u-x target_org=" + ORG + " decision=not-a-member"


def fired(alerts):
    return sorted({a["rule"] for a in alerts})


def by(alerts, rule):
    return [a for a in alerts if a["rule"] == rule]


class LoadNonDelegable(unittest.TestCase):

    def test_reads_the_shipped_policy(self):
        # One home for the list: the gate's own Rego constant, the file the
        # Go route test and the gateway test also read.
        self.assertEqual(r.load_non_delegable(r.POLICY_REGO), frozenset({"set_member_role"}))

    def test_a_policy_without_the_constant_is_refused(self):
        # An empty set would turn R4 off silently: "no non-delegable tool"
        # is not something to infer from a parse that found nothing.
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d) / "no_constant.rego"
            tmp.write_text("package gate\n")
            with self.assertRaises(ValueError):
                r.load_non_delegable(tmp)


class R4ControlPlaneCall(unittest.TestCase):
    """Any call to a non-delegable tool, whatever happened to it."""

    def test_the_vulnerable_agents_own_record_fires(self):
        recs = [pre("a_1", "s1", "set_member_role", {"user": "u-m", "role": "admin"})]
        alerts = r.find_call_alerts(recs, NON_DELEGABLE)
        self.assertEqual(fired(alerts), [r.R4])
        self.assertEqual(alerts[0]["principal"], "session s1")

    def test_a_denied_call_fires_too(self):
        # It reads what was ASKED, not what the gate decided: the same
        # alert in both modes.
        recs = [pre("d_1", "s1", "set_member_role", {"user": "u-m", "role": "admin"},
                    route="deny", reasons=["control_plane_not_delegable"], role_now="admin")]
        self.assertEqual(fired(r.find_call_alerts(recs, NON_DELEGABLE)), [r.R4])

    def test_other_tools_and_post_records_do_not(self):
        recs = [pre("d_1", "s1", "delete_document", {"id": "doc"}, route="allow"), post("d_1"),
                post("d_2", summary="set_member_role")]
        self.assertEqual(r.find_call_alerts(recs, NON_DELEGABLE), [])

    def test_one_alert_per_session(self):
        recs = [pre("a_1", "s1", "set_member_role", {"user": "u", "role": "admin"}),
                pre("a_2", "s1", "set_member_role", {"user": "v", "role": "admin"}),
                pre("a_3", "s2", "set_member_role", {"user": "u", "role": "viewer"})]
        alerts = r.find_call_alerts(recs, NON_DELEGABLE)
        self.assertEqual(sorted((a["principal"], a["count"]) for a in alerts),
                         [("session s1", 2), ("session s2", 1)])

    def test_the_alert_names_the_change_asked_for(self):
        recs = [pre("a_1", "s1", "set_member_role", {"user": "u-m", "role": "admin"})]
        self.assertIn("set_member_role u-m -> admin (unmediated)",
                      r.find_call_alerts(recs, NON_DELEGABLE)[0]["evidence"])


class R5AgentRoleChange(unittest.TestCase):
    """A role that actually changed, through an agent session."""

    def test_a_change_with_an_actor_session_fires(self):
        alerts = r.find_role_change_alerts([change("u-m", "member", "admin", "u-owner", "s1")])
        self.assertEqual(fired(alerts), [r.R5])
        self.assertEqual(alerts[0]["principal"], "session s1")
        self.assertIn("u-m member -> admin (for u-owner)", alerts[0]["evidence"])

    def test_a_human_change_is_silent(self):
        # actor_session NULL: a person used the direct admin route. That is
        # the false-positive row, and SR-B3-9's distinction as a column.
        self.assertEqual(r.find_role_change_alerts([change("u-m", "member", "admin", "u-owner")]), [])


class ParseRoleChanges(unittest.TestCase):

    def test_psql_unaligned_rows(self):
        text = ("rc1|" + ORG + "|u-m|member|admin|u-owner|s1|2026-11-17 20:08:31.24+00\n"
                "rc2|" + ORG + "|u-m|admin|member|u-owner||2026-11-17 20:08:32.01+00\n")
        rows = r.parse_role_changes(text)
        self.assertEqual([(x["id"], x["actor_session"]) for x in rows], [("rc1", "s1"), ("rc2", "")])

    def test_a_malformed_row_raises(self):
        # A detector that skips what it cannot read reports "nothing
        # found" about rows it never looked at (agent_rules.parse_jsonl).
        with self.assertRaises(ValueError):
            r.parse_role_changes("rc1|only|four|fields\n")


class R6AuthorityRefusal(unittest.TestCase):
    """The threat model's attempts: a role or delegability refusal."""

    def test_a_gateway_role_denial_fires(self):
        recs = [pre("d_1", "s1", "delete_document", {"id": "doc"}, route="deny",
                    reasons=["role_does_not_permit"], role_now="viewer")]
        alerts = r.find_refusal_alerts(recs, [])
        self.assertEqual(fired(alerts), [r.R6])
        self.assertEqual(alerts[0]["principal"], "session s1")
        self.assertIn("gateway deny role_does_not_permit (delete_document, role_now=viewer)",
                      alerts[0]["evidence"])

    def test_a_delegability_denial_fires(self):
        recs = [pre("d_1", "s1", "set_member_role", {"user": "u", "role": "admin"}, route="deny",
                    reasons=["control_plane_not_delegable"], role_now="admin")]
        self.assertEqual(fired(r.find_refusal_alerts(recs, [])), [r.R6])

    def test_other_denials_are_not_attempts(self):
        # A fetch off the allowlist is M2's signal (R2), a scope miss is the
        # session's own consent, and a fail-closed deny is the gate's
        # failure -- none is a principal reaching past its authority.
        recs = [pre(f"d_{n}", "s1", "http_fetch", {"url": "http://x/"}, route="deny", reasons=[reason])
                for n, reason in enumerate(("egress_not_allowlisted", "not_in_session_scope",
                                            "enrichment_failed", "session_expired"))]
        self.assertEqual(r.find_refusal_alerts(recs, []), [])

    def test_a_refusal_at_execution_fires_on_its_session(self):
        # The post-record carries no session: it is joined to its pre-record.
        recs = [pre("d_1", "s9", "delete_document", {"id": "doc"}, route="allow", role_now="admin"),
                post("d_1", outcome="refused_at_execution", summary="role_does_not_permit")]
        alerts = r.find_refusal_alerts(recs, [])
        self.assertEqual([(a["rule"], a["principal"]) for a in alerts], [(r.R6, "session s9")])
        self.assertIn("refused_at_execution role_does_not_permit (delete_document)", alerts[0]["evidence"])

    def test_a_refusal_at_execution_without_its_pre_record_still_fires(self):
        # Outside the window, or lost: alert on the decision id, never drop it.
        alerts = r.find_refusal_alerts([post("d_7", outcome="refused_at_execution",
                                             summary="session_expired")], [])
        self.assertEqual([(a["rule"], a["principal"]) for a in alerts], [(r.R6, "decision d_7")])

    def test_the_api_role_line_fires_on_the_user(self):
        alerts = r.find_refusal_alerts([], [ROLE_LINE])
        self.assertEqual([(a["rule"], a["principal"]) for a in alerts], [(r.R6, "user u-viewer")])
        self.assertIn("api 403 role_does_not_permit (role=viewer action=delete)", alerts[0]["evidence"])

    def test_the_api_execution_line_fires_on_the_session(self):
        alerts = r.find_refusal_alerts([], [EXEC_LINE])
        self.assertEqual([(a["rule"], a["principal"]) for a in alerts], [(r.R6, "session s-9")])
        self.assertIn("api at=execution role_does_not_permit (delete_document)", alerts[0]["evidence"])

    def test_the_execution_line_and_its_record_are_one_alert(self):
        # The same refusal, written by the API and by the gateway: one
        # alert for the session, counted twice, not two alerts.
        recs = [pre("d_1", "s-9", "delete_document", {"id": "doc"}, route="allow", role_now="admin"),
                post("d_1", outcome="refused_at_execution", summary="role_does_not_permit")]
        alerts = r.find_refusal_alerts(recs, [EXEC_LINE])
        self.assertEqual([(a["principal"], a["count"]) for a in alerts], [("session s-9", 2)])

    def test_m1s_cross_tenant_line_is_not_read(self):
        # target_org= is M1's probe signal (rule.py), not an in-org attempt.
        self.assertEqual(r.find_refusal_alerts([], [M1_LINE, "2026/11/17 api: listening on :8080"]), [])


class FindAlerts(unittest.TestCase):

    def test_06_vulnerable_shape(self):
        recs = [pre("a_1", "s1", "set_member_role", {"user": "u-m", "role": "admin"})]
        rows = [change("u-m", "member", "admin", "u-owner", "s1")]
        self.assertEqual(fired(r.find_alerts(recs, rows, [], NON_DELEGABLE)), sorted([r.R4, r.R5]))

    def test_06_hardened_shape(self):
        recs = [pre("d_1", "s1", "set_member_role", {"user": "u-m", "role": "admin"}, route="deny",
                    reasons=["control_plane_not_delegable"], role_now="admin")]
        self.assertEqual(fired(r.find_alerts(recs, [], [], NON_DELEGABLE)), sorted([r.R4, r.R6]))

    def test_a_permitted_agent_write_and_a_human_role_change_are_silent(self):
        recs = [pre("d_1", "s1", "delete_document", {"id": "doc"}, route="allow", role_now="admin"),
                post("d_1", summary="deleted")]
        rows = [change("u-d", "admin", "viewer", "u-owner")]
        self.assertEqual(r.find_alerts(recs, rows, [], NON_DELEGABLE), [])


if __name__ == "__main__":
    unittest.main()
