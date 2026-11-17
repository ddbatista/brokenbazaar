"""Tests for replay_delegation.py's judge (T10): stdlib only, no stack.

The judge is what turns a window into PASS/FAIL, so it is tested on
hand-built alerts: an extra rule fails as surely as a missing one, an
alert on another scenario's principal is a leak, and an agent row with
no records is operational, never a miss.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import replay_delegation as rd  # noqa: E402

R4, R5, R6 = rd.R4, rd.R5, rd.R6
SIX = next(s for s in rd.SCENARIOS if s.name.startswith("06"))
DIRECT = next(s for s in rd.SCENARIOS if s.name.startswith("direct"))
HUMAN = next(s for s in rd.SCENARIOS if s.name.startswith("owner changes"))


def alert(rule, principal="session s1"):
    return {"rule": rule, "principal": principal, "count": 1, "evidence": []}


class JudgeCell(unittest.TestCase):

    def judge(self, s, hardened, grew, alerts, principals, calls=None, baseline=None):
        if calls is None:
            calls = set(s.calls)
        if baseline is None:
            baseline = [alert("deny-only")] if s.deny_only[hardened] else []
        return rd.judge_cell(s, hardened, grew, calls, alerts, baseline, principals)

    def test_the_expected_set_passes(self):
        self.assertEqual(self.judge(SIX, False, {"agent.jsonl": 3}, [alert(R4), alert(R5)], {"session s1"}), [])
        self.assertEqual(self.judge(SIX, True, {"gateway.jsonl": 6}, [alert(R4), alert(R6)], {"session s1"}), [])

    def test_a_missing_rule_and_an_extra_rule_both_fail(self):
        problems = self.judge(SIX, True, {"gateway.jsonl": 6}, [alert(R4), alert(R5)], {"session s1"})
        self.assertEqual(sorted(problems), ["false positive: agent-role-change fired",
                                            "missed: authority-refusal did not fire"])

    def test_an_alert_on_another_principal_is_a_leak(self):
        problems = self.judge(DIRECT, False, {}, [alert(R6, "user someone-else")], {"user u-viewer"})
        self.assertEqual(len(problems), 1)
        self.assertIn("window leak", problems[0])

    def test_a_false_positive_row_fails_on_any_alert(self):
        problems = self.judge(HUMAN, False, {}, [alert(R5, "session s1")], set())
        self.assertIn("false positive: agent-role-change fired", problems)

    def test_an_agent_row_with_no_records_is_operational(self):
        with self.assertRaises(rd.Operational):
            self.judge(SIX, True, {"gateway.jsonl": 0, "agent.jsonl": 0}, [], {"session s1"})

    def test_an_agent_row_without_its_call_in_the_window_is_operational(self):
        # The agent's own report is not enough: the window's records must
        # hold the call, or the cell judges records that are not its own.
        with self.assertRaises(rd.Operational):
            self.judge(SIX, True, {"gateway.jsonl": 2}, [], {"session s1"}, calls={"read_document"})

    def test_a_direct_row_needs_no_audit_records(self):
        self.assertEqual(self.judge(DIRECT, True, {}, [alert(R6, "user u-v")], {"user u-v"}), [])

    def test_the_writer_contrast_is_asserted(self):
        # A hardened agent that wrote agent.jsonl executed a tool itself.
        problems = self.judge(SIX, True, {"gateway.jsonl": 6, "agent.jsonl": 1},
                              [alert(R4), alert(R6)], {"session s1"})
        self.assertEqual(len(problems), 1)
        self.assertIn("agent.jsonl grew", problems[0])

    def test_the_deny_only_baseline_is_asserted(self):
        problems = self.judge(SIX, True, {"gateway.jsonl": 6}, [alert(R4), alert(R6)], {"session s1"},
                              baseline=[])
        self.assertEqual(problems, ["deny-only baseline stayed silent, expected it to fire"])


class Matrix(unittest.TestCase):
    """The declared matrix, pinned: README's table is these rows."""

    def test_every_attack_is_caught_in_hardened_mode(self):
        for s in rd.SCENARIOS:
            if s.attack:
                with self.subTest(s.name):
                    self.assertTrue(s.expect[True])

    def test_no_false_positive_row_expects_an_alert(self):
        for s in rd.SCENARIOS:
            if not s.attack:
                with self.subTest(s.name):
                    self.assertEqual(s.expect, {False: set(), True: set()})

    def test_the_vulnerable_misses_are_exactly_finding_05(self):
        missed = sorted(s.name for s in rd.SCENARIOS if s.attack and not s.expect[False])
        self.assertEqual(missed, ["05 (i) viewer's agent deletes", "05 (ii) demoted session deletes"])

    def test_the_direct_route_is_invisible_to_the_deny_only_baseline(self):
        # Its 403 is the API's; the baseline reads gateway records only.
        self.assertEqual(DIRECT.deny_only, {False: False, True: False})
        self.assertEqual(DIRECT.expect, {False: {R6}, True: {R6}})

    def test_scenarios_reuse_the_exploits_scopes(self):
        # Loaded, not retyped: 05's scope asks for delete_document so the
        # hardened denial is the ROLE leg's, not the scope leg's.
        self.assertIn("delete_document", rd.EXPLOIT_05.SCOPE)
        self.assertIn("set_member_role", rd.EXPLOIT_06.SCOPE)


if __name__ == "__main__":
    unittest.main()
