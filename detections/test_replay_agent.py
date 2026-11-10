"""Tests for the M2 detection replay's cell judge (T9 D4).

    python3 -m unittest discover -s detections -p 'test_*.py' -v

The replay turns a live run into a matrix cell. The same trap as T7/T8:
a cell whose INPUT is missing must not pass. A scenario whose window
holds no records has not been "missed" -- nothing was looked at.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import replay_agent as rp  # noqa: E402

R1, R2, R3 = rp.R1, rp.R2, rp.R3


def alert(rule, session="s1"):
    return {"rule": rule, "session": session, "count": 1, "hosts": ["h"], "decision_ids": ["x"]}


INJECTION = rp.Scenario("03 injection", lambda docs: "m", calls={"read_document", "http_fetch"},
                        expect={False: {R1, R2}, True: {R1, R2}},
                        deny_only={False: False, True: True}, attack=True,
                        scope=("read_document", "http_fetch"))


def judge(hardened=False, grew=None, alerts=(), baseline=(), session="s1",
          calls=("read_document", "http_fetch")):
    grew = grew if grew is not None else ({"agent.jsonl": 4, "gateway.jsonl": 0} if not hardened
                                          else {"agent.jsonl": 0, "gateway.jsonl": 4})
    return rp.judge_cell(INJECTION, hardened, grew, set(calls), list(alerts), list(baseline), session)


class JudgeCell(unittest.TestCase):
    def test_the_expected_rules_from_the_expected_writer_pass(self):
        self.assertEqual(judge(alerts=[alert(R1), alert(R2)]), [])
        self.assertEqual(judge(hardened=True, alerts=[alert(R1), alert(R2)],
                               baseline=[alert("deny-only")]), [])

    def test_a_missing_rule_is_a_mismatch(self):
        problems = judge(alerts=[alert(R2)])
        self.assertTrue(any("untrusted-fetch" in p for p in problems), problems)

    def test_an_extra_rule_is_a_mismatch(self):
        # Exact set, not "at least": an extra rule firing is a false
        # positive, and a matrix that tolerates it measures nothing.
        problems = judge(alerts=[alert(R1), alert(R2), alert(R3)])
        self.assertTrue(any("metadata-endpoint" in p for p in problems), problems)

    def test_the_deny_only_baseline_is_asserted_too(self):
        self.assertTrue(judge(hardened=True, alerts=[alert(R1), alert(R2)]))   # baseline missing
        self.assertTrue(judge(alerts=[alert(R1), alert(R2)], baseline=[alert("deny-only")]))

    def test_an_alert_from_another_session_is_a_window_leak(self):
        problems = judge(alerts=[alert(R1), alert(R2), alert(R2, session="s-old")])
        self.assertTrue(any("s-old" in p for p in problems), problems)

    def test_an_empty_window_is_operational_not_a_miss(self):
        with self.assertRaises(rp.Operational):
            judge(grew={"agent.jsonl": 0, "gateway.jsonl": 0})

    def test_a_scenario_whose_call_never_happened_is_operational(self):
        # A false-positive row passes trivially if the call it exists to
        # test was never made: "the rule stayed silent" about a fetch
        # nobody attempted (T9 review). Same for an attack row -- it
        # would report "missed" about an attack that never ran.
        with self.assertRaises(rp.Operational):
            judge(calls=("read_document",), alerts=[])

    def test_the_wrong_writer_is_a_finding(self):
        # Hardened records in agent.jsonl mean the hardened binary
        # executed a tool itself (D5 broken); vulnerable records in
        # gateway.jsonl mean the planted bug is gone. Both are mismatches,
        # not operational: the run produced evidence, and it is wrong.
        problems = judge(hardened=True, grew={"agent.jsonl": 2, "gateway.jsonl": 2},
                         alerts=[alert(R1), alert(R2)], baseline=[alert("deny-only")])
        self.assertTrue(any("agent.jsonl" in p for p in problems), problems)
        problems = judge(grew={"agent.jsonl": 2, "gateway.jsonl": 1}, alerts=[alert(R1), alert(R2)])
        self.assertTrue(any("gateway.jsonl" in p for p in problems), problems)


class Scenarios(unittest.TestCase):
    def test_every_scenario_states_both_modes(self):
        for s in rp.SCENARIOS:
            with self.subTest(s=s.name):
                self.assertEqual(set(s.expect), {False, True})
                self.assertEqual(set(s.deny_only), {False, True})

    def test_every_scenario_names_the_calls_it_must_produce(self):
        for s in rp.SCENARIOS:
            with self.subTest(s=s.name):
                self.assertTrue(s.calls)

    def test_the_scenario_inputs_are_the_exploits_own(self):
        # Loaded from attacks/0*/exploit.py, not retyped: an exploit that
        # changes its URL changes the replay with it (T9 review).
        self.assertIn("metadata.google.internal", rp.EXPLOIT_04.TOKEN_URL)
        self.assertTrue(rp.EXPLOIT_03.POISONED_TITLE and rp.EXPLOIT_03.CLEAN_TITLE)

    def test_the_false_positive_rows_expect_silence(self):
        controls = [s for s in rp.SCENARIOS if not s.attack]
        self.assertGreaterEqual(len(controls), 2)
        for s in controls:
            self.assertEqual(s.expect, {False: set(), True: set()}, s.name)

    def test_every_attack_is_caught_in_both_modes(self):
        # The module's claim, as a property of the expectation table: the
        # input-reading rules fire on every attack whether or not the gate
        # stopped it. If an edit makes an attack row expect silence, the
        # claim changed and the README must say so.
        for s in rp.SCENARIOS:
            if s.attack:
                with self.subTest(s=s.name):
                    self.assertTrue(s.expect[False] and s.expect[True])


if __name__ == "__main__":
    unittest.main()
