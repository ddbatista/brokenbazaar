#!/usr/bin/env python3
"""Offline tests for the marketplace replay's judge (no stack).

judge_cell is the part that turns a measured window into a verdict;
these pin its failure taxonomy with fixture windows, the way
test_replay_agent pins the M2 judge's.

    python3 -m unittest discover -s detections -t detections -p 'test_replay_marketplace.py'
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import marketplace_rules as rules  # noqa: E402
import replay_marketplace as replay  # noqa: E402
from agentlab import Operational  # noqa: E402

POISON = replay.SCENARIOS[0]
TYPED = replay.SCENARIOS[1]
RUG = replay.SCENARIOS[2]
PATCH = replay.SCENARIOS[3]
REAPPROVED = replay.SCENARIOS[4]


def alert(rule, session="s-1", did="d-1"):
    return {"rule": rule, "session": session, "count": 1, "where": ["x"],
            "decision_ids": [did]}


def baseline_alert(session="s-1"):
    return alert("deny-only", session)


class JudgeCells(unittest.TestCase):
    def test_poison_cell_passes_with_d2_and_a_hardened_deny(self):
        problems = replay.judge_cell(POISON, True,
                                      {"gateway.jsonl": 4, "agent.jsonl": 0},
                                      {"read_document", "summarize_notes"},
                                      [alert(rules.D2)], [baseline_alert()], "s-1", False)
        self.assertEqual(problems, [])

    def test_a_missing_rule_is_a_miss_even_when_the_rest_fired(self):
        problems = replay.judge_cell(POISON, False,
                                      {"agent.jsonl": 4, "gateway.jsonl": 0},
                                      {"read_document", "summarize_notes"},
                                      [], [], "s-1", False)
        self.assertIn("missed: consent-mismatch did not fire", problems)

    def test_an_extra_rule_is_a_false_positive(self):
        # TYPED exists only in hardened mode (its channel is the gate's),
        # so its false-positive cell is judged there.
        problems = replay.judge_cell(TYPED, True,
                                     {"gateway.jsonl": 2, "agent.jsonl": 0},
                                     {"summarize_notes"},
                                     [alert(rules.D1)], [], "s-1", False)
        self.assertIn("false positive: first-seen-tool fired", problems)

    def test_the_wrong_writer_growing_is_a_problem(self):
        problems = replay.judge_cell(POISON, True,
                                     {"gateway.jsonl": 2, "agent.jsonl": 3},
                                     {"read_document", "summarize_notes"},
                                     [alert(rules.D2)], [baseline_alert()], "s-1", False)
        self.assertTrue(any("only gateway.jsonl should record" in p for p in problems))

    def test_a_window_leak_is_named(self):
        problems = replay.judge_cell(POISON, False,
                                     {"agent.jsonl": 4, "gateway.jsonl": 0},
                                     {"read_document", "summarize_notes"},
                                     [alert(rules.D2, session="other")], [], "s-1", False)
        self.assertTrue(any("window leak" in p for p in problems))

    def test_a_rug_pull_without_its_call_judges_nothing(self):
        with self.assertRaises(Operational):
            replay.judge_cell(RUG, False,
                              {"agent.jsonl": 2, "gateway.jsonl": 0},
                              {"read_document"},   # export_archive never happened
                              [], [], "s-1", False)

    def test_an_empty_window_judges_nothing(self):
        with self.assertRaises(Operational):
            replay.judge_cell(POISON, False,
                              {"agent.jsonl": 0, "gateway.jsonl": 0}, set(),
                              [], [], "s-1", False)

    def test_the_patch_cell_needs_no_agent_window_but_a_mutation(self):
        problems = replay.judge_cell(PATCH, True,
                                      {"gateway.jsonl": 0, "agent.jsonl": 0},
                                      set(), [alert(rules.D3, session="m-1")],
                                      [], "", True)
        self.assertEqual(problems, [])

    def test_the_patch_cell_without_a_mutation_judges_nothing(self):
        with self.assertRaises(Operational):
            replay.judge_cell(PATCH, True,
                              {"gateway.jsonl": 0, "agent.jsonl": 0},
                              set(), [], [], "", False)

    def test_the_reapproved_cell_fires_d2_not_d1(self):
        # Re-approval is respected for the re-pinned tool (no D1, no D2 on
        # export_archive) while the still-poisoned summarizer keeps firing
        # -- the expectation is {D2}, not silence.
        problems = replay.judge_cell(REAPPROVED, True,
                                     {"gateway.jsonl": 6, "agent.jsonl": 0},
                                     {"read_document", "summarize_notes", "export_archive"},
                                     [alert(rules.D2)], [baseline_alert()], "s-1", False)
        self.assertEqual(problems, [])


class ScenarioContract(unittest.TestCase):
    def test_every_scenario_covers_the_modes_it_exists_in(self):
        for s in replay.SCENARIOS:
            want = {True} if s.hardened_only else {False, True}
            self.assertEqual(set(s.expect), want, s.name)
            self.assertEqual(set(s.deny_only), {False, True}, s.name)

    def test_the_hardened_only_row_declares_why(self):
        typed = next(s for s in replay.SCENARIOS if s.hardened_only)
        self.assertEqual(typed.name, "07 typed control")

    def test_attack_rows_and_control_rows_both_exist(self):
        self.assertTrue(any(s.attack for s in replay.SCENARIOS))
        self.assertTrue(any(not s.attack for s in replay.SCENARIOS))


if __name__ == "__main__":
    unittest.main()
