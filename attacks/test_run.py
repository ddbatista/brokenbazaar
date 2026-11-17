"""Tests for run.py's verdict (plan M3 T8 D1): stdout_contains may be a list.

    python3 -m unittest discover -s attacks -t attacks -p 'test_*.py'

A finding with variants (05 (i)/(ii); 03 and its least-privilege variant)
prints one marker per variant. Every marker of THIS mode must appear, and no
marker of the OTHER mode may -- otherwise a run where one variant held and
the other leaked could pass on the variant that behaved.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import run  # noqa: E402

ONE = {"vulnerable": {"exit_code": 0, "stdout_contains": "LEAKED"},
       "hardened": {"exit_code": 1, "stdout_contains": "gateway denied: x"}}
TWO = {"vulnerable": {"exit_code": 0, "stdout_contains": ["(i) LEAKED", "(ii) LEAKED"]},
       "hardened": {"exit_code": 1, "stdout_contains": ["(i) gateway denied: x", "(ii) gateway denied: x"]}}


class Judge(unittest.TestCase):

    def test_a_single_marker_still_works(self):
        self.assertEqual(run.judge(ONE, "hardened", 1, "... gateway denied: x"), [])
        self.assertTrue(run.judge(ONE, "hardened", 1, "nothing"))

    def test_every_marker_of_this_mode_must_appear(self):
        self.assertEqual(run.judge(TWO, "hardened", 1, "(i) gateway denied: x\n(ii) gateway denied: x"), [])
        problems = run.judge(TWO, "hardened", 1, "(i) gateway denied: x")
        self.assertEqual(len(problems), 1)
        self.assertIn("(ii) gateway denied: x", problems[0])

    def test_no_marker_of_the_other_mode_may_appear(self):
        # One variant held, the other leaked: a hardened run must fail on
        # the leak even though its own markers are all present.
        out = "(i) gateway denied: x\n(ii) gateway denied: x\n(ii) LEAKED"
        problems = run.judge(TWO, "hardened", 1, out)
        self.assertEqual(len(problems), 1)
        self.assertIn("OTHER mode", problems[0])

    def test_the_exit_code_is_still_asserted(self):
        problems = run.judge(TWO, "vulnerable", 2, "(i) LEAKED\n(ii) LEAKED")
        self.assertEqual(len(problems), 1)
        self.assertIn("operational", problems[0])

    def test_an_empty_marker_list_is_refused(self):
        # An empty list would assert nothing: every run would pass it.
        empty = {"vulnerable": {"exit_code": 0, "stdout_contains": []}, "hardened": ONE["hardened"]}
        self.assertTrue(run.judge(empty, "vulnerable", 0, "anything"))
        blank = {"vulnerable": {"exit_code": 0, "stdout_contains": ""}, "hardened": ONE["hardened"]}
        self.assertTrue(run.judge(blank, "vulnerable", 0, "anything"))


class EveryExpectedJson(unittest.TestCase):

    def test_every_finding_declares_usable_markers(self):
        for d in run.findings():
            with self.subTest(d.name):
                import json
                expected = json.loads((d / "expected.json").read_text())
                for mode in ("vulnerable", "hardened"):
                    self.assertTrue(run.markers(expected[mode]["stdout_contains"]), f"{d.name} {mode}")


if __name__ == "__main__":
    unittest.main()
