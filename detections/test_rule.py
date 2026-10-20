"""Unit tests for the SR-B2-8 denial-burst rule (detections/rule.py).

Stdlib only (unittest) -- the repo's no-pip rule applies to detections/
the same as attacks/. Run from the repo root:

    python3 detections/test_rule.py

The rule's contract under test:
  - alerts when ONE principal accumulates >= threshold authz-denial events
  - silent below threshold (a fat-fingered request is noise; a scan is not)
  - counts per principal -- two principals below threshold never sum to an alert
  - ignores every non-deny line (boot banners, WARN fallbacks, query errors)
  - carries evidence: sub, count, distinct target orgs, a sample line
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rule import DEFAULT_THRESHOLD, find_alerts  # noqa: E402

# The exact wire format resolveHardenedStore emits (app/api/documents.go):
#   2026/10/20 03:20:47 authz: deny sub=<uuid> target_org=<uuid> decision=not-a-member
DENY_TMPL = (
    "2026/10/20 03:20:47 authz: deny sub=%s target_org=%s decision=not-a-member"
)

SUB = "b31f518e-0000-0000-0000-00000000aa01"
SUB2 = "b31f518e-0000-0000-0000-00000000aa02"
ORG = "e0bc2aff-0000-0000-0000-00000000bb01"
ORG2 = "e0bc2aff-0000-0000-0000-00000000bb02"


def deny(sub=SUB, org=ORG):
    return DENY_TMPL % (sub, org)


class ThresholdTests(unittest.TestCase):
    def test_alerts_at_exactly_threshold(self):
        alerts = find_alerts([deny() for _ in range(DEFAULT_THRESHOLD)])
        self.assertEqual(len(alerts), 1)
        a = alerts[0]
        self.assertEqual(a["sub"], SUB)
        self.assertEqual(a["count"], DEFAULT_THRESHOLD)

    def test_silent_below_threshold(self):
        self.assertEqual(find_alerts([deny() for _ in range(DEFAULT_THRESHOLD - 1)]), [])

    def test_threshold_override(self):
        self.assertEqual(len(find_alerts([deny(), deny()], threshold=2)), 1)

    def test_one_over_threshold_still_one_alert(self):
        alerts = find_alerts([deny() for _ in range(DEFAULT_THRESHOLD + 25)])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["count"], DEFAULT_THRESHOLD + 25)


class GroupingTests(unittest.TestCase):
    def test_two_principals_below_threshold_do_not_sum(self):
        lines = [deny() for _ in range(DEFAULT_THRESHOLD - 1)]
        lines += [deny(sub=SUB2) for _ in range(DEFAULT_THRESHOLD - 1)]
        self.assertEqual(find_alerts(lines), [])

    def test_each_bursting_principal_alerts_separately(self):
        lines = [deny() for _ in range(DEFAULT_THRESHOLD)]
        lines += [deny(sub=SUB2) for _ in range(DEFAULT_THRESHOLD)]
        alerts = find_alerts(lines)
        self.assertEqual(sorted(a["sub"] for a in alerts), sorted([SUB, SUB2]))


class NoiseTests(unittest.TestCase):
    NOISE = [
        "2026/10/20 03:20:47 WARN: JWT_SECRET is not set; falling back to the committed "
        '"dev-secret" secret (M1-N1, SR-M1-1)',
        "2026/10/20 03:20:48 brokenbazaar api listening on :8080 (HARDENED=true)",
        "2026/10/20 03:20:49 api: looking up \"admin@globex.example\": some pg error",
    ]

    def test_noise_never_alerts(self):
        self.assertEqual(find_alerts(self.NOISE), [])

    def test_noise_does_not_inflate_a_count(self):
        # 4 real denials + any amount of noise is still below threshold 5.
        self.assertEqual(find_alerts(self.NOISE + [deny() for _ in range(4)]), [])


class EvidenceTests(unittest.TestCase):
    def test_alert_lists_distinct_target_orgs(self):
        lines = [deny() for _ in range(3)] + [deny(org=ORG2) for _ in range(3)]
        alerts = find_alerts(lines)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["target_orgs"], sorted([ORG, ORG2]))

    def test_alert_carries_a_sample_line(self):
        lines = [deny() for _ in range(DEFAULT_THRESHOLD)]
        alerts = find_alerts(lines)
        self.assertIn("authz: deny", alerts[0]["sample"])
        self.assertIn(SUB, alerts[0]["sample"])

    def test_alert_names_the_rule_and_threshold(self):
        alerts = find_alerts([deny() for _ in range(DEFAULT_THRESHOLD)])
        self.assertEqual(alerts[0]["rule"], "deny-burst>=%d" % DEFAULT_THRESHOLD)


if __name__ == "__main__":
    unittest.main(verbosity=2)
