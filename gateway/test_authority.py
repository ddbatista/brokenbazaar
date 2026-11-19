"""Tests for the gate's authority enrichment (plan M3 T6 D3).

    python3 -m unittest discover -s gateway -t gateway -p 'test_*.py' -v

stdlib unittest, no network: the API call goes through an injected request
seam, the same pattern as tools/documents.py.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import authority as authority_mod  # noqa: E402

GOOD = {
    "session": {"id": "s-1", "org": "o-1", "acting_for": "u-1"},
    "tool": "delete_document",
    "role_now": "viewer",
    "legs": {"within_time": True, "in_scope": True, "role_permits": False},
    # M4a T5: every answer now carries the org's install facts; an empty
    # array is a complete answer (the org has no installs).
    "installs": [],
}


def answering(status, body):
    seen = {}

    def fake(api_base, method, path, headers, data, timeout):
        seen.update(method=method, path=path, headers=headers)
        return status, body if isinstance(body, str) else json.dumps(body)
    return fake, seen


def lookup(fake, session_id="s-1", tool="delete_document", secret="s3cret"):
    return authority_mod.lookup(session_id, tool, api_base="http://api:8080",
                                tools_secret=secret, request=fake)


class Lookup(unittest.TestCase):

    def test_asks_the_authority_route_for_this_session_and_tool(self):
        fake, seen = answering(200, GOOD)
        got, err = lookup(fake)
        self.assertEqual(err, "")
        self.assertEqual(seen["method"], "GET")
        self.assertEqual(seen["path"], "/internal/sessions/s-1/authority?tool=delete_document")
        self.assertEqual(seen["headers"]["Authorization"], "Bearer s3cret")
        # The ROW's session, the role now, every leg -- as the policy will
        # see them.
        self.assertEqual(got, {
            "session": {"id": "s-1", "org": "o-1", "acting_for": "u-1"},
            "role_now": "viewer",
            "legs": {"within_time": True, "in_scope": True, "role_permits": False},
            "installs": [],
        })

    def test_a_denying_leg_is_a_fact_not_an_error(self):
        # role_permits false is the authority route working: the POLICY
        # turns it into role_does_not_permit. Enrichment must not.
        fake, _ = answering(200, GOOD)
        got, err = lookup(fake)
        self.assertEqual(err, "")
        self.assertIs(got["legs"]["role_permits"], False)

    def test_every_failure_is_an_error_never_a_partial_answer(self):
        # Each of these must deny as enrichment_failed (fail closed, M2's
        # path). A partial answer passed on could leave a leg undefined, and
        # an undefined input must never read as permission (M2 T5).
        legs_missing_one = dict(GOOD, legs={"within_time": True, "in_scope": True})
        legs_not_bool = dict(GOOD, legs={"within_time": "true", "in_scope": True, "role_permits": True})
        other_session = dict(GOOD, session={"id": "s-2", "org": "o-1", "acting_for": "u-1"})
        no_org = dict(GOOD, session={"id": "s-1", "org": "", "acting_for": "u-1"})
        cases = {
            "unknown session (404)": answering(404, '{"error":"no such session"}')[0],
            "credential refused (401)": answering(401, "")[0],
            "server error (500)": answering(500, "")[0],
            "not json": answering(200, "nope")[0],
            "a leg missing": answering(200, legs_missing_one)[0],
            "a leg not boolean": answering(200, legs_not_bool)[0],
            "another session's answer": answering(200, other_session)[0],
            "no org": answering(200, no_org)[0],
        }
        for name, fake in cases.items():
            with self.subTest(name):
                got, err = lookup(fake)
                self.assertIsNone(got)
                self.assertNotEqual(err, "")

    def test_unreachable_is_an_error(self):
        def down(*_a, **_k):
            raise ConnectionRefusedError("refused")
        got, err = lookup(down)
        self.assertIsNone(got)
        self.assertIn("refused", err)

    def test_no_request_without_a_session_id_or_a_secret(self):
        called = []
        fake = lambda *a, **k: called.append(a) or (200, json.dumps(GOOD))  # noqa: E731
        for sid, secret in (("", "s3cret"), ("s-1", "")):
            got, err = lookup(fake, session_id=sid, secret=secret)
            self.assertIsNone(got)
            self.assertNotEqual(err, "")
        self.assertEqual(called, [])

    def test_the_session_id_is_path_escaped(self):
        fake, seen = answering(404, "")
        lookup(fake, session_id="s-1/../../tools/delete_document?x=")
        self.assertNotIn("/../", seen["path"])
        self.assertTrue(seen["path"].startswith("/internal/sessions/"))

    def test_install_facts_are_carried_through_cleaned(self):
        # M4a T5: a well-formed installs array is passed on with exactly
        # the decided fields -- nothing more, nothing the policy did not
        # establish.
        install = {
            "install_id": "11111111-2222-4333-8444-555555555555",
            "item_id": "99999999-9999-4999-8999-999999999999",
            "endpoint_url": "http://publisher.example/evil",
            "endpoint_address": "172.28.0.22",
            "pinned_digest": "0f" * 32,
            "pinned_manifest": '{"jsonrpc":"2.0"}',
            "tool_in_pin": True,
            "receives_document_content": False,
        }
        fake, _ = answering(200, dict(GOOD, installs=[install]))
        got, err = lookup(fake, tool="summarize_notes")
        self.assertEqual(err, "")
        self.assertEqual(got["installs"], [install])

    def test_malformed_install_facts_fail_the_whole_answer(self):
        # A partial answer is never passed on: an install fact that lacks
        # a field, or carries the wrong type, makes the entire lookup an
        # enrichment error (a stale API image that omits the field fails
        # closed here rather than deciding on facts it did not
        # establish).
        bad = {
            "install_id": "11111111-2222-4333-8444-555555555555",
            "item_id": "99999999-9999-4999-8999-999999999999",
            "endpoint_url": "http://publisher.example/evil",
            "endpoint_address": "172.28.0.22",
            "pinned_digest": "0f" * 32,
            "pinned_manifest": '{"jsonrpc":"2.0"}',
            "tool_in_pin": True,
            # receives_document_content missing
        }
        cases = {
            "a fact missing a boolean": dict(GOOD, installs=[bad]),
            "a fact not an object": dict(GOOD, installs=["nope"]),
            "installs not an array": dict(GOOD, installs="nope"),
            "installs absent": {k: v for k, v in GOOD.items() if k != "installs"},
        }
        for name, body in cases.items():
            with self.subTest(name):
                fake, _ = answering(200, body)
                got, err = lookup(fake, tool="summarize_notes")
                self.assertIsNone(got)
                self.assertNotEqual(err, "")


if __name__ == "__main__":
    unittest.main()
