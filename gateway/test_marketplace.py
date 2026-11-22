"""The marketplace channel's gateway tests (M4a T5).

These assert the FACTS the gateway establishes -- never the final policy
reason. The reason-level assertions live in the policy zone
(policy_test.rego, human-applied with the legs themselves), so this file
stays green both before and after that amendment lands: under the
shipped policy an installed-tool call denies as unknown_tool, and that is
asserted where relevant as a stability fact, not as the finding's reason.

The drift check dials publishers, so every test here injects the fetch:
the facts under test are the gateway's SELECTION and COMPARISON logic,
not the fixture's uptime.
"""

from __future__ import annotations

import json
import unittest
from unittest import mock

import decide as decide_mod  # noqa: E402
import gate
from tools import mcp

# The house pattern (test_gate.py): end-to-end decisions need an OPA
# binary; the host suite skips, the image suite (make test-gateway-image)
# never does.
OPA = decide_mod.find_opa()
needs_policy = unittest.skipUnless(OPA, "needs an opa binary (the image suite runs it)")

PIN = ('{"jsonrpc":"2.0","id":1,"result":{"tools":['
       '{"name":"summarize_notes","description":"clean","receives":["user_text"]}'
       ']}]}')
PIN_DRIFTED = PIN.replace("clean", "now with an imperative")
LIVE_RUG_PULL = ('{"jsonrpc":"2.0","id":1,"result":{"tools":['
                 '{"name":"summarize_notes","description":"clean","receives":["user_text"]},'
                 '{"name":"export_archive","description":"wide","receives":["user_text"]}'
                 ']}}')


def install_fact(**over):
    fact = {
        "install_id": "11111111-2222-4333-8444-555555555555",
        "item_id": "99999999-9999-4999-8999-999999999999",
        "endpoint_url": "http://publisher.example/evil",
        "endpoint_address": "172.28.0.22",
        "pinned_digest": mcp_hash(PIN),
        "pinned_manifest": PIN,
        "tool_in_pin": True,
        "receives_document_content": False,
    }
    fact.update(over)
    return fact


def mcp_hash(raw: str) -> str:
    import hashlib
    return hashlib.sha256(raw.encode()).hexdigest()


PLATFORM = ("read_document", "http_fetch", "update_document",
            "delete_document", "set_member_role")


class MarketplaceFacts(unittest.TestCase):

    def authority(self, installs):
        return {"session": {"id": "s", "org": "o", "acting_for": "u"},
                "role_now": "member",
                "legs": {"within_time": True, "in_scope": True,
                         "role_permits": True},
                "installs": installs}

    def test_pinned_tool_with_matching_live_is_known_and_verified(self):
        with mock.patch.object(mcp, "fetch_manifest",
                               return_value=(PIN.encode(), "")):
            facts, rel = gate.marketplace_facts(
                "summarize_notes", self.authority([install_fact()]), PLATFORM)
        self.assertTrue(facts["tool_known"])
        self.assertTrue(facts["pin_verified"])
        self.assertEqual(rel["install_id"], "11111111-2222-4333-8444-555555555555")

    def test_unreachable_endpoint_reads_as_drift_never_as_verified(self):
        # M4a-N2's trap: the drift check that cannot fetch must report
        # the pin as NOT verified, never as "no drift".
        with mock.patch.object(mcp, "fetch_manifest", return_value=(None, "unreachable")):
            facts, rel = gate.marketplace_facts(
                "summarize_notes", self.authority([install_fact()]), PLATFORM)
        self.assertTrue(facts["tool_known"])       # the pin names it
        self.assertFalse(facts["pin_verified"])    # but nothing was verified
        self.assertIsNotNone(rel)

    def test_rug_pull_name_is_live_known_and_unverified(self):
        # The flipped manifest names a tool the pin does not: it is
        # known (the live manifest says so) and the pin is NOT verified
        # (the fetched bytes differ) -- the drift leg's exact shape.
        fact = install_fact(tool_in_pin=False,
                            pinned_digest=mcp_hash(PIN_DRIFTED))
        with mock.patch.object(mcp, "fetch_manifest",
                               return_value=(LIVE_RUG_PULL.encode(), "")):
            facts, _rel = gate.marketplace_facts(
                "export_archive", self.authority([fact]), PLATFORM)
        self.assertTrue(facts["tool_known"])
        self.assertFalse(facts["pin_verified"])

    def test_rewritten_description_is_known_and_drifted(self):
        # The poisoned rewrite: the tool is in both pin and live, but the
        # live bytes differ -- drift fires on the DIGEST, not the name.
        fact = install_fact(pinned_digest=mcp_hash(PIN))
        with mock.patch.object(mcp, "fetch_manifest",
                               return_value=(PIN_DRIFTED.encode(), "")):
            facts, _rel = gate.marketplace_facts(
                "summarize_notes", self.authority([fact]), PLATFORM)
        self.assertTrue(facts["tool_known"])
        self.assertFalse(facts["pin_verified"])

    def test_a_name_neither_pin_nor_live_knows_is_unknown(self):
        # The authority's tool_in_pin fact is computed FOR THE NAMED
        # TOOL (Go-side, per query) -- a name the pin does not name
        # arrives with tool_in_pin false.
        with mock.patch.object(mcp, "fetch_manifest",
                               return_value=(PIN.encode(), "")):
            facts, rel = gate.marketplace_facts(
                "no_such_tool",
                self.authority([install_fact(tool_in_pin=False)]), PLATFORM)
        self.assertFalse(facts["tool_known"])
        self.assertFalse(facts["pin_verified"])
        self.assertIsNone(rel)

    def test_garbage_live_manifest_still_verifies_nothing(self):
        with mock.patch.object(mcp, "fetch_manifest", return_value=(b"not json", "")):
            facts, rel = gate.marketplace_facts(
                "summarize_notes", self.authority([install_fact()]), PLATFORM)
        # The pin names the tool, so it is known; the live side is
        # garbage, so nothing about the pin was verified.
        self.assertTrue(facts["tool_known"])
        self.assertFalse(facts["pin_verified"])

    def test_platform_tools_and_empty_installs_have_no_marketplace_facts(self):
        self.assertEqual(gate.marketplace_facts(
            "http_fetch", self.authority([install_fact()]), PLATFORM), ({}, None))
        self.assertEqual(gate.marketplace_facts(
            "summarize_notes", self.authority([]), PLATFORM), ({}, None))


class HandleGateInstalls(unittest.TestCase):
    """The end-to-end wiring: facts reach the policy input and the record."""

    def setUp(self):
        import tempfile
        import pathlib
        import audit as audit_mod
        import redact as redact_mod
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = pathlib.Path(self.tmp.name)
        self.cfg = gate.Config(
            policy_dir=gate.DEFAULT_POLICY_DIR,
            policy_data={"tools": list(PLATFORM), "org_grants": {},
                         "egress_allowlist": []},
            schema=redact_mod.Schema.load(
                gate.DEFAULT_POLICY_DIR / "redact.json"),
            audit=audit_mod.Audit.open(
                self.tmp_path / "gateway.jsonl",
                redact_mod.Schema.load(gate.DEFAULT_POLICY_DIR / "redact.json")),
            api_base="http://api:8080",
            tools_secret="s", hardened=True,
            authority_lookup=lambda session_id, tool: (
                {"session": {"id": session_id, "org": "0a000000-0000-4000-8000-000000000001",
                             "acting_for": "u"},
                 "role_now": "member",
                 "legs": {"within_time": True, "in_scope": True,
                          "role_permits": True},
                 "installs": [install_fact()]}, ""))

    def tearDown(self):
        self.tmp.cleanup()

    def call(self, tool, args=None, derived=None):
        payload = {"tool": tool, "args": args or {},
                   "session": {"id": "s1"},
                   "provenance": {"derived_from": derived or []}}
        return gate.handle_gate(self.cfg, payload)

    @needs_policy
    def test_installed_tool_call_allowed_by_the_applied_policy_with_facts_recorded(self):
        # The issue-#30 amendment is APPLIED, and this is the flip the
        # old version of this test predicted in its own comment: a
        # pinned, verified, user_text-declared installed tool, called
        # with the user's own bytes, is ALLOWED by the applied policy,
        # with the facts the legs decided on recorded on the attempt.
        # The deny-side reasons (consent, drift) are asserted in the
        # policy zone (41/41), not here -- this is the positive case
        # that proves the widened legs did not just forbid the channel.
        with mock.patch.object(mcp, "fetch_manifest",
                               return_value=(PIN.encode(), "")), \
             mock.patch.object(mcp, "call_tool",
                               return_value=mcp.MCPResult(allowed=True, reason="200",
                                                          text="Processed.")):
            status, body = self.call("summarize_notes", {"query": "x"})
        self.assertEqual(status, 200)
        self.assertEqual(body["route"], "allow")
        pre = [json.loads(line) for line in
               (self.tmp_path / "gateway.jsonl").read_text().splitlines()
               if line.strip()][0]
        self.assertEqual(pre["tool"], "summarize_notes")
        self.assertTrue(pre["resolved"].get("tool_known"))
        self.assertTrue(pre["resolved"].get("pin_verified"))
        self.assertTrue(pre["resolved"].get("manifest_fetched"))
        self.assertTrue(pre["authority"]["install"]["tool_in_pin"])
        self.assertFalse(pre["authority"]["install"]["receives_document_content"])
        self.assertEqual(pre["reasons"], ["policy_satisfied"])


class MCPModule(unittest.TestCase):
    """The dial-level rules: pinned addresses, envelopes, digests."""

    def test_rebinding_is_refused_before_any_dial(self):
        # The install recorded .22; the host answering .99 today is a
        # rebind, refused with its own reason (SR-B6-4).
        with mock.patch.object(mcp.fetch, "default_resolve", return_value="172.28.0.99"):
            endpoint, why = mcp.endpoint_for(install_fact())
        self.assertIsNone(endpoint)
        self.assertIn("rebinding", why)

    def test_denied_range_is_refused_at_dial_time(self):
        # The metadata space is refused even though an install row could
        # name it: the row is consent, not a range classification. A
        # listing pointed at metadata.google.internal never dials.
        fact = install_fact(endpoint_address="169.254.169.254")
        with mock.patch.object(mcp.fetch, "default_resolve",
                               return_value="169.254.169.254"):
            endpoint, why = mcp.endpoint_for(fact)
        self.assertIsNone(endpoint)
        self.assertIn("denied range", why)

    def test_a_matching_resolution_is_dialled_at_the_pinned_address(self):
        with mock.patch.object(mcp.fetch, "default_resolve", return_value="172.28.0.22"):
            endpoint, why = mcp.endpoint_for(install_fact())
        self.assertIsNotNone(endpoint)
        self.assertEqual(endpoint.ip, "172.28.0.22")
        self.assertEqual(endpoint.path, "/evil")

    def test_manifest_tool_names_reads_the_envelope_and_garbage_reads_empty(self):
        self.assertEqual(mcp.manifest_tool_names(LIVE_RUG_PULL.encode()),
                         ["summarize_notes", "export_archive"])
        self.assertEqual(mcp.manifest_tool_names(b"not json"), [])
        self.assertEqual(mcp.manifest_tool_names(b'{"jsonrpc":"2.0"}'), [])

    def test_digest_matches_the_exact_fetched_bytes(self):
        fact = install_fact(pinned_digest=mcp_hash(PIN))
        self.assertTrue(mcp.digest_matches(fact, PIN.encode()))
        self.assertFalse(mcp.digest_matches(fact, PIN_DRIFTED.encode()))

    def test_call_tool_parses_the_enveloped_answer(self):
        answer = b'{"jsonrpc":"2.0","id":1,"result":{"content":"Processed."}}'
        with mock.patch.object(mcp, "_dial",
                               return_value=mcp.MCPResult(allowed=True, reason="200",
                                                           body=answer)), \
             mock.patch.object(mcp.fetch, "default_resolve",
                               return_value="172.28.0.22"):
            res = mcp.call_tool(install_fact(), "summarize_notes", {"query": "x"})
        self.assertTrue(res.allowed)
        self.assertEqual(res.text, "Processed.")

    def test_call_tool_names_rebinding_as_operational_failure(self):
        with mock.patch.object(mcp.fetch, "default_resolve", return_value="172.28.0.99"):
            res = mcp.call_tool(install_fact(), "summarize_notes", {"query": "x"})
        self.assertFalse(res.allowed)
        self.assertIn("rebinding", res.reason)


if __name__ == "__main__":
    unittest.main()
