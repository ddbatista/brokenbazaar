"""Tests for the hardened tool implementations.

stdlib unittest, no network, no database. Run with:

    python3 -m unittest discover -s gateway/tools -t gateway -v

The important tests here are not the happy paths. They are the ones that
distinguish a correct implementation from the buggy one that behaves
IDENTICALLY whenever DNS is honest -- which is why every seam is
injected. A test against a real server cannot express "the attacker
changed the answer between the check and the connection," so it would
pass against both.
"""

from __future__ import annotations

import unittest

from tools import documents, fetch

ALLOWLIST = frozenset({"docs.example", "metadata.google.internal"})
PUBLIC_IP = "93.184.216.34"
METADATA_IP = "169.254.169.254"


class RecordingResolver:
    """Counts lookups and can change its answer between them."""

    def __init__(self, *answers: str):
        self.answers = list(answers)
        self.calls: list[str] = []

    def __call__(self, host: str) -> str:
        self.calls.append(host)
        idx = min(len(self.calls) - 1, len(self.answers) - 1)
        return self.answers[idx]


class RecordingDialer:
    """Records what was actually dialed, and replays scripted responses."""

    def __init__(self, *responses: fetch.DialResponse):
        self.responses = list(responses)
        self.targets: list[tuple[str, int]] = []
        self.headers: list[dict[str, str]] = []
        self.paths: list[str] = []

    def __call__(self, ip, port, method, path, headers, timeout=5.0):
        self.targets.append((ip, port))
        self.headers.append(dict(headers))
        self.paths.append(path)
        idx = min(len(self.targets) - 1, len(self.responses) - 1)
        return self.responses[idx]


def ok(body: str = "hello") -> fetch.DialResponse:
    return fetch.DialResponse(status=200, headers={}, body=body)


def redirect(location: str, status: int = 302) -> fetch.DialResponse:
    return fetch.DialResponse(status=status, headers={"location": location}, body="")


class ResolvedValueIsWhatExecutes(unittest.TestCase):
    """SR-B5-3, the sharpest control in M2."""

    def test_resolver_is_called_exactly_once_per_hop(self):
        # THE assertion. The buggy implementation resolves twice -- once
        # to decide and once inside create_connection -- so this count
        # is the difference between the two, expressed as a number.
        resolver = RecordingResolver(PUBLIC_IP)
        dialer = RecordingDialer(ok())

        fetch.fetch("http://docs.example/a", allowlist=ALLOWLIST,
                    resolve=resolver, dial=dialer)

        self.assertEqual(len(resolver.calls), 1, "the decision and the dial must share one lookup")

    def test_dials_the_validated_ip_not_the_hostname(self):
        resolver = RecordingResolver(PUBLIC_IP)
        dialer = RecordingDialer(ok())

        fetch.fetch("http://docs.example/a", allowlist=ALLOWLIST,
                    resolve=resolver, dial=dialer)

        self.assertEqual(dialer.targets[0], (PUBLIC_IP, 80))
        # The hostname still travels, so name-based virtual hosting works.
        self.assertEqual(dialer.headers[0]["Host"], "docs.example")

    def test_dns_rebinding_cannot_land(self):
        """Leaf B7 1.2: public on the first answer, link-local on the second.

        Under the buggy implementation the second answer is the one
        dialed and the metadata service is reached. Here the second
        answer is never requested, so there is nothing to win.
        """
        resolver = RecordingResolver(PUBLIC_IP, METADATA_IP)
        dialer = RecordingDialer(ok("should have been the real site"))

        result = fetch.fetch("http://docs.example/a", allowlist=ALLOWLIST,
                             resolve=resolver, dial=dialer)

        self.assertTrue(result.allowed)
        self.assertEqual(len(resolver.calls), 1)
        self.assertEqual(dialer.targets[0][0], PUBLIC_IP)
        self.assertNotIn(METADATA_IP, [t[0] for t in dialer.targets])


class EvaluationOrder(unittest.TestCase):
    """D6: allowlist first, then range, so each finding gets its own reason."""

    def test_unallowlisted_host_denied_for_the_right_reason(self):
        # Finding 03's destination. It sits on a Compose bridge network
        # in RFC1918 space, so a range-first gate would deny it as
        # "private address" -- true, but the wrong reason and an
        # artifact of the lab.
        resolver = RecordingResolver("172.20.0.9")
        result = fetch.fetch("http://attacker.example/collect?data=x",
                             allowlist=ALLOWLIST, resolve=resolver,
                             dial=RecordingDialer(ok()))

        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, fetch.EGRESS_NOT_ALLOWLISTED)

    def test_allowlisted_host_resolving_into_a_denied_range(self):
        # Finding 04's shape: the allowlist passes and the RANGE check is
        # what fires, which is the job SR-B7-1 was written for.
        resolver = RecordingResolver(METADATA_IP)
        result = fetch.fetch("http://metadata.google.internal/computeMetadata/v1/",
                             allowlist=ALLOWLIST, resolve=resolver,
                             dial=RecordingDialer(ok()))

        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, fetch.RESOLVED_ADDRESS_DENIED)

    def test_nothing_is_dialed_when_the_decision_denies(self):
        dialer = RecordingDialer(ok())
        fetch.fetch("http://attacker.example/x", allowlist=ALLOWLIST,
                    resolve=RecordingResolver(PUBLIC_IP), dial=dialer)
        self.assertEqual(dialer.targets, [], "a denied request must not reach the network")


class RangeChecking(unittest.TestCase):
    """SR-B7-1: by range, never by string match."""

    def test_encodings_of_the_metadata_address_all_collapse(self):
        # A string denylist catches the first of these and misses the
        # rest. ipaddress parses them all to the same address.
        for form in ("169.254.169.254", "::ffff:169.254.169.254"):
            with self.subTest(form=form):
                self.assertTrue(fetch.is_denied_range(form))

    def test_private_loopback_and_link_local_are_denied(self):
        for ip in ("10.0.0.1", "172.20.0.9", "192.168.1.1", "127.0.0.1",
                   "169.254.169.254", "0.0.0.0", "::1"):
            with self.subTest(ip=ip):
                self.assertTrue(fetch.is_denied_range(ip))

    def test_public_addresses_are_permitted(self):
        for ip in ("93.184.216.34", "8.8.8.8", "2606:2800:220:1:248:1893:25c8:1946"):
            with self.subTest(ip=ip):
                self.assertFalse(fetch.is_denied_range(ip))


class Redirects(unittest.TestCase):
    """SR-B7-1: re-evaluated on EVERY hop."""

    def test_each_hop_is_resolved_and_evaluated_again(self):
        resolver = RecordingResolver(PUBLIC_IP)
        dialer = RecordingDialer(redirect("http://docs.example/b"), ok("final"))

        result = fetch.fetch("http://docs.example/a", allowlist=ALLOWLIST,
                             resolve=resolver, dial=dialer)

        self.assertTrue(result.allowed)
        self.assertEqual(len(resolver.calls), 2, "one lookup per hop, no more and no fewer")
        self.assertEqual(len(result.hops), 2)

    def test_a_redirect_to_a_forbidden_host_is_denied(self):
        """The whole point: hop 1 is approved, hop 2 is not.

        A fetcher that followed redirects automatically would execute
        this second request having evaluated only the first -- which is
        SR-B7-1's failure delivered by a library default.
        """
        resolver = RecordingResolver(PUBLIC_IP)
        dialer = RecordingDialer(redirect("http://attacker.example/collect"), ok("leaked"))

        result = fetch.fetch("http://docs.example/a", allowlist=ALLOWLIST,
                             resolve=resolver, dial=dialer)

        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, fetch.EGRESS_NOT_ALLOWLISTED)
        self.assertEqual(len(dialer.targets), 1, "the second hop must never be dialed")

    def test_a_redirect_into_a_denied_range_is_denied(self):
        resolver = RecordingResolver(PUBLIC_IP, METADATA_IP)
        dialer = RecordingDialer(redirect("http://metadata.google.internal/"), ok("creds"))

        result = fetch.fetch("http://docs.example/a", allowlist=ALLOWLIST,
                             resolve=resolver, dial=dialer)

        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, fetch.RESOLVED_ADDRESS_DENIED)
        self.assertEqual(len(dialer.targets), 1)

    def test_redirect_loops_terminate(self):
        resolver = RecordingResolver(PUBLIC_IP)
        dialer = RecordingDialer(redirect("http://docs.example/a"))

        result = fetch.fetch("http://docs.example/a", allowlist=ALLOWLIST,
                             resolve=resolver, dial=dialer, max_redirects=2)

        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, fetch.TOO_MANY_REDIRECTS)


class Schemes(unittest.TestCase):
    def test_https_is_refused_rather_than_mishandled(self):
        # Declared limitation: dialing an IP over TLS breaks SNI and
        # hostname verification unless server_hostname is set. Refusing
        # is honest; silently dialing would be a second bug.
        result = fetch.fetch("https://docs.example/a", allowlist=ALLOWLIST,
                             resolve=RecordingResolver(PUBLIC_IP),
                             dial=RecordingDialer(ok()))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, fetch.SCHEME_NOT_SUPPORTED)


class ReadDocument(unittest.TestCase):
    """D5b: mediation is the secret, enforced at the auth layer."""

    def test_the_service_secret_is_sent(self):
        seen = {}

        def fake(api_base, path, headers, timeout):
            seen["path"] = path
            seen["headers"] = headers
            return 200, '{"id":"d1","title":"t","body":"b"}'

        result = documents.read_document("d1", "acme", api_base="http://api:8080",
                                         tools_secret="s3cret", request=fake)

        self.assertTrue(result.allowed)
        self.assertEqual(seen["headers"]["Authorization"], "Bearer s3cret")
        self.assertIn("id=d1", seen["path"])
        self.assertIn("org=acme", seen["path"])

    def test_a_missing_secret_fails_before_any_request(self):
        called = False

        def fake(*_args, **_kwargs):
            nonlocal called
            called = True
            return 200, "{}"

        result = documents.read_document("d1", "acme", api_base="http://api:8080",
                                         tools_secret="", request=fake)

        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, documents.TOOLS_SECRET_MISSING)
        self.assertFalse(called, "no request may be issued without a credential")

    def test_a_refused_credential_is_reported_as_a_refusal(self):
        # Not as an empty document. A gateway that reported 401 as
        # "document not found" would make a broken deployment look like
        # a missing row.
        result = documents.read_document("d1", "acme", api_base="http://api:8080",
                                         tools_secret="wrong",
                                         request=lambda *a, **k: (401, ""))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, documents.INTERNAL_ROUTE_REFUSED)

    def test_wrong_org_and_missing_document_are_indistinguishable(self):
        # SR-M1-4 one layer up: OrgStore.Get cannot tell them apart, so
        # neither can this, and the reason string says so.
        result = documents.read_document("d1", "globex", api_base="http://api:8080",
                                         tools_secret="s3cret",
                                         request=lambda *a, **k: (404, ""))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, documents.DOCUMENT_NOT_FOUND)


if __name__ == "__main__":
    unittest.main()
