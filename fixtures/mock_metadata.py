#!/usr/bin/env python3
"""mock-metadata -- a fake cloud metadata server. HOSTILE FIXTURE (M2, D6).

Makes finding 04 (SSRF -> service-account credentials, leaf B7 1.1)
reproducible with no cloud account and no external network. Reached
inside Compose as http://metadata.google.internal/ (extra_hosts against
a fixed container IP). GCP addresses its metadata server by that name as
well as by 169.254.169.254, so the hostname is the honest address; the
literal-IP spike is recorded as not run (T6 D4).

CONTRACT (T7 depends on it; settled in T6):

    GET /computeMetadata/v1/instance/service-accounts/default/token
        200 {"access_token": "...FAKE...", "expires_in", "token_type"}
    GET /computeMetadata/v1/instance/service-accounts/default/email
        200 the fake SA's email
    GET /redirect[?to=<url>]
        302 Location: <url>, default the token URL above -- the B7 1.2
        variant the plan names. Note its limit: the requested URL already
        names this host, so a string filter would catch it. The variant
        that defeats a string filter is the collector's /redirect
        (attacker.example -> here); T7 chooses which chain 04 drives.
    GET /
        200 a directory line (and the container healthcheck)

DECLARED DEPARTURE FROM REAL GCP: the real server refuses any request
without `Metadata-Flavor: Google`, which is a genuine SSRF mitigation --
a URL-only fetch primitive cannot set it. M2's http_fetch takes a URL
and nothing else, so this fixture omits the check and models an
endpoint without that guard (the IMDSv1 shape). It still SENDS the
header on responses, as GCP does. Pinned by
test_does_not_require_the_metadata_flavor_header so the departure is a
tested decision rather than an accident.

The credential is fake and says so. Stdlib only.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlsplit

from _http import FixtureServer, redirect_target, serve

TOKEN_PATH = "/computeMetadata/v1/instance/service-accounts/default/token"
EMAIL_PATH = "/computeMetadata/v1/instance/service-accounts/default/email"

FAKE_SA_EMAIL = "brokenbazaar-api@brokenbazaar-lab.iam.gserviceaccount.com"
FAKE_TOKEN = {
    "access_token": "ya29.FAKE-brokenbazaar-lab-token-NOT-A-CREDENTIAL",
    "expires_in": 3599,
    "token_type": "Bearer",
}


def make_server(host: str, port: int) -> FixtureServer:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format, *args):  # noqa: A002 - base class name
            sys.stderr.write("mock-metadata: " + (format % args) + "\n")

        def _send(self, status, body=b"", ctype="text/plain; charset=utf-8", extra=None):
            self.send_response(status)
            self.send_header("Metadata-Flavor", "Google")
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parts = urlsplit(self.path)
            if parts.path == TOKEN_PATH:
                self._send(200, json.dumps(FAKE_TOKEN).encode("utf-8"), "application/json")
            elif parts.path == EMAIL_PATH:
                self._send(200, FAKE_SA_EMAIL.encode("utf-8"))
            elif parts.path == "/redirect":
                target = redirect_target(parts.query)
                self._send(302, f"redirecting to {target}\n".encode("utf-8"),
                           extra={"Location": target})
            elif parts.path == "/":
                self._send(200, b"computeMetadata/\n")
            else:
                self._send(404, b"not found\n")

    return FixtureServer((host, port), Handler)


def main():  # pragma: no cover
    serve(make_server, "mock-metadata")


if __name__ == "__main__":  # pragma: no cover
    main()
