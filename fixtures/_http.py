"""Shared server base for the fixtures. Stdlib only."""

from __future__ import annotations

import socketserver
from http.server import ThreadingHTTPServer


class FixtureServer(ThreadingHTTPServer):
    """ThreadingHTTPServer without the reverse-DNS lookup at bind.

    HTTPServer.server_bind calls socket.getfqdn(host) only to fill
    server_name, which no fixture uses. That lookup can stall for tens of
    seconds on a host with slow reverse DNS -- found as a 35-second first
    test on macOS -- and a hostile fixture should not depend on the
    resolver it is meant to be found through.
    """

    daemon_threads = True

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = host
        self.server_port = port


# The default redirect target, shared by both fixtures' /redirect: the
# fake SA token on the metadata host, by name (D6, T6 D4).
METADATA_TOKEN_URL = (
    "http://metadata.google.internal"
    "/computeMetadata/v1/instance/service-accounts/default/token")


def redirect_target(query: str) -> str:
    """The Location for a /redirect request: ?to=<url>, else the token.

    An open redirect, deliberately -- these are hostile fixtures, reached
    only inside Compose, and T7 chooses the chain.
    """
    from urllib.parse import parse_qs

    return parse_qs(query).get("to", [METADATA_TOKEN_URL])[0]


def serve(make_server, name: str):  # pragma: no cover
    """Entry point shared by both fixtures: listen on $PORT (default 80)."""
    import os
    import sys

    port = int(os.getenv("PORT", "80"))
    server = make_server("0.0.0.0", port)
    sys.stderr.write(f"{name}: listening on :{port} (HOSTILE FIXTURE)\n")
    server.serve_forever()
