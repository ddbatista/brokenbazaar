#!/usr/bin/env python3
"""collector -- the attacker's exfiltration sink. HOSTILE FIXTURE (M2, D6).

Reached inside Compose as http://attacker.example/ (extra_hosts against
a fixed container IP), so finding 03's writeup reads as what it is: a
tenant's document arriving at a stranger's server.

CONTRACT (T7 depends on it; settled in T6):

    <any method> <any path>   recorded, and the response echoes the
                              request line -- the agent's tool result
                              then shows what it sent, too
    GET    /redirect[?to=<url>]
                              recorded, then 302 to <url> (default: the
                              metadata token URL). The attacker's
                              redirector for finding 04's B7 1.2 variant:
                              the requested URL names no metadata host,
                              so only per-hop re-evaluation (SR-B7-1)
                              stops it -- a string filter does not
    GET    /received          {"received": [record, ...]}  oldest first
    DELETE /received          clears the record; 204

A record is {method, path, query, params, body, host}. `query` is the raw
string as it arrived; `params` is it decoded, so the PoC can assert on
the tenant's bytes as they appear in the document. /received is never
itself recorded. At most MAX_RECORDS are kept, oldest dropped first.

Finding 03's evidence IS "the attacker received these bytes" (§7) --
this server's record, not a status code the agent saw.

Stdlib only. Localhost only: the host port is bound to 127.0.0.1.
"""

from __future__ import annotations

import json
import sys
import threading
from collections import deque
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlsplit

from _http import FixtureServer, redirect_target, serve

MAX_RECORDS = 1000
REDIRECT_PATH = "/redirect"
MAX_BODY = 64 * 1024


class _Store:
    def __init__(self, max_records):
        self._lock = threading.Lock()
        self._records = deque(maxlen=max_records)

    def add(self, record):
        with self._lock:
            self._records.append(record)

    def snapshot(self):
        with self._lock:
            return list(self._records)

    def clear(self):
        with self._lock:
            self._records.clear()


def make_server(host: str, port: int, max_records: int = MAX_RECORDS) -> FixtureServer:
    store = _Store(max_records)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format, *args):  # noqa: A002 - base class name
            sys.stderr.write("collector: " + (format % args) + "\n")

        def _send(self, status, body=b"", ctype="text/plain; charset=utf-8", extra=None):
            self.send_response(status)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            if status != 204:
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body and status != 204:
                self.wfile.write(body)

        def _read_body(self) -> str:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            raw = self.rfile.read(min(length, MAX_BODY)) if length > 0 else b""
            return raw.decode("utf-8", errors="replace")

        def _handle(self):
            parts = urlsplit(self.path)
            if parts.path == "/received":
                if self.command == "GET":
                    data = json.dumps({"received": store.snapshot()}).encode("utf-8")
                    self._send(200, data, "application/json")
                    return
                if self.command == "DELETE":
                    store.clear()
                    self._send(204)
                    return
            store.add({
                "method": self.command,
                "path": parts.path,
                "query": parts.query,
                "params": parse_qs(parts.query, keep_blank_values=True),
                "body": self._read_body(),
                "host": self.headers.get("Host", ""),
            })
            if parts.path == REDIRECT_PATH and self.command == "GET":
                target = redirect_target(parts.query)
                self._send(302, f"redirecting to {target}\n".encode("utf-8"),
                           extra={"Location": target})
                return
            self._send(200, f"collector received: {self.command} {self.path}\n".encode("utf-8"))

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _handle

    return FixtureServer((host, port), Handler)


def main():  # pragma: no cover
    serve(make_server, "collector")


if __name__ == "__main__":  # pragma: no cover
    main()
