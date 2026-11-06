"""http_fetch, implemented so that the resolved value is what executes.

SR-B5-3: "Evaluation is per call, on fully-resolved arguments
(post-normalisation, post-DNS, post-redirect), and THE RESOLVED VALUE IS
WHAT EXECUTES. No re-resolution occurs between decision and execution."

SR-B7-1: "Egress is allowlist-only, evaluated after DNS resolution
against the resolved address, and RE-EVALUATED ON EVERY REDIRECT HOP.
Link-local and private ranges are denied by range, never by string
match."

THE BUG THIS FILE EXISTS TO NOT HAVE
------------------------------------
The obvious implementation passes every test you would think to write:

    ip = socket.getaddrinfo(host, port)[0][4][0]   # resolve
    if not allowed(host) or denied_range(ip):      # validate
        return deny(...)
    conn = http.client.HTTPConnection(host, port)  # <-- RESOLVES AGAIN
    conn.request("GET", path)

Two lookups. The decision was made about the first; the connection
executes the second. An attacker serving a short TTL answers the first
with a public address and the second with a link-local one, and the gate
is bypassed having done exactly what it was told -- leaf B7 1.2, DNS
rebinding. `http.client` resolves inside `create_connection`, precisely
as Go's `http.Client` re-resolves at dial time; the language does not
matter, and most implementations in either one get this wrong.

The fix is to dial the IP that was validated and carry the hostname in
the Host header, so virtual-host routing still works. On an IP literal
`create_connection` performs no DNS at all, so there is no second lookup
left to win. `test_tools.py` asserts that as a NUMBER -- the injected
resolver must be called exactly once per hop.

LIMITATION, DECLARED RATHER THAN DISCOVERED IN REVIEW
-----------------------------------------------------
This is HTTP-only. Over TLS, dialing an IP breaks SNI and certificate
hostname verification unless `server_hostname` is set explicitly on the
SSL context. M2's fixtures (attacker.example, metadata.google.internal)
are plain HTTP, so the TLS path is not exercised and is not implemented
-- rather than implemented badly and implied to work.

WHAT THIS MODULE DOES NOT DECIDE
--------------------------------
The allowlist CONTENTS are policy, and policy is `gateway/policy/` --
a hardened zone, landing in T5. This module takes the allowlist as an
argument and implements the mechanism. Keeping the two apart is D3's
"the decision is separable from the executor" at the level of one file.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urljoin

# Denial reasons. These strings are asserted on by attacks/*/expected.json
# (§7: "the hardened assertion is a denial reason, never an absence"), so
# they are API. Changing one breaks a PoC, which is the intended coupling:
# a control that stops firing should fail a test, not go quiet.
EGRESS_NOT_ALLOWLISTED = "egress_not_allowlisted"
RESOLVED_ADDRESS_DENIED = "resolved_address_denied"
SCHEME_NOT_SUPPORTED = "scheme_not_supported"
RESOLUTION_FAILED = "resolution_failed"
TOO_MANY_REDIRECTS = "too_many_redirects"

DEFAULT_MAX_REDIRECTS = 3


@dataclass(frozen=True)
class Hop:
    """One request in a redirect chain, with the address actually dialed.

    Recorded per hop because SR-B7-1 requires re-evaluation at every hop
    and because the T9 detection work needs to see the chain, not just
    its outcome.
    """

    url: str
    host: str
    ip: str
    status: int | None = None


@dataclass
class FetchResult:
    allowed: bool
    reason: str | None = None
    detail: str = ""
    status: int | None = None
    body: str = ""
    hops: list[Hop] = field(default_factory=list)


@dataclass(frozen=True)
class DialResponse:
    status: int
    headers: dict[str, str]
    body: str


def default_resolve(host: str) -> str:
    """Resolve a hostname to a single address. Called once per hop.

    Returns the first A/AAAA answer. Picking one and dialing exactly
    that one is the point: resolving to a list and then handing the NAME
    to a connection would reintroduce the second lookup.
    """
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    if not infos:
        raise OSError(f"no address for {host!r}")
    # sockaddr is (host, port) for IPv4 and (host, port, flowinfo,
    # scope_id) for IPv6, so element 0 is typed `str | int`. It is always
    # the address string at runtime; asserting that rather than casting
    # means a surprise becomes an error here instead of an ipaddress
    # parse failure three frames away.
    address = infos[0][4][0]
    if not isinstance(address, str):
        raise OSError(f"unexpected sockaddr for {host!r}: {infos[0][4]!r}")
    return address


def default_dial(ip: str, port: int, method: str, path: str,
                 headers: dict[str, str], timeout: float = 5.0) -> DialResponse:
    """Connect to a literal IP and issue one request.

    `HTTPConnection(ip, ...)` means `create_connection` receives an IP
    literal, so no name resolution happens here. That is the entire
    control: there is no second lookup for an attacker to answer
    differently.

    Redirects are NOT followed -- `http.client` does not follow them, and
    that is why it is used instead of anything higher-level. Following
    automatically would execute hops that were never evaluated, which is
    SR-B7-1's failure in one library default.
    """
    conn = http.client.HTTPConnection(ip, port, timeout=timeout)
    try:
        conn.request(method, path, headers=headers)
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")
        return DialResponse(
            status=resp.status,
            headers={k.lower(): v for k, v in resp.getheaders()},
            body=body,
        )
    finally:
        conn.close()


def is_denied_range(ip: str) -> bool:
    """Deny by RANGE, never by string match (SR-B7-1).

    `ipaddress` parses the address and compares it against the actual
    network blocks, so 169.254.169.254, 0251.0376.0251.0376 (octal),
    2852039166 (decimal) and ::ffff:169.254.169.254 (v4-mapped v6) all
    collapse to the same answer. A denylist of strings catches the first
    and misses the rest -- leaf B7 1.2 -- which is exactly the argument
    M2-N2 makes about redaction in the other direction.
    """
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def evaluate(host: str, ip: str, allowlist) -> tuple[bool, str, str]:
    """Allowlist FIRST, then range (D6). Returns (ok, reason, detail).

    The ordering is load-bearing and is why D6 is a decision rather than
    a detail. Both M2 fixtures sit on a Compose bridge network in RFC1918
    space, so a gate that checked ranges first would deny finding 03 as
    "private address" -- true, but the wrong reason, and an artifact of
    the lab that would not generalise to an attacker on a public IP.
    Allowlist-first gives each finding its own distinct denial reason,
    which §7 asserts on.
    """
    if host not in allowlist:
        return False, EGRESS_NOT_ALLOWLISTED, f"host {host!r} is not on the egress allowlist"
    if is_denied_range(ip):
        return False, RESOLVED_ADDRESS_DENIED, f"{host!r} resolved to {ip}, which is in a denied range"
    return True, "", ""


def fetch(url: str, *, allowlist, resolve=None, dial=None,
          max_redirects: int = DEFAULT_MAX_REDIRECTS) -> FetchResult:
    """Fetch a URL, re-evaluating the full decision at every hop.

    `resolve` and `dial` are injected seams. Production passes neither
    and gets the real stdlib implementations; tests pass fakes, which is
    the only way to express "the attacker changed the DNS answer between
    the check and the connection" -- and therefore the only way to tell
    a correct implementation from the buggy one that behaves identically
    whenever DNS is honest.
    """
    resolve = resolve or default_resolve
    dial = dial or default_dial

    result = FetchResult(allowed=False)
    current = url

    for _ in range(max_redirects + 1):
        parts = urlsplit(current)
        if parts.scheme != "http":
            # https is not implemented rather than implemented badly;
            # see the module docstring.
            result.reason = SCHEME_NOT_SUPPORTED
            result.detail = f"scheme {parts.scheme!r} is not supported by this fetcher (http only)"
            return result

        host = parts.hostname or ""
        port = parts.port or 80

        try:
            ip = resolve(host)
        except OSError as exc:
            result.reason = RESOLUTION_FAILED
            result.detail = f"could not resolve {host!r}: {exc}"
            return result

        ok, reason, detail = evaluate(host, ip, allowlist)
        if not ok:
            result.hops.append(Hop(url=current, host=host, ip=ip))
            result.reason = reason
            result.detail = detail
            return result

        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"

        # The Host header carries the NAME even though we dialed the IP,
        # so name-based virtual hosting still resolves to the right site.
        resp = dial(ip, port, "GET", path, {"Host": host, "Accept": "*/*"})
        result.hops.append(Hop(url=current, host=host, ip=ip, status=resp.status))

        if resp.status in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "")
            if not location:
                result.reason = RESOLUTION_FAILED
                result.detail = f"redirect {resp.status} with no Location header"
                return result
            # Loop back to the top: the next hop is resolved and
            # evaluated from scratch. A redirect is not a continuation of
            # an approved request, it is a NEW request to a destination
            # the attacker chose, and it gets the same scrutiny as the
            # first one.
            current = urljoin(current, location)
            continue

        result.allowed = True
        result.status = resp.status
        result.body = resp.body
        return result

    result.reason = TOO_MANY_REDIRECTS
    result.detail = f"exceeded {max_redirects} redirects"
    return result
