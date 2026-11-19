"""The marketplace execution channel (plan M4a T5; m4a-marketplace.md D5/D6).

The gateway is the only thing that may execute a tool in hardened mode, and
an INSTALLED tool is executed here: the gateway dials the publisher's
endpoint, at the address the install row recorded, under an identity the
install row derives -- never the agent's session credentials, never the
org's (SR-B6-5 / SR-B5-8: a per-installation identity, attributable because
the fixture echoes what it received).

THE FACTS THIS MODULE ESTABLISHES (enrich; the policy decides, never here):

    pin_verified   the endpoint's manifest TODAY hashes to the pin
    tool_known     the tool is in the pin, or in the manifest fetched today

AN ENDPOINT THAT CANNOT BE FETCHED IS NOT "NO DRIFT". It is a pin that
could not be verified, and the caller reports pin_verified false so the
DRIFT reason names it (M4a-N2's trap: "unreachable" must never read as
"verified" or as "no drift"). This module never decides anything; it
reports facts and executes what the policy already allowed.

PINNED-ADDRESS DIALING (SR-B6-4): the hostname is resolved and compared to
the address recorded at install before any connection is made -- a mismatch
is refused as rebinding. The resolved address is also classified here: a
publisher that rebinds into (or was recorded as) the metadata space is
refused at dial, before any byte of tenant data moves. Private space is
NOT refused on this channel -- self-hosted publishers are a legitimate
shape and every lab fixture sits on the Compose bridge -- the rebinding
comparison is this channel's address-drift guard.

The manifest is the FULL tools/list response body, envelope included, and
the pin is the SHA-256 of exactly the bytes fetched (the store's one home,
store.ManifestDigest; mirrored here byte-for-byte -- see
TestManifestDigestVector on the Go side for the cross-language fixture).
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
from dataclasses import dataclass
from urllib.parse import urlsplit

from tools import fetch

# The same bound the Go parser enforces (app/mcp.MaxManifestBytes): a
# tools/list body larger than this is refused whole, both directions.
MAX_MANIFEST_BYTES = 64 << 10

# The per-installation identity header (SR-B5-8). Derived from the install
# row by the caller; the fixture echoes it into its evidence log, so the
# identity is evidence, not assertion.
INSTALL_HEADER = "X-BB-Install"

DEFAULT_TIMEOUT = 5.0


@dataclass
class Endpoint:
    """Where an install's publisher is reached, as the install row pins it."""

    host: str
    ip: str
    port: int
    path: str


@dataclass
class MCPResult:
    """One dial's outcome. `allowed` false carries a reason, never a text."""

    allowed: bool
    reason: str = ""
    text: str = ""
    body: bytes = b""


def is_denied_infrastructure(ip: str) -> bool:
    """The ranges NO publisher lives in (M4a T5's dial-time classifier).

    Loopback, link-local -- the cloud-metadata space -- unspecified,
    multicast, reserved. Deliberately NOT the fetcher's is_denied_range:
    PRIVATE space is a legitimate publisher location (self-hosted MCP
    servers; every fixture in this lab sits on the Compose bridge in
    RFC1918), and the address-drift guard on this channel is the
    REBINDING comparison, not the range. What this check exists for is
    the metadata endpoint: a listing whose endpoint is (or rebinds to)
    169.254.169.254 is refused at dial even though an install row names
    it -- the install row is consent, not a range classification.
    """
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return (addr.is_loopback or addr.is_link_local or addr.is_unspecified
            or addr.is_multicast or addr.is_reserved)


def endpoint_for(fact: dict) -> tuple[Endpoint | None, str]:
    """Resolve an install's endpoint against its RECORDED address.

    Returns (endpoint, "") or (None, why it cannot be dialled as pinned).
    The comparison is on the RESOLVED address, not the hostname the URL
    carries: the install row recorded what discovery saw, and anything
    else answering today is a rebinding (SR-B6-4). The address is then
    classified by is_denied_infrastructure above -- a publisher that
    rebinds into the metadata space is refused here, at dial, before any
    byte of tenant data moves.
    """
    url = fact.get("endpoint_url", "")
    recorded = fact.get("endpoint_address", "")
    parts = urlsplit(url)
    host = parts.hostname or ""
    if not host:
        return None, f"install endpoint has no host: {url!r}"
    if parts.scheme != "http":
        return None, f"install endpoint is not http: {url!r}"
    try:
        ip = fetch.default_resolve(host)
    except OSError as exc:
        return None, f"could not resolve {host!r}: {exc}"
    if ip != recorded:
        return None, (f"endpoint rebinding refused: {host!r} resolves to "
                      f"{ip}, the install recorded {recorded!r}")
    if is_denied_infrastructure(ip):
        return None, f"endpoint address {ip} is in a denied range"
    return Endpoint(host=host, ip=ip,
                    port=parts.port or 80,
                    path=parts.path or "/"), ""


def _dial(endpoint: Endpoint, install_id: str, body: bytes,
          timeout: float = DEFAULT_TIMEOUT) -> MCPResult:
    """One HTTP POST to the pinned address, carrying the install identity."""
    conn = http.client.HTTPConnection(endpoint.ip, endpoint.port,
                                      timeout=timeout)
    try:
        conn.request("POST", endpoint.path, body=body, headers={
            "Host": endpoint.host,
            "Content-Type": "application/json",
            INSTALL_HEADER: install_id,
        })
        resp = conn.getresponse()
        raw = resp.read(MAX_MANIFEST_BYTES + 1)
        return MCPResult(allowed=True, reason=str(resp.status),
                         body=raw[:MAX_MANIFEST_BYTES])
    except OSError as exc:
        return MCPResult(allowed=False, reason=f"endpoint unreachable: {exc}")
    finally:
        conn.close()


def fetch_manifest(fact: dict) -> tuple[bytes | None, str]:
    """Fetch the endpoint's manifest TODAY, for the per-call drift check.

    Returns (bytes, "") or (None, why). The bytes are exactly what the
    wire returned -- hashing them is the whole point; a re-serialized
    copy would compare a fiction against the pin.
    """
    endpoint, why = endpoint_for(fact)
    if endpoint is None:
        return None, why
    res = _dial(endpoint, str(fact.get("install_id", "")),
                b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
    if not res.allowed:
        return None, res.reason
    if res.reason != "200":
        return None, f"endpoint answered HTTP {res.reason}"
    if len(res.body) > MAX_MANIFEST_BYTES:
        return None, "manifest over the size bound"
    return res.body, ""


def manifest_tool_names(raw: bytes) -> list[str]:
    """The tool names a tools/list body declares. [] when it does not parse.

    A live manifest that cannot be parsed is the drift reason's to name
    (the pin could not be verified against garbage), never an exception
    and never a silent pass.
    """
    try:
        body = json.loads(raw)
        tools = body["result"]["tools"]
        return [t["name"] for t in tools
                if isinstance(t, dict) and isinstance(t.get("name"), str)]
    except (ValueError, KeyError, TypeError):
        return []


def digest_matches(fact: dict, raw: bytes) -> bool:
    """Whether the fetched bytes hash to the install's pin."""
    want = str(fact.get("pinned_digest", ""))
    return bool(want) and hashlib.sha256(raw).hexdigest() == want


def call_tool(fact: dict, name: str, arguments: dict) -> MCPResult:
    """Execute one allowed tools/call at the pinned address.

    Reached only after the policy allowed the call, so this function's
    own refusals are operational, not decisions: rebinding, range,
    transport. The answer's text is the fixture family's envelope:
    result.content as a string (evil_mcp.CALL_ANSWER's shape).
    """
    endpoint, why = endpoint_for(fact)
    if endpoint is None:
        return MCPResult(allowed=False, reason=why)
    payload = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }).encode("utf-8")
    res = _dial(endpoint, str(fact.get("install_id", "")), payload)
    if not res.allowed:
        return res
    if res.reason != "200":
        return MCPResult(allowed=False, reason=f"endpoint answered HTTP {res.reason}")
    try:
        answer = json.loads(res.body)
        text = answer["result"]["content"]
    except (ValueError, KeyError, TypeError):
        return MCPResult(allowed=False, reason="tool answer was not a well-formed envelope")
    if not isinstance(text, str):
        return MCPResult(allowed=False, reason="tool answer content is not text")
    return MCPResult(allowed=True, text=text)
