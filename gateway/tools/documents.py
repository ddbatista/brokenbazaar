"""The document tools, over the API's internal routes (D5b; plan M3 T6 D4).

D5b, forced by elimination: the gateway is Python and the documents are
in Postgres, so the gateway cannot read them directly (no stdlib
Postgres driver, and pip is the house-rule violation D4 already rejected
for the same reason). Having the agent execute it violates D5. What
remains is the gateway calling the API over HTTP with a credential the
agent does not hold:

    agent  -> POST /gate {"tool":"read_document","args":{"id":...},"session":{"id":...}}
    gateway: authority -> policy -> pre-record -> fsync
             GET /internal/tools/read_document?session=...&id=...
             Authorization: Bearer <TOOLS_SECRET>
    api:     verify secret -> re-derive the session's authority
             -> store.ForOrg(pool, the session row's org).Get(id)

THE SECRET IS WHAT KEEPS THE AGENT OUT, ENFORCED AT THE AUTH LAYER. Since
M3 it is no longer the whole of the mediation: the API also re-checks the
session's authority on every call (below).
The agent can reach this route on the Compose bridge network (M2-N1, as
conceded) but holds nothing that authenticates to it. Neither influence
over the documents it reads nor control of its prompt obtains the
gateway's environment.

The honest difference from http_fetch, recorded in the diff and repeated
here because it is easy to lose: for http_fetch, D4's "one code path in
one process" holds literally. For read_document the pre-record ordering
spans two processes, so it becomes ONE CAUSAL CHAIN. The SR's claim --
the record is written before execution -- still holds; the strength of
the mechanism differs, and saying so is cheaper than being caught
implying they are identical.

THE SESSION NAMES; IT NEVER GRANTS (plan M3 T6 D4, m3-delegation.md D3/D4). In M2
the gateway passed an org parameter, taken from the agent's payload. Every
route now takes the SESSION id instead, and the API resolves the org from
the session row and re-checks the session's authority at execution
(M3-N2) -- so a demotion or an expiry that lands between the gate's
decision and the write still refuses it. That refusal comes back as a 403
naming the failing leg, reported here as REFUSED_AT_EXECUTION with the
leg in the detail. The API binds the row's org through store.ForOrg, so a
document id from another tenant resolves to not-found by the same single
WHERE clause that serves every other caller (SR-M1-4).

There is no client for set_member_role, because there is no route for it:
a control-plane action is unreachable from the gateway by structure
(m3-delegation.md D6).
"""

from __future__ import annotations

import http.client
import json
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit

DOCUMENT_NOT_FOUND = "document_not_found"
INTERNAL_ROUTE_UNAVAILABLE = "internal_route_unavailable"
INTERNAL_ROUTE_REFUSED = "internal_route_refused"
REFUSED_AT_EXECUTION = "refused_at_execution"
TOOLS_SECRET_MISSING = "tools_secret_missing"


@dataclass
class DocumentResult:
    allowed: bool
    reason: str | None = None
    detail: str = ""
    document_id: str = ""
    title: str = ""
    body: str = ""


def read_document(document_id: str, session_id: str, *, api_base: str,
                  tools_secret: str, request=None,
                  timeout: float = 5.0) -> DocumentResult:
    """Fetch one document through the API's internal route.

    `request` is an injected seam, same pattern as fetch()'s resolve and
    dial: production passes nothing, tests pass a fake, and no network
    or database is needed to assert the behaviour that matters -- that
    the secret is sent, that a 401 is reported as a refusal rather than
    as an empty document, and that a missing secret fails before any
    request is made.
    """
    query = urlencode({"session": session_id, "id": document_id})
    return _call("GET", f"/internal/tools/read_document?{query}", None,
                 document_id, api_base=api_base, tools_secret=tools_secret,
                 request=request, timeout=timeout)


def update_document(document_id: str, body: str, session_id: str, *,
                    api_base: str, tools_secret: str, request=None,
                    timeout: float = 5.0) -> DocumentResult:
    """Replace one document's body (title kept) through the internal route."""
    payload = {"session": session_id, "id": document_id, "body": body}
    return _call("POST", "/internal/tools/update_document", payload,
                 document_id, api_base=api_base, tools_secret=tools_secret,
                 request=request, timeout=timeout)


def delete_document(document_id: str, session_id: str, *, api_base: str,
                    tools_secret: str, request=None,
                    timeout: float = 5.0) -> DocumentResult:
    """Delete one document through the internal route."""
    payload = {"session": session_id, "id": document_id}
    return _call("POST", "/internal/tools/delete_document", payload,
                 document_id, api_base=api_base, tools_secret=tools_secret,
                 request=request, timeout=timeout)


def _call(method: str, path: str, payload, document_id: str, *, api_base: str,
          tools_secret: str, request, timeout: float) -> DocumentResult:
    if not tools_secret:
        # Loud or absent, never quiet (SR-M1-1 / SR-B1-3). A gateway
        # with no credential must say so, not issue an unauthenticated
        # request and report whatever the API says about it.
        return DocumentResult(
            allowed=False,
            reason=TOOLS_SECRET_MISSING,
            detail="TOOLS_SECRET is not set; refusing to call the internal route",
        )

    status, text, err = call_internal(method, path, payload, api_base=api_base,
                                      tools_secret=tools_secret, request=request,
                                      timeout=timeout)
    if err:
        return DocumentResult(allowed=False, reason=INTERNAL_ROUTE_UNAVAILABLE,
                              detail=f"could not reach the API internal route: {err}")

    if status == 401:
        return DocumentResult(
            allowed=False,
            reason=INTERNAL_ROUTE_REFUSED,
            detail=f"the API refused the service credential (HTTP {status})",
        )
    if status == 403:
        # The re-check at execution (M3-N2): the session's authority
        # failed NOW, after the gate allowed it. The leg is in the body.
        try:
            leg = json.loads(text).get("reason", "")
        except (json.JSONDecodeError, AttributeError):
            leg = ""
        return DocumentResult(allowed=False, reason=REFUSED_AT_EXECUTION,
                              detail=leg or "no reason given")
    if status == 404:
        # The API cannot distinguish "no such document" from "not this
        # org's document" -- OrgStore.Get's single WHERE sees both as an
        # empty result (SR-M1-4) -- and neither can this. An unknown
        # session is a 404 too: the gate asked the authority route about
        # it a moment ago, so only a race lands here.
        return DocumentResult(
            allowed=False,
            reason=DOCUMENT_NOT_FOUND,
            detail=f"no document {document_id!r} reachable in this session's org",
        )
    if status == 204:
        return DocumentResult(allowed=True, document_id=document_id)
    if status != 200:
        return DocumentResult(
            allowed=False,
            reason=INTERNAL_ROUTE_UNAVAILABLE,
            detail=f"unexpected status {status} from the internal route",
        )

    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        return DocumentResult(
            allowed=False,
            reason=INTERNAL_ROUTE_UNAVAILABLE,
            detail=f"malformed JSON from the internal route: {exc}",
        )

    return DocumentResult(
        allowed=True,
        document_id=doc.get("id", ""),
        title=doc.get("title", ""),
        body=doc.get("body", ""),
    )


def call_internal(method: str, path: str, payload, *, api_base: str,
                  tools_secret: str, request=None,
                  timeout: float = 5.0) -> tuple[int, str, str]:
    """One authenticated call to an API internal route.

    Returns (status, body, error); error is non-empty when the API could
    not be reached at all. Shared by the document tools and the gate's
    authority enrichment, so the service credential is attached in one
    place.
    """
    headers = {
        "Authorization": f"Bearer {tools_secret}",
        "Accept": "application/json",
    }
    data = None
    if payload is not None:
        data = json.dumps(payload)
        headers["Content-Type"] = "application/json"
    send = request or _default_request
    try:
        status, text = send(api_base, method, path, headers, data, timeout)
    except OSError as exc:
        return 0, "", str(exc) or exc.__class__.__name__
    return status, text, ""


def _default_request(api_base: str, method: str, path: str,
                     headers: dict[str, str], data: str | None,
                     timeout: float) -> tuple[int, str]:
    parts = urlsplit(api_base)
    if not parts.hostname:
        # A malformed API base is a misconfiguration, not a runtime
        # condition to paper over -- same loud-or-absent reasoning as the
        # missing secret above.
        raise OSError(f"api_base has no host: {api_base!r}")
    conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=timeout)
    try:
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp.read().decode("utf-8", errors="replace")
    finally:
        conn.close()
