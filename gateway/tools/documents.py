"""read_document, over the D5b internal route.

D5b, forced by elimination: the gateway is Python and the documents are
in Postgres, so the gateway cannot read them directly (no stdlib
Postgres driver, and pip is the house-rule violation D4 already rejected
for the same reason). Having the agent execute it violates D5. What
remains is the gateway calling the API over HTTP with a credential the
agent does not hold:

    agent  -> POST /gate {"tool":"read_document","args":{"id":...}}
    gateway: policy -> pre-record -> fsync          (T5)
             GET /internal/tools/read_document?id=...&org=acme
             Authorization: Bearer <TOOLS_SECRET>
    api:     verify secret -> store.ForOrg(pool, org).Get(id)

MEDIATION FOR read_document IS THE SECRET, ENFORCED AT THE AUTH LAYER.
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

The org is passed explicitly by the gateway from the session, never
inferred from the document id. The API then binds it through
store.ForOrg, so a document id from another tenant resolves to
not-found by the same single WHERE clause that serves every other
caller (SR-M1-4).
"""

from __future__ import annotations

import http.client
import json
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit

DOCUMENT_NOT_FOUND = "document_not_found"
INTERNAL_ROUTE_UNAVAILABLE = "internal_route_unavailable"
INTERNAL_ROUTE_REFUSED = "internal_route_refused"
TOOLS_SECRET_MISSING = "tools_secret_missing"


@dataclass
class DocumentResult:
    allowed: bool
    reason: str | None = None
    detail: str = ""
    document_id: str = ""
    title: str = ""
    body: str = ""


def read_document(document_id: str, org_id: str, *, api_base: str,
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
    if not tools_secret:
        # Loud or absent, never quiet (SR-M1-1 / SR-B1-3). A gateway
        # with no credential must say so, not issue an unauthenticated
        # request and report whatever the API says about it.
        return DocumentResult(
            allowed=False,
            reason=TOOLS_SECRET_MISSING,
            detail="TOOLS_SECRET is not set; refusing to call the internal route",
        )

    query = urlencode({"id": document_id, "org": org_id})
    path = f"/internal/tools/read_document?{query}"
    headers = {
        "Authorization": f"Bearer {tools_secret}",
        "Accept": "application/json",
    }

    send = request or _default_request
    try:
        status, body = send(api_base, path, headers, timeout)
    except OSError as exc:
        return DocumentResult(
            allowed=False,
            reason=INTERNAL_ROUTE_UNAVAILABLE,
            detail=f"could not reach the API internal route: {exc}",
        )

    if status in (401, 403):
        return DocumentResult(
            allowed=False,
            reason=INTERNAL_ROUTE_REFUSED,
            detail=f"the API refused the service credential (HTTP {status})",
        )
    if status == 404:
        # The API cannot distinguish "no such document" from "not this
        # org's document" -- OrgStore.Get's single WHERE sees both as an
        # empty result (SR-M1-4) -- and neither can this.
        return DocumentResult(
            allowed=False,
            reason=DOCUMENT_NOT_FOUND,
            detail=f"no document {document_id!r} readable in org {org_id!r}",
        )
    if status != 200:
        return DocumentResult(
            allowed=False,
            reason=INTERNAL_ROUTE_UNAVAILABLE,
            detail=f"unexpected status {status} from the internal route",
        )

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        return DocumentResult(
            allowed=False,
            reason=INTERNAL_ROUTE_UNAVAILABLE,
            detail=f"malformed JSON from the internal route: {exc}",
        )

    return DocumentResult(
        allowed=True,
        document_id=payload.get("id", ""),
        title=payload.get("title", ""),
        body=payload.get("body", ""),
    )


def _default_request(api_base: str, path: str, headers: dict[str, str],
                     timeout: float) -> tuple[int, str]:
    parts = urlsplit(api_base)
    if not parts.hostname:
        # A malformed API base is a misconfiguration, not a runtime
        # condition to paper over -- same loud-or-absent reasoning as the
        # missing secret above.
        raise OSError(f"api_base has no host: {api_base!r}")
    conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=timeout)
    try:
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp.read().decode("utf-8", errors="replace")
    finally:
        conn.close()
