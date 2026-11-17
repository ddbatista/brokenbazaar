"""The gate's authority enrichment (plan M3 T6 D3; m3-delegation.md D3/D4).

Before the gate decides any call, it asks the API what the acting session's
authority is NOW:

    GET /internal/sessions/{id}/authority?tool=...      (service secret)
    <-  {session:{id, org, acting_for}, role_now,
         legs:{within_time, in_scope, role_permits}}

THE SESSION NAMES; IT NEVER GRANTS. The agent's payload says only which
session is acting. The org, the acting user and every leg come from the
session row and the live membership, re-derived on each call -- never from
what the agent says about itself (M2-N3's subject-vs-testimony line, applied
to the session). Nothing here is cached: a demotion takes effect on the
next action (SR-B3-3).

FAIL CLOSED. Anything short of a complete, well-formed answer about THIS
session is an error, and the gate denies the call as enrichment_failed
(M2's path). A partial answer is never passed on: a leg left undefined is
exactly the input that must never read as permission (M2 T5's lesson). A
leg that is present and false is NOT an error -- it is the fact the policy
turns into its reason.
"""

from __future__ import annotations

import json
from urllib.parse import quote, urlencode

from tools import documents

LEGS = ("within_time", "in_scope", "role_permits")


def lookup(session_id: str, tool: str, *, api_base: str, tools_secret: str,
           request=None, timeout: float = 5.0) -> tuple[dict | None, str]:
    """Return (authority, "") or (None, why it could not be established)."""
    if not session_id:
        return None, "the call names no session"
    if not tools_secret:
        return None, "TOOLS_SECRET is not set; cannot ask the authority route"

    # The id is path-escaped (no "/" survives), so a crafted session id
    # cannot walk to another internal route.
    path = (f"/internal/sessions/{quote(session_id, safe='')}/authority?"
            + urlencode({"tool": tool}))
    status, text, err = documents.call_internal(
        "GET", path, None, api_base=api_base, tools_secret=tools_secret,
        request=request, timeout=timeout)
    if err:
        return None, f"authority route unreachable: {err}"
    if status == 404:
        return None, f"no such session {session_id!r}"
    if status != 200:
        return None, f"authority route answered HTTP {status}"

    try:
        body = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, f"authority route returned malformed JSON: {exc}"
    if not isinstance(body, dict):
        return None, "authority route returned a non-object"

    session = body.get("session")
    legs = body.get("legs")
    if not isinstance(session, dict) or not isinstance(legs, dict):
        return None, "authority answer lacks session or legs"
    if session.get("id") != session_id:
        return None, "authority answer is about another session"
    if not session.get("org") or not session.get("acting_for"):
        return None, "authority answer lacks the session's org or acting user"
    for leg in LEGS:
        if not isinstance(legs.get(leg), bool):
            return None, f"authority answer lacks a boolean {leg}"

    return {
        "session": {"id": session["id"], "org": session["org"],
                    "acting_for": session["acting_for"]},
        "role_now": body.get("role_now", ""),
        "legs": {leg: legs[leg] for leg in LEGS},
    }, ""
