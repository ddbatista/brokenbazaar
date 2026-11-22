#!/usr/bin/env python3
"""M4a detection rules: the marketplace's own events, read as facts.

M1's detector alerted on denials and measured its own limit: it is
coupled to the control working -- in vulnerable mode nothing is denied.
M2 moved the detectors onto the INPUTS (SR-B5-9: every call recorded
with its inputs, both writers' schemas). M4a adds a third-party surface
whose consent artifact is the PIN: the org's install decision, in bytes,
against which every later event can be judged. These rules read the
call records (either writer) joined to the org's pins, and the catalog's
own mutation log -- and fire whether or not anything stopped the call.

Three rules, each one alert per (rule, session), firing at ONE matching
event:

  D1 first-seen-tool       an installed-tool call whose name is in NO
                           pin the org holds. The (tool -> endpoint)
                           pair was never approved: whatever endpoint
                           would serve it, the org never consented to
                           it. Catches the rug pull at call time, in
                           both modes -- in hardened the attempt is
                           denied, but the ATTEMPT is the event; a
                           detector keyed on "what executed" would be
                           coupled to the control working (M1's lesson).
  D2 consent-mismatch      an installed-tool call whose bytes are NOT
                           user-typed while the pin declares the tool
                           receives only user_text. The consent
                           artifact is the pin's `receives`; the
                           byte-provenance is the platform's own label
                           (`provenance.derived_from` -- a platform
                           fact, not a regex on text, M2-N2's ruling
                           applied one surface up). Catches 07 in
                           vulnerable mode from agent.jsonl, where no
                           gate record exists.
  D3 installed-listing-mutated
                           a catalog mutation row for a listing that
                           holds ACTIVE installs: the org is running
                           bytes that no longer match the catalog page
                           its installers will see next time. The
                           catalog is platform state, not an agent
                           event -- this rule reads the mutation log
                           itself and fires in both modes.

DECLARED COUPLINGS -- what blinds each rule:
- D1 keys on the org's pins, so its truth is the pin. A listing whose
  pin is WIDE (declares everything) is invisible by design: the org
  approved it. A publisher who flips their SERVER without PATCHing
  the listing is invisible to D3 -- and that is exactly D1's job at
  call time. The two rules are one net with two meshes.
- D2 maps provenance classes to consent classes, and the mapping is
  DECLARED: derived_from ⊆ {"user"} is user_text; ANY other label
  (untrusted, model, transcript, publisher) is document-shaped, and
  `document_content` -- the pin vocabulary's only declared non-user
  class -- is what covers it. A future class added to the pin
  vocabulary must re-derive this mapping, not inherit it silently.
  The honest limit is the assembler's: in vulnerable mode, content
  merged into the stored transcript BEFORE the run loses its label
  (the naive assembler, R1's precedent) -- a call derived from
  yesterday's transcript is invisible to D2 in vulnerable mode.
  Content read during the run is labelled in both modes, which is
  the 07 path.
- D2 trusts the pin's declaration. A publisher who declares
  document_content up front harvests WITHIN consent and no leg fires
  (M4a-N1): no detector can read intent; the install review is
  load-bearing, and this rule exists to catch the lie AFTER approval,
  not to overrule the org's own decision -- scenario "re-approved"
  in the replay stays silent for exactly that reason.
- D3 sees only the PLATFORM's mutation log. A mutation row's
  before/after digests are compared by the drift leg at call time;
  this rule is the operator's VISIBILITY that the page changed under
  active installs, not a second drift check.

Alerts carry session, count, and decision ids -- never the query
bytes: the exfiltrated document IS the stolen tenant data, and an
alert printed into a CI log must not re-leak it. D3 carries the
mutation's actor and digests (already digests in the log, not
content).

Pure functions, no IO; replay_marketplace.py feeds them real records
and real pins from a live stack.
"""

from __future__ import annotations

import json
from collections import defaultdict

D1, D2, D3 = "first-seen-tool", "consent-mismatch", "installed-listing-mutated"

# The user's own typed text -- the provenance class the consent
# vocabulary calls user_text. Everything else is derived from something
# the platform did not type.
USER_CLASSES = frozenset({"user"})

# The platform's own tool registry, mirrored from
# app/agent/executor_vulnerable.go's naiveAllowedTools. D1 judges
# MARKETPLACE calls; a platform tool is never "first-seen" no matter
# what the org has installed. A platform tool added to the Go registry
# must be added here in the SAME task -- the coupling is declared the
# way agent_rules pins the vulnerable fetcher's summary format.
PLATFORM_TOOLS = frozenset({
    "read_document", "http_fetch", "update_document", "delete_document",
    "set_member_role",
})


def parse_pins(install_rows):
    """The org's consent artifacts from install rows (agentlab.installs_of).

    One pin per row -- INCLUDING tombstoned ones? No: only ACTIVE
    installs. A tombstoned install is a decision the org UNmade, and
    judging today's calls against an unmade decision would manufacture
    consent that was revoked. Rows read as the API answers them
    (Go-default casing).
    """
    pins = []
    for row in install_rows or []:
        if (row.get("Status") or "active") != "active":
            continue
        try:
            manifest = json.loads(row.get("PinnedManifest") or "{}")
            tools = manifest["result"]["tools"]
        except (ValueError, KeyError, TypeError):
            # A pin that cannot be parsed is a pin the org holds but
            # nobody can read: D1 treats its tools as unknown (the
            # name is not in any KNOWN pin), which fails loud, not
            # silent. Parsing failure is a data-integrity event, and
            # the replay asserts digests before it ever gets here.
            continue
        pins.append({
            "install_id": row.get("ID", ""),
            "endpoint": row.get("EndpointURL", ""),
            "tools": {t.get("name", ""): frozenset(t.get("receives") or [])
                      for t in tools if isinstance(t, dict)},
        })
    return pins


def _pin_for(pins, tool):
    """The pin that declares this tool, or None."""
    for pin in pins:
        if tool in pin["tools"]:
            return pin
    return None


def _installed_tools(pins):
    return {tool for pin in pins for tool in pin["tools"]}


def find_marketplace_alerts(records, install_rows):
    """D1 + D2 over one window's call records (either writer's schema).

    Takes the RAW install rows (agentlab.installs_of shape) and parses
    the pins itself: the guard is "does the org have an ACTIVE install
    row", not "did every pin parse" -- an org holding an unreadable pin
    still has a marketplace surface, and calls against it must be
    judged first-seen, not waved through as "no marketplace events".
    """
    active = [r for r in install_rows or []
              if (r.get("Status") or "active") == "active"]
    if not active:
        # No active installs, no consent artifacts: nothing in this
        # window is a marketplace event.
        return []
    pins = parse_pins(install_rows)
    installed = _installed_tools(pins)
    hits = []
    for rec in records:
        if rec.get("phase") != "pre":
            continue
        tool = rec.get("tool", "")
        if not tool or tool in PLATFORM_TOOLS:
            continue
        if tool not in installed:
            # D1: the name is in no pin the org holds.
            hits.append((D1, rec.get("session", ""), tool, rec.get("decision_id", "")))
            continue
        pin = _pin_for(pins, tool)
        receives = pin["tools"][tool] if pin else frozenset()
        derived_from = (rec.get("provenance") or {}).get("derived_from") or []
        # D2: bytes the user did not type, to a tool that never declared
        # them. `document_content` is the pin vocabulary's only declared
        # non-user class: a tool carrying it has the org's consent for
        # non-user bytes, and the SAME call stays silent -- the rule
        # keys on the org's decision, never on a heuristic about the
        # bytes.
        if "document_content" not in receives and set(derived_from) - USER_CLASSES:
            hits.append((D2, rec.get("session", ""), tool, rec.get("decision_id", "")))
    return _group(hits)


def mutation_alerts(new_mutations, installs_by_item):
    """D3 over a window's catalog mutation rows, joined to install state.

    `new_mutations` is the window's rows (the replay snapshots the log
    before the scenario and passes only what grew); `installs_by_item`
    maps item id -> [{"Status": .., "ID": ..}] for the org. A mutation
    on a listing with an ACTIVE install is the page changing under a
    live decision.
    """
    hits = []
    for row in new_mutations or []:
        installs = installs_by_item.get(row.get("ItemID")) or []
        active = [i for i in installs if (i.get("Status") or "active") == "active"]
        if not active:
            continue
        hits.append((D3, row.get("ID", ""), row.get("Mutation", ""), row.get("ID", "")))
    return _group(hits)


def _group(hits):
    """(rule, session, where, decision_id) hits -> one alert per (rule, session).

    D3 groups by the mutation's own id (its "session" slot): one
    mutation row is one event, never merged with the audit's sessions.
    """
    grouped = defaultdict(lambda: {"where": set(), "decision_ids": []})
    for rule, session, where, did in hits:
        g = grouped[(rule, session)]
        g["where"].add(where or "<unknown>")
        g["decision_ids"].append(did)
    return [{"rule": rule, "session": session, "count": len(g["decision_ids"]),
             "where": sorted(g["where"]), "decision_ids": g["decision_ids"]}
            for (rule, session), g in grouped.items()]
