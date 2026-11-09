#!/usr/bin/env python3
"""M2 detection rules: read the agent's audit records, not the gate's verdicts.

M1's detector alerted on denials, and measured its own limit: a
denial-based detector is coupled to the control working. In vulnerable
mode it caught 0 of 3 attacks, because nothing was denied. M2's gateway
(and, in vulnerable mode, the agent's own writer -- D4's second writer)
records every call WITH ITS INPUTS (SR-B5-9). So these rules read the
inputs -- what was fetched, where it resolved, what content caused it --
and fire whether or not anything stopped the call.

Three rules, each one alert per (rule, session), firing at ONE matching
call. M1's threshold was 5 because a single denial is noise; a single
fetch of a credential endpoint, or of attacker-chosen bytes to an
unlisted host, is the incident (T9 D1):

  R1 untrusted-fetch       an http_fetch whose provenance includes
                           "untrusted": the context that produced the
                           call held content the platform labelled
                           untrusted. The injection pattern as a platform
                           FACT, not a regex on text (M2-N2 rejected value
                           guessing for redaction; it is rejected here too).
  R2 egress-off-allowlist  an http_fetch to a host not on the egress
                           allowlist -- read from gateway/policy/data.json,
                           the gate's own file (T9 D2).
  R3 metadata-endpoint     an http_fetch whose requested host, resolved
                           address, or FINAL URL after redirects is a
                           cloud metadata endpoint (T9 D3).

DECLARED COUPLINGS -- what blinds each rule:
- R1 trusts the platform's provenance. In vulnerable mode the naive
  assembler merges the STORED transcript into one unlabelled span, so
  untrusted content already in the transcript before the run is invisible
  to R1. Content read during the run is still labelled (app/agent/
  provenance.go), which is the 03 path. The fallback for the merged case,
  a read-then-fetch sequence rule, is declared and not built.
- R2 shares the gate's allowlist. An allowlist widened by mistake blinds
  R2 and the gate TOGETHER: a detector that reads the control's data is
  coupled to that data being right -- M1's lesson one level up. That is
  why R3 does not consult the allowlist, and the shipped policy shows it
  is needed: metadata.google.internal IS allowlisted (D6), so R2 alone is
  blind to finding 04.
- R3's redirect leg parses the completion record's summary, in the
  vulnerable fetcher's format "URL -> status (n bytes)". A reworded
  summary turns that leg off; test_agent_rules.py pins the format.
- R1 is TAINT, so it over-approximates: any fetch made after untrusted
  content entered the context fires, including one the user asked for
  after reading a document. The replay's false-positive rows do not
  exercise that case (the scripted model fetches before it reads), and
  in vulnerable mode a first-turn fetch carries [] -- so R1's only
  meaningful silent cell is the hardened benign fetch. Declared, not
  measured (T9 review).
- R3's resolved-address leg needs the GATEWAY's enrichment: the agent's
  own records (vulnerable mode) carry no `resolved` field, because the
  naive fetcher never resolves separately. A hostname that resolves to
  169.254.169.254 is therefore caught in hardened mode only; in
  vulnerable mode R3 sees names and the redirect target (T9 review).
- R3's redirect leg needs a COMPLETED fetch: a failed request leaves an
  empty summary, so a redirect to the metadata host whose final hop
  errored is not seen (T9 review).
- R3 matches metadata NAMES and the well-known link-local addresses,
  never the lab's fixture IP: keyed on 172.28.0.20 it would detect the
  lab, not the attack.

Alerts carry session, count, hosts ("asked -> reached" for a redirect
match) and decision ids -- never the URL. The
exfiltration URL's query string IS the stolen tenant data, and an alert
printed into a CI log must not re-leak it.

Pure functions, no IO except load_allowlist; replay_agent.py feeds them
real records from a live stack.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit

REPO = Path(__file__).resolve().parent.parent
POLICY_DATA = REPO / "gateway" / "policy" / "data.json"

R1, R2, R3 = "untrusted-fetch", "egress-off-allowlist", "metadata-endpoint"

# Cloud metadata endpoints, by the names and addresses providers document.
METADATA_HOSTS = frozenset({
    "metadata.google.internal", "metadata.goog", "metadata",   # GCP
    "instance-data", "instance-data.ec2.internal",             # AWS
})
METADATA_IPS = frozenset({
    ipaddress.ip_address("169.254.169.254"),   # AWS, GCP, Azure, OCI, DO
    ipaddress.ip_address("fd00:ec2::254"),     # AWS IMDS over IPv6
    ipaddress.ip_address("100.100.100.200"),   # Alibaba Cloud
})

# app/agent/executor_vulnerable.go: fmt.Sprintf("%s -> %d (%d bytes)", final, ...)
FINAL_URL = re.compile(r"^(\S+) -> \d{3} \(\d+ bytes\)$")


def parse_jsonl(text: str) -> list:
    """Records from a JSONL audit file. A malformed line raises: a
    detector that skips what it cannot read reports "nothing found"
    about records it never looked at."""
    records = []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"audit line {n} is not JSON: {exc}") from None
    return records


def load_allowlist(path) -> frozenset:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return frozenset(h.lower() for h in data["egress_allowlist"])


def _host(url) -> str:
    """The parsed, lower-cased host of a URL, or '' if there is none."""
    try:
        return (urlsplit(url or "").hostname or "").lower()
    except ValueError:
        return ""


def _is_metadata(host: str, ip: str = "") -> bool:
    if host in METADATA_HOSTS:
        return True
    for candidate in (host, ip):
        try:
            if candidate and ipaddress.ip_address(candidate) in METADATA_IPS:
                return True
        except ValueError:
            pass
    return False


def _final_hosts(records: list) -> dict:
    """decision_id -> the host a completed fetch finally reached."""
    final = {}
    for rec in records:
        if rec.get("phase") != "post" or rec.get("outcome") != "ok":
            continue
        match = FINAL_URL.match(rec.get("summary") or "")
        if match:
            final[rec["decision_id"]] = _host(match.group(1))
    return final


def _fetch_rules(rec: dict, allowlist, final_host: str) -> list:
    """(rule, where) pairs for one fetch pre-record. `where` is the host
    asked for, or "asked -> reached" when a redirect is what matched."""
    host = _host(rec.get("args", {}).get("url"))
    derived = (rec.get("provenance") or {}).get("derived_from") or []
    resolved_ip = (rec.get("resolved") or {}).get("ip", "")
    hits = []
    if "untrusted" in derived:
        hits.append((R1, host))
    if host not in allowlist:
        hits.append((R2, host))
    if _is_metadata(host, resolved_ip):
        hits.append((R3, host))
    elif final_host and _is_metadata(final_host):
        hits.append((R3, f"{host} -> {final_host}"))
    return hits


def _group(hits) -> list:
    """(rule, session, host, decision_id) hits -> one alert per (rule, session)."""
    grouped = defaultdict(lambda: {"hosts": set(), "decision_ids": []})
    for rule, session, host, did in hits:
        g = grouped[(rule, session)]
        g["hosts"].add(host or "<no host>")
        g["decision_ids"].append(did)
    return [{"rule": rule, "session": session, "count": len(g["decision_ids"]),
             "hosts": sorted(g["hosts"]), "decision_ids": g["decision_ids"]}
            for (rule, session), g in grouped.items()]


def find_agent_alerts(records: list, allowlist) -> list:
    """Alerts from pre-records of http_fetch calls, in either writer's
    schema, joined to their completion records for the redirect leg."""
    final = _final_hosts(records)
    hits = []
    for rec in records:
        if rec.get("phase") != "pre" or rec.get("tool") != "http_fetch":
            continue
        did = rec.get("decision_id", "")
        for rule, where in _fetch_rules(rec, allowlist, final.get(did, "")):
            hits.append((rule, rec.get("session", ""), where, did))
    return _group(hits)


def deny_only_alerts(records: list) -> list:
    """The M1-style baseline: one alert per session the gate DENIED.

    Not a rule this repo recommends -- the comparison column of the
    matrix, measuring what a denial-based detector would have seen on
    the same records."""
    hits = [("deny-only", rec.get("session", ""), _host((rec.get("args") or {}).get("url")),
             rec.get("decision_id", ""))
            for rec in records
            if rec.get("phase") == "pre" and rec.get("route") == "deny"]
    return _group(hits)
