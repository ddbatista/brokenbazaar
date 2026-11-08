#!/usr/bin/env python3
"""The BrokenBazaar gateway: the only thing that may execute a tool.

    POST /gate   decide and execute one tool call   (D5.1's contract)
    GET  /healthz liveness plus the mode it believes it is in (M2-N4)

THE FLOW, and why it is in this order (D4, D5.2, D5.5):

    enrich  ->  evaluate  ->  pre-record  ->  fsync  ->  mint id
            ->  execute   ->  post-record ->  respond

Enrichment first, because the policy decides on FACTS the gateway
established -- the resolved address, not the hostname the caller sent
(SR-B5-3: the resolved value is what executes). Evaluation before the
record, because the record states the decision. The record before
execution, because that is what makes it a license rather than a log.
The id after the write, because an id that existed first could cite a
record that does not.

THE WIRE CONTRACT (D5.1, as amended by D5.3):

    -> {"tool", "args", "session":{id,org,acting_for},
        "provenance":{"derived_from":[...]}}

    <- 200 {"route":"allow","decision_id","reason","text","summary"}
    <- 200 {"route":"deny", "decision_id","text":"gateway denied","summary":""}
    <- 5xx  no decision was reached; nothing executed

A decision is HTTP 200 either way: a deny is the gateway doing its job,
not a transport failure. Denials carry NO reason on the wire -- SR-B7-7
read against leaf B7 2.2 (the existence oracle): an attacker who learns
`resolved_address_denied` has learned the host PASSED the allowlist,
which is precisely where to point a rebinding attack. The reasons live in
gateway.jsonl, joined by decision_id, where the PoCs read them.

WHAT THE PAYLOAD MAY NEVER CARRY (M2-N3): justification, tool
descriptions, prior results, or any self-description by the caller. Those
are TESTIMONY by the party being judged. tool/args are the subject (and
the gateway re-resolves them itself); session and provenance are platform
state. Any new field must clear that test before it lands.
"""

from __future__ import annotations

import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import audit as audit_mod
import decide as decide_mod
import mode as mode_mod
import redact as redact_mod
from tools import documents, fetch

GATEWAY_ROOT = Path(__file__).resolve().parent
DEFAULT_POLICY_DIR = GATEWAY_ROOT / "policy"
DEFAULT_AUDIT_PATH = Path(os.getenv("GATEWAY_AUDIT_PATH", "audit/gateway.jsonl"))

# The uniform denial text. One string for every denial, whatever the
# reason -- see the module docstring on SR-B7-7.
DENIED_TEXT = "gateway denied"

KNOWN_TOOLS = ("read_document", "http_fetch")


class Config:
    """Everything the gate needs, resolved once at startup.

    Built by boot(), which refuses to return one if any piece is missing.
    A gateway that starts without a policy, without a redaction schema or
    without a writable audit path is a gateway that would fail open at
    the first call; failing at boot makes that impossible.
    """

    def __init__(self, policy_dir, policy_data, schema, audit, api_base,
                 tools_secret, opa_path=None, opa_timeout=decide_mod.DEFAULT_TIMEOUT,
                 hardened=False):
        self.policy_dir = policy_dir
        self.policy_data = policy_data
        self.schema = schema
        self.audit = audit
        self.api_base = api_base
        self.tools_secret = tools_secret
        self.opa_path = opa_path
        self.opa_timeout = opa_timeout
        # Parsed once, strictly, at boot (M2-N4). Reported on /healthz so
        # the API can refuse to start on a split brain.
        self.hardened = hardened

    @property
    def allowlist(self):
        """The egress allowlist, read from the SAME policy data OPA sees.

        One source, two consumers, and the duplication is deliberate
        rather than sloppy: OPA decides the call, and fetch() re-decides
        EVERY REDIRECT HOP, because only fetch() sees the hops
        (SR-B7-1). If these two read different lists, hop 1 and hop 2
        could be judged by different rules -- so they read one list.
        """
        return frozenset(self.policy_data.get("egress_allowlist", []))


def boot(policy_dir=None, audit_path=None) -> Config:
    """Boot probes: fail closed at startup, loudly, naming what is wrong.

    This is the startup half of D5.5. Every check here is something whose
    absence would otherwise surface as a confusing runtime failure three
    layers up in the agent -- or, worse, as a control that quietly does
    nothing.
    """
    policy_dir = Path(policy_dir or os.getenv("POLICY_DIR") or DEFAULT_POLICY_DIR)
    problems = []

    # Strict parse (M2-N4): "ture" is a refusal, never a silent default.
    # If it fails, assume hardened for the remaining probes so every
    # problem is reported at once -- boot refuses either way.
    try:
        hardened = mode_mod.from_env()
    except ValueError as exc:
        problems.append(str(exc))
        hardened = True

    policy_file = policy_dir / "policy.rego"
    data_file = policy_dir / "data.json"
    if not policy_file.exists():
        problems.append(f"no policy at {policy_file}")
    if not data_file.exists():
        problems.append(f"no policy data at {data_file}")

    policy_data = {}
    if data_file.exists():
        try:
            policy_data = json.loads(data_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            problems.append(f"policy data is not valid JSON: {exc}")

    schema = None
    try:
        schema = redact_mod.Schema.load(policy_dir / "redact.json")
    except (OSError, ValueError) as exc:
        problems.append(f"redaction schema unusable: {exc}")

    opa_path = os.getenv("OPA_BINARY") or decide_mod.find_opa()
    if not opa_path:
        problems.append("no opa binary on PATH (the gate cannot evaluate policy)")

    audit = None
    if schema is not None:
        try:
            audit = audit_mod.Audit.open(
                Path(audit_path or DEFAULT_AUDIT_PATH), schema)
        except OSError as exc:
            problems.append(f"audit path is not writable: {exc}")

    api_base = os.getenv("API_BASE_URL", "http://api:8080")
    tools_secret = os.getenv("TOOLS_SECRET", "")
    if not tools_secret and hardened:
        # D5b extended by the T6 mode-agreement check: an unset shared
        # secret is a startup failure, not a runtime 401 that looks like
        # a missing document three layers up. HARDENED only (T6 D3),
        # mirroring the API's loadToolsSecret: in vulnerable mode the API
        # registers no internal route and the agent never asks the gate,
        # so there is nothing for the secret to authenticate to -- and
        # `make up` must boot with no secrets set.
        problems.append("TOOLS_SECRET is not set (read_document cannot be mediated)")

    if problems:
        raise SystemExit(
            "gateway: refusing to start:\n  - " + "\n  - ".join(problems))

    return Config(policy_dir, policy_data, schema, audit, api_base,
                  tools_secret, opa_path=opa_path, hardened=hardened)


def healthz_body(cfg: Config) -> dict:
    """What /healthz answers. M2-N4's wire half.

    A BOOLEAN under "hardened", parsed at boot -- not the raw env string
    T5 reported under "mode". The API's probe accepts only this shape and
    treats anything else as no answer, so an old gateway image cannot
    pass the agreement check by accident.
    """
    return {"status": "ok", "hardened": bool(cfg.hardened)}


def enrich(tool: str, args: dict) -> tuple[dict, str]:
    """Establish the facts the policy will decide on.

    Returns (resolved, error). For http_fetch that means resolving the
    hostname ONCE and classifying the address; read_document has no
    network identity to resolve, so its decision inputs are capability
    and org, which are already fields.

    The gateway resolves. The policy never does -- no http.send from
    Rego, and no DNS from Rego either.
    """
    if tool != "http_fetch":
        return {}, ""

    url = args.get("url", "")
    if not url:
        return {}, "http_fetch requires a url"

    from urllib.parse import urlsplit

    parts = urlsplit(url)
    host = parts.hostname or ""
    if not host:
        return {}, f"no host in url {url!r}"
    if parts.scheme != "http":
        # fetch.py is HTTP-only by declared limitation; saying so here
        # keeps the reason honest instead of surfacing as a resolution
        # failure later.
        return {"host": host, "scheme": parts.scheme}, ""

    try:
        ip = fetch.default_resolve(host)
    except OSError as exc:
        return {"host": host}, f"could not resolve {host!r}: {exc}"

    return {
        "host": host,
        "ip": ip,
        # Computed here, in Python, by the same tested function the
        # fetcher uses -- ipaddress parsing, never string matching
        # (SR-B7-1). The policy consumes the boolean as a fact.
        "denied_range": fetch.is_denied_range(ip),
        "scheme": parts.scheme,
    }, ""


def execute(cfg: Config, tool: str, args: dict, session: dict):
    """Run an allowed call. Returns (outcome, text, summary).

    Only ever reached after a durable pre-record exists.
    """
    if tool == "read_document":
        res = documents.read_document(
            args.get("id", ""), session.get("org", ""),
            api_base=cfg.api_base, tools_secret=cfg.tools_secret)
        if not res.allowed:
            return "error", f"read_document failed: {res.reason}", res.reason
        text = f"{res.title}\n\n{res.body}"
        return "ok", text, f"{res.title} ({len(text)} bytes)"

    if tool == "http_fetch":
        res = fetch.fetch(args.get("url", ""), allowlist=cfg.allowlist)
        if not res.allowed:
            # The fetcher's own per-hop evaluation refused. For hop 1
            # this agrees with the policy by construction (same
            # allowlist, same range function); for hop 2+ it is the only
            # thing that could have caught it, which is why SR-B7-1
            # lives in the fetcher rather than in the gate.
            return "error", f"http_fetch failed: {res.reason}", res.reason
        final = res.hops[-1].url if res.hops else args.get("url", "")
        return "ok", res.body, f"{final} -> {res.status} ({len(res.body)} bytes)"

    return "error", f"unroutable tool {tool!r}", "unroutable"


def handle_gate(cfg: Config, payload: dict) -> tuple[int, dict]:
    """One decision, start to finish. Returns (status, body)."""
    tool = payload.get("tool", "")
    args = payload.get("args") or {}
    session = payload.get("session") or {}
    provenance = payload.get("provenance") or {"derived_from": []}

    if not isinstance(args, dict) or not isinstance(session, dict):
        return 400, {"error": "malformed request"}

    resolved, enrich_err = enrich(tool, args)

    if enrich_err:
        # Enrichment failed, so no decision can be made on facts. That is
        # a denial, recorded with its reason, not an exception: the call
        # was refused, and the record says why.
        decision = decide_mod.Decision("deny", ["enrichment_failed"], enrich_err)
    else:
        decision = decide_mod.decide(
            {
                "tool": tool,
                "args": args,
                "session": session,
                "provenance": provenance,
                "resolved": resolved,
            },
            policy_dir=str(cfg.policy_dir),
            opa_path=cfg.opa_path,
            timeout=cfg.opa_timeout,
        )

    # THE PRE-RECORD. Before execution, fsynced, and the id exists only
    # after it lands. A failure here refuses the call: no record, no
    # execution (SR-B5-6). It is reported as 5xx, not as a deny, because
    # nothing decided to refuse -- the gate could not record, which is
    # operational, and the harness must see exit 2 rather than mistake it
    # for a control holding.
    try:
        decision_id = cfg.audit.pre(
            tool=tool, args=args, session=session, provenance=provenance,
            resolved=resolved, route=decision.route, reasons=decision.reasons,
            detail=decision.detail)
    except OSError as exc:
        return 503, {"error": f"audit unavailable: {exc}"}

    if not decision.allowed:
        # Uniform denial. No reason, no detail -- see the module
        # docstring. The reasons are already in the record above.
        return 200, {
            "route": "deny",
            "decision_id": decision_id,
            "text": DENIED_TEXT,
            "summary": "",
        }

    start = time.monotonic()
    outcome, text, summary = execute(cfg, tool, args, session)
    duration_ms = int((time.monotonic() - start) * 1000)

    try:
        cfg.audit.post(decision_id, outcome=outcome, summary=summary,
                       duration_ms=duration_ms)
    except OSError:
        # The call already executed; losing the completion record must
        # not also lose the result. The pre-record -- the one that
        # matters for causation -- is already durable.
        pass

    if outcome != "ok":
        return 200, {
            "route": "deny",
            "decision_id": decision_id,
            "text": DENIED_TEXT,
            "summary": "",
        }

    return 200, {
        "route": "allow",
        "decision_id": decision_id,
        "reason": decision.reason,
        "text": text,
        "summary": summary,
    }


class Handler(BaseHTTPRequestHandler):
    cfg: "Config | None" = None  # set by serve()

    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):  # noqa: A002 - base class name
        sys.stderr.write("gateway: " + (format % args) + "\n")

    def _send(self, status: int, body: dict):
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path != "/healthz":
            self._send(404, {"error": "not found"})
            return
        # M2-N4: the gateway announces the mode it parsed at boot; the
        # API and the agent refuse to start unless it matches
        # (app/mode/gateway.go, mode.CheckGateway).
        self._send(200, healthz_body(self.cfg))

    def do_POST(self):
        if self.path != "/gate":
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send(400, {"error": "bad content-length"})
            return
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self._send(400, {"error": "malformed json"})
            return
        if not isinstance(payload, dict):
            self._send(400, {"error": "malformed json"})
            return

        status, body = handle_gate(self.cfg, payload)
        self._send(status, body)


def serve(cfg: Config, host="0.0.0.0", port=8081):  # pragma: no cover
    Handler.cfg = cfg
    server = ThreadingHTTPServer((host, port), Handler)
    sys.stderr.write(
        f"gateway: listening on {host}:{port} policy={cfg.policy_dir} "
        f"audit={cfg.audit.path}\n")
    server.serve_forever()


def main():  # pragma: no cover
    cfg = boot()
    serve(cfg, port=int(os.getenv("PORT", "8081")))


if __name__ == "__main__":  # pragma: no cover
    main()
