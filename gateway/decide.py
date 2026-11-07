"""The OPA decide flow, ported from jev-lab's decide.py.

WHAT IS PORTED, and why each piece earns its place:

  * ENRICH THEN EVALUATE. The gateway resolves the hostname, computes
    whether the address falls in a denied range, and hands those FACTS to
    the policy. The policy decides; it never fetches.

  * NO http.send FROM REGO. A policy that dials is a policy whose
    decision depends on the network being up and on whatever answered.
    This is also why OPA is a subprocess against local files rather than
    `opa run --server`: a network hop per evaluation is the same coupling
    one layer down (PROPOSED-DEPS.md, T0).

  * FAIL-CLOSED DEFAULTS. Every failure mode below returns a DENY, never
    an allow and never an exception that a caller might catch and
    proceed past.

  * THE STRUCTURED DECISION DOC. A route plus reasons, not a boolean.
    The reasons never reach the agent (D5.3 -- they are an existence
    oracle); they go to gateway.jsonl, where the PoCs read them.

WHAT IS NOT PORTED: judge.py, provider thresholds, confidence bands,
abstention, judge_unavailable. D2 traced both M2 findings and found the
judge is never consulted -- read_document is decidable by capability and
org scope, http_fetch by allowlist plus provenance -- so M4a owns it,
where the first genuinely ambiguous call appears.

THE FOUR FAILURE MODES, each with a shim in test_faults/ (D5.5):

    process died (non-zero exit)     -> deny opa_unavailable
    process hung (timeout)           -> deny opa_unavailable
    unusable output (exit 0, junk)   -> deny opa_unavailable
    well-formed JSON, wrong shape    -> deny opa_unavailable

The third is the nastiest and the reason the shims exist at all: a gate
that checks only the exit code treats a garbage-printing OPA as success
and then reads whatever it can from an empty parse -- which, with a
sloppy default, becomes an allow. Reading the rego would never catch
that; killing the process does.
"""

from __future__ import annotations

import json
import shutil
import subprocess

OPA_UNAVAILABLE = "opa_unavailable"

# The Rego entrypoint. One query, one decision document.
DECISION_QUERY = "data.bazaar.gate.decision"

DEFAULT_TIMEOUT = 5.0


class Decision:
    """A policy decision: a route, the reasons behind it, and detail.

    `reasons` is ordered by evaluation leg, and the policy reports only
    the FIRST failing leg (D5.3/D6): finding 03 must die at the allowlist
    and finding 04 at the range check, and a gate that reported every
    failing leg would give finding 03 both reasons, since the attacker
    fixture also sits in RFC1918 space on the Compose bridge.
    """

    __slots__ = ("route", "reasons", "detail")

    def __init__(self, route: str, reasons=None, detail: str = ""):
        self.route = route
        self.reasons = list(reasons or [])
        self.detail = detail

    @property
    def allowed(self) -> bool:
        return self.route == "allow"

    @property
    def reason(self) -> str:
        return self.reasons[0] if self.reasons else ""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Decision(route={self.route!r}, reasons={self.reasons!r})"


def find_opa(explicit=None) -> str | None:
    """Locate the OPA binary.

    The container copies it to /usr/local/bin/opa from the digest-pinned
    image (T0). OPA_BINARY overrides, which is how the fault shims are
    injected without touching this code.
    """
    if explicit:
        return explicit
    return shutil.which("opa")


def decide(input_doc: dict, *, policy_dir: str, opa_path=None,
           timeout: float = DEFAULT_TIMEOUT) -> Decision:
    """Evaluate one call against the policy. Returns a Decision, always.

    This function does not raise. Every path out of it is a route, so a
    caller cannot accidentally proceed past a failure -- there is no
    exception to swallow and no None to misread as falsy-but-fine.
    """
    opa = find_opa(opa_path)
    if not opa:
        return Decision("deny", [OPA_UNAVAILABLE], "no opa binary on PATH")

    cmd = [opa, "eval", "-d", policy_dir, "-I", "-f", "json", DECISION_QUERY]
    try:
        proc = subprocess.run(
            cmd,
            input=json.dumps(input_doc),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        # A gate that waits forever is a denial-of-service, not a
        # control. The wall-clock assertion in test_gate.py is what makes
        # this a measured property rather than an intention.
        return Decision("deny", [OPA_UNAVAILABLE],
                        f"policy evaluation exceeded {timeout}s")
    except OSError as exc:
        return Decision("deny", [OPA_UNAVAILABLE], f"could not run opa: {exc}")

    if proc.returncode != 0:
        return Decision("deny", [OPA_UNAVAILABLE],
                        f"opa exited {proc.returncode}: {proc.stderr.strip()[:200]}")

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        # Exit 0 and unusable output. See the module docstring.
        return Decision("deny", [OPA_UNAVAILABLE], f"opa output is not JSON: {exc}")

    value = _extract(payload)
    if value is None:
        return Decision("deny", [OPA_UNAVAILABLE],
                        "opa returned no decision for " + DECISION_QUERY)

    route = value.get("route")
    if route not in ("allow", "deny"):
        # Well-formed JSON in a shape this gate does not understand. The
        # vocabulary is closed on purpose: an unrecognised route is a
        # policy/gate version mismatch, and the safe reading of a
        # mismatch is deny.
        return Decision("deny", [OPA_UNAVAILABLE],
                        f"opa returned an unknown route {route!r}")

    reasons = value.get("reasons") or []
    if not isinstance(reasons, list):
        return Decision("deny", [OPA_UNAVAILABLE], "opa returned malformed reasons")

    return Decision(route, [str(r) for r in reasons], str(value.get("detail", "")))


def _extract(payload):
    """Pull the decision value out of `opa eval -f json` output.

    Shape: {"result": [{"expressions": [{"value": ...}]}]}. An empty
    result list means the query was undefined, which is not an error to
    OPA and IS an error to us: a gate with no decision has not decided.
    """
    try:
        result = payload["result"]
        if not result:
            return None
        value = result[0]["expressions"][0]["value"]
    except (KeyError, IndexError, TypeError):
        return None
    return value if isinstance(value, dict) else None
