#!/usr/bin/env python3
"""MCP01 in the live stack: no platform secret survives into an audit store.

    python3 attacks/leakscan.py        # against a running HARDENED stack

SR-B7-5 requires secrets redacted at audit write time. The unit tests
prove the redaction MECHANISM in-process (field-name schema, D5.4). This
proves the OUTCOME on real runs: after both attack suites, the four
places a run writes -- gateway.jsonl, agent.jsonl, and the DB's
messages and tool_calls -- contain none of the secrets this stack holds,
and no bearer JWT (T8 D3).

WHERE THE SECRETS COME FROM, and why: the running containers
(`docker inspect`), and the committed dev key from app/api/main.go
itself. Not from a copy. A scan given its own copy of a secret drifts
silently: edit the value the stack runs with and not the copy, and the
scan searches for a string the stack never had, and reports clean
(found at T8 review). If JWT_SECRET/TOOLS_SECRET are ALSO set in this
process's environment they must agree with the stack's, or the run
refuses.

Why this is not the value-pattern redaction M2-N2 rejected: that was a
CONTROL guessing what secrets look like. This is a TEST ORACLE that
knows the exact secrets. The one shape it matches, a JWT, is a fixed
structure: two base64url JSON segments, then a signature that may be
EMPTY -- an alg:none token, finding 02's own shape, has none.

Declared exclusions (R-M2-2, the free-form residual):
- the fake SA token in the transcript: finding 04's evidence, by design;
  tool output the attacker asked for, not a platform credential;
- anything not a known secret and not JWT-shaped. A green scan means
  "no KNOWN secret leaked", never "nothing sensitive is stored".

Exit: 0 clean, 1 a leak (named, never printed), 2 cannot judge (a store
or a secret unreadable, a store empty -- scanning nothing proves nothing).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass

from agentlab import EXIT_OPERATIONAL, REPO, Operational

MIN_SECRET_LEN = 8

# What the scan looks for, by NAME. Output is built from this constant,
# never from the dict of values: CodeQL (py/clear-text-logging-sensitive-
# data, PR #4) flagged a banner derived from that dict. It printed keys
# only, but one `.items()` from printing values -- a scan for leaked
# secrets must not be one edit away from being the leak.
SECRET_NAMES = ("DEV_JWT_SECRET", "JWT_SECRET", "TOOLS_SECRET")
API_MAIN = REPO / "app" / "api" / "main.go"

JWT_SHAPE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
DEV_SECRET_DECL = re.compile(r'devJWTSecret\s*=\s*"([^"]+)"')


@dataclass(frozen=True)
class Leak:
    store: str
    kind: str
    count: int

    def __str__(self):  # never includes the secret itself
        return f"{self.store}: {self.kind} found {self.count} time(s)"


def find_leaks(store: str, text: str, secrets: dict) -> list:
    """Every known secret and JWT in text, longest secret first.

    Matched spans are masked before shorter secrets are searched, so a
    secret that is a substring of another is not double-counted.
    """
    for kind, value in secrets.items():
        if len(value or "") < MIN_SECRET_LEN:
            raise ValueError(f"refusing to scan for {kind}: a secret under "
                             f"{MIN_SECRET_LEN} chars makes the scan meaningless")
    leaks = []
    for kind, value in sorted(secrets.items(), key=lambda kv: -len(kv[1])):
        count = text.count(value)
        if count:
            leaks.append(Leak(store, kind, count))
            text = text.replace(value, "\x00" * len(value))
    jwts = JWT_SHAPE.findall(text)
    if jwts:
        leaks.append(Leak(store, "JWT", len(jwts)))
    return leaks


def require_content(stores: dict):
    empty = [name for name, text in stores.items() if not text.strip()]
    if empty:
        raise Operational(f"empty store(s): {', '.join(empty)} -- run both attack suites "
                          "first; scanning nothing proves nothing")


def env_value(env: list, name: str) -> str:
    """A variable's value from a container's `NAME=value` list ('' if absent)."""
    prefix = name + "="
    return next((e[len(prefix):] for e in env if e.startswith(prefix)), "")


def dev_secret_from(go_source: str) -> str:
    """The committed vulnerable-mode signing key, read from its declaration."""
    match = DEV_SECRET_DECL.search(go_source)
    if not match:
        raise Operational("cannot find devJWTSecret in app/api/main.go -- the scan would miss it")
    return match.group(1)


def _run(args):
    try:
        proc = subprocess.run(args, cwd=REPO, capture_output=True, text=True, timeout=60)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise Operational(f"{' '.join(args[:4])}: {exc}") from None
    if proc.returncode != 0:
        raise Operational(f"{' '.join(args[:4])} failed: {proc.stderr[-300:]}")
    return proc.stdout


def container_env(name: str) -> list:
    return json.loads(_run(["docker", "inspect", "-f", "{{json .Config.Env}}", name]))


def known_secrets() -> dict:
    api = container_env("bb-api")
    gateway = container_env("bb-gateway")
    secrets = {
        "DEV_JWT_SECRET": dev_secret_from(API_MAIN.read_text(encoding="utf-8")),
        "JWT_SECRET": env_value(api, "JWT_SECRET"),
        "TOOLS_SECRET": env_value(api, "TOOLS_SECRET"),
    }
    for name in ("JWT_SECRET", "TOOLS_SECRET"):
        if not secrets[name]:
            raise Operational(f"the running api has no {name} -- scan a HARDENED stack "
                              "(the vulnerable one has no service secret to leak)")
    if env_value(gateway, "TOOLS_SECRET") != secrets["TOOLS_SECRET"]:
        raise Operational("api and gateway hold different TOOLS_SECRETs -- the stack is "
                          "misconfigured; the scan would cover only one of them")
    if set(secrets) != set(SECRET_NAMES):
        raise Operational("the secrets read do not match SECRET_NAMES -- fix the scan, not the check")
    for name in ("JWT_SECRET", "TOOLS_SECRET"):
        mine = os.environ.get(name)
        if mine and mine != secrets[name]:
            raise Operational(f"{name} in this environment differs from the running stack's -- "
                              "refusing to scan for a value the stack never had")
    return secrets


def read_stores() -> dict:
    gw = ["docker", "compose", "exec", "-T", "gateway", "cat"]
    sql = ["docker", "compose", "exec", "-T", "db", "psql", "-U", "bazaar", "-d", "bazaar", "-Atc"]
    return {
        "gateway.jsonl": _run(gw + ["/audit/gateway.jsonl"]),
        "agent.jsonl": _run(gw + ["/audit/agent.jsonl"]),
        "messages": _run(sql + ["SELECT body FROM messages"]),
        "tool_calls": _run(sql + ["SELECT arguments::text || ' ' || coalesce(result_summary, '') FROM tool_calls"]),
    }


def scan_banner() -> str:
    return f"for {', '.join(SECRET_NAMES)} (read from the running stack) and bearer JWTs"


def main() -> int:
    try:
        secrets = known_secrets()
        stores = read_stores()
        require_content(stores)
        leaks = [leak for name, text in stores.items() for leak in find_leaks(name, text, secrets)]
    except (Operational, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"OPERATIONAL ERROR: {exc}")
        return EXIT_OPERATIONAL
    sizes = ", ".join(f"{n} ({len(t.splitlines())} lines)" for n, t in stores.items())
    print(f"scanned {sizes}")
    print(scan_banner())
    if leaks:
        for leak in leaks:
            print(f"LEAK: {leak}")
        print("MCP01: a platform secret reached an audit store (SR-B7-5)")
        return 1
    print("clean: no known secret and no JWT in any store (free-form residual declared, R-M2-2)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
