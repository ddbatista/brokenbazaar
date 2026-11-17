#!/usr/bin/env python3
"""Fault injection: break the gate for real, and prove nothing passes.

    JWT_SECRET=... TOOLS_SECRET=... make harden && python3 attacks/faults.py

SR-B5-5 says fail-closed is VERIFIED, and D5.5 says by fault injection,
not by reading the code. On a HARDENED stack (checked, not assumed),
each fault is applied for real, every exploit that drives the agent is
run under it (discovered, M3 T9 D1), and every one
must exit 2 (operational) naming the fault -- never 1. An
exploit that exits 1 while the gate is broken is a SILENT PASS: the
suite would report "control held" about a control that was not there to
hold. That is the outcome T8 exists to make impossible (T8 D2).

    F1  OPA removed from inside the LIVE gateway: the gateway is up and
        answering, but cannot decide. It fails closed (opa_unavailable);
        the exploits must recognise that deny as the gate breaking, not
        a control judging.
    F2  gateway stopped: the agent's startup probe finds no gateway and
        the agent refuses to start (M2-N4).
    F3  the authority route unreachable (M3 T9 D3, SR-B8-4): inside the
        LIVE gateway, `api` is pointed at 127.0.0.1, so the gateway's calls
        to the API are refused while everything else -- its own health,
        DNS for fetches, the agent's probe -- still works. The gateway
        cannot establish the session's authority and fails closed
        (enrichment_failed, "authority route unreachable"). M3 made the
        authority route a dependency of every decision; a new dependency
        is a new fault.

All three are deterministic. The mid-request window -- the gateway dying
between the agent's probe and its /gate call -- is declared covered by
unit tests rather than a timed kill that could flake: the Go executor
fails closed on transport errors (app/agent), and agentlab parses a
stopped run as operational (attacks/test_agentlab.py).

Every fault is undone in a `finally`, and recovery is checked against
the thing the fault removed -- for F1 the OPA binary itself, because the
gateway's /healthz never calls OPA and stays "healthy" throughout (found
at T8 review). A fault case that leaves the stack broken would poison
whatever runs next.

Exit: 0 every case behaved; 1 a silent pass, a wrong verdict or a hung
exploit; 2 this check could not run (stack not hardened, a fault could
not be applied or undone, an unexpected crash).
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, NamedTuple

import agentlab as lab
from agentlab import EXIT_CONTROL_HELD, EXIT_OPERATIONAL, EXIT_VULNERABLE, REPO

HERE = Path(__file__).resolve().parent
OPA = "/usr/local/bin/opa"
HOSTS = "/etc/hosts"
EXPLOIT_TIMEOUT_S = 300


def drives_agent(source: str) -> bool:
    """Does an exploit's source run the agent (and so meet the gate)?"""
    import re
    return re.search(r"\blab\.(ask|run_agent|resume)\(", source) is not None


def agent_exploits():
    """Every attacks/0*-*/ finding whose exploit drives the agent (M3 T9 D1).

    Discovered, like run.py's findings: a new agent finding is run under
    every fault by existing, not by someone remembering to edit a list.
    The API-only exploits (01, 02) never meet the gate, so a gate fault
    says nothing about them.
    """
    return sorted(p for p in HERE.glob("0*-*")
                  if (p / "exploit.py").is_file() and drives_agent((p / "exploit.py").read_text()))


def judge(exit_code: int, stdout: str, cause: str):
    """(ok, why) for one exploit run under one fault."""
    if exit_code == EXIT_CONTROL_HELD:
        return False, "SILENT PASS: exit 1 ('control held') while the gate was broken"
    if exit_code == EXIT_VULNERABLE:
        return False, "exit 0 ('vulnerable') while the gate was broken"
    if exit_code != EXIT_OPERATIONAL:
        return False, f"unexpected exit {exit_code}"
    if cause not in stdout:
        return False, f"exit 2, but not for the injected fault: stdout never names {cause!r}"
    return True, f"exit 2, naming {cause!r}"


def compose(*args, timeout=120):
    try:
        proc = subprocess.run(["docker", "compose", *args], cwd=REPO,
                              capture_output=True, text=True, timeout=timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise lab.Operational(f"docker compose {' '.join(args)}: {exc}") from None
    if proc.returncode != 0:
        raise lab.Operational(f"docker compose {' '.join(args)}: {proc.stderr[-300:]}")
    return proc


def gateway_healthy(timeout=60) -> bool:
    """Docker's own healthcheck verdict for the gateway container.

    `docker inspect`, not `docker compose ps --format`: the latter's Go
    template is unsupported on Compose 2.13 and silently read as
    "unhealthy" -- found on first run.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        proc = subprocess.run(["docker", "inspect", "-f", "{{.State.Health.Status}}", "bb-gateway"],
                              capture_output=True, text=True, timeout=10)
        if proc.stdout.strip() == "healthy":
            return True
        time.sleep(2)
    return False


def api_reachable_from_gateway() -> bool:
    """Can the gateway reach the API's health route? (F3's recovery check)"""
    try:
        proc = subprocess.run(
            ["docker", "compose", "exec", "-T", "gateway", "python3", "-c",
             "import urllib.request; urllib.request.urlopen('http://api:8080/healthz', timeout=5)"],
            cwd=REPO, capture_output=True, timeout=30)
    except subprocess.TimeoutExpired:
        return False
    return proc.returncode == 0


def opa_present() -> bool:
    proc = subprocess.run(["docker", "compose", "exec", "-T", "gateway", "test", "-x", OPA],
                          cwd=REPO, capture_output=True, timeout=30)
    return proc.returncode == 0


class Fault(NamedTuple):
    title: str
    apply: Callable[[], object]
    undo: Callable[[], object]
    recovered: Callable[[], bool]   # checks the thing the fault removed
    cause: str                      # what the exploit's stdout must name


FAULTS = (
    Fault("F1 OPA removed from the live gateway",
          lambda: compose("exec", "-T", "-u", "root", "gateway", "mv", OPA, OPA + ".fault"),
          lambda: compose("exec", "-T", "-u", "root", "gateway", "mv", OPA + ".fault", OPA),
          lambda: opa_present() and gateway_healthy(),
          "opa_unavailable"),
    # F2's cause is the agent's own refusal (app/mode/gateway.go). Coupled
    # to that message on purpose: if it is reworded, this case fails
    # loudly rather than accepting any exit 2 as "the gateway was down".
    Fault("F2 gateway container stopped",
          lambda: compose("stop", "gateway"),
          lambda: compose("start", "gateway"),
          gateway_healthy,
          "gave no usable mode"),
    # F3's cause is the gateway's own detail (gateway/authority.py), which
    # the exploits print since M3 T9 D2. Coupled on purpose, like F2's.
    # /etc/hosts is a bind mount, so it is rewritten in place (cat >), never
    # replaced (mv), and restored byte for byte from the saved copy.
    Fault("F3 authority route unreachable (api -> 127.0.0.1 inside the gateway)",
          lambda: compose("exec", "-T", "-u", "root", "gateway", "sh", "-c",
                          f"cp {HOSTS} {HOSTS}.fault && echo '127.0.0.1 api' >> {HOSTS}"),
          # cp, not `cat >`: the shell truncates before cat runs, so a
          # missing copy would leave /etc/hosts EMPTY. cp fails first.
          lambda: compose("exec", "-T", "-u", "root", "gateway", "sh", "-c",
                          f"cp {HOSTS}.fault {HOSTS} && rm {HOSTS}.fault"),
          lambda: api_reachable_from_gateway() and gateway_healthy(),
          # The REASON and the detail together, as check_not_failed_closed
          # prints them: the route unreachable must deny as enrichment_failed
          # (SR-B8-4), not merely be mentioned.
          "'enrichment_failed': authority route unreachable"),
)


def run_exploit(name: str):
    try:
        proc = subprocess.run([sys.executable, str(HERE / name / "exploit.py")],
                              capture_output=True, text=True, timeout=EXPLOIT_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        # A hung exploit under a fault is a real failure of fail-FAST,
        # reported as such -- not a crash of this checker.
        return None, f"(timed out after {EXPLOIT_TIMEOUT_S}s)"
    return proc.returncode, proc.stdout


def _undo(fault: Fault) -> bool:
    """Undo a fault; False (and a loud line) if the stack is left broken."""
    try:
        fault.undo()
    except lab.Operational as exc:
        print(f"OPERATIONAL ERROR: could not undo {fault.title} -- the stack is still broken: {exc}")
        return False
    return True


def check() -> int:
    if not lab.stack_hardened("http://localhost:8080"):
        raise lab.Operational("the stack is VULNERABLE -- faults test the hardened gate; run `make harden`")
    if not (opa_present() and gateway_healthy(timeout=10) and api_reachable_from_gateway()):
        raise lab.Operational(
            "the gateway is not healthy (OPA missing, or the API unreachable) before any fault -- a "
            "fault run that was killed mid-way leaves its fault applied; recreate the gateway "
            "(`docker compose up -d --force-recreate gateway`, with the hardened env) and retry")
    exploits = [p.name for p in agent_exploits()]
    if not exploits:
        raise lab.Operational("no agent exploit found to run under the faults")
    failures = 0
    for fault in FAULTS:
        print(f"== {fault.title}")
        fault.apply()
        try:
            for name in exploits:
                code, out = run_exploit(name)
                ok, why = (False, f"hung {out}") if code is None else judge(code, out, fault.cause)
                print(f"   {'PASS' if ok else 'FAIL'}  {name}: {why}")
                if not ok:
                    failures += 1
                    print("      " + "\n      ".join(out.strip().splitlines()[-6:]))
        finally:
            undone = _undo(fault)
        if not undone:
            return EXIT_OPERATIONAL
        if not fault.recovered():
            raise lab.Operational(f"{fault.title}: undone, but the stack did not recover")
        print("   recovered: the removed piece is back and the gateway is healthy")
    print()
    if failures:
        print(f"faults: {failures} run(s) did NOT fail closed as exit 2 -- see above")
        return 1
    print(f"faults: every exploit exited 2 under every fault ({len(FAULTS)} faults x {len(exploits)} exploits)")
    return 0


def main() -> int:
    try:
        return check()
    except lab.Operational as exc:
        print(f"OPERATIONAL ERROR: {exc}")
    except Exception as exc:  # noqa: BLE001 - a crashed checker has judged nothing
        print(f"OPERATIONAL ERROR: the fault checker crashed: {type(exc).__name__}: {exc}")
    return EXIT_OPERATIONAL


if __name__ == "__main__":
    sys.exit(main())
