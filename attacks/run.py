#!/usr/bin/env python3
"""Run every attacks/NN-*/ PoC and assert its two-mode contract.

This is the regression harness the plan's DoD asks for. Its semantics are
inverted from a normal test suite, on purpose (attacks/README.md):

- vulnerable mode: every exploit must SUCCEED (exit 0). A failure here is a
  regression too -- someone broke the vulnerable path by accident, or
  silently "fixed" a planted bug out from under the answer key.
- hardened mode: every exploit must be BLOCKED (its expected hardened exit
  code, with the control-holds marker). An exit 0 here is the loudest alarm
  in the repo: a control stopped working.
- an operational error (exploit exit 2, or a harness timeout) fails the suite
  in BOTH modes. A stack outage must never read as "exploit succeeded" and
  never as "control held" -- an unattended suite that cannot tell an outage
  from a verdict is not a test.

Findings are discovered by glob (0*-*/ with an exploit.py and an
expected.json), so M2+ findings join the suite by existing: a new directory
appears, this file is not edited. The suite grows by addition, not by
modification -- the same paved-road argument as store.ForOrg(ctx): a rule
you satisfy by adding an artifact beats a rule you satisfy by remembering
to edit a list.

Each run also cross-asserts the OPPOSITE mode's marker is absent, so a PoC
that prints "CONTROL HOLDS" in vulnerable mode (or the leaked-title evidence
in hardened mode) fails even if its exit code happens to match. Exit codes
say what happened; stdout says why -- assert both, and assert they agree.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

ATTACKS_DIR = Path(__file__).resolve().parent
EXPLOIT_TIMEOUT_S = 120


def findings():
    """Every attacks/NN-*/ dir that obeys the contract, sorted by finding no."""
    return sorted(
        p for p in ATTACKS_DIR.glob("0*-*")
        if (p / "exploit.py").is_file() and (p / "expected.json").is_file()
    )


def run_one(d, mode, base_url):
    """Run one exploit and assert its expected.json for this mode.

    Returns (ok: bool, detail: str). Never raises -- a harness that crashes
    on a bad finding produces no report at all.
    """
    try:
        expected = json.loads((d / "expected.json").read_text())
    except (OSError, ValueError) as e:
        return False, f"unreadable expected.json: {e}"

    want = expected[mode]
    other = expected["hardened" if mode == "vulnerable" else "vulnerable"]

    try:
        proc = subprocess.run(
            [sys.executable, str(d / "exploit.py"), "--base-url", base_url],
            capture_output=True, text=True, timeout=EXPLOIT_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return False, f"exploit timed out after {EXPLOIT_TIMEOUT_S}s (operational)"

    problems = []
    if proc.returncode != want["exit_code"]:
        problems.append(
            f"exit code {proc.returncode}, expected {want['exit_code']}"
            + (" (exploit reported an operational error -- an outage is a suite failure, not a verdict)" if proc.returncode == 2 else "")
        )
    if want["stdout_contains"] not in proc.stdout:
        problems.append(f"stdout missing expected evidence: {want['stdout_contains']!r}")
    if other["stdout_contains"] in proc.stdout:
        problems.append(
            f"stdout contains the OTHER mode's marker {other['stdout_contains']!r}"
        )

    detail = "; ".join(problems) if problems else ""
    if problems and proc.stdout.strip():
        detail += f"\n    --- exploit stdout ---\n    " + "\n    ".join(proc.stdout.strip().splitlines()[-12:])
    return (not problems), detail


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", choices=["vulnerable", "hardened"], required=True)
    ap.add_argument("--base-url", default="http://localhost:8080")
    args = ap.parse_args()

    dirs = findings()
    if not dirs:
        print("attack suite: no findings found (attacks/0*-*/ with exploit.py + expected.json)")
        return 1

    verb = "SUCCEED (vulnerability present)" if args.mode == "vulnerable" else "be BLOCKED (control holds)"
    print(f"attack suite [{args.mode}] against {args.base_url}")
    print(f"  every exploit must {verb}\n")

    failures = 0
    for d in dirs:
        ok, detail = run_one(d, args.mode, args.base_url)
        print(f"  {'PASS' if ok else 'FAIL'}  {d.name}")
        if not ok:
            failures += 1
            print(f"    {detail}")
    print()
    print(f"attack suite [{args.mode}]: {len(dirs) - failures}/{len(dirs)} behaved as {args.mode} mode demands")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
