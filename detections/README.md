# Detections — measured, not asserted

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

## M1 — the SR-B2-8 denial-burst rule

The product logs every authz denial in **both** modes (T5):

    2026/10/20 03:20:47 authz: deny sub=<uuid> target_org=<uuid> decision=not-a-member

The rule (`rule.py`, pure function, unit-tested in `test_rule.py`): alert when one principal accumulates **≥ 5 denials**. Per-principal, deliberately not per (principal, org) pair — a per-pair threshold would let an attacker spread 4 probes across every org and stay silent forever. Alert carries its evidence: sub, count, distinct target orgs, a sample line.

`make detect` replays the PoCs against the live stack in both modes and asserts the full detect/miss matrix (`replay.py`):

| scenario | vulnerable | hardened |
|---|---|---|
| 01 honest cross-tenant search | attack succeeds, **miss** | blocked silently (query scoping, SR-M1-4), **miss** |
| 02 forged `alg:none` create | attack succeeds, **miss** | blocked at the verifier (SR-B2-3, before authz), **miss** |
| probe sweep: honest token, foreign org in path ×7 | succeeds (no membership check exists), **miss** | 404 per probe, **DETECT** |

## What the matrix measures — the honest result

**In vulnerable mode the detector catches 0 of 3 attacks.** All three succeed, and a denial-based detector can only see denials. This is not a rule failure; it is the structural coupling the matrix exists to expose:

> **A denial-based detector is coupled to the control working.** Where the control blocks *silently* — indistinguishability (SR-M1-4) makes the hardened 404 and "no such org" the same line — or blocks *earlier* (the verifier, before authz exists), detection is blind by design.

That is why the T7 regression suite (`make attack`, CI on every push) and this detector are **complementary mechanisms covering disjoint failure worlds**: the suite catches the day a control *stops working* (exploit flips to exit 0 → CI red); the detector catches the *live attacker probing a working system* (denial burst → alert). Neither covers the other's world. The matrix is the measured proof of that claim, printed on every `make detect`.

## Collection window is part of the rule's correctness

bb-api's container logs persist across mode flips, so `replay.py` snapshots log length before each scenario and analyzes only the delta. Stale denials from a previous mode leaking into the current measurement would inflate both the counts and the credibility. A detector whose input window is wrong is wrong even when its logic is right.
