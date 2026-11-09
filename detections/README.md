# Detections — measured, not asserted

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

## M1 — the SR-B2-8 denial-burst rule (`rule.py`, `replay.py`)

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

## M2 — rules that read the inputs, not the verdicts

M1's detector read denials and caught 0 of 3 attacks in vulnerable mode, because nothing was denied. M2's gateway records **every call with its inputs** (SR-B5-9), and the vulnerable agent records its own unmediated calls in `agent.jsonl` (D4's second writer). So the M2 rules (`agent_rules.py`, pure functions, unit-tested in `test_agent_rules.py`) read *what was fetched, where it went and what content caused it*, and fire whether or not anything stopped the call.

| rule | fires on an `http_fetch`… | one alert per |
|---|---|---|
| **R1 `untrusted-fetch`** | whose provenance includes `untrusted`: its context held content the platform labelled untrusted. The injection pattern as a platform *fact*, not a regex on text. | session, at 1 call |
| **R2 `egress-off-allowlist`** | to a host not on the egress allowlist, read from `gateway/policy/data.json` (the gate's own file) | session, at 1 call |
| **R3 `metadata-endpoint`** | whose requested host, resolved address (hardened only: the gateway resolves, the vulnerable agent records no address) or **final URL after a completed redirect** is a cloud metadata endpoint (names + `169.254.169.254`, never the lab's own fixture IP) | session, at 1 call |

The threshold is **one call**, where M1's was five denials: a single denial is noise, but a single fetch of a credential endpoint is the incident. Alerts carry session, hosts (`asked -> reached` for a redirect) and decision ids, **never the URL**, because the exfiltration URL's query string *is* the stolen tenant data.

`make detect` replays five scenarios per mode (`replay_agent.py`), each in a fresh agent session, and asserts every cell: the exact set of rules that fired, which audit file grew, the deny-only baseline's verdict, and that no alert leaked in from another session. A cell whose window lacks the call its scenario exists to produce exits 2. Otherwise a false-positive row would "stay silent" about a fetch nobody attempted.

| scenario | vulnerable: rules | vulnerable: deny-only | hardened: rules | hardened: deny-only |
|---|---|---|---|---|
| 03 injection | **R1 + R2** | miss | **R1 + R2** | fires |
| 03 clean control *(FP row)* | none | silent | none | silent |
| 04 direct | **R3** | miss | **R3** | fires |
| 04 redirect | **R2 + R3** | miss | **R2** | fires |
| benign fetch, allowlisted `docs.example` *(FP row)* | none | silent | none | **fires** |
| **attacks caught** | **3/3** | **0/3** | **3/3** | 3/3 |
| **controls fired on** | 0/2 | 0/2 | 0/2 | **1/2** |

## M2 — what the matrix measures

**Reading inputs decouples detection from the control.** The deny-only baseline is M1's detector run over M2's records. It reproduces M1's result exactly: blind in vulnerable mode (0/3), and in hardened mode it catches everything only because the gate is doing the catching. The input-reading rules catch 3/3 in **both** modes. In vulnerable mode they see the exfiltration *that succeeded*, from the agent's own honest telemetry. **The vulnerability is the missing gate, not the missing telemetry.**

**A denial is not an attack.** The benign fetch fails closed in hardened mode (`docs.example` does not resolve in the lab: `enrichment_failed`), and the deny-only baseline alerts on it. The input-reading rules stay silent because a user asked for an allowlisted host. That is the false-positive row doing its job.

**Every rule is coupled to something, and the couplings are declared:**

- **R2 shares the gate's allowlist.** A detector that reads the control's *data* is coupled to that data being right, which is M1's lesson one level up. Demonstrated live, by hand (not a committed test): with `attacker.example` added to the detector's allowlist, the replay exits 1. 03 is still caught by R1, but **the hardened 04-redirect row goes completely dark**, because only R2 could see it.
- **R3 deliberately ignores the allowlist**, and the shipped policy shows why. `metadata.google.internal` *is* allowlisted (so finding 04 can pass the allowlist and die on its resolved address, D6), so R2 alone is blind to 04.
- **R3's redirect leg reads the completion record's final URL.** Without it, the vulnerable 04-redirect run names only `attacker.example`, and the metadata hit is invisible. It is coupled to the summary format `URL -> status (n bytes)`, which a test pins.
- **R3's other legs have edges too.** The resolved-address leg needs the gateway's enrichment, so in vulnerable mode a hostname that *resolves* to `169.254.169.254` is missed. The redirect leg needs a completed fetch, so a redirect whose last hop errored is missed.
- **R1 is taint, so it over-approximates.** A fetch made after *any* untrusted content entered the context fires, including one the user asked for after reading a document. The false-positive rows don't exercise that case (the scripted model fetches before it reads), so R1's only meaningful silent cell is the hardened benign fetch. Its false-positive rate is declared, not measured.
- **R1 trusts platform provenance.** In vulnerable mode the naive assembler merges the *stored* transcript, so untrusted content already stored before the run is invisible to R1. A document read *during* the run keeps its label, which is the 03 path, pinned by `TestNaiveLoopStillLabelsInRunToolResults`. The fallback, a read-then-fetch sequence rule, is declared and not built.

**The writer contrast is asserted, not assumed.** Vulnerable runs grow `agent.jsonl` only, and hardened runs grow `gateway.jsonl` only. If the hardened agent ever writes `agent.jsonl`, it executed a tool itself (D5 broken), and the replay fails. A window with no records at all exits 2: nothing was looked at, and that is not a miss.
