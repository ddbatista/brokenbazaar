# Detections — measured, not asserted

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

## M1 — the SR-B2-8 denial-burst rule (`rule.py`, `replay.py`)

The product logs every authz denial in **both** modes (T5):

    2026/10/20 03:20:47 authz: deny sub=<uuid> target_org=<uuid> decision=not-a-member

Since M3 T3 the API also logs a **second, different** denial, in both modes: a member whose role does not permit the action (403):

    2026/11/13 22:42:47 authz: deny sub=<uuid> org=<uuid> decision=role-does-not-permit role="viewer" action=delete

Its org field is `org=`, not `target_org=`, **on purpose**. This rule reads `target_org=` as "an org this principal is probing from outside" and alerts on a sweep across orgs. A member refused inside their *own* org is a different signal: capability escalation, which M3's R6 reads (below). If the formats matched, this rule would count role denials as cross-tenant probes. So `DENY_RE` does not match the new line; R6 does.

Since M3 T6 there is a **third**, hardened mode only: an internal execution route refusing a call the gateway had allowed, because the session's authority failed when the API re-checked it at execution (M3-N2: a demotion, an expiry or a removal landing between the gate's decision and the write):

    2026/11/16 15:02:11 authz: deny session=<uuid> org=<uuid> decision=role-does-not-permit tool=delete_document at=execution

It carries `session=`, not `sub=`: the caller is the gateway, acting for a session, not a user. `decision=` uses the same hyphenated spelling as the T3 line, so one reason has one spelling across the API's logs. The gateway records the same event in `gateway.jsonl` as a completion with `outcome: "refused_at_execution"` and the failing check as its summary. `DENY_RE` does not match this line either; R6 reads both.

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

## M3 — delegated authority: the signal is a relation, not an input

M2's rules could judge a fetch from the fetch alone. A host off the allowlist or a metadata address is suspicious whoever asked. M3's findings are about authority, and **finding 05 has no suspicious input at all.** A viewer asks their own agent, in their own words, to delete a document. Nothing is injected, and the call looks exactly like an admin's permitted delete. The signal is a *relation*: the call, against what the acting user's role permits **at that moment**. Only the hardened gateway derives that role (`authority.role_now` on every pre-record). The vulnerable agent records who acted (`acting_for`), never what they were allowed to do.

The rules (`delegation_rules.py`, pure functions, unit-tested in `test_delegation_rules.py`) are the threat model's detection shapes (`threat-models/m3-delegation.md`). Each alerts on **one** event, once per principal (a session, or a user for the direct route):

| rule | fires on | reads |
|---|---|---|
| **R4 `control-plane-call`** | any call to a tool in the policy's `non_delegable` set, whatever the gate decided | pre-records, either writer |
| **R5 `agent-role-change`** | a `role_changes` row with `actor_session` set: a role that changed **through an agent** (SR-B8-7, SR-B3-9) | `role_changes` |
| **R6 `authority-refusal`** | a gateway denial for `role_does_not_permit` or `control_plane_not_delegable`; any `refused_at_execution` outcome; the API's two in-org lines above (`sub=… org=… decision=role-does-not-permit`, `session=… at=execution`) | pre/post records, the API log |

The threshold is one event. M1 needed five because a single cross-tenant 404 is a typo. Here, a role or delegability refusal is a principal reaching past its own authority, and the threat model counts both as attempts. A refusal and its log line for the same session are one alert, counted twice.

`make detect` replays seven scenarios per mode (`replay_delegation.py`) through `attacks/agentlab.py`, loading 05's and 06's users and scopes from the exploits. Each scenario has its own window over three sources: the audit files, the API container's log, and `role_changes` rows that were not there before. Every cell asserts:
- the exact set of rules that fired;
- that every alert names this scenario's principal;
- for agent rows, M2's writer contrast.

A row that did not produce its event is exit 2.

| scenario | vulnerable: rules | vulnerable: deny-only | hardened: rules | hardened: deny-only |
|---|---|---|---|---|
| 05 (i) a viewer's agent deletes | **miss** | miss | **R6** | fires |
| 05 (ii) a demoted admin's resumed session deletes | **miss** | miss | **R6** | fires |
| 06 the owner's agent reads mallory's document | **R4 + R5** | miss | **R4 + R6** | fires |
| a viewer's direct `DELETE` (403) | **R6** | miss | **R6** | miss |
| the owner's agent reads a clean document, with `set_member_role` in scope *(FP row)* | none | silent | none | silent |
| an admin's agent deletes, which it may *(FP row)* | none | silent | none | silent |
| the owner changes a role directly, and back *(FP row)* | none | silent | none | silent |
| **attacks caught** | **2/4** | 0/4 | **4/4** | 3/4 |
| **controls fired on** | 0/3 | 0/3 | 0/3 | 0/3 |

The deny-only column is M2's baseline (any gateway denial) run over the same records. In hardened mode it catches the three agent attacks only because the gate is doing the catching. It never sees the direct route, whose 403 is the API's, not the gateway's. R6 is narrower and wider than it at once. Narrower: a fetch off the allowlist or a fail-closed deny is not an authority attempt (M2's benign-fetch row is where the baseline fired falsely). Wider: R6 reads the API's in-org lines too.

05 (ii)'s own window holds two human role changes, the demotion and the restore, so R5's silence on a human change is asserted inside an attack row, not only in the false-positive row.

**A human's role change is recorded, not alerted.** Every change lands in `role_changes` with its actor (SR-B8-7), and that record is the audit trail. An admin changing a role through the direct admin route is the product doing its job. R5 alerts on the one shape the threat model names: a change made through an agent session, where the authority to change the delegation was itself delegated.

## M3 — what the matrix measures

**Vulnerable mode misses 05, and that is the result, not a gap in the replay.** To see 05 in vulnerable mode a rule would need two things: the acting user's role at the call's timestamp (reconstructable from `memberships` plus the `role_changes` history), and whether that role permits the tool. The second is the Go permission table, and M3 D4 put it in one place. A Python copy would be a second permission table, and two tables drift. Declared, not built.

So the lesson is M1's again, in a new place: **the fact detection needs is one the control derives.** The vulnerable build has the telemetry (who acted, in which session) but not the judgment (may they?). That is why R6 is a denial rule and, like M1's, is coupled to the control working.

**06 is caught in both modes, by different rules.** R4 reads what was *asked*, so it fires in both modes. R5 reads what *changed*, so it fires only where the change happened. Hardened mode's R6 replaces it with the refusal. The direct route's 403 is caught in both modes, because its role check (M3 T3) ships in both.

**Declared couplings and limits:**

- **R4 shares the gate's list.** It reads `non_delegable` from `policy.rego`, as R2 reads the allowlist. A tool dropped from the list blinds R4 and the gate together. R5 doesn't read the list, so the change is still seen in vulnerable mode. In hardened mode an allow still could not execute: there is no internal route for it (`TestNonDelegableToolsHaveNoInternalRoute`), so no role changes. But the *attempt* would go dark: R4 skips the tool, and R6 has no refusal to read.
- **R5 sees changes made through the product.** The agent's database credential can write `role_changes` and `memberships` directly (R-M3-2). A change by direct SQL is invisible, and a green matrix does not claim it.
- **R6's at-execution leg is unit-tested, not replayed.** It needs a demotion inside the gate-to-write window, which a replay cannot land deterministically (M2 T8 treated its mid-request window the same way). A refusal whose pre-record is outside the window still alerts, on its decision id.
- **A write that copies text from a document the session read** (M3-N6, R-M3-4) is a recorded detection shape, not built.
