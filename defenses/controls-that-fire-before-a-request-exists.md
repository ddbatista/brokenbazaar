# Controls that fire before a request exists

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

**Requirements:** SR-B1-1 (deny-by-default route registration), SR-B1-3 (signing key required) · **Module:** M1
**Related leaves:** M1-N1 (the quiet config fallback), SR-M1-1 (loud or absent, never quiet)
**Code:** `app/api/routes.go` (`authKind`, `registerHardened`), `app/api/main.go` (`loadJWTSecret`) — behind `HARDENED`
**Status:** shipped, verified in CI. No finding of its own — these are controls without a numbered vulnerability.

Two mechanisms, one thesis: **the strongest control is one a misconfigured process cannot reach, because it never finishes starting.** A missing auth declaration and a missing signing key are both failures of the build, not of a request — and a control that waits for a request to discover them has already agreed to serve traffic in an unknown state.

Requirement: [`threat-models/m1-tenancy.md`](../threat-models/m1-tenancy.md) §3, §4 M1-N1.

---

## 1. What they are

**SR-B1-1 — the route table with no valid zero value.** `registerHardened` wires every route from a `[]route`, and each entry's `auth` field is an `authKind` whose zero value is `authUnset`. An entry that never declared its auth hits `panic(...)` at startup. `/healthz` and `/auth/token` are in the table too, declared `authNone`, so one code path owns every route.

**SR-B1-3 — the key, or nothing.** `loadJWTSecret` reads `JWT_SECRET`. In hardened mode an empty value is `log.Fatalf`, naming the variable and the requirement. In vulnerable mode it falls back to the committed `devJWTSecret` — **and logs WARN while doing it.** Only the *strength* of the secret is flag-gated; the logging is not, because M1-N1's whole point is that an operator who typos the variable gets a working stack signed with a public key and no signal.

## 2. Options considered — the route table

**A — A comment saying "remember to declare auth."** That is convention, which is the thing M1 exists to argue against.

**B — Default the zero value to `authToken` (safe-by-default).** Rejected, and this is the subtle one. Defaulting to the *safe* value sounds strictly better and is strictly worse: a route whose declaration was forgotten would silently require a token, behave plausibly, and **never surface the omission.** The author's mistake becomes invisible because the outcome happened to be acceptable. The next forgotten declaration on a route that should have been public then fails for users at runtime, and nobody connects the two.

  Deny-by-default-as-a-default is a *behaviour*. No-valid-default is a *check*. Only the second tells you the declaration is missing.

**C — Zero value is invalid; panic at startup.** Chosen.

**D — A unit test enumerating routes and asserting each declares auth.** Complementary, not taken, and worth recording why: a test runs in CI, the panic runs **everywhere** — a developer's laptop, a reviewer's clone, a demo. A control that only fires where CI runs is absent in every environment where someone is improvising.

## 3. Options considered — the signing key

**A — Fall back to a dev secret in every mode, silently.** That is M1-N1, i.e. the planted defect.

**B — Fall back with a WARN.** What vulnerable mode ships. Not security, but it converts a silent compromise into an observable one.

**C — Required, or refuse to start.** Chosen for hardened mode.

**D — Generate a random secret at startup when unset.** The trap, included because it is the option most people reach for. It looks like a safe default, starts cleanly, and passes every smoke test. It also silently invalidates every issued token on restart, produces a service that mysteriously logs users out on deploy, and — worst — **removes the operator's signal that the key was never configured.** It converts a configuration error into an intermittent availability bug, which is the hardest class to attribute. A wrong default that starts is more dangerous than no default at all.

## 4. What they cost

This section is the honest centre of the document, because this control's cost was paid publicly.

- **SR-B1-3 broke CI for 16 days.** `docker-compose.yml` never forwarded `JWT_SECRET` to the `api` container, so the moment hardened mode refused to start, the `stack / hardened mode also starts` job failed on every push — first red run `38195487230`, green again at `39363799544`. The control worked **exactly as designed**; the build was wrong. That is the deal a refuse-to-start control makes: it converts a configuration gap into an outage, on purpose, and you pay for it in the build pipeline.

  It was left red deliberately rather than patched, because both available fixes touched hardened zones. Documented as a named exception at the time instead of discovered later.

- **The fix's entire security weight is in two characters.** The compose line is `JWT_SECRET: "${JWT_SECRET:-}"`. Writing `${JWT_SECRET:-dev-secret}` would have been a silent backdoor that made CI green and the control meaningless. An empty default is a pure passthrough that preserves refuse-to-start.

- **CI's key is plaintext `ci-only-not-a-secret`, on purpose.** Committed in a public workflow it protects nothing and should not pretend to; a real GitHub secret would misclassify a non-secret *and* break fork PRs, since secrets do not reach forks — harming the clone-and-run guarantee. The name declares its own classification.

- **`panic` is correct here only because of when it runs.** At startup it is a refusal to serve. The same mechanism reached from a request handler is a denial-of-service primitive. The scoping is the control; the panic is just how it is spelled.

## 5. How they are verified

| Evidence | Where |
|---|---|
| Hardened stack starts, answers `/healthz`, with `JWT_SECRET` supplied | `ci.yml` job `stack starts from clean clone` |
| Hardened container with **no** `JWT_SECRET` refuses to start | verified live at M1 T4 |
| Full attack suite passes in hardened mode, which requires the hardened route table to have registered every route | `ci.yml` job `attack suite (both modes)` |

**Not verified by anything:** that a route exists at all. See §6.1 — this is the real gap, and it is not small.

## 6. Where these controls would silently rot

1. **The table catches undeclared routes, not unlisted ones.** The panic fires for an entry *in* `routes` whose `auth` is `authUnset`. A handler registered straight onto the `mux` somewhere else is never in the table, never evaluated, and never panics — in **either** mode. `registerVulnerable` demonstrates the shape six times over, so the pattern is already in the codebase as a readable example to copy.

   The control is therefore "every route in the table declares its auth," not "every route goes through the table," and only the second is SR-B1-1 as written. Closing it needs a check the table cannot perform on itself: a startup assertion comparing registered patterns against the table, or a test that walks the mux. **Neither exists.** This is the single largest gap in M1's hardened path and it is in the control that was supposed to make gaps loud.

2. **M2 adds routes to a service this table does not govern.** `/sessions` and `/sessions/:id/messages` extend the table. The **gateway is a separate Python process with its own routes and no equivalent mechanism at all** — and it is the component that decides whether tool calls execute. A deny-by-default property that stops at the language boundary is not a property of the system. Carry into M2's diff as a decision.

3. **The second secret-consumer has no rule.** `loadJWTSecret` is one function, called once. M2's gateway needs its own credentials (judge API key, policy bundle location) and will have its own config path, written in a different language, with no connection to SR-B1-3. The *rule* — loud or absent, never quiet — is a repo-wide principle enforced in exactly one function.

4. **`HARDENED` itself is read by `os.Getenv(...) == "true"`.** Any other value, including a typo like `True` or `1`, silently yields vulnerable mode. The flag selecting every control in the repo has the quiet-fallback shape that M1-N1 exists to condemn. No log line distinguishes "HARDENED unset" from "HARDENED=ture". Smallest change with the highest ratio of safety to effort in M1.

## 7. Why this document exists without a finding

There is no `attacks/NN-*` for either control. Both were derived from the baseline rather than from an exploit, and the module's two findings are elsewhere.

That is worth stating because the repo's own structure could imply otherwise: `attacks/` is indexed by finding, and a reader counting directories would conclude M1 shipped two controls. It shipped five. **Controls are not conserved with findings** — the cap of 10 is a cap on vulnerabilities, never on defences, and a lab that only builds the controls its exploits happen to need is teaching the exploits, not the design.
