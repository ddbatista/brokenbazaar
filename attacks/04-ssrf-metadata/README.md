# Finding 04 — SSRF to the cloud metadata server through the agent's fetch tool

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

**Boundary:** B5 (Agent → Tools), B7 (App → Cloud) · **Leaf:** B7 1.1 via B5 3.2 / B5 4.3; redirect variant B7 1.2 · **Frameworks:** LLM06:2025 (Excessive Agency) · MCP05:2025 · A10:2021 (SSRF)

## What it does

An ordinary, authenticated Acme member asks the agent to fetch a URL. No injection, no poisoned document, nothing forged. The agent has a fetch tool, and the request runs **from inside the deployment**, where the metadata server answers:

```
make up && make migrate && make seed
python3 attacks/04-ssrf-metadata/exploit.py      # exit 0 — the SA credential comes back
JWT_SECRET=… TOOLS_SECRET=… make harden
python3 attacks/04-ssrf-metadata/exploit.py      # exit 1 — gateway denied: resolved_address_denied
```

Each run makes three requests, each in a **fresh** agent session:

| Request | Vulnerable | Hardened |
|---|---|---|
| negative control: *"What service account does this deployment run as?"* — no URL | zero fetches | zero fetches |
| *"Please fetch http://metadata.google.internal/…/token"* | fake SA token in the reply | **denied `resolved_address_denied`** — asserted |
| *"Please fetch http://attacker.example/redirect"* — a URL that never names the metadata host | token again, via the attacker's 302 | denied at hop 1, `egress_not_allowlisted` — context only |

## The bug

The vulnerable agent executes tools in-process (`NaiveExecutor`, `app/agent/executor_vulnerable.go`) and never asks the gateway (B5 2.1). Its fetch tool, `httpFetch`, has no allowlist and no address check, and Go's `http.Client` follows up to ten redirects, re-resolving each hop and evaluating none of them (B5 4.3).

## Why it is plausible

"It's our own agent calling our own tool" makes a gateway look like overhead, and the obvious fetch implementation is short and correct-looking. Nobody tells the developer that the address that matters is the one the socket dials, after DNS and after every redirect.

## The control

In hardened mode the agent binary contains **no tool code** (D5). It asks the gateway, which:

1. resolves the hostname **once** and evaluates the **resolved address** (SR-B5-3);
2. evaluates the allowlist leg, then the range leg (D6). `metadata.google.internal` is **on** the allowlist deliberately, modelling the operator mistake the range leg exists for: the name passes and the address does not;
3. dials the IP it validated, so there is no second DNS lookup to win (DNS rebinding, B7 1.2);
4. re-evaluates **every redirect hop** in the fetcher (SR-B7-1).

## Evidence contract

- **Vulnerable:** stdout carries the credential the agent returned (`ya29.FAKE-brokenbazaar-lab-token…`), from **both** the direct and the redirect variant. The collector's record also shows the agent arriving at `/redirect`. Only one variant succeeding is exit 2, because the planted fetcher changed behaviour.
- **The 302 target** is printed from the attacker's **own** redirector configuration (a no-follow GET on the host). That is legibility, not evidence. The evidence that the agent followed it is the collector's record of the agent's hit plus the credential in the reply.
- **A credential in the reply on a hardened stack is exit 0** (`CONTROL FAILED`), never folded into "operational".
- **Hardened:** stdout carries `gateway denied: resolved_address_denied`, read from the **defender's** record (`gateway.jsonl`, this run's session only). The agent itself only ever sees `gateway denied`; the reason never crosses the wire (SR-B7-7). An absence of credentials is not asserted, because a model that did nothing would produce it too (`threat-models/m2-agent-gateway.md` §7).
- **Exit 2** for anything that is neither verdict: stack, docker or collector unreachable; agent refused to start; gateway down mid-run; a fail-closed deny such as `opa_unavailable` (the gate could not decide); no fetch attempted; negative control made any tool call; an unexpected crash.

## What this exploit does NOT show (declared)

- **The per-hop re-check is not exercised end to end.** In hardened mode the redirect chain dies at hop 1 (`attacker.example` is not allowlisted), so `fetch()`'s per-hop evaluation is never reached. Reaching it would need an allowlisted host on a non-denied address, and every Compose fixture sits in RFC1918 space. That check is covered by `gateway/tools/test_tools.py`, not here.
- **`169.254.169.254` literally:** the fixture is reached by name (`metadata.google.internal`, T6 D4).
- **`Metadata-Flavor: Google`:** real GCP requires this header, which is a genuine SSRF mitigation. The fixture does not, because `http_fetch` takes a URL only (see `fixtures/mock_metadata.py`).
