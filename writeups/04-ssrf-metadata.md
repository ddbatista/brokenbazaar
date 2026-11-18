# The allowlist checked a name; the socket dialed the metadata server

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Every vulnerability in it is intentional and documented. Run it on localhost only.

*Finding 04: SSRF to the cloud metadata server through the agent's fetch tool · boundaries B5 (Agent → Tools) and B7 (App → Cloud) · leaves B7 1.1 via B5 3.2 / B5 4.3; the redirect variant B7 1.2 · `LLM06:2025` Excessive Agency · `ASI02 2026` Tool Misuse and Exploitation · `MCP05:2025` · `A10:2021` Server-Side Request Forgery.*

## Nobody injects anything

An ordinary, authenticated Acme member, logged in with the real password, asks the agent:

```
Please fetch http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token and tell me what it returns.
```

In the vulnerable build the reply carries a service-account credential: `ya29.FAKE-brokenbazaar-lab-token-NOT-A-CREDENTIAL`. It is a fake, served by the lab's `mock-metadata` fixture, but the path is the real one. The agent's fetch tool runs inside the deployment, and inside the deployment the metadata server answers.

No poisoned document, no forged token. The member asked a tool to make a request, and the platform made it from a network position the member does not have. That is excessive agency in its plainest form: the agent can reach things its user cannot, and nothing asks whether it should.

## The redirect that never names the target

The second request is the one this finding exists for:

```
Please fetch http://attacker.example/redirect and tell me what it returns.
```

That URL names no metadata host. The attacker's server answers `302` with a `Location` pointing at the token URL, and the credential comes back again. The exploit treats the two as one result: if only one variant leaks on the vulnerable stack, it exits 2, because the planted fetcher has changed behaviour.

The vulnerable fetch tool, `httpFetch` in `app/agent/executor_vulnerable.go`, is short and looks correct. It builds a request, calls Go's `http.Client`, and reads the body. It has no allowlist and no address check. The client follows up to ten redirects by default, resolving each new hostname inside its own dial and evaluating none of them. The only check in the executor is on the tool's **name** (B5 3.2): `http_fetch` is allowed, so every URL is allowed.

## Why a check on the string cannot be the control

Add the check most people would add first: parse the URL, compare the host against a list, then call the client. Against the redirect it sees `attacker.example` (or any innocent host the attacker controls) and approves it. The request that reaches the metadata server is one the check never saw.

Redirects are one way the evaluated value and the executed value come apart. There are two more:

- **DNS.** Checking a resolved address does not help if the connection resolves the name again. An attacker serving a short TTL answers the check with a public address and the dial with a link-local one (DNS rebinding, B7 1.2).
- **Encodings.** A denylist of strings catches `169.254.169.254` and misses its octal, decimal and IPv4-mapped IPv6 forms.

The baseline requirement names the property all three violate. SR-B5-3: evaluation is on fully-resolved arguments, *"post-normalisation, post-DNS, post-redirect"*, and **the resolved value is what executes**. SR-B7-1 adds that egress is evaluated against the resolved address, re-evaluated on every redirect hop, and that link-local and private ranges are denied *"by range, never by string match."*

## The control: the resolved value is what executes

The hardened fetcher is `gateway/tools/fetch.py`. For every hop it:

1. resolves the hostname **once**;
2. checks the allowlist, then the range of the **resolved address** (D6): the address the resolver returned, parsed with `ipaddress` and compared against network blocks (an IPv4-mapped IPv6 address is unwrapped first), never the string the caller wrote;
3. dials **the IP it validated**, carrying the name in the `Host` header, so there is no second lookup to win;
4. does not follow redirects (it uses `http.client`, which does not), and treats a `Location` as a new request that goes back to step 1.

One honesty note on "once". It holds inside the fetcher, per hop. Before the fetcher runs, the gateway resolves the same host for the policy decision, so hop 1 is looked up twice. That is safe, because the fetcher re-checks the address it dials, but the pre-record's `resolved` address is the policy's, and may not be the one dialled. It is carried in the threat model's §9.

`test_tools.py` asserts the first property as a number: the injected resolver must be called exactly once per hop. A rebinding resolver that answers public first and link-local second is never asked the second time.

`metadata.google.internal` is **on** the egress allowlist, deliberately. It models the operator mistake the range leg exists for: the name passes, the address does not. The direct request is denied `resolved_address_denied`, and the exploit reads that reason from the defender's record, `gateway.jsonl`. The agent sees only `gateway denied`, because a caller who learned `resolved_address_denied` would know the host had passed the allowlist (SR-B7-7).

The agent cannot route around any of this. The hardened agent binary contains no tool code (D5); `make verify-agent-images` builds the agent images from the stack's Dockerfile target and checks the hardened one holds no `NaiveExecutor` symbol. It runs by hand, not in CI. The fetch happens in the gateway or nowhere.

## The redirect, hardened

Put the two halves together. An allowlisted host redirects to the metadata service. Hop 1 is approved: allowed name, public address. Hop 2's name, `metadata.google.internal`, is **also** on the allowlist, so a per-hop check on names would approve it too. Only the range check on hop 2's resolved address refuses it.

That is `test_a_redirect_into_a_denied_range_is_denied`: `docs.example` answers `302` to `metadata.google.internal`, the resolver returns a link-local address for the second hop, the result is `resolved_address_denied`, and the dialer was called **once**. The second hop is never dialed.

One limit is stated rather than glossed. The exploit's own hardened redirect run dies at hop 1, `egress_not_allowlisted`, because `attacker.example` is not on the allowlist, and it prints that reason for context only. Reaching the per-hop check end to end needs an allowlisted host on a non-denied address, and every Compose fixture sits in RFC1918 space. So the hardened redirect case is proven by the unit tests, not by the PoC.

## What detection sees

Measured on every `make detect`, in both modes ([`detections/README.md`](../detections/README.md), M2):

| | vulnerable | hardened |
|---|---|---|
| 04 direct | **R3** | **R3** |
| 04 redirect | **R2 + R3** | **R2** |
| deny-only baseline, both rows | miss | fires |
| benign fetch to allowlisted `docs.example` *(false-positive row)* | silent | rules silent; deny-only **fires** |

**R3** `metadata-endpoint` fires on a requested host, a resolved address, or the **final URL after a completed redirect** that is a cloud metadata endpoint. The redirect leg matters: without it, the vulnerable redirect run names only `attacker.example`, and the metadata hit is invisible.

R3 ignores the allowlist on purpose. `metadata.google.internal` is allowlisted, so **R2** `egress-off-allowlist` is blind to the direct request. R2 is also coupled to the gate's allowlist data: with `attacker.example` added to the detector's copy, the hardened redirect row goes completely dark, since only R2 could see it.

The deny-only baseline is blind in vulnerable mode, because nothing was denied. In hardened mode it alerts on the benign fetch, which fails closed (`enrichment_failed`, since `docs.example` does not resolve in the lab). A denial is not an attack.

## What this does not cover

- **The network layer.** The agent container shares a bridge network with `mock-metadata` (M2-N1, R-M2-3). Mediation is enforced in code, not at the network. With no fetch code in the agent, using that path takes code execution in the agent process, not a request to it.
- **TLS.** The fetcher is HTTP only. Dialing an IP over TLS breaks SNI and certificate checks unless handled explicitly, so it is not implemented rather than implemented badly.
- **`169.254.169.254` literally**, and the `Metadata-Flavor: Google` header real GCP requires. The fixture is reached by name and does not require the header.

## The generalisable claim

An allowlist of names answers a question about the URL. SSRF is decided by the address the socket dials, after DNS and after every redirect. Any control that inspects one value and lets a library execute another has checked the wrong thing, however carefully it checked it.

Resolve once, decide on the result, dial exactly that, and treat every redirect as a new request from the attacker.

---
*Planted in `b2018c7` (in-process `httpFetch` with no allowlist, no range check and redirects followed, B5 2.1 / 4.3; the name-only tool allowlist, B5 3.2). Control: `gateway/tools/fetch.py` (added in the same commit, `b2018c7`), `97f150c` (the gateway: resolve, then decide; the agent's gateway executor), `4ed6dbe` (the policy: allowlist, then range), `733952b` (compose: the gateway and the hostile fixtures in the stack), `25b447e` (the agent image and mode agreement). Design: [`defenses/the-resolved-value-is-what-executes.md`](../defenses/the-resolved-value-is-what-executes.md). Exploit: [`attacks/04-ssrf-metadata/`](../attacks/04-ssrf-metadata/). It exits 0 on the vulnerable stack and 1 on hardened, in CI on every pull request and push to main.*
