# The resolved value is what executes

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Run it on localhost only.

**Requirements:** SR-B5-3 (evaluated on fully-resolved arguments; the resolved value is what executes), SR-B7-1 (egress allowlist on the resolved address, re-evaluated per redirect hop, ranges denied by range and never by string match) · **Module:** M2
**Kills:** finding 04, both variants, and the B5 4.3 TOCTOU it rides on · **Carries:** B7 1.2 in part (§4), M2-N1 / R-M2-3
**Code:** `gateway/tools/fetch.py` (`fetch`, `evaluate`, `is_denied_range`, `default_resolve`, `default_dial`), `gateway/gate.py` (`enrich`, `Config.allowlist`), `gateway/policy/policy.rego` (legs 7 and 8). The departure: `NaiveExecutor.httpFetch` in `app/agent/executor_vulnerable.go`. Behind `HARDENED`.
**Status:** shipped, verified in CI in both modes. Dialling the validated IP and re-checking each redirect hop are unit-tested only; no hardened fetch in the lab ever reaches a dial (§5).

Narrative: [`writeups/04-ssrf-metadata.md`](../writeups/04-ssrf-metadata.md). Requirement: [`threat-models/m2-agent-gateway.md`](../threat-models/m2-agent-gateway.md) D5, D6, §3 (SR-B5-3, SR-B7-1), B5 4.3.

---

## 1. What it is

**Resolve once per hop, decide on the address, dial that address.** For each hop, `fetch()` calls the resolver once, judges the result with `evaluate(host, ip, allowlist)` (the allowlist first, then the range), and hands the **IP literal** to `default_dial`. That function opens `http.client.HTTPConnection(ip, port)` and sends the hostname in the `Host` header. When `create_connection` receives an IP literal it does no DNS lookup, so there is no second answer for an attacker to change. The obvious version validates `getaddrinfo(host)` and then connects to `host`. That makes two lookups, and the connection uses the one nobody checked. That is B5 4.3, and it looks correct in either language.

**Redirects are new requests.** `http.client` does not follow them, which is why it was chosen. On a 301, 302, 303, 307 or 308 the fetcher joins the `Location`, goes back to the top of the loop, and resolves and evaluates the new hop from scratch. After `DEFAULT_MAX_REDIRECTS` (3) it stops with `too_many_redirects`. The fetcher and OPA read the same allowlist: `Config.allowlist` is `egress_allowlist` from the `data.json` the policy uses.

**The policy decides on facts the gateway established.** Before OPA runs, `enrich` resolves the host and passes the policy `{host, ip, denied_range}`. Leg 7 (`egress_not_allowlisted`) reads the host. Leg 8 (`resolved_address_denied`) reads the boolean, and when the field is missing it defaults to **true**: an address nobody classified counts as denied. The policy itself does no DNS and no `http.send`.

**Why a name check cannot do this job.** `metadata.google.internal` is **on** the allowlist on purpose (D6). It stands for the operator mistake the range leg exists to catch. Finding 04's name passes the allowlist, and the call is refused on its resolved address. In the lab that address is the fixture's 172.28.0.20 (RFC1918), not 169.254.169.254: the stack cannot reach the literal address, because the spike that would have made it reachable was never run (T6 D4). The unit tests use the real link-local address. A denylist of strings fails in the other direction: `2852039166` and `0251.0376.0251.0376` both resolve to 169.254.169.254. They are caught here because the resolver turns them into the canonical address before `is_denied_range` sees it.

**The redirect variant.** `attacker.example/redirect` returns a 302 to the metadata token. `attacker.example` is **not** allowlisted, so in hardened mode the chain dies at hop 1, in the policy, as `egress_not_allowlisted`, before the fetcher runs. The vulnerable `httpFetch` uses Go's `http.Client`. It follows the 302 without evaluating it and returns the token.

The thesis in one line: **the value you check and the value you use must be the same value, not two lookups of the same name.**

## 2. Options considered

**A: A denylist of metadata hosts and IP strings.** Rejected. It is B7 1.2 verbatim: decimal, octal and v4-mapped forms, a redirect, or a rebinding answer all get past it. SR-B7-1 says "by range, never by string match".

**B: An allowlist of names, and nothing else.** Rejected. A name says nothing about where it resolves, and the shipped allowlist makes that point on purpose with `metadata.google.internal`.

**C: Resolve, validate, then connect by hostname.** Rejected. This is the bug the module teaches. Nothing in a normal test suite tells it apart from the correct version, because both fetch the right page whenever DNS is honest (`b2018c7`).

**D: Monkeypatch `socket.getaddrinfo` to serve a pinned cache.** Rejected (`b2018c7`). It changes a process-wide function to fix one call site, and it would silently change name resolution for every component added later.

**E: Check the range first.** Rejected (D6). Both fixtures sit in RFC1918 space, so finding 03 would be refused as "private address". That is true, but it is the wrong reason, and it would not carry over to an attacker on a public IP.

**F: A library that follows redirects.** Rejected. It would make requests to hops nobody evaluated, which is SR-B7-1's failure as a library default.

**G: Close it at the network: an egress proxy or a `NetworkPolicy`.** Not available. Compose cannot express egress policy (M2-N1). The control lives in the one process that is allowed to fetch.

**H: Resolve once, check the IP, dial the IP, carry the name in `Host`, and follow redirects by hand.** Chosen.

## 3. What it costs

- **More than one DNS lookup per call.** Each hop costs a lookup. Hop 1 is resolved **twice**: once in `enrich`, for the policy and the record, and once in `fetch()`, for the dial. The fetcher re-runs `evaluate` on its own answer before it dials, so if DNS rebinds between the two lookups, the fetcher refuses the call. The record pays for that: the pre-record's `resolved.ip` comes from the first lookup and may not be the address the gateway dialled, or refused. The fetcher's reason appears only as the post-record's summary.
- **HTTP only.** Dialling an IP over TLS breaks SNI and certificate hostname checks unless `server_hostname` is set explicitly. That was declared up front and is refused (`scheme_not_supported`), not implemented badly. A fetch tool that cannot fetch `https://` is a real product cost.
- **Redirects are code this repo owns:** the list of status codes, `urljoin`, the cap of three, and a `Location`-less redirect reported as `resolution_failed`, a name that does not quite fit.
- **One address per name.** `default_resolve` takes the first `getaddrinfo` answer and never falls back to another, so a host with one dead address fails.
- **Seams in production code.** `resolve` and `dial` are injectable because that is the only way a test can change the DNS answer between the check and the connection.

## 4. What it does not cover

- **Ranges outside the standard library's classes.** `is_denied_range` denies what Python's `ipaddress` reports as private, loopback, link-local, reserved, multicast or unspecified. 100.64.0.0/10 (shared address space) is in none of those classes. An allowlisted name that resolves there passes the policy. IPv6 goes through the same function: v4-mapped addresses are unwrapped, and `::1` and `fc00::/7` are denied.
- **TLS, and every protocol other than `http`.** See §3.
- **A reason that is honest about https.** `enrich` does not resolve an `https` URL. For an allowlisted host, the policy's fail-closed default then denies it as `resolved_address_denied`. It fails closed, but the record names a resolution that never happened.
- **The response size.** `default_dial` reads the whole body. The naive Go fetcher caps it at 64 KiB, and this one does not.
- **The agent container's own sockets** (M2-N1). This control governs the gateway's fetches. See [`mediation-by-absence.md`](mediation-by-absence.md) §4.
- **Real metadata hardening.** GCP requires a `Metadata-Flavor: Google` header, which is a genuine SSRF mitigation. The fixture does not require it, because `http_fetch` takes a URL only.

## 5. How it is verified, and the half that is not

| Evidence | Where |
|---|---|
| 04 exits 1 hardened (`gateway denied: resolved_address_denied`, read from `gateway.jsonl`); exits 0 vulnerable with `ya29.FAKE-brokenbazaar-lab-token`, and both the direct and the redirect variant must return it | `attacks/04-ssrf-metadata/`, CI on every pull request and push to main |
| One lookup per hop; the validated IP is dialled with the name in `Host`; a second, link-local answer is never asked for | `test_resolver_is_called_exactly_once_per_hop`, `test_dials_the_validated_ip_not_the_hostname`, `test_dns_rebinding_cannot_land` (`gateway/tools/test_tools.py`) |
| Every hop is evaluated again; a redirect to a host off the allowlist, or into a denied range, is never dialled; loops end | `test_each_hop_is_resolved_and_evaluated_again`, `test_a_redirect_to_a_forbidden_host_is_denied`, `test_a_redirect_into_a_denied_range_is_denied`, `test_redirect_loops_terminate` |
| Allowlist before range; a denial dials nothing; `https` is refused | `test_unallowlisted_host_denied_for_the_right_reason`, `test_allowlisted_host_resolving_into_a_denied_range`, `test_nothing_is_dialed_when_the_decision_denies`, `test_https_is_refused_rather_than_mishandled` |
| 04 passes the allowlist and dies at the range, whatever its provenance | `test_finding_04_passes_the_allowlist_and_dies_at_the_range`, `test_finding_04_reason_is_stable_under_untrusted_provenance` (`policy_test.rego`); `test_finding_04_dies_at_the_range` (`gateway/test_gate.py`) |
| The reason never goes back on the wire (SR-B7-7) | `test_a_denial_leaks_no_reason` |
| Detection: R3 sees 04 direct in both modes; hardened 04 redirect is seen by R2 alone | `detections/README.md` (M2) |

**The fetcher's own guarantees never run end to end in the lab.** In hardened mode, 04's redirect variant dies at hop 1 in the policy, so the per-hop re-check is never reached (the 04 README says so too). No allowed fetch ever reaches a dial: every fixture is in RFC1918 space, and `docs.example` does not resolve in the stack (`enrichment_failed`). "Dial the validated IP" and "re-check every hop" are proven by unit tests with an injected resolver and dialler, and only there. The range test checks the dotted and v4-mapped forms. The decimal and octal forms are handled by the resolver, and no test pins that. No test drives `enrich` and `fetch()` together with a resolver that changes its answer.

## 6. Where this control would silently rot

1. **`default_dial` is never tested.** Every unit test injects a recording dialler, so the suite proves `fetch()` passes an IP to `dial`, not that the production dialler does no lookup of its own. The most likely change here is adding HTTPS. Written the obvious way, `HTTPSConnection(host)` brings the second lookup back, and every test in `test_tools.py` stays green. **Highest-probability rot in this control.**
2. **The `denied_range` default.** It is `true`, and that is what refuses `https` and every unclassified address. Someone unblocking `https` in the policy and adding TLS to the fetcher in the same change removes both refusals at once.
3. **The range function follows the Python version.** What `ipaddress` calls private is decided by the standard library. The gateway image pins `python:3.13-slim` by digest, which holds it still only until the pin is bumped.
4. **The seam between gate and fetcher is untested.** The fetcher's own re-evaluation is what makes hop 1's two lookups safe, and every test of it calls `fetch()` directly. No gateway test runs an allowed `http_fetch` through `execute`. So if `execute` changed how it calls the fetcher (a different allowlist, or a resolver of its own), no test would notice. The unit tests would keep passing against code production no longer calls that way.

## 7. Note for M6

The fetcher, its injected-seam tests and the naive Go fetcher were written at M2 T4 (`b2018c7`) by a coding agent under AGENTS.md gates: Hermes Agent per the author's account. That commit records the correct implementation as written first, with the naive one as the documented departure. The policy legs it is judged by were drafted by the agent and applied by hand (`4ed6dbe`), because `gateway/policy/` is a hardened zone. T6 onward was Claude Code. See [`attacks/04-ssrf-metadata/ANSWER-KEY.md`](../attacks/04-ssrf-metadata/ANSWER-KEY.md).
