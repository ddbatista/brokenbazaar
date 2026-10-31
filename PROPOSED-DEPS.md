# Proposed dependencies — for a human to apply

`go.mod`, `go.sum` and every other dependency manifest are **hardened zones** (`CLAUDE.md`). The
coding agent does not edit them. It proposes here; a human decides, applies, and commits.

Each entry states what the dependency is for, what was considered instead, and what it would cost to
remove later. An entry is deleted from this file once it is applied.

---

## M2 T0 — three images, one binary, no language-level dependencies

Proposed 2026-10-28. M2 adds a Python gateway, an OPA policy evaluation step, and two Compose
fixtures. **No Go modules and no pip packages are proposed** — the gateway is stdlib-only per house
rule, and nothing in M2 needs a Go dependency `app/go.mod` does not already carry.

### 1. `openpolicyagent/opa` — the policy binary

**Version:** `1.22.0`, released **2026-10-29** · **decided 2026-10-31**
**Digest:** `sha256:895872de1e8dc5b82e04f9410d2d1ada2f72d28fdcdba0e8789d91cfc27ec0d0`
**Verified against the 1.21.4 image** (same line, same build pipeline): entrypoint `/opa`,
`Rego Version: v1`, linux/amd64, built on Chainguard/apko — no shell and no package manager, so the
image can only ever be a COPY source and never a base.

**What it is for.** D3: the gateway evaluates policy in Rego rather than in a Python function, so the
decision stays separable from the executor and independently testable, and `SR-B5-5`'s fail-closed
requirement can be verified by killing a real process instead of flipping a test flag.

**How it is consumed — this resolves a contradiction in D3's own text.** The diff says both "OPA
arrives as a container image" and "the gateway image needs `opa` on PATH," which are different
architectures. Settled here as a **multi-stage copy**, not a separate service:

```dockerfile
COPY --from=openpolicyagent/opa@sha256:895872de1e8dc5b82e04f9410d2d1ada2f72d28fdcdba0e8789d91cfc27ec0d0 \
     /opa /usr/local/bin/opa
```

The image has no shell, so it can only ever be a COPY source — it cannot be a base. This preserves
jev-lab's `decide.py` subprocess pattern and, with it, the architectural point that was the real
reason to port that code: **no `http.send` from Rego.** Running `opa run --server` as its own Compose
service would reintroduce exactly the coupling `decide.py`'s header argues against — every policy
evaluation would depend on a network hop to a second process.

**Considered instead:** `opa run --server` as a Compose service (rejected above); a third-party
`setup-opa` GitHub Action for CI (rejected — it is itself an unreviewed dependency, and see the CI
note below for a better answer); writing the policy in Python (rejected in D3, with reasons).

**Cost to remove later:** low. Three touch points — one `COPY --from` line, `decide.py`'s
`find_opa()`/`opa_route()`, and the CI policy-test step. The Rego itself would have to be
reimplemented, which is the point of D3 rather than a hidden cost.

**What a minor bump moves, checked because 1.21 → 1.22 is not a patch.** The release notes carry one
breaking change and one new capability, and both were read before pinning:

- **Breaking: stricter handling of bundle signature filenames.** Does not apply. The gateway
  evaluates local `.rego` files via `opa eval -d`; it does not use signed bundles.
- **New `rego.v2` import** — `and`/`or` keywords and improved `not` semantics. **Opt-in and
  capability-gated**, so it is inert unless a module asks for it. jev-lab's policy declares
  `import rego.v1` and keeps v1 semantics unchanged under 1.22.0.

Pinning 1.22.0 rather than 1.21.4 is therefore safe *and* keeps an option open: M2's policy is being
written fresh in T5, and `and`/`or` with improved `not` would express the allowlist / provenance /
range rules far more plainly than v1's `else` chains. Whether to use `rego.v2` is a T5 decision;
1.21.4 would have foreclosed it.

Also logged from the notes: **static binaries are deprecated.** Irrelevant to this proposal — we take
the binary out of the image, not from a release download — but it retroactively strengthens the CI
decision below, since the release-download path some CI setups use is on its way out.

**Version choice, and the gate catching itself twice.** This is the most useful thing in the entry.

1. The first draft proposed `1.9.0` — a number produced from memory rather than from the release
   list — and **the registry returned a clean, valid digest for it.** A real tag, roughly fourteen
   months stale. Nothing about the digest would have revealed that.
2. The corrected draft proposed `1.21.4`, read from a genuine release list — **pulled three days
   earlier.** `v1.22.0` had shipped on 2026-10-29 and the entry would have recorded a stale choice
   against fresh-looking evidence. The human reviewer caught it, not the process.

> **A digest proves the bytes have not moved. It proves nothing about whether the version was
> chosen, and a release list proves nothing a day after you read it.** M1 T0's rule was *"whether a
> human chose the version or a timestamp did."* Two further cases exist: **neither did** (case 1),
> and **a human chose, from evidence that had since expired** (case 2). A version pin has a
> freshness window, and the gate must re-read the source at the moment of *recording*, not at the
> moment of drafting.

Operationally: re-run the release lookup immediately before applying this entry. If a newer release
exists, that is a new decision, not a formality — particularly across a minor bump, where the
changelog has to be read for Rego-affecting changes before `gateway/policy/`'s tests can be trusted.

**Recorded, not waved past:** the **1.21.4** image reports
`Build Commit: 05c845177c80747a2aabb607f9318f981993cc76-dirty` — the vendor's release build ran from
a dirty working tree. Observed directly on that image; **not re-verified on 1.22.0**, and the entry
says so rather than implying a check that was not run. Worth confirming at apply time with
`docker run --rm openpolicyagent/opa@sha256:895872de... version`. Not a reason to reject either
release, and exactly the sort of thing a dependency gate exists to notice and write down.

### 2. `python:3.13-slim` — base for the gateway and the fixtures

**Digest:** `sha256:b3575dcf816cdacc5292df77a6e3e59b8941631078373a045efa2ac1e9c5c3b2`
*(`python:3.12-slim` is `sha256:12316debbfb86890f6b2d825820612741ba527ad5a44e3902759141d572bfe8f` if
you prefer to match `attacks/README.md`'s stated floor.)*

**What it is for.** `gateway/Dockerfile` and one shared `fixtures/Dockerfile` for `collector` and
`mock-metadata` (same base, different `command:` in Compose). Two Dockerfiles, one base digest.

**Why 3.13 and not 3.12.** `attacks/README.md` says exploits must run on the user's **system** Python
3.12 — that is a floor statement about a machine we do not control, and it is unaffected by what the
gateway image pins. The gateway runs in a container we do control, so it should pin a specific
current version. The two are different environments with different constraints, and conflating them
would mean freezing a container to a floor set for laptops.

**Considered instead:** a distroless Python base (rejected — marginal gain, and `slim` keeps the
image debuggable, which matters for a teaching repo); Alpine (rejected — musl is a real behavioural
difference for a component whose job is DNS resolution and socket dialling, per `SR-B5-3`, and this
is precisely where a libc difference would be a bad surprise).

**Note:** `slim` ships pip, which the gateway never uses. Keeping it is a deliberate simplicity
choice, not an oversight — the stdlib-only rule is enforced by review, not by removing the tool.

**Cost to remove later:** trivial; it is a base image for code that imports only the standard library.

### 3. No Go or Python package dependencies

Stated explicitly so the absence is a decision rather than an omission. `app/go.mod` is unchanged.
The gateway imports `http.client`, `json`, `subprocess`, `os`, `hashlib` — all stdlib. If M2's build
ever reaches for `requests` or `psycopg`, that is a new entry in this file, not a quiet `pip install`.

---

## What this changes about the build — not just about the libraries

AGENTS.md: *a dependency proposal that only evaluates the dependency is incomplete.* pgx ratcheted
the language floor and moved three files, none of them the dependency. Asked and answered for M2:

| Question | Answer |
|---|---|
| **Language floor** | Unchanged. Go stays at `1.25.0`; the OPA binary is static and copied, so its Go 1.27 build has no interaction with ours. |
| **Toolchain pins** | Unchanged for Go. **New:** CI needs `opa` to run the policy suite — see below. |
| **Base images** | Two new: `python:3.13-slim` for the gateway and fixtures. `app/Dockerfile` is untouched. |
| **Build context** | New `gateway/` and `fixtures/` build contexts. The gateway context must **exclude** `gateway/data/` from the image if it ever holds anything secret — today it holds frozen policy data, which is fine, but this is where that stops being true. |
| **Cache keys** | CI's Go cache keys on `app/go.sum` and is unaffected. Docker layer caching is the real change: `make up` now builds three images instead of one, so a cold CI run is meaningfully slower. Budget for it rather than discovering it as a timeout. |
| **Compose services** | `gateway`, `agent`, `mock-metadata`, `collector` — four new, two of them hostile fixtures. `docker-compose.yml` is a hardened zone; the `collector` was never in the plan's reservations (D6). |

**CI's policy test, and the M1 T0 lesson applied.** The suite needs `opa test gateway/policy`. A
`setup-opa` action is a new unreviewed dependency, and a downloaded release is a second pin that can
drift from the one in the image. The answer that avoids both:

```yaml
- name: opa test (same digest the gateway ships)
  run: |
    docker run --rm -v "$PWD/gateway/policy:/policy:ro" \
      openpolicyagent/opa@sha256:895872de1e8dc5b82e04f9410d2d1ada2f72d28fdcdba0e8789d91cfc27ec0d0 \
      test /policy
```

**One pin, used by both CI and production.** M1 T0's finding was that a CI toolchain pin which
`GOTOOLCHAIN=auto` silently overrides stops describing what built the binary. The same failure shape
is available here: a separately-installed CI `opa` would test the policy with a different binary than
the one that enforces it. Using the digest removes the possibility rather than documenting it.

---

## Finding: the repo already contradicts D3's digest argument

D3 justifies pinning OPA by digest because *"a tag can be moved, and pinning by tag would have the
repo contradicting its own stated assumption"* (A8.5). That argument does not stop at OPA, and
`app/Dockerfile` pins by **tag**, twice:

```dockerfile
FROM golang:1.25-alpine AS build
FROM gcr.io/distroless/static-debian12:nonroot
```

Either D3's argument over-reaches, or `app/Dockerfile` under-delivers. **A distinction does exist and
should be written down, because as it stands the repo simply looks inconsistent:**

- The **Go build image** produces output verified downstream by `go.sum` against the
  `sum.golang.org` transparency log. Swapping it cannot inject an unverified dependency into the
  binary — the hashes still have to match.
- **OPA is a binary that makes security decisions at runtime**, and nothing downstream verifies it.
  Swap it and the gate's behaviour changes with no signal anywhere.
- The **distroless runtime base** sits between the two: it ships no code we execute except the
  kernel-facing bits, but a swapped base is a swapped root filesystem under our binary.

**Strength of pinning should follow what the artifact does**, and that sentence was nowhere in the
repo.

**DECIDED 2026-10-31: tags for build and base images, digest for the policy binary, and the
distinction written down.** Rejected: pinning everything by digest. It is consistent and needs no
explanation, but **digest pins receive no security updates** — it trades moving-tag risk for
stale-base risk and requires an update process (Renovate, Dependabot, or a standing manual review)
that this lab does not have. Adopting it without one would look more rigorous while being worse.

This session is itself the argument: the OPA pin went stale **twice in three days**, and both times a
human reading the release list caught it — never the pinning mechanism. A digest is an integrity
control, not a currency control, and treating it as both is how a base image quietly rots for a year.

**The rule is only defensible written down**, so it goes in `AGENTS.md` — a repo rule, not a product
control, and that file is already the single source of truth for rules. Hardened zone; the paragraph
is drafted below for a human to paste in its own commit.

> ### Pinning: strength follows what the artifact does
>
> Not every image in this repo is pinned the same way, and the difference is deliberate.
>
> - **Build images** (`golang:1.25-alpine`) are pinned by **tag**. Their output is verified
>   downstream by `go.sum` against the `sum.golang.org` transparency log, so swapping the image
>   cannot introduce an unverified dependency — the hashes still have to match.
> - **Runtime base images** (`gcr.io/distroless/static-debian12:nonroot`) are pinned by **tag**.
>   They ship no code we execute, though a swapped base is a swapped root filesystem beneath our
>   binary. This is the weakest link in the policy and is accepted knowingly.
> - **Binaries that make security decisions at runtime** (`openpolicyagent/opa`) are pinned by
>   **digest**. Nothing downstream verifies them; swap one and the gate's behaviour changes with no
>   signal anywhere.
>
> A digest is an **integrity** control, not a **currency** control. It guarantees the bytes have not
> moved and guarantees nothing about whether the version is still the right one — so digest pins are
> paired with a human re-reading the release list at the moment of recording, never at the moment of
> drafting. Until this repo has an automated update process, pinning everything by digest would
> trade a moving-tag risk for a stale-base risk and look more rigorous while being worse.

---

## Applying

Per the T0 convention, these are human-applied and land in their **own commit**, separate from
feature code, so the history shows the trust decision as its own reviewable event. `docker-compose.yml`
and `.github/workflows/ci.yml` are hardened zones and are part of the same human-applied change.
Delete this section once applied.
