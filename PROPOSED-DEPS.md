# Proposed dependencies — for a human to apply

`go.mod`, `go.sum` and every other dependency manifest are **hardened zones** (`CLAUDE.md`). The
coding agent does not edit them. It proposes here; a human decides, applies, and commits.

Each entry states what the dependency is for, what was considered instead, and what it would cost to
remove later. An entry is deleted from this file once it is applied.

---

## M1 — PostgreSQL driver

**Proposed:** `github.com/jackc/pgx/v5` **v5.11.0**

Pinned explicitly rather than taken as `@latest`. Go records a concrete version either way — there
are no version ranges in `go.mod` — so the difference is not pinned-vs-floating, it is **whether a
human chose the version or a timestamp did**. In a repo whose argument is that its commit history is
evidence, the command in that history should show the choice.

Verified at proposal time against `proxy.golang.org`:

```
v5.11.0   released 2026-09-07   tag -> github.com/jackc/pgx @ 5e583fa
```

Two checks that are the point of the rule, not ceremony:

- **Age.** ~4 weeks in the wild with no advisory. Most ecosystem compromises surface within
  days-to-weeks of publication; a same-day release is a different risk than a month-old one.
- **Origin.** The proxy reports the tag resolving to the real `jackc/pgx` repository. A fork or a
  redirect here is the typosquat tell.

**Needed by:** M1 T2–T5 — schema, seed, both store implementations, every document handler.

**Why this one**

- It is the de facto standard Postgres driver for Go and the one the ecosystem reviews.
- `pgx/v5` has **no non-test dependencies outside `github.com/jackc/*` and `golang.org/x/*`**, which
  keeps the transitive surface small and auditable — the thing that matters for a repo whose own
  threat model treats third-party code as untrusted (B6).
- Native protocol implementation with real prepared statements. Parameterised queries are the
  mechanism M1's store layer depends on, in both modes: **SQL injection is declared non-coverage in
  this lab** (B1 leaf 4), so every statement in `app/store/` must be parameterised whether it is the
  vulnerable path or the hardened one. The vulnerable store forgets the *tenant* predicate; it does
  not concatenate strings. Keeping those two failure modes separate is what makes finding 01 teach
  one thing instead of two.

**Considered and rejected**

| Alternative | Why not |
|---|---|
| `database/sql` + `lib/pq` | Still a dependency, so it does not avoid this decision; `lib/pq` is in maintenance mode and upstream points new work at `pgx`. |
| `database/sql` + `pgx/v5/stdlib` | Possible, and keeps the door open — `pgx` ships this adapter, so adopting the native API now does not foreclose it. Rejected only because the native API is clearer to read, and this code is read as teaching material. |
| No driver — stdlib only | Would require implementing the Postgres wire protocol by hand. Not a tenancy lesson, and the hand-rolled code would become the least trustworthy thing in the repo. Note the contrast with JWT, which **is** hand-rolled on purpose (M1 diff §1 D3): HMAC-SHA256 over two base64 segments is ~40 lines of standard library and the forgery path must be visible in product code. The line is drawn at *is the mechanism the lesson?*, not at *can it be written without pip*. |
| SQLite / in-memory store | Removes the deployment realism the lab needs, and `docker-compose.yml` (hardened zone) already defines Postgres. |

**Reversibility:** confined to `app/store/`. Swapping drivers later touches one package and no
handler. Low lock-in.

**Cost this proposal failed to predict — recorded rather than quietly fixed.** As written, the
proposal weighed the transitive dependency set and nothing else. Applying it moved three things the
proposal never mentioned:

| Knock-on | Why it was missed |
|---|---|
| `app/go.mod` ratcheted `go 1.22` → `go 1.25.0` | pgx v5.11.0 declares `go 1.25.0`. Go raises the consuming module to match and never lowers it. A dependency's *language version floor* is part of what you are adopting, and it is not visible in the import graph. |
| `.github/workflows/ci.yml` toolchain pin | Followed from the ratchet. Notably it would **not** have failed — `GOTOOLCHAIN=auto` downloads the newer toolchain silently. Logged as a real-world instance of SR-M1-1 in `threat-models/m1-tenancy.md` §4. |
| `app/Dockerfile` base image and build context | Same ratchet, plus `COPY go.mod ./` predating the existence of a `go.sum` — the image was resolving modules with no hashes to verify against, discarding the integrity guarantee that made a reviewed dependency worth reviewing. |

The lesson for the next entry in this file, and the reason it is written here instead of in a commit
message: **a dependency proposal that only evaluates the dependency is incomplete.** Ask what it
changes about the *build* — language floor, toolchain pins, base images, build context, cache keys —
because those are the files a reviewer skims and an agent is not allowed to touch, which is precisely
the combination that lets a change land unexamined.

**Note on `attacks/`:** unaffected. The PoC contract is stdlib-Python-only and stays that way — the
exploits talk HTTP to the API and never touch the database.

### Apply

```bash
cd app
go get github.com/jackc/pgx/v5@v5.11.0
go mod tidy
```

**Inspect `go.sum` before committing.** It should contain only `github.com/jackc/*` (pgx, puddle,
pgpassfile, pgservicefile) and `golang.org/x/*` (crypto, text, sync). Anything else arrived
transitively and deserves a second look.

`go.sum` — not `go.mod` — is the artifact with security value: it carries SHA-256 hashes verified
against `sum.golang.org`, a transparency log whose entries cannot be retroactively altered. A git tag
can be moved; a logged hash cannot. Both files are hardened zones for that reason.

Then commit `app/go.mod` and `app/go.sum` **in their own commit**, separate from any feature code, so
the history shows the trust decision as its own reviewable event:

```
deps: add pgx/v5 — Postgres driver for M1 store layer

Proposed in PROPOSED-DEPS.md, applied by hand. go.mod is a hardened zone
(CLAUDE.md); the agent does not edit dependency manifests.
```
