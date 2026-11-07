# Proposed policy — for a human to apply

`gateway/policy/` is a **hardened zone** (`AGENTS.md`). The coding agent does not write it. It
proposes here; a human reviews, applies, and commits — in its **own commit**, separate from feature
code, so the trust decision is its own reviewable event.

AGENTS.md's test for zone membership — *"if a change here were subverted, would it remove the
ability to detect the subversion?"* — answers **yes twice** for these files: the policy decides what
is allowed, **and** it decides what the audit record will say happened. `redact.json` is here for the
same reason: *what counts as a secret* is a security decision, not a code detail.

**Status: verified, not applied.** Every file below was run against the digest-pinned OPA
(`1.22.0`, `sha256:895872de…`) before being written here — `opa test` reports **8/8 PASS**. Delete
this file once applied.

---

## Apply

```sh
# from the repo root, with the four files pasted in from the sections below
mkdir -p gateway/policy
$EDITOR gateway/policy/policy.rego        # section 1
$EDITOR gateway/policy/policy_test.rego   # section 2
$EDITOR gateway/policy/data.json          # section 3
$EDITOR gateway/policy/redact.json        # section 4 -- or copy it, see the note there

# verify against the SAME digest the gateway ships (PROPOSED-DEPS.md's one-pin rule)
docker run --rm -v "$PWD/gateway/policy:/policy:ro" \
  openpolicyagent/opa@sha256:895872de1e8dc5b82e04f9410d2d1ada2f72d28fdcdba0e8789d91cfc27ec0d0 \
  test /policy
# expect: PASS: 8/8

# the Go drift test turns green the moment redact.json lands
cd app && go test ./redact/... && cd ..

git add gateway/policy
git commit -F .git/POLICY_COMMIT_MSG   # message drafted at the bottom of this file
```

---

## The fail-open this policy shipped in its first draft, and how it was caught

Recorded rather than quietly fixed, per the house rule — and it is the most useful thing in this
document.

The first draft's capability leg read:

```rego
violations contains "unknown_tool" if {
	not input.tool in data.tools
}
```

Against a well-formed request that is correct. Against `{}` it is a **fail-open**. An undefined
`input.tool` makes the membership expression undefined, so the rule body never succeeds, **no
violation is added**, `count(ordered_violations) == 0`, and the decision is **`allow`**. Verified
directly against the pinned binary:

```
$ echo '{}' | opa eval -d policy -I -f json 'data.bazaar.gate.decision'
{"reasons": ["policy_satisfied"], "route": "allow"}
```

Every leg in that policy was present, plausible, and individually correct. **Reading it does not
reveal the bug** — five legs are visible and each one does what it says. Only
`test_empty_input_is_denied` failed, and it failed on the first run of the suite.

The fix is total lookups with explicit defaults, and the asymmetry is the fail-closed direction made
explicit:

| lookup | default | why that direction |
|---|---|---|
| `tool` | `""` | an unnamed tool is not in `data.tools`, so it trips leg 1 instead of skipping every leg |
| `resolved.host` | `""` | an unresolved host is not on the allowlist |
| `resolved.denied_range` | **`true`** | an address that was never classified is treated as **denied**, never as clean |

That last default is the one worth staring at. `false` reads more naturally and would mean *"a fetch
whose address we failed to classify is fine"* — precisely the property `SR-B7-1` exists to deny.

**The generalisable lesson, which is the repo's own thesis arriving in its own policy:** in Rego, an
undefined operand inside a negated expression does not fail loudly, it silently removes the rule from
consideration — so a deny-by-default policy can be defeated by *omission* rather than by crafting a
value. A policy is not fail-closed because its `default` says `deny`; it is fail-closed when the
**empty and malformed cases are tested**. `SR-B5-5` says fail-closed must be *verified*, and this is
the second instrument that argues for it (the fault shims in `gateway/test_faults/` are the first).

---

## 1. `gateway/policy/policy.rego`

```rego
# BrokenBazaar gateway policy (M2, T5 decision D5.3).
#
# HARDENED ZONE. The agent drafts; a human applies and commits. The test
# AGENTS.md gives for zone membership -- "if a change here were
# subverted, would it remove the ability to detect the subversion?" --
# answers yes here twice over: this file decides what is allowed, and it
# decides what the audit record will say happened.
#
# EVALUATION ORDER IS THE DESIGN, not a detail (D6, D5.3):
#
#     capability -> allowlist -> range -> provenance -> default deny
#
# Only the FIRST failing leg is reported. That is load-bearing, and the
# reason is specific rather than aesthetic: both M2 fixtures sit in
# RFC1918 space on the Compose bridge, so attacker.example fails BOTH the
# allowlist leg and the range leg. A policy that reported every failing
# leg would give finding 03 two reasons, one of which ("private
# address") is an artifact of the lab that would not generalise to an
# attacker on a public IP. Reporting the first leg gives each finding its
# own distinct, honest denial reason, which is what the PoCs assert on.
#
# Range is evaluated BEFORE provenance so that finding 04's reason is
# stable however the PoC drives the call: driven directly with clean
# provenance, or driven through the document with untrusted provenance,
# the range leg fires either way. The reverse order would couple the
# asserted reason to the PoC's provenance, which an evidence contract
# cannot afford.
#
# THE REASONS NEVER REACH THE AGENT (D5.3, SR-B7-7 read against leaf
# B7 2.2). The gate returns a uniform "gateway denied"; these strings go
# to gateway.jsonl only. An attacker who could read "resolved_address_
# denied" would have learned the host PASSED the allowlist -- precisely
# where to point a rebinding attack.
#
# NO http.send AND NO DNS HERE. The gateway resolves the hostname and
# classifies the address, then hands those facts in as input.resolved.
# Policy decides; it never fetches (the jev-lab port's central point).

package bazaar.gate

import rego.v1

# TOTAL LOOKUPS, AND THE FAIL-OPEN THEY EXIST TO PREVENT.
#
# These three lines are the most important in the file, and they were
# added after a test caught the bug -- recorded here rather than quietly
# fixed, per the house rule.
#
# The first draft read `not input.tool in data.tools`. Against a
# well-formed request that is correct. Against `{}` it is a FAIL-OPEN: an
# undefined `input.tool` makes the membership expression undefined, the
# rule body never succeeds, NO violation is added, and a policy whose
# every visible leg looks right returns ALLOW. Reading the policy does
# not reveal this -- every leg is present and plausible -- and only
# test_empty_input_is_denied failed.
#
# object.get with a default is TOTAL: there is no undefined left to
# swallow a leg. Note the asymmetry in the defaults, which is the
# fail-closed direction made explicit:
#
#   tool         -> ""     an unnamed tool is not in data.tools, so it
#                          trips leg 1 instead of skipping every leg
#   host         -> ""     an unresolved host is not on the allowlist
#   denied_range -> TRUE   an address that was never classified is
#                          treated as denied, never as clean
#
# That last default is the one worth staring at. `false` would read
# naturally and would mean "a fetch whose address we failed to classify
# is fine", which is precisely the property SR-B7-1 exists to deny.
tool := object.get(input, "tool", "")

resolved := object.get(input, "resolved", {})

derived_from := object.get(input, ["provenance", "derived_from"], [])

# Leg 1 -- capability. D7 made concrete: the lookup is real, the table is
# static, and in M2 it contains every tool, because a session is created
# with every grant in scope. That is violated-by-design, named as such in
# the threat model, and M3 swaps the DATA without touching this
# mechanism. A leg that exists and passes is not theatre: it is the seam
# the redesign lands in, and it is tested.
violations contains "unknown_tool" if {
	not tool in data.tools
}

violations contains "capability_denied" if {
	tool in data.tools
	not tool in data.capabilities
}

# Leg 2 -- egress allowlist, on the RESOLVED host.
#
# metadata.google.internal is deliberately ON this list. It models the
# operator mistake that makes the range leg earn its keep, and finding 04
# requires it: the finding must pass the allowlist in order to die at the
# range check. attacker.example is deliberately OFF it, which is what
# makes finding 03's evidence the allowlist leg.
violations contains "egress_not_allowlisted" if {
	tool == "http_fetch"
	not object.get(resolved, "host", "") in data.egress_allowlist
}

# Leg 3 -- the resolved address.
#
# SR-B7-1: by range, never by string match. The classification is
# computed by the gateway with ipaddress parsing (the same tested
# function the fetcher uses), so octal, decimal and v4-mapped-v6
# encodings of 169.254.169.254 all collapse to the same answer before
# policy ever sees them.
violations contains "resolved_address_denied" if {
	tool == "http_fetch"
	object.get(resolved, "denied_range", true) == true
}

# Leg 4 -- provenance.
#
# SR-B7-2 / SR-B4-12 / SR-B5-4: an outbound request carrying
# tenant-derived content is denied EVEN WHEN THE DESTINATION IS
# ALLOWLISTED. Allowlisting is a host decision; this is a payload
# decision, and the requirements insist they are different questions.
#
# No PoC asserts this reason in M2 -- finding 03 dies one leg earlier --
# but the leg is real, tested, and is what would catch the same
# exfiltration aimed at docs.example.
violations contains "tenant_data_egress" if {
	tool == "http_fetch"
	"untrusted" in derived_from
}

# The ordered leg list. A comprehension over an ARRAY preserves order, so
# ordered_violations is the failing legs in evaluation order and
# ordered_violations[0] is the first one.
leg_order := [
	"unknown_tool",
	"capability_denied",
	"egress_not_allowlisted",
	"resolved_address_denied",
	"tenant_data_egress",
]

ordered_violations := [leg |
	some i
	leg := leg_order[i]
	leg in violations
]

# SR-B5-5: fail closed. The default is a deny, so a policy that fails to
# evaluate, a query that goes undefined, or a leg that errors all land on
# a refusal rather than on an empty allow. This is verified by FAULT
# INJECTION (killing the process), not by reading this line -- the
# requirement says verified, and a default anyone can read is not
# evidence that the path taken under failure is this one.
default decision := {"route": "deny", "reasons": ["default_deny"]}

decision := {"route": "deny", "reasons": [ordered_violations[0]]} if {
	count(ordered_violations) > 0
}

decision := {"route": "allow", "reasons": ["policy_satisfied"]} if {
	count(ordered_violations) == 0
}
```

---

## 2. `gateway/policy/policy_test.rego`

```rego
# Policy tests, run by `opa test` against the SAME digest the gateway
# ships (PROPOSED-DEPS.md's one-pin rule: a separately-installed CI opa
# would test the policy with a different binary than the one that
# enforces it).
#
# These test the POLICY. The gate's behaviour when OPA itself fails is a
# different question with a different instrument -- the fault shims in
# gateway/test_faults/ -- because no amount of policy testing can tell
# you what happens when the policy engine is dead.

package bazaar.gate_test

import rego.v1

import data.bazaar.gate

policy_data := {
	"tools": ["read_document", "http_fetch"],
	"capabilities": ["read_document", "http_fetch"],
	"egress_allowlist": ["docs.example", "metadata.google.internal"],
}

# --- the allow path ---------------------------------------------------

test_read_document_is_allowed if {
	d := gate.decision with input as {
		"tool": "read_document",
		"args": {"id": "4db02253-bccf-4cd0-a513-ae84ea18ead4"},
		"session": {"org": "acme"},
		"provenance": {"derived_from": ["user"]},
		"resolved": {},
	}
		with data.tools as policy_data.tools
		with data.capabilities as policy_data.capabilities
		with data.egress_allowlist as policy_data.egress_allowlist

	d.route == "allow"
}

test_clean_fetch_to_an_allowlisted_host_is_allowed if {
	d := gate.decision with input as {
		"tool": "http_fetch",
		"args": {"url": "http://docs.example/a"},
		"session": {"org": "acme"},
		"provenance": {"derived_from": ["user"]},
		"resolved": {"host": "docs.example", "ip": "93.184.216.34", "denied_range": false},
	}
		with data.tools as policy_data.tools
		with data.capabilities as policy_data.capabilities
		with data.egress_allowlist as policy_data.egress_allowlist

	d.route == "allow"
}

# --- finding 03: the allowlist leg ------------------------------------

# THE ORDERING TEST. attacker.example fails the allowlist leg AND the
# range leg (the Compose bridge is RFC1918) AND the provenance leg (the
# document is untrusted). Exactly one reason must come back, and it must
# be the allowlist -- otherwise finding 03's evidence becomes "private
# address", which is an artifact of the lab rather than the control.
test_finding_03_dies_at_the_allowlist_with_one_reason if {
	d := gate.decision with input as {
		"tool": "http_fetch",
		"args": {"url": "http://attacker.example/collect?data=x"},
		"session": {"org": "acme"},
		"provenance": {"derived_from": ["user", "untrusted"]},
		"resolved": {"host": "attacker.example", "ip": "172.20.0.9", "denied_range": true},
	}
		with data.tools as policy_data.tools
		with data.capabilities as policy_data.capabilities
		with data.egress_allowlist as policy_data.egress_allowlist

	d.route == "deny"
	count(d.reasons) == 1
	d.reasons[0] == "egress_not_allowlisted"
}

# --- finding 04: the range leg ----------------------------------------

test_finding_04_passes_the_allowlist_and_dies_at_the_range if {
	d := gate.decision with input as {
		"tool": "http_fetch",
		"args": {"url": "http://metadata.google.internal/computeMetadata/v1/"},
		"session": {"org": "acme"},
		"provenance": {"derived_from": ["user"]},
		"resolved": {"host": "metadata.google.internal", "ip": "169.254.169.254", "denied_range": true},
	}
		with data.tools as policy_data.tools
		with data.capabilities as policy_data.capabilities
		with data.egress_allowlist as policy_data.egress_allowlist

	d.route == "deny"
	count(d.reasons) == 1
	d.reasons[0] == "resolved_address_denied"
}

# The same finding driven THROUGH the poisoned document: untrusted
# provenance is present, and the reason must not change. This is why the
# range leg sits before the provenance leg -- the asserted evidence must
# not depend on how the PoC chose to drive the call.
test_finding_04_reason_is_stable_under_untrusted_provenance if {
	d := gate.decision with input as {
		"tool": "http_fetch",
		"args": {"url": "http://metadata.google.internal/computeMetadata/v1/"},
		"session": {"org": "acme"},
		"provenance": {"derived_from": ["user", "untrusted"]},
		"resolved": {"host": "metadata.google.internal", "ip": "169.254.169.254", "denied_range": true},
	}
		with data.tools as policy_data.tools
		with data.capabilities as policy_data.capabilities
		with data.egress_allowlist as policy_data.egress_allowlist

	d.reasons[0] == "resolved_address_denied"
}

# --- the provenance leg, which no M2 PoC reaches ----------------------

# SR-B7-2: allowlisting is a host decision, never a payload decision. An
# allowlisted destination with a public address and tenant-derived
# content is still a denial.
test_tenant_data_to_an_allowlisted_host_is_denied if {
	d := gate.decision with input as {
		"tool": "http_fetch",
		"args": {"url": "http://docs.example/collect?data=Acme+Q3"},
		"session": {"org": "acme"},
		"provenance": {"derived_from": ["user", "untrusted"]},
		"resolved": {"host": "docs.example", "ip": "93.184.216.34", "denied_range": false},
	}
		with data.tools as policy_data.tools
		with data.capabilities as policy_data.capabilities
		with data.egress_allowlist as policy_data.egress_allowlist

	d.route == "deny"
	d.reasons[0] == "tenant_data_egress"
}

# --- fail closed ------------------------------------------------------

test_an_unknown_tool_is_denied if {
	d := gate.decision with input as {
		"tool": "exfiltrate",
		"args": {},
		"session": {"org": "acme"},
		"provenance": {"derived_from": ["user"]},
		"resolved": {},
	}
		with data.tools as policy_data.tools
		with data.capabilities as policy_data.capabilities
		with data.egress_allowlist as policy_data.egress_allowlist

	d.route == "deny"
	d.reasons[0] == "unknown_tool"
}

# Empty input must not be an allow. A policy whose empty case allows is
# the shape a garbage-emitting engine turns into a bypass.
test_empty_input_is_denied if {
	d := gate.decision with input as {}
		with data.tools as policy_data.tools
		with data.capabilities as policy_data.capabilities
		with data.egress_allowlist as policy_data.egress_allowlist

	d.route == "deny"
}
```

---

## 3. `gateway/policy/data.json`

The allowlist membership is **load-bearing for both findings** (D5.3), so it is worth stating why
each entry is where it is rather than treating this as configuration:

- **`metadata.google.internal` is ON the allowlist, deliberately.** Finding 04 must *pass* the
  allowlist in order to die at the range check. It also models the real operator mistake that makes
  the range leg earn its keep — an allowlist entry that looks reasonable and is not.
- **`docs.example` is ON it** so the allow path is real and the redirect variant (B7 1.2) has an
  approved first hop.
- **`attacker.example` is OFF it**, which is what makes finding 03's evidence the *allowlist* leg.

Getting this backwards inverts both findings' asserted evidence.

`capabilities` contains every tool: D7's violated-by-design made concrete. The lookup is real and
tested; the *data* is what M3's redesign replaces.

```json
{
  "tools": [
    "read_document",
    "http_fetch"
  ],
  "capabilities": [
    "read_document",
    "http_fetch"
  ],
  "egress_allowlist": [
    "docs.example",
    "metadata.google.internal"
  ]
}
```

---

## 4. `gateway/policy/redact.json`

**This file already exists verbatim at `app/redact/redact.json`**, where Go embeds it (go:embed
cannot reach outside its package directory). Rather than retyping it, copy it — the two must be
byte-identical or `TestEmbeddedCopyMatchesPolicyFile` fails the build, which is the whole point of
the drift guard:

```sh
cp app/redact/redact.json gateway/policy/redact.json
```

For review, the content is:

```json
{
  "headers": ["authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key", "x-auth-token"],
  "fields_exact": ["password", "secret", "credential", "private_key", "access_key"],
  "fields_suffix": ["_key", "_token", "_secret", "_password", "_credential"],
  "_residual": "Free-form values are NOT covered: a URL query parameter may carry anything (finding 03's data= parameter carries tenant bytes by design), as may novel field names and non-string encodings. Redaction is by field name, never by value shape (M2-N2). Pinned by the residual tests in app/redact/redact_test.go and gateway/test_gate.py, which assert a token inside a URL SURVIVES."
}
```

The `_residual` field is not boilerplate. Redaction is by field **name**, never by value shape
(M2-N2) — so a token inside a URL query value **survives**, by design, and two tests
(`app/redact/redact_test.go`, `gateway/test_gate.py`) **pin that gap as known**. A future change that
starts mangling URLs must fail those tests and re-declare the residual consciously, rather than
silently blinding T9's detector, which reads `url` out of the audit store.

---

## Commit message

Write it to a file and use `git commit -F` — inline `-m` with backticks gets shell-substituted (the
T2 lesson):

```
M2 T5: gateway policy -- ordered legs, fail closed, reasons that never leave

Five evaluation legs in one order that is load-bearing:

    capability -> allowlist -> range -> provenance -> default deny

Only the FIRST failing leg is reported, because both M2 fixtures sit in
RFC1918 space on the Compose bridge: a policy reporting every failing leg
would give finding 03 both "egress_not_allowlisted" and
"resolved_address_denied", and the second is an artifact of the lab that
would not generalise to an attacker on a public IP. Range is evaluated
before provenance so finding 04's reason is stable however the PoC drives
the call.

The reasons never reach the agent (SR-B7-7 against leaf B7 2.2): the gate
answers a uniform "gateway denied" and the reasons go to gateway.jsonl,
where the PoCs read them. A reason on the wire is an existence oracle --
"resolved_address_denied" tells an attacker the host PASSED the allowlist.

metadata.google.internal is on the allowlist deliberately: finding 04 must
pass the allowlist to die at the range check, and it models the operator
mistake that makes the range leg earn its keep.

The first draft of this policy was FAIL-OPEN on empty input: an undefined
input.tool made every leg undefined, violations empty, and the decision
allow. Caught by test_empty_input_is_denied, not by reading the policy.
Fixed with total object.get lookups whose defaults all point closed --
denied_range defaults to true, because an address that was never
classified must not read as clean.

Verified: opa test 8/8 against the digest the gateway ships.
Boundary: B5, B7. Plants no vulnerability. Behind HARDENED: n/a (policy).
```
