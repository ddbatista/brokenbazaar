# BrokenBazaar gateway policy (M2, T5 decision D5.3; M3 T6 -- the
# per-session authority legs, m3-delegation.md D4/D9; M3 T7 -- the
# non-delegable denylist, D6).
#
# HARDENED ZONE. The agent drafts; a human applies and commits. The test
# AGENTS.md gives for zone membership -- "if a change here were
# subverted, would it remove the ability to detect the subversion?" --
# answers yes here twice over: this file decides what is allowed, and it
# decides what the audit record will say happened.
#
# EVALUATION ORDER IS THE DESIGN, not a detail (D6, D5.3; M3 T6 D5):
#
#     tool known -> delegable -> time -> session scope -> org grant
#                -> role -> allowlist -> range -> provenance -> default deny
#
# The authority legs come before the egress legs, and each finding still
# gets its own reason, because each PoC's session requests the scope its
# flow needs (m3-delegation.md D7): 03 and 04 pass every authority leg and
# die at the allowlist and the range, as in M2; 05 dies at the role; the 03
# least-privilege variant dies at the scope; finding 06 dies at
# delegability, which comes before every session leg so that no session
# fact -- expired, out of scope -- can hide an attempt at a control-plane
# action behind a more ordinary reason.
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

# M3 T6: the session's authority NOW, established by the gateway from the
# API's authority route (gateway/authority.py), never from the agent's
# payload. Each leg is a boolean that means PASSES, and a leg that is
# missing reads as FAILING -- the same fail-closed direction as
# denied_range above. A leg named for failure ("expired") would invert
# that, and a missing field would pass (m3-delegation.md D4).
legs := object.get(input, ["authority", "legs"], {})

passes(leg) if object.get(legs, leg, false) == true

# The org the session row names. "" when the gateway could not establish
# it, which no grant lists.
org := object.get(input, ["session", "org"], "")

derived_from := object.get(input, ["provenance", "derived_from"], [])

# Leg 1 -- the tool exists at all.
violations contains "unknown_tool" if {
	not tool in data.tools
}

# Leg 2 -- delegability (m3-delegation.md D6; SR-B3-7, SR-B8-2): AUTHORITY
# IS DELEGABLE; THE AUTHORITY TO CHANGE THE DELEGATION IS NOT.
#
# A tool on this list is denied to every agent session, whatever the
# session's scope, the org's grants or the requester's role. The role leg
# would ALLOW set_member_role for an admin, correctly -- the admin may do
# it directly (PATCH /orgs/{org}/members/{user}) -- so the ceiling alone
# cannot stop an admin's agent being steered into it by a document
# (finding 06). That needs this leg. Not forbidden; not delegable.
#
# SR-B8-2 asks for an EXPLICIT entry, "not by the accident of nothing
# being implemented yet": until M3 T7 set_member_role died at unknown_tool,
# which is a denial nobody decided. It is in data.tools now, so it reaches
# this leg and is refused by name.
#
# A CONSTANT HERE, NOT POLICY DATA (M3 T7 D1). data.json is deploy-time
# configuration that varies by deployment (grants, the allowlist); this is
# an invariant. A swapped or trimmed data file must not be able to empty
# it, and a constant cannot be missing, so there is no undefined to fail
# open on. M4b extends this set (SR-B9-10: installing a skill).
#
# Enforced twice: here by policy, and by STRUCTURE -- no internal execution
# route exists for any tool on this list, so an allow could not execute it
# (the API's TestNonDelegableToolsHaveNoInternalRoute reads this set).
non_delegable := {"set_member_role"}

violations contains "control_plane_not_delegable" if {
	tool in non_delegable
}

# M2's second leg, capability_denied against a static data.capabilities
# list, is RETIRED here (M3 T6 D5). It was the seam M2 left for exactly
# this redesign -- "the lookup is real, the table is static" -- and the four
# legs below replace it with authority re-derived per session and per call.

# Leg 3 -- time. sessions.expires_at against now, computed by the API.
violations contains "session_expired" if {
	not passes("within_time")
}

# Leg 4 -- session scope: the tools the session asked for at creation
# (SR-B3-5). Consent, not authority (M3-N5): it can only narrow.
violations contains "not_in_session_scope" if {
	not passes("in_scope")
}

# Leg 5 -- the org's grants, in policy data (m3-delegation.md D9): deploy-
# time, read-only at runtime (SR-B8-3), reviewed as a diff in this zone.
# Keyed by the org the SESSION ROW names. An org the data does not list is
# granted nothing -- there is no default grant, because a default is a
# fail-open.
violations contains "org_grant_absent" if {
	not tool in object.get(org_grants, org, [])
}

# Total, like the lookups at the top: policy data with no org_grants at all
# grants nothing, rather than leaving the leg undefined (and so silent).
# A defaulted rule, not object.get(data, ...): reading the whole data tree
# from a rule makes the policy depend on every package under data,
# including its own tests -- a recursion OPA refuses to compile.
default org_grants := {}

org_grants := data.org_grants

# Leg 6 -- the requester's role NOW, against the one permission table.
# Computed in Go by the same function the direct routes call (D4: role
# semantics written a second time, here, would drift). This is the ceiling
# (SR-B3-8): the agent may do only what its user could do directly.
violations contains "role_does_not_permit" if {
	not passes("role_permits")
}

# Leg 7 -- egress allowlist, on the RESOLVED host.
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

# Leg 8 -- the resolved address.
#
# SR-B7-1: by range, never by string match. The classification is
# computed by the gateway from the RESOLVED address (the same tested
# function the fetcher uses). getaddrinfo canonicalises octal and decimal
# spellings of 169.254.169.254 before classification, and ipaddress
# unwraps v4-mapped-v6, so all of them reach this leg as one answer.
# (ipaddress alone rejects the octal and decimal forms -- corrected at M2 T10.)
violations contains "resolved_address_denied" if {
	tool == "http_fetch"
	object.get(resolved, "denied_range", true) == true
}

# Leg 9 -- provenance.
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
	"control_plane_not_delegable",
	"session_expired",
	"not_in_session_scope",
	"org_grant_absent",
	"role_does_not_permit",
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
