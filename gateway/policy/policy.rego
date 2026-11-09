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
