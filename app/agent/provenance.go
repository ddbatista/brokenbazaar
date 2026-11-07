package agent

// DerivedFrom computes the provenance the platform attaches to a call:
// the distinct trust origins present in the context that produced the
// action (D1a: the label was never for the model -- it is for the gate).
// System-role spans are excluded, because the platform prompt is a
// constant present in every call and carries no per-call information;
// both illustrations in the committed diff show derived_from without it.
//
// This is platform code computing platform-owned state, never model
// output. The model has no way to alter what this function returns,
// because it reads Origin fields the model never sees and the model
// cannot touch. Falsifying it requires process compromise, not prompt
// influence -- the same severity class as M2-N1, and declared there.
//
// The asymmetry this produces between modes is deliberate, and is itself
// measurable in T9: in hardened mode, turn 2 of finding 03 reports
// ["user" "untrusted"]; in vulnerable mode the naive assembler has merged
// the whole context into one system-labelled span, so this returns an
// EMPTY list -- the agent's own telemetry recording, honestly, that the
// build could not tell where its content came from. That difference is
// the B4 2.1 bug visible as data, which is the point of having the
// vulnerable mode log at all (D4's second writer).
func DerivedFrom(spans []Span) []string {
	var out []string
	seen := map[Origin]struct{}{}
	for _, s := range spans {
		if s.Role == RoleSystem {
			continue
		}
		if _, dup := seen[s.Origin]; dup {
			continue
		}
		seen[s.Origin] = struct{}{}
		out = append(out, string(s.Origin))
	}
	if out == nil {
		// Marshal as [] rather than null: the wire contract and the audit
		// records show an empty list, never a missing field.
		out = []string{}
	}
	return out
}
