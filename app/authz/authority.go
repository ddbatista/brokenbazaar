package authz

import (
	"slices"
	"time"

	"github.com/ddbatista/brokenbazaar/app/store"
)

// The per-action authority checks (m3-delegation.md D3/D4; plan M3 T6 D1).
//
// Authority is re-derived on EVERY action, from the session row and the
// requester's current membership. Nothing is cached at session creation:
// SR-B3-3, "demotion takes effect on the next action" -- the property 05 (ii)
// exists to keep decided. The session id names the session; it never grants.
//
// Two callers, one function, so they cannot disagree:
//   - the authority route, which the gateway asks before it decides;
//   - each internal execution route, which re-checks at execution, closing
//     the gap between the gateway's decision and the write (M3-N2).

// Legs is one boolean per check, and every one means PASSES. A field whose
// zero value is false fails closed: a leg the gateway never received, or a
// struct someone forgot to fill, denies. A field where true meant failing
// ("expired") would invert that, and an absent field would pass (D4).
//
// Two legs are not here, on purpose. The org grant is platform policy and
// lives in policy data, evaluated by OPA (D9). Delegability is a rule about
// delegation, not about roles: the gateway policy's non_delegable set (D6).
// This package keeps no copy of that list -- two copies drift -- and the
// API's side of it is structural: no internal route for a listed tool.
type Legs struct {
	WithinTime  bool `json:"within_time"`
	InScope     bool `json:"in_scope"`
	RolePermits bool `json:"role_permits"`
}

// toolActions maps each agent tool onto the one permission table: an agent
// tool never gets a table of its own. http_fetch is Read -- any role may
// fetch (plan M3 T6 D1). set_member_role maps to its action and passes the
// role leg for an admin; delegability, not the role, is what refuses it.
var toolActions = map[string]Action{
	"read_document":   Read,
	"http_fetch":      Read,
	"update_document": Update,
	"delete_document": Delete,
	"set_member_role": SetMemberRole,
}

// actionFor returns the action a tool performs, and false for a tool the
// map does not name.
func actionFor(tool string) (Action, bool) {
	a, ok := toolActions[tool]
	return a, ok
}

// Derive computes the legs for one tool call at time now. Pure: the caller
// reads the session row and passes the clock, so every leg is testable on
// both sides without a database.
//
// A session is within time strictly BEFORE its expiry; at expires_at it is
// already expired. A tool the map does not name fails the role leg.
func Derive(s store.SessionAuthority, tool string, now time.Time) Legs {
	legs := Legs{
		WithinTime: now.Before(s.ExpiresAt),
		InScope:    slices.Contains(s.Scope, tool),
	}
	if action, ok := actionFor(tool); ok {
		legs.RolePermits = Permits(s.RoleNow, action)
	}
	return legs
}

// Failing names the first failing leg in the policy's evaluation order
// (plan M3 T6 D5), or "" when every leg passes. The internal execution
// routes report it, so a refusal at execution names the same reason the
// gate would have named at decision time.
func (l Legs) Failing() string {
	switch {
	case !l.WithinTime:
		return "session_expired"
	case !l.InScope:
		return "not_in_session_scope"
	case !l.RolePermits:
		return "role_does_not_permit"
	}
	return ""
}
