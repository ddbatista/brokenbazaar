package main

import (
	"testing"

	"github.com/ddbatista/brokenbazaar/app/authz"
	"github.com/ddbatista/brokenbazaar/app/store"
)

// Plan M3 T3 D3: one decision for every document route. Membership first, so
// a non-member's answer is M1's uniform 404 whatever the action -- the
// role must never be consulted for someone who is not in the org, or a 403
// would confirm the org exists and the caller is merely under-privileged.
// Then the role, against the one table (authz).
func TestAccessDecision(t *testing.T) {
	cases := []struct {
		name   string
		member bool
		role   store.Role
		action authz.Action
		want   access
	}{
		{"non-member, even as an admin claim", false, store.RoleAdmin, authz.Read, accessNotFound},
		{"non-member asking for a write", false, store.RoleViewer, authz.Delete, accessNotFound},
		{"viewer reads", true, store.RoleViewer, authz.Read, accessGranted},
		{"viewer deletes", true, store.RoleViewer, authz.Delete, accessForbidden},
		{"viewer updates", true, store.RoleViewer, authz.Update, accessForbidden},
		{"member creates", true, store.RoleMember, authz.Create, accessGranted},
		{"member deletes", true, store.RoleMember, authz.Delete, accessForbidden},
		{"admin deletes", true, store.RoleAdmin, authz.Delete, accessGranted},
		// A token minted before T3, or forged without a role, reaches the
		// vulnerable path with role "": refused, never treated as allowed.
		{"member with an empty role", true, "", authz.Read, accessForbidden},
	}
	for _, c := range cases {
		if got := accessFor(c.member, c.role, c.action); got != c.want {
			t.Errorf("%s: accessFor = %v, want %v", c.name, got, c.want)
		}
	}
}
