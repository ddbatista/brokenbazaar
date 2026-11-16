package store

import "testing"

// The three roles, stated literally, and nothing else: the Go side of the
// membership_role domain (migration 003).
func TestRoleValid(t *testing.T) {
	for _, r := range []Role{RoleAdmin, RoleMember, RoleViewer} {
		if !r.Valid() {
			t.Errorf("%q should be valid", r)
		}
	}
	for _, r := range []Role{"", "owner", "Admin", "admin ", "set_member_role"} {
		if r.Valid() {
			t.Errorf("%q should not be valid", r)
		}
	}
}
