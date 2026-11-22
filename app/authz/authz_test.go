package authz

import (
	"testing"

	"github.com/ddbatista/brokenbazaar/app/store"
)

// The table in threat-models/m3-delegation.md D1, every cell. Written out
// in full rather than derived from a rank, so the test states the policy
// and the implementation has to agree with it -- a test that computed
// "admin >= member >= viewer" would agree with any implementation that
// made the same assumption.
func TestEveryRoleActionCell(t *testing.T) {
	want := map[store.Role]map[Action]bool{
		store.RoleViewer: {Read: true, Create: false, Update: false, Delete: false, SetMemberRole: false, InstallTool: false},
		store.RoleMember: {Read: true, Create: true, Update: true, Delete: false, SetMemberRole: false, InstallTool: false},
		store.RoleAdmin:  {Read: true, Create: true, Update: true, Delete: true, SetMemberRole: true, InstallTool: true},
	}
	for role, row := range want {
		for action, allowed := range row {
			if got := Permits(role, action); got != allowed {
				t.Errorf("Permits(%s, %s) = %v, want %v", role, action, got, allowed)
			}
		}
	}
}

// The table names exactly the roles and actions this test states cells
// for. A role or action added to the table without its cells here would
// otherwise be untested, and so would one granted in a row but missing
// from the action list.
func TestTheTableHoldsOnlyTestedRolesAndActions(t *testing.T) {
	known := map[Action]bool{Read: true, Create: true, Update: true, Delete: true, SetMemberRole: true, InstallTool: true}
	if len(actions) != len(known) {
		t.Fatalf("actions has %d entries, the test covers %d: add the new action's cells to TestEveryRoleActionCell", len(actions), len(known))
	}
	for _, a := range actions {
		if !known[a] {
			t.Errorf("actions lists %q, which TestEveryRoleActionCell does not cover", a)
		}
	}
	if len(table) != 3 {
		t.Errorf("table has %d roles, the test covers viewer, member and admin", len(table))
	}
	for role, row := range table {
		for a := range row {
			if !known[a] {
				t.Errorf("table grants %s the action %q, which is not in the action list", role, a)
			}
		}
	}
}

// Anything the table does not name is refused: fail closed, the lesson
// recorded in the plan's M2 T5 entry (an undefined input must never read as
// permission).
func TestUnknownRolesAndActionsAreRefused(t *testing.T) {
	for _, role := range []store.Role{"", "owner", "ADMIN", "admin "} {
		for _, action := range actions {
			if Permits(role, action) {
				t.Errorf("Permits(%q, %s) = true for a role the table does not name", role, action)
			}
		}
	}
	for _, role := range []store.Role{store.RoleViewer, store.RoleMember, store.RoleAdmin} {
		for _, action := range []Action{"", "drop_table", "READ"} {
			if Permits(role, action) {
				t.Errorf("Permits(%s, %q) = true for an action the table does not name", role, action)
			}
		}
	}
}
