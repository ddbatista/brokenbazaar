// Package authz is the one permission table: which role may perform which
// action in an org (threat-models/m3-delegation.md D1, D4).
//
// One home, on purpose. The direct API routes call it (M3 T3), and so will
// the session authority route and the internal execution routes (T6).
// Role semantics written a second time -- in Rego, in a handler, in the
// gateway -- would drift, and "a rule that can be satisfied from two places
// is a rule you cannot enforce" (AGENTS.md, about store.ForOrg; D4 applies
// it to authorization). Agent tools map onto these actions; they never get
// a table of their own.
//
// The table answers "may a user with this role do this, directly?" -- the
// question SR-B3-8 makes the ceiling for anything done through the agent.
// It does not answer whether an action may be DELEGATED: set_member_role
// is allowed to an admin here and still never runs through an agent
// session (D6, SR-B3-7). That rule lives at the gateway, because it is a
// rule about delegation, not about roles.
package authz

import "github.com/ddbatista/brokenbazaar/app/store"

// Action is something a user can do inside an org.
type Action string

const (
	Read          Action = "read"            // list, search, get a document
	Create        Action = "create"          // create a document
	Update        Action = "update"          // edit a document
	Delete        Action = "delete"          // delete a document
	SetMemberRole Action = "set_member_role" // change a member's role (control-plane; never delegable, D6)
	InstallTool   Action = "install_tool"    // change the org's installed tool set: install, uninstall, reapprove, list (M4a D8 -- control-plane, admin-only, and NO agent tool maps here)
)

// actions is every action the table knows. Unexported until a caller
// outside the package needs to enumerate them (T6's authority route may).
var actions = []Action{Read, Create, Update, Delete, SetMemberRole, InstallTool}

// table is D1 verbatim. Each role lists everything it may do, rather than
// inheriting from the role below: a reader can check any cell by looking at
// one row, and a future role that is not a superset of another (an auditor
// who reads and nothing else, say) needs no special case.
var table = map[store.Role]map[Action]bool{
	store.RoleViewer: {Read: true},
	store.RoleMember: {Read: true, Create: true, Update: true},
	store.RoleAdmin:  {Read: true, Create: true, Update: true, Delete: true, SetMemberRole: true, InstallTool: true},
}

// Permits reports whether role may perform action. A role or an action the
// table does not name is refused: fail closed, never "not listed, so
// allowed".
func Permits(role store.Role, action Action) bool {
	return table[role][action]
}
