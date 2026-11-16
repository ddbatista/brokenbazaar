// Package store is the data-access layer for BrokenBazaar's M1 tenancy
// objects (orgs, users, memberships, documents). It is where M1's thesis
// lives or dies: "tenant isolation is a data-layer property, not a
// handler-layer one." See threat-models/m1-tenancy.md.
package store

import "time"

// Role is a membership's role within one org. A user can hold a different
// role in each org they belong to -- the role lives on the membership, not
// on the user (docs/product-spec.md §3.2).
type Role string

const (
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
	RoleViewer Role = "viewer"
)

// Valid reports whether r is one of the three roles. The schema's
// membership_role domain enforces the same list (migration 003); this is
// the Go side of that language boundary, so an unknown role is refused
// before a statement is sent rather than by a constraint error.
func (r Role) Valid() bool {
	switch r {
	case RoleAdmin, RoleMember, RoleViewer:
		return true
	}
	return false
}

type Org struct {
	ID        string
	Name      string
	CreatedAt time.Time
}

type User struct {
	ID           string
	Email        string
	DisplayName  string
	PasswordHash string // never serialize this into an API response
}

type Membership struct {
	OrgID  string
	UserID string
	Role   Role
}

type Document struct {
	ID        string
	OrgID     string
	Title     string
	Body      string
	CreatedBy string
	CreatedAt time.Time
}
