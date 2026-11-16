package main

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ddbatista/brokenbazaar/app/auth"
	"github.com/ddbatista/brokenbazaar/app/authz"
	"github.com/ddbatista/brokenbazaar/app/store"
)

// The direct role route, PATCH /orgs/{org_id}/members/{user_id} (M3 T5).
//
// Three jobs, none of them a finding:
//   - finding 06's positive control: an admin changing a role DIRECTLY is
//     allowed, so 06's hardened denial reads as "not delegable", never as
//     "forbidden" (m3-delegation.md D6);
//   - every role-changing PoC's idempotent reset (attacks/README.md rule 5,
//     §7 of the threat model);
//   - the human half of the role-change record: actor user, no session.
//
// It plants nothing, and it is the SAME in both modes (plan M3 T5 D1). The
// caller's membership and role come from a server-side lookup on the path's
// org; the token supplies identity (sub) only, never the org or the role.
//
// What that does and does not buy, stated exactly. The token is still
// trusted for sub, and in vulnerable mode the verifier is finding 02's: an
// alg:none token whose sub is a REAL admin of the target org passes the
// lookup and changes roles there. That is 02 -- forged identity -- reaching
// one more route, and its answer key says so (plan M3 T3/T5 carried items).
// What the lookup refuses is a second, easier path: a route that read org
// and role from the claims would accept ANY sub claiming "admin" of any org,
// with no real admin's id needed. That would be a new escalation no
// threat-model row assigns; the planted bug lives in the delegation path
// only (m3-delegation.md D1).
//
// The route has no last-admin or self-demotion guard: an admin can demote
// themselves, or the org's last admin. Not in the spec, and no PoC changes
// the owner admin (m3-delegation.md §7); recorded as a follow-up in the
// plan's T5 entry.

// membershipLookup answers "is this user a member of this org, and with
// which role" -- AdminStore.MembershipRole in production.
type membershipLookup interface {
	MembershipRole(ctx context.Context, orgID, userID string) (store.Role, bool, error)
}

// roleSetter is one org's role-change write -- OrgStore.SetMemberRole,
// reached only through ForOrg (M3-N1).
type roleSetter interface {
	SetMemberRole(ctx context.Context, subject string, role store.Role, actor store.RoleActor) (store.RoleChange, bool, error)
}

// memberHandlers holds the role route. Its two dependencies are interfaces
// so the route's decisions are testable without a database (members_test.go),
// including the one that matters most: a refused request never reaches the
// setter.
type memberHandlers struct {
	lookup    membershipLookup
	setterFor func(orgID string) roleSetter
}

func newMemberHandlers(admin *store.AdminStore, pool *pgxpool.Pool) *memberHandlers {
	return &memberHandlers{
		lookup:    admin,
		setterFor: func(orgID string) roleSetter { return store.ForOrg(pool, orgID) },
	}
}

type setRoleRequest struct {
	Role string `json:"role"`
}

type roleChangeResponse struct {
	OrgID        string `json:"org_id"`
	UserID       string `json:"user_id"`
	Role         string `json:"role"`
	PreviousRole string `json:"previous_role"`
	Changed      bool   `json:"changed"`
}

func (h *memberHandlers) setRole(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
	ctx := r.Context()
	orgID := r.PathValue("org_id")

	// Authorization first, before the body is read: a caller who may not
	// change roles learns nothing about which roles or subjects exist.
	// The same decision the document routes make (accessFor): membership,
	// then the one permission table.
	callerRole, member, err := h.lookup.MembershipRole(ctx, orgID, claims.Sub)
	if err != nil {
		internalError(w, err)
		return
	}
	switch accessFor(member, callerRole, authz.SetMemberRole) {
	case accessNotFound:
		// M1's format: a caller who is not in this org IS probing it from
		// outside, which is what target_org= means to M1's rule.
		logNotAMember(claims.Sub, orgID)
		notFound(w)
		return
	case accessForbidden:
		forbidden(w, claims.Sub, orgID, callerRole, authz.SetMemberRole)
		return
	}

	var req setRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	role := store.Role(req.Role)
	if !role.Valid() {
		writeJSONError(w, http.StatusBadRequest, "role must be admin, member or viewer")
		return
	}

	// The path's org, through the org-bound handle. A human's direct
	// change: the actor is the caller, with no session.
	change, found, err := h.setterFor(orgID).SetMemberRole(ctx, r.PathValue("user_id"), role, store.RoleActor{User: claims.Sub})
	if err != nil {
		internalError(w, err)
		return
	}
	if !found {
		notFound(w)
		return
	}
	writeJSON(w, http.StatusOK, roleChangeResponse{
		OrgID:        change.OrgID,
		UserID:       change.Subject,
		Role:         string(change.After),
		PreviousRole: string(change.Before),
		Changed:      change.Changed,
	})
}
