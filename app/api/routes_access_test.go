package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ddbatista/brokenbazaar/app/auth"
)

// Each document route asks the permission table for the RIGHT action. The
// table itself is tested in authz; this pins the wiring, which a test of
// the table alone cannot see -- a PATCH handler passing authz.Read would
// leave every table test green (T3 review).
//
// Run against the vulnerable handlers with no database at all: the role
// comes from the claims there, and a refused request returns before the
// store is ever touched. So for each route, the highest role that must be
// REFUSED gets a 403 -- and a route wired to a looser action would reach
// the nil-pool store instead and fail here. (The allowed cells need a
// database; the live role matrix and the attack suite cover them.)
func TestEachRouteRefusesTheRoleBelowItsThreshold(t *testing.T) {
	h := &docHandlers{hardened: false} // nil pool: reaching the store would be a failure
	cases := []struct {
		name    string
		handler protectedHandler
		method  string
		role    string // the highest role the route must refuse
	}{
		{"list/search needs any real role", h.listOrSearch, http.MethodGet, ""},
		{"get needs any real role", h.get, http.MethodGet, ""},
		{"create needs member", h.create, http.MethodPost, "viewer"},
		{"update needs member", h.update, http.MethodPatch, "viewer"},
		{"delete needs admin", h.delete, http.MethodDelete, "member"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(c.method, "/orgs/o1/documents/d1", strings.NewReader(`{"title":"t","body":"b"}`))
			req.SetPathValue("org_id", "o1")
			req.SetPathValue("doc_id", "d1")
			rec := httptest.NewRecorder()
			func() {
				defer func() {
					if p := recover(); p != nil {
						t.Fatalf("role %q reached the store (panicked: %v): the route is wired to a looser action", c.role, p)
					}
				}()
				c.handler(rec, req, auth.Claims{Sub: "u1", OrgID: "o1", Role: c.role})
			}()
			if rec.Code != http.StatusForbidden {
				t.Errorf("role %q: status %d, want 403", c.role, rec.Code)
			}
		})
	}
}
