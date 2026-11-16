package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ddbatista/brokenbazaar/app/auth"
	"github.com/ddbatista/brokenbazaar/app/store"
)

// Plan M3 T5 D1-D3: the direct role route's decisions, with no database. The
// membership lookup and the role setter are fakes, so every branch is
// reachable -- and the property that matters most is checkable: a refused
// request never reaches the setter.

type fakeLookup map[string]store.Role // "org/user" -> role

func (f fakeLookup) MembershipRole(_ context.Context, orgID, userID string) (store.Role, bool, error) {
	r, ok := f[orgID+"/"+userID]
	return r, ok, nil
}

type fakeSetter struct {
	calls   int
	org     string
	subject string
	role    store.Role
	actor   store.RoleActor
	members map[string]store.Role // subject -> current role, in fakeSetter's org
}

func (f *fakeSetter) forOrg(org string) roleSetter {
	f.org = org
	return f
}

func (f *fakeSetter) SetMemberRole(_ context.Context, subject string, role store.Role, actor store.RoleActor) (store.RoleChange, bool, error) {
	f.calls++
	f.subject, f.role, f.actor = subject, role, actor
	before, ok := f.members[subject]
	if !ok {
		return store.RoleChange{}, false, nil
	}
	return store.RoleChange{OrgID: f.org, Subject: subject, Before: before, After: role, Changed: before != role}, true, nil
}

const (
	org1    = "11111111-1111-4111-8111-111111111111"
	admin1  = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	member1 = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	viewer1 = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	outside = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
)

func fakeMemberHandlers() (*memberHandlers, *fakeSetter) {
	lookup := fakeLookup{
		org1 + "/" + admin1:  store.RoleAdmin,
		org1 + "/" + member1: store.RoleMember,
		org1 + "/" + viewer1: store.RoleViewer,
	}
	setter := &fakeSetter{members: map[string]store.Role{admin1: store.RoleAdmin, member1: store.RoleMember, viewer1: store.RoleViewer}}
	return &memberHandlers{lookup: lookup, setterFor: setter.forOrg}, setter
}

func patchRole(h *memberHandlers, caller, subject, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPatch, "/orgs/"+org1+"/members/"+subject, strings.NewReader(body))
	req.SetPathValue("org_id", org1)
	req.SetPathValue("user_id", subject)
	rec := httptest.NewRecorder()
	h.setRole(rec, req, auth.Claims{Sub: caller})
	return rec
}

// Refusals, and that none of them reaches the setter. Authorization runs
// before the body is read, so a non-admin learns nothing about which roles
// or subjects exist.
func TestRoleRouteRefusals(t *testing.T) {
	cases := []struct {
		name   string
		caller string
		body   string
		want   int
	}{
		{"a non-member gets the uniform 404", outside, `{"role":"admin"}`, http.StatusNotFound},
		{"a viewer is refused", viewer1, `{"role":"admin"}`, http.StatusForbidden},
		{"a member is refused", member1, `{"role":"admin"}`, http.StatusForbidden},
		{"a member is refused even with a bad body", member1, `not json`, http.StatusForbidden},
		{"an admin with an unknown role", admin1, `{"role":"owner"}`, http.StatusBadRequest},
		{"an admin with no role", admin1, `{}`, http.StatusBadRequest},
		{"an admin with a malformed body", admin1, `not json`, http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, setter := fakeMemberHandlers()
			rec := patchRole(h, c.caller, member1, c.body)
			if rec.Code != c.want {
				t.Errorf("status %d, want %d (%s)", rec.Code, c.want, rec.Body)
			}
			if setter.calls != 0 {
				t.Errorf("the setter was called %d times on a refused request", setter.calls)
			}
		})
	}
}

// The role comes from the server-side lookup, never from the token, in
// both modes (plan M3 T5 D1). A token claiming admin changes nothing for a viewer.
func TestRoleRouteIgnoresTheTokensRole(t *testing.T) {
	h, setter := fakeMemberHandlers()
	req := httptest.NewRequest(http.MethodPatch, "/x", strings.NewReader(`{"role":"admin"}`))
	req.SetPathValue("org_id", org1)
	req.SetPathValue("user_id", member1)
	rec := httptest.NewRecorder()
	h.setRole(rec, req, auth.Claims{Sub: viewer1, OrgID: org1, Role: "admin"})
	if rec.Code != http.StatusForbidden || setter.calls != 0 {
		t.Fatalf("a viewer with an admin claim: status %d, setter calls %d; want 403 and none", rec.Code, setter.calls)
	}
}

func TestRoleRouteAdminChangesARole(t *testing.T) {
	h, setter := fakeMemberHandlers()
	rec := patchRole(h, admin1, member1, `{"role":"admin"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 (%s)", rec.Code, rec.Body)
	}
	// The PATH's org, the PATH's subject, the body's role, and the caller
	// as a human actor: no session on a direct change.
	if setter.org != org1 || setter.subject != member1 || setter.role != store.RoleAdmin {
		t.Errorf("setter got org=%s subject=%s role=%s", setter.org, setter.subject, setter.role)
	}
	if setter.actor != (store.RoleActor{User: admin1}) {
		t.Errorf("actor %+v, want a human actor (no session)", setter.actor)
	}
	var got roleChangeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := roleChangeResponse{OrgID: org1, UserID: member1, Role: "admin", PreviousRole: "member", Changed: true}
	if got != want {
		t.Errorf("response %+v, want %+v", got, want)
	}
}

// Setting a role the subject already holds is a 200 with changed:false --
// the idempotent precondition every role-changing PoC starts with (rule 5).
func TestRoleRouteNoOpIsNotAnError(t *testing.T) {
	h, _ := fakeMemberHandlers()
	rec := patchRole(h, admin1, member1, `{"role":"member"}`)
	var got roleChangeResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != http.StatusOK || got.Changed || got.PreviousRole != "member" {
		t.Fatalf("status %d, response %+v; want 200, changed:false", rec.Code, got)
	}
}

// A subject who is not a member of the PATH's org is the uniform 404, the
// same body a non-member caller gets.
func TestRoleRouteUnknownSubjectIs404(t *testing.T) {
	h, _ := fakeMemberHandlers()
	rec := patchRole(h, admin1, outside, `{"role":"viewer"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", rec.Code)
	}
	nonMember := patchRole(h, outside, member1, `{"role":"viewer"}`)
	if rec.Body.String() != nonMember.Body.String() {
		t.Errorf("the two 404s differ: %q vs %q", rec.Body, nonMember.Body)
	}
}

type failingLookup struct{}

func (failingLookup) MembershipRole(context.Context, string, string) (store.Role, bool, error) {
	return "", false, errors.New("db down")
}

func TestRoleRouteLookupFailureIs500(t *testing.T) {
	_, setter := fakeMemberHandlers()
	h := &memberHandlers{lookup: failingLookup{}, setterFor: setter.forOrg}
	if rec := patchRole(h, admin1, member1, `{"role":"admin"}`); rec.Code != http.StatusInternalServerError || setter.calls != 0 {
		t.Fatalf("status %d, setter calls %d; want 500 and none", rec.Code, setter.calls)
	}
}

// The route is registered in BOTH modes, behind the token check, and wired
// to setRole -- which no handler-level test can see. Deleting either
// registration line, or wiring the pattern to another handler, fails here.
// No database: the member handlers are the fakes above, and the document
// handlers are never reached.
func TestRoleRouteIsRegisteredInBothModes(t *testing.T) {
	secret := []byte("test-secret-not-a-real-one")
	modes := map[string]http.Handler{}
	m, _ := fakeMemberHandlers()
	modes["hardened"] = registerHardened(&docHandlers{hardened: true}, m, nil, secret, []byte("tools-secret"))
	vmux := http.NewServeMux()
	m2, _ := fakeMemberHandlers()
	registerVulnerable(vmux, &docHandlers{}, m2, nil, secret)
	modes["vulnerable"] = vmux

	token := func(sub string) string {
		tok, err := auth.Encode(mintClaims(sub, org1, store.RoleViewer, false, time.Now()), secret)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	send := func(h http.Handler, bearer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPatch, "/orgs/"+org1+"/members/"+member1, strings.NewReader(`{"role":"viewer"}`))
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for name, h := range modes {
		t.Run(name, func(t *testing.T) {
			if rec := send(h, ""); rec.Code != http.StatusUnauthorized {
				t.Errorf("no token: status %d, want 401 (route missing, or not token-guarded)", rec.Code)
			}
			// The fakes know admin1 as an admin of org1: reaching 200 with
			// the fake's answer proves the pattern reaches setRole.
			rec := send(h, token(admin1))
			var got roleChangeResponse
			_ = json.Unmarshal(rec.Body.Bytes(), &got)
			if rec.Code != http.StatusOK || got.PreviousRole != "member" || got.Role != "viewer" {
				t.Errorf("admin: status %d body %s, want 200 from setRole", rec.Code, rec.Body)
			}
		})
	}
}
