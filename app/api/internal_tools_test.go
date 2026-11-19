package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ddbatista/brokenbazaar/app/auth"
	"github.com/ddbatista/brokenbazaar/app/authz"
	"github.com/ddbatista/brokenbazaar/app/store"
)

// Plan M3 T6 D2/D4: the authority route and the internal execution routes,
// with no database. The session lookup and the document store are fakes, so
// every branch is reachable -- and the property M3-N2 is about is checkable:
// when the re-check at execution fails, the store is never touched.

var t6now = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

type fakeSessions map[string]store.SessionAuthority

func (f fakeSessions) SessionAuthority(_ context.Context, id string) (store.SessionAuthority, bool, error) {
	s, ok := f[id]
	return s, ok, nil
}

// fakeDocs is one org's documents. It records the org it was opened for
// and every write, so a test can assert both WHICH org the route bound and
// that a refused request wrote nothing.
type fakeDocs struct {
	org    string
	docs   map[string]store.Document
	writes int
}

func (f *fakeDocs) Create(context.Context, store.Document) (store.Document, error) {
	panic("not used")
}
func (f *fakeDocs) Get(_ context.Context, id string) (store.Document, bool, error) {
	d, ok := f.docs[id]
	return d, ok, nil
}
func (f *fakeDocs) List(context.Context) ([]store.Document, error)           { panic("not used") }
func (f *fakeDocs) Search(context.Context, string) ([]store.Document, error) { panic("not used") }
func (f *fakeDocs) Update(_ context.Context, d store.Document) (store.Document, bool, error) {
	f.writes++
	if _, ok := f.docs[d.ID]; !ok {
		return store.Document{}, false, nil
	}
	f.docs[d.ID] = d
	return d, true, nil
}
func (f *fakeDocs) Delete(_ context.Context, id string) (bool, error) {
	f.writes++
	_, ok := f.docs[id]
	delete(f.docs, id)
	return ok, nil
}

const (
	sAdmin   = "10000000-0000-4000-8000-000000000001"
	sViewer  = "10000000-0000-4000-8000-000000000002"
	sExpired = "10000000-0000-4000-8000-000000000003"
	sNarrow  = "10000000-0000-4000-8000-000000000004"
	docA     = "20000000-0000-4000-8000-000000000001"
)

func fakeInternalTools() (*internalTools, *fakeDocs) {
	all := []string{"read_document", "update_document", "delete_document", "http_fetch"}
	sessions := fakeSessions{
		sAdmin:   {SessionID: sAdmin, OrgID: org1, ActingFor: admin1, Scope: all, ExpiresAt: t6now.Add(time.Hour), RoleNow: store.RoleAdmin},
		sViewer:  {SessionID: sViewer, OrgID: org1, ActingFor: viewer1, Scope: all, ExpiresAt: t6now.Add(time.Hour), RoleNow: store.RoleViewer},
		sExpired: {SessionID: sExpired, OrgID: org1, ActingFor: admin1, Scope: all, ExpiresAt: t6now.Add(-time.Minute), RoleNow: store.RoleAdmin},
		sNarrow:  {SessionID: sNarrow, OrgID: org1, ActingFor: admin1, Scope: []string{"read_document"}, ExpiresAt: t6now.Add(time.Hour), RoleNow: store.RoleAdmin},
	}
	docs := &fakeDocs{docs: map[string]store.Document{docA: {ID: docA, OrgID: org1, Title: "Q3", Body: "numbers"}}}
	return &internalTools{
		sessions: sessions,
		docsFor:  func(org string) store.DocumentStore { docs.org = org; return docs },
		now:      func() time.Time { return t6now },
	}, docs
}

func serve(h protectedHandler, method, target, body string, pathValues map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	for k, v := range pathValues {
		req.SetPathValue(k, v)
	}
	rec := httptest.NewRecorder()
	h(rec, req, auth.Claims{})
	return rec
}

// The authority route returns the ROW's org and acting user, the role now,
// and every leg -- present and named "passes" -- for allow and deny alike.
func TestAuthorityRouteReportsTheRowAndEveryLeg(t *testing.T) {
	it, _ := fakeInternalTools()
	for _, c := range []struct {
		session, tool string
		want          authz.Legs
	}{
		{sAdmin, "delete_document", authz.Legs{WithinTime: true, InScope: true, RolePermits: true}},
		{sViewer, "delete_document", authz.Legs{WithinTime: true, InScope: true, RolePermits: false}},
		{sExpired, "read_document", authz.Legs{WithinTime: false, InScope: true, RolePermits: true}},
		{sNarrow, "http_fetch", authz.Legs{WithinTime: true, InScope: false, RolePermits: true}},
	} {
		rec := serve(it.authority, http.MethodGet, "/x?tool="+c.tool, "", map[string]string{"session_id": c.session})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s/%s: status %d (%s)", c.session, c.tool, rec.Code, rec.Body)
		}
		// Decode generically: the wire must carry every leg by name, not
		// just decode into a struct that would default a missing one.
		var raw map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &raw)
		legs, _ := raw["legs"].(map[string]any)
		for _, name := range []string{"within_time", "in_scope", "role_permits"} {
			if _, ok := legs[name]; !ok {
				t.Errorf("%s/%s: leg %q missing from the wire", c.session, c.tool, name)
			}
		}
		var got authorityResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &got)
		if got.Legs != c.want || got.Session.Org != org1 || got.Session.ID != c.session {
			t.Errorf("%s/%s: got %+v", c.session, c.tool, got)
		}
	}
}

func TestAuthorityRouteRefusals(t *testing.T) {
	it, _ := fakeInternalTools()
	if rec := serve(it.authority, http.MethodGet, "/x?tool=read_document", "", map[string]string{"session_id": "nope"}); rec.Code != http.StatusNotFound {
		t.Errorf("unknown session: %d, want 404", rec.Code)
	}
	if rec := serve(it.authority, http.MethodGet, "/x", "", map[string]string{"session_id": sAdmin}); rec.Code != http.StatusBadRequest {
		t.Errorf("no tool: %d, want 400", rec.Code)
	}
}

// The execution routes bind the ROW's org -- the request names a session,
// never an org -- and execute when every leg passes.
func TestInternalToolsExecuteOnTheRowsOrg(t *testing.T) {
	it, docs := fakeInternalTools()
	rec := serve(it.readDocument, http.MethodGet, "/x?session="+sViewer+"&id="+docA+"&org=attacker-org", "", nil)
	if rec.Code != http.StatusOK || docs.org != org1 {
		t.Fatalf("read: status %d, bound org %q; want 200 on %s (an org parameter is ignored)", rec.Code, docs.org, org1)
	}
	rec = serve(it.updateDocument, http.MethodPost, "/x", `{"session":"`+sAdmin+`","id":"`+docA+`","body":"restated"}`, nil)
	if rec.Code != http.StatusOK || docs.docs[docA].Body != "restated" || docs.docs[docA].Title != "Q3" {
		t.Fatalf("update: status %d, doc %+v; want 200, body replaced, title kept", rec.Code, docs.docs[docA])
	}
	rec = serve(it.deleteDocument, http.MethodPost, "/x", `{"session":"`+sAdmin+`","id":"`+docA+`"}`, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: status %d, want 204", rec.Code)
	}
	if _, still := docs.docs[docA]; still {
		t.Fatal("delete: the document is still there")
	}
}

// M3-N2: the re-check at execution. A session whose legs fail NOW is
// refused with the failing leg's reason, and the store is never written --
// whatever the gateway decided a moment earlier.
func TestInternalToolsRecheckAndNeverWriteOnRefusal(t *testing.T) {
	cases := []struct {
		name   string
		h      func(*internalTools) protectedHandler
		method string
		target string
		body   string
		want   string
	}{
		{"viewer delete", func(i *internalTools) protectedHandler { return i.deleteDocument }, http.MethodPost, "/x",
			`{"session":"` + sViewer + `","id":"` + docA + `"}`, "role_does_not_permit"},
		{"viewer update", func(i *internalTools) protectedHandler { return i.updateDocument }, http.MethodPost, "/x",
			`{"session":"` + sViewer + `","id":"` + docA + `","body":"x"}`, "role_does_not_permit"},
		{"expired delete", func(i *internalTools) protectedHandler { return i.deleteDocument }, http.MethodPost, "/x",
			`{"session":"` + sExpired + `","id":"` + docA + `"}`, "session_expired"},
		{"out-of-scope delete", func(i *internalTools) protectedHandler { return i.deleteDocument }, http.MethodPost, "/x",
			`{"session":"` + sNarrow + `","id":"` + docA + `"}`, "not_in_session_scope"},
		{"expired read", func(i *internalTools) protectedHandler { return i.readDocument }, http.MethodGet,
			"/x?session=" + sExpired + "&id=" + docA, "", "session_expired"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			it, docs := fakeInternalTools()
			rec := serve(c.h(it), c.method, c.target, c.body, nil)
			var got map[string]string
			_ = json.Unmarshal(rec.Body.Bytes(), &got)
			if rec.Code != http.StatusForbidden || got["reason"] != c.want {
				t.Errorf("status %d reason %q, want 403 %q", rec.Code, got["reason"], c.want)
			}
			if docs.writes != 0 {
				t.Errorf("the store was written %d times on a refused request", docs.writes)
			}
		})
	}
}

func TestInternalToolsBadRequests(t *testing.T) {
	cases := []struct {
		name   string
		h      func(*internalTools) protectedHandler
		method string
		target string
		body   string
		want   int
	}{
		{"read without a session", func(i *internalTools) protectedHandler { return i.readDocument }, http.MethodGet, "/x?id=" + docA, "", http.StatusBadRequest},
		{"read, unknown session", func(i *internalTools) protectedHandler { return i.readDocument }, http.MethodGet, "/x?session=nope&id=" + docA, "", http.StatusNotFound},
		{"update without a body field", func(i *internalTools) protectedHandler { return i.updateDocument }, http.MethodPost, "/x", `{"session":"` + sAdmin + `","id":"` + docA + `"}`, http.StatusBadRequest},
		{"delete, malformed json", func(i *internalTools) protectedHandler { return i.deleteDocument }, http.MethodPost, "/x", `nope`, http.StatusBadRequest},
		{"delete, missing document", func(i *internalTools) protectedHandler { return i.deleteDocument }, http.MethodPost, "/x", `{"session":"` + sAdmin + `","id":"` + sAdmin + `"}`, http.StatusNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			it, _ := fakeInternalTools()
			if rec := serve(c.h(it), c.method, c.target, c.body, nil); rec.Code != c.want {
				t.Errorf("status %d, want %d (%s)", rec.Code, c.want, rec.Body)
			}
		})
	}
}

// Hardened only, all behind the service secret; the vulnerable build
// registers none of them (its agent runs tools in-process, B5 2.1).
func TestInternalRoutesAreHardenedOnlyAndServiceGuarded(t *testing.T) {
	secret := []byte("test-secret-not-a-real-one")
	it, _ := fakeInternalTools()
	m, _ := fakeMemberHandlers()
	hard := registerHardened(&docHandlers{hardened: true}, m, nil, it, nil, secret, []byte("tools-secret"))
	vmux := http.NewServeMux()
	registerVulnerable(vmux, &docHandlers{}, m, nil, nil, secret)
	paths := []struct{ method, path string }{
		{http.MethodGet, "/internal/sessions/" + sAdmin + "/authority?tool=read_document"},
		{http.MethodGet, "/internal/tools/read_document?session=" + sAdmin + "&id=" + docA},
		{http.MethodPost, "/internal/tools/update_document"},
		{http.MethodPost, "/internal/tools/delete_document"},
	}
	for _, p := range paths {
		rec := httptest.NewRecorder()
		hard.ServeHTTP(rec, httptest.NewRequest(p.method, p.path, strings.NewReader(`{}`)))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("hardened %s %s with no secret: %d, want 401", p.method, p.path, rec.Code)
		}
		rec = httptest.NewRecorder()
		req := httptest.NewRequest(p.method, p.path, strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer tools-secret")
		hard.ServeHTTP(rec, req)
		if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusNotFound && strings.Contains(rec.Body.String(), "page not found") {
			t.Errorf("hardened %s %s with the secret: %d, want it routed", p.method, p.path, rec.Code)
		}
		rec = httptest.NewRecorder()
		vmux.ServeHTTP(rec, httptest.NewRequest(p.method, p.path, strings.NewReader(`{}`)))
		if rec.Code != http.StatusNotFound {
			t.Errorf("vulnerable %s %s: %d, want 404 (not registered)", p.method, p.path, rec.Code)
		}
	}
}

// A session id that is not an id is the same 404 as an unknown one, never a
// 500 from the database's uuid cast (plan M3 T6 review).
func TestMalformedSessionIDIsNotFound(t *testing.T) {
	it, _ := fakeInternalTools()
	for _, id := range []string{"nope", "../tools/delete_document", "S-1"} {
		rec := serve(it.authority, http.MethodGet, "/x?tool=read_document", "", map[string]string{"session_id": id})
		if rec.Code != http.StatusNotFound {
			t.Errorf("session %q: %d, want 404", id, rec.Code)
		}
	}
}
