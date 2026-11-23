package main

// M4b T3: the skills-plane routes' decisions, on the marketplace
// fakes (marketplace_test.go's pattern: a refused request never reaches
// the store, and every refusal's shape is asserted). The review
// payload's mode split has its own pair of files --
// review_vulnerable_test.go and review_hardened_test.go -- because
// each build can only assert its own half of 09's thesis.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ddbatista/brokenbazaar/app/skill"
	"github.com/ddbatista/brokenbazaar/app/store"
)

// skillItemID is the fake catalog's skill listing. Registered here, in
// the tests' own map, so the M4a fixtures above stay byte-identical.
const skillItemID = "33333333-2222-4333-8444-555555555555"

func registerSkillItem(t *testing.T) {
	t.Helper()
	mpAdmin.items[skillItemID] = store.CatalogItemDetail{
		CatalogItem: store.CatalogItem{
			ID: skillItemID, PublisherID: pubA, Name: "meeting-notes",
			EndpointURL:    "", // skills have no MCP endpoint (migration 005)
			Manifest:       skill.ExampleBundle,
			ManifestDigest: store.ManifestDigest([]byte(skill.ExampleBundle)),
			Type:           "skill",
		},
		Publisher: store.Publisher{ID: pubA, DisplayName: "BrokenBazaar Labs"},
	}
}

func TestSkillPublishRoute(t *testing.T) {
	registerSkillItem(t)
	rec := httptest.NewRecorder()
	body := `{"type":"skill","name":"meeting-notes","bundle":` + jsonQuote(skill.ExampleBundle) + `}`
	req := httptest.NewRequest(http.MethodPost, "/catalog", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+mpPublisherToken(t))
	mpServe(t).ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("publish skill = %d: %s", rec.Code, rec.Body.String())
	}
	var item store.CatalogItem
	if err := json.Unmarshal(rec.Body.Bytes(), &item); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if item.Type != "skill" || item.ManifestDigest != "e1f06dcd6f369f47eea7738a1a3113cc0de7f2293087c63fbba16696d0e34c79" {
		t.Fatalf("item = %+v: the pin is over the posted bytes", item)
	}
	// The parse never runs against the vocabulary on the mcp path: an
	// mcp publish with no type field is byte-identical to M4a's.
	if mpPub.publish != 1 {
		t.Fatalf("publishes = %d", mpPub.publish)
	}
}

func TestSkillPublishRouteRejectsABadBundle(t *testing.T) {
	registerSkillItem(t)
	for _, tc := range []struct {
		name, body, substr string
	}{
		{"unknown capability", `{"type":"skill","name":"x","bundle":"---\nname: x\ndescription: \"d\"\ntriggers:\n  - \"t\"\ncapabilities:\n  - install_tool\n---\nbody\n"}`, "not a platform tool"},
		{"bidi in the description", `{"type":"skill","name":"x","bundle":"---\nname: x\ndescription: \"notes \u202Eevil\"\ntriggers:\n  - \"t\"\ncapabilities:\n  - read_document\n---\nbody\n"}`, "non-printing"},
		{"name disagreement", `{"type":"skill","name":"other-name","bundle":"---\nname: x\ndescription: \"d\"\ntriggers:\n  - \"t\"\ncapabilities:\n  - read_document\n---\nbody\n"}`, "disagrees"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/catalog", strings.NewReader(tc.body))
			req.Header.Set("Authorization", "Bearer "+mpPublisherToken(t))
			mpServe(t).ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), tc.substr) {
				t.Fatalf("code=%d body=%s, want 400 containing %q", rec.Code, rec.Body.String(), tc.substr)
			}
		})
	}
}

func TestSkillInstallRoute(t *testing.T) {
	registerSkillItem(t)
	before := mpIns.installs
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/orgs/"+orgA+"/installs", strings.NewReader(`{"item_id":"`+skillItemID+`"}`))
	req.Header.Set("Authorization", "Bearer "+mpToken(t, adminA))
	mpServe(t).ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("install skill = %d: %s", rec.Code, rec.Body.String())
	}
	var ins store.Install
	if err := json.Unmarshal(rec.Body.Bytes(), &ins); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ins.ItemType != "skill" || ins.PinnedDigest != "e1f06dcd6f369f47eea7738a1a3113cc0de7f2293087c63fbba16696d0e34c79" {
		t.Fatalf("install = %+v", ins)
	}
	if mpIns.installs != before+1 {
		t.Fatalf("installs = %d, want %d", mpIns.installs, before+1)
	}
	if string(mpIns.pinned) != skill.ExampleBundle {
		t.Fatal("the pin is the listing's exact bytes")
	}
	// The org's admin record: who consented.
	if mpIns.byUser != adminA {
		t.Fatalf("installed_by = %s", mpIns.byUser)
	}
}

func TestSkillInstallIsStillAdminOnly(t *testing.T) {
	registerSkillItem(t)
	for _, tc := range []struct {
		who  string
		code int
	}{
		{adminA, http.StatusCreated},
		{memberA, http.StatusForbidden},
		{outside, http.StatusNotFound},
	} {
		t.Run(tc.who, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/orgs/"+orgA+"/installs", strings.NewReader(`{"item_id":"`+skillItemID+`"}`))
			req.Header.Set("Authorization", "Bearer "+mpToken(t, tc.who))
			mpServe(t).ServeHTTP(rec, req)
			if rec.Code != tc.code {
				t.Fatalf("%s install = %d: %s", tc.who, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestAuthoriseSkillRoute(t *testing.T) {
	registerSkillItem(t)
	mpIns.authorises = 0
	cases := []struct {
		name, who string
		code      int
	}{
		{"member", memberA, http.StatusCreated},
		{"admin for own sessions", adminA, http.StatusCreated},
		{"viewer", viewerA, http.StatusForbidden},
		{"non-member", outside, http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/orgs/"+orgA+"/skills/"+installID+"/authorise", nil)
			req.Header.Set("Authorization", "Bearer "+mpToken(t, tc.who))
			mpServe(t).ServeHTTP(rec, req)
			if rec.Code != tc.code {
				t.Fatalf("authorise = %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
	// The actor is always the CALLER: the store saw the member, never a
	// user_id from a request body (there is no such field).
	if mpIns.authorises != 2 {
		t.Fatalf("authorises = %d, want member+admin = 2", mpIns.authorises)
	}
}

func TestAuthoriseSkillDuplicateRefused(t *testing.T) {
	registerSkillItem(t)
	mpIns.authorises = 1 // already authorised once
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/orgs/"+orgA+"/skills/"+installID+"/authorise", nil)
	req.Header.Set("Authorization", "Bearer "+mpToken(t, memberA))
	mpServe(t).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("duplicate authorise = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSkillIndexRoute(t *testing.T) {
	registerSkillItem(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/orgs/"+orgA+"/skills", nil)
	req.Header.Set("Authorization", "Bearer "+mpToken(t, memberA))
	mpServe(t).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("index = %d: %s", rec.Code, rec.Body.String())
	}
	var idx []store.SkillIndexEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &idx); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(idx) != 1 || idx[0].Name != "meeting-notes" || !idx[0].IsPlatform {
		t.Fatalf("index = %+v", idx)
	}
	if idx[0].Description != "Prepare meeting notes from a document the user names." {
		t.Fatalf("description = %q", idx[0].Description)
	}
	// The unauthorised viewer's answer is an EMPTY ARRAY, never null
	// (the T7 nil-slice lesson, held on the wire).
	vrec := httptest.NewRecorder()
	vreq := httptest.NewRequest(http.MethodGet, "/orgs/"+orgA+"/skills", nil)
	vreq.Header.Set("Authorization", "Bearer "+mpToken(t, viewerA))
	mpServe(t).ServeHTTP(vrec, vreq)
	if vrec.Code != http.StatusOK || strings.TrimSpace(vrec.Body.String()) != "[]" {
		t.Fatalf("viewer index = %d: %s", vrec.Code, vrec.Body.String())
	}
}

func TestSkillIndexNonMemberIsTheUniform404(t *testing.T) {
	registerSkillItem(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/orgs/"+orgA+"/skills", nil)
	req.Header.Set("Authorization", "Bearer "+mpToken(t, outside))
	mpServe(t).ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "no such org") {
		t.Fatalf("non-member index = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRevokeSkillAuthorisationRoute(t *testing.T) {
	registerSkillItem(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/orgs/"+orgA+"/skills/authorisations/auth-1", nil)
	req.Header.Set("Authorization", "Bearer "+mpToken(t, memberA))
	mpServe(t).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke = %d: %s", rec.Code, rec.Body.String())
	}
	// Someone else's authorisation id simply does not exist.
	nrec := httptest.NewRecorder()
	nreq := httptest.NewRequest(http.MethodDelete, "/orgs/"+orgA+"/skills/authorisations/auth-404", nil)
	nreq.Header.Set("Authorization", "Bearer "+mpToken(t, memberA))
	mpServe(t).ServeHTTP(nrec, nreq)
	if nrec.Code != http.StatusNotFound {
		t.Fatalf("foreign revoke = %d: %s", nrec.Code, nrec.Body.String())
	}
}

// jsonQuote encodes a Go string as a JSON string literal, so the
// bundle bytes ride the request body exactly (the same bytes the
// parser's digest vector pins).
func jsonQuote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// mpPublisherToken mints a token whose claims carry the publisher
// principal (resolvePublisher's vocabulary: pubA).
func mpPublisherToken(t *testing.T) string {
	t.Helper()
	return mpToken(t, "11111111-2222-4333-8444-555555555555")
}
