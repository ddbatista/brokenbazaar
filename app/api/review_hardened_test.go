//go:build !vulnerable

package main

// THE HARDENED BUILD'S REVIEW SURFACE — SR-B9-1 asserted as a
// property: "the artifact presented for approval is the artifact that
// executes." The admin sees the full body, the declared capabilities
// (the ceiling the org is buying), the declared triggers and
// references, and the exact digest an install will pin.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSkillReviewRendersTheFullArtifact(t *testing.T) {
	registerSkillItem(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/catalog/"+skillItemID, nil)
	req.Header.Set("Authorization", "Bearer "+mpToken(t, memberA))
	mpServe(t).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("skill review = %d: %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Type          string   `json:"type"`
		Name          string   `json:"name"`
		Description   string   `json:"description"`
		Triggers      []string `json:"triggers"`
		Capabilities  []string `json:"capabilities"`
		References    []string `json:"references"`
		Body          string   `json:"body"`
		PinningDigest string   `json:"pinning_digest"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// The full artifact: the body IS what will load at S8.
	if !strings.Contains(payload.Body, "titled Notes: at the end") {
		t.Fatalf("body = %q", payload.Body)
	}
	// The ceiling's declaration, shown before the org buys it.
	if len(payload.Capabilities) != 2 || payload.Capabilities[0] != "read_document" {
		t.Fatalf("capabilities = %v", payload.Capabilities)
	}
	// The pin the install will record, answerable after the fact.
	if payload.PinningDigest != "e1f06dcd6f369f47eea7738a1a3113cc0de7f2293087c63fbba16696d0e34c79" {
		t.Fatalf("pinning_digest = %q", payload.PinningDigest)
	}
	if payload.Type != "skill" || payload.Name != "meeting-notes" {
		t.Fatalf("type/name = %s/%s", payload.Type, payload.Name)
	}
	// No references in the canonical bundle: the field is present and
	// empty, never absent (the vocabulary must be visible even when
	// unused, or a listing with references would read as a schema
	// change).
	if payload.References == nil {
		t.Fatal("references field is absent/null: the declared fetch surface must always render")
	}
}
