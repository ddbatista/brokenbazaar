//go:build vulnerable

package main

// THE VULNERABLE BUILD'S REVIEW SURFACE — finding 09's planted bug,
// asserted as a property, not narrated. The naive catalog detail is
// the spec's own S3: the org reviews a name and a description, and the
// bytes that will execute at S8 are absent from the review. The same
// JSON decode this test uses is what an org admin's review screen
// would consume, so the assertion is about the wire, not a struct.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSkillReviewIsTheSpecsS3(t *testing.T) {
	registerSkillItem(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/catalog/"+skillItemID, nil)
	req.Header.Set("Authorization", "Bearer "+mpToken(t, memberA))
	mpServe(t).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("skill review = %d: %s", rec.Code, rec.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// What S3 shows: the name and the description, byte-identical to
	// the bundle's own (single rendering holds even here, or the review
	// and the index would disagree about what the org saw).
	if payload["name"] != "meeting-notes" {
		t.Fatalf("name = %v", payload["name"])
	}
	if payload["description"] != "Prepare meeting notes from a document the user names." {
		t.Fatalf("description = %v", payload["description"])
	}
	// What S3 does NOT show — and this absence is the finding: the
	// body the agent will obey, the capabilities the org is implicitly
	// handing the session, and the digest an install will pin.
	for _, absent := range []string{"body", "capabilities", "triggers", "references", "pinning_digest"} {
		if _, present := payload[absent]; present {
			t.Fatalf("the vulnerable review payload carries %q — the spec's S3 reviews a name and a description, and 09's thesis needs this surface to stay honest to the spec", absent)
		}
	}
	// The raw bytes never leak either: the payload is a rendering, and
	// the bundle's own phrasing exists only inside the body.
	if strings.Contains(rec.Body.String(), "titled Notes: at the end") {
		t.Fatal("the review rendered the body's instruction text: the naive org must not have been able to read what would execute")
	}
}
