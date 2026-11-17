package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Plan M3 T7 (m3-delegation.md D6): a control-plane tool is refused twice,
// by two different mechanisms. The gateway policy denies it by name
// (control_plane_not_delegable), and the API has no internal route that
// could execute it, so an allow could not run it (M2 D5's mediation by
// absence, applied to one tool).
//
// This test holds the second half to the first. It reads the denylist from
// the gateway policy itself rather than restating it here -- two copies of
// the list would drift, and the policy is a hardened zone this package
// cannot edit -- so when M4b adds a tool to the list, this test probes its
// route with no edit.

// nonDelegable reads policy.rego's `non_delegable := {...}` set.
func nonDelegable(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("../../gateway/policy/policy.rego")
	if err != nil {
		t.Fatal(err)
	}
	set := regexp.MustCompile(`(?m)^non_delegable := \{([^}]*)\}`).FindSubmatch(raw)
	if set == nil {
		t.Fatal("policy.rego has no `non_delegable := {...}` set")
	}
	var tools []string
	for _, m := range regexp.MustCompile(`"([^"]+)"`).FindAllSubmatch(set[1], -1) {
		tools = append(tools, string(m[1]))
	}
	// Not vacuous: a parse that found nothing would pass every probe below.
	if !slices.Contains(tools, "set_member_role") {
		t.Fatalf("non_delegable = %q, want it to name set_member_role (finding 06)", tools)
	}
	return tools
}

func TestNonDelegableToolsHaveNoInternalRoute(t *testing.T) {
	secret := []byte("test-secret-not-a-real-one")
	it, _ := fakeInternalTools()
	m, _ := fakeMemberHandlers()
	modes := map[string]http.Handler{
		"hardened": registerHardened(&docHandlers{hardened: true}, m, it, nil, secret, []byte("tools-secret")),
	}
	vmux := http.NewServeMux()
	registerVulnerable(vmux, &docHandlers{}, m, nil, secret)
	modes["vulnerable"] = vmux

	// The probe's own positive control (T0 D3): with the same mux, path
	// shape and secret, a delegable tool's route IS found. Without it, a
	// wrong prefix or a mis-wired mux would 404 everything, and the absence
	// asserted below would be the probe's, not the route's.
	for _, delegable := range []string{"read_document", "update_document", "delete_document"} {
		method := http.MethodPost
		if delegable == "read_document" {
			method = http.MethodGet
		}
		req := httptest.NewRequest(method, "/internal/tools/"+delegable, strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer tools-secret")
		rec := httptest.NewRecorder()
		modes["hardened"].ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound && strings.Contains(rec.Body.String(), "page not found") ||
			rec.Code == http.StatusMethodNotAllowed || rec.Code == http.StatusUnauthorized {
			t.Fatalf("positive control: hardened %s /internal/tools/%s = %d; the probe cannot see routes that exist", method, delegable, rec.Code)
		}
	}

	methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
	for _, tool := range nonDelegable(t) {
		for _, path := range []string{"/internal/tools/" + tool, "/internal/" + tool} {
			for mode, h := range modes {
				for _, method := range methods {
					req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
					// The service secret: the probe is the gateway's own
					// credential, so a 404 here is the route's absence,
					// never an auth refusal standing in for it.
					req.Header.Set("Authorization", "Bearer tools-secret")
					rec := httptest.NewRecorder()
					h.ServeHTTP(rec, req)
					// The MUX's 404, not a handler's: a registered route that
					// answered not-found for a missing session would also be
					// 404, and would still be a route.
					if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "page not found") {
						t.Errorf("%s %s %s: %d %q, want the mux's 404 -- a non-delegable tool must have no execution route", mode, method, path, rec.Code, rec.Body.String())
					}
				}
			}
		}
	}
}
