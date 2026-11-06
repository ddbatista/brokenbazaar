package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ddbatista/brokenbazaar/app/auth"
)

// D5b's security claim is one sentence: "mediation for read_document is
// the secret, enforced at the auth layer. The agent can reach this route
// on the bridge network (M2-N1, as conceded) but holds nothing that
// authenticates to it."
//
// The second half is the part worth asserting. The agent legitimately
// holds a user JWT -- it is a real, signed, unexpired bearer token -- so
// "the agent cannot call this route" is only true if a valid JWT is
// refused here. That is what these tests pin down, rather than leaving
// it as a claim in a comment.

// A structurally valid JWT. Not minted by auth.Sign on purpose: the
// point is that ANY well-formed bearer token which is not the service
// secret is refused, so coupling the test to token issuance would test
// the wrong thing.
const wellFormedJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJzdWIiOiJ1XzEiLCJvcmdfaWQiOiJhY21lIiwicm9sZSI6Im1lbWJlciJ9." +
	"c2lnbmF0dXJlLXdvdWxkLWdvLWhlcmU"

func serviceRoute(secret string) http.HandlerFunc {
	reached := func(w http.ResponseWriter, _ *http.Request, _ auth.Claims) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"d1"}`))
	}
	return requireServiceSecret([]byte(secret), reached)
}

func callWith(t *testing.T, h http.HandlerFunc, authHeader string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/internal/tools/read_document?id=d1&org=acme", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestInternalRouteRefusesEverythingButTheServiceSecret(t *testing.T) {
	const secret = "s3rv1ce-secret"
	h := serviceRoute(secret)

	cases := []struct {
		name   string
		header string
		want   int
	}{
		// THE assertion D5b rests on.
		{"a valid user JWT", "Bearer " + wellFormedJWT, http.StatusUnauthorized},
		{"no header at all", "", http.StatusUnauthorized},
		{"empty bearer", "Bearer ", http.StatusUnauthorized},
		{"the secret without the Bearer prefix", secret, http.StatusUnauthorized},
		{"a different secret", "Bearer not-the-secret", http.StatusUnauthorized},
		// Near-misses: a prefix comparison or a trim would let these
		// through, and both are plausible implementations.
		{"the secret with a trailing space", "Bearer " + secret + " ", http.StatusUnauthorized},
		{"a prefix of the secret", "Bearer s3rv1ce", http.StatusUnauthorized},
		{"the secret with extra suffix", "Bearer " + secret + "x", http.StatusUnauthorized},
		// The only thing that works.
		{"the exact service secret", "Bearer " + secret, http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := callWith(t, h, tc.header); got != tc.want {
				t.Fatalf("want HTTP %d, got %d", tc.want, got)
			}
		})
	}
}

// TestHardenedMuxCannotBeExtended is the seal from T4 D3. M1's T9 audit
// found SR-B1-1's panic only covers routes already in the table, so a
// handler registered straight onto the mux bypassed the control
// entirely. registerHardened now owns its mux and returns it wrapped,
// so there is no *http.ServeMux for a caller to get hold of.
func TestHardenedMuxCannotBeExtended(t *testing.T) {
	var h http.Handler = sealedMux{inner: http.NewServeMux()}

	if _, ok := h.(*http.ServeMux); ok {
		t.Fatal("the hardened handler can be asserted back to *http.ServeMux; routes could be added outside the table")
	}
	if _, ok := h.(interface {
		HandleFunc(string, func(http.ResponseWriter, *http.Request))
	}); ok {
		t.Fatal("the hardened handler exposes HandleFunc; routes could be added outside the table")
	}
	if _, ok := h.(interface{ Handle(string, http.Handler) }); ok {
		t.Fatal("the hardened handler exposes Handle; routes could be added outside the table")
	}
}

// TestServiceRouteIsRefusedWhenNoSecretIsConfigured covers the
// loud-or-absent rule from the other side: if TOOLS_SECRET is empty,
// registerHardened panics at startup rather than serving a route that
// rejects every caller. An empty secret must never be the thing an
// empty presented credential matches.
func TestEmptySecretMatchesNothing(t *testing.T) {
	h := serviceRoute("")
	for _, header := range []string{"", "Bearer ", "Bearer anything"} {
		if got := callWith(t, h, header); got != http.StatusUnauthorized {
			t.Fatalf("header %q: want 401 with no configured secret, got %d", header, got)
		}
	}
}
