package main

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"

	"github.com/ddbatista/brokenbazaar/app/auth"
	"github.com/ddbatista/brokenbazaar/app/store"
)

// authKind declares, per route, what authentication a route requires. Its zero
// value is authUnset on purpose (SR-B1-1, deny-by-default): a route added to
// the hardened table without an explicit declaration does not silently fall
// through with no check -- registerHardened panics at startup. "Forgot to
// declare" is a build-time/startup failure, never a request-time 401 or, worse,
// a request served with no auth at all.
type authKind int

const (
	authUnset   authKind = iota // zero value -- a route that never declared. Panic.
	authNone                    // unauthenticated by design (/healthz, /auth/token -- D4)
	authToken                   // requires a valid bearer token (D4)
	authService                 // requires the TOOLS_SECRET service credential (M2, D5b)
)

// protectedHandler is a handler that receives the verified claims. A route
// declared authNone uses the same shape and simply ignores the claims argument
// (see noClaims), so one table can hold authenticated and unauthenticated
// routes alike and the declaration -- not the handler's shape -- decides which
// check is applied.
type protectedHandler func(w http.ResponseWriter, r *http.Request, claims auth.Claims)

type route struct {
	method  string
	pattern string
	auth    authKind
	handler protectedHandler
}

// requireToken verifies the bearer token before dispatching to next. It is the
// single place a document route's auth check lives. In hardened mode
// registerHardened applies it by deriving it from a route's declared authKind;
// in vulnerable mode registerVulnerable applies it by hand, because there is no
// table to derive it from -- that structural difference is the whole of
// SR-B1-1.
func requireToken(secret []byte, hardened bool, next protectedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := bearerClaims(r, secret, hardened)
		if !ok {
			unauthorized(w)
			return
		}
		next(w, r, claims)
	}
}

// bearerClaims extracts and verifies an "Authorization: Bearer <token>" header.
// The hardened flag is threaded straight through to auth.Verify: in vulnerable
// mode the verifier accepts alg:none (finding 02's substrate), in hardened mode
// it does not. A missing/malformed header or a failed verification is a flat
// false -- the caller returns the uniform 401.
func bearerClaims(r *http.Request, secret []byte, hardened bool) (auth.Claims, bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return auth.Claims{}, false
	}
	claims, err := auth.Verify(strings.TrimPrefix(h, prefix), secret, hardened)
	if err != nil {
		return auth.Claims{}, false
	}
	return claims, true
}

// requireServiceSecret guards the D5b internal tool routes. The gateway
// presents TOOLS_SECRET; the agent holds nothing that satisfies this,
// which IS the mediation for read_document -- enforced at the auth layer
// rather than by the network, since M2-N1 concedes the agent can reach
// this route on the shared bridge network.
//
// The comparison is constant-time. A timing oracle on a shared secret is
// a real finding in its own right and not one this lab is teaching, so
// it does not get planted by accident.
//
// Note what this handler does NOT do: parse a JWT, read claims, or
// identify a user. A service credential authenticates a COMPONENT, and
// conflating it with user identity is how an internal route ends up
// trusting a caller-supplied org. The org arrives as an explicit query
// parameter from the gateway's session record, and the handler binds it
// through store.ForOrg.
func requireServiceSecret(toolsSecret []byte, next protectedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// An empty configured secret must match NOTHING -- not even an
		// empty presented credential.
		//
		// subtle.ConstantTimeCompare returns 1 for two empty slices,
		// because they are equal. So without this guard, a stack with
		// TOOLS_SECRET unset would ACCEPT `Authorization: Bearer `
		// (empty token) on the one route whose entire purpose is to be
		// unreachable by the agent. registerHardened panics before that
		// can happen in a real process, but a comparison function that
		// is only safe because of a check somewhere else is the shape
		// this repo keeps finding and writing up -- so the guard lives
		// here too, next to the comparison it protects. Caught by
		// TestEmptySecretMatchesNothing.
		if len(toolsSecret) == 0 {
			unauthorized(w)
			return
		}
		const prefix = "Bearer "
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, prefix) {
			unauthorized(w)
			return
		}
		presented := []byte(strings.TrimPrefix(h, prefix))
		if subtle.ConstantTimeCompare(presented, toolsSecret) != 1 {
			// A user's valid JWT lands here and is refused: it is a
			// well-formed bearer token that is not this secret. That is
			// the property D5b rests on, and api_internal_test.go
			// asserts it rather than leaving it as prose.
			unauthorized(w)
			return
		}
		next(w, r, auth.Claims{})
	}
}

// noClaims adapts a plain handler (healthz, auth/token) into a protectedHandler
// so authNone routes can live in the same table as token routes. The claims
// argument is unused -- an authNone route has none.
func noClaims(h http.HandlerFunc) protectedHandler {
	return func(w http.ResponseWriter, r *http.Request, _ auth.Claims) { h(w, r) }
}

// sealedMux is a http.Handler whose underlying ServeMux is unreachable.
//
// M1's T9 audit found SR-B1-1 does not enforce what it claims: the panic
// below fires only for a route ALREADY IN the table whose auth is
// authUnset. A handler registered straight onto the mux is never in the
// table, never evaluated, never panics -- in either mode. The
// requirement is "every route goes through the table"; the control was
// only "every route in the table declares its auth."
//
// T4 is the first task to add a route since that finding was written,
// and the route it adds is the one whose entire security property is
// that the agent cannot call it. So the gap is closed here rather than
// widened: registerHardened builds the mux locally and returns it
// wrapped, with the field unexported. There is no *http.ServeMux left
// for a later caller to reach -- a type assertion back to it fails, and
// `inner` is not addressable from another package. "Every route goes
// through the table" stops being a convention and becomes the only
// reachable path.
//
// This fixes an M1 ROT finding, not a planted bug: the hardened path is
// meant to be correct, and AGENTS.md's don't-fix rule protects
// deliverables, not accidents. registerVulnerable is deliberately
// untouched and still registers directly on a bare mux -- that contrast
// is what M1 teaches.
type sealedMux struct{ inner *http.ServeMux }

func (s sealedMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.inner.ServeHTTP(w, r)
}

// registerHardened wires every route through a declaration table
// (SR-B1-1) and returns a handler whose mux cannot be added to
// afterwards. Each entry must name its auth; an entry whose auth is the
// zero value (authUnset) is a missing declaration and panics the process
// at startup rather than registering a route that serves with no check.
// /healthz and /auth/token are listed here too, with their existing
// auth: none, so this one path owns every route and no route can be
// added without declaring how it is guarded.
func registerHardened(h *docHandlers, admin *store.AdminStore, secret, toolsSecret []byte) http.Handler {
	mux := http.NewServeMux()
	routes := []route{
		{http.MethodGet, "/healthz", authNone, noClaims(healthzHandler(true))},
		{http.MethodPost, "/auth/token", authNone, noClaims(authTokenHandler(admin, secret, true))},
		{http.MethodGet, "/me", authToken, h.me},
		{http.MethodGet, "/orgs/{org_id}/documents", authToken, h.listOrSearch},
		{http.MethodPost, "/orgs/{org_id}/documents", authToken, h.create},
		{http.MethodGet, "/orgs/{org_id}/documents/{doc_id}", authToken, h.get},
		{http.MethodPatch, "/orgs/{org_id}/documents/{doc_id}", authToken, h.update},
		{http.MethodDelete, "/orgs/{org_id}/documents/{doc_id}", authToken, h.delete},

		// D5b. Declared in the table with an explicit authKind, which
		// the committed threat model requires in as many words: "the
		// internal route must be declared in the registerHardened table
		// as a new authKind (service-secret), panicking if undeclared,
		// or it is exactly the bypass shape SR-B1-1 already fails to
		// catch." Registering it outside the table because it is
		// "internal" would be leaf B5 2.1's own reasoning applied to the
		// API's auth table -- the second time the word "internal"
		// licensed skipping a control in one module.
		//
		// Hardened mode only. Vulnerable mode runs read_document
		// in-process (T4 D2), so it needs no internal route, and
		// registering one there would plant a leaf §2 never assigned.
		{http.MethodGet, "/internal/tools/read_document", authService, h.internalReadDocument},
	}
	for _, rt := range routes {
		pattern := rt.method + " " + rt.pattern
		switch rt.auth {
		case authUnset:
			panic(fmt.Sprintf("api: route %q has no auth declaration (SR-B1-1 deny-by-default); refusing to start", pattern))
		case authNone:
			handler := rt.handler
			mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) { handler(w, r, auth.Claims{}) })
		case authToken:
			mux.HandleFunc(pattern, requireToken(secret, true, rt.handler))
		case authService:
			if len(toolsSecret) == 0 {
				// Loud or absent, never quiet (SR-B1-3). A hardened
				// stack with no service credential must refuse to
				// start, not serve a route that rejects every caller
				// and surfaces as a confusing tool failure three layers
				// up in the agent.
				panic(fmt.Sprintf("api: route %q declares authService but TOOLS_SECRET is empty; refusing to start (SR-B1-3, D5b)", pattern))
			}
			mux.HandleFunc(pattern, requireServiceSecret(toolsSecret, rt.handler))
		}
	}
	return sealedMux{inner: mux}
}

// registerVulnerable registers directly on the bare mux, exactly the T4 pattern
// already used for /healthz and /auth/token: no table, no auth declaration, no
// panic-on-missing. Each document route is wrapped in requireToken by hand --
// so the handlers DO check auth -- but nothing structural forces that. The
// mechanism that makes a forgotten auth check loud (the hardened table above)
// simply does not exist in this mode, which is the SR-B1-1 contrast the lab is
// teaching.
func registerVulnerable(mux *http.ServeMux, h *docHandlers, admin *store.AdminStore, secret []byte) {
	mux.HandleFunc("/healthz", healthzHandler(false))
	mux.HandleFunc("/auth/token", authTokenHandler(admin, secret, false))

	mux.HandleFunc("GET /me", requireToken(secret, false, h.me))
	mux.HandleFunc("GET /orgs/{org_id}/documents", requireToken(secret, false, h.listOrSearch))
	mux.HandleFunc("POST /orgs/{org_id}/documents", requireToken(secret, false, h.create))
	mux.HandleFunc("GET /orgs/{org_id}/documents/{doc_id}", requireToken(secret, false, h.get))
	mux.HandleFunc("PATCH /orgs/{org_id}/documents/{doc_id}", requireToken(secret, false, h.update))
	mux.HandleFunc("DELETE /orgs/{org_id}/documents/{doc_id}", requireToken(secret, false, h.delete))
}
