package main

import (
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
	authUnset authKind = iota // zero value -- a route that never declared. Panic.
	authNone                  // unauthenticated by design (/healthz, /auth/token -- D4)
	authToken                 // requires a valid bearer token (D4)
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

// noClaims adapts a plain handler (healthz, auth/token) into a protectedHandler
// so authNone routes can live in the same table as token routes. The claims
// argument is unused -- an authNone route has none.
func noClaims(h http.HandlerFunc) protectedHandler {
	return func(w http.ResponseWriter, r *http.Request, _ auth.Claims) { h(w, r) }
}

// registerHardened wires every route through a declaration table (SR-B1-1).
// Each entry must name its auth; an entry whose auth is the zero value
// (authUnset) is a missing declaration and panics the process at startup rather
// than registering a route that serves with no check. /healthz and /auth/token
// are listed here too, with their existing auth: none, so this one path owns
// every route and no route can be added without declaring how it is guarded.
func registerHardened(mux *http.ServeMux, h *docHandlers, admin *store.AdminStore, secret []byte) {
	routes := []route{
		{http.MethodGet, "/healthz", authNone, noClaims(healthzHandler)},
		{http.MethodPost, "/auth/token", authNone, noClaims(authTokenHandler(admin, secret, true))},
		{http.MethodGet, "/me", authToken, h.me},
		{http.MethodGet, "/orgs/{org_id}/documents", authToken, h.listOrSearch},
		{http.MethodPost, "/orgs/{org_id}/documents", authToken, h.create},
		{http.MethodGet, "/orgs/{org_id}/documents/{doc_id}", authToken, h.get},
		{http.MethodPatch, "/orgs/{org_id}/documents/{doc_id}", authToken, h.update},
		{http.MethodDelete, "/orgs/{org_id}/documents/{doc_id}", authToken, h.delete},
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
		}
	}
}

// registerVulnerable registers directly on the bare mux, exactly the T4 pattern
// already used for /healthz and /auth/token: no table, no auth declaration, no
// panic-on-missing. Each document route is wrapped in requireToken by hand --
// so the handlers DO check auth -- but nothing structural forces that. The
// mechanism that makes a forgotten auth check loud (the hardened table above)
// simply does not exist in this mode, which is the SR-B1-1 contrast the lab is
// teaching.
func registerVulnerable(mux *http.ServeMux, h *docHandlers, admin *store.AdminStore, secret []byte) {
	mux.HandleFunc("/healthz", healthzHandler)
	mux.HandleFunc("/auth/token", authTokenHandler(admin, secret, false))

	mux.HandleFunc("GET /me", requireToken(secret, false, h.me))
	mux.HandleFunc("GET /orgs/{org_id}/documents", requireToken(secret, false, h.listOrSearch))
	mux.HandleFunc("POST /orgs/{org_id}/documents", requireToken(secret, false, h.create))
	mux.HandleFunc("GET /orgs/{org_id}/documents/{doc_id}", requireToken(secret, false, h.get))
	mux.HandleFunc("PATCH /orgs/{org_id}/documents/{doc_id}", requireToken(secret, false, h.update))
	mux.HandleFunc("DELETE /orgs/{org_id}/documents/{doc_id}", requireToken(secret, false, h.delete))
}
