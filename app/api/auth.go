package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/ddbatista/brokenbazaar/app/auth"
	"github.com/ddbatista/brokenbazaar/app/store"
)

// POST /auth/token request and response (D3 / D4). No org_id in the request:
// the acting org is resolved server-side from the user's membership
// (store.SoleMembership), never taken from the caller.
type tokenRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type tokenResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

// authTokenHandler serves POST /auth/token. The `hardened` flag selects the
// one behaviour that differs between modes: whether a password is a required
// proof (SR-B1-2) or whether an email alone is accepted as sufficient
// (B1 1.1). Everything else -- the lookup, the membership resolution, the
// minting -- is identical, because the honest issuer is honest in both modes
// (SR-B1-4); M1's token weakness is at verification time (finding 02), not at
// issue time.
func authTokenHandler(admin *store.AdminStore, secret []byte, hardened bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		var req tokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		ctx := r.Context()
		user, found, err := admin.UserByEmail(ctx, req.Email)
		if err != nil {
			log.Printf("auth: looking up %q: %v", req.Email, err)
			writeJSONError(w, http.StatusInternalServerError, "internal error")
			return
		}

		// "No such email" and "wrong password" must be indistinguishable to
		// the caller: the same 401, the same body. This is the auth-plane
		// counterpart of SR-B2-5 (denial indistinguishable from not-found) and
		// of store.VerifyPassword's own contract -- its doc comment: "a
		// malformed stored hash is not distinguishable, to the caller, from a
		// wrong password; both must fail the same way." An attacker must not
		// be able to enumerate which emails have accounts.
		if !found {
			unauthorized(w)
			return
		}

		if hardened {
			// SR-B1-2: a verifiable credential, not just an identifier.
			if !store.VerifyPassword(req.Password, user.PasswordHash) {
				unauthorized(w)
				return
			}
		} else {
			// B1 1.1: "POST /auth/token accepts an identifier as sufficient
			// proof." The vulnerable path mints a token from the email alone
			// and never calls VerifyPassword -- even if a password field is
			// present in the body, it is ignored. password_hash exists in the
			// schema (D1) and is simply not consulted. DO NOT add the password
			// check here: this is the planted vulnerability, not an oversight
			// (AGENTS.md: "do not fix a planted vulnerability as a drive-by").
		}

		// Resolve the acting org/role server-side (SR-B2-2), never from the
		// request. A user with no single membership cannot be issued a scoped
		// token in M1 (see store.SoleMembership for why multi-org is deferred).
		orgID, role, err := admin.SoleMembership(ctx, user.ID)
		if err != nil {
			switch {
			case errors.Is(err, store.ErrNoMembership):
				// A principal with no org binding has no issuable identity in
				// this module (SR-B2-7 is about exactly this: every principal
				// carries an org binding). Fold into the uniform 401 so it is
				// not an enumeration oracle either; log the real reason.
				log.Printf("auth: %q has no membership: %v", req.Email, err)
				unauthorized(w)
			case errors.Is(err, store.ErrAmbiguousMembership):
				// Multi-org login is deferred to M3 (see SoleMembership). This
				// path is unreachable with the current seed (one membership
				// per user) but is handled rather than left to mint a token
				// for an arbitrary org.
				log.Printf("auth: %q has multiple memberships (multi-org login deferred to M3): %v", req.Email, err)
				writeJSONError(w, http.StatusNotImplemented, "multi-org login is not supported in M1")
			default:
				log.Printf("auth: resolving membership for %q: %v", req.Email, err)
				writeJSONError(w, http.StatusInternalServerError, "internal error")
			}
			return
		}

		now := time.Now()
		claims := auth.Claims{
			Sub:   user.ID,
			OrgID: orgID,
			Role:  string(role),
			Iss:   auth.Issuer,
			Iat:   now.Unix(),
			Exp:   now.Add(auth.TokenTTL).Unix(),
		}
		token, err := auth.Encode(claims, secret)
		if err != nil {
			log.Printf("auth: encoding token for %q: %v", req.Email, err)
			writeJSONError(w, http.StatusInternalServerError, "internal error")
			return
		}

		writeJSON(w, http.StatusOK, tokenResponse{Token: token, ExpiresAt: claims.Exp})
	}
}

// unauthorized writes the single, uniform 401 used for every credential
// failure, so callers cannot tell the failure modes apart (see above).
func unauthorized(w http.ResponseWriter) {
	writeJSONError(w, http.StatusUnauthorized, "invalid email or password")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
