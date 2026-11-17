package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ddbatista/brokenbazaar/app/auth"
	"github.com/ddbatista/brokenbazaar/app/authz"
	"github.com/ddbatista/brokenbazaar/app/store"
)

// The internal routes the gateway calls, hardened mode only, behind the
// service secret (M2 D5b; plan M3 T6 D2/D4).
//
//	GET  /internal/sessions/{session_id}/authority?tool=...   the gateway asks before it decides
//	GET  /internal/tools/read_document?session=...&id=...     execution
//	POST /internal/tools/update_document  {session, id, body}
//	POST /internal/tools/delete_document  {session, id}
//
// THE SESSION NAMES; IT NEVER GRANTS (m3-delegation.md D3). Every route takes
// a session id and nothing else about the caller: the org, the acting user
// and the role all come from the session row and the live membership, read
// fresh on every request. M2's read route took the org as a parameter from
// the gateway, which passed on what the agent's payload said (D3 names the
// two lines). That parameter is gone; an org= in a request is ignored.
//
// EVERY EXECUTION ROUTE RE-CHECKS (M3-N2). The gateway asked the authority
// route a moment ago, but a demotion, an expiry or a removal can land in
// between. Each route re-runs the same authz.Derive and refuses with the
// failing leg's reason before the store is touched. The gateway records that
// reason as the execution outcome; the agent sees only the uniform denial.
//
// There is no route for set_member_role, and there must never be one: a
// control-plane action is unreachable from the agent by structure, as well
// as refused by policy (D6, T7).

// sessionAuthorityLookup is AdminStore.SessionAuthority in production.
type sessionAuthorityLookup interface {
	SessionAuthority(ctx context.Context, sessionID string) (store.SessionAuthority, bool, error)
}

// internalTools holds the internal routes. Its dependencies are a lookup, an
// org-bound store constructor and a clock, so every leg and every refusal is
// testable without a database (internal_tools_test.go).
type internalTools struct {
	sessions sessionAuthorityLookup
	docsFor  func(orgID string) store.DocumentStore
	now      func() time.Time
}

func newInternalTools(admin *store.AdminStore, pool *pgxpool.Pool) *internalTools {
	return &internalTools{
		sessions: admin,
		docsFor:  func(orgID string) store.DocumentStore { return store.ForOrg(pool, orgID) },
		now:      time.Now,
	}
}

type sessionRef struct {
	ID        string `json:"id"`
	Org       string `json:"org"`
	ActingFor string `json:"acting_for"`
}

// authorityResponse is what the gateway enriches its policy input with.
// Every leg is always present; each means PASSES (authz.Legs).
type authorityResponse struct {
	Session sessionRef `json:"session"`
	Tool    string     `json:"tool"`
	RoleNow string     `json:"role_now"`
	Legs    authz.Legs `json:"legs"`
}

// load reads the session and derives the legs for tool, writing the 500 or
// 404 itself when there is nothing to derive from.
func (it *internalTools) load(w http.ResponseWriter, ctx context.Context, sessionID, tool string) (store.SessionAuthority, authz.Legs, bool) {
	if !store.IsID(sessionID) {
		// Not an id at all: the same 404 as an unknown session, rather than
		// a 500 from the database's uuid cast. The gateway fails closed on
		// either, but only one of them is the truth.
		writeJSONError(w, http.StatusNotFound, "no such session")
		return store.SessionAuthority{}, authz.Legs{}, false
	}
	s, found, err := it.sessions.SessionAuthority(ctx, sessionID)
	if err != nil {
		internalError(w, err)
		return store.SessionAuthority{}, authz.Legs{}, false
	}
	if !found {
		writeJSONError(w, http.StatusNotFound, "no such session")
		return store.SessionAuthority{}, authz.Legs{}, false
	}
	return s, authz.Derive(s, tool, it.now()), true
}

// authorize is the execution routes' re-check: the legs NOW, or a 403 that
// names the first failing leg. Logged where it is decided, in a format of
// its own (session=, not M1's target_org=): this is a refusal at execution
// of a call the gateway had allowed, which T10 reads as its own signal.
func (it *internalTools) authorize(w http.ResponseWriter, ctx context.Context, sessionID, tool string) (store.SessionAuthority, bool) {
	s, legs, ok := it.load(w, ctx, sessionID, tool)
	if !ok {
		return store.SessionAuthority{}, false
	}
	if reason := legs.Failing(); reason != "" {
		// decision= is spelled with hyphens, like T3's role-does-not-permit
		// and M1's not-a-member, so one reason has one spelling in the logs
		// a rule reads. The 403 body carries the policy's underscore form,
		// which the gateway records.
		log.Printf("authz: deny session=%s org=%s decision=%s tool=%s at=execution",
			s.SessionID, s.OrgID, strings.ReplaceAll(reason, "_", "-"), tool)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "refused at execution", "reason": reason})
		return store.SessionAuthority{}, false
	}
	return s, true
}

func (it *internalTools) authority(w http.ResponseWriter, r *http.Request, _ auth.Claims) {
	tool := r.URL.Query().Get("tool")
	if tool == "" {
		writeJSONError(w, http.StatusBadRequest, "tool is required")
		return
	}
	s, legs, ok := it.load(w, r.Context(), r.PathValue("session_id"), tool)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, authorityResponse{
		Session: sessionRef{ID: s.SessionID, Org: s.OrgID, ActingFor: s.ActingFor},
		Tool:    tool,
		RoleNow: string(s.RoleNow),
		Legs:    legs,
	})
}

func (it *internalTools) readDocument(w http.ResponseWriter, r *http.Request, _ auth.Claims) {
	q := r.URL.Query()
	sessionID, docID := q.Get("session"), q.Get("id")
	if sessionID == "" || docID == "" {
		writeJSONError(w, http.StatusBadRequest, "session and id are required")
		return
	}
	s, ok := it.authorize(w, r.Context(), sessionID, "read_document")
	if !ok {
		return
	}
	// The ROW's org, bound through the org-scoped store: a document id from
	// another tenant is not-found by the same single WHERE as everywhere
	// else (SR-M1-4).
	doc, found, err := it.docsFor(s.OrgID).Get(r.Context(), docID)
	if err != nil {
		internalError(w, err)
		return
	}
	if !found {
		notFound(w)
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(doc))
}

// toolWriteRequest is the body of the two write routes. Body is a pointer
// so a request with no body field is refused rather than read as "" -- the
// same rule as the agent's executor (plan M3 T4 D4).
type toolWriteRequest struct {
	Session string  `json:"session"`
	ID      string  `json:"id"`
	Body    *string `json:"body"`
}

func decodeToolWrite(w http.ResponseWriter, r *http.Request, needBody bool) (toolWriteRequest, bool) {
	var req toolWriteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return req, false
	}
	if req.Session == "" || req.ID == "" || (needBody && req.Body == nil) {
		writeJSONError(w, http.StatusBadRequest, "session, id (and body, for update) are required")
		return req, false
	}
	return req, true
}

func (it *internalTools) updateDocument(w http.ResponseWriter, r *http.Request, _ auth.Claims) {
	req, ok := decodeToolWrite(w, r, true)
	if !ok {
		return
	}
	s, ok := it.authorize(w, r.Context(), req.Session, "update_document")
	if !ok {
		return
	}
	docs := it.docsFor(s.OrgID)
	// Body replaced, title kept: the tool's contract in both builds (plan
	// M3 T4 D3). Read, then write -- the same two statements as the
	// vulnerable executor, with the same accepted lost-update window.
	doc, found, err := docs.Get(r.Context(), req.ID)
	if err != nil {
		internalError(w, err)
		return
	}
	if !found {
		notFound(w)
		return
	}
	doc.Body = *req.Body
	updated, found, err := docs.Update(r.Context(), doc)
	if err != nil {
		internalError(w, err)
		return
	}
	if !found {
		notFound(w)
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(updated))
}

func (it *internalTools) deleteDocument(w http.ResponseWriter, r *http.Request, _ auth.Claims) {
	req, ok := decodeToolWrite(w, r, false)
	if !ok {
		return
	}
	s, ok := it.authorize(w, r.Context(), req.Session, "delete_document")
	if !ok {
		return
	}
	deleted, err := it.docsFor(s.OrgID).Delete(r.Context(), req.ID)
	if err != nil {
		internalError(w, err)
		return
	}
	if !deleted {
		notFound(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
