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
	"github.com/ddbatista/brokenbazaar/app/mcp"
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
// as refused by policy as control_plane_not_delegable (D6). Both halves are
// pinned: TestNonDelegableToolsHaveNoInternalRoute reads the policy's
// denylist and probes every listed tool's route.

// sessionAuthorityLookup is AdminStore.SessionAuthority in production.
type sessionAuthorityLookup interface {
	SessionAuthority(ctx context.Context, sessionID string) (store.SessionAuthority, bool, error)
}

// internalTools holds the internal routes. Its dependencies are a lookup, an
// org-bound store constructor and a clock, so every leg and every refusal is
// testable without a database (internal_tools_test.go).
type internalTools struct {
	sessions    sessionAuthorityLookup
	docsFor     func(orgID string) store.DocumentStore
	installsFor func(orgID string) installLister
	now         func() time.Time
}

// installLister is the org-bound install surface the authority route reads.
// *store.OrgStore satisfies it; the tests fake it.
type installLister interface {
	Installs(ctx context.Context) ([]store.Install, error)
}

func newInternalTools(admin *store.AdminStore, pool *pgxpool.Pool) *internalTools {
	return &internalTools{
		sessions:    admin,
		docsFor:     func(orgID string) store.DocumentStore { return store.ForOrg(pool, orgID) },
		installsFor: func(orgID string) installLister { return store.ForOrg(pool, orgID) },
		now:         time.Now,
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
	// Installs is the session's org's ACTIVE installs, with the facts the
	// gateway's marketplace legs decide on (M4a T5): the pin's bytes and
	// endpoint, and -- computed here, against the PIN, not against any
	// live manifest -- whether THIS tool is in the pin and whether the
	// pin's consent covers document content. The gateway fetches live
	// itself (its egress, its one classifier) and compares digests; these
	// facts are the platform-owned half (SR-B5-1: the decision derives
	// from state the reviewed party cannot influence).
	Installs []installFact `json:"installs"`
}

// installFact is one active install as the gateway needs it. ToolInPin and
// ReceivesDocumentContent are computed from the pinned manifest HERE, in Go,
// by the same parser that validated it at install -- one home for "what does
// the pin say" (mcp.Parse). A pin that no longer parses (corruption, not an
// attack surface -- installs are validated at write) reports tool_in_pin
// false; the gateway's drift check still runs on the digest, so a corrupt
// pin can never read as verified.
type installFact struct {
	InstallID               string `json:"install_id"`
	ItemID                  string `json:"item_id"`
	EndpointURL             string `json:"endpoint_url"`
	EndpointAddress         string `json:"endpoint_address"`
	PinnedDigest            string `json:"pinned_digest"`
	PinnedManifest          string `json:"pinned_manifest"`
	ToolInPin               bool   `json:"tool_in_pin"`
	ReceivesDocumentContent bool   `json:"receives_document_content"`
}

// installFacts reads the org's active installs and derives the per-tool
// facts from each pin. Stable order (store.Installs), so the gateway's
// candidate selection is deterministic.
func (it *internalTools) installFacts(ctx context.Context, orgID, tool string) ([]installFact, error) {
	installs, err := it.installsFor(orgID).Installs(ctx)
	if err != nil {
		return nil, err
	}
	var out []installFact
	for _, ins := range installs {
		fact := installFact{
			InstallID:       ins.ID,
			ItemID:          ins.ItemID,
			EndpointURL:     ins.EndpointURL,
			EndpointAddress: ins.EndpointAddress,
			PinnedDigest:    ins.PinnedDigest,
			PinnedManifest:  ins.PinnedManifest,
		}
		if tools, err := mcp.Parse([]byte(ins.PinnedManifest)); err == nil {
			for _, t := range tools {
				if t.Name != tool {
					continue
				}
				fact.ToolInPin = true
				fact.ReceivesDocumentContent = mcp.Receives(t, mcp.ReceivesDocumentContent)
			}
		}
		out = append(out, fact)
	}
	return out, nil
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
// of a call the gateway had allowed, which R6 (detections/delegation_rules.py)
// reads as its own signal.
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
	installs, err := it.installFacts(r.Context(), s.OrgID, tool)
	if err != nil {
		internalError(w, err)
		return
	}
	// A store list for an org with no installs returns a NIL slice, and
	// Go marshals nil as JSON null -- which the gateway's strict
	// validation correctly refuses as "lacks an installs array": null is
	// not "no installs", it is NO ANSWER ABOUT INSTALLS. Found live by
	// the F1 fault run (every 03-06 hardened control exited
	// enrichment_failed on a freshly seeded org). An org with no
	// installs answers an EMPTY ARRAY, deliberately.
	if installs == nil {
		installs = []installFact{}
	}
	// M4a T5 (mediation): installed-tool calls ride the M3 legs
	// (m4a-marketplace.md A8.2/A8.6), and their action class is Read --
	// http_fetch's own precedent (M3 T6 D1: "any role may fetch"). The
	// org's install decision, not the caller's role, is the authority
	// boundary (D8), so role is the WRONG leg to distinguish a pinned
	// name from a drifted one: this applies to every non-platform name
	// once the org has any active install. A name that is neither
	// pinned nor live dies at unknown_tool, which evaluates FIRST; a
	// drifted one is the drift leg's to refuse, which evaluates AFTER
	// role -- so both keep their own reasons.
	if _, platform := authz.ActionFor(tool); !platform && len(installs) > 0 {
		legs.RolePermits = authz.Permits(s.RoleNow, authz.Read)
	}
	writeJSON(w, http.StatusOK, authorityResponse{
		Session:  sessionRef{ID: s.SessionID, Org: s.OrgID, ActingFor: s.ActingFor},
		Tool:     tool,
		RoleNow:  string(s.RoleNow),
		Legs:     legs,
		Installs: installs,
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
