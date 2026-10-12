package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ddbatista/brokenbazaar/app/auth"
	"github.com/ddbatista/brokenbazaar/app/store"
)

// docHandlers serves the D4 document routes and GET /me. The one decision that
// differs between modes -- which org's DocumentStore a request acts through,
// and how that org is decided -- is isolated in resolveStore below; every
// handler then calls through the store.DocumentStore interface and is otherwise
// identical code. That is the whole reason D5 designed DocumentStore as a single
// interface in T3: the vulnerability is not in the handlers, it is in the one
// resolution step they all share.
type docHandlers struct {
	admin    *store.AdminStore
	pool     *pgxpool.Pool
	hardened bool
}

// resolveStore is the single decision point for "which store, which acting
// org". It is deliberately the only place the two modes diverge on tenancy, so
// a reader can see the entire difference between the hardened and vulnerable
// products in one function pair rather than scattered across six handlers.
//
// The bool is "proceed": false means the caller must return the uniform 404
// (hardened mode, no membership). Vulnerable mode always proceeds -- it never
// denies, which is exactly the point.
func (h *docHandlers) resolveStore(ctx context.Context, pathOrgID string, claims auth.Claims) (store.DocumentStore, bool, error) {
	if h.hardened {
		return resolveHardenedStore(ctx, h.admin, h.pool, pathOrgID, claims)
	}
	return resolveVulnerableStore(h.pool, claims), true, nil
}

// resolveHardenedStore scopes to the PATH's org, but only after confirming the
// user's real, current membership in it server-side (SR-B2-2). It never trusts
// claims.OrgID.
func resolveHardenedStore(ctx context.Context, admin *store.AdminStore, pool *pgxpool.Pool, pathOrgID string, claims auth.Claims) (store.DocumentStore, bool, error) {
	// SR-B2-2: the acting org is decided by the user's membership in the PATH's
	// {org_id}, looked up against records the API owns -- never from
	// claims.OrgID. That claim is present and signed (M1-N5) but is exactly the
	// field finding 02 forges, so it is not consulted here. The role is read
	// but intentionally discarded: M1 authorises on membership alone -- any
	// member does all CRUD -- because roles "with real teeth" are M3 scope.
	_, ok, err := admin.MembershipRole(ctx, pathOrgID, claims.Sub)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		// SR-B2-5 / SR-M1-4: "not a member of this org" is turned by the caller
		// into the identical 404 used for "no such document", never a distinct
		// "you're not in this org" -- the same indistinguishability principle
		// /auth/token already uses. SR-B2-8: the denial is logged here, which is
		// the only clean denial point in the hardened path; a wrong-org document
		// lookup is deliberately indistinguishable from not-found (OrgStore.Get's
		// single WHERE id=$1 AND org_id=$2) and so cannot be logged without
		// reintroducing the very distinction SR-M1-4 removes.
		log.Printf("authz: deny sub=%s target_org=%s decision=not-a-member", claims.Sub, pathOrgID)
		return nil, false, nil
	}
	return store.ForOrg(pool, pathOrgID), true, nil
}

// resolveVulnerableStore is the planted decision every vulnerable document
// handler shares. DO NOT "fix" it by checking the path against membership --
// that is the deliverable, not a bug (AGENTS.md).
func resolveVulnerableStore(pool *pgxpool.Pool, claims auth.Claims) store.DocumentStore {
	// B2 1.3 / B2 2.2: the acting org is claims.OrgID, straight from the
	// verified token, and the path's {org_id} is read by the handler but never
	// checked against real membership. This is uniform across every document
	// handler, not special-cased to PATCH -- it is what a developer writes who
	// reasons "I already verified the user via JWT, so why hit the DB again."
	// PATCH is merely where finding 02's PoC lands in T6 (mutating another
	// tenant's data is the sharper demo), but read and write share this one
	// trust-the-claim decision.
	//
	// NaiveStore's methods take no org context at all, so for Get/Search/
	// Update/Delete the claim does not even constrain the query -- that absence
	// is the IDOR (B2 2.1) and search-leak (finding 01) substrate. The two
	// handlers that genuinely need the acting org -- the List filter (M1-N3)
	// and the Create org_id fallback -- read claims.OrgID directly.
	return store.NewNaiveStore(pool)
}

// documentResponse is the wire shape of a document. store.Document carries no
// JSON tags on purpose (it is a storage type); this is the API representation,
// with snake_case names matching D1's columns. password_hash-style leakage is a
// non-issue here -- a document has no secret fields -- but keeping an explicit
// DTO means the serialized shape is decided here, not inherited by accident.
type documentResponse struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

func toDocumentResponse(d store.Document) documentResponse {
	return documentResponse{
		ID:        d.ID,
		OrgID:     d.OrgID,
		Title:     d.Title,
		Body:      d.Body,
		CreatedBy: d.CreatedBy,
		CreatedAt: d.CreatedAt,
	}
}

// createDocumentRequest is the hardened create DTO (SR-B2-6): title and body
// only. There is no org_id and no created_by field in the shape at all, so
// neither is client-settable -- OrgID comes from the membership-verified path
// org (OrgStore.Create binds it), CreatedBy from claims.Sub.
type createDocumentRequest struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

// naiveCreateDocumentRequest is the vulnerable create shape. Unlike the
// hardened DTO it DELIBERATELY carries org_id (B2 4.1, mass assignment): the
// org a document is created in is taken from the body when present, honouring a
// client-chosen value. (store.Document has no JSON tags, so a literal "bind the
// whole body into the struct" would silently bind nothing; this explicit struct
// reproduces the same client-controlled-org_id leaf faithfully.) CreatedBy is
// still server-side from claims.Sub -- identity is not the leaf planted here,
// org_id is, and the demo stays focused on the one documented leaf.
type naiveCreateDocumentRequest struct {
	OrgID string `json:"org_id"`
	Title string `json:"title"`
	Body  string `json:"body"`
}

// updateDocumentRequest is shared by both modes: only title and body are
// patchable. org_id and created_by are not in the shape, so PATCH can never
// move a document between orgs or rewrite its author in either mode. (The store
// Update overwrites both title and body; partial-field PATCH is not attempted
// -- the stores expose a full title/body replace, which is what this binds.)
type updateDocumentRequest struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

// meResponse echoes the verified claims (D4 GET /me). No store access and no
// planted bug -- it is the claims-echo the route table names.
type meResponse struct {
	Sub   string `json:"sub"`
	OrgID string `json:"org_id"`
	Role  string `json:"role"`
}

func (h *docHandlers) me(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
	writeJSON(w, http.StatusOK, meResponse{Sub: claims.Sub, OrgID: claims.OrgID, Role: claims.Role})
}

// listOrSearch serves GET /orgs/{org_id}/documents, branching on the q param:
// present -> Search, absent -> List. The list/search asymmetry (M1-N3) lives
// here in vulnerable mode -- List filters, Search does not.
func (h *docHandlers) listOrSearch(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
	ctx := r.Context()
	ds, ok, err := h.resolveStore(ctx, r.PathValue("org_id"), claims)
	if err != nil {
		internalError(w, err)
		return
	}
	if !ok {
		notFound(w)
		return
	}

	if q := r.URL.Query().Get("q"); q != "" {
		// finding 01 (attacks/01-cross-tenant-read): in vulnerable mode
		// NaiveStore.Search has no org predicate and -- unlike List below --
		// NOTHING here filters afterward. The leak needs no forgery: an
		// honestly issued token reads every org's documents. DO NOT add a
		// post-filter; that is the planted vulnerability. In hardened mode the
		// same call is scoped by OrgStore.Search and this code is identical.
		docs, err := ds.Search(ctx, q)
		if err != nil {
			internalError(w, err)
			return
		}
		writeDocuments(w, docs)
		return
	}

	docs, err := ds.List(ctx)
	if err != nil {
		internalError(w, err)
		return
	}
	if !h.hardened {
		// M1-N3, the "list remembers the rule" half: NaiveStore.List returns
		// every org's documents, so the handler filters in Go to the acting
		// org. This is the sibling that (if accidentally, structurally
		// fragile) gets scope right -- placed next to Search so a reader sees
		// the contrast. In hardened mode OrgStore.List is already scoped, so
		// no filter runs.
		docs = filterByOrg(docs, claims.OrgID)
	}
	writeDocuments(w, docs)
}

func (h *docHandlers) create(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
	ctx := r.Context()
	pathOrgID := r.PathValue("org_id")
	ds, ok, err := h.resolveStore(ctx, pathOrgID, claims)
	if err != nil {
		internalError(w, err)
		return
	}
	if !ok {
		notFound(w)
		return
	}

	var doc store.Document
	if h.hardened {
		var req createDocumentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		// OrgID is intentionally left zero: OrgStore.Create binds it to the
		// membership-verified path org (SR-B2-6). CreatedBy from claims.Sub,
		// never the body.
		doc = store.Document{Title: req.Title, Body: req.Body, CreatedBy: claims.Sub}
	} else {
		var req naiveCreateDocumentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		// B2 4.1 mass assignment: org_id comes from the body and is NOT
		// stripped or overridden. If the body omits it, fall back to
		// claims.OrgID so the honest path still works. CreatedBy stays
		// server-side.
		orgID := req.OrgID
		if orgID == "" {
			orgID = claims.OrgID
		}
		doc = store.Document{OrgID: orgID, Title: req.Title, Body: req.Body, CreatedBy: claims.Sub}
	}

	created, err := ds.Create(ctx, doc)
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toDocumentResponse(created))
}

func (h *docHandlers) get(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
	ctx := r.Context()
	ds, ok, err := h.resolveStore(ctx, r.PathValue("org_id"), claims)
	if err != nil {
		internalError(w, err)
		return
	}
	if !ok {
		notFound(w)
		return
	}
	// Hardened: OrgStore.Get's single WHERE id=$1 AND org_id=$2 makes wrong-org
	// and no-such-id the identical empty result (SR-B2-5 / SR-M1-4). Vulnerable:
	// NaiveStore.Get has no org predicate -- any doc id from any org resolves
	// (B2 2.1, IDOR). Same handler code either way; the store decides.
	doc, found, err := ds.Get(ctx, r.PathValue("doc_id"))
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

func (h *docHandlers) update(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
	ctx := r.Context()
	ds, ok, err := h.resolveStore(ctx, r.PathValue("org_id"), claims)
	if err != nil {
		internalError(w, err)
		return
	}
	if !ok {
		notFound(w)
		return
	}
	var req updateDocumentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// finding 02's target in vulnerable mode: the acting org came from
	// claims.OrgID (resolveVulnerableStore), and NaiveStore.Update scopes by id
	// alone, so a forged org_id claim (T6 + T4's alg:none) mutates another
	// tenant's document. Hardened mode kills it: ds is scoped to the
	// membership-verified path org, so Update's WHERE org_id=$4 misses.
	updated, found, err := ds.Update(ctx, store.Document{ID: r.PathValue("doc_id"), Title: req.Title, Body: req.Body})
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

func (h *docHandlers) delete(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
	ctx := r.Context()
	ds, ok, err := h.resolveStore(ctx, r.PathValue("org_id"), claims)
	if err != nil {
		internalError(w, err)
		return
	}
	if !ok {
		notFound(w)
		return
	}
	deleted, err := ds.Delete(ctx, r.PathValue("doc_id"))
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

// filterByOrg keeps only the documents belonging to orgID. Used by the
// vulnerable List path (M1-N3) and nowhere else -- the hardened store scopes in
// SQL, so no Go-side filter exists to forget.
func filterByOrg(docs []store.Document, orgID string) []store.Document {
	out := make([]store.Document, 0, len(docs))
	for _, d := range docs {
		if d.OrgID == orgID {
			out = append(out, d)
		}
	}
	return out
}

func writeDocuments(w http.ResponseWriter, docs []store.Document) {
	out := make([]documentResponse, 0, len(docs))
	for _, d := range docs {
		out = append(out, toDocumentResponse(d))
	}
	writeJSON(w, http.StatusOK, map[string]any{"documents": out})
}

// notFound is the single uniform 404 used for both "no such document" and, in
// hardened mode, "not a member of this org" -- the two must be indistinguishable
// (SR-B2-5).
func notFound(w http.ResponseWriter) {
	writeJSONError(w, http.StatusNotFound, "not found")
}

func internalError(w http.ResponseWriter, err error) {
	log.Printf("api: %v", err)
	writeJSONError(w, http.StatusInternalServerError, "internal error")
}
