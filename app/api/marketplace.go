package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/ddbatista/brokenbazaar/app/auth"
	"github.com/ddbatista/brokenbazaar/app/authz"
	"github.com/ddbatista/brokenbazaar/app/mcp"
	"github.com/ddbatista/brokenbazaar/app/skill"
	"github.com/ddbatista/brokenbazaar/app/store"

	"github.com/jackc/pgx/v5/pgxpool"
)

// M4a T3: the marketplace's product routes -- publisher registration,
// catalog publish/PATCH, and the install verbs. The whole set is
// mode-neutral on purpose: these are DIRECT routes, and M3 D1's rule
// holds here too (the planted bugs live in the agent path, T4; a route
// that misbehaved in vulnerable mode would blur which gap the findings
// measure). The one thing every install verb shares is D8: installs are
// control-plane -- the authz table's install_tool action is admin-only,
// and NO agent tool, grammar rule or internal route exists for any of
// them, in either mode.
type marketplaceHandlers struct {
	lookup membershipLookup // the same interface memberHandlers uses: sub -> role in org
	admin  marketplaceAdmin // platform-plane reads and publisher creation
	pubFor func(publisherID string) publisherStore
	forOrg func(orgID string) installStore
	secret []byte

	// The discovery fetch and the DNS resolution are injected so the
	// route matrix is testable offline (members_test.go's pattern). Both
	// are the API's own outbound behavior -- the platform dialing a
	// publisher endpoint -- and D2's structural half applies to them:
	// they are bounded (SR-B6-7), and the ADDRESS is recorded, never
	// classified (T2 D2: the one range classifier lives in the gateway
	// and runs at dial; a Go port would be the two-homes drift).
	fetchManifest func(endpoint string) ([]byte, error)
	resolveAddr   func(host string) (string, error)
}

// marketplaceAdmin is the platform-plane surface the routes need.
// *store.AdminStore satisfies it; the tests fake it.
type marketplaceAdmin interface {
	RegisterPublisher(ctx context.Context, displayName string) (store.Publisher, error)
	Publisher(ctx context.Context, publisherID string) (store.Publisher, bool, error)
	CatalogItem(ctx context.Context, itemID string) (store.CatalogItemDetail, bool, error)
	CatalogItems(ctx context.Context) ([]store.CatalogItem, error)
}

// publisherStore is the publisher-bound write surface (ForPublisher).
type publisherStore interface {
	PublishItem(ctx context.Context, name, endpointURL string, manifest []byte) (store.CatalogItem, error)
	PublishSkillItem(ctx context.Context, name string, bundle []byte, idx skill.Index) (store.CatalogItem, error)
	UpdateItem(ctx context.Context, itemID string, manifest []byte) (store.CatalogItem, bool, error)
}

// installStore is the org-bound install surface (ForOrg).
type installStore interface {
	InstallItem(ctx context.Context, itemID, endpointURL, endpointAddress string, manifest []byte, installedBy string) (store.Install, error)
	InstallSkillItem(ctx context.Context, itemID, installedBy string, bundle []byte, idx skill.Index) (store.Install, error)
	Uninstall(ctx context.Context, installID, byUser string) (bool, error)
	Reapprove(ctx context.Context, installID string, manifest []byte, byUser string) (store.Install, bool, error)
	Installs(ctx context.Context) ([]store.Install, error)
	Install(ctx context.Context, installID string) (store.Install, bool, error)
	AuthoriseSkill(ctx context.Context, installID, userID string) (store.SkillAuthorisation, error)
	RevokeSkillAuthorisation(ctx context.Context, authID, userID string) (bool, error)
	SkillIndexForUser(ctx context.Context, userID string) ([]store.SkillIndexEntry, error)
}

func newMarketplaceHandlers(admin *store.AdminStore, pool *pgxpool.Pool, secret []byte) *marketplaceHandlers {
	client := &http.Client{Timeout: 5 * time.Second}
	resolver := net.DefaultResolver
	return &marketplaceHandlers{
		lookup: admin,
		admin:  admin,
		pubFor: func(publisherID string) publisherStore { return store.ForPublisher(pool, publisherID) },
		forOrg: func(orgID string) installStore { return store.ForOrg(pool, orgID) },
		secret: secret,

		// The discovery fetch (SR-B6-4's platform half): POST the
		// tools/list request, bounded read. The RESPONSE BODY is the
		// manifest -- envelope included, never extracted (package mcp's
		// doc comment; T2 D1's raw-bytes rule).
		fetchManifest: func(endpoint string) ([]byte, error) { return fetchToolsList(client, endpoint) },

		// Resolution is recorded, not classified. A host that does not
		// resolve fails the install loudly (fail closed).
		resolveAddr: func(host string) (string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			addrs, err := resolver.LookupHost(ctx, host)
			if err != nil {
				return "", err
			}
			if len(addrs) == 0 {
				return "", fmt.Errorf("no addresses for %q", host)
			}
			return addrs[0], nil
		},
	}
}

// fetchToolsList performs the subset's discovery POST against a
// publisher endpoint and returns the raw response body. It is a
// function, not a method, so the gateway-facing contract reads in one
// place: one attempt, no redirect-following beyond the client default,
// and a bounded read (an oversized body is refused by mcp.Parse's size
// leg -- reading to a cap first would duplicate the limit in two
// places).
func fetchToolsList(client *http.Client, endpoint string) ([]byte, error) {
	resp, err := client.Post(endpoint, "application/json", bytes.NewReader(mcp.Request("tools/list")))
	if err != nil {
		return nil, fmt.Errorf("reaching %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered HTTP %d", endpoint, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", endpoint, err)
	}
	return body, nil
}

// registerPublisher serves POST /publishers/register (authNone, by
// design: baseline B6 5.2, open and unvetted -- the product decision
// the module's premise stands on, and the PoC's own front door). A
// plain http.HandlerFunc, the healthz/auth/token shape, because there
// are no claims to receive.
//
// The token carries sub and nothing else (D1: no class claim -- the
// routes resolve sub against the publishers table, and a user token on
// a publisher route is a uniform 404). It is minted clean in BOTH modes:
// there is no vulnerable-mode publisher claim to forge, because there is
// no claim to carry.
func (m *marketplaceHandlers) registerPublisher(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		DisplayName string `json:"display_name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.DisplayName == "" || len(req.DisplayName) > 128 {
		writeJSONError(w, http.StatusBadRequest, "display_name is required (max 128 bytes)")
		return
	}

	ctx := r.Context()
	pub, err := m.admin.RegisterPublisher(ctx, req.DisplayName)
	if err != nil {
		log.Printf("register publisher: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	claims := mintClaims(pub.ID, "", "", true, time.Now())
	token, err := auth.Encode(claims, m.secret)
	if err != nil {
		log.Printf("minting publisher token: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, struct {
		Token     string          `json:"token"`
		ExpiresAt int64           `json:"expires_at"`
		Publisher store.Publisher `json:"publisher"`
	}{Token: token, ExpiresAt: claims.Exp, Publisher: pub})
}

// resolvePublisher resolves claims.Sub against the publishers table.
// found=false answers 404 -- for a publisher that does not exist, and
// for a USER token that reached a publisher route. Same table, same
// answer (D1's resolution-by-table).
func (m *marketplaceHandlers) resolvePublisher(w http.ResponseWriter, r *http.Request, claims auth.Claims) (store.Publisher, bool) {
	pub, found, err := m.admin.Publisher(r.Context(), claims.Sub)
	if err != nil {
		log.Printf("resolving publisher %s: %v", claims.Sub, err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return store.Publisher{}, false
	}
	if !found {
		writeJSONError(w, http.StatusNotFound, "not found")
		return store.Publisher{}, false
	}
	return pub, true
}

// validEndpoint is the STRUCTURAL half of endpoint validation (T2 D2):
// parseable, http, host present. Range classification is not here and
// is not the route's -- the address is recorded at install and
// classified at dial, by the one classifier, in the gateway.
func validEndpoint(raw string) (host string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Hostname() == "" {
		return "", false
	}
	return u.Hostname(), true
}

// publishListing serves POST /catalog: a publisher posts a listing whose
// manifest is the ADVERTISED copy -- what install review will show and
// what a server that behaves will serve. The bytes are stored exactly
// as posted (T2 D1) after mcp.Parse validates the shape and the
// vocabulary (SR-B6-7; D4's "only polices classes ship").
func (m *marketplaceHandlers) publishListing(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
	pub, ok := m.resolvePublisher(w, r, claims)
	if !ok {
		return
	}
	var req struct {
		Name        string `json:"name"`
		EndpointURL string `json:"endpoint_url"`
		Manifest    string `json:"manifest"`
		Type        string `json:"type"`
		Bundle      string `json:"bundle"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, mcp.MaxManifestBytes+4096)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// M4b: type=skill posts the BUNDLE BYTES. The branch dispatch is
	// the only place publish's shape widens: absent type stays the M4a
	// manifest listing, unchanged, so every existing caller and test
	// holds byte-for-byte.
	if req.Type == "skill" {
		if req.Name == "" {
			writeJSONError(w, http.StatusBadRequest, "name is required")
			return
		}
		m.publishSkill(w, r, claims, req.Name, req.Bundle)
		return
	}
	if req.Name == "" || len(req.Name) > 128 {
		writeJSONError(w, http.StatusBadRequest, "name is required (max 128 bytes)")
		return
	}
	if _, ok := validEndpoint(req.EndpointURL); !ok {
		writeJSONError(w, http.StatusBadRequest, "endpoint_url must be an http URL with a host")
		return
	}
	if _, err := mcp.Parse([]byte(req.Manifest)); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	item, err := m.pubFor(pub.ID).PublishItem(r.Context(), req.Name, req.EndpointURL, []byte(req.Manifest))
	if err != nil {
		log.Printf("publish listing for publisher %s: %v", pub.ID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

// updateListing serves PATCH /catalog/{item_id}: the advertised copy
// changes, the mutation is recorded with before and after (SR-B6-8),
// and -- the pin's whole point -- no install moves. A vulnerable
// catalog reader that re-serves this row to installers is finding 08
// (ii)'s shape; this route is the honest product, the same in both
// modes.
func (m *marketplaceHandlers) updateListing(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
	pub, ok := m.resolvePublisher(w, r, claims)
	if !ok {
		return
	}
	itemID := r.PathValue("item_id")
	var req struct {
		Manifest string `json:"manifest"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, mcp.MaxManifestBytes+4096)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if _, err := mcp.Parse([]byte(req.Manifest)); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	item, found, err := m.pubFor(pub.ID).UpdateItem(r.Context(), itemID, []byte(req.Manifest))
	if err != nil {
		// Same-bytes updates are refused by the store (a mutation row
		// that says "same" is a false record); surface them as the
		// caller's error, everything else as ours.
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !found {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

// listCatalog serves GET /catalog: the browse surface, token-authed.
// A publisher token reads it too -- an authenticated principal browsing
// platform-level state; there is no scope to leak.
func (m *marketplaceHandlers) listCatalog(w http.ResponseWriter, r *http.Request, _ auth.Claims) {
	items, err := m.admin.CatalogItems(r.Context())
	if err != nil {
		log.Printf("listing catalog: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, items)
}

// catalogDetail serves GET /catalog/{item_id}: the install decision
// point's payload (SR-B6-6) -- the listing, its publisher, the active
// install count, and the full mutation history (SR-B8-8's visible
// diff). What an org weighs before consenting, in one response.
func (m *marketplaceHandlers) catalogDetail(w http.ResponseWriter, r *http.Request, _ auth.Claims) {
	detail, found, err := m.admin.CatalogItem(r.Context(), r.PathValue("item_id"))
	if err != nil {
		log.Printf("loading catalog item: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !found {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}

	// M4b: a skill listing's review surface is mode-dependent (the
	// repo's first route-level mode split -- skills.go's header states
	// the inversion of M4a's mode-neutrality rule, and why 09's thesis
	// requires it: the naive build's spec-faithful S3 IS the finding).
	if detail.Type == "skill" {
		idx, err := skill.ParseFrontmatter([]byte(detail.Manifest), authz.IsKnownTool)
		if err != nil {
			// The listing's bytes no longer parse: a broken row, fail
			// closed rather than rendered half.
			log.Printf("catalog detail: skill listing %s does not parse: %v", detail.ID, err)
			writeJSONError(w, http.StatusInternalServerError, "the listing's bundle no longer parses")
			return
		}
		writeJSON(w, http.StatusOK, buildSkillReviewPayload(idx, detail))
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

// orgInstallAdmin is the shared gate for every org install verb:
// non-member is the uniform 404, then the authz table's install_tool
// cell (admin-only, D8). The log line says org=, M3 T3's deliberate
// vocabulary: an in-org refusal is not a cross-org probe, and the
// detection side reads it that way.
func (m *marketplaceHandlers) orgInstallAdmin(w http.ResponseWriter, r *http.Request, claims auth.Claims) (string, bool) {
	orgID := r.PathValue("org_id")
	role, found, err := m.lookup.MembershipRole(r.Context(), orgID, claims.Sub)
	if err != nil {
		log.Printf("install route: resolving membership: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return "", false
	}
	if !found {
		writeJSONError(w, http.StatusNotFound, "not found")
		return "", false
	}
	if !authz.Permits(role, authz.InstallTool) {
		log.Printf("403 install route org=%s user=%s role=%s (not admin)", orgID, claims.Sub, role)
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return "", false
	}
	return orgID, true
}

// installItem serves POST /orgs/{org_id}/installs: the consent moment.
// The route fetches the manifest from the server (discovery -- what the
// org is actually consenting to, never the advertised copy), validates
// it, resolves and RECORDS the endpoint address, and pins the fetched
// bytes. The digest is computed inside the store, from exactly these
// bytes. Failures are loud and pin nothing (SR-B6-7).
func (m *marketplaceHandlers) installItem(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
	orgID, ok := m.orgInstallAdmin(w, r, claims)
	if !ok {
		return
	}
	var req struct {
		ItemID string `json:"item_id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || req.ItemID == "" {
		writeJSONError(w, http.StatusBadRequest, "item_id is required")
		return
	}

	ctx := r.Context()
	detail, found, err := m.admin.CatalogItem(ctx, req.ItemID)
	if err != nil {
		log.Printf("install: loading item: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !found {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}

	// M4b: the install verb's skill branch. Skills have no server to
	// dial -- the artifact is the listing's posted bytes -- so the
	// M4a discovery path does not run; the org consents to exactly the
	// bytes the listing carries, re-parsed here so the pin and the
	// index provably agree (skills.go's installSkill).
	if detail.Type == "skill" {
		m.installSkill(w, r, orgID, claims, detail)
		return
	}

	// The org consents to what DISCOVERY returns, not to the listing's
	// advertised copy: the two are expected to agree, and the gap
	// between them is a rug pull (08 (ii)).
	fetched, err := m.fetchManifest(detail.EndpointURL)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "the listing's server did not answer discovery: "+err.Error())
		return
	}
	if _, err := mcp.Parse(fetched); err != nil {
		writeJSONError(w, http.StatusBadGateway, "the listing's server returned an invalid manifest: "+err.Error())
		return
	}
	host, ok := validEndpoint(detail.EndpointURL)
	if !ok {
		// Defensive: the listing was validated at publish; a catalog row
		// that fails here means the table was written around the route.
		writeJSONError(w, http.StatusInternalServerError, "listing endpoint is malformed")
		return
	}
	addr, err := m.resolveAddr(host)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "the listing's endpoint does not resolve: "+err.Error())
		return
	}

	ins, err := m.forOrg(orgID).InstallItem(ctx, detail.ID, detail.EndpointURL, addr, fetched, claims.Sub)
	if err != nil {
		// The composite FK's loud path: a non-member installer, or the
		// partial unique's: an org installing twice what it already
		// holds. Both are the caller's error to see named.
		log.Printf("install of %s in org %s: %v", detail.ID, orgID, err)
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, ins)
}

// listInstalls serves GET /orgs/{org_id}/installs: the org's active
// pins, with the digests and endpoints an admin audited them on.
func (m *marketplaceHandlers) listInstalls(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
	orgID, ok := m.orgInstallAdmin(w, r, claims)
	if !ok {
		return
	}
	installs, err := m.forOrg(orgID).Installs(r.Context())
	if err != nil {
		log.Printf("listing installs in org %s: %v", orgID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, installs)
}

// uninstall serves DELETE /orgs/{org_id}/installs/{install_id}: the
// tombstone (T2 D3). The grant ends; the row and its audit never leave.
func (m *marketplaceHandlers) uninstall(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
	orgID, ok := m.orgInstallAdmin(w, r, claims)
	if !ok {
		return
	}
	removed, err := m.forOrg(orgID).Uninstall(r.Context(), r.PathValue("install_id"), claims.Sub)
	if err != nil {
		log.Printf("uninstall in org %s: %v", orgID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !removed {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// reapprove serves POST /orgs/{org_id}/installs/{install_id}/reapprove:
// the admin's answer to drift. It takes no manifest in the body -- the
// re-consent is to what the server CURRENTLY serves (T2's store
// contract), fetched here, validated, and pinned as the new bytes.
func (m *marketplaceHandlers) reapprove(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
	orgID, ok := m.orgInstallAdmin(w, r, claims)
	if !ok {
		return
	}
	installID := r.PathValue("install_id")
	ctx := r.Context()
	ins, found, err := m.forOrg(orgID).Install(ctx, installID)
	if err != nil {
		log.Printf("reapprove: loading install: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !found {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	fetched, err := m.fetchManifest(ins.EndpointURL)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "the installed server did not answer discovery: "+err.Error())
		return
	}
	if _, err := mcp.Parse(fetched); err != nil {
		writeJSONError(w, http.StatusBadGateway, "the installed server returned an invalid manifest: "+err.Error())
		return
	}
	updated, found, err := m.forOrg(orgID).Reapprove(ctx, installID, fetched, claims.Sub)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !found {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, updated)
}
