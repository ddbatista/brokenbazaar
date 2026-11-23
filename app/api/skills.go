// M4b T3: the skills plane's product routes -- the S5 authorisation
// verbs, the member's index answer, and the skill branches of the M4a
// marketplace verbs (publish, install). Everything here is
// mode-neutral EXCEPT the review payload builder in review_*.go --
// the repo's first route-level mode split, and the inversion is the
// module's thesis: M4a's rule said a route that misbehaved in
// vulnerable mode would blur which gap the findings measure, and that
// is exactly backwards for 09, because 09's gap IS the review surface
// (m4b-skills.md's third derivation: the naive build is spec-faithful
// S3 -- the org reviews a name and a description, and the body
// executes at S8). The naive review route returning the description
// only is not a blurring; it is the finding.
package main

import (
	"log"
	"net/http"

	"github.com/ddbatista/brokenbazaar/app/auth"
	"github.com/ddbatista/brokenbazaar/app/authz"
	"github.com/ddbatista/brokenbazaar/app/skill"
	"github.com/ddbatista/brokenbazaar/app/store"
)

// maxBundleBytes bounds the SKILL.md the publish route will read.
// Mirrors mcp.MaxManifestBytes's shape (SR-B6-7: bounded parsing, one
// cap at the route, the parse's own depth rules behind it).
const maxBundleBytes = 64 << 10

// publishSkill is POST /catalog's type=skill branch: the publisher
// posts the BUNDLE BYTES; the route is the parser's one binding site
// (authz.IsKnownTool -- the vocabulary's one home, T2's cycle rule),
// and the store pins what was parsed. The name in the request must be
// the bundle's own name: the store enforces it, and this route's
// error surfaces it.
func (m *marketplaceHandlers) publishSkill(w http.ResponseWriter, r *http.Request, claims auth.Claims, name, bundle string) {
	if len(bundle) > maxBundleBytes {
		writeJSONError(w, http.StatusBadRequest, "bundle exceeds the 64KB cap")
		return
	}
	idx, err := skill.ParseFrontmatter([]byte(bundle), authz.IsKnownTool)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	pub, ok := m.resolvePublisher(w, r, claims)
	if !ok {
		return
	}
	item, err := m.pubFor(pub.ID).PublishSkillItem(r.Context(), name, []byte(bundle), idx)
	if err != nil {
		log.Printf("publish skill listing for publisher %s: %v", pub.ID, err)
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

// installSkill is the install route's skill branch. Skills have no
// server to dial: the artifact is the listing's posted bytes, already
// parsed at publish; the org consents to exactly those bytes, and the
// route re-parses them to prove the pin and the index agree (the same
// "consent to what discovery returns" rule, with the catalog playing
// discovery's part). A listing whose bytes no longer parse is a
// broken row, fail closed: the org is not offered an install.
func (m *marketplaceHandlers) installSkill(w http.ResponseWriter, r *http.Request, orgID string, claims auth.Claims, detail store.CatalogItemDetail) {
	bundle := []byte(detail.Manifest)
	idx, err := skill.ParseFrontmatter(bundle, authz.IsKnownTool)
	if err != nil {
		log.Printf("install: skill listing %s does not parse: %v", detail.ID, err)
		writeJSONError(w, http.StatusInternalServerError, "the listing's bundle no longer parses; refuse to install what cannot be reviewed")
		return
	}
	ins, err := m.forOrg(orgID).InstallSkillItem(r.Context(), detail.ID, claims.Sub, bundle, idx)
	if err != nil {
		log.Printf("install of skill %s in org %s: %v", detail.ID, orgID, err)
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, ins)
}

// skillIndex serves GET /orgs/{org_id}/skills: the CALLER's authorised
// index (S6) -- every skill this user authorised for their own
// sessions, rendered from the install rows' stored parse,
// precedence-ordered by the store (SR-B9-4). Non-members get the
// uniform 404, the same vocabulary as every org route; a member who
// never authorised anything gets an EMPTY array, not null (the T7
// nil-slice lesson holds on the wire too).
func (m *marketplaceHandlers) skillIndex(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
	orgID := r.PathValue("org_id")
	if _, ok := m.orgMember(w, r, claims, orgID); !ok {
		return
	}
	index, err := m.forOrg(orgID).SkillIndexForUser(r.Context(), claims.Sub)
	if err != nil {
		log.Printf("skill index for org %s: %v", orgID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, index)
}

// authoriseSkill serves POST /orgs/{org_id}/skills/{install_id}/
// authorise -- S5, the member's own trust decision. The actor is the
// caller THEMSELVES: there is no user_id in the request, because a
// member who could authorise for someone else would be an admin plane
// hiding in a member verb. The role gate is member-or-admin: a viewer
// cannot hold a session, so authorising one for their sessions is a
// decision with no effect, and this route refuses to record decisions
// that cannot matter (the honest shape of M4b-N4's bounded surface).
func (m *marketplaceHandlers) authoriseSkill(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
	orgID := r.PathValue("org_id")
	role, ok := m.orgMember(w, r, claims, orgID)
	if !ok {
		return
	}
	if role != store.RoleAdmin && role != store.RoleMember {
		writeJSONError(w, http.StatusForbidden, "viewers cannot authorise skills for their own sessions")
		return
	}
	authRow, err := m.forOrg(orgID).AuthoriseSkill(r.Context(), r.PathValue("install_id"), claims.Sub)
	if err != nil {
		log.Printf("authorise skill %s in org %s by %s: %v", r.PathValue("install_id"), orgID, claims.Sub, err)
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, authRow)
}

// revokeSkillAuthorisation serves DELETE /orgs/{org_id}/skills/
// authorisations/{auth_id}: the caller's own retreat. The store's
// WHERE clauses bind org and user; a revoke that names someone else's
// authorisation simply finds nothing, and nothing is recorded.
func (m *marketplaceHandlers) revokeSkillAuthorisation(w http.ResponseWriter, r *http.Request, claims auth.Claims) {
	orgID := r.PathValue("org_id")
	if _, ok := m.orgMember(w, r, claims, orgID); !ok {
		return
	}
	revoked, err := m.forOrg(orgID).RevokeSkillAuthorisation(r.Context(), r.PathValue("auth_id"), claims.Sub)
	if err != nil {
		log.Printf("revoke authorisation %s in org %s: %v", r.PathValue("auth_id"), orgID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !revoked {
		writeJSONError(w, http.StatusNotFound, "no active authorisation of yours by that id")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// orgMember is the shared in-org gate for the skill routes: the
// uniform 404 for non-members (M3 T3's vocabulary), the role for the
// caller to branch on. Written for the skill routes because
// orgInstallAdmin (the marketplace's) hard-codes the admin-only cell:
// S5 is not the admin's plane, and giving it its own gate keeps D8's
// verb set untouched.
func (m *marketplaceHandlers) orgMember(w http.ResponseWriter, r *http.Request, claims auth.Claims, orgID string) (store.Role, bool) {
	role, ok, err := m.lookup.MembershipRole(r.Context(), orgID, claims.Sub)
	if err != nil {
		log.Printf("membership lookup for org %s: %v", orgID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return "", false
	}
	if !ok {
		// Not a member: the uniform 404, indistinguishable from an
		// unknown org, so this route is not an org probe.
		writeJSONError(w, http.StatusNotFound, "no such org")
		return "", false
	}
	return role, true
}
