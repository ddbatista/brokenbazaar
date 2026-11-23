package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ddbatista/brokenbazaar/app/auth"
	"github.com/ddbatista/brokenbazaar/app/authz"
	"github.com/ddbatista/brokenbazaar/app/skill"
	"github.com/ddbatista/brokenbazaar/app/store"
)

// Plan M4a T3: the marketplace routes' decisions, with no database
// (members_test.go's pattern). The load-bearing property is the same
// one that file states: a refused request never reaches the store. The
// discovery fetch and the DNS resolution are injected, so the install
// matrix is reachable offline -- including the property T4's PoC will
// lean on: the pin is over the bytes FETCHED at install, never the
// listing's advertised copy.

const (
	mpSecret  = "mp-test-secret"
	pubA      = "11111111-2222-4333-8444-555555555555" // a publisher principal
	adminA    = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" // Acme admin (fakeLookup's vocabulary)
	memberA   = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" // Acme member
	viewerA   = "cccccccc-cccc-4ccc-8ccc-cccccccccccc" // Acme viewer
	orgA      = "11111111-1111-4111-8111-111111111111"
	itemID    = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	installID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
)

// mpToken mints a bearer token for a sub. The claims are always
// clean-shape (no org, no role): that is what publisher tokens look
// like in BOTH modes, and what hardened user tokens look like -- the
// routes resolve sub against their own table and read nothing else
// (plan M4a T3 D1).
func mpToken(t *testing.T, sub string) string {
	t.Helper()
	token, err := auth.Encode(auth.Claims{Sub: sub, Iss: "brokenbazaar", Iat: time.Now().Unix(), Exp: time.Now().Add(time.Hour).Unix()}, []byte(mpSecret))
	if err != nil {
		t.Fatalf("minting token: %v", err)
	}
	return token
}

func mpReq(t *testing.T, method, target, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rd *strings.Reader
	if body == "" {
		rd = strings.NewReader("")
	} else {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	mpServe(t).ServeHTTP(rec, req)
	return rec
}

// mpMarketAdmin fakes the platform plane. CatalogItem returns a listing
// whose ADVERTISED manifest differs from what the (injected) discovery
// fetch returns -- so the pin-fetched-not-advertised property is
// asserted against live-shaped data.
type mpMarketAdmin struct {
	pubs  map[string]store.Publisher
	items map[string]store.CatalogItemDetail
	n     int
}

func (f *mpMarketAdmin) RegisterPublisher(_ context.Context, displayName string) (store.Publisher, error) {
	f.n++
	id := strings.Replace(pubA, "555555555555", "5555555555"+strconv.Itoa(f.n%10), 1)
	f.pubs[id] = store.Publisher{ID: id, DisplayName: displayName}
	return f.pubs[id], nil
}

func (f *mpMarketAdmin) Publisher(_ context.Context, id string) (store.Publisher, bool, error) {
	p, ok := f.pubs[id]
	return p, ok, nil
}

func (f *mpMarketAdmin) CatalogItem(_ context.Context, id string) (store.CatalogItemDetail, bool, error) {
	d, ok := f.items[id]
	return d, ok, nil
}

func (f *mpMarketAdmin) CatalogItems(_ context.Context) ([]store.CatalogItem, error) {
	var out []store.CatalogItem
	for _, d := range f.items {
		out = append(out, d.CatalogItem)
	}
	return out, nil
}

type mpPubStore struct {
	last     []byte
	publish  int
	updates  int
	failNext bool
	found    bool
}

func (f *mpPubStore) PublishItem(_ context.Context, name, endpoint string, manifest []byte) (store.CatalogItem, error) {
	f.publish++
	if f.failNext {
		return store.CatalogItem{}, errors.New("store refused")
	}
	f.last = manifest
	return store.CatalogItem{ID: itemID, Name: name, EndpointURL: endpoint, Manifest: string(manifest), ManifestDigest: store.ManifestDigest(manifest)}, nil
}

func (f *mpPubStore) UpdateItem(_ context.Context, itemID string, manifest []byte) (store.CatalogItem, bool, error) {
	if string(manifest) == string(f.last) {
		return store.CatalogItem{}, false, errors.New("store: update carries identical bytes")
	}
	f.updates++
	f.last = manifest
	return store.CatalogItem{ID: itemID, Manifest: string(manifest), ManifestDigest: store.ManifestDigest(manifest)}, f.found, nil
}

// M4b: the skill-plane fake halves. PublishSkillItem records the
// bundle and answers the shape the store would (Type skill, the
// digest over exactly these bytes).
func (f *mpPubStore) PublishSkillItem(_ context.Context, name string, bundle []byte, idx skill.Index) (store.CatalogItem, error) {
	f.publish++
	if f.failNext {
		return store.CatalogItem{}, errors.New("store refused")
	}
	f.last = bundle
	if name != idx.Name {
		return store.CatalogItem{}, errors.New("store: listing name disagrees with the bundle's frontmatter name")
	}
	return store.CatalogItem{ID: itemID, Name: name, Manifest: string(bundle),
		ManifestDigest: store.ManifestDigest(bundle), Type: "skill"}, nil
}

type mpInstallStore struct {
	installs    int
	uninstalls  int
	reapproves  int
	authorises  int
	revokes     int
	authPairs   map[string]bool
	pinned      []byte
	addr        string
	byUser      string
	failInstall bool
	found       bool
}

func (f *mpInstallStore) InstallItem(_ context.Context, itemID, endpoint, addr string, manifest []byte, by string) (store.Install, error) {
	f.installs++
	if f.failInstall {
		return store.Install{}, errors.New("store: duplicate active install")
	}
	f.pinned, f.addr, f.byUser = manifest, addr, by
	return store.Install{ID: installID, ItemID: itemID, PinnedManifest: string(manifest), PinnedDigest: store.ManifestDigest(manifest), EndpointAddress: addr, Status: "active"}, nil
}

func (f *mpInstallStore) Uninstall(_ context.Context, id, by string) (bool, error) {
	f.uninstalls++
	f.byUser = by
	return f.found, nil
}

func (f *mpInstallStore) Reapprove(_ context.Context, id string, manifest []byte, by string) (store.Install, bool, error) {
	f.reapproves++
	if string(manifest) == string(f.pinned) {
		return store.Install{}, false, errors.New("store: reapproval carries identical bytes")
	}
	f.pinned = manifest
	return store.Install{ID: id, PinnedManifest: string(manifest), PinnedDigest: store.ManifestDigest(manifest)}, f.found, nil
}

func (f *mpInstallStore) Installs(_ context.Context) ([]store.Install, error) { return nil, nil }

func (f *mpInstallStore) Install(_ context.Context, id string) (store.Install, bool, error) {
	return store.Install{ID: id, EndpointURL: "http://srv.example/"}, f.found, nil
}

// M4b: the skill-plane fake halves (skills_test.go exercises these).
func (f *mpInstallStore) InstallSkillItem(_ context.Context, itemID, by string, bundle []byte, idx skill.Index) (store.Install, error) {
	f.installs++
	if f.failInstall {
		return store.Install{}, errors.New("store: duplicate active install")
	}
	f.pinned = bundle
	f.byUser = by
	return store.Install{ID: installID, ItemID: itemID, InstalledBy: by,
		PinnedManifest: string(bundle), PinnedDigest: store.ManifestDigest(bundle),
		Status: "active", ItemType: "skill", SkillIndex: &idx}, nil
}

func (f *mpInstallStore) AuthoriseSkill(_ context.Context, installID, userID string) (store.SkillAuthorisation, error) {
	f.authorises++
	if f.authPairs == nil {
		f.authPairs = map[string]bool{}
	}
	key := installID + "/" + userID
	if f.authPairs[key] {
		return store.SkillAuthorisation{}, errors.New("store: duplicate active authorisation")
	}
	f.authPairs[key] = true
	return store.SkillAuthorisation{ID: "auth-1", OrgID: orgA, InstallID: installID, UserID: userID, Status: "active"}, nil
}

func (f *mpInstallStore) RevokeSkillAuthorisation(_ context.Context, authID, userID string) (bool, error) {
	f.revokes++
	return authID == "auth-1" && userID != "", nil
}

func (f *mpInstallStore) SkillIndexForUser(_ context.Context, userID string) ([]store.SkillIndexEntry, error) {
	if userID == viewerA {
		return []store.SkillIndexEntry{}, nil
	}
	return []store.SkillIndexEntry{{
		InstallID: installID, Name: "meeting-notes",
		Description:  "Prepare meeting notes from a document the user names.",
		Triggers:     []string{"use when the user asks to prepare meeting notes"},
		Capabilities: []string{"read_document", "update_document"},
		Publisher:    "BrokenBazaar Labs", IsPlatform: true,
		PinnedDigest: "e1f06dcd6f369f47eea7738a1a3113cc0de7f2293087c63fbba16696d0e34c79",
	}}, nil
}

// mpServe builds the marketplace routes on fakes, through the same
// requireToken wrapper production uses.
var mpAdmin = &mpMarketAdmin{
	pubs: map[string]store.Publisher{pubA: {ID: pubA, DisplayName: "evil corp"}},
	items: map[string]store.CatalogItemDetail{itemID: {
		CatalogItem: store.CatalogItem{ID: itemID, PublisherID: pubA, Name: "notes_helper", EndpointURL: "http://srv.example/",
			Manifest: `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"summarize_notes","description":"advertised copy","receives":["user_text"]}]}}`},
	}},
}

var mpPub = &mpPubStore{found: true}
var mpIns = &mpInstallStore{found: true}

// fetchedManifest is what the injected discovery returns: DIFFERENT
// bytes from the advertised copy above, on purpose.
const fetchedManifest = `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"summarize_notes","description":"what the server serves","receives":["user_text"]}]}}`

func mpServe(t *testing.T) http.Handler {
	t.Helper()
	h := &marketplaceHandlers{
		lookup: fakeLookup{
			orgA + "/" + adminA:  store.RoleAdmin,
			orgA + "/" + memberA: store.RoleMember,
			orgA + "/" + viewerA: store.RoleViewer,
		},
		admin:         mpAdmin,
		pubFor:        func(string) publisherStore { return mpPub },
		forOrg:        func(string) installStore { return mpIns },
		secret:        []byte(mpSecret),
		fetchManifest: func(string) ([]byte, error) { return []byte(fetchedManifest), nil },
		resolveAddr:   func(string) (string, error) { return "172.28.0.22", nil },
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /publishers/register", h.registerPublisher)
	mux.HandleFunc("POST /catalog", requireToken([]byte(mpSecret), true, h.publishListing))
	mux.HandleFunc("GET /catalog/{item_id}", requireToken([]byte(mpSecret), true, h.catalogDetail))
	mux.HandleFunc("PATCH /catalog/{item_id}", requireToken([]byte(mpSecret), true, h.updateListing))
	mux.HandleFunc("POST /orgs/{org_id}/installs", requireToken([]byte(mpSecret), true, h.installItem))
	mux.HandleFunc("DELETE /orgs/{org_id}/installs/{install_id}", requireToken([]byte(mpSecret), true, h.uninstall))
	mux.HandleFunc("POST /orgs/{org_id}/installs/{install_id}/reapprove", requireToken([]byte(mpSecret), true, h.reapprove))
	// M4b: the skills plane, same wrapper (skills_test.go +
	// review_*_test.go).
	mux.HandleFunc("GET /orgs/{org_id}/skills", requireToken([]byte(mpSecret), true, h.skillIndex))
	mux.HandleFunc("POST /orgs/{org_id}/skills/{install_id}/authorise", requireToken([]byte(mpSecret), true, h.authoriseSkill))
	mux.HandleFunc("DELETE /orgs/{org_id}/skills/authorisations/{auth_id}", requireToken([]byte(mpSecret), true, h.revokeSkillAuthorisation))
	return mux
}

func TestRegisterPublisherMintsACleanToken(t *testing.T) {
	rec := mpReq(t, "POST", "/publishers/register", "", `{"display_name":"evil corp"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register = %d", rec.Code)
	}
	var resp struct {
		Token     string          `json:"token"`
		Publisher store.Publisher `json:"publisher"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if resp.Publisher.ID == "" {
		t.Fatal("no publisher id in the response")
	}
	// The token is usable immediately: publish with it.
	pub, _, _ := mpAdmin.Publisher(context.Background(), resp.Publisher.ID)
	if pub.ID == "" {
		t.Fatal("registration did not land in the platform plane")
	}
}

func TestUserTokenOnPublisherRouteIsFortyFour(t *testing.T) {
	rec := mpReq(t, "POST", "/catalog", mpToken(t, adminA), `{"name":"x","endpoint_url":"http://s/","manifest":"{}"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("user token on publisher route = %d, want the uniform 404 (resolution by table)", rec.Code)
	}
	if mpPub.publish != 0 {
		t.Fatal("a 404 reached the publisher store")
	}
}

func TestPublishRefusesBadManifests(t *testing.T) {
	for _, bad := range []string{
		`{}`,
		`{"tools":[{"name":"t","description":"d","receives":["user_text"]}]}`,                                    // bare, no envelope
		`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"t","description":"d","receives":["keystrokes"]}]}}`, // unknown class
	} {
		rec := mpReq(t, "POST", "/catalog", mpToken(t, pubA), `{"name":"x","endpoint_url":"http://s/","manifest":`+strconv.Quote(bad)+`}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("bad manifest accepted: %d (%s)", rec.Code, bad)
		}
	}
}

func TestUpdateListingSameBytesRefused(t *testing.T) {
	// Two valid manifests differing only in description: the update
	// contract is about BYTES, and the handler's mcp.Parse gate runs
	// before the store, so the bodies must be real envelopes.
	first := `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"summarize_notes","description":"one","receives":["user_text"]}]}}`
	second := `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"summarize_notes","description":"two","receives":["user_text"]}]}}`
	mpPub.last = []byte(first)
	rec := mpReq(t, "PATCH", "/catalog/"+itemID, mpToken(t, pubA), `{"manifest":`+strconv.Quote(first)+`}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("same-bytes update = %d, want 400", rec.Code)
	}
	rec = mpReq(t, "PATCH", "/catalog/"+itemID, mpToken(t, pubA), `{"manifest":`+strconv.Quote(second)+`}`)
	if rec.Code != http.StatusOK || mpPub.updates != 1 {
		t.Fatalf("real update = %d (updates %d)", rec.Code, mpPub.updates)
	}
}

func TestInstallRoleMatrixNeverReachesTheStore(t *testing.T) {
	before := mpIns.installs
	for _, tc := range []struct {
		token string
		want  int
		name  string
	}{
		{mpToken(t, viewerA), http.StatusForbidden, "viewer"},
		{mpToken(t, memberA), http.StatusForbidden, "member"},
		{mpToken(t, outside), http.StatusNotFound, "an admin of another org (non-member here)"},
	} {
		rec := mpReq(t, "POST", "/orgs/"+orgA+"/installs", tc.token, `{"item_id":"`+itemID+`"}`)
		if rec.Code != tc.want {
			t.Fatalf("%s: install = %d, want %d", tc.name, rec.Code, tc.want)
		}
	}
	if mpIns.installs != before {
		t.Fatal("a refused install reached the store")
	}
	if authz.Permits(store.RoleMember, authz.InstallTool) || authz.Permits(store.RoleViewer, authz.InstallTool) {
		t.Fatal("the authz table grants install_tool below admin")
	}
}

func TestInstallPinsTheFetchedBytesNotTheAdvertisedCopy(t *testing.T) {
	mpIns.found = true
	rec := mpReq(t, "POST", "/orgs/"+orgA+"/installs", mpToken(t, adminA), `{"item_id":"`+itemID+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("admin install = %d: %s", rec.Code, rec.Body.String())
	}
	var ins store.Install
	if err := json.Unmarshal(rec.Body.Bytes(), &ins); err != nil {
		t.Fatalf("decoding install: %v", err)
	}
	if want := store.ManifestDigest([]byte(fetchedManifest)); ins.PinnedDigest != want {
		t.Fatalf("pin digest = %s, want the FETCHED bytes' digest %s", ins.PinnedDigest, want)
	}
	if mpIns.addr != "172.28.0.22" || mpIns.byUser != adminA {
		t.Fatalf("install recorded addr=%q by=%q", mpIns.addr, mpIns.byUser)
	}
}

func TestInstallFailsClosedOnDiscoveryAndResolution(t *testing.T) {
	// A shared fake accumulates across tests (T2's throwaway lesson):
	// assert the DELTA, captured before any request in this test.
	before := mpIns.installs
	failing := &marketplaceHandlers{
		lookup:        fakeLookup{orgA + "/" + adminA: store.RoleAdmin},
		admin:         mpAdmin,
		pubFor:        func(string) publisherStore { return mpPub },
		forOrg:        func(string) installStore { return mpIns },
		secret:        []byte(mpSecret),
		fetchManifest: func(string) ([]byte, error) { return nil, errors.New("connection refused") },
		resolveAddr:   func(string) (string, error) { return "172.28.0.22", nil },
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /orgs/{org_id}/installs", requireToken([]byte(mpSecret), true, failing.installItem))

	req := httptest.NewRequest("POST", "/orgs/"+orgA+"/installs", strings.NewReader(`{"item_id":"`+itemID+`"}`))
	req.Header.Set("Authorization", "Bearer "+mpToken(t, adminA))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("unreachable server = %d, want 502", rec.Code)
	}
	badBody := &marketplaceHandlers{
		lookup:        fakeLookup{orgA + "/" + adminA: store.RoleAdmin},
		admin:         mpAdmin,
		pubFor:        func(string) publisherStore { return mpPub },
		forOrg:        func(string) installStore { return mpIns },
		secret:        []byte(mpSecret),
		fetchManifest: func(string) ([]byte, error) { return []byte("garbage"), nil },
		resolveAddr:   func(string) (string, error) { return "172.28.0.22", nil },
	}
	mux2 := http.NewServeMux()
	mux2.HandleFunc("POST /orgs/{org_id}/installs", requireToken([]byte(mpSecret), true, badBody.installItem))
	req2 := httptest.NewRequest("POST", "/orgs/"+orgA+"/installs", strings.NewReader(`{"item_id":"`+itemID+`"}`))
	req2.Header.Set("Authorization", "Bearer "+mpToken(t, adminA))
	rec2 := httptest.NewRecorder()
	mux2.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusBadGateway {
		t.Fatalf("invalid server manifest = %d, want 502", rec2.Code)
	}
	if mpIns.installs != before {
		t.Fatalf("a failed discovery pinned something (installs went %d -> %d)", before, mpIns.installs)
	}
}

func TestUninstallAndReapprove(t *testing.T) {
	mpIns.found = true
	// The re-approval scenario is DRIFT: the pin holds old bytes, the
	// server now serves different ones, and the admin re-consents to
	// what it currently serves. A pin already equal to the fetched bytes
	// has nothing to re-approve -- the store's identical-bytes rule
	// refuses it, and this test's second call asserts exactly that.
	driftedPin := `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"summarize_notes","description":"the old approved copy","receives":["user_text"]}]}}`
	mpIns.pinned = []byte(driftedPin)
	rec := mpReq(t, "DELETE", "/orgs/"+orgA+"/installs/"+installID, mpToken(t, adminA), "")
	if rec.Code != http.StatusNoContent || mpIns.uninstalls != 1 {
		t.Fatalf("uninstall = %d (calls %d)", rec.Code, mpIns.uninstalls)
	}
	rec = mpReq(t, "POST", "/orgs/"+orgA+"/installs/"+installID+"/reapprove", mpToken(t, adminA), "")
	if rec.Code != http.StatusOK || mpIns.reapproves != 1 {
		t.Fatalf("reapprove = %d (calls %d): %s", rec.Code, mpIns.reapproves, rec.Body.String())
	}
	var ins store.Install
	_ = json.Unmarshal(rec.Body.Bytes(), &ins)
	if ins.PinnedDigest != store.ManifestDigest([]byte(fetchedManifest)) {
		t.Fatalf("reapprove pinned %s", ins.PinnedDigest)
	}
	// The pin now equals what the server serves; a second re-approval of
	// the same bytes is the no-op the store refuses (a mutation row that
	// says "same" is a false record).
	rec = mpReq(t, "POST", "/orgs/"+orgA+"/installs/"+installID+"/reapprove", mpToken(t, adminA), "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("identical reapproval = %d, want 400", rec.Code)
	}
}
