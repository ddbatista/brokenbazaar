package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ddbatista/brokenbazaar/app/skill"
)

// ManifestDigest is the pin's hash: sha256 over the RAW manifest bytes,
// exactly as fetched, never over a re-serialized form (migration 004's
// opening comment). One home, here in the store -- callers pass bytes,
// never a digest they computed themselves, so no row can carry a digest
// that disagrees with its bytes.
//
// CROSS-LANGUAGE CONTRACT (T5's gateway holds the other half): the
// gateway re-fetches a publisher's manifest and compares
// hashlib.sha256(fetched_bytes).hexdigest() against installs.
// pinned_digest. No canonicalization on either side -- the fixture
// serves static bytes, and any server that re-serializes between fetches
// reads as drift, which is the honest failure direction (m4a M4a-N2:
// unreachable reads as drift, never as verified). The shared test
// vector is TestManifestDigestVector in install_test.go; the gateway's
// Python test must produce the same hex from the same bytes.
func ManifestDigest(manifest []byte) string {
	sum := sha256.Sum256(manifest)
	return hex.EncodeToString(sum[:])
}

// Install is one org's consent decision, org-scoped tenant data (m4a D3).
// The pinned fields ARE the pin: raw manifest bytes, their digest, the
// endpoint as the listing advertised it, and the address that endpoint
// resolved to at install time (recorded, not classified -- the one range
// classifier lives in the gateway; migration 004). Status is active or
// uninstalled: drift is computed per call by the gateway, not stored
// here, and re-approval writes a fresh pin on the same row.
type Install struct {
	ID              string
	OrgID           string
	ItemID          string
	InstalledBy     string
	InstalledAt     time.Time
	PinnedManifest  string
	PinnedDigest    string
	EndpointURL     string
	EndpointAddress string
	Status          string
	// ItemType is the artifact kind copied at install (migration 005):
	// the org's record of WHAT they installed, read back without a
	// join, exactly as EndpointURL is the record of where an MCP server
	// answered. SkillIndex is the parse of the pinned bytes, stored
	// beside the pin at install and recomputed only when the pin
	// advances -- nil for MCP installs.
	ItemType   string
	SkillIndex *skill.Index
}

// InstallChange is one row of the install plane's immutable audit
// (SR-B8-7). Before/After carry the raw manifest bytes the grant covered,
// or "" where the CHECK requires NULL (before for installed, after for
// uninstalled). Actor is always a user: no agent path to any install verb
// exists (D8), which is why there is no session column anywhere in this
// plane -- the absence is the control's shadow.
type InstallChange struct {
	ID        string
	InstallID string
	OrgID     string
	ActorUser string
	Mutation  string
	Before    string
	After     string
	CreatedAt time.Time
}

// InstallItem records an org's install and its audit row in ONE
// transaction, on the org-bound handle (M3-N1's acceptance shape applied
// to the new plane: never AdminStore, never the raw pool).
//
// manifest is the bytes FETCHED FROM THE SERVER at install time, not the
// listing's advertised copy -- the org consents to what discovery
// returned, and the drift check compares exactly these bytes against
// the server's later answers (D3: the install row is the pin). The digest
// is computed here from those bytes; the caller never supplies it.
//
// Authorization is the caller's, as with every ForOrg method: the
// composite foreign key (org_id, installed_by) -> memberships is the
// integrity backstop -- a caller that forgets the admin check gets a
// loud constraint error for a non-member installer, never a silently
// inconsistent row.
func (s *OrgStore) InstallItem(ctx context.Context, itemID, endpointURL, endpointAddress string, manifest []byte, installedBy string) (Install, error) {
	ins := Install{
		ID:              NewID(),
		OrgID:           s.orgID, // never taken from the caller
		ItemID:          itemID,
		InstalledBy:     installedBy,
		PinnedManifest:  string(manifest),
		PinnedDigest:    ManifestDigest(manifest),
		EndpointURL:     endpointURL,
		EndpointAddress: endpointAddress,
		Status:          "active",
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Install{}, fmt.Errorf("store: beginning install of %s in org %s: %w", itemID, s.orgID, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	err = tx.QueryRow(ctx,
		`INSERT INTO installs (id, org_id, item_id, installed_by, pinned_manifest, pinned_digest, endpoint_url, endpoint_address)
		 VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6, $7, $8)
		 RETURNING installed_at`,
		ins.ID, s.orgID, itemID, installedBy, ins.PinnedManifest, ins.PinnedDigest, endpointURL, endpointAddress,
	).Scan(&ins.InstalledAt)
	if err != nil {
		return Install{}, fmt.Errorf("store: installing %s in org %s: %w", itemID, s.orgID, err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO install_changes (id, install_id, org_id, actor_user, mutation, before, after)
		 VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'installed', NULL, $5)`,
		NewID(), ins.ID, s.orgID, installedBy, ins.PinnedManifest,
	); err != nil {
		return Install{}, fmt.Errorf("store: recording install of %s in org %s: %w", itemID, s.orgID, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return Install{}, fmt.Errorf("store: committing install of %s in org %s: %w", itemID, s.orgID, err)
	}
	return ins, nil
}

// Uninstall tombstones an active install and records what it granted, in
// one transaction. No row is ever deleted: the install's audit must
// outlive the install (M3-N3's rule), and the tombstone is what lets a
// reinstall be a NEW grant rather than a resumed one -- SR-B8-8's "never
// resumed" is structural here, the partial unique index clears the way
// only for a row that pins the bytes fetched at THAT moment.
//
// found=false covers an id that is not this org's, already uninstalled,
// or nonexistent -- the same indistinguishability everywhere else.
func (s *OrgStore) Uninstall(ctx context.Context, installID, byUser string) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("store: beginning uninstall in org %s: %w", s.orgID, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var pinned string
	err = tx.QueryRow(ctx,
		`UPDATE installs
		 SET status = 'uninstalled'
		 WHERE id = $1::uuid AND org_id = $2::uuid AND status = 'active'
		 RETURNING pinned_manifest`,
		installID, s.orgID,
	).Scan(&pinned)
	if err != nil {
		if isNoRows(err) {
			return false, nil
		}
		return false, fmt.Errorf("store: uninstalling %s in org %s: %w", installID, s.orgID, err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO install_changes (id, install_id, org_id, actor_user, mutation, before, after)
		 VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'uninstalled', $5, NULL)`,
		NewID(), installID, s.orgID, byUser, pinned,
	); err != nil {
		return false, fmt.Errorf("store: recording uninstall of %s in org %s: %w", installID, s.orgID, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("store: committing uninstall in org %s: %w", s.orgID, err)
	}
	return true, nil
}

// Reapprove advances an active install's pin to new bytes an admin has
// accepted, recording before and after, in one transaction. This is the
// ONLY method in the package that writes pinned_manifest after the
// install -- the one widening path, and it is an explicit, audited,
// admin-initiated decision (SR-B8-7; m4a D3). Identical bytes are
// refused: a re-approval that pins what is already pinned is a no-op
// wearing audit's clothes (the role_changes precedent).
//
// The new manifest's bytes are, like the install's, the ones fetched from
// the server now -- re-approval is re-consent to what the server CURRENTLY
// serves, which is the product's honest answer to a drift an org decided
// to accept.
func (s *OrgStore) Reapprove(ctx context.Context, installID string, manifest []byte, byUser string) (Install, bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Install{}, false, fmt.Errorf("store: beginning reapproval in org %s: %w", s.orgID, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var ins Install
	var before string
	err = tx.QueryRow(ctx,
		`SELECT id::text, item_id::text, endpoint_url, endpoint_address, pinned_manifest
		 FROM installs
		 WHERE id = $1::uuid AND org_id = $2::uuid AND status = 'active'
		 FOR UPDATE`,
		installID, s.orgID,
	).Scan(&ins.ID, &ins.ItemID, &ins.EndpointURL, &ins.EndpointAddress, &before)
	if err != nil {
		if isNoRows(err) {
			return Install{}, false, nil
		}
		return Install{}, false, fmt.Errorf("store: loading install %s in org %s: %w", installID, s.orgID, err)
	}
	if before == string(manifest) {
		return Install{}, false, fmt.Errorf("store: reapproval of %s carries identical bytes; nothing to record", installID)
	}

	ins.OrgID = s.orgID
	ins.PinnedManifest = string(manifest)
	ins.PinnedDigest = ManifestDigest(manifest)
	ins.Status = "active"

	if _, err := tx.Exec(ctx,
		`UPDATE installs
		 SET pinned_manifest = $3, pinned_digest = $4
		 WHERE id = $1::uuid AND org_id = $2::uuid`,
		installID, s.orgID, ins.PinnedManifest, ins.PinnedDigest,
	); err != nil {
		return Install{}, false, fmt.Errorf("store: reapproving %s in org %s: %w", installID, s.orgID, err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO install_changes (id, install_id, org_id, actor_user, mutation, before, after)
		 VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'reapproved', $5, $6)`,
		NewID(), installID, s.orgID, byUser, before, ins.PinnedManifest,
	); err != nil {
		return Install{}, false, fmt.Errorf("store: recording reapproval of %s in org %s: %w", installID, s.orgID, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return Install{}, false, fmt.Errorf("store: committing reapproval in org %s: %w", s.orgID, err)
	}
	return ins, true, nil
}

// Installs lists this org's active installs -- the pins the agent's
// catalog and the gateway's mediation read (T4 and T5's read model, in
// stable order for deterministic assembly).
func (s *OrgStore) Installs(ctx context.Context) ([]Install, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id::text, org_id::text, item_id::text, installed_by::text, installed_at,
		        pinned_manifest, pinned_digest, endpoint_url, endpoint_address, status
		 FROM installs
		 WHERE org_id = $1::uuid AND status = 'active'
		 ORDER BY installed_at, id`,
		s.orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("store: listing installs in org %s: %w", s.orgID, err)
	}
	defer rows.Close()

	var out []Install
	for rows.Next() {
		var ins Install
		if err := rows.Scan(&ins.ID, &ins.OrgID, &ins.ItemID, &ins.InstalledBy, &ins.InstalledAt,
			&ins.PinnedManifest, &ins.PinnedDigest, &ins.EndpointURL, &ins.EndpointAddress, &ins.Status); err != nil {
			return nil, fmt.Errorf("store: reading installs in org %s: %w", s.orgID, err)
		}
		out = append(out, ins)
	}
	return out, rows.Err()
}

// Install loads one of this org's installs by id. Both predicates in one
// statement, tombstones included: reading what an org USED to have
// granted is legitimate history, and the uninstall row in install_changes
// is the authoritative record of it ending.
func (s *OrgStore) Install(ctx context.Context, installID string) (Install, bool, error) {
	var ins Install
	err := s.pool.QueryRow(ctx,
		`SELECT id::text, org_id::text, item_id::text, installed_by::text, installed_at,
		        pinned_manifest, pinned_digest, endpoint_url, endpoint_address, status
		 FROM installs
		 WHERE id = $1::uuid AND org_id = $2::uuid`,
		installID, s.orgID,
	).Scan(&ins.ID, &ins.OrgID, &ins.ItemID, &ins.InstalledBy, &ins.InstalledAt,
		&ins.PinnedManifest, &ins.PinnedDigest, &ins.EndpointURL, &ins.EndpointAddress, &ins.Status)
	if err != nil {
		if isNoRows(err) {
			return Install{}, false, nil
		}
		return Install{}, false, fmt.Errorf("store: loading install %s in org %s: %w", installID, s.orgID, err)
	}
	return ins, true, nil
}

// InstallChanges is the install's immutable history, oldest first
// (SR-B8-8's "the diff is visible to orgs that installed it" -- the
// store half; the route exposes it, detection reads it).
func (s *OrgStore) InstallChanges(ctx context.Context, installID string) ([]InstallChange, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id::text, install_id::text, org_id::text, actor_user::text, mutation,
		        COALESCE(before, '') AS before, COALESCE(after, '') AS after, created_at
		 FROM install_changes
		 WHERE install_id = $1::uuid AND org_id = $2::uuid
		 ORDER BY created_at, id`,
		installID, s.orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("store: listing changes for install %s in org %s: %w", installID, s.orgID, err)
	}
	defer rows.Close()

	var out []InstallChange
	for rows.Next() {
		var c InstallChange
		if err := rows.Scan(&c.ID, &c.InstallID, &c.OrgID, &c.ActorUser, &c.Mutation, &c.Before, &c.After, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: reading changes for install %s in org %s: %w", installID, s.orgID, err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
