// Package store -- the skills plane (M4b, migration 005). The parse
// lives at the api layer exactly as mcp.Parse did for manifests (one
// parser, called by the route; the store receives bytes plus the
// already-validated skill.Index and pins them). The store never imports
// authz: the capability vocabulary's one home is authz.ActionFor, and
// the route binds it -- a copied list here would be the two-homes drift
// this repo argues against.
package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ddbatista/brokenbazaar/app/skill"
)

// SkillIndexEntry is one row of the S6 answer: the index a session's
// agent reads. It renders from the install row's stored parse (the
// skill_index jsonb), never from a live re-parse, so the description
// here is byte-identical to the one the admin reviewed at S3
// (SR-B9-13, by construction). IsPlatform carries SR-B9-4's precedence
// value: platform > reviewed > third-party, computed from the
// PUBLISHER row (the platform decides who is first-party), and the
// ordering of the whole answer is that precedence, then install time,
// then name -- deterministic and attributable, never the model's
// discretion.
type SkillIndexEntry struct {
	InstallID    string
	Name         string
	Description  string
	Triggers     []string
	Capabilities []string
	References   []string
	Publisher    string
	IsPlatform   bool
	PinnedDigest string
}

// SkillAuthorisation is one member's S5 decision: an already-installed
// skill, authorised for THEIR sessions. The admin's install review
// remains the only entry to the org's index (SR-B9-10); this row narrows
// whose sessions see it at all.
type SkillAuthorisation struct {
	ID           string
	OrgID        string
	InstallID    string
	UserID       string
	Status       string
	AuthorisedAt int64 // unix: the store is a data layer; time formatting is the api's
}

// PublishSkillItem posts a SKILL bundle as a type='skill' listing and
// records the publish as the first catalog mutation, one transaction
// (publisher.go's PublishItem shape). bundle is the RAW bytes; idx is
// the route's validated parse of exactly those bytes -- the store
// re-marshals it for the jsonb columns it owns, but the DIGEST is
// computed here from the bytes, one home, and the caller cannot mint a
// row whose index disagrees with its bytes: the marshal is over the
// idx the route parsed FROM these bytes, and any disagreement is a
// route bug the pin will surface.
func (s *PublisherStore) PublishSkillItem(ctx context.Context, name string, bundle []byte, idx skill.Index) (CatalogItem, error) {
	if name != idx.Name {
		// The listing's name IS the bundle's name: one home for the
		// string the catalog shows and the frontmatter declares, or the
		// index would render a name the bundle never carried.
		return CatalogItem{}, fmt.Errorf("store: listing name %q disagrees with the bundle's frontmatter name %q", name, idx.Name)
	}
	item := CatalogItem{
		ID:             NewID(),
		PublisherID:    s.publisherID,
		Name:           name,
		EndpointURL:    "", // skills have no MCP endpoint; the references are the fetch surface (migration 005)
		Manifest:       string(bundle),
		ManifestDigest: ManifestDigest(bundle),
		Type:           "skill",
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return CatalogItem{}, fmt.Errorf("store: beginning skill publish for publisher %s: %w", s.publisherID, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	err = tx.QueryRow(ctx,
		`INSERT INTO catalog_items (id, publisher_id, name, endpoint_url, manifest, manifest_digest, type)
		 VALUES ($1::uuid, $2::uuid, $3, '', $4, $5, 'skill')
		 RETURNING version, published_at, updated_at`,
		item.ID, s.publisherID, name, item.Manifest, item.ManifestDigest,
	).Scan(&item.Version, &item.PublishedAt, &item.UpdatedAt)
	if err != nil {
		return CatalogItem{}, fmt.Errorf("store: publishing skill %s for publisher %s: %w", item.ID, s.publisherID, err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO catalog_mutations (id, item_id, actor_publisher, mutation, before, after)
		 VALUES ($1::uuid, $2::uuid, $3::uuid, 'publish', NULL, $4)`,
		NewID(), item.ID, s.publisherID, item.Manifest,
	); err != nil {
		return CatalogItem{}, fmt.Errorf("store: recording skill publish of %s: %w", item.ID, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return CatalogItem{}, fmt.Errorf("store: committing skill publish for publisher %s: %w", s.publisherID, err)
	}
	return item, nil
}

// UpdateSkillItem is deliberately ABSENT: publisher.go's UpdateItem is
// type-blind over the manifest bytes (read FOR UPDATE, same-bytes
// refused, version advanced, the mutation row written with the
// captured before) and serves S10 for skills unchanged. The route
// validates the new bundle's parse BEFORE calling it, exactly as the
// publish route does; the store is the pin, not the parser. One verb,
// two artifact kinds -- the alternative would be a near-copy whose
// drift from the original would be the two-homes bug.

// InstallSkillItem pins a skill bundle as the org's install, with the
// parse stored beside the pin, in one transaction. The bundle is the
// bytes the ORG's install decision rendered (the listing's current
// bytes, read by the route -- the analogue of the manifest bytes
// discovery fetched in 004). idx is the route's parse of those bytes;
// the store marshals it to the skill_index jsonb once, and every later
// reader renders from that one stored string.
//
// The install_changes row is the same three-state audit 004 defined:
// 'installed' with before NULL and after = the pinned bytes.
func (s *OrgStore) InstallSkillItem(ctx context.Context, itemID, installedBy string, bundle []byte, idx skill.Index) (Install, error) {
	indexJSON, err := json.Marshal(idx)
	if err != nil {
		return Install{}, fmt.Errorf("store: marshalling skill index: %w", err)
	}
	install := Install{
		ID:              NewID(),
		OrgID:           s.orgID,
		ItemID:          itemID,
		InstalledBy:     installedBy,
		PinnedManifest:  string(bundle),
		PinnedDigest:    ManifestDigest(bundle),
		EndpointURL:     "",
		EndpointAddress: "",
		Status:          "active",
		ItemType:        "skill",
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Install{}, fmt.Errorf("store: beginning skill install for org %s: %w", s.orgID, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	err = tx.QueryRow(ctx,
		`INSERT INTO installs (id, org_id, item_id, installed_by, pinned_manifest, pinned_digest,
		                       endpoint_url, endpoint_address, item_type, skill_index)
		 VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6, '', '', 'skill', $7::jsonb)
		 RETURNING installed_at`,
		install.ID, s.orgID, itemID, installedBy, install.PinnedManifest, install.PinnedDigest, string(indexJSON),
	).Scan(&install.InstalledAt)
	if err != nil {
		return Install{}, fmt.Errorf("store: installing skill %s for org %s: %w", itemID, s.orgID, err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO install_changes (id, install_id, org_id, actor_user, mutation, before, after)
		 VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'installed', NULL, $5)`,
		NewID(), install.ID, s.orgID, installedBy, install.PinnedManifest,
	); err != nil {
		return Install{}, fmt.Errorf("store: recording skill install of %s: %w", install.ID, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return Install{}, fmt.Errorf("store: committing skill install for org %s: %w", s.orgID, err)
	}
	return install, nil
}

// AuthoriseSkill records a member's S5 decision -- their own sessions
// may load this installed skill -- with its audit row, one transaction.
// Actor is the user THEMSELVES: S5 is the member's trust decision
// (m4b-N4 records that this decision is honestly attackable and bounded
// by the same legs as every load). No session column exists on this
// plane for 004's reason: the verbs are control-plane and nothing
// agent-reachable calls them.
func (s *OrgStore) AuthoriseSkill(ctx context.Context, installID, userID string) (SkillAuthorisation, error) {
	auth := SkillAuthorisation{
		ID:        NewID(),
		OrgID:     s.orgID,
		InstallID: installID,
		UserID:    userID,
		Status:    "active",
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return SkillAuthorisation{}, fmt.Errorf("store: beginning skill authorisation for org %s: %w", s.orgID, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	err = tx.QueryRow(ctx,
		`INSERT INTO skill_authorisations (id, org_id, install_id, user_id)
		 VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid)
		 RETURNING extract(epoch from authorised_at)::bigint`,
		auth.ID, s.orgID, installID, userID,
	).Scan(&auth.AuthorisedAt)
	if err != nil {
		return SkillAuthorisation{}, fmt.Errorf("store: authorising skill install %s: %w", installID, err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO skill_authorisation_changes (id, auth_id, org_id, actor_user, mutation)
		 VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'authorised')`,
		NewID(), auth.ID, s.orgID, userID,
	); err != nil {
		return SkillAuthorisation{}, fmt.Errorf("store: recording authorisation of %s: %w", auth.ID, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return SkillAuthorisation{}, fmt.Errorf("store: committing skill authorisation for org %s: %w", s.orgID, err)
	}
	return auth, nil
}

// RevokeSkillAuthorisation flips the member's authorisation to a
// tombstone (M3-N3: no cascades, no deletes) and records the retreat.
// A later re-authorise writes a fresh row -- the unique index allows
// one ACTIVE row per (install, user), so the history accumulates.
func (s *OrgStore) RevokeSkillAuthorisation(ctx context.Context, authID, userID string) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("store: beginning skill authorisation revoke for org %s: %w", s.orgID, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx,
		`UPDATE skill_authorisations SET status = 'revoked'
		 WHERE id = $1::uuid AND org_id = $2::uuid AND user_id = $3::uuid AND status = 'active'`,
		authID, s.orgID, userID,
	)
	if err != nil {
		return false, fmt.Errorf("store: revoking authorisation %s: %w", authID, err)
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO skill_authorisation_changes (id, auth_id, org_id, actor_user, mutation)
		 VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'revoked')`,
		NewID(), authID, s.orgID, userID,
	); err != nil {
		return false, fmt.Errorf("store: recording revoke of %s: %w", authID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("store: committing authorisation revoke for org %s: %w", s.orgID, err)
	}
	return true, nil
}

// SkillIndexForUser is the S6 answer: every skill this user has an
// ACTIVE authorisation for, joined through ACTIVE installs, rendered
// from the stored parse, ordered by precedence (platform publishers
// first), then install time, then name -- SR-B9-4's determinism, so two
// skills claiming one situation resolve by rule, never by which
// description reads more persuasively.
func (s *OrgStore) SkillIndexForUser(ctx context.Context, userID string) ([]SkillIndexEntry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT i.id,
		       (i.skill_index->>'name')::text,
		       (i.skill_index->>'description')::text,
		       i.skill_index->'triggers',
		       i.skill_index->'capabilities',
		       i.skill_index->'references',
		       p.display_name,
		       p.is_platform,
		       i.pinned_digest
		FROM skill_authorisations a
		JOIN installs i ON i.id = a.install_id AND i.status = 'active' AND i.item_type = 'skill'
		JOIN catalog_items c ON c.id = i.item_id
		JOIN publishers p ON p.id = c.publisher_id
		WHERE a.org_id = $1::uuid AND a.user_id = $2::uuid AND a.status = 'active'
		ORDER BY p.is_platform DESC, i.installed_at, (i.skill_index->>'name')`,
		s.orgID, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("store: reading skill index for user %s: %w", userID, err)
	}
	defer rows.Close()

	var out []SkillIndexEntry
	for rows.Next() {
		var e SkillIndexEntry
		var triggers, caps, refs []byte
		if err := rows.Scan(&e.InstallID, &e.Name, &e.Description, &triggers, &caps, &refs,
			&e.Publisher, &e.IsPlatform, &e.PinnedDigest); err != nil {
			return nil, fmt.Errorf("store: scanning skill index row: %w", err)
		}
		if err := json.Unmarshal(triggers, &e.Triggers); err != nil {
			return nil, fmt.Errorf("store: skill index triggers for %s: %w", e.InstallID, err)
		}
		if err := json.Unmarshal(caps, &e.Capabilities); err != nil {
			return nil, fmt.Errorf("store: skill index capabilities for %s: %w", e.InstallID, err)
		}
		if err := json.Unmarshal(refs, &e.References); err != nil {
			return nil, fmt.Errorf("store: skill index references for %s: %w", e.InstallID, err)
		}
		if e.References == nil {
			e.References = []string{}
		}
		out = append(out, e)
	}
	if out == nil {
		out = []SkillIndexEntry{}
	}
	return out, nil
}
