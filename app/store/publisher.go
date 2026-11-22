package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Publisher is the marketplace's new principal (m4a D1): registration is
// open and unvetted by design (baseline B6 5.2), identity is the uuid, the
// display name is advisory, and the token minted at registration is the
// whole credential -- no recovery flow exists, so B6 5.1 (account
// takeover) is credential theft, out of scope by shape.
type Publisher struct {
	ID          string
	DisplayName string
	CreatedAt   time.Time
}

// CatalogItem is one listing: a name, an endpoint, and the manifest the
// publisher last posted -- the ADVERTISED copy. It is not what installed
// orgs run; installs pin the bytes they fetched at install time, and the
// gap between the two copies is exactly the drift baseline leaves 2.1
// and 2.2 describe. Manifest is raw bytes as text: jsonb would silently
// re-format them and the pin is over bytes (migration 004).
type CatalogItem struct {
	ID             string
	PublisherID    string
	Name           string
	EndpointURL    string
	Manifest       string
	ManifestDigest string
	Version        int
	PublishedAt    time.Time
	UpdatedAt      time.Time
}

// PublisherStore is the publisher-bound handle: a publisher may mutate
// exactly their own listings, and the binding is the constructor's, the
// same shape as ForOrg (plan M4a T2 D1; references/schema-store-tasks.md
// -- a per-call publisher id on a wider store is what the handle pattern
// exists to reject). Reads through this handle carry BOTH predicates even
// where one would do, so the handle's scope is consulted rather than
// trusted from construction.
type PublisherStore struct {
	pool        *pgxpool.Pool
	publisherID string
}

// ForPublisher returns a store scoped to one publisher's listings.
// Authorization is the caller's: the publisher route resolved sub against
// publishers before calling this, and a token that is not this publisher
// never reaches a handle bound to it.
func ForPublisher(pool *pgxpool.Pool, publisherID string) *PublisherStore {
	return &PublisherStore{pool: pool, publisherID: publisherID}
}

// PublishItem posts a new listing and records the publish as the first
// catalog mutation, in one transaction (SR-B6-8: actor, before NULL,
// after -- the record a later rug pull will be read against). The digest
// is computed here, in the store, from the exact bytes passed in -- one
// home for "what this listing's manifest hashes to", so no caller can
// mint a row whose digest disagrees with its bytes.
func (s *PublisherStore) PublishItem(ctx context.Context, name, endpointURL string, manifest []byte) (CatalogItem, error) {
	item := CatalogItem{
		ID:             NewID(),
		PublisherID:    s.publisherID, // never taken from the caller
		Name:           name,
		EndpointURL:    endpointURL,
		Manifest:       string(manifest),
		ManifestDigest: ManifestDigest(manifest),
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return CatalogItem{}, fmt.Errorf("store: beginning publish for publisher %s: %w", s.publisherID, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	err = tx.QueryRow(ctx,
		`INSERT INTO catalog_items (id, publisher_id, name, endpoint_url, manifest, manifest_digest)
		 VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)
		 RETURNING version, published_at, updated_at`,
		item.ID, s.publisherID, name, endpointURL, item.Manifest, item.ManifestDigest,
	).Scan(&item.Version, &item.PublishedAt, &item.UpdatedAt)
	if err != nil {
		return CatalogItem{}, fmt.Errorf("store: publishing item for publisher %s: %w", s.publisherID, err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO catalog_mutations (id, item_id, actor_publisher, mutation, before, after)
		 VALUES ($1::uuid, $2::uuid, $3::uuid, 'publish', NULL, $4)`,
		NewID(), item.ID, s.publisherID, item.Manifest,
	); err != nil {
		return CatalogItem{}, fmt.Errorf("store: recording publish of %s for publisher %s: %w", item.ID, s.publisherID, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return CatalogItem{}, fmt.Errorf("store: committing publish for publisher %s: %w", s.publisherID, err)
	}
	return item, nil
}

// UpdateItem replaces the listing's advertised manifest and records the
// update with before and after, in one transaction. The row is read FOR
// UPDATE first so two concurrent updates cannot record the same "before",
// and the item is looked up constrained on the handle's publisher: a
// publisher PATCHing another publisher's listing is not found here --
// found=false, the same not-found indistinguishability as a wrong-org
// document. A same-bytes update is refused by the caller-visible error
// and by the schema's CHECK: a mutation row that says "same" is a false
// record (SR-B6-8; the role_changes precedent, migration 003).
//
// What this method deliberately does NOT touch: any install. Installed
// orgs' pins are unaffected by a listing update -- the pin is content,
// not a pointer to the listing (SR-B6-1; finding 08 (ii) exists because
// the vulnerable catalog reader defers to exactly this row).
func (s *PublisherStore) UpdateItem(ctx context.Context, itemID string, manifest []byte) (CatalogItem, bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return CatalogItem{}, false, fmt.Errorf("store: beginning item update for publisher %s: %w", s.publisherID, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var item CatalogItem
	err = tx.QueryRow(ctx,
		`SELECT id::text, publisher_id::text, name, endpoint_url, manifest, version
		 FROM catalog_items
		 WHERE id = $1::uuid AND publisher_id = $2::uuid
		 FOR UPDATE`,
		itemID, s.publisherID,
	).Scan(&item.ID, &item.PublisherID, &item.Name, &item.EndpointURL, &item.Manifest, &item.Version)
	if err != nil {
		if isNoRows(err) {
			return CatalogItem{}, false, nil
		}
		return CatalogItem{}, false, fmt.Errorf("store: reading item %s for publisher %s: %w", itemID, s.publisherID, err)
	}
	if item.Manifest == string(manifest) {
		// Same bytes: refused loudly rather than recorded, matching the
		// schema CHECK that would refuse the mutation row anyway.
		return item, false, fmt.Errorf("store: update of %s carries identical bytes; nothing to record", itemID)
	}

	before := item.Manifest
	item.Manifest = string(manifest)
	item.ManifestDigest = ManifestDigest(manifest)
	if _, err := tx.Exec(ctx,
		`UPDATE catalog_items
		 SET manifest = $3, manifest_digest = $4, version = version + 1, updated_at = now()
		 WHERE id = $1::uuid AND publisher_id = $2::uuid`,
		itemID, s.publisherID, item.Manifest, item.ManifestDigest,
	); err != nil {
		return CatalogItem{}, false, fmt.Errorf("store: updating item %s for publisher %s: %w", itemID, s.publisherID, err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO catalog_mutations (id, item_id, actor_publisher, mutation, before, after)
		 VALUES ($1::uuid, $2::uuid, $3::uuid, 'update', $4, $5)`,
		NewID(), itemID, s.publisherID, before, string(manifest),
	); err != nil {
		return CatalogItem{}, false, fmt.Errorf("store: recording update of %s for publisher %s: %w", itemID, s.publisherID, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return CatalogItem{}, false, fmt.Errorf("store: committing update of %s for publisher %s: %w", itemID, s.publisherID, err)
	}
	return item, true, nil
}

// Items lists this publisher's own listings, newest first.
func (s *PublisherStore) Items(ctx context.Context) ([]CatalogItem, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id::text, publisher_id::text, name, endpoint_url, manifest, manifest_digest, version, published_at, updated_at
		 FROM catalog_items
		 WHERE publisher_id = $1::uuid
		 ORDER BY published_at DESC, id`,
		s.publisherID,
	)
	if err != nil {
		return nil, fmt.Errorf("store: listing items for publisher %s: %w", s.publisherID, err)
	}
	defer rows.Close()

	var out []CatalogItem
	for rows.Next() {
		var it CatalogItem
		if err := rows.Scan(&it.ID, &it.PublisherID, &it.Name, &it.EndpointURL,
			&it.Manifest, &it.ManifestDigest, &it.Version, &it.PublishedAt, &it.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: reading items for publisher %s: %w", s.publisherID, err)
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// Item loads one of this publisher's listings. Both predicates in one
// statement: another publisher's item id and a nonexistent id produce
// the identical empty result (SR-M1-4's rule, applied to the new plane).
func (s *PublisherStore) Item(ctx context.Context, itemID string) (CatalogItem, bool, error) {
	var it CatalogItem
	err := s.pool.QueryRow(ctx,
		`SELECT id::text, publisher_id::text, name, endpoint_url, manifest, manifest_digest, version, published_at, updated_at
		 FROM catalog_items
		 WHERE id = $1::uuid AND publisher_id = $2::uuid`,
		itemID, s.publisherID,
	).Scan(&it.ID, &it.PublisherID, &it.Name, &it.EndpointURL,
		&it.Manifest, &it.ManifestDigest, &it.Version, &it.PublishedAt, &it.UpdatedAt)
	if err != nil {
		if isNoRows(err) {
			return CatalogItem{}, false, nil
		}
		return CatalogItem{}, false, fmt.Errorf("store: loading item %s for publisher %s: %w", itemID, s.publisherID, err)
	}
	return it, true, nil
}
