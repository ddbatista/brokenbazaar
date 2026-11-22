package store

import (
	"context"
	"fmt"
	"time"
)

// The marketplace's platform-plane surface on AdminStore.
//
// AdminStore is the plane that CREATES principals and reads
// platform-level objects without a scope (it already resolves users for
// the token route). Publishers are principals, so registration lands
// here; catalog reads are platform-level, so they land here too. What
// deliberately does NOT land here: any scoped mutation -- a publisher's
// own listings go through ForPublisher, an org's installs through ForOrg
// (m4a D1's three planes, applied the way the tenancy plane already
// applies them).

// RegisterPublisher creates a publisher principal. Registration is open
// and unauthenticated-in-effect: the baseline accepts unvetted
// registration by design (B6 5.2) and the exploit registers its hostile
// publisher through this front door on purpose -- the product decision is
// the finding's premise, not a gap in it. The caller mints the token that
// authenticates all later calls; this method only creates the row.
func (s *AdminStore) RegisterPublisher(ctx context.Context, displayName string) (Publisher, error) {
	pub := Publisher{ID: NewID(), DisplayName: displayName}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO publishers (id, display_name)
		 VALUES ($1::uuid, $2)
		 RETURNING created_at`,
		pub.ID, displayName,
	).Scan(&pub.CreatedAt)
	if err != nil {
		return Publisher{}, fmt.Errorf("store: registering publisher %q: %w", displayName, err)
	}
	return pub, nil
}

// Publisher resolves one publisher by id, for the route that
// authenticated a token's sub against this table (D1: resolution by
// table, not by claim).
func (s *AdminStore) Publisher(ctx context.Context, publisherID string) (Publisher, bool, error) {
	var pub Publisher
	err := s.pool.QueryRow(ctx,
		`SELECT id::text, display_name, created_at
		 FROM publishers WHERE id = $1::uuid`,
		publisherID,
	).Scan(&pub.ID, &pub.DisplayName, &pub.CreatedAt)
	if err != nil {
		if isNoRows(err) {
			return Publisher{}, false, nil
		}
		return Publisher{}, false, fmt.Errorf("store: loading publisher %s: %w", publisherID, err)
	}
	return pub, true, nil
}

// CatalogItemDetail is the install decision point's payload (SR-B6-6):
// the listing, its publisher, and the provenance an org should weigh
// before consenting -- publisher age, how many orgs installed it, and the
// version history. It is read data assembled for the route; nothing here
// is a decision. InstallCount counts ACTIVE installs only: an uninstalled
// row granted nothing to anyone at this moment (the tombstone rows remain
// queryable in install_changes for anyone auditing history).
type CatalogItemDetail struct {
	CatalogItem
	Publisher    Publisher
	InstallCount int
	MutationLog  []CatalogMutation
}

// CatalogMutation is one row of the listing's immutable history
// (SR-B6-8). Before is "" for a publish (nothing preceded it); the raw
// manifest bytes are carried as-is, never re-serialized.
type CatalogMutation struct {
	ID             string
	ItemID         string
	ActorPublisher string
	Mutation       string
	Before         string
	After          string
	CreatedAt      time.Time
}

// CatalogItem loads one listing with its provenance payload. Unlike the
// publisher-bound reads, this lookup is by id alone: the catalog is
// platform-level and public to authenticated users, so there is no scope
// to carry and no membership to leak (SR-M1-4 does not apply -- the
// difference between "no such item" and "an item you may not see" does
// not exist here).
func (s *AdminStore) CatalogItem(ctx context.Context, itemID string) (CatalogItemDetail, bool, error) {
	var d CatalogItemDetail
	err := s.pool.QueryRow(ctx,
		`SELECT c.id::text, c.publisher_id::text, c.name, c.endpoint_url,
		        c.manifest, c.manifest_digest, c.version, c.published_at, c.updated_at, c.type,
		        p.id::text, p.display_name, p.created_at,
		        (SELECT count(*) FROM installs i
		         WHERE i.item_id = c.id AND i.status = 'active')
		 FROM catalog_items c
		 JOIN publishers p ON p.id = c.publisher_id
		 WHERE c.id = $1::uuid`,
		itemID,
	).Scan(&d.ID, &d.PublisherID, &d.Name, &d.EndpointURL,
		&d.Manifest, &d.ManifestDigest, &d.Version, &d.PublishedAt, &d.UpdatedAt, &d.Type,
		&d.Publisher.ID, &d.Publisher.DisplayName, &d.Publisher.CreatedAt,
		&d.InstallCount,
	)
	if err != nil {
		if isNoRows(err) {
			return CatalogItemDetail{}, false, nil
		}
		return CatalogItemDetail{}, false, fmt.Errorf("store: loading catalog item %s: %w", itemID, err)
	}

	// COALESCE on before: publish rows store NULL (the CHECK requires it),
	// and the read's contract is ""-means-absent, matching InstallChange.
	rows, err := s.pool.Query(ctx,
		`SELECT id::text, item_id::text, actor_publisher::text, mutation,
		        COALESCE(before, '') AS before, after, created_at
		 FROM catalog_mutations
		 WHERE item_id = $1::uuid
		 ORDER BY created_at, id`,
		itemID,
	)
	if err != nil {
		return CatalogItemDetail{}, false, fmt.Errorf("store: loading mutations for item %s: %w", itemID, err)
	}
	defer rows.Close()
	for rows.Next() {
		var m CatalogMutation
		if err := rows.Scan(&m.ID, &m.ItemID, &m.ActorPublisher, &m.Mutation, &m.Before, &m.After, &m.CreatedAt); err != nil {
			return CatalogItemDetail{}, false, fmt.Errorf("store: reading mutations for item %s: %w", itemID, err)
		}
		d.MutationLog = append(d.MutationLog, m)
	}
	if err := rows.Err(); err != nil {
		return CatalogItemDetail{}, false, fmt.Errorf("store: iterating mutations for item %s: %w", itemID, err)
	}
	return d, true, nil
}

// CatalogItems lists the catalog, newest first. The payload is the
// listing rows without provenance (the detail view carries that); the
// catalog index is what an org browses before an install decision.
func (s *AdminStore) CatalogItems(ctx context.Context) ([]CatalogItem, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id::text, publisher_id::text, name, endpoint_url, manifest, manifest_digest, version, published_at, updated_at, type
		 FROM catalog_items
		 ORDER BY published_at DESC, id`,
	)
	if err != nil {
		return nil, fmt.Errorf("store: listing catalog: %w", err)
	}
	defer rows.Close()

	var out []CatalogItem
	for rows.Next() {
		var it CatalogItem
		if err := rows.Scan(&it.ID, &it.PublisherID, &it.Name, &it.EndpointURL,
			&it.Manifest, &it.ManifestDigest, &it.Version, &it.PublishedAt, &it.UpdatedAt, &it.Type); err != nil {
			return nil, fmt.Errorf("store: reading catalog: %w", err)
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// RegisterPlatformPublisher registers the platform's OWN publisher row
// (SR-B9-11): is_platform is the precedence value -- platform >
// reviewed > third-party under SR-B9-4 -- and its home is the publisher
// row, because the platform decides who is first-party; a publisher
// cannot claim the class. This is the ONLY writer of is_platform=true:
// no route accepts it as an input, and the seed is the platform's own
// hand. The platform's skills then go through the same parse, the same
// pin and the same index as anyone else's -- first-party is a
// precedence value, never an exemption from review.
func (s *AdminStore) RegisterPlatformPublisher(ctx context.Context, displayName string) (Publisher, error) {
	pub := Publisher{ID: NewID(), DisplayName: displayName}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO publishers (id, display_name, is_platform)
		 VALUES ($1::uuid, $2, true)
		 RETURNING created_at`,
		pub.ID, pub.DisplayName,
	).Scan(&pub.CreatedAt)
	if err != nil {
		return Publisher{}, fmt.Errorf("store: registering platform publisher: %w", err)
	}
	return pub, nil
}
