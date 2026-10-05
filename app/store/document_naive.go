package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NaiveStore is the vulnerable DocumentStore (D5). It is a documented
// departure from OrgStore, not an accident later discovered -- OrgStore
// above was written first, per house rule, specifically so this file's
// ANSWER-KEY can argue *why a real developer would write it this way*
// rather than dismissing it as a typo. Nothing about Go's type system
// forces a store to be scoped; NaiveStore is what you get when "the caller
// will pass the right org" is treated as a convention instead of enforced
// by the constructor.
//
// DO NOT fix the missing predicates below. They are the planted
// vulnerabilities attacks/01-cross-tenant-read (Search) and the IDOR noted
// at B2 2.1 (Get) exploit. They are wired into handlers only when
// HARDENED=false (M1 T7). See AGENTS.md: "do not fix a planted vulnerability
// as a drive-by."
type NaiveStore struct {
	pool *pgxpool.Pool
}

func NewNaiveStore(pool *pgxpool.Pool) *NaiveStore {
	return &NaiveStore{pool: pool}
}

var _ DocumentStore = (*NaiveStore)(nil)

func (s *NaiveStore) Create(ctx context.Context, doc Document) (Document, error) {
	// No store-side scoping on create either: org_id is whatever the caller
	// put in doc.OrgID -- including, upstream in the handler, a client-
	// supplied field straight out of a JSON body (B2 4.1, mass assignment).
	// The store does not question it; SR-B2-6 is a handler-layer DTO
	// decision in the hardened build, not something this type enforces.
	doc.ID = NewID()
	err := s.pool.QueryRow(ctx,
		`INSERT INTO documents (id, org_id, title, body, created_by)
		 VALUES ($1::uuid, $2::uuid, $3, $4, $5::uuid)
		 RETURNING created_at`,
		doc.ID, doc.OrgID, doc.Title, doc.Body, doc.CreatedBy,
	).Scan(&doc.CreatedAt)
	if err != nil {
		return Document{}, fmt.Errorf("store: creating document: %w", err)
	}
	return doc, nil
}

func (s *NaiveStore) Get(ctx context.Context, id string) (Document, bool, error) {
	// B2 2.1 -- IDOR. No org predicate at all: any valid document id
	// resolves, regardless of which org holds it. The control that kills
	// this (OrgStore.Get's AND org_id=$2) is the same control that kills
	// finding 01, which is why this leaf is not a separate numbered finding
	// (threat model §2: "one finding per control, not per leaf").
	var d Document
	err := s.pool.QueryRow(ctx,
		`SELECT id::text, org_id::text, title, body, created_by::text, created_at
		 FROM documents WHERE id = $1::uuid`,
		id,
	).Scan(&d.ID, &d.OrgID, &d.Title, &d.Body, &d.CreatedBy, &d.CreatedAt)
	if err != nil {
		if isNoRows(err) {
			return Document{}, false, nil
		}
		return Document{}, false, fmt.Errorf("store: getting document %s: %w", id, err)
	}
	return d, true, nil
}

func (s *NaiveStore) List(ctx context.Context) ([]Document, error) {
	// Returns every document in the table, from every org. By plan intent
	// this is the path whose handler filters in Go afterwards (the
	// B2 2.3 "sibling" list path that *does* remember the rule) -- the
	// filtering is wired up in T5, not here. This store method alone leaks
	// nothing only because nothing calls it unfiltered; that fragility is
	// the point of the finding, not a gap in this file.
	rows, err := s.pool.Query(ctx,
		`SELECT id::text, org_id::text, title, body, created_by::text, created_at
		 FROM documents ORDER BY created_at`,
	)
	if err != nil {
		return nil, fmt.Errorf("store: listing documents: %w", err)
	}
	return scanDocuments(rows)
}

func (s *NaiveStore) Search(ctx context.Context, q string) ([]Document, error) {
	// B2 2.3 -- THE planted vulnerability attacks/01-cross-tenant-read
	// exploits. No org predicate, and unlike List, nothing downstream
	// filters this one either: the search handler added beside the list
	// handler forgot the rule the list handler remembered (M1-N3).
	rows, err := s.pool.Query(ctx,
		`SELECT id::text, org_id::text, title, body, created_by::text, created_at
		 FROM documents WHERE title ILIKE $1 OR body ILIKE $1 ORDER BY created_at`,
		"%"+q+"%",
	)
	if err != nil {
		return nil, fmt.Errorf("store: searching documents: %w", err)
	}
	return scanDocuments(rows)
}

func (s *NaiveStore) Update(ctx context.Context, doc Document) (Document, bool, error) {
	var updated Document
	err := s.pool.QueryRow(ctx,
		`UPDATE documents SET title = $1, body = $2 WHERE id = $3::uuid
		 RETURNING id::text, org_id::text, title, body, created_by::text, created_at`,
		doc.Title, doc.Body, doc.ID,
	).Scan(&updated.ID, &updated.OrgID, &updated.Title, &updated.Body, &updated.CreatedBy, &updated.CreatedAt)
	if err != nil {
		if isNoRows(err) {
			return Document{}, false, nil
		}
		return Document{}, false, fmt.Errorf("store: updating document %s: %w", doc.ID, err)
	}
	return updated, true, nil
}

func (s *NaiveStore) Delete(ctx context.Context, id string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM documents WHERE id = $1::uuid`, id)
	if err != nil {
		return false, fmt.Errorf("store: deleting document %s: %w", id, err)
	}
	return tag.RowsAffected() > 0, nil
}
