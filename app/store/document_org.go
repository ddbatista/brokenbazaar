package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// OrgStore is the hardened DocumentStore (D5): every statement carries the
// bound org_id, and ForOrg is the only constructor. This is SR-B2-1, SR-B2-2
// (combined with a caller that already checked membership before calling
// ForOrg -- this type does not check membership itself) and SR-B2-4's second
// half (authorise against the object's owner).
//
// Written before NaiveStore, per AGENTS.md house rule: "write the correct
// implementation before the vulnerable one." The vulnerable store is then a
// documented departure from a design that was reasoned out first, not an
// accident that happened to get fixed later.
type OrgStore struct {
	pool  *pgxpool.Pool
	orgID string
}

// ForOrg returns a DocumentStore that can reach exactly one org's documents.
// Call it only after the caller has already verified, server-side, that the
// acting user holds membership in orgID (SR-B2-2) -- ForOrg trusts its
// argument unconditionally, the same way a SQL query trusts its bind
// parameters: the authorization decision happens once, upstream, and this
// type is where that decision becomes structurally impossible to bypass
// afterwards.
func ForOrg(pool *pgxpool.Pool, orgID string) *OrgStore {
	return &OrgStore{pool: pool, orgID: orgID}
}

var _ DocumentStore = (*OrgStore)(nil)

func (s *OrgStore) Create(ctx context.Context, doc Document) (Document, error) {
	doc.ID = NewID()
	doc.OrgID = s.orgID // SR-B2-6: org_id never taken from the caller's struct
	err := s.pool.QueryRow(ctx,
		`INSERT INTO documents (id, org_id, title, body, created_by)
		 VALUES ($1::uuid, $2::uuid, $3, $4, $5::uuid)
		 RETURNING created_at`,
		doc.ID, s.orgID, doc.Title, doc.Body, doc.CreatedBy,
	).Scan(&doc.CreatedAt)
	if err != nil {
		return Document{}, fmt.Errorf("store: creating document in org %s: %w", s.orgID, err)
	}
	return doc, nil
}

func (s *OrgStore) Get(ctx context.Context, id string) (Document, bool, error) {
	var d Document
	err := s.pool.QueryRow(ctx,
		// SR-M1-4: the WHERE clause carries both predicates in one
		// statement. "Wrong org" and "no such id" produce the identical
		// empty result from the identical query -- there is no later step
		// that could leak a difference between the two, because the two
		// cases never separate.
		`SELECT id::text, org_id::text, title, body, created_by::text, created_at
		 FROM documents WHERE id = $1::uuid AND org_id = $2::uuid`,
		id, s.orgID,
	).Scan(&d.ID, &d.OrgID, &d.Title, &d.Body, &d.CreatedBy, &d.CreatedAt)
	if err != nil {
		if isNoRows(err) {
			return Document{}, false, nil
		}
		return Document{}, false, fmt.Errorf("store: getting document %s in org %s: %w", id, s.orgID, err)
	}
	return d, true, nil
}

func (s *OrgStore) List(ctx context.Context) ([]Document, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id::text, org_id::text, title, body, created_by::text, created_at
		 FROM documents WHERE org_id = $1::uuid ORDER BY created_at`,
		s.orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("store: listing documents in org %s: %w", s.orgID, err)
	}
	return scanDocuments(rows)
}

func (s *OrgStore) Search(ctx context.Context, q string) ([]Document, error) {
	rows, err := s.pool.Query(ctx,
		// The sibling of NaiveStore.Search (M1-N3): same shape of query,
		// this one carries the org predicate. Both are one call site each --
		// the bug is not that search is harder to scope, it's that nothing
		// forces it to be scoped except remembering to type "AND org_id=$2"
		// a second time. OrgStore's answer is that there is no query here
		// *without* $2.
		`SELECT id::text, org_id::text, title, body, created_by::text, created_at
		 FROM documents WHERE org_id = $1::uuid AND (title ILIKE $2 OR body ILIKE $2)
		 ORDER BY created_at`,
		s.orgID, "%"+q+"%",
	)
	if err != nil {
		return nil, fmt.Errorf("store: searching documents in org %s: %w", s.orgID, err)
	}
	return scanDocuments(rows)
}

func (s *OrgStore) Update(ctx context.Context, doc Document) (Document, bool, error) {
	var updated Document
	err := s.pool.QueryRow(ctx,
		`UPDATE documents SET title = $1, body = $2
		 WHERE id = $3::uuid AND org_id = $4::uuid
		 RETURNING id::text, org_id::text, title, body, created_by::text, created_at`,
		doc.Title, doc.Body, doc.ID, s.orgID,
	).Scan(&updated.ID, &updated.OrgID, &updated.Title, &updated.Body, &updated.CreatedBy, &updated.CreatedAt)
	if err != nil {
		if isNoRows(err) {
			return Document{}, false, nil
		}
		return Document{}, false, fmt.Errorf("store: updating document %s in org %s: %w", doc.ID, s.orgID, err)
	}
	return updated, true, nil
}

func (s *OrgStore) Delete(ctx context.Context, id string) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM documents WHERE id = $1::uuid AND org_id = $2::uuid`,
		id, s.orgID,
	)
	if err != nil {
		return false, fmt.Errorf("store: deleting document %s in org %s: %w", id, s.orgID, err)
	}
	return tag.RowsAffected() > 0, nil
}

// scanDocuments drains a pgx.Rows into a slice. Shared by both stores'
// List/Search so the row-scanning shape is written once; the thing that
// differs between the two stores is always the query text, never this loop.
func scanDocuments(rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close()
}) ([]Document, error) {
	defer rows.Close()
	var docs []Document
	for rows.Next() {
		var d Document
		if err := rows.Scan(&d.ID, &d.OrgID, &d.Title, &d.Body, &d.CreatedBy, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: scanning document row: %w", err)
		}
		docs = append(docs, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating document rows: %w", err)
	}
	return docs, nil
}
