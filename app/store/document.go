package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// DocumentStore is the contract both implementations satisfy (D5). No
// method takes an org_id parameter. That absence is the entire design: scope
// is a property of *which implementation, and for OrgStore which instance*
// answers the call -- never a value a caller supplies per request. A
// parameter can be forgotten in one call site and remembered in its sibling
// (M1-N3); a value baked into a constructor at authorization time cannot be,
// because there is no call site left where it could be supplied differently.
type DocumentStore interface {
	Create(ctx context.Context, doc Document) (Document, error)
	Get(ctx context.Context, id string) (Document, bool, error)
	List(ctx context.Context) ([]Document, error)
	Search(ctx context.Context, q string) ([]Document, error)
	Update(ctx context.Context, doc Document) (Document, bool, error)
	Delete(ctx context.Context, id string) (bool, error)
}

// isNoRows centralizes the pgx.ErrNoRows check so both store
// implementations, and AdminStore, treat "not found" the same way: as a
// plain false, not an error. SR-M1-4 (the module's "uniform 404" leaf) wants
// callers that can't tell "no such row" apart from "a query failed" by
// inspecting the bool, which is what makes the hardened handler's identical
// response for both tenancy cases possible later in T5.
func isNoRows(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}
