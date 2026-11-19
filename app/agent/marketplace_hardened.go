//go:build !vulnerable

package agent

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// CatalogText in the hardened build returns nothing, DELIBERATELY, and
// T5 replaces this stub with the real mechanism: the pinned catalog
// served from the install rows, wrapped and marked as origin
// `publisher` (m4a D5) -- never concatenated into the system prompt,
// and never fetched live from any server. Until T5 lands, the hardened
// agent holds no marketplace code at all, which is the same property
// verify-agent-builds asserts for every other tool: there is nothing in
// this binary that dials a publisher.
func CatalogText(_ context.Context, _ *pgxpool.Pool, _ string) (string, error) {
	return "", nil
}
