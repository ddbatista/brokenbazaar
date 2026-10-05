package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Open creates a connection pool. It does not ping -- callers that need to
// fail fast on a bad DSN should call Pool.Ping themselves, because a
// migration runner and a long-lived API server want different retry
// behaviour and this package should not guess which one it's in.
func Open(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("store: opening pool: %w", err)
	}
	return pool, nil
}
