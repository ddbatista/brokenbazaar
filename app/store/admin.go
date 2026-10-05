package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AdminStore operates on orgs, users and memberships -- the tables that
// *define* tenancy rather than live inside it. These are deliberately not
// behind an org-scoped constructor the way DocumentStore is.
//
// SR-B2-1 requires that no code path reach a document without an org
// context. It says nothing about these three tables, and it cannot:
//   - an org row cannot "belong to" an org -- it is the unit itself.
//   - a user belongs to zero or more orgs through membership, so scoping
//     user lookups to a single org would make cross-org login (one person,
//     multiple orgs, docs/product-spec.md §3.2) impossible to implement.
//   - a membership *is* the thing that establishes an org binding; requiring
//     it to already have one to be created is circular.
//
// Documents are the tenant-scoped boundary this module threat-models
// (B2). AdminStore is the admin plane that defines tenants in the first
// place, and direct SQL here is not the leaf M1-N2 describes -- that leaf is
// specifically about documents (see app/cmd/seed).
type AdminStore struct {
	pool *pgxpool.Pool
}

func NewAdminStore(pool *pgxpool.Pool) *AdminStore {
	return &AdminStore{pool: pool}
}

func (s *AdminStore) CreateOrg(ctx context.Context, name string) (Org, error) {
	org := Org{ID: NewID(), Name: name}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO orgs (id, name) VALUES ($1::uuid, $2) RETURNING created_at`,
		org.ID, org.Name,
	).Scan(&org.CreatedAt)
	if err != nil {
		return Org{}, fmt.Errorf("store: creating org %q: %w", name, err)
	}
	return org, nil
}

func (s *AdminStore) CreateUser(ctx context.Context, email, displayName, passwordHash string) (User, error) {
	user := User{ID: NewID(), Email: email, DisplayName: displayName, PasswordHash: passwordHash}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO users (id, email, display_name, password_hash) VALUES ($1::uuid, $2, $3, $4)`,
		user.ID, user.Email, user.DisplayName, user.PasswordHash,
	)
	if err != nil {
		return User{}, fmt.Errorf("store: creating user %q: %w", email, err)
	}
	return user, nil
}

func (s *AdminStore) AddMembership(ctx context.Context, orgID, userID string, role Role) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO memberships (org_id, user_id, role) VALUES ($1::uuid, $2::uuid, $3)`,
		orgID, userID, string(role),
	)
	if err != nil {
		return fmt.Errorf("store: adding membership (org=%s user=%s): %w", orgID, userID, err)
	}
	return nil
}

// UserByEmail and MembershipRole are not called by anything in T2/T3 -- they
// exist here because they are AdminStore's responsibility, not a handler's,
// and T4 (auth) needs exactly these two server-side lookups: one to find the
// account POST /auth/token is issued for, one to answer "does this user
// actually hold membership in this org" (SR-B2-2), rather than trusting the
// org_id claim already inside a presented token.

func (s *AdminStore) UserByEmail(ctx context.Context, email string) (User, bool, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id::text, email, display_name, password_hash FROM users WHERE email = $1`,
		email,
	).Scan(&u.ID, &u.Email, &u.DisplayName, &u.PasswordHash)
	if err != nil {
		if isNoRows(err) {
			return User{}, false, nil
		}
		return User{}, false, fmt.Errorf("store: looking up user %q: %w", email, err)
	}
	return u, true, nil
}

func (s *AdminStore) MembershipRole(ctx context.Context, orgID, userID string) (Role, bool, error) {
	var role string
	err := s.pool.QueryRow(ctx,
		`SELECT role FROM memberships WHERE org_id = $1::uuid AND user_id = $2::uuid`,
		orgID, userID,
	).Scan(&role)
	if err != nil {
		if isNoRows(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("store: looking up membership (org=%s user=%s): %w", orgID, userID, err)
	}
	return Role(role), true, nil
}
