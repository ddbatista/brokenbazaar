package store

import (
	"context"
	"errors"
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

// ErrNoMembership and ErrAmbiguousMembership are the two ways SoleMembership
// cannot name a single acting org for a user.
var (
	ErrNoMembership        = errors.New("store: user holds no membership")
	ErrAmbiguousMembership = errors.New("store: user holds more than one membership")
)

// SoleMembership returns the org and role of the user's *single* membership.
// POST /auth/token's request carries only an email and password -- no org_id
// (that is deliberate; see the handler) -- so the acting org for the minted
// token has to be resolved server-side, and in M1 it is resolved from the one
// membership each seeded user has.
//
// If the user has zero or more than one membership this returns an error
// rather than guessing. Multi-org login -- one person choosing which of
// several orgs to act as at token-issue time -- is out of scope for M1 and
// deferred, the same way the threat-model diff defers SR-B1-6 (rate limiting)
// and SR-M1-5 (the org_id claim): named here in writing rather than silently
// not handled. It lands with the session work in M3, where "principal"
// becomes a type rather than a word.
//
// This is a server-side lookup against records the API owns (SR-B2-2): the
// org binding on the issued token derives from the memberships table, never
// from anything the caller supplied.
func (s *AdminStore) SoleMembership(ctx context.Context, userID string) (orgID string, role Role, err error) {
	rows, err := s.pool.Query(ctx,
		`SELECT org_id::text, role FROM memberships WHERE user_id = $1::uuid`,
		userID,
	)
	if err != nil {
		return "", "", fmt.Errorf("store: listing memberships for user %s: %w", userID, err)
	}
	defer rows.Close()

	var found int
	for rows.Next() {
		found++
		if found > 1 {
			// We fail as soon as a second row appears. A user with two
			// memberships is the deferred multi-org case.
			return "", "", fmt.Errorf("store: user %s: %w", userID, ErrAmbiguousMembership)
		}
		var roleStr string
		if err := rows.Scan(&orgID, &roleStr); err != nil {
			return "", "", fmt.Errorf("store: scanning membership for user %s: %w", userID, err)
		}
		role = Role(roleStr)
	}
	if err := rows.Err(); err != nil {
		return "", "", fmt.Errorf("store: iterating memberships for user %s: %w", userID, err)
	}
	if found == 0 {
		return "", "", fmt.Errorf("store: user %s: %w", userID, ErrNoMembership)
	}
	return orgID, role, nil
}
