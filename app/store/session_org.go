package store

import (
	"context"
	"fmt"
	"time"
)

// OrgStore's session-plane methods (T2 D1): sessions are org-scoped rows,
// so they belong on the org-bound handle -- ForOrg's name covers every
// table the org owns from here on. Creating and loading a session are org
// operations; everything inside one session (its transcript, its tool
// calls) lives behind ForSession (session.go), which binds both scopes.

// CreateSession creates a session acting for one user. actingFor must
// have been verified as a member of this org by the caller (SR-B2-2, the
// same contract as ForOrg itself: the authorization decision happens
// upstream, once); the schema's composite foreign key
// (org_id, acting_for) -> memberships(org_id, user_id) is the integrity
// backstop -- a caller that forgets the check gets a loud constraint
// error, never a silently inconsistent session.
//
// expiresAt is recorded, not enforced (D7, no quiet partial fixes):
// nothing in M2 consults it before acting. Time-bounding as SR-B3-4
// constrains it is violated-by-design and lands in M3; the column exists
// so M3's enforcement has real data to measure against.
func (s *OrgStore) CreateSession(ctx context.Context, actingFor string, expiresAt time.Time) (Session, error) {
	sess := Session{
		ID:        NewID(),
		OrgID:     s.orgID, // never taken from the caller (SR-B2-6 shape)
		ActingFor: actingFor,
		ExpiresAt: expiresAt,
	}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO sessions (id, org_id, acting_for, expires_at)
		 VALUES ($1::uuid, $2::uuid, $3::uuid, $4)
		 RETURNING created_at`,
		sess.ID, s.orgID, actingFor, expiresAt,
	).Scan(&sess.CreatedAt)
	if err != nil {
		return Session{}, fmt.Errorf("store: creating session for user %s in org %s: %w", actingFor, s.orgID, err)
	}
	return sess, nil
}

// GetSession loads one session by id. Both predicates in one statement
// (SR-M1-4): a session id from another org and a session id that does not
// exist produce the identical empty result from the identical query --
// there is no later step that could leak the difference.
func (s *OrgStore) GetSession(ctx context.Context, id string) (Session, bool, error) {
	var (
		sess      Session
		orgID     string
		actingFor string
	)
	err := s.pool.QueryRow(ctx,
		`SELECT id::text, org_id::text, acting_for::text, created_at, expires_at
		 FROM sessions WHERE id = $1::uuid AND org_id = $2::uuid`,
		id, s.orgID,
	).Scan(&sess.ID, &orgID, &actingFor, &sess.CreatedAt, &sess.ExpiresAt)
	if err != nil {
		if isNoRows(err) {
			return Session{}, false, nil
		}
		return Session{}, false, fmt.Errorf("store: getting session %s in org %s: %w", id, s.orgID, err)
	}
	sess.OrgID = orgID
	sess.ActingFor = actingFor
	return sess, true, nil
}
