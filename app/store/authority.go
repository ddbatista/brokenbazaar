package store

import (
	"context"
	"fmt"
	"time"
)

// SessionAuthority is everything the per-action authority checks read, in
// one row, fresh on every call (m3-delegation.md D3/D4; plan M3 T6 D1):
// the session's org and acting user, the scope it was opened with, its
// expiry, and the acting user's role in that org NOW. RoleNow is "" when the
// membership no longer exists, and an empty role permits nothing.
type SessionAuthority struct {
	SessionID string
	OrgID     string
	ActingFor string
	Scope     []string
	ExpiresAt time.Time
	RoleNow   Role
}

// SessionAuthority loads one session's authority facts by session id alone.
//
// It lives on AdminStore, not on the org-bound handle, for the reason
// SoleMembership does: its job is to RESOLVE which org a session belongs to.
// The gateway knows only the session id (it ignores the org the agent's
// payload names, D3), so there is no org to bind first. The org that comes
// back is the row's, and every later step binds it through ForOrg.
//
// The membership is LEFT JOINed: a session whose acting user has since been
// removed from the org still loads, with no role, so the role leg fails with
// role_does_not_permit -- never "no such session", which would hide the
// removal behind an operational error.
func (s *AdminStore) SessionAuthority(ctx context.Context, sessionID string) (SessionAuthority, bool, error) {
	var a SessionAuthority
	var role *string
	err := s.pool.QueryRow(ctx,
		`SELECT s.id::text, s.org_id::text, s.acting_for::text, s.scope, s.expires_at, m.role
		 FROM sessions s
		 LEFT JOIN memberships m ON m.org_id = s.org_id AND m.user_id = s.acting_for
		 WHERE s.id = $1::uuid`,
		sessionID,
	).Scan(&a.SessionID, &a.OrgID, &a.ActingFor, &a.Scope, &a.ExpiresAt, &role)
	if err != nil {
		if isNoRows(err) {
			return SessionAuthority{}, false, nil
		}
		return SessionAuthority{}, false, fmt.Errorf("store: loading authority for session %s: %w", sessionID, err)
	}
	if role != nil {
		a.RoleNow = Role(*role)
	}
	return a, true, nil
}
