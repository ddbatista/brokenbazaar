package store

import (
	"context"
	"fmt"
)

// RoleActor is who made a role change (SR-B8-7, SR-B3-9). Session is the
// agent session the change came through, or "" when a human made it
// directly -- the column role_changes.actor_session, NULL for a human.
type RoleActor struct {
	User    string
	Session string
}

// RoleChange is the outcome of SetMemberRole. Changed is false when the
// subject already held the role: nothing was written, and no audit row
// exists for it (role_changes refuses a change that changes nothing).
type RoleChange struct {
	OrgID   string
	Subject string
	Before  Role
	After   Role
	Changed bool
}

// SetMemberRole sets subject's role in this org and records the change,
// in ONE transaction, on the org-bound handle. That is M3-N1's acceptance
// criterion for T5, stated in the threat model so it would not be a
// code-review discovery: the first tenant-scoped write to memberships and
// the new org-scoped audit table both go through ForOrg, never through
// AdminStore (unscoped by design) or the raw pool.
//
// One transaction because the change and its record are one fact. A role
// that changed with no row would be a silent change (SR-B8-7); a row with
// no change would be a false record. The membership row is locked first,
// so two concurrent changes cannot both read the same "before".
//
// The org comes from the handle, never from the caller, in every
// statement: a subject who is a member of a DIFFERENT org is simply not
// found here (found=false), the same shape as a wrong-org document.
//
// Authorization is the caller's, as with every ForOrg method: this type
// does not ask whether the actor may change roles. The direct route asks
// (authz.SetMemberRole); the vulnerable agent's set_member_role does not,
// which is finding 06.
func (s *OrgStore) SetMemberRole(ctx context.Context, subject string, role Role, actor RoleActor) (RoleChange, bool, error) {
	if !role.Valid() {
		return RoleChange{}, false, fmt.Errorf("store: unknown role %q", role)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return RoleChange{}, false, fmt.Errorf("store: beginning role change in org %s: %w", s.orgID, err)
	}
	// Rolls back whatever has not been committed; after Commit it is a
	// no-op.
	defer func() { _ = tx.Rollback(ctx) }()

	var before string
	err = tx.QueryRow(ctx,
		`SELECT role FROM memberships
		 WHERE org_id = $1::uuid AND user_id = $2::uuid
		 FOR UPDATE`,
		s.orgID, subject,
	).Scan(&before)
	if err != nil {
		if isNoRows(err) {
			return RoleChange{}, false, nil
		}
		return RoleChange{}, false, fmt.Errorf("store: reading role of %s in org %s: %w", subject, s.orgID, err)
	}

	change := RoleChange{OrgID: s.orgID, Subject: subject, Before: Role(before), After: role}
	if change.Before == role {
		return change, true, nil
	}

	if _, err := tx.Exec(ctx,
		`UPDATE memberships SET role = $3
		 WHERE org_id = $1::uuid AND user_id = $2::uuid`,
		s.orgID, subject, string(role),
	); err != nil {
		return RoleChange{}, false, fmt.Errorf("store: setting role of %s in org %s: %w", subject, s.orgID, err)
	}

	// actor_session is NULL for a human's direct change. The composite
	// foreign key (actor_session, org_id) -> sessions keeps an agent
	// session inside this org -- an integrity backstop, not the
	// authorization (migration 003).
	var session *string
	if actor.Session != "" {
		session = &actor.Session
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO role_changes (id, org_id, subject, role_before, role_after, actor_user, actor_session)
		 VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6::uuid, $7::uuid)`,
		NewID(), s.orgID, subject, before, string(role), actor.User, session,
	); err != nil {
		return RoleChange{}, false, fmt.Errorf("store: recording role change of %s in org %s: %w", subject, s.orgID, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return RoleChange{}, false, fmt.Errorf("store: committing role change of %s in org %s: %w", subject, s.orgID, err)
	}
	change.Changed = true
	return change, true, nil
}
