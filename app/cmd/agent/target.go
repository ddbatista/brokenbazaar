package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ddbatista/brokenbazaar/app/store"
)

// freshSessionLifetime matches the seed's. expires_at is recorded, never
// enforced, in M2 (D7: hygiene only -- SR-B3-4 is M3's).
const freshSessionLifetime = time.Hour

// target is what one agent run acts on: an existing session, or a fresh
// one opened for a user's request (T7 D1).
type target struct {
	orgID     string
	sessionID string // existing-session shape
	actingFor string // fresh-session shape
	message   string // fresh-session shape
}

func (t target) fresh() bool { return t.sessionID == "" }

// parseTarget validates the flag combination. Exactly one shape:
//
//	-org O -session S                    run an existing session
//	-org O -acting-for U -message "..."  open a fresh session, then run it
//
// Why the fresh shape exists (T7 D1): a session shows an attack on its
// FIRST run only -- the scripted model reads the stored transcript, so a
// re-run sees "already read, already fetched" and behaves differently.
// Exploits must run twice in a row and CI runs both modes against one
// seed, so each exploit run opens its own session. It writes through the
// same ForOrg/ForSession paved road the seed uses; the database's
// (org_id, acting_for) -> memberships foreign key refuses a user who is
// not a member of the org, loudly.
func parseTarget(orgID, sessionID, actingFor, message string) (target, error) {
	message = strings.TrimSpace(message)
	if orgID == "" {
		return target{}, errors.New("-org is required")
	}
	if sessionID != "" && (actingFor != "" || message != "") {
		return target{}, errors.New("give -session OR -acting-for/-message, not both")
	}
	if sessionID != "" {
		return target{orgID: orgID, sessionID: sessionID}, nil
	}
	switch {
	case actingFor == "" && message == "":
		return target{}, errors.New("give -session to run an existing session, or -acting-for and -message to open a fresh one")
	case actingFor == "":
		return target{}, errors.New("-message needs -acting-for: a session is opened on behalf of a user (D7)")
	case message == "":
		return target{}, errors.New("-acting-for needs a non-blank -message: a fresh session starts from the user's request")
	}
	return target{orgID: orgID, actingFor: actingFor, message: message}, nil
}

// openFresh creates the session and stores the user's request as its
// first message, origin user -- the same two writes the seed makes.
// Not transactional: if the message write fails, an empty session row
// remains and the run stops loudly. Nothing runs against it.
func openFresh(ctx context.Context, pool *pgxpool.Pool, t target) (store.Session, error) {
	sess, err := store.ForOrg(pool, t.orgID).CreateSession(ctx, t.actingFor, time.Now().Add(freshSessionLifetime))
	if err != nil {
		return store.Session{}, err
	}
	if _, err := store.ForSession(pool, t.orgID, sess.ID).AppendMessage(ctx, store.Message{
		Role:   store.MessageRoleUser,
		Origin: store.MessageOriginUser,
		Body:   t.message,
	}); err != nil {
		return store.Session{}, fmt.Errorf("storing the request in fresh session %s: %w", sess.ID, err)
	}
	return sess, nil
}
