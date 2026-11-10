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
// enforced, in M2 (D7: hygiene only -- SR-B3-4 is M3's, enforced from T6).
const freshSessionLifetime = time.Hour

// target is what one agent run acts on: an existing session, or a fresh
// one opened for a user's request (T7 D1).
type target struct {
	orgID     string
	sessionID string   // existing-session shape
	actingFor string   // fresh-session shape
	message   string   // fresh-session shape
	scope     []string // fresh-session shape: the tools the session may request (plan M3 T2 D4)
}

func (t target) fresh() bool { return t.sessionID == "" }

// parseTarget validates the flag combination. Exactly one shape:
//
//	-org O -session S                    run an existing session
//	-org O -acting-for U -message "..." -scope T1,T2
//	                                     open a fresh session, then run it
//
// Why the fresh shape exists (T7 D1): a session shows an attack on its
// FIRST run only -- the scripted model reads the stored transcript, so a
// re-run sees "already read, already fetched" and behaves differently.
// Exploits must run twice in a row and CI runs both modes against one
// seed, so each exploit run opens its own session. It writes through the
// same ForOrg/ForSession paved road the seed uses; the database's
// (org_id, acting_for) -> memberships foreign key refuses a user who is
// not a member of the org, loudly.
//
// -scope (plan M3 T2 D4) is required for a fresh session and refused with
// -session. Required because SR-B3-5 says a session's scope is explicitly
// requested, so there is no default to fall back on. Refused with
// -session because an existing session's scope is on its row and has no
// update path (SR-B3-6); accepting the flag would silently ignore it. The
// scope is consent, not authority (m3-delegation.md M3-N5): nothing here
// checks it against the user's role -- the per-action role leg does.
func parseTarget(orgID, sessionID, actingFor, message, scope string) (target, error) {
	message = strings.TrimSpace(message)
	if orgID == "" {
		return target{}, errors.New("-org is required")
	}
	if sessionID != "" && (actingFor != "" || message != "") {
		return target{}, errors.New("give -session OR -acting-for/-message, not both")
	}
	if sessionID != "" {
		if strings.TrimSpace(scope) != "" {
			return target{}, errors.New("-scope applies to a fresh session only: an existing session's scope is fixed on its row")
		}
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
	tools, err := parseScope(scope)
	if err != nil {
		return target{}, err
	}
	return target{orgID: orgID, actingFor: actingFor, message: message, scope: tools}, nil
}

// parseScope splits a comma-separated tool list, trimming each entry. An
// empty entry or a repeated one is refused rather than dropped: either is
// a typo in a security-relevant list, and a list that silently differs
// from what was typed is the failure this flag exists to prevent.
func parseScope(scope string) ([]string, error) {
	if strings.TrimSpace(scope) == "" {
		return nil, errors.New("a fresh session needs -scope: the comma-separated tools it may request (SR-B3-5)")
	}
	var tools []string
	seen := map[string]bool{}
	for _, raw := range strings.Split(scope, ",") {
		tool := strings.TrimSpace(raw)
		if tool == "" {
			return nil, fmt.Errorf("-scope %q has an empty entry", scope)
		}
		if seen[tool] {
			return nil, fmt.Errorf("-scope names %q twice", tool)
		}
		seen[tool] = true
		tools = append(tools, tool)
	}
	return tools, nil
}

// openFresh creates the session and stores the user's request as its
// first message, origin user -- the same two writes the seed makes.
// Not transactional: if the message write fails, an empty session row
// remains and the run stops loudly. Nothing runs against it.
func openFresh(ctx context.Context, pool *pgxpool.Pool, t target) (store.Session, error) {
	sess, err := store.ForOrg(pool, t.orgID).CreateSession(ctx, t.actingFor, t.scope, time.Now().Add(freshSessionLifetime))
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
