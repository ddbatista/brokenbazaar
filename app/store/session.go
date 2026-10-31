package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// M2 session-plane types and the session-scoped store. See
// threat-models/m2-agent-gateway.md (D4, D5, D7) and the T2 decisions in
// the implementation plan. The org plane -- creating and loading a
// session -- lives on OrgStore (session_org.go); everything inside one
// session lives here, behind ForSession.

// MessageRole is who authored a transcript row. Distinct from the tenancy
// Role (models.go): role is EVIDENCE -- finding 03's writeup must be able
// to show the assistant emitted the fetch after reading the document,
// which is a different claim from "a tool result containing tenant data
// exists".
type MessageRole string

const (
	MessageRoleSystem    MessageRole = "system"
	MessageRoleUser      MessageRole = "user"
	MessageRoleAssistant MessageRole = "assistant"
	MessageRoleTool      MessageRole = "tool"
)

// MessageOrigin is the trust class the platform assigned when the row
// entered the system -- SR-B4-4: the platform owns the labels. It uses
// the same vocabulary the hardened context assembler consumes
// (Span.Origin), so the stored label and the runtime span can never
// disagree. All tool output enters as untrusted, including
// read_document results from this platform's own database: tenant
// content is the injection vector, and that judgment is made once, at
// entry, never re-derived per reader.
type MessageOrigin string

const (
	MessageOriginSystem    MessageOrigin = "system"
	MessageOriginUser      MessageOrigin = "user"
	MessageOriginUntrusted MessageOrigin = "untrusted"
)

// ToolRoute records what happened at the gate for one tool call.
// ToolRouteUnmediated is the third, honest outcome: in vulnerable mode no
// decision was made, and recording "allow" would claim one was. This is
// SR-B5-9's "the vulnerable mode is not silent" as queryable state.
type ToolRoute string

const (
	ToolRouteAllow      ToolRoute = "allow"
	ToolRouteDeny       ToolRoute = "deny"
	ToolRouteUnmediated ToolRoute = "unmediated"
)

// Session is an agent session (product spec §3.3): its own principal,
// created on behalf of a user, and the thing that actually calls tools.
// In M2 it is created with every grant in scope and its authority is
// resolved at creation and never re-derived -- violated by design, with
// M3 owning the redesign (m2-agent-gateway.md D7). ExpiresAt ships for
// hygiene only: nothing in M2 consults it before acting.
type Session struct {
	ID        string
	OrgID     string
	ActingFor string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Message is one row of a session's transcript. Role and Origin are two
// axes, not one: who wrote it, and what the platform trusts it as.
// Origin is written once at insert; the store exposes no method that can
// change it, so stickiness is enforced by the absence of a write path,
// not by a trigger (T2 D2).
type Message struct {
	ID        string
	SessionID string
	Role      MessageRole
	Origin    MessageOrigin
	Body      string
	CreatedAt time.Time
}

// ToolCall is the agent's record of one tool call -- a transcript with
// citation, not an audit record. D4's JSONL store is the security record,
// written by the gate before execution; this row is written after, by the
// agent, and cites its JSONL counterpart via DecisionID. Route and
// DecisionID are kept consistent by a CHECK in the schema: a row claiming
// mediation with no license cited is rejected by the database itself.
type ToolCall struct {
	ID            string
	SessionID     string
	ToolName      string
	Arguments     string // JSON-encoded; shape is per-tool
	Route         ToolRoute
	DecisionID    *string // set iff Route != unmediated (schema CHECK)
	ResultSummary *string // short note; the full bytes live in messages
	CreatedAt     time.Time
}

// SessionStore reaches exactly one session's messages and tool calls --
// and only inside the org bound at construction. Both scopes are handle
// properties (T2 D1): no method here takes an org or a session id, so no
// call site can supply them differently from the constructor. There is
// deliberately no naive sibling implementation and no interface: M2's
// findings (03, 04) live in mediation, not in session scoping, and an
// interface with one implementation is ceremony -- M1's DocumentStore
// interface exists because two implementations share it.
type SessionStore struct {
	pool      *pgxpool.Pool
	orgID     string
	sessionID string
}

// ForSession returns the session-plane store for one session in one org.
// The pair states the same fact twice (the session row already knows its
// org) -- twice on purpose: every statement this type runs carries BOTH
// predicates, so a handle built from a mismatched (org, session) pair
// reads as not-found and writes as zero-rows-inserted. That is the
// SR-M1-4 property one level down: wrong org and no such session are the
// identical outcome, and the safe one.
func ForSession(pool *pgxpool.Pool, orgID, sessionID string) *SessionStore {
	return &SessionStore{pool: pool, orgID: orgID, sessionID: sessionID}
}

// AppendMessage adds one transcript row. The INSERT is a SELECT from
// sessions constrained on both the session and the org: if the handle's
// (org, session) pair does not name a real session, the SELECT is empty,
// nothing inserts, and the caller gets a loud error rather than a
// message attached to a session it had no right to touch.
func (s *SessionStore) AppendMessage(ctx context.Context, msg Message) (Message, error) {
	msg.ID = NewID()
	msg.SessionID = s.sessionID
	err := s.pool.QueryRow(ctx,
		`INSERT INTO messages (id, session_id, role, origin, body)
		 SELECT $1::uuid, s.id, $2, $3, $4
		 FROM sessions s
		 WHERE s.id = $5::uuid AND s.org_id = $6::uuid
		 RETURNING created_at`,
		msg.ID, string(msg.Role), string(msg.Origin), msg.Body, s.sessionID, s.orgID,
	).Scan(&msg.CreatedAt)
	if err != nil {
		return Message{}, fmt.Errorf("store: appending %s message to session %s in org %s: %w",
			msg.Role, s.sessionID, s.orgID, err)
	}
	return msg, nil
}

// Messages returns the transcript in a stable total order (created_at,
// then id as the tie-break -- ids are random, so a tie breaks arbitrarily
// but identically on every read, which is what deterministic assembly
// needs). The JOIN through sessions carries the org predicate on every
// read, the same property AppendMessage enforces on writes.
func (s *SessionStore) Messages(ctx context.Context) ([]Message, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT m.id::text, m.session_id::text, m.role, m.origin, m.body, m.created_at
		 FROM messages m
		 JOIN sessions s ON s.id = m.session_id
		 WHERE m.session_id = $1::uuid AND s.org_id = $2::uuid
		 ORDER BY m.created_at, m.id`,
		s.sessionID, s.orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("store: listing messages for session %s in org %s: %w", s.sessionID, s.orgID, err)
	}
	defer rows.Close()
	var msgs []Message
	for rows.Next() {
		var (
			m      Message
			role   string
			origin string
		)
		if err := rows.Scan(&m.ID, &m.SessionID, &role, &origin, &m.Body, &m.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: scanning message row: %w", err)
		}
		m.Role = MessageRole(role)
		m.Origin = MessageOrigin(origin)
		msgs = append(msgs, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating message rows: %w", err)
	}
	return msgs, nil
}

// AppendToolCall records one tool call from the agent's side. Same
// insert-via-select property as AppendMessage; the schema's CHECK
// (route = 'unmediated') = (decision_id IS NULL) is the storage-layer
// echo of D4: a mediated call must cite the license record that
// pre-authorized it.
func (s *SessionStore) AppendToolCall(ctx context.Context, call ToolCall) (ToolCall, error) {
	call.ID = NewID()
	call.SessionID = s.sessionID
	err := s.pool.QueryRow(ctx,
		`INSERT INTO tool_calls (id, session_id, tool_name, arguments, route, decision_id, result_summary)
		 SELECT $1::uuid, s.id, $2, $3::jsonb, $4, $5, $6
		 FROM sessions s
		 WHERE s.id = $7::uuid AND s.org_id = $8::uuid
		 RETURNING created_at`,
		call.ID, call.ToolName, call.Arguments, string(call.Route), call.DecisionID, call.ResultSummary, s.sessionID, s.orgID,
	).Scan(&call.CreatedAt)
	if err != nil {
		return ToolCall{}, fmt.Errorf("store: recording %s tool call in session %s in org %s: %w",
			call.ToolName, s.sessionID, s.orgID, err)
	}
	return call, nil
}

// ToolCalls returns the session's tool-call history (M3's B3 work is SQL
// over exactly this), in the same stable order as Messages.
func (s *SessionStore) ToolCalls(ctx context.Context) ([]ToolCall, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT t.id::text, t.session_id::text, t.tool_name, t.arguments::text, t.route,
		        t.decision_id, t.result_summary, t.created_at
		 FROM tool_calls t
		 JOIN sessions s ON s.id = t.session_id
		 WHERE t.session_id = $1::uuid AND s.org_id = $2::uuid
		 ORDER BY t.created_at, t.id`,
		s.sessionID, s.orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("store: listing tool calls for session %s in org %s: %w", s.sessionID, s.orgID, err)
	}
	defer rows.Close()
	var calls []ToolCall
	for rows.Next() {
		var (
			t     ToolCall
			route string
		)
		if err := rows.Scan(&t.ID, &t.SessionID, &t.ToolName, &t.Arguments, &route,
			&t.DecisionID, &t.ResultSummary, &t.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: scanning tool call row: %w", err)
		}
		t.Route = ToolRoute(route)
		calls = append(calls, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating tool call rows: %w", err)
	}
	return calls, nil
}
