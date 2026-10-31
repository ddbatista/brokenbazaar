-- BrokenBazaar M2 schema: agent sessions, the message transcript, and
-- tool-call records. See threat-models/m2-agent-gateway.md (D4, D5, D7)
-- and the four T2 decisions in the implementation plan.
--
-- Naming: this migration follows the committed threat model's names,
-- which differ from docs/product-spec.md §4 in four places and add one
-- table the spec never names:
--
--   spec §4            shipped        why
--   agent_session      sessions       plural, matching orgs/users/documents
--   tool_call          tool_calls     same
--   acting_for_user_id acting_for     the threat model's D7 column name,
--                                     which the audit records also use
--   decision           route          the gate, the JSONL and the rego all
--                                     say "route"; one vocabulary end to end
--   (absent)           messages       §4 has no transcript entity at all,
--                                     though §5.1's flow says "User sends a
--                                     message" -- a gap, not a rename
--
-- Both the renames and the missing entity are queued for the v1 spec
-- revision in the implementation plan's M2 section (the vault plan is the
-- editable planning artifact; the threat-model diff is a dated record and
-- is never edited after commit).

-- Sessions are tenant-scoped rows: org_id NOT NULL with an FK, exactly
-- like documents (m1-tenancy.md D1: ownership is a storage-layer
-- invariant, not a convention). The composite FK below additionally
-- says the session's principal must be a member of the org the session
-- belongs to. That is an integrity backstop, not an authorization
-- decision: the caller still verifies membership before CreateSession
-- (SR-B2-2), and a caller that forgets gets a loud constraint error
-- instead of a silently inconsistent row.
CREATE TABLE sessions (
    id         uuid PRIMARY KEY,
    org_id     uuid NOT NULL REFERENCES orgs(id),
    acting_for uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    -- D7, no quiet partial fixes: expires_at ships for HYGIENE ONLY.
    -- Nothing in M2 consults it before acting. Time-bounding as SR-B3-4
    -- constrains it is violated-by-design and lands in M3. A column that
    -- exists but is never read is labelled as such; it never claims the
    -- requirement.
    expires_at timestamptz NOT NULL,
    FOREIGN KEY (org_id, acting_for) REFERENCES memberships (org_id, user_id)
);

-- Nothing in M2 scans sessions by org (GetSession is a primary-key
-- lookup; the session plane queries messages and tool_calls by session).
-- This index serves M3's session-plane queries, already scheduled --
-- the documents_org_id_idx precedent with the same honesty.
CREATE INDEX sessions_org_id_idx ON sessions (org_id);

-- The transcript. Two columns that mean two different things (T2 D2):
--   role   -- who authored the row. Evidence: finding 03's writeup must
--             be able to show the ASSISTANT emitted the fetch after
--             reading the document.
--   origin -- the trust class the platform assigned at entry (SR-B4-4:
--             the platform owns the labels), in the same vocabulary the
--             hardened assembler consumes. All tool output enters as
--             'untrusted' -- including read_document results from this
--             platform's own database: tenant content is the injection
--             vector, and that judgment is made once, at entry, never
--             re-derived per reader.
-- Stickiness is enforced by the absence of any update path in the store
-- (no method exists that can rewrite a row), not by a trigger.
CREATE TABLE messages (
    id         uuid PRIMARY KEY,
    session_id uuid NOT NULL REFERENCES sessions(id),
    role       text NOT NULL CHECK (role IN ('system','user','assistant','tool')),
    origin     text NOT NULL CHECK (origin IN ('system','user','untrusted')),
    body       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX messages_session_id_idx ON messages (session_id);

-- Tool-call records: the agent's transcript, with citation (T2 D3).
-- D4's JSONL audit store is the security record -- written by the gate
-- BEFORE execution, which is the causation property a row written after
-- the fact cannot carry. This table is the agent's side: queryable
-- application state (M3's B3 work is SQL over session -> tool history)
-- and the honest record of the mode difference.
--
--   route       -- what happened at the gate. 'unmediated' is the third,
--                  honest outcome: in vulnerable mode NO decision was
--                  made, and recording 'allow' would claim one was.
--                  SR-B5-9's "the vulnerable mode is not silent" as
--                  queryable state.
--   decision_id -- citation of the JSONL record for mediated calls. The
--                  CHECK makes the citation and the vocabulary agree: a
--                  row claiming mediation with no license cited is
--                  rejected by the schema itself -- D4's "the record is
--                  a license; execution is a consequence of it" as a
--                  storage constraint.
--   arguments / result_summary -- the call's arguments and a short
--                  result note. The full result bytes live in messages
--                  (the assembler reads the transcript, not this
--                  table), so tenant data is stored once, where the
--                  context comes from.
CREATE TABLE tool_calls (
    id             uuid PRIMARY KEY,
    session_id     uuid NOT NULL REFERENCES sessions(id),
    tool_name      text NOT NULL,
    arguments      jsonb NOT NULL,
    route          text NOT NULL CHECK (route IN ('allow','deny','unmediated')),
    decision_id    text,
    result_summary text,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CHECK ((route = 'unmediated') = (decision_id IS NULL))
);

CREATE INDEX tool_calls_session_id_idx ON tool_calls (session_id);

-- tool_name is deliberately NOT CHECK-constrained to M2's two tools:
-- M4 adds publisher tools, and which tools may run is the gateway's
-- allowlist decision, not a schema enumeration.
