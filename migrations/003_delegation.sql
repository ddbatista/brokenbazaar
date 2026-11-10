-- BrokenBazaar M3 schema: session scope and the role-change record.
-- See threat-models/m3-delegation.md (D4, D6, D9, M3-N3, M3-N5) and the
-- T2 decisions in the implementation plan. A bare D-number in this file
-- is the threat model's; the plan's task decisions are written "plan M3
-- T2 Dn".
--
-- What is deliberately NOT here: an org_grants table. Org grants are
-- platform policy and live in gateway/policy/data.json (D9): a policy
-- table in Postgres is B8 2.2 verbatim -- "policy lives in the database
-- beside tenant data, reachable with the same credentials" -- and the
-- agent holds those credentials (M3-N1).

-- The tools a session was created to request (SR-B3-5: explicitly
-- requested). NOT NULL with NO DEFAULT: every creator must state it, so
-- a session whose scope nobody chose cannot exist. An empty array is a
-- stated "nothing" and is allowed -- it denies every tool, which is safe.
--
-- Tool names are not CHECK-constrained, for the reason tool_calls.
-- tool_name is not (002): which tools exist is the gateway's allowlist
-- decision, not a schema enumeration, and M4 adds publisher tools.
--
-- Scope narrows; it never authorizes (M3-N5). Nothing compares it with
-- the user's role at creation -- the per-action role leg does that (D4).
-- There is no update path in the store, so a session cannot widen its own
-- scope (SR-B3-6): stickiness by the absence of a method, as with
-- messages.origin. Recorded from T2; consulted from T6.
--
-- Migrations run against a fresh database only (`make down` resets the
-- volume, and 001 uses plain CREATE TABLE), so adding a NOT NULL column
-- with no default needs no backfill.
--
-- Both creation paths outside the store (the agent's -scope flag and the
-- exploits' check_scope) refuse an empty scope, because neither has a use
-- for a session that may do nothing; only a direct store caller can state
-- one. The schema allows it because it is safe, not because anything asks.
ALTER TABLE sessions ADD COLUMN scope text[] NOT NULL;

-- One home for the role vocabulary in the schema. 001 wrote it as a CHECK
-- on memberships.role; role_changes needs it twice more, and three copies
-- of "which roles exist" drift -- the argument D4 makes for the Go
-- permission table, applied to the schema. The domain is the copy; the
-- old CHECK is dropped in the same statement that adopts it, so there is
-- never a moment with two rules. (Go's store.Role constants are the other
-- side of the language boundary and stay a second home by necessity.)
CREATE DOMAIN membership_role AS text
    CHECK (VALUE IN ('admin', 'member', 'viewer'));

ALTER TABLE memberships
    DROP CONSTRAINT memberships_role_check,
    ALTER COLUMN role TYPE membership_role;

-- Lets role_changes cite a session AND its org in one foreign key (below).
-- id is already the primary key, so this adds no new uniqueness -- only a
-- target for the composite reference, the 002 pattern for (org_id,
-- acting_for) -> memberships.
ALTER TABLE sessions ADD CONSTRAINT sessions_id_org_id_key UNIQUE (id, org_id);

-- The role-change record (SR-B8-7: every policy and configuration change
-- is an audited event, with actor, before and after). Roles are tenant
-- configuration (m3-delegation.md §3, SR-B8-1): what a session's
-- authority derives from, so changing them is non-delegable (D6) and
-- audited here, in BOTH modes -- the vulnerable build must not be silent,
-- or T10 cannot measure a miss (M2 D4's lesson).
--
-- Written by T5's store method in the same transaction as the role change
-- itself, through an org-bound handle (M3-N1). T2 creates the table only.
CREATE TABLE role_changes (
    id            uuid PRIMARY KEY,
    org_id        uuid NOT NULL REFERENCES orgs(id),
    -- NO foreign key to memberships, on purpose (M3-N3): this record must
    -- outlive the membership it describes. A FK to memberships would
    -- block removal, and the "fix" for that -- ON DELETE CASCADE -- would
    -- erase the history of the very role it recorded.
    subject       uuid NOT NULL REFERENCES users(id),
    role_before   membership_role NOT NULL,
    role_after    membership_role NOT NULL,
    -- Who made the change. actor_session is set when the change came
    -- through an agent session (finding 06's vulnerable path) and NULL
    -- when a human made it directly -- SR-B3-9's "an agent-initiated
    -- action is distinguishable from a human one", as a column.
    actor_user    uuid NOT NULL REFERENCES users(id),
    actor_session uuid,
    created_at    timestamptz NOT NULL DEFAULT now(),
    -- The session that made the change belongs to the org the change was
    -- made in. Without this, a role change in one org could cite another
    -- org's session as its actor -- attribution crossing B2. An integrity
    -- backstop like 002's composite key, not an authorization decision:
    -- T5's org-bound handle is what keeps the two consistent (M3-N1). A
    -- NULL actor_session (a human's direct change) is not checked, by the
    -- default MATCH SIMPLE rule.
    FOREIGN KEY (actor_session, org_id) REFERENCES sessions (id, org_id),
    -- A change that changes nothing is not a change, and is not recorded.
    -- The exploits set the roles they need at the start of every run
    -- (rule 5); without this, every run would log no-op "changes".
    CHECK (role_before <> role_after)
);

CREATE INDEX role_changes_org_id_idx ON role_changes (org_id);

-- No trigger forbids UPDATE or DELETE on role_changes. The only principal
-- such a trigger would stop -- one issuing SQL directly -- connects as the
-- database owner and could drop the trigger first (M3-N1, R-M3-2).
-- Append-only is enforced the way messages' stickiness is: no store
-- method can update or delete a row. SR-B8-6 is declared violated at the
-- compromise level, not defended with a mechanism that only looks like it.
