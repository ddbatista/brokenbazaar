-- BrokenBazaar M4b schema: the skills plane (B9).
-- See threat-models/m4b-skills.md (D0, D1, D2, D3 and §3's rows for
-- SR-B9-1, SR-B9-2, SR-B9-10, SR-B9-11) and the T2 decisions in the
-- implementation plan. A bare D-number is the threat model's.
--
-- THE BUNDLE FORMAT, stated once because three artifacts must agree on
-- it byte for byte: a skill's artifact is the full SKILL.md bytes --
-- YAML frontmatter (name, description, triggers, capabilities,
-- references) above a --- line, body below. The listing's advertised
-- copy, the install's pinned copy and the fixture's served copy are all
-- this shape. Pinning is over RAW BYTES, exactly as 004 pinned MCP
-- manifests (m4a D3): the digest is sha256 of the posted bytes, never
-- of a re-serialized form. The frontmatter is parsed by ONE parser
-- (package app/skill, normative as mcp.Parse is for manifests) and the
-- parse of the PINNED bytes is stored beside the pin at install (the
-- skill_index below) -- so the string the admin reviewed at S3 and the
-- string the agent's index renders at S6 are one stored string, not
-- two renderings that could disagree (SR-B9-13's single rendering,
-- by construction rather than by hope).
--
-- What is deliberately NOT here, each an absence as a decision:
--
-- * No capabilities-enforcement column on any table, and no "caps" row
--   in policy data. The ceiling is INTERSECTED at tool-call time in the
--   gate's leg 4 (m4b D1): the session scope meets the loaded skills'
--   declared caps, per call, never cached. A column the gate consulted
--   would be the capability token M3's D3 deleted -- cached authority
--   the demotion walks through. The one home for a skill's caps is the
--   pinned frontmatter bytes; skill_index is the parse of those bytes
--   and is recomputed only when the pin advances (install, reapprove),
--   never at read.
--
-- * No consent column, for the reason 004 stated: the vocabulary lives
--   inside the pinned bytes. The caps vocabulary mirrors the manifest
--   "receives" design (m4b §3) -- declared at publish, enforced at one
--   leg, understatement buys less (SR-B9-2's own words).
--
-- * No skill_loads table. A load is an event, not a state: T5 writes
--   load events to the audit log with session, org, tenant, trigger and
--   digest (SR-B9-6), and T8's detections read the log. State here
--   would be a second home for what the log already records.
--
-- * No triggers-validation column. A trigger is natural language; the
--   baseline's branch-2 note says maliciousness is not a property of
--   the string, and any column claiming to check it would be a lie in
--   this schema (m4b §6's accepted residual).
--
-- * No DELETE path anywhere; tombstones only, exactly as 004.

-- SR-B9-11: "first-party is a precedence value, never an exemption."
-- The value's home is the PUBLISHER row, because the platform decides
-- which publishers are its own -- a publisher cannot claim the class.
-- The seeded platform publisher is the only row that will hold true;
-- the route never accepts it as an input (the seed writes it).
ALTER TABLE publishers
    ADD COLUMN is_platform boolean NOT NULL DEFAULT false;

-- The listing gains its artifact type (plan M4b Build line). The
-- manifest column's meaning widens to "the artifact as posted": for
-- mcp_server it stays the tools/list JSON envelope (004's syntax floor
-- holds, constraint swapped for the type-aware form below); for a
-- skill it is the raw SKILL.md bytes, whose syntax authority is the
-- app/skill parser at publish, not a JSON cast here.
--
-- The old constraint (manifest::jsonb IS NOT NULL) is REPLACED, not
-- dropped: the floor is now type-aware. The two artifact kinds hold
-- different syntax and the schema says so loudly.
ALTER TABLE catalog_items
    ADD COLUMN type text NOT NULL DEFAULT 'mcp_server'
        CHECK (type IN ('mcp_server', 'skill'));

ALTER TABLE catalog_items DROP CONSTRAINT catalog_items_manifest_check;

ALTER TABLE catalog_items ADD CONSTRAINT manifest_shape_check
    CHECK ((type = 'mcp_server' AND manifest::jsonb IS NOT NULL)
        OR (type = 'skill'));

-- A skill has no single MCP endpoint: its fetch surface is the
-- frontmatter's declared references, and THAT list is what leg 7 and
-- the reference-digest rule (T5) will consult. The empty endpoint is
-- the stated absence, not a placeholder that could be mistaken for a
-- dial target.
ALTER TABLE catalog_items ADD CONSTRAINT endpoint_by_type_check
    CHECK ((type = 'mcp_server' AND endpoint_url <> '')
        OR (type = 'skill' AND endpoint_url = ''));

-- catalog_mutations' before/after lose 004's JSON floor, deliberately:
-- the mutation rows carry the bytes of whatever artifact kind the item
-- is, and the syntax authority for those bytes is the item's own
-- type-aware parse (the route calls app/skill for skills, mcp.Parse for
-- manifests) -- a JSON cast here would refuse exactly the skill
-- histories this module exists to record, and the found-live proof is
-- that the first skill publish died on it. The mutation table's job is
-- FIDELITY (the exact before and after bytes), not validation; the
-- item row's constraint remains the syntax floor for its kind.
ALTER TABLE catalog_mutations DROP CONSTRAINT catalog_mutations_after_check;

-- Installs pin whichever artifact kind the item was. item_type is
-- copied at install, like endpoint_url is: the org's record of WHAT
-- they installed, read back without a join. The pinned_manifest
-- constraint is replaced with the type-aware floor -- the old JSON
-- cast was 004's syntax floor for manifests only; a skill's pinned
-- bytes are SKILL.md, and the parser at install is their authority.
ALTER TABLE installs
    ADD COLUMN item_type text NOT NULL DEFAULT 'mcp_server'
        CHECK (item_type IN ('mcp_server', 'skill'));

ALTER TABLE installs DROP CONSTRAINT installs_pinned_manifest_check;

ALTER TABLE installs ADD CONSTRAINT pinned_shape_check
    CHECK ((item_type = 'mcp_server' AND pinned_manifest::jsonb IS NOT NULL)
        OR (item_type = 'skill'));

-- The parse of the pinned bytes, stored when the pin is written and
-- recomputed only then: name, description, triggers, capabilities,
-- references, body. NULL for MCP installs. This is a rendering, not a
-- second truth: the pin is the truth, and every reader (S3's review
-- answer, S6's index answer, S8's loader) renders from THIS jsonb so
-- there is only ever one string in flight per field (SR-B9-13). The
-- re-hash before every load (SR-B9-1, m4b D2) runs against the pinned
-- BYTES; this column is never consulted for integrity, only for
-- content -- the digest's one home stays pinned_digest.
ALTER TABLE installs
    ADD COLUMN skill_index jsonb
        CHECK (item_type = 'skill' OR skill_index IS NULL);

-- The S5 plane (baseline spine, step 5): a MEMBER authorises an
-- already-installed skill for their own sessions. The admin's install
-- review stays the only entry to the org's index (SR-B9-10); this table
-- is the member's own trust decision, which M4b-N4 records as
-- honestly attackable -- bounded by the same legs as every load.
--
-- No session column, for 004's reason verbatim: the authorising verbs
-- are control-plane, no agent tool or grammar rule reaches them (the
-- absence is the control's shadow, and a future module that adds a
-- session path must answer for it here). Actor is the user themselves;
-- revoke is a status flip (M3-N3's tombstones, never cascades).
CREATE TABLE skill_authorisations (
    id            uuid PRIMARY KEY,
    org_id        uuid NOT NULL REFERENCES orgs(id),
    install_id    uuid NOT NULL REFERENCES installs(id),
    user_id       uuid NOT NULL,
    status        text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    authorised_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (org_id, user_id) REFERENCES memberships (org_id, user_id)
);

-- One ACTIVE authorisation per (install, user). Re-authorising after
-- a revoke writes a new row; the old rows accumulate as history.
CREATE UNIQUE INDEX one_active_authorisation_per_install_user
    ON skill_authorisations (install_id, user_id) WHERE status <> 'revoked';

CREATE INDEX skill_authorisations_user_idx ON skill_authorisations (user_id);

-- Every authorisation-plane mutation, immutably, with actor and time
-- (004's install_changes shape, one table per control plane):
-- authorised (the member's own decision) and revoked (their own
-- retreat). before/after are absent because the decision has no bytes
-- to record -- it grants nothing the install did not already hold; it
-- narrows WHOSE sessions see the skill at all.
CREATE TABLE skill_authorisation_changes (
    id         uuid PRIMARY KEY,
    auth_id    uuid NOT NULL REFERENCES skill_authorisations(id),
    org_id     uuid NOT NULL REFERENCES orgs(id),
    actor_user uuid NOT NULL,
    mutation   text NOT NULL CHECK (mutation IN ('authorised', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (mutation = 'authorised' OR mutation = 'revoked'),
    FOREIGN KEY (org_id, actor_user) REFERENCES memberships (org_id, user_id)
);

CREATE INDEX skill_authorisation_changes_auth_id_idx
    ON skill_authorisation_changes (auth_id);

-- Nothing here references sessions, and nothing agent-reachable reads
-- or writes any of it: the authority route (T5) is the only conduit
-- skill facts reach the gateway through, under the service secret --
-- the same answer 004 gave D9's inheritance question.
