-- BrokenBazaar M1 schema. See threat-models/m1-tenancy.md §1 (D1).
--
-- Identifiers are UUIDv4 (SR-B2-4, first half: non-enumerable ids), generated
-- by the application in store.NewID(), never by Postgres -- so there is
-- exactly one place in the codebase that mints an id, and it is reviewable
-- Go, not a database default nobody reads.

CREATE TABLE orgs (
    id         uuid PRIMARY KEY,
    name       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id            uuid PRIMARY KEY,
    email         text NOT NULL UNIQUE,
    display_name  text NOT NULL,
    password_hash text NOT NULL
);

CREATE TABLE memberships (
    org_id  uuid NOT NULL REFERENCES orgs(id),
    user_id uuid NOT NULL REFERENCES users(id),
    role    text NOT NULL CHECK (role IN ('admin', 'member', 'viewer')),
    PRIMARY KEY (org_id, user_id)
);

-- documents.org_id is NOT NULL with a foreign key: per D1, "ownership is a
-- storage-layer invariant, not a convention." No row can exist without an
-- org, full stop. That is NOT the same claim as SR-B2-1 (every *query*
-- carries an org context) -- this constraint is what makes ownership a
-- schema property; SR-B2-1 is what makes reachability one, and it lives in
-- the store layer (app/store/document_org.go), not here. See threat model
-- §5, A8.3a/A8.3b -- the spec PR that splits those two claims apart.
CREATE TABLE documents (
    id         uuid PRIMARY KEY,
    org_id     uuid NOT NULL REFERENCES orgs(id),
    title      text NOT NULL,
    body       text NOT NULL,
    created_by uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Every tenant-scoped query in the hardened store filters on org_id; this
-- index is what keeps that filter cheap instead of a seq scan as row counts
-- grow. Not load-bearing for correctness -- only for the day the lab's
-- dataset stops being three orgs and fifteen documents.
CREATE INDEX documents_org_id_idx ON documents (org_id);
