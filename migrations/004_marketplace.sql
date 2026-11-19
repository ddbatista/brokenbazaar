-- BrokenBazaar M4a schema: the marketplace plane (B6).
-- See threat-models/m4a-marketplace.md (D1, D3, D4, D8, D10) and the T2
-- decisions in the implementation plan. A bare D-number in this file is
-- the threat model's; the plan's task decisions are written "plan M4a
-- T2 Dn".
--
-- THE MANIFEST FORMAT, stated once because three artifacts must agree on
-- it byte for byte: the manifest is a tools/list response body -- a JSON
-- object {"tools": [{"name", "description", "receives": [...]}]}. The
-- listing's advertised copy, the install's pinned copy and the fixture's
-- served copy are all this shape. Pinning is over RAW BYTES: the digest is
-- sha256 of exactly the bytes fetched, never of a re-serialized form.
-- Rejected here: canonical-JSON hashing. Go and Python canonicalize the
-- same document differently (key order is shared, number formatting is
-- not), and a cross-language canonical form is a false-drift bug waiting
-- to happen; raw bytes are what the org reviewed (D3: "pin the bytes, not
-- a pointer"). The manifest vocabulary is strings and arrays only, so
-- there are no numbers for the two languages to disagree about.
--
-- What is deliberately NOT here, each an absence as a decision:
--
-- * No org_grants change. Installs are tenant data read through the
--   authority route, not policy in Postgres (D9's inheritance answered,
--   m4a D1): putting them in policy data would break the product
--   (installs are runtime), putting them in a policy table would be B8
--   2.2 verbatim. The agent's credential can still write these tables
--   (R-M4a-5) and the database-role split remains the recorded fix.
--
-- * No consent column. The consent vocabulary lives inside the pinned
--   manifest bytes -- each tool declares its "receives". A copied column
--   would be a second home that could disagree with the bytes it
--   summarizes; the one home is the pin (D4).
--
-- * No stored "needs_reapproval" status. Drift is computed per call by
--   the gateway against the pin; re-approval is a fresh pin written by an
--   admin (plan M4a T2's resolution of the diff's SR-B8-8 wording: the
--   old grant is never resumed -- a reinstall pins the bytes it fetches
--   at that moment, which IS the fresh consent; the old row stays as a
--   tombstone). Two statuses exist: active and uninstalled.
--
-- * No ON DELETE clause anywhere, and no DELETE path at all. M3-N3's
--   rule: tombstones, never cascades -- an uninstall flips status, and
--   the install's audit rows outlive it by construction.

-- Publishers: a new principal class (m4a D1). Registration is open and
-- unvetted -- baseline B6 5.2, accepted by design, the product decision
-- the module's premise stands on. Identity is the uuid; the display name
-- is advisory and may collide (SR-B6-6: namespaced identity, no name
-- directory exists to squat -- B6 1.3 not reachable). No credential
-- column: the token minted at registration IS the credential, same shape
-- as users; there is no recovery flow to attack (B6 5.1 out of scope).
CREATE TABLE publishers (
    id           uuid PRIMARY KEY,
    display_name text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- Catalog listings: platform-level, written only through a publisher's
-- scoped handle, read by everyone. The manifest here is the ADVERTISED
-- copy the publisher posted; an install pins the bytes it FETCHED from
-- the server at install time, and the two are expected to agree until a
-- rug pull makes them disagree (baseline leaves 2.1 vs 2.2). manifest is
-- TEXT, not jsonb: the pin is over bytes and jsonb would silently
-- re-format them; the CHECK casts to jsonb so a manifest that is not
-- JSON is refused loudly here as well as in the route (SR-B6-7's bounded
-- parsing is the route's job -- size and depth caps -- this is only the
-- syntax floor).
--
-- No version-history table for items: catalog_mutations below IS the
-- history (count its rows for this item). version is a display counter
-- maintained by the same store transaction that writes the mutation row,
-- so the counter and the history cannot disagree (one home, M3 D4's
-- argument applied to bookkeeping).
CREATE TABLE catalog_items (
    id              uuid PRIMARY KEY,
    publisher_id    uuid NOT NULL REFERENCES publishers(id),
    name            text NOT NULL,
    endpoint_url    text NOT NULL,
    manifest        text NOT NULL CHECK (manifest::jsonb IS NOT NULL),
    manifest_digest text NOT NULL,
    version         integer NOT NULL DEFAULT 1,
    published_at    timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX catalog_items_publisher_id_idx ON catalog_items (publisher_id);

-- Every catalog mutation, immutably, with actor, before, after and
-- timestamp (SR-B6-8): the record a rug pull leaves behind. before/after
-- are TEXT -- the raw manifest bytes, same rule as catalog_items.
--
-- Append-only by the absence of an update path in the store's method
-- set, the same stickiness as role_changes: a trigger would only stop a
-- principal who connects as the database owner and could drop the
-- trigger first (R-M3-2's reasoning, unchanged).
--
-- An update that changes nothing is refused by CHECK, mirroring
-- role_changes: a mutation row that says "same" is a false record.
CREATE TABLE catalog_mutations (
    id               uuid PRIMARY KEY,
    item_id          uuid NOT NULL REFERENCES catalog_items(id),
    actor_publisher  uuid NOT NULL REFERENCES publishers(id),
    mutation         text NOT NULL CHECK (mutation IN ('publish', 'update')),
    before           text,
    after            text NOT NULL CHECK (after::jsonb IS NOT NULL),
    created_at       timestamptz NOT NULL DEFAULT now(),
    CHECK ((mutation = 'publish' AND before IS NULL)
        OR (mutation = 'update' AND before IS NOT NULL AND before IS DISTINCT FROM after))
);

CREATE INDEX catalog_mutations_item_id_idx ON catalog_mutations (item_id);

-- Installs: the org's consent decision, org-scoped tenant data (D1/D3).
-- This row IS the pin. pinned_manifest holds the raw bytes fetched from
-- the server at install time; pinned_digest is their sha256; the
-- hardened path serves and executes from this row and nowhere else
-- (SR-B6-1, SR-B6-3). The vulnerable build writes the same row and then
-- ignores it -- the advisory pin, the planted bug (finding 08).
--
-- endpoint_url is copied from the listing at install (what the org saw);
-- endpoint_address is the address the endpoint resolved to at that
-- moment, recorded so the gateway can compare at dial time (rebinding:
-- a mid-session DNS flip is a mismatch, not a redirect). Resolution is
-- recorded, not classified: the range classifier exists in exactly one
-- copy (gateway/tools/fetch.py) and stays there -- a Go port would be
-- the two-homes drift this repo argues against. Structural endpoint
-- validation is the route's (T3); the range leg is the gateway's (T5).
-- Plan M4a T2 records this as the implementing resolution of the diff's
-- "install-time endpoint classification" line.
--
-- The composite FK is the M2/M3 integrity backstop, not the
-- authorization: a caller that forgets the admin check upstream gets a
-- loud constraint error for a non-member installer, while the role
-- check itself is the route's (D8: installs are control-plane,
-- admin-only in both builds).
CREATE TABLE installs (
    id               uuid PRIMARY KEY,
    org_id           uuid NOT NULL REFERENCES orgs(id),
    item_id          uuid NOT NULL REFERENCES catalog_items(id),
    installed_by     uuid NOT NULL,
    installed_at     timestamptz NOT NULL DEFAULT now(),
    pinned_manifest  text NOT NULL CHECK (pinned_manifest::jsonb IS NOT NULL),
    pinned_digest    text NOT NULL,
    endpoint_url     text NOT NULL,
    endpoint_address text NOT NULL,
    status           text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'uninstalled')),
    FOREIGN KEY (org_id, installed_by) REFERENCES memberships (org_id, user_id)
);

-- One ACTIVE install per (org, item). Uninstalling clears the way for a
-- reinstall that pins the bytes fetched at THAT moment (SR-B8-8:
-- re-consented, never resumed); the tombstone rows accumulate as
-- history and install_changes below carries what each one granted.
CREATE UNIQUE INDEX one_active_install_per_org_item
    ON installs (org_id, item_id) WHERE status <> 'uninstalled';

CREATE INDEX installs_org_id_idx ON installs (org_id);

-- Every install-plane mutation, immutably, with actor, before and after
-- (SR-B8-7): installed (before NULL -- nothing preceded it),
-- uninstalled (after NULL -- the grant ends; the before bytes preserve
-- exactly what it was), reapproved (before and after -- the pin
-- advancing to bytes an admin accepted after drift). Actor is a user,
-- always: no agent tool, grammar rule or internal route exists for any
-- of these verbs (D8), so there is no session column -- the absence is
-- the control's shadow, and a future module that adds an agent path to
-- any of these verbs must add the column and answer for it here.
CREATE TABLE install_changes (
    id          uuid PRIMARY KEY,
    install_id  uuid NOT NULL REFERENCES installs(id),
    org_id      uuid NOT NULL REFERENCES orgs(id),
    actor_user  uuid NOT NULL,
    mutation    text NOT NULL CHECK (mutation IN ('installed', 'uninstalled', 'reapproved')),
    before      text,
    after       text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CHECK ((mutation = 'installed'   AND before IS NULL AND after IS NOT NULL)
        OR (mutation = 'uninstalled' AND before IS NOT NULL AND after IS NULL)
        OR (mutation = 'reapproved'  AND before IS NOT NULL AND after IS NOT NULL
                                AND before IS DISTINCT FROM after)),
    FOREIGN KEY (org_id, actor_user) REFERENCES memberships (org_id, user_id)
);

CREATE INDEX install_changes_install_id_idx ON install_changes (install_id);
CREATE INDEX install_changes_org_id_idx ON install_changes (org_id);

-- No table here references sessions, and nothing agent-reachable reads
-- or writes any of these five: the authority route (T5) is the only
-- conduit install facts reach the gateway through, and it runs under
-- the service secret (D1's answer to D9's inheritance).
