-- 0067_scim_provisioning: the identity provider provisions this hub over SCIM
-- 2.0, and disabling an account there reaches the hub without an administrator
-- (Task 20415).
--
-- Before this, "Somebody leaves" in the runbook began with a sentence the hub
-- could not change: disabling an account at the identity provider does not, on
-- its own, sever anything the hub has already issued. Sessions ran to their
-- absolute TTL, API tokens to their ExpiresAt, glasses links for up to 30
-- days, and leases, running tasks, memberships and stored credentials until an
-- administrator ran `cloop hub user offboard`. Entra ID and Okta close that gap
-- with SCIM provisioning; these tables are what the hub keeps of it.
--
-- Every statement is additive (schema_compat.go): new tables, plain indexes,
-- and four appended columns with defaults. A hub built before this keeps
-- opening the database and simply knows nothing of SCIM.
--
-- # sessions: two columns
--
--   username  the preferred_username claim the session signed in with
--   oid       Microsoft Entra ID's oid claim, lowercased
--
-- What ui.oidc.scim.match_claim matches a provisioned user against when it is
-- preferred_username or oid, and what the deny binding written when that user
-- is deactivated names. Empty for a provider that released neither and for
-- every session signed in before this migration.
--
-- # broker_grants: two columns
--
--   suspended_at  when the grant was suspended because its owner was
--                 deactivated at the identity provider; '' while it is not
--   suspended_by  who suspended it: scim:<credential name>
--
-- A suspension is not a revocation. A revoked grant stays revoked; a suspended
-- one is lifted again when the identity provider reactivates the account. Only
-- grants over the person's own personal secrets are suspended, and the lift
-- touches only grants this hub's SCIM directory suspended. A hub built before
-- this column does not read it, and would lease a suspended grant: run every
-- member of a provisioned hub on this build or later.
--
-- # scim_users, scim_groups, scim_group_members
--
-- The directory as the identity provider last described it. resource_json is
-- the resource as provisioned — every attribute, including the enterprise
-- extension and anything an identity provider's validator invents — less the
-- server-assigned id and meta, and less any password, which is never stored.
-- The typed columns are what the hub filters and decides on:
--
--   user_name_key      userName, lowercased: RFC 7643 makes userName unique
--                      and not case-exact
--   external_id(_key)  the provider's own id for the account; _key lowercased
--   email              the primary email, lowercased: emails[primary], else
--                      the work address, else the first, else an
--                      address-shaped userName
--   active             what the provider last said
--   deactivated_at     when it last went from active to inactive — the clock
--                      ui.oidc.scim.offboard_after_days runs from
--   suspension_json    what the suspension wrote and may lift again: the deny
--                      bindings it created and the grants it suspended. The
--                      lift removes those and nothing else — never a deny an
--                      administrator wrote for the same identity
--   offboarded_at      when the full offboarding ran for this account, after
--                      offboard_after_days; a later reactivation lifts nothing,
--                      because what an offboarding destroys is never restored
--   version            the resource's ETag
--
-- A group's members are rows of scim_group_members rather than a column, so
-- "which groups is this account in" — asked at every authorization decision by
-- the hub's directory cache — is one indexed read.
--
-- # scim_credentials
--
-- The dedicated bearer credential an identity provider presents, accepted on
-- /scim/v2 and nowhere else: cloop_scim_<id>_<secret>. Like an API token, only
-- an HMAC of the secret is stored. Rotation keeps the id and replaces the
-- secret; the one it replaced is accepted until previous_expires_at, so the new
-- value can be pasted into the provider without a failed provisioning cycle.
--
-- # legal_holds
--
-- An identity under a legal hold is offboarded with its stored credentials
-- kept (`--keep-credentials`), whoever starts the offboarding: the identity
-- provider deleting the account, the offboard_after_days clock, or an operator
-- who forgets. Keyed by owner key — a lowercased email, or sub:<subject>.
--
-- # scim_meta
--
-- version is bumped by every write to the directory, so a hub member's cache
-- learns a change made through another member with one tiny read.

ALTER TABLE sessions ADD COLUMN username TEXT NOT NULL DEFAULT '';

ALTER TABLE sessions ADD COLUMN oid TEXT NOT NULL DEFAULT '';

ALTER TABLE broker_grants ADD COLUMN suspended_at TEXT NOT NULL DEFAULT '';

ALTER TABLE broker_grants ADD COLUMN suspended_by TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS scim_users (
    id               TEXT PRIMARY KEY,
    user_name        TEXT NOT NULL,
    user_name_key    TEXT NOT NULL,
    external_id      TEXT NOT NULL DEFAULT '',
    external_id_key  TEXT NOT NULL DEFAULT '',
    display_name     TEXT NOT NULL DEFAULT '',
    email            TEXT NOT NULL DEFAULT '',
    active           INTEGER NOT NULL DEFAULT 1,
    resource_json    TEXT NOT NULL DEFAULT '{}',
    version          INTEGER NOT NULL DEFAULT 1,
    created_at       TEXT NOT NULL DEFAULT '',
    created_by       TEXT NOT NULL DEFAULT '',
    updated_at       TEXT NOT NULL DEFAULT '',
    updated_by       TEXT NOT NULL DEFAULT '',
    deactivated_at   TEXT NOT NULL DEFAULT '',
    suspension_json  TEXT NOT NULL DEFAULT '',
    offboarded_at    TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_scim_users_user_name ON scim_users(user_name_key);

CREATE INDEX IF NOT EXISTS idx_scim_users_external_id ON scim_users(external_id_key);

CREATE INDEX IF NOT EXISTS idx_scim_users_email ON scim_users(email);

CREATE TABLE IF NOT EXISTS scim_groups (
    id                TEXT PRIMARY KEY,
    display_name      TEXT NOT NULL,
    display_name_key  TEXT NOT NULL,
    external_id       TEXT NOT NULL DEFAULT '',
    resource_json     TEXT NOT NULL DEFAULT '{}',
    version           INTEGER NOT NULL DEFAULT 1,
    created_at        TEXT NOT NULL DEFAULT '',
    created_by        TEXT NOT NULL DEFAULT '',
    updated_at        TEXT NOT NULL DEFAULT '',
    updated_by        TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_scim_groups_display_name ON scim_groups(display_name_key);

CREATE TABLE IF NOT EXISTS scim_group_members (
    group_id  TEXT NOT NULL,
    user_id   TEXT NOT NULL,
    added_at  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_scim_group_members_user ON scim_group_members(user_id);

CREATE TABLE IF NOT EXISTS scim_credentials (
    id                   TEXT PRIMARY KEY,
    name                 TEXT NOT NULL,
    secret_hash          TEXT NOT NULL,
    previous_hash        TEXT NOT NULL DEFAULT '',
    previous_expires_at  TEXT NOT NULL DEFAULT '',
    created_at           TEXT NOT NULL DEFAULT '',
    created_by           TEXT NOT NULL DEFAULT '',
    rotated_at           TEXT NOT NULL DEFAULT '',
    rotated_by           TEXT NOT NULL DEFAULT '',
    revoked_at           TEXT NOT NULL DEFAULT '',
    revoked_by           TEXT NOT NULL DEFAULT '',
    last_used_at         TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_scim_credentials_name ON scim_credentials(name);

CREATE TABLE IF NOT EXISTS legal_holds (
    identity   TEXT PRIMARY KEY,
    reason     TEXT NOT NULL DEFAULT '',
    placed_at  TEXT NOT NULL DEFAULT '',
    placed_by  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS scim_meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL DEFAULT ''
);
