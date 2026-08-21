-- 0012_secret_broker: scoped, expiring credential grants (Task 20159).
--
-- Replaces the flat, all-or-nothing .cloop/secrets.enc map for the
-- multi-tenant remote-executor model. Three tables:
--
--   broker_secrets  what a credential is. `payload` is an AES-256-GCM
--                   envelope (nonce||ciphertext||tag) sealed with a key
--                   derived from CLOOP_SECRET_KEY and the salt in
--                   broker_meta. Plaintext never reaches this table, so a
--                   database file, a backup, or a replica leaks ciphertext
--                   only. `metadata_json` is operator-supplied descriptive
--                   data and is NOT protected — the broker documents that
--                   credential material must not be put there.
--
--   broker_grants   who may use a secret, under what constraints, until
--                   when. `subject_type` is project|executor|label|any and
--                   `subject_value` is the project path, executor id, or
--                   (for label) a k=v,k2=v2 selector. `constraints_json` is
--                   the marshalled secretbroker.Constraints: repo globs,
--                   permission set, kube namespaces/contexts, egress hosts,
--                   registries, env keys.
--
--                   Revocation is a stamp, not a delete: `revoked_at` keeps
--                   the row so an audit reader can still answer "who had
--                   access to this in March", which a DELETE would destroy.
--                   The broker treats a non-empty revoked_at as denial on
--                   the next lease.
--
--   broker_meta     broker-scoped key/value. Currently holds the KDF salt.
--                   Kept separate from the `metadata` table (0001) so a
--                   future per-project state split cannot accidentally
--                   carry the salt into a tenant's own database.
--
-- Leases are deliberately absent. A lease is ephemeral credential material
-- with a minutes-long TTL; persisting one would create exactly the durable
-- plaintext-adjacent record the design exists to avoid, and would outlive
-- the process that can still wipe its tmpfs. Renewal state lives in memory,
-- and an unknown lease id is re-leased rather than resurrected.

CREATE TABLE IF NOT EXISTS broker_secrets (
    id            TEXT PRIMARY KEY,
    kind          TEXT NOT NULL DEFAULT '',
    name          TEXT NOT NULL DEFAULT '',
    payload       BLOB NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at    TEXT NOT NULL DEFAULT '',
    created_by    TEXT NOT NULL DEFAULT ''
);

-- Names are the handle operators use on the CLI ("cloop secret grant
-- prod-pat --to ..."), so ambiguity would attach a grant to the wrong
-- credential. Uniqueness is enforced here rather than only in Go so a
-- second writer cannot create the ambiguity behind the broker's back.
CREATE UNIQUE INDEX IF NOT EXISTS idx_broker_secrets_name ON broker_secrets(name);

CREATE INDEX IF NOT EXISTS idx_broker_secrets_kind ON broker_secrets(kind);

CREATE TABLE IF NOT EXISTS broker_grants (
    id               TEXT PRIMARY KEY,
    secret_id        TEXT NOT NULL,
    scope            TEXT NOT NULL DEFAULT '',
    subject_type     TEXT NOT NULL DEFAULT '',
    subject_value    TEXT NOT NULL DEFAULT '',
    constraints_json TEXT NOT NULL DEFAULT '{}',
    expires_at       TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL DEFAULT '',
    created_by       TEXT NOT NULL DEFAULT '',
    revoked_at       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_broker_grants_secret ON broker_grants(secret_id);

CREATE INDEX IF NOT EXISTS idx_broker_grants_subject ON broker_grants(subject_type, subject_value);

CREATE TABLE IF NOT EXISTS broker_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);
