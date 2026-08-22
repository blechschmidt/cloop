-- 0019_envelope_encryption: envelope encryption and online sealing-key
-- rotation for every piece of long-lived sealed material (Task 20181).
--
-- Before this, one key sealed everything. That key was derived from
-- CLOOP_SECRET_KEY and a single store-wide salt, and it was applied directly
-- to each payload. The consequence was documented in the runbook as a caveat:
-- changing CLOOP_SECRET_KEY made every stored secret permanently unopenable,
-- and the only "rotation" was to re-mint every credential by hand. For a
-- product whose purpose is brokering GitHub PATs, kubeconfigs and egress
-- credentials, an unrotatable master key is disqualifying wherever key
-- rotation is an audit finding rather than a preference.
--
-- The fix is the standard one: separate the key that protects data from the
-- key that protects keys.
--
--   DEK   a fresh random 32-byte data-encryption key per row. It seals the
--         payload, is used by exactly one row, and never exists on disk in
--         plaintext.
--   KEK   a key-encryption key derived from CLOOP_SECRET_KEY and a per-KEK
--         salt. It seals DEKs and nothing else.
--
-- Rotation then means rewrapping DEKs, which is a 60-byte AES operation per
-- row against material the hub already holds — not decrypting and
-- re-encrypting payloads, and emphatically not re-minting credentials at
-- their sources. Several KEKs may be usable at once, so a rotation can run
-- while the hub serves traffic: rows move to the new KEK one at a time and
-- both old and new stay openable throughout.
--
-- Tables and columns:
--
--   broker_keks         one row per KEK. `salt` is the hex KDF salt; `state`
--                       is primary|active|retired with a partial unique index
--                       enforcing at most one primary, so two racing
--                       promotions cannot both win and leave rows sealed under
--                       a key nobody considers current.
--
--                       `check_value` is a key check value: a fixed constant
--                       sealed under the KEK. It answers "does the passphrase
--                       currently in the environment actually derive this
--                       KEK?" without touching a single secret, which is what
--                       makes `cloop hub key list` able to say *which* keys are
--                       openable rather than discovering it row by row during
--                       an incident. It leaks nothing an attacker holding the
--                       database did not already have: any wrapped DEK is
--                       equally usable as a passphrase oracle.
--
--                       Retirement blanks `salt`. That is deliberate and it is
--                       the point of the second step: once the salt is gone the
--                       KEK cannot be re-derived from the passphrase at all, so
--                       retirement is crypto-shredding rather than a flag a
--                       future bug could ignore.
--
--   key_rotations       progress and history for a rotation run. It is a
--                       *record*, not a cursor — the rows themselves are the
--                       source of truth for what remains ("everything whose
--                       key_id is not the target"), so a rotation resumes by
--                       being re-run and is idempotent by construction. A
--                       corrupt or stale cursor therefore cannot strand a
--                       rotation half-done, because there is no cursor.
--
--   broker_secrets      +key_id, +wrapped_dek.
--   sessions            +refresh_key_id, +refresh_wrapped_dek.
--
-- The one-time in-place upgrade of existing rows is split across two layers,
-- because it has to be: SQL cannot decrypt. Here, every pre-existing row is
-- stamped key_id='legacy', which names the old construction explicitly instead
-- of leaving it inferable from an empty string. The Go keyring then knows
-- exactly which rows are sealed directly under the passphrase-derived key,
-- keeps opening them, and rewraps them into envelope form on the next write or
-- on the first `cloop hub key rotate` — after which no legacy row remains and
-- `cloop hub key status` says so.

CREATE TABLE IF NOT EXISTS broker_keks (
    id          TEXT PRIMARY KEY,
    salt        TEXT NOT NULL DEFAULT '',
    state       TEXT NOT NULL DEFAULT 'active',
    check_value BLOB,
    created_at  TEXT NOT NULL DEFAULT '',
    created_by  TEXT NOT NULL DEFAULT '',
    retired_at  TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_broker_keks_primary
    ON broker_keks(state) WHERE state = 'primary';

CREATE INDEX IF NOT EXISTS idx_broker_keks_state ON broker_keks(state);

CREATE TABLE IF NOT EXISTS key_rotations (
    id           TEXT PRIMARY KEY,
    to_key_id    TEXT NOT NULL DEFAULT '',
    state        TEXT NOT NULL DEFAULT 'running',
    started_at   TEXT NOT NULL DEFAULT '',
    updated_at   TEXT NOT NULL DEFAULT '',
    finished_at  TEXT NOT NULL DEFAULT '',
    started_by   TEXT NOT NULL DEFAULT '',
    total        INTEGER NOT NULL DEFAULT 0,
    rewrapped    INTEGER NOT NULL DEFAULT 0,
    skipped      INTEGER NOT NULL DEFAULT 0,
    failed       INTEGER NOT NULL DEFAULT 0,
    last_error   TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_key_rotations_started ON key_rotations(started_at);

ALTER TABLE broker_secrets ADD COLUMN key_id TEXT NOT NULL DEFAULT '';

ALTER TABLE broker_secrets ADD COLUMN wrapped_dek BLOB;

ALTER TABLE sessions ADD COLUMN refresh_key_id TEXT NOT NULL DEFAULT '';

ALTER TABLE sessions ADD COLUMN refresh_wrapped_dek BLOB;

UPDATE broker_secrets SET key_id = 'legacy' WHERE key_id = '';

UPDATE sessions SET refresh_key_id = 'legacy'
    WHERE refresh_key_id = '' AND refresh_sealed IS NOT NULL AND length(refresh_sealed) > 0;

CREATE INDEX IF NOT EXISTS idx_broker_secrets_key ON broker_secrets(key_id);

CREATE INDEX IF NOT EXISTS idx_sessions_refresh_key ON sessions(refresh_key_id);
