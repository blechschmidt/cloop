-- 0011_executor_agents: enrollment tokens and long-lived agent credentials
-- for remote executors (Task 20158).
--
-- Remote agents run on machines the control plane cannot dial — edge devices
-- behind NAT, laptops on hotel wifi. They enroll by dialling *out* and
-- presenting a token, so these two tables are the durable half of that
-- handshake.
--
-- Two secrets with different lifetimes, and the split is the whole security
-- design:
--
--   executor_enrollment_tokens  single-use, TTL-bounded. This is the secret
--                               that gets pasted into terminals and baked
--                               into provisioning scripts — the one that
--                               leaks. Single-use means a leak is only
--                               exploitable before the real device redeems
--                               it, and a losing race surfaces loudly as
--                               "already redeemed" instead of two parties
--                               silently sharing an identity.
--
--   executor_agent_credentials  long-lived, per-agent. Never pasted anywhere;
--                               issued once over the enrolling connection and
--                               persisted 0600 on the device.
--
-- NEITHER TABLE STORES A SECRET. Both hold hex SHA-256 of the secret, so a
-- stolen state.db yields nothing an attacker can authenticate with. The
-- columns are named *_hash to make that obvious at the schema level and to
-- make a future plaintext column stand out in review.
--
-- Timestamps are RFC3339 TEXT, matching every other table in this database.
-- The empty string means "not set" rather than NULL, so scanning code does
-- not need sql.NullString for what is conceptually a zero time.

CREATE TABLE IF NOT EXISTS executor_enrollment_tokens (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL DEFAULT '',
    -- hex SHA-256 of the token secret; never the secret itself
    secret_hash       TEXT NOT NULL,
    workdir_root      TEXT NOT NULL DEFAULT '',
    labels_json       TEXT NOT NULL DEFAULT '{}',
    created_at        TEXT NOT NULL DEFAULT '',
    expires_at        TEXT NOT NULL DEFAULT '',
    created_by        TEXT NOT NULL DEFAULT '',
    -- redeemed_at is the single-use latch: redemption is a conditional
    -- UPDATE ... WHERE redeemed_at = '', so two concurrent redemptions
    -- cannot both succeed no matter how they interleave.
    redeemed_at       TEXT NOT NULL DEFAULT '',
    redeemed_agent_id TEXT NOT NULL DEFAULT '',
    revoked_at        TEXT NOT NULL DEFAULT ''
);

-- Expiry sweeps and the `executor enroll --list` view both scan by recency.
CREATE INDEX IF NOT EXISTS idx_enrollment_expires ON executor_enrollment_tokens(expires_at);

CREATE INDEX IF NOT EXISTS idx_enrollment_redeemed ON executor_enrollment_tokens(redeemed_at);

CREATE TABLE IF NOT EXISTS executor_agent_credentials (
    agent_id      TEXT PRIMARY KEY,
    name          TEXT NOT NULL DEFAULT '',
    -- hex SHA-256 of the credential secret; never the secret itself
    secret_hash   TEXT NOT NULL,
    workdir_root  TEXT NOT NULL DEFAULT '',
    labels_json   TEXT NOT NULL DEFAULT '{}',
    created_at    TEXT NOT NULL DEFAULT '',
    last_seen     TEXT NOT NULL DEFAULT '',
    revoked_at    TEXT NOT NULL DEFAULT '',
    -- Which token minted this agent, so revoking a leaked enrollment token
    -- can also reach the identity an attacker obtained with it.
    enrollment_id TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_agent_credentials_revoked ON executor_agent_credentials(revoked_at);

CREATE INDEX IF NOT EXISTS idx_agent_credentials_enrollment ON executor_agent_credentials(enrollment_id);
