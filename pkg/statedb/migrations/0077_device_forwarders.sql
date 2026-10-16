-- 0077_device_forwarders: enrollment tokens and long-lived credentials for
-- device forwarders (Task 20429).
--
-- A forwarder is a minimal on-prem binary that bridges ONE configured USB or
-- layer-2 device to the hub and does nothing else — no harness, no workload.
-- It is deliberately NOT an executor, so it gets its own tables rather than a
-- role column on executor_agents: a forwarder credential must never be able to
-- authenticate as something that can run work, and keeping the two populations
-- in separate tables makes that structural instead of a check that can be
-- forgotten.
--
-- The design mirrors 0011_executor_agents exactly, because the enrollment
-- security argument is identical:
--
--   forwarder_enrollment_tokens  single-use, TTL-bounded; the secret that gets
--                                pasted into a terminal and leaks. Redemption
--                                is a conditional UPDATE ... WHERE
--                                redeemed_at = '' so two racers cannot share
--                                an identity.
--
--   device_forwarders            long-lived, per-forwarder; issued once over
--                                the enrolling connection, persisted 0600 on
--                                the device.
--
-- NEITHER TABLE STORES A SECRET: both hold hex SHA-256, named *_hash so a
-- future plaintext column would stand out in review. device_json is the
-- forwarded-device descriptor the operator chose at mint time, which is
-- authoritative — a compromised forwarder cannot claim to carry a different
-- device than it was enrolled for. Timestamps are RFC3339 TEXT; the empty
-- string means "not set".

CREATE TABLE IF NOT EXISTS forwarder_enrollment_tokens (
    id                    TEXT PRIMARY KEY,
    name                  TEXT NOT NULL DEFAULT '',
    secret_hash           TEXT NOT NULL,
    device_json           TEXT NOT NULL DEFAULT '{}',
    owner                 TEXT NOT NULL DEFAULT '',
    created_at            TEXT NOT NULL DEFAULT '',
    expires_at            TEXT NOT NULL DEFAULT '',
    created_by            TEXT NOT NULL DEFAULT '',
    redeemed_at           TEXT NOT NULL DEFAULT '',
    redeemed_forwarder_id TEXT NOT NULL DEFAULT '',
    revoked_at            TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_fwd_enrollment_expires ON forwarder_enrollment_tokens(expires_at);

CREATE TABLE IF NOT EXISTS device_forwarders (
    forwarder_id  TEXT PRIMARY KEY,
    name          TEXT NOT NULL DEFAULT '',
    secret_hash   TEXT NOT NULL,
    device_json   TEXT NOT NULL DEFAULT '{}',
    owner         TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL DEFAULT '',
    last_seen     TEXT NOT NULL DEFAULT '',
    revoked_at    TEXT NOT NULL DEFAULT '',
    enrollment_id TEXT NOT NULL DEFAULT '',
    -- Connectivity, refreshed as the forwarder connects and disconnects. Not a
    -- secret; purely for the dashboard, like executors.status.
    status        TEXT NOT NULL DEFAULT 'offline',
    status_at     TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_device_forwarders_owner ON device_forwarders(owner);
