-- 0015_egress_broker: scoped Internet-egress grants (Task 20163).
--
-- The fourth grantable resource, alongside the GitHub repositories, PATs, and
-- Kubernetes clusters that 0012 covers. An executor that runs with
-- --network=none has no route of its own; it reaches the outside world only
-- through the control plane's forward proxy, and a row here is what says
-- which destinations that proxy will open for it.
--
--   egress_grants  who may make outbound connections, to which hosts, CIDRs,
--                  ports and methods, under what byte quota, until when.
--                  `subject_type` is project|executor|label|any and
--                  `subject_value` is the project path, executor id, or (for
--                  label) a k=v,k2=v2 selector — identical to broker_grants,
--                  because an operator should not have to learn a second
--                  targeting syntax for the second resource.
--
--                  `policy_json` is the marshalled egressbroker.Grant policy:
--                  hosts, cidrs, ports, methods, max_bytes_up/down, and the
--                  per-session TTL.
--
--                  Revocation is a stamp, not a delete, matching 0012: the
--                  row survives so "which sandbox could reach the Internet in
--                  March, and to where" stays answerable after the grant is
--                  gone.
--
-- There is no table for sessions, and that is a design decision rather than
-- an omission. A session *is* a live proxy credential with a minutes-long
-- TTL; writing one to disk would create a durable artifact that outlives the
-- proxy able to enforce its quota, and a restart that resurrected it would
-- hand back a credential whose byte counters had been reset to zero. Sessions
-- live in memory and die with the process, exactly as broker leases do.
--
-- Note also what is absent from every column: there is no credential material
-- here at all. An egress grant brokers a capability, not a token — the
-- strongest form of the pattern, because there is nothing to leak from a
-- database file, a backup, or a replica.

CREATE TABLE IF NOT EXISTS egress_grants (
    id            TEXT PRIMARY KEY,
    scope         TEXT NOT NULL DEFAULT '',
    subject_type  TEXT NOT NULL DEFAULT '',
    subject_value TEXT NOT NULL DEFAULT '',
    policy_json   TEXT NOT NULL DEFAULT '{}',
    expires_at    TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL DEFAULT '',
    created_by    TEXT NOT NULL DEFAULT '',
    revoked_at    TEXT NOT NULL DEFAULT ''
);

-- Redemption walks the grants for one subject on every sandbox start, so the
-- subject columns carry the lookup.
CREATE INDEX IF NOT EXISTS idx_egress_grants_subject
    ON egress_grants(subject_type, subject_value);

CREATE INDEX IF NOT EXISTS idx_egress_grants_expiry
    ON egress_grants(expires_at);
