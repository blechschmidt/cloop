-- 0052_hub_cluster: what several hub processes need to share one control plane
-- (Task 20354).
--
-- Until this migration a control plane had exactly one hub. 0026 made that the
-- code's rule rather than the operator's: a second `cloop ui` found the lease
-- in hub_instances held and refused to start, because everything a hub keeps
-- beside the database — the run it dispatched, the agent socket it holds, the
-- dashboard clients it pushes to — lived in that one process. These three
-- tables move each of those facts into the database the processes already
-- share, so that N hubs can serve one control plane behind a load balancer.
-- hub_instances keeps its row: with members it is the *leader* lease, held by
-- whichever member runs the sweeps that must happen once (retention, the lease
-- janitor, auto-resume), and an older fenced binary still reads it as "a hub is
-- here" and refuses to start beside a cluster it cannot take part in.
--
-- Timestamps in these tables are INTEGER Unix milliseconds, not the RFC3339
-- TEXT the older tables use. 0026 explains why RFC3339Nano TEXT cannot be
-- ordered in SQL; these tables need ordering and range deletes (the bus is
-- pruned by age every few seconds), so they store a number that sorts.
--
-- hub_members — who is serving right now.
--   instance_id    UUID minted once per process; the key every other row here
--                  refers to
--   hostname, pid, boot_id
--                  who the process is, so a peer on the same machine can probe
--                  the pid and learn of a crash at once instead of after the TTL
--                  (the same rule hub_instances uses: only trusted when the boot
--                  ids match)
--   address        the listen address (":8080"), for `cloop hub cluster status`
--   advertise_url  how *peers* reach this process — a pod IP, a loopback port.
--                  Requests another member owns are forwarded here
--   version        build identifier, for spotting a mixed-version rollout
--   meta           JSON object of further endpoints (the git proxy's internal
--                  URL); '{}' when there are none
--   started_ms     when the process joined
--   heartbeat_ms   last renewal. A member whose heartbeat is older than the
--                  membership TTL is dead, and what it owned is up for adoption
--   left_ms        a graceful leave; 0 while serving. The row is kept so an
--                  operator can see who served last and when they stopped
--
-- hub_bus — events one process produced that the others' clients must see.
--   A dashboard socket is attached to one process, but the event it waits for
--   (a line of harness output, a run starting, an executor going offline) is
--   produced by whichever process owns the thing it describes. Each member
--   appends what it produced and polls for what the others did, by seq.
--   seq is AUTOINCREMENT on purpose: a plain rowid may be reused once the
--   highest row is pruned, and a reused number is an event a reader's cursor
--   has already passed and would never deliver.
--   origin     instance that published it; a member skips its own
--   target     instance it is addressed to, '' for every member
--   topic      what kind of event (ws, log, run_state, presence, …)
--   key        the subject, usually a project directory
--   payload    JSON
--   created_ms when it was published; pruned after a few minutes
--
-- hub_owners — which process holds a thing that cannot be shared.
--   An agent's WebSocket, a dispatched run's output stream, a `claude auth
--   login` waiting for its code: each lives in one process's memory. A request
--   about it that lands on another member is forwarded to the owner, and a
--   thing whose owner died is adopted by a member that can reach it.
--   kind, key   what is owned: ('agent', executor id), ('run', project dir), …
--   instance_id the owning member
--   meta        JSON the owner records for whoever adopts it next (a run's
--               executor and handle, a seeded dispatch's provenance)
--   claimed_ms  when the current owner took it. Part of the compare-and-swap
--               that adoption uses, so two members adopting the same orphan
--               cannot both win
--   updated_ms  last write by the owner

CREATE TABLE IF NOT EXISTS hub_members (
    instance_id   TEXT PRIMARY KEY,
    hostname      TEXT NOT NULL DEFAULT '',
    pid           INTEGER NOT NULL DEFAULT 0,
    boot_id       TEXT NOT NULL DEFAULT '',
    address       TEXT NOT NULL DEFAULT '',
    advertise_url TEXT NOT NULL DEFAULT '',
    version       TEXT NOT NULL DEFAULT '',
    meta          TEXT NOT NULL DEFAULT '{}',
    started_ms    INTEGER NOT NULL DEFAULT 0,
    heartbeat_ms  INTEGER NOT NULL DEFAULT 0,
    left_ms       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS hub_bus (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    origin     TEXT NOT NULL DEFAULT '',
    target     TEXT NOT NULL DEFAULT '',
    topic      TEXT NOT NULL DEFAULT '',
    key        TEXT NOT NULL DEFAULT '',
    payload    TEXT NOT NULL DEFAULT '',
    created_ms INTEGER NOT NULL DEFAULT 0
);

-- Pruning deletes by age.
CREATE INDEX IF NOT EXISTS idx_hub_bus_created ON hub_bus(created_ms);

CREATE TABLE IF NOT EXISTS hub_owners (
    kind        TEXT NOT NULL,
    key         TEXT NOT NULL,
    instance_id TEXT NOT NULL DEFAULT '',
    meta        TEXT NOT NULL DEFAULT '{}',
    claimed_ms  INTEGER NOT NULL DEFAULT 0,
    updated_ms  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (kind, key)
);

-- "What did this member own" is the adoption query when a member dies.
CREATE INDEX IF NOT EXISTS idx_hub_owners_instance ON hub_owners(instance_id);

-- secret_lease_dirs.instance_id — the member that materialised a credential
-- directory. The startup sweep used to wipe every recorded directory not held
-- by its own process, on the grounds that at startup every row is an orphan of
-- a previous run. With several members that is false: a member starting beside
-- a live one would shred the credentials of the other's running tasks. The
-- sweep now spares rows of live members, and the leader sweeps a member's rows
-- once it dies. '' for rows written before this column existed.
ALTER TABLE secret_lease_dirs ADD COLUMN instance_id TEXT NOT NULL DEFAULT '';

-- hub_seen — single-use values every member must agree it has seen.
--   A CI pipeline's OIDC token may be exchanged once (its jti is remembered
--   until it expires); with one hub that memory was a map, and with several a
--   token refused as replayed on one member would be accepted by the next.
--   kind names the namespace ('ci_jti'), key the value, and expires_ms when
--   remembering it stops mattering; the leader prunes rows past it.
CREATE TABLE IF NOT EXISTS hub_seen (
    kind       TEXT NOT NULL,
    key        TEXT NOT NULL,
    expires_ms INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (kind, key)
);

CREATE INDEX IF NOT EXISTS idx_hub_seen_expires ON hub_seen(expires_ms);
