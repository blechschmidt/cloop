-- 0026_hub_instances: a mutual-exclusion lease so two hub processes cannot run
-- against one control plane (Task 20214).
--
-- Nothing prevented a second `cloop ui` from opening a state.db another hub was
-- already using, and the failure was silent rather than loud. SQLite's WAL keeps
-- the *file* consistent, so no error is ever raised — what diverges is the
-- per-process state the hub keeps beside it. pkg/ui/server.go holds diffCache,
-- runStates, chatHistories, liveLogRooms and projStatuses/projEntries purely in
-- memory, and broadcastToProject fans out only to the hubClients of the process
-- it runs in. A browser attached to hub B therefore never sees hub A's events
-- and reads a snapshot that stopped advancing, while both hubs independently
-- run refreshProjectStatuses and stale-run recovery and can send two stop
-- signals for one run.
--
-- deploy/helm/cloop-hub pins replicaCount: 1 for exactly this reason, but a
-- comment in a values file is not an enforcement mechanism: raising replicas,
-- or just starting `cloop ui` twice in one directory, degraded quietly. This
-- table makes the constraint the code's, not the operator's.
--
-- Single row, keyed by scope. The key is not the instance id on purpose: a
-- table keyed by instance would hold one row per hub and "is anyone holding
-- this" would become a scan plus a policy decision, racing every other reader.
-- Keyed by scope, the primary key *is* the mutual exclusion, and acquisition is
-- one INSERT ... ON CONFLICT DO UPDATE ... WHERE — atomic in SQLite without a
-- transaction, so two hubs racing cannot both see a free lease. The row is kept
-- (released_at set) rather than deleted on release, so an operator can still
-- see who held it last and when they let go.
--
-- scope is 'hub' for every row this binary writes. The column exists so a later
-- fenced role — a leader for scheduled sweeps, say — can be added without a
-- migration and without sharing this lease's lifetime.
--
-- Columns:
--   scope        fence name; always 'hub' today
--   instance_id  UUID minted once per process. Every write is conditioned on
--                it, which is what makes renewal *fencing* rather than a
--                blind touch: a hub that was paused past the TTL and had its
--                lease taken finds its own renewal matches no row, learns it
--                lost, and stands down instead of running on as a second
--                writer
--   hostname     os.Hostname of the holder, for the refusal message
--   pid          holder's OS pid, for the refusal message and for the
--                same-host liveness probe described below
--   boot_id      /proc/sys/kernel/random/boot_id when readable, else ''. A pid
--                recorded before a reboot names an unrelated process after
--                one, so the liveness probe only trusts pid when the boot ids
--                match and are non-empty
--   address      listen address (":8080"), so the refusal can name the port
--                the holder is serving rather than only its pid
--   version      holder's build identifier, '' when unknown. Forensics only:
--                a mixed-version pair is a likely explanation for a takeover
--   acquired_at  RFC3339 instant the current holder took the lease
--   heartbeat_at RFC3339 instant of the holder's last renewal. This is the
--                liveness signal: a lease whose heartbeat is older than the
--                TTL is stale and may be taken, which is what stops a crashed
--                holder from wedging the hub forever
--   released_at  RFC3339 instant of a graceful release, '' while held. Set
--                rather than deleting the row so the last holder stays visible
--
-- Timestamps are RFC3339 TEXT with '' meaning "not set", matching every other
-- table in this database. Note that nothing compares them with < or > in SQL,
-- and that is deliberate: Go's RFC3339Nano drops trailing zeros from the
-- fractional second, so a whole-second instant renders "…:00Z" and sorts ABOVE
-- "…:00.5Z" — 'Z' is greater than '.'. Staleness is therefore decided in Go
-- against parsed time.Time values, and acquisition conditions on string
-- equality with the row the caller read (a compare-and-swap) rather than on
-- ordering. That is also the stronger check: it closes the window where the
-- holder renews between the caller's read and its write.

CREATE TABLE IF NOT EXISTS hub_instances (
    scope        TEXT PRIMARY KEY,
    instance_id  TEXT NOT NULL,
    hostname     TEXT NOT NULL DEFAULT '',
    pid          INTEGER NOT NULL DEFAULT 0,
    boot_id      TEXT NOT NULL DEFAULT '',
    address      TEXT NOT NULL DEFAULT '',
    version      TEXT NOT NULL DEFAULT '',
    acquired_at  TEXT NOT NULL DEFAULT '',
    heartbeat_at TEXT NOT NULL DEFAULT '',
    released_at  TEXT NOT NULL DEFAULT ''
);
