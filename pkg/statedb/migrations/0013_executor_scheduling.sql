-- 0013_executor_scheduling: probe-driven executor liveness and the in-flight
-- session ledger that failover requeues from (Task 20162).
--
-- Two tables, and the reason they are *new* tables rather than columns bolted
-- onto `executors` is the whole point of this migration.
--
-- executor_health is deliberately NOT extra columns on `executors`.
-- `executors` (0010) is the *enrollment* registry: a row exists there only for
-- backends that enrolled or were synced, and its `status`/`last_heartbeat` are
-- values the agent itself pushed. Health is the opposite — it is the control
-- plane's own *observation*, written by the scheduler's prober, and it must
-- exist for in-process drivers (localprocess, container) that are registered
-- from config and never enroll at all. Tying health to an enrollment row would
-- mean exactly those executors could never be marked unhealthy or cordoned,
-- which is precisely the set an operator most often needs to drain on a busy
-- host. Keying by executor_id with no foreign key is intentional: health may
-- be recorded for an executor that has no enrollment row, and must survive
-- de-enrollment long enough for a supervisor to see why a node went away.
--
-- Columns (executor_health):
--   executor_id          registry key; same identifier space as executors.id
--   state                scheduler's verdict: ready|degraded|unhealthy|cordoned
--   reason               human-readable cause of the current state
--   consecutive_failures probe failures in a row; drives the demotion ladder
--   last_seen            RFC3339 of the last successful probe
--   last_probe           RFC3339 of the last probe attempt, success or not
--   state_changed_at     RFC3339 the state column last transitioned; used for
--                        flap damping so a blip does not trigger failover
--
-- executor_sessions tracks work that is in flight on an executor so a
-- supervisor can find and requeue it when the executor dies.
--
-- claim_token is the safety-critical part. Requeue is a single conditional
-- UPDATE gated on BOTH state = 'running' AND claim_token = the token the
-- caller read, and it rotates the token as it writes. SQLite serialises
-- writers, so of two supervisors racing to fail over the same dead node
-- exactly one matches and updates a row; the loser matches nothing, gets zero
-- rows affected, and reports a lost claim instead of also requeueing. This is
-- the same single-use latch as the enrollment token in 0011, and it exists
-- here for a blunter reason: double-execution means two AI agents editing the
-- same repository at the same time. A read-then-write implementation would let
-- both supervisors win.
--
-- requeued_from carries the previous session id forward so an operator can
-- follow a task across failovers instead of seeing unrelated attempts, and
-- attempt counts them so a task that kills every executor it lands on can be
-- capped rather than chewing through the fleet.
--
-- Columns (executor_sessions):
--   id            session identifier, unique per attempt
--   executor_id   which backend is running it
--   handle_id     driver-side handle, for cancellation and log attachment
--   project_path  project directory the work belongs to
--   task_id       plan task id, 0 when the session is not task-scoped
--   claim_token   rotating token gating the requeue latch; never a secret
--   state         running|requeued|finished|failed
--   attempt       1-based attempt counter across failovers
--   started_at    RFC3339 the session opened
--   updated_at    RFC3339 of the last state write
--   ended_at      RFC3339 the session left the running state
--   requeued_from session id this one replaced, '' for a first attempt
--
-- Timestamps are RFC3339 TEXT with '' meaning "not set", matching every other
-- table in this database, so scanning code needs no sql.NullString for what is
-- conceptually a zero time.

CREATE TABLE IF NOT EXISTS executor_health (
    executor_id          TEXT PRIMARY KEY,
    state                TEXT NOT NULL DEFAULT 'ready',
    reason               TEXT NOT NULL DEFAULT '',
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    last_seen            TEXT NOT NULL DEFAULT '',
    last_probe           TEXT NOT NULL DEFAULT '',
    state_changed_at     TEXT NOT NULL DEFAULT ''
);

-- The scheduler's hot query is "which executors are placeable right now",
-- which is a scan by state.
CREATE INDEX IF NOT EXISTS idx_executor_health_state ON executor_health(state);

CREATE TABLE IF NOT EXISTS executor_sessions (
    id            TEXT PRIMARY KEY,
    executor_id   TEXT NOT NULL,
    handle_id     TEXT NOT NULL DEFAULT '',
    project_path  TEXT NOT NULL DEFAULT '',
    task_id       INTEGER NOT NULL DEFAULT 0,
    -- claim_token is the exactly-once latch: requeue is a conditional
    -- UPDATE ... WHERE claim_token = ? AND state = 'running', so two
    -- supervisors failing over the same node cannot both requeue the session.
    claim_token   TEXT NOT NULL,
    state         TEXT NOT NULL DEFAULT 'running',
    attempt       INTEGER NOT NULL DEFAULT 1,
    started_at    TEXT NOT NULL DEFAULT '',
    updated_at    TEXT NOT NULL DEFAULT '',
    ended_at      TEXT NOT NULL DEFAULT '',
    requeued_from TEXT NOT NULL DEFAULT ''
);

-- Failover asks "what is still running on this dead executor"; capacity
-- checks ask the same question for a live one.
CREATE INDEX IF NOT EXISTS idx_executor_sessions_executor_state ON executor_sessions(executor_id, state);

-- Sweeps and the global in-flight view scan by state across all executors.
CREATE INDEX IF NOT EXISTS idx_executor_sessions_state ON executor_sessions(state);
