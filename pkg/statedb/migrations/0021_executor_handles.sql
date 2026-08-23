-- 0021_executor_handles: durable identity for dispatched workloads, so a hub
-- restart does not lose track of workloads that are still running (Task 20191).
--
-- Every driver already kept a handle map in memory, and until now that map was
-- the *only* record that a workload existed. A control plane that restarted
-- came up with an empty map while its containers, Pods and edge-device
-- processes kept running: Stream, Status and Signal all answered
-- "handle not found", so the workload was alive and unreachable at once.
--
-- This table is deliberately NOT executor_sessions (0013) even though the two
-- describe overlapping things, and the distinction is load-bearing:
--
--   executor_sessions is the *control plane's* ledger. The UI supervisor opens
--   a row when it dispatches, failover requeues from it, and drain counts it.
--   Its key is a session id the control plane minted, it carries a claim token
--   and an attempt counter, and it retains the Spec so a session can be
--   re-dispatched somewhere else.
--
--   executor_handles is the *driver's* ledger. A driver writes a row when the
--   runtime accepts a workload and drops it when the workload goes terminal.
--   Its key is the driver-side handle id, and it carries the external name the
--   runtime knows the workload by — a container name, a namespace/pod pair, an
--   agent handle. Nothing else can reattach `docker logs -f` to a container
--   started by a process that no longer exists.
--
-- Collapsing them would mean either drivers writing claim tokens they have no
-- business minting, or the control plane inventing external ids it cannot
-- know. It would also break the case that motivated the split: a driver used
-- without the UI supervisor (the CLI, an embedder) still needs to survive a
-- restart, and a session row is never opened for it.
--
-- No spec_json column, on purpose. Spec.Env carries brokered secret values and
-- a handle row outlives the lease they came from. Rehydration reattaches to a
-- *running* workload and never re-dispatches one, so it needs no spec;
-- executor_sessions keeps one where re-dispatch actually happens.
--
-- No foreign key to `executors`, for the same reason executor_health has none:
-- in-process drivers (localprocess, container) never enroll, and they are
-- exactly the drivers whose orphans an operator most often has to clean up.
--
-- Columns:
--   handle_id    driver-side handle; the key callers hold
--   executor_id  owning executor instance; rehydration is scoped by it so two
--                container executors on one runtime cannot adopt each other's
--                containers
--   driver       Kind* constant, so a sweep can reason about rows whose
--                executor is no longer registered at all
--   external_id  the name the runtime knows the workload by. Driver-specific:
--                localprocess = decimal pid, container = container name,
--                kubernetes = "namespace/pod", remote = agent handle id
--   project_path project the work belongs to, '' when not project-scoped
--   task_id      plan task id, 0 when not task-scoped
--   pid          OS pid where meaningful (localprocess), else 0
--   image        resolved image reference, '' for drivers without one
--   meta_json    driver-specific extras (NetworkPolicy name, runtime); never
--                secrets, it is stored verbatim
--   started_at   RFC3339 dispatch time. The orphan sweep compares it against a
--                grace period, so it is the dispatch time and not the write
--                time
--   deadline     RFC3339 instant at which Spec.TimeoutMinutes expires, '' for
--                an unbounded workload. Absolute rather than a duration
--                because the two disagree in exactly the case it exists for:
--                a hub down for twenty minutes must resume a one-hour timeout
--                with forty minutes left, not restart the hour
--   updated_at   RFC3339 of the last write, for operator forensics
--
-- Timestamps are RFC3339 TEXT with '' meaning "not set", matching every other
-- table in this database.

CREATE TABLE IF NOT EXISTS executor_handles (
    handle_id    TEXT PRIMARY KEY,
    executor_id  TEXT NOT NULL,
    driver       TEXT NOT NULL DEFAULT '',
    external_id  TEXT NOT NULL DEFAULT '',
    project_path TEXT NOT NULL DEFAULT '',
    task_id      INTEGER NOT NULL DEFAULT 0,
    pid          INTEGER NOT NULL DEFAULT 0,
    image        TEXT NOT NULL DEFAULT '',
    meta_json    TEXT NOT NULL DEFAULT '{}',
    started_at   TEXT NOT NULL DEFAULT '',
    deadline     TEXT NOT NULL DEFAULT '',
    updated_at   TEXT NOT NULL DEFAULT ''
);

-- The hot query is rehydration: "which handles does this executor own",
-- asked once per driver at every control-plane start.
CREATE INDEX IF NOT EXISTS idx_executor_handles_executor ON executor_handles(executor_id);

-- The cross-driver orphan sweep scans by driver when an executor id has
-- changed between restarts (a renamed container executor still owns the
-- containers the old id started).
CREATE INDEX IF NOT EXISTS idx_executor_handles_driver ON executor_handles(driver);
