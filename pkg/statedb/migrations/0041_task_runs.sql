-- 0041_task_runs: correlate a task's audit rows with the execution that ran it
-- (Task 20282).
--
-- An auditor asking "which executor ran task 63, under which secret leases, and
-- how did it end" could not answer it from audit_events. A task's entire trace
-- was task.upsert rows emitted incidentally by SaveState, from which a status
-- transition had to be inferred, and the lease rows the same dispatch wrote had
-- nothing to join against.
--
-- Two columns close that, and they are deliberately in a table of their own
-- rather than on plan_tasks.
--
-- # Why a new table instead of ALTER TABLE plan_tasks
--
-- schema_compat.go classifies every migration by reading its SQL, and an ALTER
-- on a pre-existing table is classified breaking — correctly, because an older
-- binary issues statements against plan_tasks and must not meet a shape it does
-- not know. This deployment runs two hubs against one set of project databases
-- (:8080 from the installed binary, :8888 from main), and a breaking migration
-- applied by the newer one blanks the older one's dashboard until the next
-- nightly rebuild. That has happened before, on 0034.
--
-- A CREATE TABLE is additive: the older binary has never heard of task_runs and
-- issues nothing that names it, so it keeps reading plan_tasks exactly as
-- before. The audit correlation is bookkeeping about executions, not plan data,
-- so it belongs beside the plan rather than inside it anyway.
--
-- # Columns
--
--   run_id          the execution this task's latest attempt was dispatched
--                   into, mirroring artifact.SandboxRecord.RunID. It is the
--                   join key between this task's task.dispatch / task.finish
--                   rows and the secret.lease rows the hub wrote when it
--                   started the run.
--
--                   A task id is not a key for that question: task 63 may run
--                   five times, and joining leases to the task id silently
--                   unions five different answers. Persisted rather than held
--                   in memory so that a hub which died mid-task still writes a
--                   terminal row naming the run that actually spent the leases,
--                   not the run that noticed the corpse.
--
--   audited_status  the task status for which a lifecycle row was last emitted.
--
--                   This is the cursor that makes terminal auditing complete by
--                   construction. Rather than asking each of the orchestrator's
--                   many exit paths to remember to emit — kill, timeout,
--                   provider abort, crash recovery, executor failover, and the
--                   ordinary signal paths — the emitter compares this against
--                   the status being written and emits task.dispatch on any
--                   transition into in_progress and task.finish on any
--                   transition out of it. Every exit path has to persist the
--                   status it decided, so every exit path is covered without
--                   knowing this exists.
--
--                   Empty means no lifecycle row has been emitted for this task
--                   yet, which is the correct reading for every task that
--                   predates this migration: their history is not reconstructed,
--                   because inventing dispatch rows under today's timestamps
--                   would put a false account of when work ran into a table
--                   whose whole purpose is to say when things happened.
--
-- Rows are dropped with the task, alongside the audit_task_fingerprints entry,
-- so an id reused later starts clean rather than inheriting an unrelated task's
-- run and cursor.

CREATE TABLE IF NOT EXISTS task_runs (
    task_id        INTEGER PRIMARY KEY,
    run_id         TEXT NOT NULL DEFAULT '',
    audited_status TEXT NOT NULL DEFAULT ''
);

-- "Everything that happened in run X" is the fleet-facing query — the one an
-- operator runs when a single execution is under review — and without this it
-- is a scan of every task in the project.
CREATE INDEX IF NOT EXISTS task_runs_run ON task_runs(run_id);
