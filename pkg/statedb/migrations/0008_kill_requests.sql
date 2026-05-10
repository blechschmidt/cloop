-- 0008_kill_requests: ephemeral table holding per-task abort requests issued
-- from the UI when an operator manually changes an in_progress task's status
-- (Task 20140).
--
-- The orchestrator polls this table from a fast-tick goroutine and fires the
-- watchdog-registered context.CancelFunc for any matching task ID, then
-- re-applies the operator's chosen target_status after the worker exits so
-- the user-selected status wins over the worker's normal "canceled →
-- failed" handling.
--
-- Rows are short-lived: the orchestrator deletes them immediately after
-- firing the cancel. Stale rows that survive a crash are harmless — the
-- next orchestrator startup processes them at boot, and a missing
-- in-progress task is a no-op.

CREATE TABLE IF NOT EXISTS kill_requests (
    task_id        INTEGER PRIMARY KEY,
    target_status  TEXT    NOT NULL DEFAULT '',
    requested_at   TEXT    NOT NULL DEFAULT '',
    requested_by   TEXT    NOT NULL DEFAULT ''
);
