-- 0003_events: unified event history (Task 20118).
--
-- Steps capture the *result* of provider invocations. Many other things happen
-- around them — task starts, evolves, kills, skips, heal retries, status
-- transitions, run pause/resume — that the user has historically had no way to
-- see in chronological order. This table is the single canonical journal.
--
-- Event types currently recorded by the orchestrator (extensible — readers must
-- not panic on unknown values):
--
--   session_started   — orchestrator.Run begins a fresh execution loop
--   session_paused    — token/cost budget hit, run paused mid-execution
--   session_failed    — too many consecutive task failures aborted the run
--   plan_complete     — every non-skipped task is done
--   task_started      — a task transitioned pending -> in_progress
--   task_done         — a task signalled TASK_DONE (or implicit success)
--   task_failed       — a task signalled TASK_FAILED (after heal retries)
--   task_skipped      — a task signalled TASK_SKIPPED
--   task_heal         — a TASK_FAILED was rerouted to heal-retry
--   task_killed       — the watchdog or user terminated a stuck task
--   task_added        — a task was inserted (externally or via evolve)
--   task_added_external — distinct: came from disk merge, not this loop
--   task_deleted      — a task was removed from the plan
--   task_status_change — UI/CLI toggled a task status manually
--   evolve_round_start — the evolve loop began a discovery round
--   evolve_discovered — N novel tasks added by evolve
--   evolve_no_op      — evolve ran but found no new work
--   step              — synthetic events that mirror the steps table for
--                       call-sites that want a single chronological feed; the
--                       UI/api still merges with `steps` so we don't duplicate
--
-- The `details` column stores arbitrary JSON for event-specific extras
-- (e.g. heal attempt counter, error message, source path). Keep the schema
-- thin: anything stable should be promoted to a column in a follow-up
-- migration; everything else lives in JSON so we don't have to migrate the
-- table on every new event type.

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL DEFAULT '',
    type        TEXT    NOT NULL DEFAULT '',
    task_id     INTEGER NOT NULL DEFAULT 0,
    task_title  TEXT    NOT NULL DEFAULT '',
    step        INTEGER NOT NULL DEFAULT -1,
    message     TEXT    NOT NULL DEFAULT '',
    details     TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS events_type ON events(type);
CREATE INDEX IF NOT EXISTS events_task_id ON events(task_id);
