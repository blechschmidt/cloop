-- failover_cap — what a lost node was running, and which tasks are suspected
-- of taking nodes down (Task 20391).
--
-- When an executor stops answering while it holds a workload, the hub claims
-- the workload's session and re-dispatches it elsewhere. That used to happen
-- with no ceiling, so a workload that itself takes its node down — a fork
-- bomb, a memory hog, a module that panics the kernel — was carried from node
-- to node until every enrolled device had gone down in turn. The cap
-- (executors.failover.max_attempts) needs no schema: it is decided in the
-- claim's UPDATE against executor_sessions.attempt, and a session past it is
-- closed in a new state, 'failover_exhausted'. What does need storage is the
-- evidence for the tasks, kept here.
--
-- executor_sessions.running_tasks — the tasks the session's workload last
--   announced it was working on, as a JSON array of task ids. A run on a
--   device works on a copy of the project, so the hub's own plan cannot say
--   which task a node died under; this column can. Control-plane rows only.
--
-- task_node_losses — one row per task per lost session: the executor that
--   went unreachable while the task was running, and when. A project's own
--   table, beside the plan the task belongs to. Two or more distinct
--   executors on one task make it a suspected node killer.
--
--   task_id      the task.
--   session_id   the executor session that was lost: the claim that
--                recorded the loss is exactly-once, so (task_id, session_id)
--                is too.
--   executor_id  the executor that went unreachable.
--   lost_at      when it was found unreachable, RFC 3339.
--   attempt      the session's attempt number: 1 for the original dispatch.
--
-- task_quarantine — the tasks marked as suspected node killers. A marked task
--   runs again only after an explicit reset (`cloop task reset`, a reset
--   from the dashboard), which deletes its row and its losses; --retry-failed
--   and every other automatic path leave it alone.
--
--   task_id      the task.
--   kind         what it is suspected of: 'node_killer'.
--   reason       one sentence, naming the nodes.
--   nodes_json   the losses behind the mark: [{executor_id, lost_at,
--                session_id}], oldest first.
--   marked_at    when it was marked, RFC 3339.
--   marked_by    what marked it: 'failover'.
--
-- Additive in schema_compat.go's sense: executor_sessions is not a table any
-- shipped build rewrites (its writers INSERT and UPDATE named columns), and a
-- binary predating the two tables neither reads nor writes them. Neither table
-- is a plan_tasks column on purpose — builds before Task 20388 rewrite
-- plan_tasks on every save and would erase one.
ALTER TABLE executor_sessions ADD COLUMN running_tasks TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS task_node_losses (
    task_id     INTEGER NOT NULL,
    session_id  TEXT    NOT NULL,
    executor_id TEXT    NOT NULL,
    lost_at     TEXT    NOT NULL,
    attempt     INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (task_id, session_id)
);

CREATE TABLE IF NOT EXISTS task_quarantine (
    task_id    INTEGER PRIMARY KEY,
    kind       TEXT NOT NULL DEFAULT 'node_killer',
    reason     TEXT NOT NULL DEFAULT '',
    nodes_json TEXT NOT NULL DEFAULT '[]',
    marked_at  TEXT NOT NULL DEFAULT '',
    marked_by  TEXT NOT NULL DEFAULT ''
);
