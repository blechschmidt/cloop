-- 0001_init: baseline schema for the statedb package.
--
-- This migration reconstructs the canonical schema as it existed before the
-- migration framework was introduced (Task 20101). It uses CREATE TABLE
-- IF NOT EXISTS so that:
--   * fresh databases get the full schema, and
--   * databases created by older binaries (which executed the same DDL ad-hoc
--     in pkg/statedb.Open) are accepted without error and recorded as
--     baseline migration version 1.
--
-- Future schema changes MUST land as new files (0002_*.sql, 0003_*.sql, ...).
-- Never edit this file once shipped — migrations are append-only.

PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS plan_tasks (
    id                INTEGER PRIMARY KEY,
    title             TEXT    NOT NULL DEFAULT '',
    description       TEXT    NOT NULL DEFAULT '',
    priority          INTEGER NOT NULL DEFAULT 5,
    status            TEXT    NOT NULL DEFAULT 'pending',
    role              TEXT    NOT NULL DEFAULT '',
    depends_on        TEXT    NOT NULL DEFAULT '[]',
    result            TEXT    NOT NULL DEFAULT '',
    started_at        TEXT,
    completed_at      TEXT,
    deadline          TEXT,
    verify_retries    INTEGER NOT NULL DEFAULT 0,
    github_issue      INTEGER NOT NULL DEFAULT 0,
    estimated_minutes INTEGER NOT NULL DEFAULT 0,
    actual_minutes    INTEGER NOT NULL DEFAULT 0,
    artifact_path     TEXT    NOT NULL DEFAULT '',
    failure_diagnosis TEXT    NOT NULL DEFAULT '',
    tags              TEXT    NOT NULL DEFAULT '[]',
    fail_count        INTEGER NOT NULL DEFAULT 0,
    heal_attempts     INTEGER NOT NULL DEFAULT 0,
    annotations       TEXT    NOT NULL DEFAULT '[]',
    condition_expr    TEXT    NOT NULL DEFAULT '',
    recurrence        TEXT    NOT NULL DEFAULT '',
    next_run_at       TEXT,
    requires_approval INTEGER NOT NULL DEFAULT 0,
    approved          INTEGER NOT NULL DEFAULT 0,
    max_minutes       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS steps (
    step          INTEGER PRIMARY KEY,
    task          TEXT    NOT NULL DEFAULT '',
    output        TEXT    NOT NULL DEFAULT '',
    exit_code     INTEGER NOT NULL DEFAULT 0,
    duration      TEXT    NOT NULL DEFAULT '',
    time          TEXT    NOT NULL DEFAULT '',
    input_tokens  INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS costs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL DEFAULT '',
    task_id         INTEGER NOT NULL DEFAULT 0,
    task_title      TEXT    NOT NULL DEFAULT '',
    provider        TEXT    NOT NULL DEFAULT '',
    model           TEXT    NOT NULL DEFAULT '',
    input_tokens    INTEGER NOT NULL DEFAULT 0,
    output_tokens   INTEGER NOT NULL DEFAULT 0,
    thinking_tokens INTEGER NOT NULL DEFAULT 0,
    estimated_usd   REAL    NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS costs_timestamp ON costs(timestamp);
CREATE INDEX IF NOT EXISTS costs_task_id ON costs(task_id);

-- Activity queue: every unit of work cloop performs (PM task executions,
-- auto-heal retries, evolve discovery cycles, externally-merged tasks,
-- session-level work). Co-located with state in state.db so there is a
-- single SQLite database per project (Task 20079: merge queue + state db).
CREATE TABLE IF NOT EXISTS queue (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    kind            TEXT    NOT NULL DEFAULT 'task',
    task_id         INTEGER NOT NULL DEFAULT 0,
    attempt         INTEGER NOT NULL DEFAULT 0,
    parent_id       INTEGER NOT NULL DEFAULT 0,
    title           TEXT    NOT NULL DEFAULT '',
    description     TEXT    NOT NULL DEFAULT '',
    status          TEXT    NOT NULL DEFAULT 'queued',
    source          TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT '',
    started_at      TEXT,
    completed_at    TEXT,
    output_summary  TEXT    NOT NULL DEFAULT '',
    error_message   TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS queue_task_id ON queue(task_id);
CREATE INDEX IF NOT EXISTS queue_status ON queue(status);
CREATE INDEX IF NOT EXISTS queue_created_at ON queue(created_at);

-- Stuck-task forensics: every time the watchdog flags a long-running task
-- as stuck (started > stuck_threshold ago AND artifact untouched for > 5min)
-- we append one row here. Useful as a post-mortem trail when investigating
-- silent provider stalls, infinite tool loops, or network partitions.
CREATE TABLE IF NOT EXISTS stuck_tasks (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id            INTEGER NOT NULL DEFAULT 0,
    task_title         TEXT    NOT NULL DEFAULT '',
    started_at         TEXT    NOT NULL DEFAULT '',
    detected_at        TEXT    NOT NULL DEFAULT '',
    stuck_for_seconds  INTEGER NOT NULL DEFAULT 0,
    artifact_idle_secs INTEGER NOT NULL DEFAULT 0,
    artifact_path      TEXT    NOT NULL DEFAULT '',
    auto_killed        INTEGER NOT NULL DEFAULT 0,
    note               TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS stuck_tasks_task_id ON stuck_tasks(task_id);
CREATE INDEX IF NOT EXISTS stuck_tasks_detected_at ON stuck_tasks(detected_at);
