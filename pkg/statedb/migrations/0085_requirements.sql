-- 0085_requirements: what a project must keep doing, and whether it still does
-- (Task 20458).
--
-- requirements — one row per requirement:
--
--   id           AUTOINCREMENT, so an id is never given to a second
--                requirement after the first is deleted: a verdict, an audit
--                row or a task that names R-7 names one requirement for good.
--   title,       what the project must do, and in what detail.
--   description
--   priority     must, should, could, or '' (unranked).
--   tags         a JSON array of lower-case tags.
--   tests        a JSON array of {name, command, timeout_seconds}: shell
--                commands run in the project's root, passing when they exit 0.
--                '[]' for a requirement nothing tests.
--   created_*,   when and by whom, as fixed-width UTC text.
--   updated_*
--
-- requirement_checks — one row per requirement per check, newest last:
--
--   run_id       the check run that produced it (requirement_runs), or '' for
--                a verdict a person recorded.
--   method       tests, ai (the model read the code), manual, or none.
--   verdict      fulfilled, unfulfilled, unverified or error.
--   summary      one line saying why.
--   detail       JSON: each test's outcome, exit status, duration and the end
--                of its output (16 KiB at most), scrubbed of credentials; or
--                the model's evidence.
--   fingerprint  the requirement's definition as checked — title, description
--                and tests. A verdict whose fingerprint is not the
--                requirement's current one is stale.
--   git_commit,  HEAD of the tree the check ran in, and whether that tree had
--   dirty        uncommitted changes.
--   executor_id  where it ran.
--
-- Bounded by its writer: a requirement keeps its newest 50 checks.
--
-- requirement_runs — one row per check run, so a run in progress is visible to
-- every hub member and a run whose member died is seen to have lapsed
-- (heartbeat, deadline):
--
--   state            running, done, failed or cancelled.
--   source           dashboard or cli.
--   requirement_ids  a JSON array: what the run was asked to check.
--   fulfilled, …     what it found, by verdict.
--   cancel_requested set by a cancel from any member; the member running the
--                    check stops it.
--   heartbeat        when the member running the check last said it still is,
--                    every few seconds: a run silent for long has lost its
--                    member, and stops holding the project's one check.
--
-- Bounded by its writer: the newest 200 runs are kept.
--
-- Additive in schema_compat.go's sense: three new tables no shipped build
-- reads, and nothing done to a table that exists.

CREATE TABLE IF NOT EXISTS requirements (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    priority    TEXT NOT NULL DEFAULT '',
    tags        TEXT NOT NULL DEFAULT '[]',
    tests       TEXT NOT NULL DEFAULT '[]',
    created_at  TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL DEFAULT '',
    created_by  TEXT NOT NULL DEFAULT '',
    updated_by  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS requirement_checks (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    requirement_id INTEGER NOT NULL,
    run_id         TEXT    NOT NULL DEFAULT '',
    method         TEXT    NOT NULL DEFAULT '',
    verdict        TEXT    NOT NULL,
    summary        TEXT    NOT NULL DEFAULT '',
    detail         TEXT    NOT NULL DEFAULT '{}',
    fingerprint    TEXT    NOT NULL DEFAULT '',
    git_commit     TEXT    NOT NULL DEFAULT '',
    dirty          INTEGER NOT NULL DEFAULT 0,
    executor_id    TEXT    NOT NULL DEFAULT '',
    checked_by     TEXT    NOT NULL DEFAULT '',
    checked_at     TEXT    NOT NULL DEFAULT '',
    duration_ms    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS requirement_checks_requirement ON requirement_checks(requirement_id, id);
CREATE INDEX IF NOT EXISTS requirement_checks_run ON requirement_checks(run_id);

CREATE TABLE IF NOT EXISTS requirement_runs (
    run_id           TEXT    PRIMARY KEY,
    state            TEXT    NOT NULL,
    source           TEXT    NOT NULL DEFAULT '',
    started_by       TEXT    NOT NULL DEFAULT '',
    started_at       TEXT    NOT NULL DEFAULT '',
    deadline         TEXT    NOT NULL DEFAULT '',
    finished_at      TEXT    NOT NULL DEFAULT '',
    executor_id      TEXT    NOT NULL DEFAULT '',
    assess           INTEGER NOT NULL DEFAULT 0,
    requirement_ids  TEXT    NOT NULL DEFAULT '[]',
    fulfilled        INTEGER NOT NULL DEFAULT 0,
    unfulfilled      INTEGER NOT NULL DEFAULT 0,
    unverified       INTEGER NOT NULL DEFAULT 0,
    errored          INTEGER NOT NULL DEFAULT 0,
    error            TEXT    NOT NULL DEFAULT '',
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    heartbeat        TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS requirement_runs_started ON requirement_runs(started_at);
CREATE INDEX IF NOT EXISTS requirement_runs_state ON requirement_runs(state);
