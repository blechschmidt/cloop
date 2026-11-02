-- 0090_requirement_proofs: red-green proofs of requirements' tests (Task 20464).
--
-- A check says whether a requirement's tests pass; a proof says whether they
-- show anything. It runs them twice — at the base, the code before a change,
-- in a throwaway checkout, and on the change — and records what the two runs
-- add up to: proven (red before, green after), vacuous (green before), broken
-- (red after), inconclusive (the test does not exist at the base, and the
-- base code with the change's test files laid over it could not settle it),
-- or error (the proof itself did not work).
--
-- requirement_proofs — one row per requirement per proof, newest last:
--
--   run_id       the run that produced it (requirement_runs), or the gate
--                check's run for a proof of a task's tests.
--   outcome      proven, vacuous, broken, inconclusive or error.
--   summary      one sentence saying why.
--   detail       JSON: each side's tests — outcome, exit status, duration and
--                the end of their output, scrubbed of credentials — the test
--                files the change added, changed or removed, and whether it
--                held anything besides them.
--   fingerprint  the requirement's definition as proved, like a check's: a
--                proof whose fingerprint is not the requirement's current one
--                is about tests it no longer has.
--   base_commit, the base, and how it was chosen: task (where the task's work
--   base_from    started), test (the commit before the test's implementation),
--                worktree (the test was uncommitted) or given.
--   git_commit,  HEAD of the change and whether it had uncommitted work.
--   dirty
--   fallback     1 when the base run used the base code with the change's test
--                files laid over it.
--   new_tests    1 when the change added a test rather than only changing one:
--                a vacuous proof of a new test keeps a task from being done
--                under the requirements gate's linked+must mode.
--   executor_id, where it ran, who asked, when, and how long it took.
--   proved_by,
--   proved_at,
--   duration_ms
--   task_id      the task whose tests it proved, or 0.
--
-- Bounded by its writer: a requirement keeps its newest 20 proofs — each holds
-- two runs' output, where a check holds one.
--
-- requirement_runs.kind — prove for a run of proofs; anything else, '' for
-- the runs before this column, is a check. A proof takes the project's one
-- check slot, as a check does: both run the requirement's tests in the
-- project's tree.
--
-- Additive in schema_compat.go's sense: a new table no shipped build reads,
-- and a defaulted column appended to one that no build rewrites.

CREATE TABLE IF NOT EXISTS requirement_proofs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    requirement_id INTEGER NOT NULL,
    run_id         TEXT    NOT NULL DEFAULT '',
    outcome        TEXT    NOT NULL,
    summary        TEXT    NOT NULL DEFAULT '',
    detail         TEXT    NOT NULL DEFAULT '{}',
    fingerprint    TEXT    NOT NULL DEFAULT '',
    base_commit    TEXT    NOT NULL DEFAULT '',
    base_from      TEXT    NOT NULL DEFAULT '',
    git_commit     TEXT    NOT NULL DEFAULT '',
    dirty          INTEGER NOT NULL DEFAULT 0,
    fallback       INTEGER NOT NULL DEFAULT 0,
    new_tests      INTEGER NOT NULL DEFAULT 0,
    executor_id    TEXT    NOT NULL DEFAULT '',
    proved_by      TEXT    NOT NULL DEFAULT '',
    proved_at      TEXT    NOT NULL DEFAULT '',
    duration_ms    INTEGER NOT NULL DEFAULT 0,
    task_id        INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS requirement_proofs_requirement ON requirement_proofs(requirement_id, id);

ALTER TABLE requirement_runs ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT '';
