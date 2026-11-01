-- 0088_requirements_gate: requirement-gated completion (Task 20461).
--
-- A project may hold its tasks to their requirements: with the gate on, a task
-- whose agent reports TASK_DONE is checked — its linked requirements, and in
-- linked+must mode every approved must requirement — on the project's
-- executor, and becomes done only when they pass. The setting itself is a
-- metadata row (requirements_gate), as the commit policy is; what the gate
-- found is recorded here.
--
-- plan_tasks.requirements_check — what the gate found when it last checked the
-- task's work, as JSON (pm.TaskRequirementsCheck): each requirement's verdict
-- and test outcomes, which of them kept the task from being done, and which
-- are regressions. '' when the gate never checked it. It is what the task's
-- next attempt is told, what the task's page shows, and how a verdict reached
-- on a device travels back to the hub with the task.
--
-- requirement_checks.task_id — the task whose completion the check gated, or
-- 0 for a check that gated none (the dashboard's, `cloop requirements check`,
-- a verdict recorded by hand). With git_commit it ties a verdict to the task
-- and the commit it was reached at.
--
-- requirement_checks.regression — 1 when the requirement was fulfilled at its
-- previous check of the same definition and this check found it unfulfilled:
-- something since broke it. 2 when it still fails at a later check gating the
-- same task — a regression that persists through the task's retries, which
-- the task shows but the journal and the notifier report once. 0 otherwise.
-- Indexed, because the hub's notifier looks for the regressions of every
-- project it serves.
--
-- requirement_runs.task_id — as on requirement_checks, for the run.
--
-- An append to plan_tasks, so additive-columns (schema_compat.go), as 0087:
-- builds from Task 20388 on update task rows in place, in the columns they
-- know, and keep this one; every build before refuses the database instead.
-- The other two tables are not rewritten by any build.

ALTER TABLE plan_tasks ADD COLUMN IF NOT EXISTS requirements_check TEXT NOT NULL DEFAULT '';

ALTER TABLE requirement_checks ADD COLUMN IF NOT EXISTS task_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE requirement_checks ADD COLUMN IF NOT EXISTS regression INTEGER NOT NULL DEFAULT 0;
ALTER TABLE requirement_runs ADD COLUMN IF NOT EXISTS task_id INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS requirement_checks_task ON requirement_checks(task_id, id);
CREATE INDEX IF NOT EXISTS requirement_checks_regression ON requirement_checks(regression, id);
