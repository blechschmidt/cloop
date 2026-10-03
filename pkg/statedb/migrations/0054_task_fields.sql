-- 0054_task_fields: the pm.Task fields plan_tasks never had a column for
-- (Task 20361).
--
-- When state moved from state.json to SQLite, the writer and both readers
-- enumerated this table's columns by hand, and these fields were not among
-- them. Every feature that sets one worked until the next load and then read
-- back zero: team assignment, `cloop task link`, sprint planning,
-- ai-complexity, plan branching, the risk matrix, ai-impact, per-task retry
-- budgets and TDD verification. A branched plan quietly stopped branching,
-- because the orchestrator that ran it had loaded on_success and on_failure as
-- empty lists.
--
-- Columns, each named for its pm.Task field:
--
--   assignee, external_url, complexity_size, tdd_status   text, '' when unset
--   tdd_score, sprint_id, story_points, risk_score,
--   impact_score, retry_budget                             integers, 0 when unset
--   links, on_success, on_failure                          JSON arrays, like
--                                                          depends_on and tags
--
-- ChainInput gets no column: it is a copy of the chained predecessor's output
-- (up to 16 MiB), derived again when the chained task is dispatched rather
-- than rewritten into every save. RunID already lives in task_runs.
--
-- IF NOT EXISTS is the migration runner's, not SQLite's (see addcolumn.go). It
-- is load-bearing: `cloop migrate` (pkg/migrate) has added assignee,
-- external_url and links to every project it ever upgraded, with no row in
-- schema_migrations to say so, and the hub's own control plane is one of them.
-- A plain ADD COLUMN would fail there with "duplicate column name" and keep the
-- hub from starting. The three are declared exactly as pkg/migrate declares
-- them, so its columns are adopted; a column of any other shape fails this
-- migration and names both shapes.
--
-- Additive in the form schema_compat.go admits: NOT NULL with a DEFAULT and no
-- constraint, so an older binary sharing this database neither selects nor
-- inserts the columns and keeps opening it.

ALTER TABLE plan_tasks ADD COLUMN IF NOT EXISTS assignee        TEXT    NOT NULL DEFAULT '';
ALTER TABLE plan_tasks ADD COLUMN IF NOT EXISTS external_url    TEXT    NOT NULL DEFAULT '';
ALTER TABLE plan_tasks ADD COLUMN IF NOT EXISTS links           TEXT    NOT NULL DEFAULT '[]';
ALTER TABLE plan_tasks ADD COLUMN IF NOT EXISTS tdd_status      TEXT    NOT NULL DEFAULT '';
ALTER TABLE plan_tasks ADD COLUMN IF NOT EXISTS tdd_score       INTEGER NOT NULL DEFAULT 0;
ALTER TABLE plan_tasks ADD COLUMN IF NOT EXISTS sprint_id       INTEGER NOT NULL DEFAULT 0;
ALTER TABLE plan_tasks ADD COLUMN IF NOT EXISTS complexity_size TEXT    NOT NULL DEFAULT '';
ALTER TABLE plan_tasks ADD COLUMN IF NOT EXISTS story_points    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE plan_tasks ADD COLUMN IF NOT EXISTS on_success      TEXT    NOT NULL DEFAULT '[]';
ALTER TABLE plan_tasks ADD COLUMN IF NOT EXISTS on_failure      TEXT    NOT NULL DEFAULT '[]';
ALTER TABLE plan_tasks ADD COLUMN IF NOT EXISTS risk_score      INTEGER NOT NULL DEFAULT 0;
ALTER TABLE plan_tasks ADD COLUMN IF NOT EXISTS impact_score    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE plan_tasks ADD COLUMN IF NOT EXISTS retry_budget    INTEGER NOT NULL DEFAULT 0;
