-- 0097_task_kind: what a plan entry is (Task 20477).
--
-- plan_tasks.kind — '' for work an agent performs, which is every row written
-- before this migration, or 'human_gate' for a human review gate: an entry in
-- the queue that no agent runs and that holds every task after it in
-- execution order until a person approves it. Set when the entry is created
-- (`cloop task gate add`, POST /api/tasks/gate) and never changed after.
--
-- IF NOT EXISTS is the migration runner's (addcolumn.go), as in 0054 and 0087.
--
-- An append to plan_tasks, recorded additive-columns like 0087: builds from
-- Task 20388 on update rows in place and keep the column; older ones refuse
-- the database. A build that predates this column but reads it keeps it, and
-- treats a gate as an ordinary task, so the hub refuses to send a plan holding
-- one to a device agent older than protocol 27.

ALTER TABLE plan_tasks ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT '';
