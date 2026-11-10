-- 0100_executor_pool_storage: what an executor pool's runner storage holds,
-- and what a pool's controller last said about its own health (Task 20484).
--
-- A pool's controller may give each runner a persistent volume that outlives
-- the runner — a workspace, a git object cache, tool caches — so a project's
-- next run does not clone and build from nothing. A volume that served one
-- project must never be handed, unwiped, to a run of another: so a runner
-- records what its storage holds, and the hub hands it only a run of that
-- project.
--
-- executor_pool_runners
--   holds          the tenant (executorpool.ProjectTenant: a digest of the
--                  pool, the project and its owner) whose data the runner's
--                  storage holds, as its controller declared when minting it;
--                  '' for a runner whose storage is empty — fresh, or wiped
--                  before it started — or that has none. A runner that holds
--                  a tenant is handed only that tenant's runs, which the
--                  assignment's UPDATE itself checks. Once a runner was handed
--                  a run, returning it to idle unstarted makes the run's
--                  tenant what it holds, so it is never handed another's.
--   project        the tenant of the run the runner was handed, set as it is
--                  handed it: how the hub tells the controller, on its feed,
--                  each runner's project at assignment.
--   project_name   that project's name, for the people reading the volume's
--                  record in the cluster.
--   project_owner  that project's owner key, '' when unowned.
--
-- executor_pool_controller_status  one row per pool and controller credential:
--                  the last health report the controller made — ok, or the
--                  reason and message of what keeps it from starting runners
--                  (a volume stuck Pending, a full one) — so the runs waiting
--                  in the pool's queue say why, on every hub member.
--
-- Columns added to a table no build rewrites, and a new table: additive in
-- schema_compat.go's sense. An older binary sharing this control plane never
-- names them; it would mint runners holding nothing and hand them any run,
-- which is what a runner without storage is.
ALTER TABLE executor_pool_runners ADD COLUMN IF NOT EXISTS holds TEXT NOT NULL DEFAULT '';
ALTER TABLE executor_pool_runners ADD COLUMN IF NOT EXISTS project TEXT NOT NULL DEFAULT '';
ALTER TABLE executor_pool_runners ADD COLUMN IF NOT EXISTS project_name TEXT NOT NULL DEFAULT '';
ALTER TABLE executor_pool_runners ADD COLUMN IF NOT EXISTS project_owner TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS executor_pool_controller_status (
    pool_id       TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    healthy       INTEGER NOT NULL DEFAULT 1,
    reason        TEXT NOT NULL DEFAULT '',
    message       TEXT NOT NULL DEFAULT '',
    reported_at   TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (pool_id, credential_id)
);
