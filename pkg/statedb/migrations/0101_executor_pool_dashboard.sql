-- 0101_executor_pool_dashboard: what the dashboard, the CLI and hub doctor show
-- of an executor pool, and what a task keeps of the pool runner it ran on
-- (Task 20486).
--
-- executor_pools
--   cordoned_at    set while an administrator holds the pool: its runners are
--   cordoned_by    handed no queued run, its controller is told no demand and
--   cordon_reason  minted no runner, and runners already busy finish their
--                  runs. RFC 3339 UTC, the acting identity and why; all three
--                  are cleared by uncordoning.
--
-- executor_pool_credentials
--   controller_version   the build the controller using the credential last
--                        named in its User-Agent, '' for none.
--   controller_protocol  the pool-controller protocol it last said it speaks
--                        (X-Cloop-Pool-Controller-Protocol); 0 for a controller
--                        that says none, which is one older than this numbering.
--
-- executor_pool_controller_status
--   storage_json   the controller's last count of its runners' volumes, a JSON
--                  object (claims, bound, pending, in use, bytes used and
--                  capacity); '' when it keeps none or did not say.
--
-- executor_pool_placements  in a project's database: one row per pool runner a
--                  run of the project was handed, written by the hub as it
--                  hands the run over. A task records the executor it ran on;
--                  for a pool runner that is an ephemeral agent whose record the
--                  control plane prunes once it is retired, so this is what
--                  still names the pool and the runner when the task is read
--                  later. The task readers join it in by executor_id.
--
-- Columns appended to tables no build rewrites, and a new table: additive in
-- schema_compat.go's sense. An older binary sharing this control plane never
-- names them: it hands a cordoned pool's runners runs as if it were not
-- cordoned, and shows tasks by their runner's id.
ALTER TABLE executor_pools ADD COLUMN IF NOT EXISTS cordoned_at TEXT NOT NULL DEFAULT '';
ALTER TABLE executor_pools ADD COLUMN IF NOT EXISTS cordoned_by TEXT NOT NULL DEFAULT '';
ALTER TABLE executor_pools ADD COLUMN IF NOT EXISTS cordon_reason TEXT NOT NULL DEFAULT '';

ALTER TABLE executor_pool_credentials ADD COLUMN IF NOT EXISTS controller_version TEXT NOT NULL DEFAULT '';
ALTER TABLE executor_pool_credentials ADD COLUMN IF NOT EXISTS controller_protocol INTEGER NOT NULL DEFAULT 0;

ALTER TABLE executor_pool_controller_status ADD COLUMN IF NOT EXISTS storage_json TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS executor_pool_placements (
    executor_id  TEXT PRIMARY KEY,
    pool_id      TEXT NOT NULL DEFAULT '',
    pool_name    TEXT NOT NULL DEFAULT '',
    runner_name  TEXT NOT NULL DEFAULT '',
    recorded_at  TEXT NOT NULL DEFAULT ''
);
