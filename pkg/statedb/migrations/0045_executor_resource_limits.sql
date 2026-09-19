-- executor_resource_limits — the per-executor resource ceiling (Task 20310).
--
-- The third ceiling, and the one whose absence had no workaround. cloop could
-- already say "no workload on this hub gets more than this" (config
-- `executors.limits`) and "this one project gets no more than this"
-- (project_resource_limits, 0043). It could not say the sentence an admin
-- onboarding a device actually wants to say: *this machine has 8 GB, so nothing
-- that lands here gets more, whatever the fleet allows and whatever the project
-- asks for.*
--
-- Neither existing ceiling can express it. The fleet's applies to every
-- executor, so writing the weakest device's capacity there holds the whole
-- fleet down to it. The project's is set per project, and a project does not
-- know which executor it will be placed on — that is the hub's decision, made
-- after the ceiling was written.
--
-- It is a separate table from executor_sandbox (0044) rather than four more
-- columns on it, because the two have independent lifecycles. Clearing an
-- executor's sandbox override — "go back to deciding containment for yourself"
-- — must not also drop the cap on how much memory it may hand out, and a
-- single row makes those one operation. The split mirrors 0043's, which is the
-- same policy about a project rather than about an executor.
--
-- Zero on any column means that resource is uncapped for this executor, which
-- is what an executor with no row gets too — so inserting a row that caps only
-- memory leaves CPU exactly as it was. That is what makes this migration a
-- no-op for every existing deployment.
--
-- Additive: one CREATE TABLE and one CREATE INDEX, the form schema_compat.go
-- classifies as additive. An older binary sharing this control plane never
-- selects a table it does not know about, so it keeps reading the database
-- rather than refusing to open it — which is the 2026-09-14 outage that file
-- exists to prevent.
CREATE TABLE IF NOT EXISTS executor_resource_limits (
    executor_id TEXT PRIMARY KEY,
    cpu_millis  INTEGER NOT NULL DEFAULT 0,
    memory_mb   INTEGER NOT NULL DEFAULT 0,
    disk_mb     INTEGER NOT NULL DEFAULT 0,
    pids        INTEGER NOT NULL DEFAULT 0,
    set_at      TEXT NOT NULL DEFAULT '',
    set_by      TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_executor_resource_limits_set_at
    ON executor_resource_limits(set_at);
