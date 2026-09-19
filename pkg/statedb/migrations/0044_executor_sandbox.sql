-- executor_sandbox — per-executor sandbox configuration (Task 20307).
--
-- The row answers a question that had no home: *on this executor, does a
-- payload run on the host, or in a container on that host, and under which
-- runtime?*
--
-- For every driver the hub constructs itself the question is settled by
-- config.yaml before anything runs, because there the driver *is* the answer.
-- A remote agent is the exception: the hub does not choose the driver on an
-- edge device, the device did — and it chose host execution unconditionally,
-- while advertising the container runtimes it had found on PATH. This table is
-- where an admin overrides that, per executor, from the UI.
--
-- It lives in the control plane rather than on the device for the reason
-- project_executors and project_resource_limits do: it is an operator's policy
-- *about* an executor, not a fact belonging to it. A device that stored its own
-- containment setting could be asked by its own operator to lie about it, and
-- the hub would have no way to tell. Here the hub reads the row at dispatch and
-- stamps it on the start frame, so the device gets told rather than consulted.
--
-- An absent row means "unset", which is not the same as mode='host': it means
-- nobody has said, so the executor keeps behaving exactly as it did before this
-- table existed. That is what makes the migration a no-op for every existing
-- deployment.
--
-- Additive: one CREATE TABLE and one CREATE INDEX, the form schema_compat.go
-- classifies as additive. An older binary sharing this control plane never
-- selects a table it does not know about, so it keeps reading the database
-- rather than refusing to open it — which is the 2026-09-14 outage that file
-- exists to prevent.
CREATE TABLE IF NOT EXISTS executor_sandbox (
    executor_id TEXT PRIMARY KEY,
    -- '' | 'host' | 'container'. Stored as written rather than as a constraint,
    -- because a value this binary does not recognise must be legible to an
    -- operator debugging it rather than rejected at read time by SQLite.
    mode        TEXT NOT NULL DEFAULT '',
    -- The container CLI to drive: 'docker', 'podman', 'nerdctl'. Empty lets the
    -- executor detect one.
    engine      TEXT NOT NULL DEFAULT '',
    -- The OCI runtime the engine hands each container to — the `--runtime`
    -- value. Empty means the engine's default (runc/crun). This is the column
    -- that decides whether the payload sits behind a hypervisor.
    runtime     TEXT NOT NULL DEFAULT '',
    -- Image payloads run in; empty means the executor's configured default.
    image       TEXT NOT NULL DEFAULT '',
    set_at      TEXT NOT NULL DEFAULT '',
    set_by      TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_executor_sandbox_set_at
    ON executor_sandbox(set_at);
