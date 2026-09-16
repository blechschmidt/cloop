-- project_resource_limits — the per-project resource ceiling (Task 20301).
--
-- A project's resource *request* already had a home: .cloop/sandbox.yaml, in
-- the repository. That file is the right place for a project to say what it
-- needs and the wrong place for anyone to say what it may have, because it is
-- authored by whoever can push to the repo. The hub had nowhere to record the
-- other half of that sentence, so "cap this one project at 2 GB" was not a
-- thing an operator could express.
--
-- It lives in the control plane rather than in the project's own state.db, for
-- the same reason project_executors does: it is an operator's policy *about* a
-- project, not a fact belonging to it. Both tables answer questions the project
-- does not get a vote on.
--
-- Zero on any column means that resource is uncapped for this project, which is
-- what a project with no row gets too — so inserting a row that caps only
-- memory leaves CPU exactly as it was.
--
-- Additive: one CREATE TABLE and one CREATE INDEX, the form schema_compat.go
-- classifies as additive. An older binary sharing this control plane never
-- selects a table it does not know about, so it keeps reading the database
-- rather than refusing to open it — which is the 2026-09-14 outage that file
-- exists to prevent.
CREATE TABLE IF NOT EXISTS project_resource_limits (
    project_path TEXT PRIMARY KEY,
    cpu_millis   INTEGER NOT NULL DEFAULT 0,
    memory_mb    INTEGER NOT NULL DEFAULT 0,
    disk_mb      INTEGER NOT NULL DEFAULT 0,
    pids         INTEGER NOT NULL DEFAULT 0,
    set_at       TEXT NOT NULL DEFAULT '',
    set_by       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_project_resource_limits_set_at
    ON project_resource_limits(set_at);
