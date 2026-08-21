-- 0010_executors: registry of execution backends and their per-project
-- bindings (Task 20156).
--
-- cloop is moving from "the Web UI forks the harness on its own host" to
-- "the Web UI dispatches work to a registered executor". An executor may be
-- the local host (kind='localprocess'), a container runtime on the host
-- (kind='container'), or a remote agent that enrolled itself over an
-- outbound connection (kind='remote'). This table is the control plane's
-- durable view of them; the in-process registry in pkg/executor is the
-- live view.
--
-- Columns:
--   id                stable unique identifier, also the registry key
--   name              human-readable label shown in the UI
--   kind              driver implementation (localprocess|container|remote)
--   endpoint          driver-specific address; empty for local execution
--   status            last known health: online|offline|degraded|unknown
--   capabilities_json marshalled executor.Capabilities
--   labels_json       free-form selector labels (region, arch, gpu, ...)
--   last_heartbeat    RFC3339 of the most recent liveness signal
--   created_at        RFC3339 of enrollment
--   enrolled_by       identity that enrolled it (OIDC subject, or '' local)
--
-- project_executors binds a project directory to the executor that must run
-- its work. A project with no row falls back to the registry default. A row
-- naming an unregistered executor is a hard failure at resolve time, never
-- a silent downgrade to host execution — that is the whole point of pinning
-- a project to an isolated backend.

CREATE TABLE IF NOT EXISTS executors (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL DEFAULT '',
    kind              TEXT NOT NULL DEFAULT '',
    endpoint          TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL DEFAULT 'unknown',
    capabilities_json TEXT NOT NULL DEFAULT '{}',
    labels_json       TEXT NOT NULL DEFAULT '{}',
    last_heartbeat    TEXT NOT NULL DEFAULT '',
    created_at        TEXT NOT NULL DEFAULT '',
    enrolled_by       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_executors_kind ON executors(kind);

CREATE INDEX IF NOT EXISTS idx_executors_status ON executors(status);

CREATE TABLE IF NOT EXISTS project_executors (
    project_path TEXT PRIMARY KEY,
    executor_id  TEXT NOT NULL,
    bound_at     TEXT NOT NULL DEFAULT '',
    bound_by     TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_project_executors_executor ON project_executors(executor_id);
