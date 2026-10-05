-- secret_leases — every live lease a hub process issued, so the lease outlives
-- the process (Task 20382).
--
-- A lease lived only in the memory of the hub process that issued it: the
-- broker's record of it, the keepalive that extends it while its run is live,
-- the janitor that takes it back when it lapses, and the release that ends it
-- with the run. A hub restarted while a device ran a task — :8888 restarts
-- nightly — came back with none of that. The run itself survived (its owner
-- row and handle row were already durable, Tasks 20191 and 20354), but its
-- credentials were held by nobody: never extended, never swept, never
-- released, and invisible in the Secrets panel for the rest of the run.
--
-- A row here is that record. The process that adopts the run takes the lease
-- over by moving `holder` to itself, keeps it alive, and releases it when the
-- run ends; a lease whose holder stopped and that nobody took over is swept
-- once it lapses, on the devices that hold it as well as here.
--
--   lease_id     the broker's lease id, the primary key.
--   holder       the hub process (cluster member id) that keeps the lease
--                alive and owes its release. Taking a lease over is a
--                conditional UPDATE on it, so two processes adopting the same
--                run cannot both hold its lease.
--   executor_id, project_id, run_id
--                who the lease was issued to, for the sweep and for operators;
--                the same values record_json carries.
--   record_json  the requester (executor, project, run, labels, withheld
--                grants), the audit actor, the credential kinds and the grant
--                ids the lease carries. Ids and names only — never a value: a
--                lease's material is re-derived from its grants by whoever
--                needs it, and is never written here.
--   issued_at, expires_at, updated_at
--                RFC 3339 UTC. expires_at moves forward with every extension.
--
-- Additive in schema_compat.go's sense: a binary predating this table neither
-- reads nor writes it, and keeps its leases in memory exactly as before.
CREATE TABLE IF NOT EXISTS secret_leases (
    lease_id    TEXT PRIMARY KEY,
    holder      TEXT NOT NULL DEFAULT '',
    executor_id TEXT NOT NULL DEFAULT '',
    project_id  TEXT NOT NULL DEFAULT '',
    run_id      TEXT NOT NULL DEFAULT '',
    record_json TEXT NOT NULL DEFAULT '{}',
    issued_at   TEXT NOT NULL DEFAULT '',
    expires_at  TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL DEFAULT ''
);

-- "What did this process hold" when it stops, and the sweep's scan.
CREATE INDEX IF NOT EXISTS idx_secret_leases_holder ON secret_leases(holder);
