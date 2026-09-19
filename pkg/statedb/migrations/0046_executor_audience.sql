-- executor_audience — who may run work on one executor (Task 20310).
--
-- cloop had no answer to "make this executor available to these people and not
-- to everyone". Every identity holding executor.manage could bind any project
-- to any executor, and pkg/executor's Resolve — the chokepoint every dispatch
-- funnels through — is handed a project path and no identity at all, so there
-- was nowhere for the question to even be asked.
--
-- # Why this is not a role binding
--
-- pkg/authz already supports narrowing a binding to one executor
-- (Binding.Executor), and at first glance that is this feature. It is the
-- opposite one. A role binding is *additive*: it grants an identity a role,
-- optionally only on executor X. Granting nobody anything on executor Y leaves
-- Y reachable by every identity whose unscoped binding already covers it.
-- Restriction cannot be expressed by adding grants, because the permission
-- being restricted is one the caller already holds fleet-wide.
--
-- So this table is a gate rather than a grant, and it is deliberately
-- *opt-in per executor*: an executor with no rows is unrestricted, exactly as
-- every executor was before this table existed. Adding the first row is the act
-- that turns the gate on, which is what keeps the migration a no-op for
-- existing deployments and makes the UI control honest — an admin who lists two
-- groups has restricted it to two groups, and an admin who lists none has not
-- accidentally locked the fleet out of itself.
--
-- # principal_kind
--
-- 'user' matches an identity's subject or email; 'group' matches a value of the
-- OIDC group claim, in either Keycloak's '/cloop-admins' path form or the bare
-- form — the same two spellings authz.matchesClaim already normalises, so an
-- admin types what their IdP shows them and it works.
--
-- The pair is the primary key rather than a synthetic id: admitting the same
-- group twice is not two facts, and an INSERT OR REPLACE keyed on the pair
-- makes re-adding an existing principal idempotent rather than a duplicate row
-- that one DELETE would leave half-removed.
--
-- Additive: one CREATE TABLE and one CREATE INDEX, the form schema_compat.go
-- classifies as additive. An older binary sharing this control plane never
-- selects a table it does not know about — it keeps reading the database rather
-- than refusing to open it. Note what that means for this table specifically:
-- an older hub does not enforce the gate, because it cannot see it. That is the
-- correct trade and the same one every other policy table here makes, but it is
-- the reason the audience is enforced at dispatch as well as at bind time —
-- see pkg/ui/executoraudience.go.
CREATE TABLE IF NOT EXISTS executor_audience (
    executor_id     TEXT NOT NULL,
    -- 'user' | 'group'. Stored as written rather than as a CHECK constraint,
    -- because a value this binary does not recognise must be legible to an
    -- operator debugging it rather than rejected at read time by SQLite.
    principal_kind  TEXT NOT NULL,
    principal_value TEXT NOT NULL,
    added_at        TEXT NOT NULL DEFAULT '',
    added_by        TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (executor_id, principal_kind, principal_value)
);

CREATE INDEX IF NOT EXISTS idx_executor_audience_executor
    ON executor_audience(executor_id);
