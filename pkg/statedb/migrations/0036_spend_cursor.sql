-- 0036_spend_cursor: the hub's booking position in each project's cost ledger
-- (Task 20264).
--
-- Quota counters are incremented by the hub, but the numbers are written by the
-- orchestrator into the *project's* database, one row per finished task. So the
-- hub is a reader catching up with a writer it does not share a process with,
-- and a reader like that needs two things to be correct across a restart: where
-- it got to, and who it is billing. This table holds both, in the control plane
-- — deliberately not in the project database, which lives inside the sandbox's
-- own workspace and is therefore the workload's to edit.
--
--   project_path      the project this cursor tracks, absolute. Primary key:
--                     one cursor per project, because one ledger per project.
--
--   identity          who the hub resolved at dispatch, and the only identity
--                     it will ever bill this project's spend to. Re-stamped at
--                     each dispatch, so the next run bills its own initiator.
--
--                     This is the load-bearing column of the whole feature. The
--                     costs table also carries an identity, but that one is
--                     written inside the sandbox; if enforcement read it, a
--                     workload could drain a colleague's daily budget by
--                     writing their address into its own ledger. Enforcement
--                     reads this column instead, which only the hub can write.
--
--   last_cost_row_id  the highest costs.id already booked into the quota
--                     counters. Rows at or below it have been charged; rows
--                     above have not.
--
--                     An id rather than a timestamp because this is a
--                     de-duplication key, and timestamps are not unique (two
--                     tasks can finish in the same nanosecond) nor monotonic (a
--                     clock adjustment moves one backwards). Either failure
--                     bills a tenant twice or lets spend through unbilled.
--
--                     Seeded at dispatch from MAX(id), not from zero: a hub
--                     adopting a project that already has a year of history
--                     must not bill today's tenant for all of it.
--
-- Deleting a row is safe and loses only a position — the next dispatch reseeds
-- it. Nothing here is a permission or a credential, so a missing row degrades
-- to "bill nothing yet", never to "allow more than the cap".

CREATE TABLE IF NOT EXISTS project_spend_cursor (
    project_path     TEXT PRIMARY KEY,
    identity         TEXT    NOT NULL DEFAULT '',
    last_cost_row_id INTEGER NOT NULL DEFAULT 0,
    updated_at       TEXT    NOT NULL DEFAULT ''
);

-- "Everything this identity is currently attached to" is how offboarding and
-- the fleet spend view both read this table; without an index that is a scan
-- per identity over every project the hub has ever dispatched for.
CREATE INDEX IF NOT EXISTS idx_spend_cursor_identity ON project_spend_cursor(identity);
