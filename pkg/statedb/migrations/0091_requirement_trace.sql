-- 0091_requirement_trace: indexes for the traceability matrix (Task 20465).
--
-- The matrix — each approved requirement with its tasks, their commits, its
-- latest verdict and its latest proof — is read a page at a time in id order
-- (statedb/requirements_trace.go): `status = 'approved' AND id > ?`, and with
-- a priority filter `AND priority = ?`, then ORDER BY id LIMIT ?. Without an
-- index the page walks the table from the cursor and reads every draft and
-- deprecated row on the way; with these the page seeks its first row and reads
-- only rows it returns. An index ends in the row's id implicitly, so both
-- serve the ORDER BY and the keyset without a sort.
--
-- Each row's latest check and latest proof are found through the indexes 0085
-- and 0090 made, requirement_checks(requirement_id, id) and
-- requirement_proofs(requirement_id, id).
--
-- Additive in schema_compat.go's sense: two plain indexes, which change only
-- the query planner's options.

CREATE INDEX IF NOT EXISTS requirements_status ON requirements(status);
CREATE INDEX IF NOT EXISTS requirements_status_priority ON requirements(status, priority);
