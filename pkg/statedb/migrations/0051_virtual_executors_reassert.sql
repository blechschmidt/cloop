-- Re-asserts 0049 and 0050, idempotently (Task 20345).
--
-- Versions 49 and 50 were recorded on at least one deployed control plane from
-- a stranded working tree whose own migrations used those numbers (see the
-- SKIPPED warning migrate.go prints for a divergent version). On such a
-- database this build's 0049 and 0050 never run — the version is already
-- there — so the table would be missing exactly where the feature was deployed
-- to. Everywhere else these statements find the objects present and do
-- nothing.
CREATE TABLE IF NOT EXISTS virtual_executors (
    id         TEXT PRIMARY KEY,
    parent_id  TEXT NOT NULL,
    name       TEXT NOT NULL DEFAULT '',
    spec_json  TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_virtual_executors_parent
    ON virtual_executors(parent_id);
