-- Virtual executors are listed per device — the Executors panel renders them
-- under their parent, and revoking a device has to find every sub-executor it
-- leaves orphaned — so the parent is indexed (Task 20345).
--
-- The table is asserted first, idempotently. A database that recorded version
-- 49 from a stranded build's own migration (one on the sgx executor host
-- does: 0049_project_members.sql) skipped this build's 0049, and an index on a
-- table that does not exist aborts the whole migration run — taking the hub's
-- database down with it — before 0051 could repair anything.
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
