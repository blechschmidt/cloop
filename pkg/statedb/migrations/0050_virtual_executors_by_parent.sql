-- Virtual executors are listed per device — the Executors panel renders them
-- under their parent, and revoking a device has to find every sub-executor it
-- leaves orphaned — so the parent is indexed (Task 20345).
CREATE INDEX IF NOT EXISTS idx_virtual_executors_parent
    ON virtual_executors(parent_id);
