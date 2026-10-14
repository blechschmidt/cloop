-- task_attachments — files attached to a task (Task 20428).
--
-- A task's transcript says what an agent did; an attachment is what it made
-- for a person to look at: a report, a chart, a screenshot, a data export, a
-- log. A run attaches a file by copying it into the task's outbox
-- (.cloop/attachments/outbox/<task id>/), and the orchestrator moves it into
-- the store when the attempt ends; `cloop task attachments add` attaches one
-- by hand. The bytes live beside this database, in .cloop/attachments/<id>;
-- this table is what describes them.
--
--   id           32 lower-case hex characters, random. Also the file's name
--                in the store, so it is never anything a run chose.
--   task_id      the task. Not a foreign key: plan_tasks is rewritten row by
--                row by every save, and a reference would make an older
--                binary's delete of a task fail. Rows of a deleted task are
--                deleted by the save that drops it (and by DeleteTask), and a
--                task id that comes back — ids are reused — starts with none.
--   name         the name it was attached under: its path inside the outbox,
--                slash-separated, cleaned. Display only — it never names a
--                file on disk.
--   media_type   the type cloop detected for it, from its name and content.
--   size         bytes in the store.
--   sha256       hex digest of the bytes in the store.
--   source       'run' (a run's outbox) or 'cli' (attached by hand).
--   run_id       the execution that attached it, for 'run'.
--   note         what the attacher said about it, for 'cli'.
--   added_by     who attached it: 'agent' for a run, the local user for 'cli'.
--   created_at   when it was attached, RFC 3339.
--   unavailable  empty when the bytes are in the store; otherwise why they
--                are not — a run on a remote executor whose result had no room
--                for the file left it on the device.
--
-- Additive in schema_compat.go's sense: a new table, which no shipped build
-- reads or writes, and not a plan_tasks column — builds before Task 20388
-- rewrite plan_tasks on every save and would erase one.
CREATE TABLE IF NOT EXISTS task_attachments (
    id          TEXT PRIMARY KEY,
    task_id     INTEGER NOT NULL,
    name        TEXT NOT NULL,
    media_type  TEXT NOT NULL DEFAULT 'application/octet-stream',
    size        INTEGER NOT NULL DEFAULT 0,
    sha256      TEXT NOT NULL DEFAULT '',
    source      TEXT NOT NULL DEFAULT '',
    run_id      TEXT NOT NULL DEFAULT '',
    note        TEXT NOT NULL DEFAULT '',
    added_by    TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT '',
    unavailable TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS task_attachments_task ON task_attachments(task_id, created_at);
