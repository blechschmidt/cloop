-- 0103_project_readers: which other projects may read a project (Task 20498).
--
-- A project's readers list is deny-by-default: no project may read another
-- unless the other's list names it. A row here is one such permission, written
-- by the project's administrator. pkg/projectreaders reads the table and
-- answers CanRead(reader, project) and ReadableBy(project); the runs that use
-- the answer (a read-only copy of the project in the reader's sandbox, a git
-- fetch or a knowledge search across projects) come later and ask it there.
--
-- Columns:
--   id            "prd_" and 24 random hex digits: how a person who cannot
--                 see the reader still names the row to remove it. Random, so
--                 the id says nothing about either path.
--   project_path  the project that may be read: its absolute, cleaned path on
--                 the hub, the project's identity there. A rename changes its
--                 registry name, never this path, and a move keeps the path.
--   reader_path   the project that may read it, the same way.
--   added_by      the identity that added the row ("local" on a hub without
--                 sign-in).
--   added_at      RFC 3339 UTC.
--
-- One row per pair (idx_project_readers_pair): adding a reader that is already
-- listed changes nothing. A project never lists itself, and a feature is never
-- listed on either side; pkg/projectreaders refuses both and skips such a row
-- if one was written by hand. Removing a project from the hub removes every
-- row naming it, on either side, with an audit row for each.
--
-- A new table, created IF NOT EXISTS: the stable UI that shares this control
-- plane predates it and never names it, so an older hub reads none of it and
-- grants nothing from it. Additive in schema_compat.go's sense.
CREATE TABLE IF NOT EXISTS project_readers (
    id           TEXT PRIMARY KEY,
    project_path TEXT NOT NULL DEFAULT '',
    reader_path  TEXT NOT NULL DEFAULT '',
    added_by     TEXT NOT NULL DEFAULT '',
    added_at     TEXT NOT NULL DEFAULT ''
);

-- "who may read this project", and the pair's uniqueness.
CREATE UNIQUE INDEX IF NOT EXISTS idx_project_readers_pair ON project_readers(project_path, reader_path);

-- "what may this project read", and the cascade when it is removed.
CREATE INDEX IF NOT EXISTS idx_project_readers_reader ON project_readers(reader_path);
