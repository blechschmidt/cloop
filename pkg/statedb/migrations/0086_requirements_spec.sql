-- 0086_requirements_spec: requirements as code (Task 20459).
--
-- requirements.status — where a requirement is in its life: draft, approved
-- or deprecated. A check checks the approved ones unless told otherwise.
-- 'approved' is the default because every requirement written before this
-- column existed was one the project kept and checked, and an older build
-- (Task 20458's) that adds a requirement names its columns and so gets the
-- default: what it adds is checked, as it was when it added it. No build
-- replaces requirements rows — UpdateRequirement sets the columns it knows —
-- so an older build's edit leaves the status as it was.
--
-- requirement_spec_base — the requirements as the hub and the project's spec
-- file (.cloop/requirements.yaml) last agreed on them: at an import, at an
-- export, or at a read that found the file saying what the hub does. It is
-- the base of the three-way merge (pkg/requirements/merge.go): a requirement
-- that differs from its base on one side only was changed on that side.
--
--   requirement_id  the requirement's id.
--   definition      JSON of its definition as a spec file holds it.
--   fingerprint     its SyncFingerprint.
--   synced_at       when the row was last written, as fixed-width UTC text.
--
-- requirement_spec_files — what the hub knows of the spec file, one row per
-- slot:
--
--   'read'  the file as the hub last read it from the project's checkout —
--           through the project's executor, never from the hub's own host:
--           its bytes (at most 2 MiB) and their SHA-256, the commit the
--           checkout was at, whether the file had uncommitted changes or is
--           ignored by git, and why the read did not work when it did not.
--   'sync'  the last import or export (direction): the SHA-256 of the file
--           imported or written, its path and commit, who, when, and from
--           where (source: dashboard or cli).
--
-- Additive in schema_compat.go's sense: a defaulted column appended to a
-- table no shipped build rewrites, and two new tables.

ALTER TABLE requirements ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'approved';

CREATE TABLE IF NOT EXISTS requirement_spec_base (
    requirement_id INTEGER PRIMARY KEY,
    definition     TEXT NOT NULL DEFAULT '{}',
    fingerprint    TEXT NOT NULL DEFAULT '',
    synced_at      TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS requirement_spec_files (
    slot        TEXT    PRIMARY KEY,
    at          TEXT    NOT NULL DEFAULT '',
    actor       TEXT    NOT NULL DEFAULT '',
    source      TEXT    NOT NULL DEFAULT '',
    direction   TEXT    NOT NULL DEFAULT '',
    executor_id TEXT    NOT NULL DEFAULT '',
    path        TEXT    NOT NULL DEFAULT '',
    found       INTEGER NOT NULL DEFAULT 0,
    content     BLOB,
    sha256      TEXT    NOT NULL DEFAULT '',
    git_commit  TEXT    NOT NULL DEFAULT '',
    dirty       INTEGER NOT NULL DEFAULT 0,
    ignored     INTEGER NOT NULL DEFAULT 0,
    error       TEXT    NOT NULL DEFAULT ''
);
