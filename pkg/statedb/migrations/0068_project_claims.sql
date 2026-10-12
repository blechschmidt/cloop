-- 0068_project_claims: a project directory is claimed in the control plane
-- before anything is created in it (Task 20418).
--
-- POST /api/projects/new used to check that a directory held no project, make
-- it, run `cloop init` in it and register it, as four separate steps. Two
-- requests for one path both passed the check, both ran init, and the loser's
-- executor binding and grants landed on the winner's project. Two requests for
-- a path and its parent both passed it too, and left two projects sharing a
-- tree. And the hub kept no record of which directories it had made itself,
-- so ?delete_root=true removed whatever directory a row named — including one
-- the hub had merely adopted.
--
-- A creation now inserts its path here in one transaction that first refuses
-- any live claim equal to it, inside it or above it, and only then makes the
-- directory. One row per project the hub created, kept while the project is
-- registered and dropped when it is removed.
--
--   path        the canonical directory (pkg/projectconfine.Canonical)
--   state       'creating' while init runs, 'created' once the project exists.
--               A 'creating' row older than the init timeout is a creation
--               that died with its hub and no longer holds the path.
--   owner       the creator's owner key, '' for an unowned project
--   hub_made    1 when this hub made the directory itself, inside
--               ui.projects_root: the only directories ?delete_root=true may
--               remove. 0 for a directory that already existed.
--   root        the projects root it was made under, when hub_made
--   claimed_by  the audit actor who created it
--   claimed_at, updated_at
--               RFC 3339
--
-- Additive (schema_compat.go): one new table. A hub built before this ignores
-- it, and creates projects without claiming them, as it always did.

CREATE TABLE IF NOT EXISTS project_claims (
    path        TEXT PRIMARY KEY,
    state       TEXT NOT NULL DEFAULT 'creating',
    owner       TEXT NOT NULL DEFAULT '',
    hub_made    INTEGER NOT NULL DEFAULT 0,
    root        TEXT NOT NULL DEFAULT '',
    claimed_by  TEXT NOT NULL DEFAULT '',
    claimed_at  TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL DEFAULT ''
);
