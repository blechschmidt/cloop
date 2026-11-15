-- 0102_project_moves: the journal of project moves (Task 20494).
--
-- A move takes a project from the executor it is bound to onto another one
-- without losing what the old side holds: it stops the project's run, captures
-- the source's trees and .cloop files into a bundle the hub keeps, switches the
-- binding, seeds the target and checks the target holds what was captured.
-- Every step is a phase of one row here, advanced by a compare-and-swap on
-- (phase, version), so a hub that stops between two steps — killed, upgraded,
-- or a cluster member that lost its lease — leaves the row naming the step to
-- run next, and whichever member takes the move's lease next runs it. A row is
-- never replaced and never deleted by the move: it is the record of what
-- happened to the project's work.
--
-- Columns:
--   id             random identifier, also the move's hidden ref
--                  (refs/cloop/move/<id>) and its directory in the move store
--   project_path   the project's path on the hub; a move never changes it
--   project_name   its registry name when the move started
--   source_binding where the project was bound when the move started: an
--                  executor ID, pool:<id>, or '' for the hub's default
--   target_binding where the move binds it: an executor ID or pool:<id>
--   phase          preflight, quiesce, capture, switch, seed, verify (open);
--                  done, failed, rolled_back (closed)
--   failed_phase   the phase that failed, for failed and rolled_back
--   error          why it failed, in a sentence
--   abandon_source 1 when the move was asked not to capture its source
--   started_by     the identity that started the move
--   version        incremented by every write; the compare-and-swap's other half
--   created_at     RFC 3339 UTC, when the move started
--   updated_at     RFC 3339 UTC, the last write
--   finished_at    RFC 3339 UTC, when it reached a closed phase; '' while open
--   detail_json    what each phase recorded: the preflight's counts, the
--                  capture manifest (branches, trees, file hashes, sizes), the
--                  binding and firewall rules before the switch, the seed's and
--                  the verification's results, the retained source and the
--                  command that cleans it up
--
-- project_moves_open allows one open move per project: two moves of one
-- project at once would capture and switch under each other. A closed move no
-- longer counts, so a project can be moved again after a failure.
--
-- A new table, guarded: the stable UI that shares this control plane predates
-- it and never names it, and an older hub refuses nothing it does not know.
CREATE TABLE IF NOT EXISTS project_moves (
    id             TEXT PRIMARY KEY,
    project_path   TEXT NOT NULL,
    project_name   TEXT NOT NULL DEFAULT '',
    source_binding TEXT NOT NULL DEFAULT '',
    target_binding TEXT NOT NULL DEFAULT '',
    phase          TEXT NOT NULL,
    failed_phase   TEXT NOT NULL DEFAULT '',
    error          TEXT NOT NULL DEFAULT '',
    abandon_source INTEGER NOT NULL DEFAULT 0,
    started_by     TEXT NOT NULL DEFAULT '',
    version        INTEGER NOT NULL DEFAULT 1,
    created_at     TEXT NOT NULL DEFAULT '',
    updated_at     TEXT NOT NULL DEFAULT '',
    finished_at    TEXT NOT NULL DEFAULT '',
    detail_json    TEXT NOT NULL DEFAULT '{}'
);

CREATE UNIQUE INDEX IF NOT EXISTS project_moves_open
    ON project_moves(project_path) WHERE phase NOT IN ('done', 'failed', 'rolled_back');

CREATE INDEX IF NOT EXISTS project_moves_project
    ON project_moves(project_path, created_at);
