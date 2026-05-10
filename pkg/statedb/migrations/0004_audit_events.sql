-- 0004_audit_events: forensic audit trail with hash chain (Task 20119).
--
-- Distinct from the `events` table (0003) which is a UI-friendly journal of
-- noteworthy run events. `audit_events` is an append-only event-sourcing
-- log of every state-mutation: task created/updated/deleted, plan goal
-- changed, config blob written, etc. Each row links to the previous row
-- via SHA-256(prev_hash || canonical(this_row_minus_hash)) so any tamper
-- (insert, edit, delete in place) is detectable by `cloop events verify`.
--
-- Replay reconstructs the state of the database at any earlier id by
-- re-applying the payload_json blobs to a fresh database.
--
-- Columns:
--   id          monotonic primary key (defines causal order)
--   timestamp   RFC3339Nano string (UTC)
--   actor       who initiated the change: "system", "orchestrator", "ui",
--               "cli", "evolve", or any user-supplied value. Free-form on
--               purpose so users can plug in real identities later without
--               another migration.
--   event_type  imperative verb in lowercase: "task.create", "task.update",
--               "task.delete", "task.status", "plan.update", "config.set",
--               "step.append", "session.start", etc. Dotted prefix groups
--               the entity for filtering.
--   entity_type "task", "plan", "config", "step", "session"; correlates
--               with the leading segment of event_type.
--   entity_id   stringified entity identifier ("12" for tasks, empty for
--               plan/config singletons, step number for steps, ...).
--   payload     JSON blob describing the mutation in enough detail to
--               replay it. For task.update this is the full task row
--               post-mutation; for task.delete it carries the id only.
--   prev_hash   SHA-256 hex of the previous row's full hash chain link,
--               or 64 zeros for the first row.
--   row_hash    SHA-256 hex of (prev_hash || canonical(row-without-hashes))
--               used to verify integrity and serve as prev_hash for the
--               next row.

CREATE TABLE IF NOT EXISTS audit_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL DEFAULT '',
    actor       TEXT    NOT NULL DEFAULT '',
    event_type  TEXT    NOT NULL DEFAULT '',
    entity_type TEXT    NOT NULL DEFAULT '',
    entity_id   TEXT    NOT NULL DEFAULT '',
    payload     TEXT    NOT NULL DEFAULT '',
    prev_hash   TEXT    NOT NULL DEFAULT '',
    row_hash    TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS audit_events_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS audit_events_actor ON audit_events(actor);
CREATE INDEX IF NOT EXISTS audit_events_entity ON audit_events(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS audit_events_type ON audit_events(event_type);
