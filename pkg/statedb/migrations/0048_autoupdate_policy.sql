-- Fleet auto-update policy (Task 20331).
--
-- One row, not one per executor. The policy is a statement about the fleet —
-- "converge everything on this release, this many at a time" — and per-device
-- overrides would invite exactly the configuration an operator cannot reason
-- about: a fleet that is supposed to be uniform, quietly holding two versions
-- because somebody pinned one device a year ago and forgot.
--
-- The single row is enforced by the CHECK rather than by convention, so the
-- table cannot drift into holding two policies that disagree.
CREATE TABLE IF NOT EXISTS autoupdate_policy (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    enabled        INTEGER NOT NULL DEFAULT 0,
    target_version TEXT    NOT NULL DEFAULT '',
    max_in_flight  INTEGER NOT NULL DEFAULT 0,
    set_at         TEXT    NOT NULL DEFAULT '',
    set_by         TEXT    NOT NULL DEFAULT ''
);
