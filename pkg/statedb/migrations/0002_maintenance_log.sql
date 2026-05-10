-- 0002_maintenance_log: track VACUUM/ANALYZE maintenance runs (Task 20107).
--
-- Records every `cloop db maintain` invocation so we can:
--   * gate --auto runs on DB growth since the last vacuum (≥20% threshold),
--   * surface "last maintenance" + freed bytes in `cloop doctor`,
--   * give operators a forensic trail when investigating disk-usage spikes.
--
-- Schema is append-only: never UPDATE existing rows. Always INSERT a new row
-- per maintenance run.

CREATE TABLE IF NOT EXISTS maintenance_log (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    operation         TEXT    NOT NULL DEFAULT 'vacuum',
    started_at        TEXT    NOT NULL DEFAULT '',
    completed_at      TEXT    NOT NULL DEFAULT '',
    page_count_before INTEGER NOT NULL DEFAULT 0,
    page_count_after  INTEGER NOT NULL DEFAULT 0,
    page_size         INTEGER NOT NULL DEFAULT 0,
    bytes_before      INTEGER NOT NULL DEFAULT 0,
    bytes_after       INTEGER NOT NULL DEFAULT 0,
    note              TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS maintenance_log_started_at ON maintenance_log(started_at);
