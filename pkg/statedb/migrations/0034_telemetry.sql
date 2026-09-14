-- 0034_telemetry: browser-side diagnostic trails (Task 20251).
--
-- The hub's front ends run on machines it cannot inspect. For the dashboard
-- that is inconvenient; for the Meta Ray-Ban Display page it is total. Those
-- glasses have no developer tools, no console, no network inspector, and the
-- wearer's only reporting channel is a sentence of prose. Three separate tasks
-- (20237, 20242, 20243) were spent reproducing such a sentence by simulation
-- because there was no record of what the device actually did.
--
-- This table is that record: an ordered trail of gestures, view changes,
-- requests and errors, written by the page and read back by whoever is
-- debugging it.
--
-- Columns:
--   id            autoincrement. Also the paging cursor — see the index note.
--   received_at   RFC3339Nano UTC, the hub's clock. The only timestamp worth
--                 comparing across sessions.
--   client_millis the page's own Date.now(). Stored because the *gaps* between
--                 events are the diagnostic signal ("the second swipe arrived
--                 80 ms later and nothing moved"), and never used for ordering:
--                 a wearable's absolute clock is routinely wrong.
--   source        'dashboard' or 'glasses'. Stamped from the ingest route, not
--                 from the payload.
--   kind          error | rejection | gesture | view | fetch | lifecycle | note.
--   session       the page's own random id for one page load. The unit a reader
--                 actually works in: "show me what that wearer's session did".
--   seq           the page's monotonic counter within the session. The trusted
--                 ordering key — batches race in flight and two events in the
--                 same millisecond are otherwise indistinguishable. A gap in
--                 seq means a batch was lost, which is itself a finding.
--   message/stack/url/view/detail
--                 the payload, already clamped and credential-scrubbed by
--                 pkg/telemetry before it reaches here. Scrubbing happens at
--                 ingest rather than at read time because the glasses link
--                 carries its bearer token in the page URL: a row written
--                 unscrubbed is a leaked credential no matter who reads it.
--   user_agent/client_ip/actor
--                 server-observed context. A page reports; it does not get to
--                 assert who it is.
--   release       the hub build the page was served by, so a trail can be tied
--                 to the code that produced it.
--
-- Retention is enforced at write time (see PruneTelemetry, called from
-- AppendTelemetry) rather than by the periodic janitor. A public ingest
-- endpoint is the one writer that must not be able to fill a disk between two
-- hourly sweeps, so the bound has to hold on the write path itself.
--
-- Indexes: the read patterns are "latest N, optionally filtered by source or
-- kind" and "everything in this session, in order". The first is served by
-- id DESC — id is monotonic with received_at and cheaper to compare than a
-- text timestamp. The second is served by the session index.

CREATE TABLE IF NOT EXISTS telemetry_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at   TEXT    NOT NULL DEFAULT '',
    client_millis INTEGER NOT NULL DEFAULT 0,
    source        TEXT    NOT NULL DEFAULT '',
    kind          TEXT    NOT NULL DEFAULT '',
    session       TEXT    NOT NULL DEFAULT '',
    seq           INTEGER NOT NULL DEFAULT 0,
    message       TEXT    NOT NULL DEFAULT '',
    stack         TEXT    NOT NULL DEFAULT '',
    url           TEXT    NOT NULL DEFAULT '',
    view          TEXT    NOT NULL DEFAULT '',
    detail        TEXT    NOT NULL DEFAULT '',
    user_agent    TEXT    NOT NULL DEFAULT '',
    client_ip     TEXT    NOT NULL DEFAULT '',
    actor         TEXT    NOT NULL DEFAULT '',
    release       TEXT    NOT NULL DEFAULT ''
);

-- "Show me the recent glasses errors" — the opening question of every
-- investigation this table exists for.
CREATE INDEX IF NOT EXISTS idx_telemetry_source_kind ON telemetry_events(source, kind, id DESC);

-- "Now show me that whole session, in the order the page recorded it."
CREATE INDEX IF NOT EXISTS idx_telemetry_session ON telemetry_events(session, seq);
