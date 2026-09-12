-- 0027_audit_retention: stop the audit trail amplifying, and give it a way to
-- end (Task 20218).
--
-- Two problems, two tables.
--
-- ── audit_task_fingerprints ────────────────────────────────────────────────
--
-- auditPlanTasks() emitted one `task.upsert` row per task in the plan on every
-- SaveState, with actor='system'. SaveState runs once per finished step, so
-- growth was O(saves x tasks) regardless of whether any task changed. On the
-- hub this database was measured at 2.44 GB with 1,096,198 audit rows, of
-- which 1,093,055 (99.7%) were that one event type — burying the handful of
-- rows a compliance reader actually wants and making chain verification a
-- 1.1M-row walk.
--
-- The rows were never events. audit_events is defined by 0004 as "one row per
-- mutation", and re-declaring a byte-identical task is not a mutation. This
-- table is how the writer can tell: it holds SHA-256 of the exact payload last
-- emitted for each task, so SaveState can diff inside its own transaction and
-- emit only what genuinely changed.
--
-- Why a side table rather than a column on plan_tasks: plan_tasks is rewritten
-- DELETE-all/INSERT-all on every save and its column list is enumerated in
-- several places. Keeping the audit bookkeeping out of it means the plan schema
-- and its readers are untouched, and mirrors the separation 0004 already draws
-- between the operational journal and the legal record.
--
-- A missing row means "never emitted", which makes the task new to the trail
-- and gets one row. That is also what every existing deployment sees on its
-- first save after this migration: one baseline emission per task, once, and
-- O(changed) forever after.

CREATE TABLE IF NOT EXISTS audit_task_fingerprints (
    task_id     INTEGER PRIMARY KEY,
    fingerprint TEXT    NOT NULL DEFAULT ''
);

-- ── audit_anchors ──────────────────────────────────────────────────────────
--
-- audit_events had no retention path at all: nothing pruned it, pkg/compact
-- did not touch it, and `cloop db maintain` copied all 2.4 GB. It could not
-- simply be given a DELETE, because the table is hash-chained and 20167 ships
-- a verifier — removing a prefix leaves the first surviving row pointing at a
-- predecessor that no longer exists, which the verifier correctly calls
-- tampering.
--
-- An anchor is the record that a truncation was deliberate, and the evidence
-- that it was honest. One row per `cloop hub audit prune`:
--
--   boundary_hash      row_hash of the last pruned row. This is the load-
--                      bearing field: the first surviving row's prev_hash must
--                      equal it, which is what lets the verifier walk *across*
--                      the truncation instead of reporting a break. It is also
--                      what AppendAuditEvent resumes from when a prune emptied
--                      the table, so ids and hashes stay continuous.
--   retained_from_id   first surviving id, or 0 when the prune emptied the
--                      table. Pinning it means a later deletion of rows just
--                      after the boundary is still detected: the anchor says
--                      where the chain must resume, so a second silent
--                      truncation cannot hide behind the first.
--   export_path        where the pruned prefix was sealed before deletion.
--   export_sha256      digest of that file. The anchor asserts a truncation;
--                      the digest is what makes the assertion checkable
--                      against something outside this database.
--   prev_anchor_hash / anchor_hash
--                      the anchors are themselves chained. This does not
--                      defend against an attacker who rewrites the whole
--                      table — nothing inside the database can — but it does
--                      catch a single edited anchor, which is the realistic
--                      accident, and it costs one hash per prune. The real
--                      off-box binding is export_sha256.
--
-- Rows are append-only. A prune never rewrites a previous anchor.

CREATE TABLE IF NOT EXISTS audit_anchors (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at        TEXT    NOT NULL DEFAULT '',
    actor             TEXT    NOT NULL DEFAULT '',
    cutoff            TEXT    NOT NULL DEFAULT '',
    pruned_first_id   INTEGER NOT NULL DEFAULT 0,
    pruned_through_id INTEGER NOT NULL DEFAULT 0,
    pruned_count      INTEGER NOT NULL DEFAULT 0,
    boundary_hash     TEXT    NOT NULL DEFAULT '',
    retained_from_id  INTEGER NOT NULL DEFAULT 0,
    export_path       TEXT    NOT NULL DEFAULT '',
    export_format     TEXT    NOT NULL DEFAULT '',
    export_sha256     TEXT    NOT NULL DEFAULT '',
    export_bytes      INTEGER NOT NULL DEFAULT 0,
    prev_anchor_hash  TEXT    NOT NULL DEFAULT '',
    anchor_hash       TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS audit_anchors_through ON audit_anchors(pruned_through_id);
