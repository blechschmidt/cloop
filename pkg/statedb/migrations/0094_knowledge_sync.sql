-- 0094_knowledge_sync: the hub's knowledge sync scheduler (Task 20470) — how
-- often each source is synced, how its last sync went, the lease that keeps two
-- hub processes from syncing one source at once, and tombstones for the
-- documents a source no longer holds.
--
-- knowledge_sources, the last sync and the next:
--
--   sync_interval_min  how often the hub-cluster leader syncs the source, in
--                      minutes; 0 means the default (30). pkg/knowledge bounds
--                      it to 5–1440 before it is stored.
--   sync_started_ns    when the last sync began (Unix ns, 0: never).
--   sync_duration_ms   how long it ran.
--   sync_origin        what started it: schedule, or manual (a person's
--                      POST /api/knowledge/sources/{id}/sync).
--   sync_report        what it did, as a JSON object of counts — pages,
--                      documents listed, created, updated, unchanged, deleted,
--                      rejected, removed — never a document's content.
--   sync_more          1 when it stopped before its listing's end (its page or
--                      time budget ran out), so the next sync is due at once
--                      rather than an interval on.
--   synced_ok_ns       when a sync last ended ok (Unix ns, 0: never).
--
-- knowledge_documents.deleted_ns — when the document left the source (Unix ns,
-- 0: it is live): reported deleted by the connector, not reached by a full
-- listing's sweep, or left out of a reconciliation. Its chunks, full-text
-- entries and binding matches go at once, and its title, URL, access hints and
-- ancestors are blanked; the row — the document's id and external id — stays
-- as a tombstone, so a citation made before the deletion still resolves, to
-- "deleted", and a document that comes back keeps its id. The janitor purges
-- tombstones older than retention.knowledge_deleted_days (30). The partial
-- index is what makes that purge a range read over tombstones alone; the one
-- on (source_id, listed_ns) does the same for a full listing's sweep, which
-- takes out in batches the documents the listing did not reach.
--
-- knowledge_sync_leases — one row per source ever synced: which hub process
-- holds the source's sync (holder, the sync's own id; member, the process's
-- instance id), why (origin, and the actor of a manual sync), and until when
-- (expires_ns, Unix ns; 0: released). A sync takes it before it opens the
-- source's credential, renews it while it runs, and every write the sync makes
-- checks it, so a process that stalled past its lease cannot write over the
-- sync that took over. Released by setting expires_ns to 0, never by deleting
-- the row, which also says which process synced the source last; deleting the
-- source deletes it.
--
-- Additive in schema_compat.go's sense: appended columns, each with a default
-- and no constraint, on tables 0092 created, which no build before it knows;
-- two plain indexes; and a new table. The runner's idempotent ADD COLUMN IF NOT
-- EXISTS (addcolumn.go) and IF NOT EXISTS leave a database that already has
-- them as it is.

ALTER TABLE knowledge_sources ADD COLUMN IF NOT EXISTS sync_interval_min INTEGER NOT NULL DEFAULT 0;

ALTER TABLE knowledge_sources ADD COLUMN IF NOT EXISTS sync_started_ns INTEGER NOT NULL DEFAULT 0;

ALTER TABLE knowledge_sources ADD COLUMN IF NOT EXISTS sync_duration_ms INTEGER NOT NULL DEFAULT 0;

ALTER TABLE knowledge_sources ADD COLUMN IF NOT EXISTS sync_origin TEXT NOT NULL DEFAULT '';

ALTER TABLE knowledge_sources ADD COLUMN IF NOT EXISTS sync_report TEXT NOT NULL DEFAULT '{}';

ALTER TABLE knowledge_sources ADD COLUMN IF NOT EXISTS sync_more INTEGER NOT NULL DEFAULT 0;

ALTER TABLE knowledge_sources ADD COLUMN IF NOT EXISTS synced_ok_ns INTEGER NOT NULL DEFAULT 0;

ALTER TABLE knowledge_documents ADD COLUMN IF NOT EXISTS deleted_ns INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_knowledge_documents_deleted ON knowledge_documents(deleted_ns) WHERE deleted_ns > 0;

CREATE INDEX IF NOT EXISTS idx_knowledge_documents_listed ON knowledge_documents(source_id, listed_ns);

CREATE TABLE IF NOT EXISTS knowledge_sync_leases (
    source_id   INTEGER PRIMARY KEY,
    holder      TEXT    NOT NULL DEFAULT '',
    member      TEXT    NOT NULL DEFAULT '',
    origin      TEXT    NOT NULL DEFAULT '',
    actor       TEXT    NOT NULL DEFAULT '',
    acquired_ns INTEGER NOT NULL DEFAULT 0,
    expires_ns  INTEGER NOT NULL DEFAULT 0
);
