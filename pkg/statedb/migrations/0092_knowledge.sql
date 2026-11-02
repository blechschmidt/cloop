-- 0092_knowledge: enterprise knowledge sources, the projects they serve, and a
-- full-text index of what they hold (Task 20467).
--
-- knowledge_sources — one row per connected source (a Confluence site, a Jira
-- project, ...):
--
--   id           AUTOINCREMENT, so an id is never given to a second source
--                after the first is deleted: an audit row or a binding that
--                names source 7 names one source for good.
--   kind         the connector that reads it (pkg/knowledge's registry).
--   name         what people call it; unique per owner (and among org
--                sources, whose owner is '').
--   scope        org (the organisation's, managed by admins) or personal
--                (one person's, read with their own credential).
--   owner        the personal source's owner in OwnerKey form (a lowercased
--                email, or "sub:<subject>"); '' for an org source.
--   config       the connector's configuration as a JSON object. Never a
--                credential: pkg/knowledge refuses one before it is stored.
--   secret_ref   the secret store reference the hub signs in with — a shared
--                secret for an org source, the owner's personal one for a
--                personal source. Only the reference lives here; the value is
--                opened on the hub for one sync and never leaves it.
--   enabled      1 or 0. A disabled source is neither synced nor searched.
--   sync_*       where incremental sync resumes (the connector's opaque
--                cursor), and how the last sync ended: status '', ok or error,
--                its error, and when.
--   listing_     when the full listing in progress began, in Unix
--   started_ns   nanoseconds (0: none is); a full listing may take several
--                syncs, and when it reaches its end, every document it did not
--                list — listed_ns older than this — is removed.
--   full_        when a full listing last reached its end (Unix ns, 0: never),
--   listing_ns   which decides when the next one is due.
--   created_*,   when and by whom, as RFC 3339 UTC text.
--   updated_*
--
-- knowledge_bindings — which projects a source serves, one row per (source,
-- project). project_path is the project's absolute path, as authz.Scope
-- carries it (a feature searches its parent's). A binding may narrow the
-- source: spaces is a JSON array of space or project keys (empty: all), query
-- a connector-native filter such as JQL or CQL ('' for none). A binding with a
-- query admits only the documents a sync recorded as matching it
-- (knowledge_binding_documents), so it serves nothing until one has.
--
-- knowledge_documents — one row per document a source holds: its external id
-- at the source, title, URL, space key, the source's updated_at, the source's
-- ACL hints (a JSON array), and content_hash: what the chunks were made from.
-- A document whose hash is unchanged is never chunked again. listed_ns is when
-- a sync last listed it (Unix ns).
--
-- knowledge_chunks — one row per chunk of a document, numbered from 0 within
-- it. The chunk's text lives in knowledge_chunks_fts, an FTS5 table whose
-- rowid is the chunk's id, which ranks matches by BM25 inside SQLite: no
-- external search service. The FTS table owns its copy of the text, so
-- SQLite keeps the index consistent with it by itself. A prefix index of three
-- characters keeps the shortest prefix query a search allows ("dep*") cheap.
--
-- knowledge_binding_documents — for a binding with a query, the documents the
-- connector reported as matching it at the last sync.
--
-- Bounded by its writer: a source holds what its remote holds, a document at
-- most pkg/knowledge's chunk limit, and deleting a source deletes everything
-- it brought.
--
-- Additive in schema_compat.go's sense: new tables, their indexes and one
-- FTS5 virtual table, and nothing done to a table that exists. Every statement
-- is IF NOT EXISTS, so a database that already has them — a re-run, or a
-- stranded build that created them — is left as it is.

CREATE TABLE IF NOT EXISTS knowledge_sources (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT    NOT NULL,
    name        TEXT    NOT NULL,
    scope       TEXT    NOT NULL DEFAULT 'org',
    owner       TEXT    NOT NULL DEFAULT '',
    config      TEXT    NOT NULL DEFAULT '{}',
    secret_ref  TEXT    NOT NULL DEFAULT '',
    enabled     INTEGER NOT NULL DEFAULT 1,
    sync_cursor TEXT    NOT NULL DEFAULT '',
    sync_status TEXT    NOT NULL DEFAULT '',
    sync_error  TEXT    NOT NULL DEFAULT '',
    synced_at   TEXT    NOT NULL DEFAULT '',
    listing_started_ns INTEGER NOT NULL DEFAULT 0,
    full_listing_ns    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL DEFAULT '',
    created_by  TEXT    NOT NULL DEFAULT '',
    updated_at  TEXT    NOT NULL DEFAULT '',
    updated_by  TEXT    NOT NULL DEFAULT ''
);

-- One name per owner: "Engineering wiki" means one source to the people who
-- see it.
CREATE UNIQUE INDEX IF NOT EXISTS ux_knowledge_sources_owner_name ON knowledge_sources(owner, name);

CREATE TABLE IF NOT EXISTS knowledge_bindings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id    INTEGER NOT NULL,
    project_path TEXT    NOT NULL,
    spaces       TEXT    NOT NULL DEFAULT '[]',
    query        TEXT    NOT NULL DEFAULT '',
    narrowed_at  TEXT    NOT NULL DEFAULT '',
    created_at   TEXT    NOT NULL DEFAULT '',
    created_by   TEXT    NOT NULL DEFAULT '',
    updated_at   TEXT    NOT NULL DEFAULT '',
    updated_by   TEXT    NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_knowledge_bindings_source_project ON knowledge_bindings(source_id, project_path);

-- Search: "which sources does this project read".
CREATE INDEX IF NOT EXISTS idx_knowledge_bindings_project ON knowledge_bindings(project_path);

CREATE TABLE IF NOT EXISTS knowledge_documents (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id         INTEGER NOT NULL,
    external_id       TEXT    NOT NULL,
    title             TEXT    NOT NULL DEFAULT '',
    url               TEXT    NOT NULL DEFAULT '',
    space_key         TEXT    NOT NULL DEFAULT '',
    remote_updated_at TEXT    NOT NULL DEFAULT '',
    acl               TEXT    NOT NULL DEFAULT '[]',
    content_hash      TEXT    NOT NULL DEFAULT '',
    body_bytes        INTEGER NOT NULL DEFAULT 0,
    truncated         INTEGER NOT NULL DEFAULT 0,
    chunk_count       INTEGER NOT NULL DEFAULT 0,
    indexed_at        TEXT    NOT NULL DEFAULT '',
    listed_ns         INTEGER NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_knowledge_documents_external ON knowledge_documents(source_id, external_id);

CREATE TABLE IF NOT EXISTS knowledge_chunks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL,
    source_id   INTEGER NOT NULL,
    ordinal     INTEGER NOT NULL,
    heading     TEXT    NOT NULL DEFAULT '',
    tokens      INTEGER NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_knowledge_chunks_position ON knowledge_chunks(document_id, ordinal);

-- Deleting a source: every chunk it brought.
CREATE INDEX IF NOT EXISTS idx_knowledge_chunks_source ON knowledge_chunks(source_id);

CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_chunks_fts USING fts5(title, heading, body, tokenize = 'unicode61 remove_diacritics 2', prefix = '3');

CREATE TABLE IF NOT EXISTS knowledge_binding_documents (
    binding_id  INTEGER NOT NULL,
    document_id INTEGER NOT NULL,
    PRIMARY KEY (binding_id, document_id)
);

-- Deleting a document: every binding that admitted it.
CREATE INDEX IF NOT EXISTS idx_knowledge_binding_documents_document ON knowledge_binding_documents(document_id);
