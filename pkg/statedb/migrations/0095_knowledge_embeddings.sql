-- 0095_knowledge_embeddings: vectors for semantic retrieval over the knowledge
-- index (Task 20471).
--
-- knowledge_chunk_embeddings — one row per chunk and embedding model: the
-- chunk's vector as that model made it, which a search compares with the
-- query's to rank the chunks of a project's bound sources by meaning, beside
-- the full-text index's ranking by words. Written only while an administrator
-- has knowledge.embeddings enabled.
--
--   chunk_id     the chunk (knowledge_chunks.id). Chunk ids are never reused,
--                so a row whose chunk is gone can only ever be that chunk's.
--   model        the vector's model: provider, model and dimensions, as
--                pkg/knowledge names it ("openai/text-embedding-3-small/1536").
--                A vector is compared only with a query of the same model;
--                rows of a model the hub no longer uses are purged.
--   source_id    the chunk's source, so a search reads the vectors of the
--                sources bound to one project through one index.
--   document_id  the chunk's document, which a search checks the vector is
--                current for without a lookup of the chunk itself.
--   dims         the vector's length.
--   vector       dims float32 values, little-endian, scaled to unit length so
--                that the dot product of two is their cosine.
--   text_hash    SHA-256 of the text the vector was made from (the document's
--                title, the chunk's heading and its body): a chunk whose
--                document changed around it keeps its vector without asking
--                the endpoint again.
--   doc_hash     the document's content_hash when the vector was made. A
--                vector is current while this equals the document's; once the
--                document changes its chunks are found by their words alone
--                until a sync embeds them again. Kept on the row rather than as
--                a flag a writer clears, so a build that predates this table —
--                one rewriting a document's chunks without knowing it exists —
--                cannot leave a stale vector looking current.
--   embedded_ns  when the vector was made (Unix ns).
--
-- Bounded by its writers: one row per chunk per model, and a chunk's rows go
-- with it — when its document is rewritten shorter, deleted, or purged, and
-- when its source is deleted.
--
-- Additive in schema_compat.go's sense: a new table and a plain index, which
-- no build before it knows.

CREATE TABLE IF NOT EXISTS knowledge_chunk_embeddings (
    chunk_id    INTEGER NOT NULL,
    model       TEXT    NOT NULL,
    source_id   INTEGER NOT NULL,
    document_id INTEGER NOT NULL,
    dims        INTEGER NOT NULL,
    vector      BLOB    NOT NULL,
    text_hash   TEXT    NOT NULL DEFAULT '',
    doc_hash    TEXT    NOT NULL DEFAULT '',
    embedded_ns INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (chunk_id, model)
);

-- A search reads one model's vectors of the sources bound to a project; a
-- deleted source's are purged by it.
CREATE INDEX IF NOT EXISTS idx_knowledge_chunk_embeddings_source ON knowledge_chunk_embeddings(source_id, model);
