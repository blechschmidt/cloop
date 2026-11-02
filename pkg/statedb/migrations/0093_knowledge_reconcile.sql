-- 0093_knowledge_reconcile: where a knowledge document sits at its source, and
-- when a source's documents were last reconciled against it (Task 20468).
--
-- knowledge_documents.ancestors — the titles of what holds the document at its
-- source, outermost first, as a JSON array: the pages above a Confluence page.
-- A citation places a search hit by them ("Runbooks › Deploys"). Metadata, like
-- url and acl: written at every index, never part of content_hash, so a
-- renamed parent does not re-chunk its children.
--
-- knowledge_sources.reconciled_ns — when the source's documents were last
-- reconciled (Unix ns, 0: never): the connector reported every document its
-- remote holds in scope now, and the hub removed the ones it did not report —
-- deleted, moved out of scope, or hidden by a view restriction, none of which
-- an incremental listing says. A full listing that reaches its end counts as
-- one, since its sweep removes the same documents.
--
-- Additive in schema_compat.go's sense: two appended columns, each with a
-- default and no constraint, on tables 0092 created, which no build before it
-- knows. The runner's idempotent ADD COLUMN IF NOT EXISTS (addcolumn.go) leaves
-- a database that already has them as it is.

ALTER TABLE knowledge_documents ADD COLUMN IF NOT EXISTS ancestors TEXT NOT NULL DEFAULT '[]';

ALTER TABLE knowledge_sources ADD COLUMN IF NOT EXISTS reconciled_ns INTEGER NOT NULL DEFAULT 0;
