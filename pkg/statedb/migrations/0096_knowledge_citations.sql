-- 0096_knowledge_citations: what a task's run read from the project's
-- knowledge sources (Task 20472).
--
-- plan_tasks.citations — the documents the task's latest run was given as
-- reference material in its prompt, or read through the hub's knowledge
-- search while it worked: a JSON array of {kind, title, url, source,
-- source_kind, document_id, run_id}, at most 24 (pm.MaxTaskCitations). Written
-- by the run with the rest of the task's outcome; '' reads as none. An append
-- to plan_tasks, recorded additive-columns as 0087 was (schema_compat.go): a
-- build from before Task 20388 empties plan_tasks on each save and so refuses
-- the database instead.
--
-- knowledge_run_reads — the documents a run's agent read through the hub's
-- run-scoped knowledge search (POST /api/run/knowledge/get and /search),
-- recorded by the hub as it serves them, keyed by the run's knowledge session
-- and the task the request named. The run's orchestrator collects a task's
-- rows when the task's attempt ends and keeps them on the task as fetched
-- citations; the rows of a session that ended go with it. A control-plane
-- table: only the hub writes it, and an agent cannot add a document it was
-- never served.

ALTER TABLE plan_tasks ADD COLUMN IF NOT EXISTS citations TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS knowledge_run_reads (
    session_id  TEXT    NOT NULL,
    task_id     INTEGER NOT NULL DEFAULT 0,
    document_id INTEGER NOT NULL,
    read_ns     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (session_id, task_id, document_id)
);

CREATE INDEX IF NOT EXISTS idx_knowledge_run_reads_read ON knowledge_run_reads(read_ns);
