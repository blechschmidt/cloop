-- 0004_replay_runs: deterministic task replay history (Task 20120).
--
-- Stores the result of re-executing a previously-completed task against a
-- different provider/model combination so the user can compare quality,
-- validate model upgrades, or A/B test prompt changes. Each row pairs the
-- original task output with the replayed output and a similarity score
-- (0.0–1.0) computed via Jaccard token overlap. An optional AI-judged
-- equivalence verdict (when a judge provider is supplied) is stored
-- alongside as a free-form score in `equivalence_score`.
--
-- The table is append-only: every replay is a new row keyed by id. The same
-- task can be replayed many times against different targets — readers
-- typically GROUP BY task_id and ORDER BY created_at DESC.
--
-- Schema is intentionally narrow. The full prompt and outputs may be large;
-- they are stored verbatim because the comparison view needs them, but
-- callers should clamp before insert if they ever exceed a few MiB.

CREATE TABLE IF NOT EXISTS replay_runs (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at            TEXT    NOT NULL DEFAULT '',
    task_id               INTEGER NOT NULL DEFAULT 0,
    task_title            TEXT    NOT NULL DEFAULT '',
    original_provider     TEXT    NOT NULL DEFAULT '',
    original_model        TEXT    NOT NULL DEFAULT '',
    target_provider       TEXT    NOT NULL DEFAULT '',
    target_model          TEXT    NOT NULL DEFAULT '',
    prompt                TEXT    NOT NULL DEFAULT '',
    original_output       TEXT    NOT NULL DEFAULT '',
    replayed_output       TEXT    NOT NULL DEFAULT '',
    similarity_score      REAL    NOT NULL DEFAULT 0,
    equivalence_score     INTEGER NOT NULL DEFAULT 0,  -- 0 = not judged, 1-10 = AI verdict
    equivalence_rationale TEXT    NOT NULL DEFAULT '',
    duration_ms           INTEGER NOT NULL DEFAULT 0,
    input_tokens          INTEGER NOT NULL DEFAULT 0,
    output_tokens         INTEGER NOT NULL DEFAULT 0,
    error                 TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS replay_runs_task_id ON replay_runs(task_id);
CREATE INDEX IF NOT EXISTS replay_runs_created_at ON replay_runs(created_at);
