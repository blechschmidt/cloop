-- 0028_reproductions: hermetic sandbox replay verdicts (Task 20221).
--
-- `replay_runs` (0006) records a prompt re-sent to a different provider and the
-- Jaccard overlap of the two transcripts. That is a claim about models. This
-- table records a task re-executed in a fresh isolating sandbox and the two
-- commits compared — a claim about code. They share a package and nothing else:
-- no column here has a counterpart there, and folding them together would mean
-- a row whose meaning depends on which half of it is NULL.
--
-- Columns:
--
--   verdict          'identical' | 'equivalent' | 'divergent' | 'inconclusive'.
--                    See pkg/taskreplay/reproduce.go for why the fourth is not
--                    a fourth opinion but the refusal to have one.
--   reason           one sentence naming why this verdict and not another.
--                    Never empty; it is the field an operator reads first.
--   base_sha         the commit the reproduction started from.
--   base_source      'recorded' (from the original write_back event) or
--                    'first-parent' (inferred). An inferred base caps the
--                    verdict at inconclusive, so this is load-bearing.
--   original_commit  the commit the original run returned.
--   replay_commit    the commit the reproduction returned.
--   original_tree    tree hash of original_commit — what actually decides
--   replay_tree      tree hash of replay_commit —   an 'identical' verdict.
--   diff_stat        --stat summary of the diff-of-diffs.
--   diff_of_diffs    the patch between the two trees, capped by the writer.
--   provenance       JSON: the reconstructed input state (prompt hash, model
--                    settings, sandbox stamp, warnings).
--   original_test    JSON: the project's test command run on the original tree.
--   replay_test      JSON: the same command run on the reproduced tree.
--
-- The three JSON blobs follow the precedent plan_tasks.background set in 0025:
-- each is a small nested record, always read and written whole, never filtered
-- or aggregated on. The scalars that ARE queried — verdict, task_id — are
-- columns, which is what the two indexes below serve.
--
-- No foreign key to plan_tasks. A reproduction is evidence about a commit, and
-- deleting or renumbering a task must not delete the record of what its commit
-- was proven to be.

CREATE TABLE IF NOT EXISTS reproductions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      TEXT    NOT NULL DEFAULT '',
    task_id         INTEGER NOT NULL DEFAULT 0,
    task_title      TEXT    NOT NULL DEFAULT '',

    verdict         TEXT    NOT NULL DEFAULT '',
    reason          TEXT    NOT NULL DEFAULT '',

    base_sha        TEXT    NOT NULL DEFAULT '',
    base_source     TEXT    NOT NULL DEFAULT '',
    original_commit TEXT    NOT NULL DEFAULT '',
    replay_commit   TEXT    NOT NULL DEFAULT '',
    original_tree   TEXT    NOT NULL DEFAULT '',
    replay_tree     TEXT    NOT NULL DEFAULT '',

    executor_id     TEXT    NOT NULL DEFAULT '',
    executor_kind   TEXT    NOT NULL DEFAULT '',
    isolation       TEXT    NOT NULL DEFAULT '',
    pinned_image    TEXT    NOT NULL DEFAULT '',

    diff_stat       TEXT    NOT NULL DEFAULT '',
    diff_of_diffs   TEXT    NOT NULL DEFAULT '',

    provenance      TEXT    NOT NULL DEFAULT '',
    original_test   TEXT    NOT NULL DEFAULT '',
    replay_test     TEXT    NOT NULL DEFAULT '',

    agent_exit_code INTEGER NOT NULL DEFAULT 0,
    duration_ms     INTEGER NOT NULL DEFAULT 0,
    error           TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS reproductions_task_id ON reproductions(task_id);
CREATE INDEX IF NOT EXISTS reproductions_verdict ON reproductions(verdict);
