-- 0074_audit_forward: where each audit sink has got to in each chain
-- (Task 20426).
--
-- The cluster leader ships every row of every audit chain — the control
-- plane's and each registered project's — to the sinks in audit.forward. This
-- table is the forwarder's only memory: one row per (sink, chain), in the
-- control plane's database and never in a project's, because a project's
-- database is writable by whatever runs in that project, and a cursor moved
-- forward there would make the forwarder skip rows nobody had shipped.
--
--   sink          the sink's name from audit.forward.sinks.
--   chain         the absolute path of the chain's database: how checkpoints
--                 name a chain too.
--   source, dir   control-plane or project, and the directory holding it —
--                 what every forwarded record says about where it came from.
--   acked_id      the newest row the sink has acknowledged, and acked_hash
--   acked_hash    its row_hash. Advanced only after the sink acknowledged the
--                 batch ending there, and only by compare-and-swap against the
--                 value the batch was read from, so a leader that lost its
--                 lease mid-send cannot move a cursor its successor moved.
--   acked_row_at  that row's timestamp.
--   acked_at      when the sink acknowledged it; '' while it never has.
--   delivered     rows the sink has acknowledged, over the cursor's life.
--   marks         JSON list of older acknowledged (id, hash) points, thinned
--                 to roughly exponential spacing: where to resume when the
--                 chain no longer holds the cursor's row (a restore, a
--                 truncation), instead of from the start.
--   last_error,   the newest delivery failure, and how many sends have
--   last_error_at failed since the last acknowledgement. Cleared by an
--   failures      acknowledgement.
--   retired_at    set when the sink is no longer configured or the chain no
--                 longer served. A retired cursor holds no retention and is
--                 resumed, not restarted, if its sink or chain returns.
--
-- Retention reads the table too: auditretention.Prune clamps its cutoff to
-- the lowest acked_id of the live cursors on the chain it prunes.
--
-- Additive — a new table and a non-unique index — so an older hub opens a
-- database carrying it and simply does not forward.

CREATE TABLE IF NOT EXISTS audit_forward_cursors (
    sink          TEXT    NOT NULL,
    chain         TEXT    NOT NULL,
    source        TEXT    NOT NULL DEFAULT '',
    dir           TEXT    NOT NULL DEFAULT '',
    acked_id      INTEGER NOT NULL DEFAULT 0,
    acked_hash    TEXT    NOT NULL DEFAULT '',
    acked_row_at  TEXT    NOT NULL DEFAULT '',
    acked_at      TEXT    NOT NULL DEFAULT '',
    delivered     INTEGER NOT NULL DEFAULT 0,
    marks         TEXT    NOT NULL DEFAULT '',
    last_error    TEXT    NOT NULL DEFAULT '',
    last_error_at TEXT    NOT NULL DEFAULT '',
    failures      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL,
    retired_at    TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (sink, chain)
);

CREATE INDEX IF NOT EXISTS idx_audit_forward_cursors_chain ON audit_forward_cursors(chain);
