-- ci_sessions — a CI relay session, recorded so it outlives the hub process
-- that minted it (Task 20390).
--
-- A GitHub Actions job that federates with the hub (POST /api/ci/token) gets a
-- session token and uses the hub as ANTHROPIC_BASE_URL for the rest of the job,
-- for up to six hours. The session lived only in the memory of the process that
-- minted it (pkg/claudeproxy's Registry), so every job relaying through the hub
-- during a nightly deploy or a rolling update retried its 401s for about three
-- minutes and failed with "Not logged in".
--
-- A row here is one minted session, written before its token is handed out and
-- kept in step while it lives: its counters are flushed every 15 seconds and
-- when the hub stops, its end is written when it is closed. A hub
-- that stops gracefully suspends the session instead of closing it — the record
-- stays open. When a request presents the token of a session whose holder is
-- no live hub process, the member receiving it takes the record over (a
-- conditional UPDATE on `holder`, as secret_leases.holder is), holds it to its
-- rule as the rule stands now, and serves it under the same id and token hash.
--
-- Never a credential. What is stored is what the registry keeps in memory
-- instead of the token — its SHA-256 — and the hub's Anthropic credential is
-- not the session's at all: the relay attaches the hub's own configuration.
-- tests/security scans this table for both.
--
--   session_id      the session's id: the public half of the token
--                   (cloop_ci_<id>.<secret>), in every audit row it produces.
--   token_sha256    hex SHA-256 of the whole token the pipeline presents.
--   rule_id         the allowlist rule that admitted the pipeline; a restore
--                   re-reads it, and refuses a session whose rule is gone,
--                   disabled, or no longer admits the pipeline.
--   holder          the hub process (cluster member id) serving the session.
--   instance        the hub instance whose configuration governs it: the
--                   port of the `cloop ui` process that minted or last
--                   restored it, which names the per-instance overlay that
--                   may set ui.ci.enabled. Any member can read that
--                   configuration; while it has federation off, no other
--                   instance restores the session, and the leader ends the
--                   record once no live process serves it.
--   provenance_json which pipeline the rule admitted: the rule's name, the
--                   project it binds, and the verified claims of the OIDC
--                   token the session was minted for (repository, ref,
--                   workflow, actor, run, …) — never the token itself, whose
--                   signature is not kept.
--   policy_json     the session's policy as minted or last narrowed: model
--                   allowlist, request and output caps, body bound.
--   counters_json   the session's spend so far, so a restored session keeps
--                   counting against its request budget.
--   issued_at, expires_at, last_used_at, updated_at, closed_at
--                   RFC 3339 UTC.
--   close_reason    why the session ended; '' while it is open.
--
-- The leader's session janitor deletes rows of closed sessions and of lapsed
-- ones.
--
-- Additive in schema_compat.go's sense: a binary predating this table neither
-- reads nor writes it, and keeps its sessions in memory as before.
CREATE TABLE IF NOT EXISTS ci_sessions (
    session_id      TEXT PRIMARY KEY,
    token_sha256    TEXT NOT NULL DEFAULT '',
    rule_id         TEXT NOT NULL DEFAULT '',
    holder          TEXT NOT NULL DEFAULT '',
    instance        TEXT NOT NULL DEFAULT '',
    provenance_json TEXT NOT NULL DEFAULT '{}',
    policy_json     TEXT NOT NULL DEFAULT '{}',
    counters_json   TEXT NOT NULL DEFAULT '{}',
    issued_at       TEXT NOT NULL DEFAULT '',
    expires_at      TEXT NOT NULL DEFAULT '',
    last_used_at    TEXT NOT NULL DEFAULT '',
    updated_at      TEXT NOT NULL DEFAULT '',
    closed_at       TEXT NOT NULL DEFAULT '',
    close_reason    TEXT NOT NULL DEFAULT ''
);

-- "Which sessions did this rule mint", when the rule is edited, disabled or
-- deleted.
CREATE INDEX IF NOT EXISTS idx_ci_sessions_rule ON ci_sessions(rule_id);

-- "Which sessions does this process still hold", on every checkpoint tick.
CREATE INDEX IF NOT EXISTS idx_ci_sessions_holder ON ci_sessions(holder);
