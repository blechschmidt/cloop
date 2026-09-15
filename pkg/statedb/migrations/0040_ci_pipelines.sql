-- 0040_ci_pipelines: the allowlist of CI/CD pipelines this hub will federate,
-- and a record of every exchange it decided (Task 20278).
--
-- A GitHub Actions job can mint a short-lived OIDC token that names itself —
-- repository, ref, workflow, environment, actor, event — and present it to a
-- third party. pkg/ciauth verifies such a token against GitHub's own signing
-- keys, which establishes that the forge said it; it does not establish that
-- this hub meant to trust it. Every repository on GitHub can obtain a valid
-- token naming itself, so a hub that verifies without matching trusts the
-- internet. These tables are the matching half.
--
-- # ci_pipeline_rules
--
-- One row per allowlist entry, in the shape pkg/ciauth.Rule consumes. The
-- glob columns cover what nearly every deployment needs and are legible to a
-- reviewer who has never read a CEL grammar; `condition` is the escape hatch,
-- evaluated by pkg/celmatch, which refuses anything it does not fully
-- implement rather than guessing.
--
--   repository      owner/name glob. pkg/ciauth refuses a wildcard in the
--                   owner segment, because "*/tool" reads like "the tool
--                   repository" and means "any account that creates a
--                   repository called tool" — which anyone can do, in
--                   seconds, for free. The check lives in the Go layer rather
--                   than in a CHECK constraint so the refusal can explain
--                   itself to the person typing it.
--
--   condition       a strict-CEL expression over the token's claims. Stored
--                   as source and recompiled on load, deliberately: a rule
--                   that round-trips through this table is held to exactly
--                   the checks it passed on the way in, and a rule that stops
--                   compiling becomes inert and visible rather than silently
--                   ignored.
--
--   models_json     the model allowlist a match buys. Empty means "the hub
--                   default applies", which the minting path resolves before
--                   a session exists — an empty list never reaches a live
--                   session, where it would mean "no model" and read as a
--                   broken proxy.
--
--   last_matched_at advisory, stamped on a successful exchange. It is what
--                   tells an operator that a rule they were about to delete
--                   is still load-bearing.
--
-- There is no credential column and nowhere one could go. A rule describes who
-- may ask; what they get is minted at exchange time from the hub's own
-- Anthropic credential, which lives in the hub config and never in this table.
--
-- # ci_exchanges
--
-- One row per federation attempt, accepted or refused. This is not the audit
-- trail — pkg/statedb's hash-chained audit_events is — it is the operator's
-- debugging surface, and the two have different retention and different
-- readers. The question it answers is the one asked at 2am: "my pipeline says
-- 401, what did the hub see?" Without it the answer is a token the operator
-- cannot decode and a claim set nobody recorded.
--
-- Refusals are stored precisely because they are the interesting rows. An
-- accepted exchange is visible from the session list while it lasts; a refused
-- one leaves no other trace, and "no rule matched" versus "your rule reads a
-- claim this token does not carry" are different problems with the same
-- symptom.
--
--   claims_json     the verified payload, minus nothing. It is a public
--                   assertion about a public repository, already visible to
--                   anyone who can read the workflow file, and it carries no
--                   credential: the token itself is not stored, only what it
--                   said. Storing it is what makes a rule fixable by reading
--                   rather than by guessing.
--
--   session_id      the claudeproxy session an acceptance minted, empty on a
--                   refusal. Sessions live in the hub process and not in this
--                   database (see pkg/claudeproxy/session.go for why), so this
--                   is a correlation key into the live registry and the audit
--                   trail, not a foreign key.
--
-- # Compatibility
--
-- Additive, and it has to be: :8080 and :8888 share one control-plane database
-- and a breaking migration blanks whichever hub is older until the nightly
-- rebuild. Every statement is a CREATE TABLE or a non-unique CREATE INDEX over
-- a table this migration itself creates, which is what schema_compat.go's
-- classifier recognises as tolerable to a binary that predates it. An older hub
-- has no statement naming either table.

CREATE TABLE IF NOT EXISTS ci_pipeline_rules (
    id                  TEXT PRIMARY KEY,
    name                TEXT    NOT NULL DEFAULT '',
    enabled             INTEGER NOT NULL DEFAULT 1,

    -- Matcher.
    repository          TEXT    NOT NULL DEFAULT '',
    ref                 TEXT    NOT NULL DEFAULT '',
    workflow            TEXT    NOT NULL DEFAULT '',
    environment         TEXT    NOT NULL DEFAULT '',
    actor               TEXT    NOT NULL DEFAULT '',
    event_name          TEXT    NOT NULL DEFAULT '',
    condition           TEXT    NOT NULL DEFAULT '',

    -- GrantPolicy.
    models_json         TEXT    NOT NULL DEFAULT '[]',
    max_requests        INTEGER NOT NULL DEFAULT 0,
    max_output_tokens   INTEGER NOT NULL DEFAULT 0,
    ttl_seconds         INTEGER NOT NULL DEFAULT 0,

    project             TEXT    NOT NULL DEFAULT '',
    created_by          TEXT    NOT NULL DEFAULT '',
    created_at          TEXT    NOT NULL DEFAULT '',
    updated_at          TEXT    NOT NULL DEFAULT '',
    last_matched_at     TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_ci_pipeline_rules_order
    ON ci_pipeline_rules(created_at, id);

CREATE TABLE IF NOT EXISTS ci_exchanges (
    id           TEXT PRIMARY KEY,
    at           TEXT    NOT NULL DEFAULT '',
    accepted     INTEGER NOT NULL DEFAULT 0,
    issuer       TEXT    NOT NULL DEFAULT '',
    subject      TEXT    NOT NULL DEFAULT '',
    repository   TEXT    NOT NULL DEFAULT '',
    ref          TEXT    NOT NULL DEFAULT '',
    workflow     TEXT    NOT NULL DEFAULT '',
    actor        TEXT    NOT NULL DEFAULT '',
    event_name   TEXT    NOT NULL DEFAULT '',
    run_id       TEXT    NOT NULL DEFAULT '',
    rule_id      TEXT    NOT NULL DEFAULT '',
    rule_name    TEXT    NOT NULL DEFAULT '',
    session_id   TEXT    NOT NULL DEFAULT '',
    reason       TEXT    NOT NULL DEFAULT '',
    detail       TEXT    NOT NULL DEFAULT '',
    remote_addr  TEXT    NOT NULL DEFAULT '',
    claims_json  TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_ci_exchanges_at
    ON ci_exchanges(at DESC);

CREATE INDEX IF NOT EXISTS idx_ci_exchanges_repository
    ON ci_exchanges(repository, at DESC);
