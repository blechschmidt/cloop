-- 0064_static_tokens: retire the static admin token without a restart, and
-- say when it was last used (Task 20406).
--
-- The static --token / CLOOP_UI_TOKEN is an administrator credential outside
-- RBAC with no expiry. Until this migration the only way to stop a hub
-- honouring it was to edit the Secret and restart every member, and nothing
-- said whether anything still presented it. Two tables, both keyed by the
-- token's fingerprint (statictoken.Fingerprint: a domain-separated SHA-256 of
-- the value). The value itself is never stored.
--
-- retired_static_tokens — one row per retired token. Every hub process loads
-- the set at start, re-reads it on a hub-bus notice and at least every 30
-- seconds, and refuses a token whose fingerprint is in it. Retirement is per
-- fingerprint, so deploying a new value is the rotation path: a new value is
-- admitted, a retired one never again.
--
--   fingerprint  the retired token's fingerprint, 64 hex characters.
--   retired_at   when, RFC 3339.
--   retired_by   who: an operator at a shell (cli:<os user>), a signed-in
--                administrator, an API token, or the static token itself.
--   reason       why, as stated by whoever retired it. Shown on the Settings
--                card and in `cloop hub token static status`; never in the 401
--                a caller presenting the token receives.
--
-- static_token_use — what the hub processes holding a static token report
-- about it, flushed from memory every 30 seconds rather than written per
-- request. One row per fingerprint: members holding the same token merge
-- into it, each keeping the latest use.
--
--   fingerprint     the token's fingerprint.
--   first_seen_at   when a hub process first reported holding it, RFC 3339.
--   held_at         when one last did. A row reported within a few minutes
--                   is held by a running hub; `cloop hub token static retire`
--                   finds the token to retire this way, without its value.
--   held_by         the hub process (cluster member id) that last reported.
--   sso             1 when that process has single sign-on configured.
--   last_used_at    when a request was last admitted with it; '' if never.
--   last_used_ip    the client address of that request.
--   refused_count   requests refused because it is retired.
--   last_refused_at when the last of those arrived; '' if none has.
--   last_refused_ip its client address — after a leak, who is still trying.
--
-- Additive in schema_compat.go's sense: two new tables, which no older binary
-- reads or writes.

CREATE TABLE IF NOT EXISTS retired_static_tokens (
    fingerprint TEXT PRIMARY KEY,
    retired_at  TEXT NOT NULL DEFAULT '',
    retired_by  TEXT NOT NULL DEFAULT '',
    reason      TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS static_token_use (
    fingerprint     TEXT PRIMARY KEY,
    first_seen_at   TEXT NOT NULL DEFAULT '',
    held_at         TEXT NOT NULL DEFAULT '',
    held_by         TEXT NOT NULL DEFAULT '',
    sso             INTEGER NOT NULL DEFAULT 0,
    last_used_at    TEXT NOT NULL DEFAULT '',
    last_used_ip    TEXT NOT NULL DEFAULT '',
    refused_count   INTEGER NOT NULL DEFAULT 0,
    last_refused_at TEXT NOT NULL DEFAULT '',
    last_refused_ip TEXT NOT NULL DEFAULT ''
);
