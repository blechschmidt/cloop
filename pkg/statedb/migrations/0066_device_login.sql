-- 0066_device_login: a terminal signs in to an SSO hub by device authorization,
-- and the result is a session like any other (Task 20412).
--
-- On a hub with single sign-on a developer had no way to get a credential for
-- the command line: API tokens take token.admin, which is provisioning an
-- identity, and the session cookie never leaves the browser. `cloop login`
-- runs the RFC 8628 device authorization grant against the hub — the terminal
-- shows a code, a signed-in browser approves it at /device — and what comes
-- out is a row in `sessions`, so it expires, idles out, re-checks its claims,
-- is listed, revoked and offboarded exactly as a browser session is.
--
-- # sessions: two columns
--
--   kind    'browser' or 'cli'. What the session authenticates: a browser by
--           its cookie, a terminal by `Authorization: Bearer cloop_cli_…`.
--           Neither is accepted the other way, so a terminal credential copied
--           into a cookie, or a cookie presented as a bearer, finds nothing.
--           A CLI session's idle and absolute lifetimes are its own, and never
--           longer than a browser's (ui.oidc.cli_*).
--   client  the host name the terminal reported when it asked for a code, for
--           the Active Sessions table and the audit trail. Attacker-supplied,
--           like ip and user_agent: a label an operator reads, never an input
--           to a decision.
--
-- # device_authorizations
--
-- One row per code a terminal asked for. It lives ten minutes unless approved,
-- and the leader's session janitor deletes it a while after that. It holds no
-- credential, by construction:
--
--   device_hash   SHA-256 of the device code, hex. The terminal polls with the
--                 code itself; only its digest is stored, as for sessions.
--   user_code_hash
--                 SHA-256 of the normalised user code (the ten letters a person
--                 reads off the terminal and types at /device). Looked up when a
--                 signed-in browser enters it.
--   credential_hash
--                 SHA-256 of the session credential the terminal will present
--                 — which the terminal generated and kept, and committed to by
--                 sending this digest when it asked for the code, the way PKCE
--                 commits to a verifier. The approval writes the session under
--                 a labelled digest of it (oidcauth.CLISessionID), so the token
--                 endpoint never hands a credential out, nothing in this table,
--                 a log or a proxy can be replayed as the session, and no
--                 session id the hub shows can be committed to. Cleared once
--                 the terminal collects its session.
--   status        pending | approved | denied | consumed. A code is approved or
--                 denied once, and an approval is exchanged once.
--   client_ip, client_user_agent, client_hostname
--                 who asked, as the hub saw them and as the terminal said. The
--                 approval page shows all three, because device-code phishing —
--                 somebody else's code, sent to you to approve — is the attack
--                 on this grant, and "where is this request from" is the
--                 question that defeats it.
--   created_at, expires_at
--                 RFC 3339; expires_at is ten minutes after created_at.
--   interval_seconds, last_polled_at
--                 the polling contract: a terminal that polls faster than the
--                 interval is told slow_down and the interval grows by five
--                 seconds, as RFC 8628 has it.
--   approver, approver_session, decided_at, reason
--                 who approved or denied it (their owner key), from which
--                 browser session (its hashed id), when, and why it was denied.
--   subject       the approver's IdP subject.
--
-- Additive in schema_compat.go's sense: two appended columns with defaults and
-- no constraints, and a new table. A binary predating this migration reads
-- every session as a browser session — the only kind it can authenticate — and
-- never touches the new table.

ALTER TABLE sessions ADD COLUMN kind TEXT NOT NULL DEFAULT 'browser';
ALTER TABLE sessions ADD COLUMN client TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS device_authorizations (
    device_hash       TEXT PRIMARY KEY,
    user_code_hash    TEXT NOT NULL DEFAULT '',
    credential_hash   TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL DEFAULT 'pending',
    client_ip         TEXT NOT NULL DEFAULT '',
    client_user_agent TEXT NOT NULL DEFAULT '',
    client_hostname   TEXT NOT NULL DEFAULT '',
    created_at        TEXT NOT NULL DEFAULT '',
    expires_at        TEXT NOT NULL DEFAULT '',
    interval_seconds  INTEGER NOT NULL DEFAULT 5,
    last_polled_at    TEXT NOT NULL DEFAULT '',
    approver          TEXT NOT NULL DEFAULT '',
    approver_session  TEXT NOT NULL DEFAULT '',
    subject           TEXT NOT NULL DEFAULT '',
    decided_at        TEXT NOT NULL DEFAULT '',
    reason            TEXT NOT NULL DEFAULT ''
);

-- A person types the user code; the browser looks it up by its digest. Not
-- UNIQUE: that would make this index a constraint schema_compat.go reads as
-- breaking, and uniqueness among live codes is the issuer's job (it draws again
-- on a collision, which at 43 bits and a ten-minute lifetime never happens).
CREATE INDEX IF NOT EXISTS idx_device_authorizations_user_code ON device_authorizations(user_code_hash);

-- The janitor sweeps by expiry.
CREATE INDEX IF NOT EXISTS idx_device_authorizations_expires ON device_authorizations(expires_at);

-- The janitor sweeps CLI sessions on their own idle clock.
CREATE INDEX IF NOT EXISTS idx_sessions_kind_last_seen ON sessions(kind, last_seen);
