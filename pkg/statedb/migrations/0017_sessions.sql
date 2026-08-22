-- 0017_sessions: durable dashboard sessions (Task 20176).
--
-- Before this table an OIDC session was a map entry in the hub process. That
-- made three things true at once, all of them wrong for a hosted deployment:
-- a restart or a rolling upgrade signed every user out; there was no way for
-- an operator to see who was logged in, let alone end one session; and a user
-- the identity provider had just disabled kept working until their 24h TTL
-- lapsed, because nothing ever asked the IdP again.
--
-- What is stored:
--
--   id            SHA-256 of the session cookie, hex. The cookie itself is
--                 256 bits of CSPRNG output and is never written anywhere —
--                 not here, not to a log, not to the audit trail. Lookup is
--                 by primary key on the hash, so authenticating a request is
--                 one indexed read rather than a scan, and a stolen database
--                 file yields no usable cookie. Same reasoning as the `hash`
--                 column in 0016_api_tokens, minus the salt: the preimage
--                 here is full-entropy random rather than a chosen secret, so
--                 there is no dictionary for a per-row salt to defeat, and an
--                 unsalted digest is what lets the lookup be a key read.
--
--                 This value is also the session's public id — it is what the
--                 admin API lists and what DELETE /api/sessions/{id} names.
--                 Knowing it does not let anyone authenticate as that session,
--                 for the same reason knowing a username does not.
--
--   subject       the IdP's `sub` claim. Stable across logins, which is what
--                 makes "log out everywhere" and "terminate this person's
--                 sessions" expressible as one indexed DELETE.
--
--   owner_key     the string pkg/ui records project ownership under (email,
--                 or sub: prefixed). Denormalised so a restarted hub can scope
--                 the project list without a round trip to the IdP.
--
--   groups_json / roles_json
--                 the claims RBAC resolves against. Persisted for the same
--                 reason: after a restart the roles a session holds must be
--                 exactly the roles it held before, not whatever a re-derived
--                 default would produce.
--
--   issued_at / last_seen / expires_at
--                 the two clocks a session runs on. expires_at is the absolute
--                 ceiling set at login; last_seen drives the idle timeout and
--                 is refreshed on authenticated requests, throttled to at most
--                 one write per session per minute so a busy dashboard does not
--                 turn every read into a write on the state DB. A dropped
--                 refresh loses a timestamp, never an authorization decision —
--                 and it errs toward expiring sooner, which is the safe
--                 direction.
--
--   ip / user_agent
--                 recorded once at login, for the Active Sessions table. An
--                 operator asked to explain a session needs to recognise it.
--                 Never used as a security control: both are attacker-supplied
--                 and pinning a session to either breaks users behind mobile
--                 networks far more often than it stops a thief.
--
--   refresh_sealed
--                 the IdP refresh token, sealed with the secretbroker AEAD
--                 (AES-256-GCM under CLOOP_SECRET_KEY) exactly like a brokered
--                 credential. It is the mechanism that makes IdP-side
--                 revocation real: a background pass redeems it on an interval,
--                 and an `invalid_grant` — which is what a disabled user, a
--                 revoked consent, or a forced sign-out looks like on the wire
--                 — terminates the session immediately.
--
--                 NULL when the hub has no encryption key configured. That is a
--                 deliberate degradation, not a bug: without a key the only
--                 alternatives are to store a live credential in plaintext or
--                 to refuse to log anyone in, and neither is better than losing
--                 one revocation channel while the two timeouts still hold.
--
--   refresh_checked_at
--                 when the IdP last confirmed the session. Written on every
--                 attempt, success or failure, so an unreachable IdP is retried
--                 on the interval rather than on every request.
--
-- Unlike broker_grants (0012) and api_tokens (0016), an ended session is
-- DELETEd rather than stamped. Those tables answer "what could this credential
-- reach in March", so their rows must outlive the grant; a session row is live
-- state, not a record of authority granted, and the record of its whole
-- lifecycle — created, expired, revoked, idp_revoked — is written to the
-- hash-chained audit trail, which is append-only and cannot be edited to hide
-- one. Keeping dead rows here as well would grow the table by one row per login
-- forever in exchange for a history that already exists somewhere tamper-
-- evident.

CREATE TABLE IF NOT EXISTS sessions (
    id                 TEXT PRIMARY KEY,
    subject            TEXT NOT NULL DEFAULT '',
    issuer             TEXT NOT NULL DEFAULT '',
    email              TEXT NOT NULL DEFAULT '',
    display_name       TEXT NOT NULL DEFAULT '',
    owner_key          TEXT NOT NULL DEFAULT '',
    groups_json        TEXT NOT NULL DEFAULT '[]',
    roles_json         TEXT NOT NULL DEFAULT '[]',
    ip                 TEXT NOT NULL DEFAULT '',
    user_agent         TEXT NOT NULL DEFAULT '',
    issued_at          TEXT NOT NULL DEFAULT '',
    last_seen          TEXT NOT NULL DEFAULT '',
    expires_at         TEXT NOT NULL DEFAULT '',
    refresh_sealed     BLOB,
    refresh_checked_at TEXT NOT NULL DEFAULT ''
);

-- Logout-everywhere and admin termination both delete by subject.
CREATE INDEX IF NOT EXISTS idx_sessions_subject ON sessions(subject);

-- The janitor sweeps on both clocks; without these it degrades into a full
-- scan every tick on a hub with a large signed-in population.
CREATE INDEX IF NOT EXISTS idx_sessions_expires   ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_last_seen ON sessions(last_seen);

-- The IdP revalidation pass selects the oldest-checked sessions first.
CREATE INDEX IF NOT EXISTS idx_sessions_refresh_checked ON sessions(refresh_checked_at);
