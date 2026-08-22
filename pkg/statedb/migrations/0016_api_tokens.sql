-- 0016_api_tokens: scoped, expiring, individually revocable API tokens
-- (Task 20175).
--
-- Before this table the hub had exactly two ways in: an OIDC browser session,
-- and one static bearer token that bypassed RBAC entirely and saw every
-- project. There was no way to hand CI, a script, or an edge device a
-- credential that was narrower than "everything", expired on its own, or could
-- be taken away without rotating the secret every other caller also uses.
--
-- What is stored:
--
--   id            the public half of the token. It appears verbatim inside the
--                 minted string (`cloop_pat_<id>_<secret>`) and is the lookup
--                 key on the verification path, so verification is one indexed
--                 read rather than a scan-and-compare over every row. Knowing
--                 an id is useless without the secret; it is a username, not a
--                 password.
--
--   hash          `<alg>$<salt-hex>$<digest-hex>` over the secret half. The
--                 plaintext is returned by the mint call exactly once and is
--                 never written anywhere — not here, not to the audit trail,
--                 not to a log line. A stolen database file therefore yields no
--                 usable credential. The salt is per token, so one precomputed
--                 table cannot attack the whole column.
--
--   prefix        `cloop_pat_<id>`: enough to recognise a token in a CI log or
--                 a config file and match it to a row here, and nothing more.
--
--   roles_json    the authz roles the bearer acts with. The mint path refuses
--                 to write a role the minter does not already hold, so this
--                 column can delegate authority but never manufacture it.
--
--   project_scope_json
--                 project paths (or registry names) the token may address. An
--                 empty list means every project the roles allow; a non-empty
--                 one is enforced in visibleProjectEntries, which is also the
--                 index space resolveWorkDir maps ?project_idx through — so a
--                 scoped token cannot reach an out-of-scope project even by
--                 guessing an index.
--
-- Revocation is a stamp, not a DELETE, matching broker_grants (0012): an
-- auditor asking "what could this CI job reach in March, and when did we take
-- it away" needs the row to still exist. Verification treats any non-empty
-- revoked_at as a refusal, so a stamped row is inert the moment it is written.
--
-- last_used_at is advisory. It is written off the verification path (see
-- pkg/apitoken) and coalesced, so a busy token does not turn every authenticated
-- read into a write; a dropped update loses a timestamp, never an authorization
-- decision.

CREATE TABLE IF NOT EXISTS api_tokens (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL DEFAULT '',
    hash               TEXT NOT NULL,
    prefix             TEXT NOT NULL DEFAULT '',
    roles_json         TEXT NOT NULL DEFAULT '[]',
    project_scope_json TEXT NOT NULL DEFAULT '[]',
    created_by         TEXT NOT NULL DEFAULT '',
    created_at         TEXT NOT NULL DEFAULT '',
    expires_at         TEXT NOT NULL DEFAULT '',
    last_used_at       TEXT NOT NULL DEFAULT '',
    revoked_at         TEXT NOT NULL DEFAULT ''
);

-- The list view orders by creation date; an index keeps that from degrading
-- into a sort over the table as a hub accumulates retired tokens it is
-- deliberately not deleting.
CREATE INDEX IF NOT EXISTS idx_api_tokens_created ON api_tokens(created_at);
