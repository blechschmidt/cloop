-- 0023_api_token_owner: label hub-issued tokens and bind them to a user
-- (Task 20194).
--
-- 0016 modelled a token as a self-contained bundle of roles. That is the right
-- shape for a CI credential, which acts as itself, but the wrong shape for a
-- credential the hub issues *on a person's behalf* — a display-glasses link,
-- where the URL is the only place a wearable can carry a secret.
--
-- Two columns:
--
--   kind        "" for an ordinary operator-minted PAT, or a name from the
--               Kind* constants in pkg/apitoken. It is what lets the hub find
--               "this user's glasses link" precisely, so minting a new one can
--               rotate the old one out rather than accumulating live
--               credentials nobody is tracking. Without it the only handle
--               would be the operator-chosen name, which is not unique and not
--               the hub's to reserve.
--
--   owner_json  the identity's claim bundle (sub, email, name, groups, roles)
--               as it stood at mint time. NOT a permission snapshot: it is the
--               *input* to the role mapping, re-resolved against the current
--               policy on every request, and the resulting authority is
--               intersected with the token's own roles (authz.Intersect). So a
--               delegated token can only ever shrink when its owner's access
--               is narrowed, and never widens when their token is left lying
--               around. An empty string means an unbound token, which behaves
--               exactly as it did before this migration.
--
-- Why claims and not a user id: cloop has no user directory. An IdP subject
-- that has not signed in recently exists nowhere else in the database, so a
-- foreign key would resolve to nothing precisely when a long-lived link is
-- being used. Nothing here is an OAuth credential — no access or refresh token
-- — so a stolen database still cannot act as the user anywhere but here, where
-- the hash column already denies it the token itself.
--
-- Both columns default to '' so every row written before this migration keeps
-- its exact previous meaning: an unlabelled, unbound token.

ALTER TABLE api_tokens ADD COLUMN kind TEXT NOT NULL DEFAULT '';
ALTER TABLE api_tokens ADD COLUMN owner_json TEXT NOT NULL DEFAULT '';

-- Finding one user's hub-issued tokens is a lookup by (kind, owner), done on
-- the self-service path where a user opens the panel. Indexed so it stays a
-- lookup as retired links accumulate — revocation is a stamp, not a DELETE.
CREATE INDEX IF NOT EXISTS idx_api_tokens_kind_owner ON api_tokens(kind, owner_json);
