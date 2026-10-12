-- 0071_api_token_mint_policy: whether a role policy was in force when an API
-- token was minted, and an administrator's re-approval of one that was not
-- (Task 20422).
--
-- A token minted from the dashboard has no owner: its authority is the roles
-- stamped into it, checked at mint against the minter's own. While single
-- sign-on runs with no role policy every signed-in identity holds every role,
-- so any of them could mint an admin token — and it stayed admin, for up to a
-- year, after the policy was switched on. The hub now records what governed
-- the mint, and suspends an owner-less token minted without a policy, on a hub
-- that enforces one, until an administrator approves it under that policy:
--
--   minted_under  'policy'    minted through the hub while its role policy was
--                             in force;
--                 'no_policy' minted through the hub while none was;
--                 'operator'  minted at the control plane (`cloop hub token
--                             create`), by whoever holds its database;
--                 ''          minted before this column existed — unknown,
--                             and treated as no policy.
--   approved_at   RFC 3339 UTC, when an administrator approved it; ''.
--   approved_by   who did.
--
-- Additive — three defaulted columns — so an older hub opens a database
-- carrying it; a token such a hub mints is recorded '' and so, on a hub that
-- enforces a policy, waits for an approval.

ALTER TABLE api_tokens ADD COLUMN minted_under TEXT NOT NULL DEFAULT '';

ALTER TABLE api_tokens ADD COLUMN approved_at TEXT NOT NULL DEFAULT '';

ALTER TABLE api_tokens ADD COLUMN approved_by TEXT NOT NULL DEFAULT '';
