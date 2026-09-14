-- 0033_role_bindings: runtime role bindings for incident response (Task 20248).
--
-- Until now every role binding came from .cloop/config.yaml — `oidc.admin_emails`
-- and `oidc.role_mappings`, read once by pkg/authz at startup. That is the right
-- home for policy: it is reviewable, diffable, and deployed like the rest of the
-- hub's configuration.
--
-- It is the wrong home for an emergency. Demoting a compromised administrator
-- meant editing a ConfigMap and redeploying, which on a hosted hub is minutes at
-- best and needs whoever holds the deployment pipeline — not the on-call engineer
-- watching the account being used. This table is the other half: bindings an
-- operator can write in one command, that outrank the configured ones, and that
-- can be taken back just as fast.
--
-- Columns:
--   id          deterministic: "rb_" || first 12 hex of SHA-256 over
--               effect|claim|value|project|executor. Deterministic rather than
--               random so writing the same binding twice is idempotent — an
--               on-call engineer repeating a command under pressure must not end
--               up with two rows and no way to tell which one is live — and so
--               the primary key doubles as the uniqueness constraint.
--   effect      'allow' or 'deny'. Modelled explicitly rather than as
--               role='none' because the two obey different precedence rules:
--               "strongest role wins" is what ranks allows against each other,
--               and a deny has to beat every allow regardless of rank. Folding
--               them into one column would make the emergency lever lose to any
--               admin binding at the same specificity, which is precisely the
--               case it exists for.
--   claim       email | sub | group | role, matching authz.ClaimKind.
--   value       the claim value, normalized the same way authz normalizes it
--               (trimmed, leading '/' stripped, lowercased for email).
--   role        the granted role for effect='allow'; 'none' for a deny, where
--               it carries no meaning and is stored only to keep the column
--               non-null.
--   project     optional narrowing to one project (registry name or path).
--   executor    optional narrowing to one executor.
--   reason      why this binding exists. Required by the CLI, not by the
--               schema: a row written by a future REST handler should not be
--               rejected by storage for a policy the caller enforces.
--   created_at  RFC3339Nano UTC.
--   created_by  the operating OS user recorded by the CLI ("cli:aiden"), or an
--               HTTP identity if this is ever written from a handler.
--
-- Read on every authorization decision through a TTL-cached source
-- (pkg/rolestore), which is what lets a demotion written on a live hub take
-- effect without a restart. Row counts are tiny by construction — this is the
-- exception table, not the policy table — so the periodic full scan is cheaper
-- than any incremental scheme would be.

CREATE TABLE IF NOT EXISTS role_bindings (
    id         TEXT PRIMARY KEY,
    effect     TEXT NOT NULL DEFAULT 'allow',
    claim      TEXT NOT NULL DEFAULT '',
    value      TEXT NOT NULL DEFAULT '',
    role       TEXT NOT NULL DEFAULT 'none',
    project    TEXT NOT NULL DEFAULT '',
    executor   TEXT NOT NULL DEFAULT '',
    reason     TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT ''
);

-- The incident query is "is this identity denied anywhere", asked by a human
-- under time pressure and by `cloop hub role list --identity`.
CREATE INDEX IF NOT EXISTS idx_role_bindings_value ON role_bindings(claim, value);
