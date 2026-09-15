-- 0039_secret_owner: let a user keep a credential that is theirs alone
-- (Task 20275).
--
-- Every secret in broker_secrets has so far belonged to the organisation. A
-- maintainer minted it, and anybody else holding secret.grant could list it,
-- hand it to an executor and delete it. For the deploy key a whole fleet
-- shares that is right. For the credential one developer brings — their own
-- GitHub PAT, their own kubeconfig — it is the reason they cannot bring it:
-- on a multi-user hub, storing a personal credential meant handing a usable
-- copy to every other maintainer, so the supported alternative was to paste it
-- into a project config and hope.
--
-- owner is that missing dimension. It holds an identity in the same OwnerKey
-- namespace the rest of the hub uses for people (a lowercased email, or
-- "sub:<issuer subject>" when the IdP releases no email), and empty — the
-- default every existing row takes — keeps meaning "shared". That is what
-- makes this migration additive in behaviour as well as in schema: no existing
-- secret changes hands, and a hub rolled back to the previous binary sees
-- columns it ignores rather than rows it cannot read.
--
-- broker_grants carries the owner too, denormalised from the secret it points
-- at. A grant listing is read far more often than a secret is minted, so
-- resolving each grant's secret to decide whether the viewer may see the row
-- would be the N+1 read the listing handlers already avoid. It also keeps the
-- row self-describing once the secret is gone: the revoked grants a deleted
-- personal secret leaves behind still say whose credential they spent, which
-- is the question an offboarding review asks.

ALTER TABLE broker_secrets ADD COLUMN owner TEXT NOT NULL DEFAULT '';
ALTER TABLE broker_grants  ADD COLUMN owner TEXT NOT NULL DEFAULT '';

-- Listing "my secrets" is the single hottest query the personal path adds: the
-- Secrets panel issues it on every open, for every signed-in user. The index
-- is on owner alone rather than (owner, name) because the broker sorts by name
-- in Go after filtering, and a covering index would have to be maintained on
-- every mint for a set that is small by construction — one person's
-- credentials.
CREATE INDEX IF NOT EXISTS idx_broker_secrets_owner ON broker_secrets(owner);
CREATE INDEX IF NOT EXISTS idx_broker_grants_owner  ON broker_grants(owner);
