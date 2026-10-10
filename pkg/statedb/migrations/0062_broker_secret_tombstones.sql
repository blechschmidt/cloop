-- 0062_broker_secret_tombstones: remember what a deleted secret was called
-- (Task 20400).
--
-- Deleting a secret revokes every grant over it and removes its row, sealed
-- payload and wrapped data key together. The revoked grants stay — revocation
-- is a stamp, so "who could reach this last month" keeps an answer — but each
-- one then names a secret_id that resolves to nothing. That used to be all the
-- next run of a project granted the credential could say about it: a lease
-- refused the grant as revoked, or as pointing at a missing secret, with no
-- name a person would recognise.
--
-- It matters most when nobody on the project deleted anything. Offboarding
-- destroys the personal secrets of the person who left — their GitHub PAT,
-- their kubeconfig — and a shared project a colleague had granted one of them
-- to finds out on its next run. A tombstone is how that refusal can say whose
-- credential it was, what it was called, and why it is gone.
--
-- One row per deleted secret, holding metadata only:
--
--   secret_id   the deleted secret's id, which the revoked grants still carry.
--   name, kind  what it was. A name is a handle chosen by a person, never the
--               value, and is already in every audit row the secret produced.
--   owner       the identity it personally belonged to, or '' for a shared one.
--   deleted_at  when it was destroyed, RFC 3339.
--   deleted_by  who destroyed it — an operator, or the offboarding run.
--   cause       'deleted', or 'offboarded' when the secret was destroyed
--               because its owner was offboarded. This is what a refusal
--               tells the project that lost the credential.
--   reason      why, as stated by whoever deleted it. For an offboarding that
--               is often an HR matter, so it stays here and in the audit
--               trail and never reaches a refusal a project member reads.
--
-- Nothing sealed is kept: the point of deleting is that the material is gone,
-- and a tombstone is what is left to say so.
--
-- broker_grants.revoked_cause says why a revoked grant was revoked, in the one
-- vocabulary a lease reads back: 'owner_offboarded' (its personal secret's
-- owner left — the grant was revoked by the offboarding, whether the secret was
-- then destroyed or kept under a legal hold), 'secret_deleted' (the secret it
-- spent was deleted), or '' (revoked by hand, or before this column existed).
-- A fixed word rather than the revoker's text: the text goes to the audit
-- trail, and this column decides what a project that lost a grant is told.

CREATE TABLE IF NOT EXISTS broker_secret_tombstones (
    secret_id  TEXT PRIMARY KEY,
    name       TEXT NOT NULL DEFAULT '',
    kind       TEXT NOT NULL DEFAULT '',
    owner      TEXT NOT NULL DEFAULT '',
    deleted_at TEXT NOT NULL DEFAULT '',
    deleted_by TEXT NOT NULL DEFAULT '',
    cause      TEXT NOT NULL DEFAULT '',
    reason     TEXT NOT NULL DEFAULT ''
);

-- "What did this person leave behind" is asked by owner during an offboarding
-- review, after their secrets' own rows — and the owner column on them — are
-- gone.
CREATE INDEX IF NOT EXISTS idx_broker_secret_tombstones_owner ON broker_secret_tombstones(owner);

ALTER TABLE broker_grants ADD COLUMN revoked_cause TEXT NOT NULL DEFAULT '';
