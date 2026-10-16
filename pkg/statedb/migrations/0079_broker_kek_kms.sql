-- 0079_broker_kek_kms: key-encryption keys held wrapped by an external
-- key-management service (Task 20433).
--
-- A KEK used to be derived from CLOOP_SECRET_KEY and the row's salt, so the
-- database and the key file together opened every sealed credential. With
-- secrets.kms configured a KEK is random instead, and only a KMS's ciphertext
-- of it is stored: opening it is a call to the KMS.
--
--   wrap             '' — derived from a passphrase root and salt, as every
--                    key before this column; 'kms' — held wrapped by the KMS
--                    the root column names.
--   kms_key_id       the KMS key (and, for most KMSs, its version) that
--                    wrapped it, as the KMS reported it. A rotation of the KMS
--                    key is noticed by comparing this with the key the KMS now
--                    encrypts under, and the KEK is rewrapped in place.
--   kms_ciphertext   the KMS's ciphertext of the KEK. Never the KEK. Destroyed
--                    with the salt when the key is retired.
--   kms_annotations  JSON object of base64 values: the metadata a Kubernetes
--                    KMS v2 plugin returns with a ciphertext and must be given
--                    back to decrypt it. Not secret by the protocol's rules.
--
-- A KMS-held row's salt is a decoy — random bytes no passphrase derives its
-- key from — so a build from before this migration sees a live key it cannot
-- derive and refuses to start or seal, instead of reading an empty salt as a
-- retired key and minting a passphrase key over the KMS's primary.
--
-- Additive — four defaulted columns — so an older hub opens a database
-- carrying them; its own keys are written with wrap '' and stay derived.

ALTER TABLE broker_keks ADD COLUMN wrap TEXT NOT NULL DEFAULT '';
ALTER TABLE broker_keks ADD COLUMN kms_key_id TEXT NOT NULL DEFAULT '';
ALTER TABLE broker_keks ADD COLUMN kms_ciphertext BLOB;
ALTER TABLE broker_keks ADD COLUMN kms_annotations TEXT NOT NULL DEFAULT '';
