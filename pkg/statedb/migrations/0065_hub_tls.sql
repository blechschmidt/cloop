-- 0065_hub_tls: the hub's own certificate authority, and the short-lived
-- certificates it issues the credential monitors (Task 20409).
--
-- The git interception proxy and the Kubernetes access monitor speak TLS,
-- because the session token a sandbox presents rides every request. Until this
-- migration their certificate was a pair of files the operator had to supply,
-- and a self-signed one needed its CA baked into every sandbox image, so most
-- hubs ran neither and handed forge credentials into sandboxes instead. With
-- executors.git_proxy.tls: auto (and kube_guard's) the hub issues both
-- certificates from a CA of its own, kept here so every hub-cluster member
-- serves the same identity and a backup of this database carries it.
--
-- One table, three kinds of row:
--
--   id 'ca'                 the CA. Minted once, by whichever member needed it
--                           first; the insert is ON CONFLICT DO NOTHING, so two
--                           members starting together agree on one.
--   id 'leaf:git_proxy'     the git proxy's serving certificate.
--   id 'leaf:kube_guard'    the monitor's.
--
-- A leaf lives 72 hours and the cluster leader replaces it when less than 48
-- remain, so a sandbox — which trusts the CA, never the leaf — sees a new leaf
-- long before the old one stops verifying. A replacement is a compare-and-swap
-- on serial, so two members renewing at once leave one leaf, not two.
--
--   kind        'ca' or 'leaf'.
--   serial      the certificate's serial, lowercase hex.
--   issuer      for a leaf, the serial of the CA that signed it; '' for the CA.
--   cert_pem    the certificate, PEM. Public by construction.
--   key_id, wrapped_dek, key_sealed
--               the private key, sealed under the hub's KEK registry as every
--               brokered secret is (envelope encryption, Task 20181). The
--               associated data binds it to this row's id and serial, so a
--               sealed key moved onto another row does not open. Rotated by
--               `cloop hub key rotate`; retirement counts these rows.
--   sans        the leaf's DNS names and IP addresses, a JSON array; '[]' for
--               the CA.
--   not_before, not_after, issued_at
--               RFC 3339.
--   issued_by   the hub process (cluster member id) that issued it.
--
-- Additive in schema_compat.go's sense: one new table, which no older binary
-- reads or writes.

CREATE TABLE IF NOT EXISTS hub_tls (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL DEFAULT '',
    serial      TEXT NOT NULL DEFAULT '',
    issuer      TEXT NOT NULL DEFAULT '',
    cert_pem    TEXT NOT NULL DEFAULT '',
    key_id      TEXT NOT NULL DEFAULT '',
    wrapped_dek BLOB,
    key_sealed  BLOB,
    sans        TEXT NOT NULL DEFAULT '[]',
    not_before  TEXT NOT NULL DEFAULT '',
    not_after   TEXT NOT NULL DEFAULT '',
    issued_at   TEXT NOT NULL DEFAULT '',
    issued_by   TEXT NOT NULL DEFAULT ''
);
