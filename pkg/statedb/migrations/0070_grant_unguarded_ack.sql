-- 0070_grant_unguarded_ack: an administrator's acknowledgement that a
-- kubeconfig grant may reach a sandbox without the Kubernetes access monitor
-- (Task 20420).
--
-- Without the monitor, a kubeconfig grant's namespace allowlist is only the
-- default kubectl uses when -n is not given, and its verbs — read-only above
-- all — are not checked at all. The broker therefore refuses to deliver a
-- grant that claims either on a hub that runs no monitor, unless an
-- administrator has recorded, on the grant, that delivering it unenforced is
-- acceptable. These three columns are that record:
--
--   unguarded_ack_at      RFC 3339 UTC, when it was recorded; '' when none is.
--   unguarded_ack_by      who recorded it.
--   unguarded_ack_reason  why, as they wrote it.
--
-- Written by the acknowledgement and its withdrawal only: PutBrokerGrant sets
-- them on insert and never on update, as it does the suspension columns.
-- Additive — three defaulted columns — so an older hub opens a database
-- carrying it and simply never reads them.

ALTER TABLE broker_grants ADD COLUMN unguarded_ack_at TEXT NOT NULL DEFAULT '';

ALTER TABLE broker_grants ADD COLUMN unguarded_ack_by TEXT NOT NULL DEFAULT '';

ALTER TABLE broker_grants ADD COLUMN unguarded_ack_reason TEXT NOT NULL DEFAULT '';
