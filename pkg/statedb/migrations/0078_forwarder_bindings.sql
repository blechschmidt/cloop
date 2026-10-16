-- 0078_forwarder_bindings: which projects a device forwarder's device is made
-- available to, and the requests for that (Task 20430).
--
-- A forwarder (0077) carries one on-prem USB device or network segment to the
-- hub. A binding is the operator's decision that one project's runs — and,
-- when virtual_executor is set, only those that run on that virtual executor —
-- get the device: at dispatch the hub relays the forwarder's stream to the
-- executor that runs the sandbox, which attaches the device and gives it to
-- the sandbox alone. Like every other grant it is RBAC-gated (executor.manage),
-- bounded by expires_at and audited (forwarder.bind / forwarder.unbind); a
-- revoked or lapsed binding detaches the device from a run already using it.
--
--   forwarder_bindings          one row per decision. revoked_at is set, never
--                               deleted, so the audit trail can name what a
--                               run held. project is the policy path every
--                               grant names a project by (a feature is its
--                               parent's). interface_json is an L2 segment's
--                               sandbox-side shape: target name, address,
--                               gateway, MTU.
--
--   forwarder_binding_requests  a maintainer's request for a binding, through
--                               the same request flow and inbox as secret grant
--                               requests; approving one mints the binding.
--                               state is pending, approved, denied, withdrawn
--                               or expired, as for secret_grant_requests.
--
-- Timestamps are RFC3339 TEXT; the empty string means "not set". Two new
-- tables and plain indexes only: additive, so an older hub sharing this
-- control plane keeps serving it.

CREATE TABLE IF NOT EXISTS forwarder_bindings (
    id               TEXT PRIMARY KEY,
    forwarder_id     TEXT NOT NULL DEFAULT '',
    project          TEXT NOT NULL DEFAULT '',
    virtual_executor TEXT NOT NULL DEFAULT '',
    interface_json   TEXT NOT NULL DEFAULT '',
    note             TEXT NOT NULL DEFAULT '',
    created_by       TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL DEFAULT '',
    expires_at       TEXT NOT NULL DEFAULT '',
    request_id       TEXT NOT NULL DEFAULT '',
    revoked_at       TEXT NOT NULL DEFAULT '',
    revoked_by       TEXT NOT NULL DEFAULT '',
    revoke_reason    TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_forwarder_bindings_project ON forwarder_bindings(project);
CREATE INDEX IF NOT EXISTS idx_forwarder_bindings_forwarder ON forwarder_bindings(forwarder_id);

CREATE TABLE IF NOT EXISTS forwarder_binding_requests (
    id               TEXT PRIMARY KEY,
    forwarder_id     TEXT NOT NULL DEFAULT '',
    project          TEXT NOT NULL DEFAULT '',
    virtual_executor TEXT NOT NULL DEFAULT '',
    interface_json   TEXT NOT NULL DEFAULT '',
    ttl_seconds      INTEGER NOT NULL DEFAULT 0,
    justification    TEXT NOT NULL DEFAULT '',
    requested_by     TEXT NOT NULL DEFAULT '',
    state            TEXT NOT NULL DEFAULT 'pending',
    created_at       TEXT NOT NULL DEFAULT '',
    expires_at       TEXT NOT NULL DEFAULT '',
    decided_by       TEXT NOT NULL DEFAULT '',
    decided_at       TEXT NOT NULL DEFAULT '',
    decision_note    TEXT NOT NULL DEFAULT '',
    binding_id       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_forwarder_binding_requests_state ON forwarder_binding_requests(state);
