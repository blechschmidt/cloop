-- virtual_executors — sub-executors of an enrolled device, each with a
-- sandbox configuration of its own (Task 20345).
--
-- Before this, containment was a property of a machine: one sandbox mode, one
-- runtime, one network per enrolled device. A virtual executor is a named
-- sub-executor that dispatches through its parent's connection and carries its
-- own engine, runtime, image, IP firewall and host devices, so one bench host
-- can offer a locked-down sandbox to everyone and a sandbox with its hardware
-- security module in it to the people allowed near the module.
--
-- The row holds only what is specific to a virtual executor: which device it
-- belongs to, its label, and its configuration as JSON (executor.VirtualSpec —
-- sandbox settings, firewall rules and device selectors). Everything that is
-- per-executor already — resource ceilings, the access list, project bindings —
-- is keyed by executor ID in its own table and applies to a virtual executor
-- under its own ID, unchanged.
--
-- spec_json is a document rather than columns because its parts only ever
-- travel together — to the dashboard, to the audit trail and in a start frame —
-- and because the firewall and device lists are lists.
--
-- Additive: one CREATE TABLE, which an older binary sharing this control plane
-- never selects.
CREATE TABLE IF NOT EXISTS virtual_executors (
    id         TEXT PRIMARY KEY,
    parent_id  TEXT NOT NULL,
    name       TEXT NOT NULL DEFAULT '',
    spec_json  TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT ''
);
