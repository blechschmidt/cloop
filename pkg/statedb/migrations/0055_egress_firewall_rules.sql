-- executor_firewall_rules / project_firewall_rules — the two stored levels of
-- the IP-layer egress firewall (Task 20363, re-landing Task 20319).
--
-- An admin's rule set per device is the superset of what any sandbox on that
-- device may reach; a virtual executor's firewall (virtual_executors.spec_json)
-- and a project's rule set may only narrow it. pkg/fwpolicy holds the
-- containment rule. Both tables key one rule set per subject and store it as
-- the canonical JSON of executor.FirewallRules, so two spellings of one policy
-- are one string; `fingerprint` is fwpolicy.Fingerprint of it, the name the
-- container driver gives the bridge and nftables table a workload with rules
-- of its own runs on.
--
-- # Why IF NOT EXISTS, in exactly this shape
--
-- A stranded build of Task 20319 created both tables on the live hub database
-- under a migration number that collided with main's (48), and that database
-- still has them, empty. Main's 0048 is a different migration, so this version
-- is the first main applies there — and a plain CREATE TABLE would fail on the
-- existing table and keep the hub from starting. The columns, defaults and
-- indexes below are the stranded ones verbatim, so on that database every
-- statement here is a no-op and the existing tables are already what this
-- build reads; statedb's TestFirewallTablesAdoptTheStrandedShape opens a
-- database holding them.
--
-- Additive in schema_compat.go's sense: two CREATE TABLEs and two plain
-- CREATE INDEXes, so an older binary sharing this control plane keeps opening
-- it. The cost is stated plainly: an older binary dispatching a task does not
-- see these rules and does not apply them.
CREATE TABLE IF NOT EXISTS executor_firewall_rules (
    executor_id TEXT PRIMARY KEY,
    rules       TEXT NOT NULL DEFAULT '{}',
    fingerprint TEXT NOT NULL DEFAULT '',
    set_at      TEXT NOT NULL DEFAULT '',
    set_by      TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_executor_firewall_rules_set_at
    ON executor_firewall_rules(set_at);

CREATE TABLE IF NOT EXISTS project_firewall_rules (
    project_path TEXT PRIMARY KEY,
    rules        TEXT NOT NULL DEFAULT '{}',
    fingerprint  TEXT NOT NULL DEFAULT '',
    set_at       TEXT NOT NULL DEFAULT '',
    set_by       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_project_firewall_rules_set_at
    ON project_firewall_rules(set_at);
