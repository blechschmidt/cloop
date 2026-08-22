-- 0020_quotas: per-identity quotas and usage accounting (Task 20182).
--
-- RBAC (pkg/authz) answers "may this identity act?". Nothing answered "how
-- much?", so on a shared hub one tenant could hold every executor slot, open
-- projects without bound, and — the expensive one — burn the organisation's
-- whole token budget from a single compromised account before anyone looked.
-- pkg/globalbudget already existed but is keyed by *project*, which is the
-- wrong axis under multi-tenancy: a user who can create projects can create
-- budget headroom.
--
-- Two tables, because the policy and the accounting have different lifetimes
-- and different trust properties.
--
--   quota_overrides   an admin's per-identity edit, made from the Quotas
--                     panel. It is policy, it is rare, and it must survive
--                     everything. limits_json is a sparse object — only the
--                     ceilings actually edited appear — so raising one user's
--                     max_projects does not silently freeze the rest of their
--                     limits at whatever their group granted on the day the
--                     edit was made.
--
--                     Deliberately not the only source of limits: the bulk of
--                     policy lives in config (ui.quotas.bindings) so it can be
--                     reviewed, diffed and deployed like the role mappings it
--                     sits next to. This table is the escape hatch for the
--                     one-off, and updated_by records who took it.
--
--   quota_counters    live usage. One row per (identity, resource, bucket).
--
--                     bucket is '' for gauge resources (projects, concurrent
--                     tasks, executors, sessions) and the UTC day for the two
--                     daily budgets. Putting the day in the key rather than
--                     resetting rows at midnight means a rollover needs no
--                     scheduled job and no process staying awake to run it:
--                     yesterday's row simply stops being read, and a periodic
--                     prune reclaims it.
--
-- Why counters are persisted at all, given that they are reconciled from live
-- state at startup: the two kinds need opposite treatment, and only one of
-- them can be rebuilt.
--
--   Gauges CAN be rebuilt — from the project registry, the executor table and
--   the session table — and MUST be, because nothing decrements the counter
--   for a run whose process died with the hub. Trusting the stored value
--   there fails in the direction that hurts: the tenant stays narrowed
--   forever and no operator can see why. Reconcile() therefore replaces the
--   whole set of bucket='' rows at startup. They are still written on every
--   admission so that a hub which crashes and restarts twice in a second
--   without a chance to reconcile is approximately right rather than empty.
--
--   Daily counters CANNOT be rebuilt from anything that survives, and must
--   not be: re-deriving "spend so far today" would hand a compromised account
--   a fresh token budget on every crash. So they are written on every spend
--   and read back verbatim.
--
-- value is REAL rather than INTEGER because one of the six resources is money.
-- Splitting into an integer table and a float table to save a few bytes would
-- double the accessor surface for no benefit at these row counts.

CREATE TABLE IF NOT EXISTS quota_overrides (
    identity    TEXT PRIMARY KEY,
    limits_json TEXT NOT NULL DEFAULT '{}',
    updated_at  TEXT NOT NULL DEFAULT '',
    updated_by  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS quota_counters (
    identity   TEXT NOT NULL,
    resource   TEXT NOT NULL,
    bucket     TEXT NOT NULL DEFAULT '',
    value      REAL NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (identity, resource, bucket)
);

-- The startup prune deletes every daily row older than today, and the
-- reconciliation replaces every gauge row; both scan by bucket.
CREATE INDEX IF NOT EXISTS idx_quota_counters_bucket ON quota_counters(bucket);
