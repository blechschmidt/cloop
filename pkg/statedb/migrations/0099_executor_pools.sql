-- 0099_executor_pools: executor pools, their controllers' credentials, the
-- ephemeral runners they enroll and the runs waiting for one (Task 20482).
--
-- An executor pool is a set of runners a controller outside the hub starts on
-- demand, modelled on GitHub's Actions Runner Controller scale sets: the
-- controller watches the pool's demand, asks the hub for runner tokens, and
-- starts one runner per token; each runner enrolls, takes one run, and is
-- retired. A project bound to a pool (project_executors.executor_id
-- "pool:<id>") has its runs queued for the pool instead of dispatched to an
-- executor.
--
-- executor_pools         one row per pool.
--   id                   "pool-" and 16 base64url characters; what a project
--                        binding, a credential and a runner name.
--   name                 what people call it, unique.
--   labels_json          the labels its runners carry — and enroll with, so
--                        label grants reach them — as a JSON object.
--   capabilities_json    what its runners advertise (harnesses, container
--                        runtimes, platform, architecture, memory), a JSON
--                        object placement matches a queued run against.
--   max_runners          how many runners may exist at once: tokens minted
--                        and not yet expired or redeemed, plus runners
--                        enrolled and not yet retired.
--   owner                who the pool belongs to, in oidcauth.Identity's
--                        OwnerKey namespace; '' for an organisation pool. A
--                        pool with an owner serves only projects its owner may
--                        read: its runners would hold their code and secrets.
--   workdir_root         the root its runners confine workloads to; '' lets
--                        the runner choose.
--   created_*, updated_* RFC 3339 UTC and the acting identity.
--   revoked_*            set once, when the pool is revoked: every credential,
--                        unredeemed token, queued run and live runner of it is
--                        refused or retired in the same transaction.
--
-- executor_pool_audience who may run work on the pool's runners, like
--                        executor_audience for an executor: no rows, anyone a
--                        project binding sends there.
--
-- executor_pool_credentials  the controller's credentials. Never the secret:
--                        secret_hash is the hex SHA-256 of the
--                        cloop_pool1_<id>.<secret> credential's secret part.
--
-- executor_pool_runners  one row per runner token minted, keyed by the token's
--                        executor_enrollment_tokens id. state is pending
--                        (minted), idle (enrolled, waiting for a run), busy
--                        (handed a run: queue_id) or retired. executor_id is
--                        the agent the token became; member the hub process
--                        holding its connection; credential_id the controller
--                        credential that minted it, so revoking that credential
--                        takes back what it minted.
--
-- executor_pool_queue    one row per run waiting for, or handed to, a runner.
--                        state is waiting, assigned (a runner has claimed it
--                        and is starting it), dispatched, cancelled or failed;
--                        reason says why, for the project's readers. starter
--                        and payer are whom the run acts for and who pays,
--                        decided when it was queued with the person's own
--                        sign-in in hand; audience_fp is the pool's access
--                        list as it was then, so a change since is noticed.
--                        requirements_json is what the run needs of an
--                        executor; slot_json the concurrency slot it holds
--                        while it waits, handed to the run or given back.
--                        attempts counts the runners it was handed: a run that
--                        no runner could start is failed after a few, rather
--                        than handed to runner after runner for ever.
--                        At most one open (waiting or assigned) row per
--                        project, which the unique index below enforces.
--
-- New tables only, so additive in schema_compat.go's sense: an older binary
-- sharing this control plane never reads them. It reads a pool binding as an
-- executor ID, finds no executor, and refuses the run.
CREATE TABLE IF NOT EXISTS executor_pools (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL DEFAULT '',
    labels_json       TEXT NOT NULL DEFAULT '{}',
    capabilities_json TEXT NOT NULL DEFAULT '{}',
    max_runners       INTEGER NOT NULL DEFAULT 1,
    owner             TEXT NOT NULL DEFAULT '',
    workdir_root      TEXT NOT NULL DEFAULT '',
    created_at        TEXT NOT NULL DEFAULT '',
    created_by        TEXT NOT NULL DEFAULT '',
    updated_at        TEXT NOT NULL DEFAULT '',
    updated_by        TEXT NOT NULL DEFAULT '',
    revoked_at        TEXT NOT NULL DEFAULT '',
    revoked_by        TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_executor_pools_name ON executor_pools(name);

CREATE TABLE IF NOT EXISTS executor_pool_audience (
    pool_id         TEXT NOT NULL,
    principal_kind  TEXT NOT NULL,
    principal_value TEXT NOT NULL,
    added_at        TEXT NOT NULL DEFAULT '',
    added_by        TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (pool_id, principal_kind, principal_value)
);

CREATE TABLE IF NOT EXISTS executor_pool_credentials (
    id           TEXT PRIMARY KEY,
    pool_id      TEXT NOT NULL,
    secret_hash  TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT '',
    created_by   TEXT NOT NULL DEFAULT '',
    last_used_at TEXT NOT NULL DEFAULT '',
    revoked_at   TEXT NOT NULL DEFAULT '',
    revoked_by   TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_executor_pool_credentials_pool ON executor_pool_credentials(pool_id);

CREATE TABLE IF NOT EXISTS executor_pool_runners (
    enrollment_id TEXT PRIMARY KEY,
    pool_id       TEXT NOT NULL,
    name          TEXT NOT NULL DEFAULT '',
    executor_id   TEXT NOT NULL DEFAULT '',
    state         TEXT NOT NULL DEFAULT 'pending',
    member        TEXT NOT NULL DEFAULT '',
    queue_id      TEXT NOT NULL DEFAULT '',
    minted_at     TEXT NOT NULL DEFAULT '',
    expires_at    TEXT NOT NULL DEFAULT '',
    enrolled_at   TEXT NOT NULL DEFAULT '',
    busy_at       TEXT NOT NULL DEFAULT '',
    retired_at    TEXT NOT NULL DEFAULT '',
    retire_reason TEXT NOT NULL DEFAULT '',
    credential_id TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_executor_pool_runners_pool ON executor_pool_runners(pool_id, state);
CREATE INDEX IF NOT EXISTS idx_executor_pool_runners_executor ON executor_pool_runners(executor_id);
CREATE INDEX IF NOT EXISTS idx_executor_pool_runners_credential ON executor_pool_runners(credential_id);

CREATE TABLE IF NOT EXISTS executor_pool_queue (
    id                TEXT PRIMARY KEY,
    pool_id           TEXT NOT NULL,
    project_path      TEXT NOT NULL,
    handler           TEXT NOT NULL DEFAULT '',
    starter           TEXT NOT NULL DEFAULT '',
    payer             TEXT NOT NULL DEFAULT '',
    audience_fp       TEXT NOT NULL DEFAULT '',
    requirements_json TEXT NOT NULL DEFAULT '{}',
    slot_json         TEXT NOT NULL DEFAULT '',
    state             TEXT NOT NULL DEFAULT 'waiting',
    reason            TEXT NOT NULL DEFAULT '',
    executor_id       TEXT NOT NULL DEFAULT '',
    member            TEXT NOT NULL DEFAULT '',
    attempts          INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT NOT NULL DEFAULT '',
    updated_at        TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_executor_pool_queue_pool ON executor_pool_queue(pool_id, state, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_executor_pool_queue_open ON executor_pool_queue(project_path)
    WHERE state IN ('waiting', 'assigned');
