-- proxy_sessions and app_token_slots — what a run's lease feeds, recorded so
-- it outlives the hub process that minted it (Task 20383).
--
-- Since Task 20382 a restarted hub takes over an adopted device run's secret
-- lease (secret_leases). Everything that lease feeds still lived only in the
-- stopped process's memory: the git proxy session the sandbox's git presents,
-- the Kubernetes monitor session its kubectl presents, the egress proxy session
-- its HTTPS_PROXY names, and the slots that re-mint a GitHub App token before
-- GitHub's hour runs out. After a restart the device still held each session's
-- token and no process could authenticate it: the run's next fetch, push or
-- kubectl call got a 401, and a token file died at its hour.
--
-- A row in proxy_sessions is one minted session, written when it is minted and
-- kept in step when it is extended, checkpointed and closed. The process that
-- adopts the run takes the session over by moving `holder` to itself — a
-- conditional UPDATE, as secret_leases.holder is — and restores it into its own
-- registry under the same id, token hash, scope and expiry, with an upstream
-- credential it re-derives from the lease's grants.
--
-- Never a credential. What is stored is what the registries already keep in
-- memory instead of one: the SHA-256 of the bearer token a sandbox presents,
-- and the scope the session enforces. The upstream credential — the PAT, the
-- App installation token, the kubeconfig — is re-derived through the broker by
-- whoever restores the session; tests/security scans both tables for it.
--
--   kind          git | kube | egress.
--   session_id    the session's id, which the sandbox presents beside its
--                 token. Not secret: it is in every audit row the session
--                 produces.
--   token_sha256  hex SHA-256 of the bearer token the sandbox presents (git:
--                 the basic-auth password; kube: the whole "<id>.<secret>";
--                 egress: the proxy password). The token itself exists only in
--                 the sandbox.
--   lease_id      the secret lease whose grant the upstream credential came
--                 from (git, kube); '' for egress, whose grant is not a secret.
--   grant_id      the grant the session stands on — a secret grant for git and
--                 kube, an egress grant for egress.
--   holder        the hub process (cluster member id) serving the session.
--   run_id, project_id, executor_id, task_id, actor
--                 labels, the same the session's audit rows carry.
--   scope_json    what the session enforces: git — repository path or
--                 patterns, forge host, ref policy; kube — cluster URL, context,
--                 policy; egress — the grant snapshot and the requester it was
--                 issued to. Names, patterns and URLs only.
--   counters_json egress: the byte and request counters, checkpointed so a
--                 restored session keeps counting against its quota.
--   issued_at, expires_at, updated_at, closed_at
--                 RFC 3339 UTC; expires_at moves with an egress renewal.
--   close_reason  why the session ended; '' while it is open.
--
-- A row in app_token_slots is one GitHub App installation token a lease holds
-- (secretbroker apprefresh.go): the scope it was minted at — installation,
-- repository ids, the permissions asked for and the ones GitHub granted — so
-- the process that takes the lease over re-mints at that scope and never
-- wider, and keeps the token alive past GitHub's hour as the stopped process
-- would have. The token is never stored; token_expires_at is when the one the
-- workload or session holds stops working, and file_name is the lease file a
-- token delivered without the git proxy is rewritten in.
--
-- The leader's lease janitor retires rows of closed or lapsed sessions, and the
-- slots of a lease, along with the lease.
--
-- Additive in schema_compat.go's sense: a binary predating these tables
-- neither reads nor writes them, and keeps its sessions in memory as before.
CREATE TABLE IF NOT EXISTS proxy_sessions (
    kind          TEXT NOT NULL,
    session_id    TEXT NOT NULL,
    token_sha256  TEXT NOT NULL DEFAULT '',
    lease_id      TEXT NOT NULL DEFAULT '',
    grant_id      TEXT NOT NULL DEFAULT '',
    holder        TEXT NOT NULL DEFAULT '',
    run_id        TEXT NOT NULL DEFAULT '',
    project_id    TEXT NOT NULL DEFAULT '',
    executor_id   TEXT NOT NULL DEFAULT '',
    task_id       TEXT NOT NULL DEFAULT '',
    actor         TEXT NOT NULL DEFAULT '',
    scope_json    TEXT NOT NULL DEFAULT '{}',
    counters_json TEXT NOT NULL DEFAULT '{}',
    issued_at     TEXT NOT NULL DEFAULT '',
    expires_at    TEXT NOT NULL DEFAULT '',
    updated_at    TEXT NOT NULL DEFAULT '',
    closed_at     TEXT NOT NULL DEFAULT '',
    close_reason  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (kind, session_id)
);

-- "Which sessions does this lease feed" at adoption, and "which go with it"
-- when the lease is retired.
CREATE INDEX IF NOT EXISTS idx_proxy_sessions_lease ON proxy_sessions(lease_id);
-- An egress session belongs to a run rather than to a lease.
CREATE INDEX IF NOT EXISTS idx_proxy_sessions_run ON proxy_sessions(run_id);

CREATE TABLE IF NOT EXISTS app_token_slots (
    lease_id          TEXT NOT NULL,
    grant_id          TEXT NOT NULL,
    holder            TEXT NOT NULL DEFAULT '',
    secret_id         TEXT NOT NULL DEFAULT '',
    secret_name       TEXT NOT NULL DEFAULT '',
    scope_json        TEXT NOT NULL DEFAULT '{}',
    guarded           INTEGER NOT NULL DEFAULT 0,
    session_id        TEXT NOT NULL DEFAULT '',
    env_exported      INTEGER NOT NULL DEFAULT 0,
    file_name         TEXT NOT NULL DEFAULT '',
    token_expires_at  TEXT NOT NULL DEFAULT '',
    updated_at        TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (lease_id, grant_id)
);
