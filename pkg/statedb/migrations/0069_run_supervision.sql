-- 0069_run_supervision: a lease revocation outlives the hub process holding
-- the lease, and a dispatch is on record before its workload exists (Task
-- 20419).
--
-- secret_lease_revocations — every lease an operator (or the hub, on cordon)
-- revoked, kept beside the lease record rather than in it.
--
-- A revocation used to be a fan-out and nothing else: each live hub member
-- took the lease back from what it held, and the request answered 404 when
-- none of them held it. A lease whose holder member had died was held by
-- nobody until another member adopted its run — and that member then took
-- the lease over and restored the git proxy and Kubernetes monitor sessions it
-- fed, because nothing recorded that an incident responder had revoked it in
-- between. A row here is that record. The broker refuses to hand a revoked
-- lease to a new holder (secretbroker.Broker.Restore), a member adopting the
-- run takes the material back instead, and the lease janitor enforces a
-- revocation its holder did not hear about. The row outlives the lease record
-- on purpose: a lease retired while its revocation was pending is still one a
-- member reaching its workload must take back.
--
--   lease_id, grant_id   the lease, and the one grant of it the revocation
--                        names — '' for the whole lease.
--   action               scrub or kill, as the operator asked.
--   reason, actor        why, and who: what the holders and the trail are told.
--   executor_id, project_id
--                        who the lease was issued to, for the panel.
--   holder               the hub member that held the lease when it was
--                        revoked, '' when none did.
--   revoked_at           RFC 3339 UTC, the first revocation.
--   enforced_at, enforced_by
--                        when, and by which member, the material was found
--                        taken back from every holder; '' while pending.
--   detail               the last account of why it is still pending.
--
-- dispatch_intents — a workload a hub process is starting, recorded before it
-- exists.
--
-- A member that died between creating a workload and recording its run left
-- a claim marked "dispatching" that the leader cleared, so the project could
-- be started again beside a workload whose lease nobody kept or revoked. The
-- intent is written before the executor is asked to start anything, completed
-- with the handle once it has one, and deleted once the run is on record —
-- or when the workload ends. An intent whose member is gone names a workload
-- nobody supervises, and the member that can reach its executor stops it and
-- takes its credentials back.
--
--   run_id        the execution id the hub minted for the dispatch, which the
--                 workload carries (a container's cloop.spec.run_id label).
--   instance_id   the hub member dispatching it.
--   executor_id, driver, project_path
--                 where, by which driver, and for which project.
--   handle_id     the workload's handle once the executor returned one.
--   lease_ids, egress_ids
--                 JSON arrays: the credential leases and egress sessions the
--                 workload was given, taken back if it is reaped.
--   state         'dispatching' until the executor answered, then 'started'.
--   created_at, updated_at
--                 RFC 3339 UTC.
--   detail        why a reap has not finished, for the operator.
--
-- Additive (schema_compat.go): two new tables. A hub built before this ignores
-- both, revokes as it always did, and dispatches without an intent.

CREATE TABLE IF NOT EXISTS secret_lease_revocations (
    lease_id    TEXT NOT NULL,
    grant_id    TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL DEFAULT 'scrub',
    reason      TEXT NOT NULL DEFAULT '',
    actor       TEXT NOT NULL DEFAULT '',
    executor_id TEXT NOT NULL DEFAULT '',
    project_id  TEXT NOT NULL DEFAULT '',
    holder      TEXT NOT NULL DEFAULT '',
    revoked_at  TEXT NOT NULL DEFAULT '',
    enforced_at TEXT NOT NULL DEFAULT '',
    enforced_by TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (lease_id, grant_id)
);

-- The janitor's question: which revocations are still pending.
CREATE INDEX IF NOT EXISTS idx_secret_lease_revocations_enforced ON secret_lease_revocations(enforced_at);

CREATE TABLE IF NOT EXISTS dispatch_intents (
    run_id       TEXT PRIMARY KEY,
    instance_id  TEXT NOT NULL DEFAULT '',
    executor_id  TEXT NOT NULL DEFAULT '',
    driver       TEXT NOT NULL DEFAULT '',
    project_path TEXT NOT NULL DEFAULT '',
    handle_id    TEXT NOT NULL DEFAULT '',
    lease_ids    TEXT NOT NULL DEFAULT '[]',
    egress_ids   TEXT NOT NULL DEFAULT '[]',
    state        TEXT NOT NULL DEFAULT 'dispatching',
    created_at   TEXT NOT NULL DEFAULT '',
    updated_at   TEXT NOT NULL DEFAULT '',
    detail       TEXT NOT NULL DEFAULT ''
);

-- "What did this member have in flight" when it dies, and the lookup a run's
-- record makes to retire its intent.
CREATE INDEX IF NOT EXISTS idx_dispatch_intents_instance ON dispatch_intents(instance_id);
CREATE INDEX IF NOT EXISTS idx_dispatch_intents_handle ON dispatch_intents(executor_id, handle_id);
