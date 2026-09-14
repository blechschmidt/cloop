-- 0037_secret_grant_requests: let a developer ask for access, and an operator
-- approve it, instead of pre-creating every grant (Task 20271).
--
-- pkg/secretbroker brokers all four resources the project goal names — GitHub
-- repositories, PATs, Kubernetes clusters and the hub's own egress — and it
-- brokers them in one direction only. Mint and Grant are gated on
-- authz.PermSecretGrant and there is nothing else: a developer who needs a
-- repository or a cluster has no in-product way to say so. Access is therefore
-- negotiated in a chat window and then hand-minted by whoever is around, which
-- is precisely how a standing, over-broad grant gets created — the person
-- minting it is guessing at a scope they were told once, and widening it is the
-- cheaper guess.
--
-- These two tables carry the request side of that conversation, so the ask, the
-- justification, the decision and the person who made it are one reviewable row
-- rather than scrollback.
--
-- # secret_grant_requests
--
-- One row per ask. The columns mirror secretbroker.GrantRequest deliberately:
-- an approval is not a new kind of authorisation, it is a stored GrantRequest
-- that a second person agreed to, and approval replays it through the same
-- Broker.Grant that `cloop secret grant` calls. Storing the request in the
-- shape the grant path consumes is what keeps that from drifting into a second,
-- subtly-different minting path — which would be the one place a scope check
-- could go missing.
--
--   state           pending | approved | denied | withdrawn | expired.
--                   Free text rather than a CHECK constraint: pkg/secretbroker
--                   owns the lifecycle and rejects unknown states at the door,
--                   and a CHECK here would be a second copy of that rule that
--                   can only ever disagree with the first.
--
--   expires_at      when the *request* lapses if nobody decides it. Distinct
--                   from grant_expires_at, which is when the credential the
--                   approval minted stops working. A request with no deadline
--                   sits pending forever and becomes the thing everyone
--                   approves in a batch six weeks later without rereading it.
--
--   ttl_seconds     the grant lifetime asked for. Stored as the request made
--                   it; the approval clamps it, and grant_expires_at records
--                   what was actually issued. Keeping both is what lets a
--                   reviewer see that an approver narrowed an ask rather than
--                   rubber-stamped it.
--
--   grant_id        the grant an approval produced, empty in every other
--                   state. It is the join back into broker_grants, and the
--                   reason an approved request can be followed all the way to
--                   the credential it authorised.
--
-- There is deliberately no payload column and no place one could go. A request
-- names a secret that already exists; it never carries material.
--
-- # secret_grant_request_uses
--
-- What the approval actually did. An approver's real question is not "was a
-- grant created" — they know, they created it — but "did anything use it, and
-- for what". broker_grants cannot answer that: a grant is an authorisation, and
-- an authorisation nothing ever redeemed looks identical to one that has been
-- feeding a workload for a week.
--
-- So each lease that materialises an approved grant records a row here. The
-- lease is issued before the workload is dispatched, so task_id is not known at
-- that moment and starts at 0; statedb.AttributeRequestUseTasks stamps it in
-- once a dispatched handle names both the lease and the task. A row whose
-- task_id is still 0 means a run-scoped lease (the hub leases per project run,
-- not per task) or a workload that had not started yet — never "no task ran",
-- which is why the column is not nullable and the distinction is documented
-- rather than encoded as NULL.
--
-- last_seen advances on every renewal, so the pair (first_seen, last_seen)
-- bounds how long the credential was actually held — the number an approver
-- needs when deciding whether the next request from the same person should be
-- narrower.
--
-- # Compatibility
--
-- Additive, and it has to be: :8080 and :8888 share one control-plane database
-- and a breaking migration blanks whichever hub is older until the nightly
-- rebuild. Both statements are CREATE TABLE plus non-unique CREATE INDEX over
-- tables this migration itself creates, which is what statedb's classifier
-- (schema_compat.go) recognises as tolerable to a binary that predates it. An
-- older hub has no statement that names either table.

CREATE TABLE IF NOT EXISTS secret_grant_requests (
    id               TEXT PRIMARY KEY,
    requested_by     TEXT    NOT NULL,
    secret_id        TEXT    NOT NULL,
    secret_name      TEXT    NOT NULL DEFAULT '',
    kind             TEXT    NOT NULL DEFAULT '',
    subject_type     TEXT    NOT NULL DEFAULT '',
    subject_value    TEXT    NOT NULL DEFAULT '',
    scope            TEXT    NOT NULL DEFAULT '',
    constraints_json TEXT    NOT NULL DEFAULT '{}',
    ttl_seconds      INTEGER NOT NULL DEFAULT 0,
    justification    TEXT    NOT NULL DEFAULT '',
    state            TEXT    NOT NULL DEFAULT 'pending',
    created_at       TEXT    NOT NULL DEFAULT '',
    expires_at       TEXT    NOT NULL DEFAULT '',
    decided_by       TEXT    NOT NULL DEFAULT '',
    decided_at       TEXT    NOT NULL DEFAULT '',
    decision_note    TEXT    NOT NULL DEFAULT '',
    grant_id         TEXT    NOT NULL DEFAULT '',
    grant_expires_at TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_secret_grant_requests_state
    ON secret_grant_requests(state, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_secret_grant_requests_requester
    ON secret_grant_requests(requested_by, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_secret_grant_requests_grant
    ON secret_grant_requests(grant_id);

CREATE TABLE IF NOT EXISTS secret_grant_request_uses (
    request_id   TEXT    NOT NULL,
    lease_id     TEXT    NOT NULL,
    grant_id     TEXT    NOT NULL DEFAULT '',
    executor_id  TEXT    NOT NULL DEFAULT '',
    project_path TEXT    NOT NULL DEFAULT '',
    task_id      INTEGER NOT NULL DEFAULT 0,
    first_seen   TEXT    NOT NULL DEFAULT '',
    last_seen    TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (request_id, lease_id)
);

CREATE INDEX IF NOT EXISTS idx_secret_grant_request_uses_lease
    ON secret_grant_request_uses(lease_id);
