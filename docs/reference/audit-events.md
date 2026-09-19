# Audit event reference

Every action name cloop writes to the `event_type` column of
`audit_events`, generated from the registry the emitters reference. Do not
edit this file: it is rendered by `tests/docs/audit_events_test.go` from
`pkg/auditaction`, and a CI check fails when it stops matching. Regenerate
with `make docs-audit`.

For what the trail is and how it is protected see the
[security model](../security/model.md); for the endpoints that read it see the
[HTTP API reference](http-api.md).

## How to read this

`audit_events` is cloop's legal record: one append-only, hash-chained row per
mutation that actually changed something. It is distinct from the `events`
table, which is a UI journal that may be lossy and is prunable at will. A row
carries an actor, an action, an entity type and id, and a JSON payload.

The **action** is the value of `event_type`. It is the field a detection rule
keys on, and it is stable: a name in this list will not be renamed, because
renaming it would orphan rows already sealed into a chain that cannot be
rewritten. A superseded action is marked deprecated here and keeps being
emitted until retention has passed over the last row carrying it.

The **entity** is the value of `entity_type`, and it says which id space
`entity_id` is in. Filtering a subject's whole history means filtering on
both.

**Payload keys are conditional.** An emitter omits what it does not know, so
the keys listed for an action are what a consumer may expect to see, not what
every row carries. New keys may be added to a stable action without notice — a
consumer must tolerate that — but no listed key is removed or repurposed.

**Stability** is a contract with consumers, not a measure of code quality:

| Marker | Means |
| --- | --- |
| `stable` | Safe to key a paging alert on. The name and the listed payload keys will not change. |
| `beta` | The rows are real, but the name or payload may still change while the surface emitting them settles. Key a dashboard on it, not a pager. |
| `deprecated` | Still emitted, replaced by something else. The note says by what. |

### Exporting

`cloop audit export` writes these rows as JSONL or CEF for a SIEM, and
`cloop audit verify` checks the hash chain. Both are documented under
[commands](commands.md). Note that the trail exists per project *and* in the
control plane, with separate chains — a row emitted to one is not visible in
the other.

## Who may read these

Reading all 112 of the actions below requires the `audit.read` permission, held by `admin`.

The trail is one table behind one pair of admin-only endpoints, so the
permission does not vary by action today. It is recorded per action anyway,
because the day one family needs narrower reads than the rest, the registry
has to be able to say so without a schema change — and because a reader is
better served by a column that says "the same everywhere" than by prose that
leaves them guessing whether it varies.

## Which database an action is recorded in

`audit_events` is not one table. It exists in the hub's own control-plane
`state.db` and in every project's `.cloop/state.db`, and **each copy carries its
own independent hash chain**. A row does not say which database it came from, so
verifying one chain proves nothing about the other: both stay internally
consistent whether or not an event landed in the right one.

This matters when answering a question about one project. The plan's own life is
in the project's chain; the executor that ran it, the image policy that admitted
it, the workspace that was fetched for it and the credentials it held are in the
hub's. Use `cloop hub audit list` to read both at once — it labels every row with
its source — and `cloop hub audit verify` to verify both chains rather than
whichever one happened to be opened.

| Home | Meaning | Actions |
| --- | --- | --- |
| `control-plane` | the hub's own state.db | 100 |
| `project` | the project's .cloop/state.db | 10 |
| `either` | whichever chain the decision was scoped to | 2 |

Recorded in the project's .cloop/state.db: `config.set`, `run.cap_paused`, `run.cap_resumed`, `state.save`, `step.append`, `task.delete`, `task.dispatch`, `task.finish`, `task.status`, `task.upsert`.

Recorded in whichever chain the decision was scoped to: `authz.denied`, `authz.granted`.

Everything else is recorded in the hub's own state.db.

## Actions by family

112 actions in 32 families. Every action is listed: this section is the whole
vocabulary of the `event_type` column.

[`task.*`](#task) (5) · [`run.*`](#run) (2) · [`step.*`](#step) (1) · [`state.*`](#state) (1) · [`config.*`](#config) (1) · [`executor.*`](#executor) (10) · [`workspace.*`](#workspace) (2) · [`sandbox.*`](#sandbox) (1) · [`sandbox.attach.*`](#sandboxattach) (3) · [`secret.*`](#secret) (13) · [`secret.lease.*`](#secretlease) (1) · [`lease.*`](#lease) (3) · [`github_app.*`](#github_app) (1) · [`egress.*`](#egress) (6) · [`gitproxy.*`](#gitproxy) (6) · [`kubeguard.*`](#kubeguard) (5) · [`ci.*`](#ci) (1) · [`ci.session.*`](#cisession) (3) · [`ci.exchange.*`](#ciexchange) (2) · [`ci.relay.*`](#cirelay) (2) · [`ci.rule.*`](#cirule) (3) · [`ci.config.*`](#ciconfig) (1) · [`authz.*`](#authz) (2) · [`api_token.*`](#api_token) (4) · [`session.*`](#session) (8) · [`role_binding.*`](#role_binding) (3) · [`quota.*`](#quota) (4) · [`resource_ceiling.*`](#resource_ceiling) (2) · [`sealing_key.*`](#sealing_key) (2) · [`stt.credential.*`](#sttcredential) (2) · [`user.*`](#user) (9) · [`project.member.*`](#projectmember) (3)

### task.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `task.delete` | `task` | project | stable | A task disappears from the plan between two saves, or is deleted outright. |
| `task.dispatch` | `task` | project | stable | A task is handed to an executor, recording where it will run and what it was given. |
| `task.finish` | `task` | project | stable | A dispatched task reaches a terminal outcome — done, failed, skipped, timed out, or aborted. |
| `task.status` | `task` | project | stable | Somebody flips a task's status by hand, rather than the orchestrator moving it. |
| `task.upsert` | `task` | project | stable | A task is created, or a saved task's audited fields differ from the ones already stored. |

Payload keys:

- `task.delete` — `id`
- `task.dispatch` — `task_id`, `title`, `project`, `run_id`, `executor_id`, `executor_kind`, `isolation`, `requested_image`, `pinned_image`, `spec_sha256`, `setup_sha256`, `lease_ids`
- `task.finish` — `task_id`, `outcome`, `title`, `project`, `run_id`, `executor_id`, `executor_kind`, `isolation`, `reason`, `started_at`, `completed_at`, `duration_ms`, `abort_class`, `abort_cleared`, `fail_count`, `write_back_commit`
- `task.status` — `id`, `old_status`, `new_status`
- `task.upsert` — `id`, `title`, `status`, `priority`, `role`, `description`

- `task.dispatch` — This and task.finish are what make "where did this task run, and what credentials did it hold" answerable from audit_events alone, without joining the executor tables.
- `task.finish` — `outcome` carries the terminal status; `reason` carries why, when there is one.
- `task.upsert` — Emitted from the diff SaveState computes inside its own transaction, not from the plan — a byte-identical re-save produces no row. Before that diff existed this action was 99.7% of a 1.09M-row table.

### run.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `run.cap_paused` | `plan` | project | stable | A Claude Code subscription cap stops the run before it dispatches its next task. |
| `run.cap_resumed` | `plan` | project | stable | The hub restarts a cap-paused run after its window rolled over, without a human. |

Payload keys:

- `run.cap_paused` — `project`, `windows`, `utilization`, `cap`, `resumes_at`, `detail`
- `run.cap_resumed` — `project`, `paused_detail`, `resumes_at`, `resumed_at`

- `run.cap_paused` — Distinct from state.save's bare "paused" status because a cap is the one pause that ends by itself: `resumes_at` is the window's reset from the OAuth usage API, and it is what run.cap_resumed is later matched against.
- `run.cap_resumed` — The only action recording work that a machine started on its own initiative, so "who restarted this project" stays answerable from the trail alone.

### step.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `step.append` | `step` | project | stable | One execution step finishes and its transcript is appended to the run. |

Payload keys, on every action above: `step`, `task`, `exit_code`, `duration`, `time`, `input_tokens`, `output_tokens`

### state.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `state.save` | `plan` | project | stable | The project's plan-level state is written: goal, run status, counters, and the mode flags in force. |

Payload keys, on every action above: `goal`, `status`, `current_step`, `evolve_step`, `plan_version`, `task_count`, `total_input_tokens`, `total_output_tokens`, `auto_evolve`, `innovate_mode`, `parallel`, `max_parallel`, `pause_code`, `pause_detail`, `pause_resumes_at`

- `state.save` — The `pause_*` keys appear only when `status` is `paused`, and are what make an approval gate distinguishable from a spent budget or an exhausted usage window — before them all ~26 pause conditions recorded the same word.

### config.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `config.set` | `config` | project | stable | A configuration write lands, from the Settings panel, the CLI, or config validation repair. |

Payload keys, on every action above: `yaml`

- `config.set` — `yaml` is the post-write document with secret-shaped values redacted, not a diff.

### executor.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `executor.bind` | `executor` | control-plane | stable | A project is pinned to one executor, at creation time or from the Executors panel. |
| `executor.cordon` | `executor` | control-plane | stable | An executor is marked to refuse new work while finishing what it holds. |
| `executor.drain` | `executor` | control-plane | stable | An executor is set to shed in-flight work as well as refuse new work. |
| `executor.enroll` | `executor` | control-plane | stable | A remote agent completes outbound enrolment and joins the fleet. |
| `executor.failover` | `executor_session` | control-plane | stable | A session is moved off an executor that stopped answering, or fails to be placed anywhere. |
| `executor.revoke` | `executor` | control-plane | stable | An enrolled agent's credential is revoked and it is removed from the fleet. |
| `executor.sandbox` | `executor` | control-plane | stable | An admin sets where an executor's payloads run: the device's host, or a container on it. |
| `executor.state_change` | `executor` | control-plane | stable | Liveness tracking moves an executor between health states without an operator asking. |
| `executor.unbind` | `executor` | control-plane | stable | A project's executor pin is cleared and it falls back to registry placement. |
| `executor.uncordon` | `executor` | control-plane | stable | A cordoned executor is returned to normal scheduling. |

Payload keys:

- `executor.bind` — `action`, `executor_id`, `project`, `project_path`, `kind`, `via`
- `executor.cordon` — `action`, `executor_id`, `reason`, `state`
- `executor.drain` — `action`, `executor_id`, `reason`, `state`
- `executor.enroll` — `action`, `executor_id`, `name`, `expires_at`, `workdir_root`, `labels`
- `executor.failover` — `session_id`, `from`, `to`, `attempt`, `project_path`, `task_id`, `placed`, `error`
- `executor.revoke` — `action`, `executor_id`, `name`, `kind`
- `executor.sandbox` — `action`, `executor_id`, `from`, `to`, `mode`, `cleared`
- `executor.state_change` — `from`, `to`, `reason`
- `executor.unbind` — `action`, `project`, `project_path`
- `executor.uncordon` — `action`, `executor_id`, `state`

- `executor.bind` — Where a project's code runs is the most consequential setting on the hub, which is why the creation-dialog path emits this too.
- `executor.enroll` — `action` repeats the verb without the family prefix — `enroll`, not `executor.enroll`.
- `executor.failover` — `placed` distinguishes a successful move from an exhausted one; on failure `to` is empty and `error` says why.
- `executor.sandbox` — The only executor action that records its previous value: it changes a containment boundary, so `from` is what makes "when did this device stop isolating its workloads" answerable from the trail alone. `cleared` is true when the configuration was removed rather than replaced.

### workspace.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `workspace.provision_end` | `project` | control-plane | stable | Workspace provisioning finishes, successfully or not. |
| `workspace.provision_start` | `project` | control-plane | stable | An executor begins materialising a project's source tree, before the harness starts. |

Payload keys:

- `workspace.provision_end` — `phase`, `project`, `executor_id`, `executor_kind`, `handle_id`, `kind`, `repo`, `ref`, `depth`, `grant_id`, `lease_id`, `duration_ms`, `error`
- `workspace.provision_start` — `phase`, `project`, `executor_id`, `executor_kind`, `handle_id`, `kind`, `repo`, `ref`, `depth`, `grant_id`, `lease_id`

- `workspace.provision_end` — A row with no `error` is the success case; there is no separate failure action.
- `workspace.provision_start` — `depth` is the shallow-fetch depth, or the string `full` when the spec asked for whole history.

### sandbox.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `sandbox.image_denied` | `project` | control-plane | stable | Image trust policy refuses a container image a project asked to run. |

Payload keys, on every action above: `image`, `rule`, `reason`, `registry`, `repository`, `project`

- `sandbox.image_denied` — The one sandbox placement decision worth a permanent row: the others record a project asking for less than it could have, this one records it asking to execute code from somewhere the operator does not trust.

### sandbox.attach.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `sandbox.attach.close` | `sandbox_session` | control-plane | stable | An attached session ends, by the caller leaving or the sandbox going away. |
| `sandbox.attach.denied` | `sandbox_session` | control-plane | stable | An attach request is refused, by permission, by scope, or because the target is not running. |
| `sandbox.attach.open` | `sandbox_session` | control-plane | stable | A caller is admitted to a shell inside a running task's sandbox. |

Payload keys:

- `sandbox.attach.close` — `session_id`, `writable`, `executor_id`, `handle_id`, `task_id`, `command`, `detail`
- `sandbox.attach.denied` — `session_id`, `writable`, `executor_id`, `handle_id`, `task_id`, `command`, `detail`
- `sandbox.attach.open` — `session_id`, `writable`, `executor_id`, `handle_id`, `task_id`, `command`

- `sandbox.attach.open` — `writable` records whether the second, narrower `sandbox.attach.write` permission was exercised.

### secret.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `secret.access_check` | `secret` | control-plane | stable | A repository or cluster access decision is evaluated against a grant's constraints. |
| `secret.delete` | `secret` | control-plane | stable | A secret is destroyed and every grant depending on it is revoked with it. |
| `secret.grant` | `secret` | control-plane | stable | A grant is written authorising a subject to lease a secret. |
| `secret.lease` | `secret` | control-plane | stable | A lease is issued — or refused — against the grants matching a request. |
| `secret.mint` | `secret` | control-plane | stable | A credential is sealed and stored as a new secret. |
| `secret.release` | `secret` | control-plane | stable | A workload finishes with a lease and it is dropped from the server-side record. |
| `secret.renew` | `secret` | control-plane | stable | A live lease is re-issued to the same holder before it expires. |
| `secret.request` | `secret` | control-plane | stable | A developer files a self-service request for access they do not have. |
| `secret.request_approve` | `secret` | control-plane | stable | A reviewer approves a pending request and the grant it asked for is minted. |
| `secret.request_deny` | `secret` | control-plane | stable | A reviewer refuses a pending request. |
| `secret.request_expire` | `secret` | control-plane | stable | A pending request lapses with nobody having decided it. |
| `secret.request_withdraw` | `secret` | control-plane | stable | A requester withdraws their own pending request. |
| `secret.revoke` | `secret` | control-plane | stable | An operator marks a grant unusable. |

Payload keys, on every action above: `decision`, `subject`, `secret_id`, `secret_name`, `kind`, `grant_id`, `request_id`, `lease_id`, `executor_id`, `project_id`, `run_id`, `constraints`, `reason`, `task_id`, `host`, `port`, `bytes_up`, `bytes_down`, `expires_at`

- `secret.grant` — This is the row that answers "what authority exists"; the request family answers "who asked for it".
- `secret.lease` — `decision` is `allow` or `deny` on every action in this family; a denial is a row, not a missing one.
- `secret.release` — An ordinary end of life. Compare the lease.revoke_* family, which is somebody deciding mid-run that a holder may no longer hold it.
- `secret.request` — The gap between this row and its approval is the number that says whether the request path is used or routed around.
- `secret.request_expire` — Its own action rather than a flavour of deny: denied is an answer, expired is the absence of one, and conflating them hides a queue nobody is working.

### secret.lease.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `secret.lease.sweep` | `secret` | control-plane | stable | The periodic sweeper reaps leases whose TTL has passed. |

Payload keys, on every action above: `decision`, `wiped`, `vanished`, `skipped`, `failed`, `expired`

- `secret.lease.sweep` — One row per sweep, not per lease — the counts are the point.

### lease.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `lease.revoke_acked` | `lease` | control-plane | stable | An executor confirms it destroyed the material for a revoked lease. |
| `lease.revoke_failed` | `lease` | control-plane | stable | A revocation fails to land on an executor that still holds the credential. |
| `lease.revoke_sent` | `lease` | control-plane | stable | A revocation is queued for delivery to the executors holding a lease. |

Payload keys:

- `lease.revoke_acked` — `decision`, `lease_id`, `grant_id`, `executor_id`, `project_id`, `action`, `state`, `env_scrubbed`, `files_removed`, `reason`
- `lease.revoke_failed` — `decision`, `lease_id`, `grant_id`, `executor_id`, `project_id`, `action`, `state`, `error`, `reason`
- `lease.revoke_sent` — `decision`, `lease_id`, `grant_id`, `executor_id`, `project_id`, `action`, `secrets`, `holders`, `reason`

- `lease.revoke_failed` — The row an incident response cares about: the credential is still out there.

### github_app.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `github_app.token_destroy` | `secret` | control-plane | stable | A GitHub App installation token is deleted at GitHub. |

Payload keys, on every action above: `decision`, `subject`, `secret_id`, `secret_name`, `kind`, `grant_id`, `request_id`, `lease_id`, `executor_id`, `project_id`, `run_id`, `constraints`, `reason`, `task_id`, `host`, `port`, `bytes_up`, `bytes_down`, `expires_at`

- `github_app.token_destroy` — Deliberately not secret.revoke: a github_app token is destroyed on every ordinary lease release, so folding these in would make "how many grants did an operator withdraw" a number dominated by routine teardown.

### egress.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `egress.close` | `secret` | control-plane | stable | An egress proxy session closes, carrying the bytes it moved in each direction. |
| `egress.connect` | `secret` | control-plane | stable | A sandbox's connection attempt is evaluated against the session's host allowlist. |
| `egress.grant` | `secret` | control-plane | stable | A subject is authorised to reach the network through the hub's egress proxy. |
| `egress.redeem` | `secret` | control-plane | stable | A proxy session is minted against a matching egress grant. |
| `egress.request` | `secret` | control-plane | stable | An HTTP request passes through the egress proxy. |
| `egress.revoke` | `secret` | control-plane | stable | An egress authorisation is marked unusable. |

Payload keys, on every action above: `decision`, `subject`, `secret_id`, `secret_name`, `kind`, `grant_id`, `request_id`, `lease_id`, `executor_id`, `project_id`, `run_id`, `constraints`, `reason`, `task_id`, `host`, `port`, `bytes_up`, `bytes_down`, `expires_at`

- `egress.connect` — `host` and `port` name the attempted destination; `decision` says whether it was reached.

### gitproxy.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `gitproxy.fetch` | `gitproxy` | control-plane | stable | A read passes through the proxy. |
| `gitproxy.push_allowed` | `gitproxy` | control-plane | stable | A push is checked against the session's branch allowlist and forwarded. |
| `gitproxy.push_denied` | `gitproxy` | control-plane | stable | A push is refused because it names a ref the session may not write. |
| `gitproxy.rejected` | `gitproxy` | control-plane | stable | A request is refused before any policy could be evaluated — no session, bad credential, unknown repository. |
| `gitproxy.session_closed` | `gitproxy` | control-plane | stable | A proxy session ends and its credential stops working. |
| `gitproxy.session_minted` | `gitproxy` | control-plane | stable | A proxy session is created for a task, scoping which repository and refs it may touch. |

Payload keys, on every action above: `kind`, `session_id`, `repo`, `project_id`, `task_id`, `refs`, `detail`

- `gitproxy.push_denied` — The row that matters in this family: it is the only place a sandbox's attempt to write outside its lane is recorded. `refs` names what it tried to push.

### kubeguard.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `kubeguard.rejected` | `kubeguard` | control-plane | stable | A request is refused before its session could be identified. |
| `kubeguard.request_allowed` | `kubeguard` | control-plane | stable | A Kubernetes request is admitted by policy. |
| `kubeguard.request_denied` | `kubeguard` | control-plane | stable | A Kubernetes request is refused by the session's verb and resource policy. |
| `kubeguard.session_closed` | `kubeguard` | control-plane | stable | A Kubernetes proxy session ends. |
| `kubeguard.session_minted` | `kubeguard` | control-plane | stable | A Kubernetes proxy session is created for a task against one cluster and context. |

Payload keys, on every action above: `kind`, `session_id`, `cluster`, `context`, `verb`, `resource`, `namespace`, `object`, `reason`, `project_id`, `task_id`, `executor_id`, `grant_id`, `lease_id`, `detail`

- `kubeguard.request_allowed` — Sampled rather than exhaustive — a watch against a busy cluster would otherwise be the whole table.
- `kubeguard.request_denied` — This is what enforces a read-only grant on a cluster from outside the sandbox: `verb`, `resource` and `namespace` say exactly what was attempted.

### ci.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `ci.rejected` | `ci_session` | control-plane | beta | A relay request is refused before a session could be established. |

Payload keys, on every action above: `kind`, `session_id`, `rule_id`, `rule_name`, `project`, `subject`, `repository`, `ref`, `workflow`, `actor`, `run_id`, `method`, `path`, `model`, `status`, `reason`, `input_tokens`, `output_tokens`, `detail`, `at`

### ci.session.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `ci.session.closed` | `ci_session` | control-plane | beta | A relay session ends, by expiry or by revocation. |
| `ci.session.minted` | `ci_session` | control-plane | beta | A pipeline's OIDC token matches an allowlist rule and a relay session is issued. |
| `ci.session.revoked` | `ci_rule` | control-plane | beta | An operator revokes a live relay session from the CI panel. |

Payload keys:

- `ci.session.closed` — `kind`, `session_id`, `rule_id`, `rule_name`, `project`, `subject`, `repository`, `ref`, `workflow`, `actor`, `run_id`, `method`, `path`, `model`, `status`, `reason`, `input_tokens`, `output_tokens`, `detail`, `at`
- `ci.session.minted` — `kind`, `session_id`, `rule_id`, `rule_name`, `project`, `subject`, `repository`, `ref`, `workflow`, `actor`, `run_id`, `method`, `path`, `model`, `status`, `reason`, `input_tokens`, `output_tokens`, `detail`, `at`
- `ci.session.revoked` — `rule_id`, `rule_name`, `repository`, `ref`, `condition`, `models`, `detail`, `error`

### ci.exchange.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `ci.exchange.accepted` | `ci_session` | control-plane | beta | A pipeline's OIDC token is verified and exchanged for relay credentials. |
| `ci.exchange.rejected` | `ci_session` | control-plane | beta | A token exchange fails: bad signature, wrong issuer, or no rule admits the claims. |

Payload keys, on every action above: `kind`, `session_id`, `rule_id`, `rule_name`, `project`, `subject`, `repository`, `ref`, `workflow`, `actor`, `run_id`, `method`, `path`, `model`, `status`, `reason`, `input_tokens`, `output_tokens`, `detail`, `at`

- `ci.exchange.rejected` — The row to alert on. A pipeline that should be admitted and is not looks identical here to one that should never have asked.

### ci.relay.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `ci.relay.allowed` | `ci_session` | control-plane | beta | A relayed API call is forwarded upstream on a live session. |
| `ci.relay.denied` | `ci_session` | control-plane | beta | A relayed API call is refused — expired session, unsupported path, or a quota. |

Payload keys, on every action above: `kind`, `session_id`, `rule_id`, `rule_name`, `project`, `subject`, `repository`, `ref`, `workflow`, `actor`, `run_id`, `method`, `path`, `model`, `status`, `reason`, `input_tokens`, `output_tokens`, `detail`, `at`

### ci.rule.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `ci.rule.created` | `ci_rule` | control-plane | beta | An allowlist rule is added, widening which pipelines may authenticate. |
| `ci.rule.deleted` | `ci_rule` | control-plane | beta | An allowlist rule is removed. |
| `ci.rule.updated` | `ci_rule` | control-plane | beta | An allowlist rule is edited; live sessions it no longer admits are revoked in the same operation. |

Payload keys, on every action above: `rule_id`, `rule_name`, `repository`, `ref`, `condition`, `models`, `detail`, `error`

- `ci.rule.created` — `match` is the CEL expression the rule admits on. Rules are the CI surface's whole access-control policy, so these three rows are its change log.

### ci.config.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `ci.config.updated` | `ci_rule` | control-plane | beta | The CI relay's own settings change — whether it is enabled, its issuer, its session ceiling. |

Payload keys, on every action above: `rule_id`, `rule_name`, `repository`, `ref`, `condition`, `models`, `detail`, `error`

### authz.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `authz.denied` | `permission` | either | stable | Any permission check refuses a caller. |
| `authz.granted` | `permission` | either | stable | A privileged permission is exercised successfully. |

Payload keys, on every action above: `outcome`, `permission`, `role`, `source`, `scope`, `subject`, `method`, `path`, `binding`

- `authz.denied` — Every denial, unlike the grant side. `scope` says whether the check was fleet-wide or against one project; `binding` names the runtime rule when one decided it. Neither action in this family is emitted when RBAC is not in force for the caller — with no identity provider configured every request is granted everything and there is no decision to record, so an absence of rows here means "nobody was refused" only on a hub that has SSO or API tokens. Project-scoped decisions land in that project's trail rather than the control plane's.
- `authz.granted` — Not every allow: ordinary reads would drown the table, so only privileged permissions are recorded on this side. Home varies with scope — a check against a project lands in that project's chain, a fleet-wide one in the hub's — so answering "what was this subject allowed to do" needs both.

### api_token.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `api_token.auth_failed` | `api_token` | control-plane | stable | A request presents a token that does not authenticate: unknown, revoked, or expired. |
| `api_token.create_denied` | `api_token` | control-plane | stable | A token mint is refused because it would grant more than the caller holds. |
| `api_token.created` | `api_token` | control-plane | stable | A scoped API token or a display-glasses link is minted, from the UI or the CLI. |
| `api_token.revoked` | `api_token` | control-plane | stable | A token or glasses link is revoked, or rotated — a rotation revokes the old one. |

Payload keys:

- `api_token.auth_failed` — `reason`, `ip`, `method`, `path`
- `api_token.create_denied` — `reason`, `roles`, `project_scope`
- `api_token.created` — `name`, `roles`, `project_scope`, `expires_at`, `kind`, `owner`
- `api_token.revoked` — `name`, `roles`, `reason`

- `api_token.auth_failed` — Filed against the token's *public* id (`cloop_pat_<id>`), never the secret half, and against `(unparseable)` when the credential is not even shaped like a token — so a garbage value is not echoed back into the trail. Rate of this action by `ip` is the credential-stuffing signal.
- `api_token.create_denied` — The anti-escalation check. A maintainer trying to mint an admin token lands here.
- `api_token.created` — `kind` distinguishes a service-account token from a glasses link, which is a token with one narrow role and a URL as its only delivery mechanism.

### session.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `session.claims_rejected` | `session` | control-plane | stable | The IdP answers the re-assertion by refusing the claims outright. |
| `session.claims_stale` | `session` | control-plane | stable | A privileged operation is blocked because the session's claims are older than the freshness bound allows. |
| `session.claims_unverified` | `session` | control-plane | stable | The hub cannot reach the IdP to re-assert a session's claims. |
| `session.created` | `session` | control-plane | stable | A sign-in completes and a durable session is written. |
| `session.expired` | `session` | control-plane | stable | The session janitor removes a session past its absolute or idle deadline. |
| `session.idp_revoked` | `session` | control-plane | stable | The identity provider reports the authorisation behind a session is gone. |
| `session.revoked` | `session` | control-plane | stable | A user logs out, or an operator terminates a session from the UI or the CLI. |
| `session.role_narrowed` | `session` | control-plane | stable | A re-assertion finds the session's claims now map to a lower role than it held. |

Payload keys, on every action above: `event`, `session_id`, `subject`, `email`, `actor`, `reason`, `ip`, `user_agent`, `prior_role`, `role`, `dropped_claims`, `issued_at`, `selector`, `selected`, `via`, `os_user`

- `session.claims_stale` — A block, not a revocation: the session stays, and ordinary reads keep working.
- `session.role_narrowed` — `prior_role` and `role` bracket the demotion; `dropped_claims` names what the IdP stopped asserting.

### role_binding.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `role_binding.deleted` | `role_binding` | control-plane | stable | A runtime binding is removed and the identity falls back to its configured role. |
| `role_binding.denied` | `role_binding` | control-plane | stable | A runtime deny binding is written, demoting an identity ahead of the IdP catching up. |
| `role_binding.granted` | `role_binding` | control-plane | stable | A runtime binding is written mapping a claim to a role, without an IdP or config change. |

Payload keys, on every action above: `id`, `effect`, `claim`, `value`, `role`, `project`, `executor`, `binding_reason`, `created_at`, `created_by`, `reason`, `via`, `os_user`

- `role_binding.denied` — The incident-response verb: it takes authority away now, from a CLI, without a browser.

### quota.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `quota.denied` | `quota` | control-plane | stable | Admission control refuses an operation because the caller is at a resource ceiling. |
| `quota.override_cleared` | `quota` | control-plane | stable | A per-identity override is removed and the identity returns to the default ceiling. |
| `quota.override_set` | `quota` | control-plane | stable | A per-identity quota override is written, from the UI or the CLI. |
| `quota.spend_refused` | `project` | control-plane | stable | A run is stopped between tasks because the identity paying for it is over its spend limit. |

Payload keys:

- `quota.denied` — `limit`, `used`, `requested`, `source`, `transient`, `method`, `path`
- `quota.override_cleared` — `target`, `identity`, `cleared_limits`, `reason`, `via`, `os_user`
- `quota.override_set` — `target`, `identity`, `limits`, `unset`, `reason`, `via`, `os_user`
- `quota.spend_refused` — `identity`, `resource`, `limit`, `used`, `source`, `project`, `outcome`

- `quota.denied` — The identity is the row's actor and the resource is its entity id, so neither repeats in the payload.
- `quota.override_set` — Two emitters with different shapes: the UI writes `target` plus one key per resource, the CLI writes `identity` with the limits nested under `limits`.
- `quota.spend_refused` — Enforced between tasks, not mid-task: a task already running is allowed to finish.

### resource_ceiling.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `resource_ceiling.cleared` | `project_resource_limit` | control-plane | stable | A per-project ceiling is removed and the project returns to the fleet ceiling alone. |
| `resource_ceiling.set` | `project_resource_limit` | control-plane | stable | A per-project resource ceiling is written with `cloop hub limits set`. |

Payload keys:

- `resource_ceiling.cleared` — `target`, `project`, `reason`, `via`, `os_user`
- `resource_ceiling.set` — `target`, `project`, `cpu_millis`, `memory_mb`, `disk_mb`, `pids`, `reason`, `via`, `os_user`

- `resource_ceiling.set` — The values are the merged ceiling that was stored, not the flags that were passed: `set` merges onto the existing row, so the flags alone would not say what the project ended up capped at.

### sealing_key.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `sealing_key.retired` | `sealing_key` | control-plane | stable | A superseded sealing key is retired once nothing is wrapped under it. |
| `sealing_key.rotated` | `sealing_key` | control-plane | stable | The secret store's sealing key is rotated and stored payloads are re-wrapped under the new one. |

Payload keys:

- `sealing_key.retired` — `key_id`, `via`
- `sealing_key.rotated` — `from_primary`, `to_key`, `rewrapped`, `skipped`, `failed`, `complete`, `via`

- `sealing_key.rotated` — Envelope encryption means rotation re-wraps data keys rather than re-encrypting payloads, so this row is cheap even on a large store.

### stt.credential.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `stt.credential.cleared` | `config` | control-plane | stable | The speech-to-text API key is removed. |
| `stt.credential.set` | `config` | control-plane | stable | The speech-to-text API key behind the Dictate button is configured. |

Payload keys, on every action above: `scope`

- `stt.credential.set` — The key itself never reaches the payload. The row is filed against entity id `stt.groq_api_key`, so what changed is in the entity rather than the payload.

### user.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `user.offboard` | `user` | control-plane | stable | An identity is offboarded, summarising every surface the operation touched. |
| `user.offboard_deny` | `user` | control-plane | stable | Offboarding writes deny bindings so a stale IdP mapping cannot re-admit the identity. |
| `user.offboard_glasses` | `user` | control-plane | stable | Offboarding revokes the identity's display-glasses links. |
| `user.offboard_lease` | `user` | control-plane | stable | Offboarding releases secret leases held on the identity's behalf. |
| `user.offboard_membership` | `user` | control-plane | stable | Offboarding drops the identity's project memberships. |
| `user.offboard_project` | `user` | control-plane | stable | Offboarding reports projects that need a new owner; it does not reassign them. |
| `user.offboard_session` | `user` | control-plane | stable | Offboarding revokes the identity's live sessions. |
| `user.offboard_task` | `user` | control-plane | stable | Offboarding stops tasks the identity had running. |
| `user.offboard_token` | `user` | control-plane | stable | Offboarding revokes the identity's API tokens. |

Payload keys:

- `user.offboard` — `sessions`, `tokens`, `glasses`, `denies`, `leases`, `tasks`, `projects`, `memberships`, `warnings`, `identity`, `identity_input`, `subjects`, `emails`, `reason`, `via`
- `user.offboard_deny` — `count`, `bindings`, `claims`, `identity`, `identity_input`, `subjects`, `emails`, `reason`, `via`
- `user.offboard_glasses` — `count`, `links`, `identity`, `identity_input`, `subjects`, `emails`, `reason`, `via`
- `user.offboard_lease` — `count`, `leases`, `identity`, `identity_input`, `subjects`, `emails`, `reason`, `via`
- `user.offboard_membership` — `count`, `projects`, `identity`, `identity_input`, `subjects`, `emails`, `reason`, `via`
- `user.offboard_project` — `count`, `projects`, `action`, `identity`, `identity_input`, `subjects`, `emails`, `reason`, `via`
- `user.offboard_session` — `count`, `sessions`, `identity`, `identity_input`, `subjects`, `emails`, `reason`, `via`
- `user.offboard_task` — `count`, `tasks`, `identity`, `identity_input`, `subjects`, `emails`, `reason`, `via`
- `user.offboard_token` — `count`, `tokens`, `identity`, `identity_input`, `subjects`, `emails`, `reason`, `via`

- `user.offboard_project` — Deliberately a report rather than a mutation — picking a project's next owner is not a decision an offboarding script should make.

### project.member.*

| Action | Entity | Home | Stability | Fires when |
| --- | --- | --- | --- | --- |
| `project.member.grant` | `project_member` | control-plane | beta | An identity is added to a project's roster. |
| `project.member.leave` | `project_member` | control-plane | beta | A member removes themselves from a project. |
| `project.member.revoke` | `project_member` | control-plane | beta | A maintainer removes an identity from a project's roster. |

Payload keys, on every action above: `project`, `project_path`, `identity`, `left`

- `project.member.leave` — Separate from project.member.revoke so "was this person removed or did they leave" stays answerable.

