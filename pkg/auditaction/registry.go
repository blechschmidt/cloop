package auditaction

import "github.com/blechschmidt/cloop/pkg/authz"

// registry is the single source of truth for every action name the hub writes
// to audit_events.
//
// Declaration order is page order. Entries are grouped by family, and families
// are ordered so a reader moves through the system the way an incident does:
// what the plan did, what ran it, what it was given, what it was allowed to
// reach, who authorised it, and who administered the hub. Within a family the
// generated page sorts by name, so adding an entry never reshuffles its
// neighbours.
//
// Adding an action:
//
//  1. Add the constant and the registry entry here, together. Both, or
//     tests/arch/auditaction_test.go fails on the emission site.
//  2. Emit it by referencing the constant — never by writing the literal
//     again. That is the whole point.
//  3. Run `make docs-audit` to regenerate docs/reference/audit-events.md.
//
// Every entry names authz.PermAuditRead because the trail is read through one
// pair of admin-only endpoints. See Entry.Read for why the field exists per
// entry rather than as a package constant.
var registry = []Entry{
	// ── task ───────────────────────────────────────────────────────────────
	// The plan's own mutations. These are the highest-volume rows in the
	// table by a wide margin and the only ones pkg/eventlog/replay.go can
	// rebuild a task tree from, which is why they are audit rows rather than
	// UI-journal rows.
	{
		Action:    ActionTaskUpsert,
		Home:      HomeProject,
		Entity:    "task",
		Trigger:   "A task is created, or a saved task's audited fields differ from the ones already stored.",
		Payload:   []string{"id", "title", "status", "priority", "role", "description"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "Emitted from the diff SaveState computes inside its own transaction, " +
			"not from the plan — a byte-identical re-save produces no row. Before that " +
			"diff existed this action was 99.7% of a 1.09M-row table.",
	},
	{
		Action:    ActionTaskDelete,
		Home:      HomeProject,
		Entity:    "task",
		Trigger:   "A task disappears from the plan between two saves, or is deleted outright.",
		Payload:   []string{"id"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionTaskStatus,
		Home:      HomeProject,
		Entity:    "task",
		Trigger:   "Somebody flips a task's status by hand, rather than the orchestrator moving it.",
		Payload:   []string{"id", "old_status", "new_status"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:  ActionTaskDispatch,
		Home:    HomeProject,
		Entity:  "task",
		Trigger: "A task is handed to an executor, recording where it will run and what it was given.",
		Payload: []string{
			"task_id", "title", "project", "run_id", "executor_id", "executor_kind",
			"isolation", "requested_image", "pinned_image", "spec_sha256",
			"setup_sha256", "lease_ids",
		},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "This and task.finish are what make \"where did this task run, and what " +
			"credentials did it hold\" answerable from audit_events alone, without " +
			"joining the executor tables.",
	},
	{
		Action:  ActionTaskFinish,
		Home:    HomeProject,
		Entity:  "task",
		Trigger: "A dispatched task reaches a terminal outcome — done, failed, skipped, timed out, or aborted.",
		Payload: []string{
			"task_id", "outcome", "title", "project", "run_id", "executor_id",
			"executor_kind", "isolation", "reason", "started_at", "completed_at",
			"duration_ms", "abort_class", "abort_cleared", "fail_count", "write_back_commit",
		},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "`outcome` carries the terminal status; `reason` carries why, when there is one.",
	},

	// ── run ────────────────────────────────────────────────────────────────
	{
		Action:  ActionRunCapPaused,
		Home:    HomeProject,
		Entity:  "plan",
		Trigger: "A Claude Code subscription cap stops the run before it dispatches its next task.",
		Payload: []string{
			"project", "windows", "utilization", "cap", "resumes_at", "detail",
		},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "Distinct from state.save's bare \"paused\" status because a cap is the " +
			"one pause that ends by itself: `resumes_at` is the window's reset from " +
			"the OAuth usage API, and it is what run.cap_resumed is later matched against.",
	},
	{
		Action:    ActionRunCapResumed,
		Home:      HomeProject,
		Entity:    "plan",
		Trigger:   "The hub restarts a cap-paused run after its window rolled over, without a human.",
		Payload:   []string{"project", "paused_detail", "resumes_at", "resumed_at"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "The only action recording work that a machine started on its own initiative, " +
			"so \"who restarted this project\" stays answerable from the trail alone.",
	},

	// ── step ───────────────────────────────────────────────────────────────
	{
		Action:    ActionStepAppend,
		Home:      HomeProject,
		Entity:    "step",
		Trigger:   "One execution step finishes and its transcript is appended to the run.",
		Payload:   []string{"step", "task", "exit_code", "duration", "time", "input_tokens", "output_tokens"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},

	// ── state / config ─────────────────────────────────────────────────────
	{
		Action:  ActionStateSave,
		Home:    HomeProject,
		Entity:  "plan",
		Trigger: "The project's plan-level state is written: goal, run status, counters, and the mode flags in force.",
		Payload: []string{
			"goal", "status", "current_step", "evolve_step", "plan_version", "task_count",
			"total_input_tokens", "total_output_tokens", "auto_evolve", "innovate_mode",
			"parallel", "max_parallel", "pause_code", "pause_detail", "pause_resumes_at",
		},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "The `pause_*` keys appear only when `status` is `paused`, and are what " +
			"make an approval gate distinguishable from a spent budget or an exhausted " +
			"usage window — before them all ~26 pause conditions recorded the same word.",
	},
	{
		Action:    ActionConfigSet,
		Home:      HomeProject,
		Entity:    "config",
		Trigger:   "A configuration write lands, from the Settings panel, the CLI, or config validation repair.",
		Payload:   []string{"yaml"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "`yaml` is the post-write document with secret-shaped values redacted, not a diff.",
	},

	// ── executor ───────────────────────────────────────────────────────────
	// Seven operator verbs plus two the scheduler raises on its own. All nine
	// share entity_type `executor`; executor.failover is the exception that
	// identifies a session rather than a node, and says so.
	{
		Action:    ActionExecutorEnroll,
		Home:      HomeControlPlane,
		Entity:    "executor",
		Trigger:   "A remote agent completes outbound enrolment and joins the fleet.",
		Payload:   []string{"action", "executor_id", "name", "expires_at", "workdir_root", "labels"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "`action` repeats the verb without the family prefix — `enroll`, not `executor.enroll`.",
	},
	{
		Action:    ActionExecutorRevoke,
		Home:      HomeControlPlane,
		Entity:    "executor",
		Trigger:   "An enrolled agent's credential is revoked and it is removed from the fleet.",
		Payload:   []string{"action", "executor_id", "name", "kind"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionExecutorCordon,
		Home:      HomeControlPlane,
		Entity:    "executor",
		Trigger:   "An executor is marked to refuse new work while finishing what it holds.",
		Payload:   []string{"action", "executor_id", "reason", "state"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionExecutorUncordon,
		Home:      HomeControlPlane,
		Entity:    "executor",
		Trigger:   "A cordoned executor is returned to normal scheduling.",
		Payload:   []string{"action", "executor_id", "state"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionExecutorDrain,
		Home:      HomeControlPlane,
		Entity:    "executor",
		Trigger:   "An executor is set to shed in-flight work as well as refuse new work.",
		Payload:   []string{"action", "executor_id", "reason", "state"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionExecutorBind,
		Home:      HomeControlPlane,
		Entity:    "executor",
		Trigger:   "A project is pinned to one executor, at creation time or from the Executors panel.",
		Payload:   []string{"action", "executor_id", "project", "project_path", "kind", "via"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "Where a project's code runs is the most consequential setting on the hub, which is why the creation-dialog path emits this too.",
	},
	{
		Action:    ActionExecutorUnbind,
		Home:      HomeControlPlane,
		Entity:    "executor",
		Trigger:   "A project's executor pin is cleared and it falls back to registry placement.",
		Payload:   []string{"action", "project", "project_path"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionExecutorStateChange,
		Home:      HomeControlPlane,
		Entity:    "executor",
		Trigger:   "Liveness tracking moves an executor between health states without an operator asking.",
		Payload:   []string{"from", "to", "reason"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionExecutorFailover,
		Home:      HomeControlPlane,
		Entity:    "executor_session",
		Trigger:   "A session is moved off an executor that stopped answering, or fails to be placed anywhere.",
		Payload:   []string{"session_id", "from", "to", "attempt", "project_path", "task_id", "placed", "error"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "`placed` distinguishes a successful move from an exhausted one; on failure `to` is empty and `error` says why.",
	},

	// ── workspace ──────────────────────────────────────────────────────────
	{
		Action:  ActionWorkspaceProvisionStart,
		Home:    HomeControlPlane,
		Entity:  "project",
		Trigger: "An executor begins materialising a project's source tree, before the harness starts.",
		Payload: []string{
			"phase", "project", "executor_id", "executor_kind", "handle_id", "kind",
			"repo", "ref", "depth", "grant_id", "lease_id",
		},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "`depth` is the shallow-fetch depth, or the string `full` when the spec asked for whole history.",
	},
	{
		Action:  ActionWorkspaceProvisionEnd,
		Home:    HomeControlPlane,
		Entity:  "project",
		Trigger: "Workspace provisioning finishes, successfully or not.",
		Payload: []string{
			"phase", "project", "executor_id", "executor_kind", "handle_id", "kind",
			"repo", "ref", "depth", "grant_id", "lease_id", "duration_ms", "error",
		},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "A row with no `error` is the success case; there is no separate failure action.",
	},

	// ── sandbox ────────────────────────────────────────────────────────────
	{
		Action:    ActionSandboxImageDenied,
		Home:      HomeControlPlane,
		Entity:    "project",
		Trigger:   "Image trust policy refuses a container image a project asked to run.",
		Payload:   []string{"image", "rule", "reason", "registry", "repository", "project"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "The one sandbox placement decision worth a permanent row: the others record a " +
			"project asking for less than it could have, this one records it asking to " +
			"execute code from somewhere the operator does not trust.",
	},

	// ── sandbox.attach ─────────────────────────────────────────────────────
	// Interactive access to a running task's sandbox. Three rows rather than
	// one because a refusal and a session are different facts, and the close
	// is what bounds how long a human held a shell inside a workload.
	{
		Action:    ActionSandboxAttachOpen,
		Home:      HomeControlPlane,
		Entity:    "sandbox_session",
		Trigger:   "A caller is admitted to a shell inside a running task's sandbox.",
		Payload:   []string{"session_id", "writable", "executor_id", "handle_id", "task_id", "command"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "`writable` records whether the second, narrower `sandbox.attach.write` permission was exercised.",
	},
	{
		Action:    ActionSandboxAttachClose,
		Home:      HomeControlPlane,
		Entity:    "sandbox_session",
		Trigger:   "An attached session ends, by the caller leaving or the sandbox going away.",
		Payload:   []string{"session_id", "writable", "executor_id", "handle_id", "task_id", "command", "detail"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionSandboxAttachDenied,
		Home:      HomeControlPlane,
		Entity:    "sandbox_session",
		Trigger:   "An attach request is refused, by permission, by scope, or because the target is not running.",
		Payload:   []string{"session_id", "writable", "executor_id", "handle_id", "task_id", "command", "detail"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},

	// ── secret ─────────────────────────────────────────────────────────────
	// Every brokered credential operation. All of these share one payload
	// shape, built in pkg/secretstore's auditor from a pkg/secretbroker Event
	// and redacted twice on the way — once at emission and once here, because
	// this is the last function before a credential-shaped string would become
	// a permanent, hash-chained row.
	{
		Action:    ActionSecretMint,
		Home:      HomeControlPlane,
		Entity:    "secret",
		Trigger:   "A credential is sealed and stored as a new secret.",
		Payload:   secretPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionSecretDelete,
		Home:      HomeControlPlane,
		Entity:    "secret",
		Trigger:   "A secret is destroyed and every grant depending on it is revoked with it.",
		Payload:   secretPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionSecretGrant,
		Home:      HomeControlPlane,
		Entity:    "secret",
		Trigger:   "A grant is written authorising a subject to lease a secret.",
		Payload:   secretPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "This is the row that answers \"what authority exists\"; the request family answers \"who asked for it\".",
	},
	{
		Action:    ActionSecretRevoke,
		Home:      HomeControlPlane,
		Entity:    "secret",
		Trigger:   "An operator marks a grant unusable.",
		Payload:   secretPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionSecretLease,
		Home:      HomeControlPlane,
		Entity:    "secret",
		Trigger:   "A lease is issued — or refused — against the grants matching a request.",
		Payload:   secretPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "`decision` is `allow` or `deny` on every action in this family; a denial is a row, not a missing one.",
	},
	{
		Action:    ActionSecretRenew,
		Home:      HomeControlPlane,
		Entity:    "secret",
		Trigger:   "A live lease is re-issued to the same holder before it expires.",
		Payload:   secretPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionSecretRelease,
		Home:      HomeControlPlane,
		Entity:    "secret",
		Trigger:   "A workload finishes with a lease and it is dropped from the server-side record.",
		Payload:   secretPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "An ordinary end of life. Compare the lease.revoke_* family, which is somebody deciding mid-run that a holder may no longer hold it.",
	},
	{
		Action:    ActionSecretAccessCheck,
		Home:      HomeControlPlane,
		Entity:    "secret",
		Trigger:   "A repository or cluster access decision is evaluated against a grant's constraints.",
		Payload:   secretPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionSecretRequest,
		Home:      HomeControlPlane,
		Entity:    "secret",
		Trigger:   "A developer files a self-service request for access they do not have.",
		Payload:   secretPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "The gap between this row and its approval is the number that says whether the request path is used or routed around.",
	},
	{
		Action:    ActionSecretRequestApprove,
		Home:      HomeControlPlane,
		Entity:    "secret",
		Trigger:   "A reviewer approves a pending request and the grant it asked for is minted.",
		Payload:   secretPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionSecretRequestDeny,
		Home:      HomeControlPlane,
		Entity:    "secret",
		Trigger:   "A reviewer refuses a pending request.",
		Payload:   secretPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionSecretRequestWithdraw,
		Home:      HomeControlPlane,
		Entity:    "secret",
		Trigger:   "A requester withdraws their own pending request.",
		Payload:   secretPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionSecretRequestExpire,
		Home:      HomeControlPlane,
		Entity:    "secret",
		Trigger:   "A pending request lapses with nobody having decided it.",
		Payload:   secretPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "Its own action rather than a flavour of deny: denied is an answer, expired is the absence of one, and conflating them hides a queue nobody is working.",
	},
	{
		Action:    ActionSecretLeaseSweep,
		Home:      HomeControlPlane,
		Entity:    "secret",
		Trigger:   "The periodic sweeper reaps leases whose TTL has passed.",
		Payload:   []string{"decision", "wiped", "vanished", "skipped", "failed", "expired"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "One row per sweep, not per lease — the counts are the point.",
	},

	// ── lease ──────────────────────────────────────────────────────────────
	// Revocation is not one event. It is sent, and then it either lands or it
	// does not, possibly minutes later when an offline device reconnects.
	// Collapsing these would make the trail claim a credential was withdrawn
	// at a moment when it demonstrably still worked.
	{
		Action:    ActionLeaseRevokeSent,
		Home:      HomeControlPlane,
		Entity:    "lease",
		Trigger:   "A revocation is queued for delivery to the executors holding a lease.",
		Payload:   []string{"decision", "lease_id", "grant_id", "executor_id", "project_id", "action", "secrets", "holders", "reason"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionLeaseRevokeAcked,
		Home:      HomeControlPlane,
		Entity:    "lease",
		Trigger:   "An executor confirms it destroyed the material for a revoked lease.",
		Payload:   []string{"decision", "lease_id", "grant_id", "executor_id", "project_id", "action", "state", "env_scrubbed", "files_removed", "reason"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionLeaseRevokeFailed,
		Home:      HomeControlPlane,
		Entity:    "lease",
		Trigger:   "A revocation fails to land on an executor that still holds the credential.",
		Payload:   []string{"decision", "lease_id", "grant_id", "executor_id", "project_id", "action", "state", "error", "reason"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "The row an incident response cares about: the credential is still out there.",
	},

	// ── github_app ─────────────────────────────────────────────────────────
	{
		Action:    ActionGitHubAppTokenDestroy,
		Home:      HomeControlPlane,
		Entity:    "secret",
		Trigger:   "A GitHub App installation token is deleted at GitHub.",
		Payload:   secretPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "Deliberately not secret.revoke: a github_app token is destroyed on every " +
			"ordinary lease release, so folding these in would make \"how many grants did " +
			"an operator withdraw\" a number dominated by routine teardown.",
	},

	// ── egress ─────────────────────────────────────────────────────────────
	{
		Action:    ActionEgressGrant,
		Home:      HomeControlPlane,
		Entity:    "secret",
		Trigger:   "A subject is authorised to reach the network through the hub's egress proxy.",
		Payload:   secretPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionEgressRevoke,
		Home:      HomeControlPlane,
		Entity:    "secret",
		Trigger:   "An egress authorisation is marked unusable.",
		Payload:   secretPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionEgressRedeem,
		Home:      HomeControlPlane,
		Entity:    "secret",
		Trigger:   "A proxy session is minted against a matching egress grant.",
		Payload:   secretPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionEgressConnect,
		Home:      HomeControlPlane,
		Entity:    "secret",
		Trigger:   "A sandbox's connection attempt is evaluated against the session's host allowlist.",
		Payload:   secretPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "`host` and `port` name the attempted destination; `decision` says whether it was reached.",
	},
	{
		Action:    ActionEgressRequest,
		Home:      HomeControlPlane,
		Entity:    "secret",
		Trigger:   "An HTTP request passes through the egress proxy.",
		Payload:   secretPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionEgressClose,
		Home:      HomeControlPlane,
		Entity:    "secret",
		Trigger:   "An egress proxy session closes, carrying the bytes it moved in each direction.",
		Payload:   secretPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},

	// ── gitproxy ───────────────────────────────────────────────────────────
	// The git interception proxy runs outside the sandbox, so these rows are
	// written by something the workload cannot reach. gitproxy.Event has no
	// field that could hold credential material or object content, which is
	// what makes the whole payload safe to export.
	{
		Action:    ActionGitProxySessionMinted,
		Home:      HomeControlPlane,
		Entity:    "gitproxy",
		Trigger:   "A proxy session is created for a task, scoping which repository and refs it may touch.",
		Payload:   gitProxyPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionGitProxySessionClosed,
		Home:      HomeControlPlane,
		Entity:    "gitproxy",
		Trigger:   "A proxy session ends and its credential stops working.",
		Payload:   gitProxyPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionGitProxyPushAllowed,
		Home:      HomeControlPlane,
		Entity:    "gitproxy",
		Trigger:   "A push is checked against the session's branch allowlist and forwarded.",
		Payload:   gitProxyPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionGitProxyPushDenied,
		Home:      HomeControlPlane,
		Entity:    "gitproxy",
		Trigger:   "A push is refused because it names a ref the session may not write.",
		Payload:   gitProxyPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "The row that matters in this family: it is the only place a sandbox's " +
			"attempt to write outside its lane is recorded. `refs` names what it tried to push.",
	},
	{
		Action:    ActionGitProxyFetch,
		Home:      HomeControlPlane,
		Entity:    "gitproxy",
		Trigger:   "A read passes through the proxy.",
		Payload:   gitProxyPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionGitProxyRejected,
		Home:      HomeControlPlane,
		Entity:    "gitproxy",
		Trigger:   "A request is refused before any policy could be evaluated — no session, bad credential, unknown repository.",
		Payload:   gitProxyPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},

	// ── kubeguard ──────────────────────────────────────────────────────────
	{
		Action:    ActionKubeGuardSessionMinted,
		Home:      HomeControlPlane,
		Entity:    "kubeguard",
		Trigger:   "A Kubernetes proxy session is created for a task against one cluster and context.",
		Payload:   kubeGuardPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionKubeGuardSessionClosed,
		Home:      HomeControlPlane,
		Entity:    "kubeguard",
		Trigger:   "A Kubernetes proxy session ends.",
		Payload:   kubeGuardPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionKubeGuardRequestDenied,
		Home:      HomeControlPlane,
		Entity:    "kubeguard",
		Trigger:   "A Kubernetes request is refused by the session's verb and resource policy.",
		Payload:   kubeGuardPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "This is what enforces a read-only grant on a cluster from outside the sandbox: `verb`, `resource` and `namespace` say exactly what was attempted.",
	},
	{
		Action:    ActionKubeGuardRequestAllowed,
		Home:      HomeControlPlane,
		Entity:    "kubeguard",
		Trigger:   "A Kubernetes request is admitted by policy.",
		Payload:   kubeGuardPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "Sampled rather than exhaustive — a watch against a busy cluster would otherwise be the whole table.",
	},
	{
		Action:    ActionKubeGuardRejected,
		Home:      HomeControlPlane,
		Entity:    "kubeguard",
		Trigger:   "A request is refused before its session could be identified.",
		Payload:   kubeGuardPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},

	// ── ci ─────────────────────────────────────────────────────────────────
	// The GitHub Actions relay: a pipeline authenticates to the hub with an
	// OIDC token and reaches Claude through it, so the pipeline never holds
	// the hub's credential. These rows are how an operator sees what the
	// pipelines did with that.
	{
		Action:    ActionCIRejected,
		Home:      HomeControlPlane,
		Entity:    "ci_session",
		Trigger:   "A relay request is refused before a session could be established.",
		Payload:   ciPayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionCISessionMinted,
		Home:      HomeControlPlane,
		Entity:    "ci_session",
		Trigger:   "A pipeline's OIDC token matches an allowlist rule and a relay session is issued.",
		Payload:   ciPayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionCISessionClosed,
		Home:      HomeControlPlane,
		Entity:    "ci_session",
		Trigger:   "A relay session ends, by expiry or by revocation.",
		Payload:   ciPayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionCISessionRevoked,
		Home:      HomeControlPlane,
		Entity:    "ci_rule",
		Trigger:   "An operator revokes a live relay session from the CI panel.",
		Payload:   ciRulePayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionCIExchangeAccepted,
		Home:      HomeControlPlane,
		Entity:    "ci_session",
		Trigger:   "A pipeline's OIDC token is verified and exchanged for relay credentials.",
		Payload:   ciPayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionCIExchangeRejected,
		Home:      HomeControlPlane,
		Entity:    "ci_session",
		Trigger:   "A token exchange fails: bad signature, wrong issuer, or no rule admits the claims.",
		Payload:   ciPayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note:      "The row to alert on. A pipeline that should be admitted and is not looks identical here to one that should never have asked.",
	},
	{
		Action:    ActionCIRelayAllowed,
		Home:      HomeControlPlane,
		Entity:    "ci_session",
		Trigger:   "A relayed API call is forwarded upstream on a live session.",
		Payload:   ciPayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionCIRelayDenied,
		Home:      HomeControlPlane,
		Entity:    "ci_session",
		Trigger:   "A relayed API call is refused — expired session, unsupported path, or a quota.",
		Payload:   ciPayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionCIRuleCreated,
		Home:      HomeControlPlane,
		Entity:    "ci_rule",
		Trigger:   "An allowlist rule is added, widening which pipelines may authenticate.",
		Payload:   ciRulePayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note:      "`match` is the CEL expression the rule admits on. Rules are the CI surface's whole access-control policy, so these three rows are its change log.",
	},
	{
		Action:    ActionCIRuleUpdated,
		Home:      HomeControlPlane,
		Entity:    "ci_rule",
		Trigger:   "An allowlist rule is edited; live sessions it no longer admits are revoked in the same operation.",
		Payload:   ciRulePayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionCIRuleDeleted,
		Home:      HomeControlPlane,
		Entity:    "ci_rule",
		Trigger:   "An allowlist rule is removed.",
		Payload:   ciRulePayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionCIConfigUpdated,
		Home:      HomeControlPlane,
		Entity:    "ci_rule",
		Trigger:   "The CI relay's own settings change — whether it is enabled, its issuer, its session ceiling.",
		Payload:   ciRulePayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
	},

	// ── authz ──────────────────────────────────────────────────────────────
	{
		Action:    ActionAuthzGranted,
		Home:      HomeEither,
		Entity:    "permission",
		Trigger:   "A privileged permission is exercised successfully.",
		Payload:   authzPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "Not every allow: ordinary reads would drown the table, so only privileged " +
			"permissions are recorded on this side. Home varies with scope — a check " +
			"against a project lands in that project's chain, a fleet-wide one in the " +
			"hub's — so answering \"what was this subject allowed to do\" needs both.",
	},
	{
		Action:    ActionAuthzDenied,
		Home:      HomeEither,
		Entity:    "permission",
		Trigger:   "Any permission check refuses a caller.",
		Payload:   authzPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "Every denial, unlike the grant side. `scope` says whether the check was " +
			"fleet-wide or against one project; `binding` names the runtime rule when one " +
			"decided it. Neither action in this family is emitted when RBAC is not in " +
			"force for the caller — with no identity provider configured every request is " +
			"granted everything and there is no decision to record, so an absence of rows " +
			"here means \"nobody was refused\" only on a hub that has SSO or API tokens. " +
			"Project-scoped decisions land in that project's trail rather than the control " +
			"plane's.",
	},

	// ── api_token ──────────────────────────────────────────────────────────
	{
		Action:    ActionAPITokenCreated,
		Home:      HomeControlPlane,
		Entity:    "api_token",
		Trigger:   "A scoped API token or a display-glasses link is minted, from the UI or the CLI.",
		Payload:   []string{"name", "roles", "project_scope", "expires_at", "kind", "owner"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "`kind` distinguishes a service-account token from a glasses link, which is a token with one narrow role and a URL as its only delivery mechanism.",
	},
	{
		Action:    ActionAPITokenRevoked,
		Home:      HomeControlPlane,
		Entity:    "api_token",
		Trigger:   "A token or glasses link is revoked, or rotated — a rotation revokes the old one.",
		Payload:   []string{"name", "roles", "reason"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionAPITokenAuthFailed,
		Home:      HomeControlPlane,
		Entity:    "api_token",
		Trigger:   "A request presents a token that does not authenticate: unknown, revoked, or expired.",
		Payload:   []string{"reason", "ip", "method", "path"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "Filed against the token's *public* id (`cloop_pat_<id>`), never the secret " +
			"half, and against `(unparseable)` when the credential is not even shaped like " +
			"a token — so a garbage value is not echoed back into the trail. Rate of this " +
			"action by `ip` is the credential-stuffing signal.",
	},
	{
		Action:    ActionAPITokenCreateDenied,
		Home:      HomeControlPlane,
		Entity:    "api_token",
		Trigger:   "A token mint is refused because it would grant more than the caller holds.",
		Payload:   []string{"reason", "roles", "project_scope"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "The anti-escalation check. A maintainer trying to mint an admin token lands here.",
	},

	// ── session ────────────────────────────────────────────────────────────
	// The OIDC session lifecycle. The claims_* trio exists because a session's
	// authority has to be re-asserted against the IdP rather than trusted for
	// its whole lifetime: a demotion at the IdP must not survive in a live
	// session.
	{
		Action:    ActionSessionCreated,
		Home:      HomeControlPlane,
		Entity:    "session",
		Trigger:   "A sign-in completes and a durable session is written.",
		Payload:   sessionPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionSessionExpired,
		Home:      HomeControlPlane,
		Entity:    "session",
		Trigger:   "The session janitor removes a session past its absolute or idle deadline.",
		Payload:   sessionPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionSessionRevoked,
		Home:      HomeControlPlane,
		Entity:    "session",
		Trigger:   "A user logs out, or an operator terminates a session from the UI or the CLI.",
		Payload:   sessionPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionSessionIdPRevoked,
		Home:      HomeControlPlane,
		Entity:    "session",
		Trigger:   "The identity provider reports the authorisation behind a session is gone.",
		Payload:   sessionPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionSessionRoleNarrowed,
		Home:      HomeControlPlane,
		Entity:    "session",
		Trigger:   "A re-assertion finds the session's claims now map to a lower role than it held.",
		Payload:   sessionPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "`prior_role` and `role` bracket the demotion; `dropped_claims` names what the IdP stopped asserting.",
	},
	{
		Action:    ActionSessionClaimsUnverified,
		Home:      HomeControlPlane,
		Entity:    "session",
		Trigger:   "The hub cannot reach the IdP to re-assert a session's claims.",
		Payload:   sessionPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionSessionClaimsRejected,
		Home:      HomeControlPlane,
		Entity:    "session",
		Trigger:   "The IdP answers the re-assertion by refusing the claims outright.",
		Payload:   sessionPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionSessionClaimsStale,
		Home:      HomeControlPlane,
		Entity:    "session",
		Trigger:   "A privileged operation is blocked because the session's claims are older than the freshness bound allows.",
		Payload:   sessionPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "A block, not a revocation: the session stays, and ordinary reads keep working.",
	},

	// ── role_binding ───────────────────────────────────────────────────────
	{
		Action:    ActionRoleBindingGranted,
		Home:      HomeControlPlane,
		Entity:    "role_binding",
		Trigger:   "A runtime binding is written mapping a claim to a role, without an IdP or config change.",
		Payload:   roleBindingPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionRoleBindingDenied,
		Home:      HomeControlPlane,
		Entity:    "role_binding",
		Trigger:   "A runtime deny binding is written, demoting an identity ahead of the IdP catching up.",
		Payload:   roleBindingPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "The incident-response verb: it takes authority away now, from a CLI, without a browser.",
	},
	{
		Action:    ActionRoleBindingDeleted,
		Home:      HomeControlPlane,
		Entity:    "role_binding",
		Trigger:   "A runtime binding is removed and the identity falls back to its configured role.",
		Payload:   roleBindingPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},

	// ── quota ──────────────────────────────────────────────────────────────
	{
		Action:    ActionQuotaDenied,
		Home:      HomeControlPlane,
		Entity:    "quota",
		Trigger:   "Admission control refuses an operation because the caller is at a resource ceiling.",
		Payload:   []string{"limit", "used", "requested", "source", "transient", "method", "path"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "The identity is the row's actor and the resource is its entity id, so neither repeats in the payload.",
	},
	{
		Action:    ActionQuotaOverrideSet,
		Home:      HomeControlPlane,
		Entity:    "quota",
		Trigger:   "A per-identity quota override is written, from the UI or the CLI.",
		Payload:   []string{"target", "identity", "limits", "unset", "reason", "via", "os_user"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "Two emitters with different shapes: the UI writes `target` plus one key " +
			"per resource, the CLI writes `identity` with the limits nested under `limits`.",
	},
	{
		Action:    ActionQuotaOverrideCleared,
		Home:      HomeControlPlane,
		Entity:    "quota",
		Trigger:   "A per-identity override is removed and the identity returns to the default ceiling.",
		Payload:   []string{"target", "identity", "cleared_limits", "reason", "via", "os_user"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionQuotaSpendRefused,
		Home:      HomeControlPlane,
		Entity:    "project",
		Trigger:   "A run is stopped between tasks because the identity paying for it is over its spend limit.",
		Payload:   []string{"identity", "resource", "limit", "used", "source", "project", "outcome"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "Enforced between tasks, not mid-task: a task already running is allowed to finish.",
	},

	// ── sealing_key ────────────────────────────────────────────────────────
	{
		Action:    ActionSealingKeyRotated,
		Home:      HomeControlPlane,
		Entity:    "sealing_key",
		Trigger:   "The secret store's sealing key is rotated and stored payloads are re-wrapped under the new one.",
		Payload:   []string{"from_primary", "to_key", "rewrapped", "skipped", "failed", "complete", "via"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "Envelope encryption means rotation re-wraps data keys rather than re-encrypting payloads, so this row is cheap even on a large store.",
	},
	{
		Action:    ActionSealingKeyRetired,
		Home:      HomeControlPlane,
		Entity:    "sealing_key",
		Trigger:   "A superseded sealing key is retired once nothing is wrapped under it.",
		Payload:   []string{"key_id", "via"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},

	// ── stt.credential ─────────────────────────────────────────────────────
	{
		Action:    ActionSTTCredentialSet,
		Home:      HomeControlPlane,
		Entity:    "config",
		Trigger:   "The speech-to-text API key behind the Dictate button is configured.",
		Payload:   []string{"scope"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "The key itself never reaches the payload. The row is filed against entity id `stt.groq_api_key`, so what changed is in the entity rather than the payload.",
	},
	{
		Action:    ActionSTTCredentialCleared,
		Home:      HomeControlPlane,
		Entity:    "config",
		Trigger:   "The speech-to-text API key is removed.",
		Payload:   []string{"scope"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},

	// ── user ───────────────────────────────────────────────────────────────
	// Offboarding writes one summary row plus one row per surface it touched.
	// The per-surface rows exist because offboarding is partial by nature —
	// a lease may fail to release while sessions revoke cleanly — and a
	// single row could only report the aggregate, which is the one shape that
	// cannot answer "what is still live".
	{
		Action:    ActionUserOffboard,
		Home:      HomeControlPlane,
		Entity:    "user",
		Trigger:   "An identity is offboarded, summarising every surface the operation touched.",
		Payload:   append([]string{"sessions", "tokens", "glasses", "denies", "leases", "tasks", "projects", "memberships", "warnings"}, offboardPayload...),
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionUserOffboardSession,
		Home:      HomeControlPlane,
		Entity:    "user",
		Trigger:   "Offboarding revokes the identity's live sessions.",
		Payload:   append([]string{"count", "sessions"}, offboardPayload...),
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionUserOffboardToken,
		Home:      HomeControlPlane,
		Entity:    "user",
		Trigger:   "Offboarding revokes the identity's API tokens.",
		Payload:   append([]string{"count", "tokens"}, offboardPayload...),
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionUserOffboardGlasses,
		Home:      HomeControlPlane,
		Entity:    "user",
		Trigger:   "Offboarding revokes the identity's display-glasses links.",
		Payload:   append([]string{"count", "links"}, offboardPayload...),
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionUserOffboardDeny,
		Home:      HomeControlPlane,
		Entity:    "user",
		Trigger:   "Offboarding writes deny bindings so a stale IdP mapping cannot re-admit the identity.",
		Payload:   append([]string{"count", "bindings", "claims"}, offboardPayload...),
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionUserOffboardMembership,
		Home:      HomeControlPlane,
		Entity:    "user",
		Trigger:   "Offboarding drops the identity's project memberships.",
		Payload:   append([]string{"count", "projects"}, offboardPayload...),
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionUserOffboardLease,
		Home:      HomeControlPlane,
		Entity:    "user",
		Trigger:   "Offboarding releases secret leases held on the identity's behalf.",
		Payload:   append([]string{"count", "leases"}, offboardPayload...),
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionUserOffboardTask,
		Home:      HomeControlPlane,
		Entity:    "user",
		Trigger:   "Offboarding stops tasks the identity had running.",
		Payload:   append([]string{"count", "tasks"}, offboardPayload...),
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionUserOffboardProject,
		Home:      HomeControlPlane,
		Entity:    "user",
		Trigger:   "Offboarding reports projects that need a new owner; it does not reassign them.",
		Payload:   append([]string{"count", "projects", "action"}, offboardPayload...),
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "Deliberately a report rather than a mutation — picking a project's next owner is not a decision an offboarding script should make.",
	},

	// ── project.member ─────────────────────────────────────────────────────
	{
		Action:    ActionProjectMemberGrant,
		Home:      HomeControlPlane,
		Entity:    "project_member",
		Trigger:   "An identity is added to a project's roster.",
		Payload:   projectMemberPayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionProjectMemberRevoke,
		Home:      HomeControlPlane,
		Entity:    "project_member",
		Trigger:   "A maintainer removes an identity from a project's roster.",
		Payload:   projectMemberPayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionProjectMemberLeave,
		Home:      HomeControlPlane,
		Entity:    "project_member",
		Trigger:   "A member removes themselves from a project.",
		Payload:   projectMemberPayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note:      "Separate from project.member.revoke so \"was this person removed or did they leave\" stays answerable.",
	},
}

// Shared payload shapes. These are families whose members all go through one
// emitter and therefore carry one set of keys; listing them once keeps the
// registry from claiming a difference between siblings that does not exist.
var (
	// secretPayload is built by pkg/secretstore's Auditor from a
	// pkg/secretbroker Event. Every key is conditional — the emitter omits
	// what it does not know — except `decision`, which is on every row.
	secretPayload = []string{
		"decision", "subject", "secret_id", "secret_name", "kind", "grant_id",
		"request_id", "lease_id", "executor_id", "project_id", "run_id",
		"constraints", "reason", "task_id", "host", "port", "bytes_up",
		"bytes_down", "expires_at",
	}

	gitProxyPayload = []string{"kind", "session_id", "repo", "project_id", "task_id", "refs", "detail"}

	kubeGuardPayload = []string{
		"kind", "session_id", "cluster", "context", "verb", "resource", "namespace",
		"object", "reason", "project_id", "task_id", "executor_id", "grant_id",
		"lease_id", "detail",
	}

	// ciPayload is a whole pkg/claudeproxy Event, marshalled as-is. That type
	// has no field capable of holding a prompt, a completion or a token, which
	// is what makes marshalling the whole thing safe.
	ciPayload = []string{
		"kind", "session_id", "rule_id", "rule_name", "project", "subject",
		"repository", "ref", "workflow", "actor", "run_id", "method", "path",
		"model", "status", "reason", "input_tokens", "output_tokens", "detail", "at",
	}

	// ciRulePayload is what the CI panel records about a rule change. `models`
	// and `condition` are the two fields that decide who is admitted and what
	// they may call, so they are the ones a reviewer is here for.
	ciRulePayload = []string{
		"rule_id", "rule_name", "repository", "ref", "condition", "models",
		"detail", "error",
	}

	authzPayload = []string{
		"outcome", "permission", "role", "source", "scope", "subject",
		"method", "path", "binding",
	}

	// sessionPayload covers both emitters: the hub's own session lifecycle, and
	// `cloop hub session revoke`, which adds the selector it matched on and the
	// admin block every CLI mutation carries.
	sessionPayload = []string{
		"event", "session_id", "subject", "email", "actor", "reason", "ip",
		"user_agent", "prior_role", "role", "dropped_claims",
		"issued_at", "selector", "selected", "via", "os_user",
	}

	// roleBindingPayload is the binding itself plus the block every hub-admin
	// CLI mutation carries: why, through what, and as which OS user.
	roleBindingPayload = []string{
		"id", "effect", "claim", "value", "role", "project", "executor",
		"binding_reason", "created_at", "created_by", "reason", "via", "os_user",
	}

	// offboardPayload is the identity block every user.offboard* row carries
	// on top of its own counts.
	offboardPayload = []string{"identity", "identity_input", "subjects", "emails", "reason", "via"}

	projectMemberPayload = []string{"project", "project_path", "identity", "left"}
)
