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
			"isolation", "requested_image", "pinned_image", "image_digest", "image_provenance",
			"verified_digest", "spec_sha256", "setup_sha256", "lease_ids", "recorded_by",
		},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "This and task.finish are what make \"where did this task run, and what " +
			"credentials did it hold\" answerable from audit_events alone, without " +
			"joining the executor tables. image_digest is the digest pinned_image names. " +
			"A run carried out as a seed — on a Kubernetes Pod or a device — writes its own " +
			"rows into a copy of the project that never comes back, so the hub writes them " +
			"when it merges the run's outcome, recorded_by \"hub\" (Task 20457).",
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
	{
		Action:    ActionTaskQuarantine,
		Home:      HomeProject,
		Entity:    "task",
		Trigger:   "Failover marks a task as a suspected node killer: two or more distinct executors went unreachable while it was running.",
		Payload:   []string{"task_id", "title", "kind", "nodes", "reason"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "`nodes` lists each executor that went down under the task with when it went unreachable. " +
			"A marked task runs again only after an explicit reset, recorded as task.quarantine_release.",
	},
	{
		Action:    ActionTaskQuarantineRelease,
		Home:      HomeProject,
		Entity:    "task",
		Trigger:   "An explicit reset returns a suspected node killer to pending, clearing its mark and the losses behind it.",
		Payload:   []string{"task_id", "kind", "nodes", "marked_at", "via"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "`via` names the reset — the dashboard, `cloop task reset`, `cloop task bulk reset`; the actor is who pressed it.",
	},
	{
		Action:    ActionTaskAttachmentDelete,
		Home:      HomeProject,
		Entity:    "task",
		Trigger:   "A person deletes a file attached to a task, from the dashboard or with `cloop task attachments remove`.",
		Payload:   []string{"id", "attachment_id", "name", "size", "sha256"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "Attaching is not audited: a run's files are recorded in the project's event journal, which names the run. A file deleted with its task is covered by that task's `task.delete`.",
	},

	// ── run ────────────────────────────────────────────────────────────────
	{
		Action:  ActionRunCapPaused,
		Home:    HomeProject,
		Entity:  "plan",
		Trigger: "A Claude Code subscription cap stops the run before it dispatches its next task — a configured cap, or a window used up while budget.block_extra_usage holds the run out of extra usage (`cap` 100).",
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
		Trigger:   "The hub restarts a cap-paused run after its window rolled over, without a human — or, for the extra-usage pause an older build recorded as a spent budget, once the usage API shows the window open (no `resumes_at`).",
		Payload:   []string{"project", "paused_detail", "resumes_at", "resumed_at", "acted_for", "acted_for_basis"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "The only action recording work that a machine started on its own initiative, " +
			"so \"who restarted this project\" stays answerable from the trail alone. On a hub with single sign-on " +
			"`acted_for` names whom the run acts for, on their own Claude account, and `acted_for_basis` how that " +
			"was decided: `starter`, the person the resumed run was started for as recorded at its dispatch (no " +
			"`acted_for` when it was started acting for no one), `owner`, the project's owner, for a run older than " +
			"that record, or `unknown`, nobody nameable, on an executor that needs no Claude home. A resume that " +
			"could not act for them is not restarted, and leaves no row.",
	},
	{
		Action:    ActionRunAdoptRequested,
		Home:      HomeProject,
		Entity:    "plan",
		Trigger:   "Somebody asks a project's running host-process run to adopt the hub's build at its next task boundary.",
		Payload:   []string{"project", "request_id", "pid", "run_build", "hub_build", "behind"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "Gated like starting a run. The request names the run's process, so it is acted on by " +
			"that run or by none; what the run then did is its run.reexecuted row, or a refusal in " +
			"the project's journal.",
	},
	{
		Action:    ActionRunReexecuted,
		Home:      HomeProject,
		Entity:    "plan",
		Trigger:   "A run replaces its own image with a newer build at a task boundary, keeping its process.",
		Payload:   []string{"project", "run_id", "pid", "from", "to", "reason", "reexecs"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "Written by the new image. Together with task.dispatch it answers \"which build ran this " +
			"task\": a run's tasks before this row ran on `from`, after it on `to`.",
	},
	{
		Action:  ActionRunFirewallDenied,
		Home:    HomeProject,
		Entity:  "plan",
		Trigger: "A run ends whose sandbox firewall refused connections: one row per deny path that refused any, with the totals.",
		Payload: []string{"project", "run_id", "executor_id", "rule", "why", "count", "destinations", "top",
			"first_seen", "last_seen", "fingerprint"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "Aggregated per run and rule (Task 20437), never per packet: `count` is the refusals the " +
			"sandbox's packet log reported — rate-limited to ten a second per deny path, so a flood is at " +
			"least this many — `destinations` how many distinct destinations, `top` up to eight of them as " +
			"`dst:port/proto`. `rule` is the deny path's tag (`default`, `deny:<prefix>`, `meta:<prefix>`, " +
			"`block:<prefix>`, `xlat:<prefix>`), or `unitemised` for what the run's capped aggregate counted " +
			"without itemising; `why` is the hub's sentence for it. Each destination is also a " +
			"`network_blocked` row in the run's history. Absent for a run on Kubernetes, whose NetworkPolicy " +
			"has no portable log, and for one on a device whose agent predates protocol v24.",
	},

	// ── feature ────────────────────────────────────────────────────────────
	{
		Action:    ActionFeatureCreate,
		Home:      HomeProject,
		Entity:    "feature",
		Trigger:   "A feature — a git worktree of the project with its own task list — is created.",
		Payload:   []string{"slug", "branch", "base", "path", "auto_evolve", "innovate", "tasks"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "Filed in the parent project's trail, not the feature's: the feature's own trail " +
			"starts with its first run, and \"which features did this project have\" is a question about the parent.",
	},
	{
		Action:    ActionFeatureRemove,
		Home:      HomeProject,
		Entity:    "feature",
		Trigger:   "A feature's worktree, and with it its task list and history, is removed.",
		Payload:   []string{"slug", "branch", "branch_deleted", "force"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionFeaturePROpen,
		Home:      HomeProject,
		Entity:    "feature",
		Trigger:   "A feature's branch is pushed and a pull request for it is opened or updated.",
		Payload:   []string{"slug", "number", "url", "base", "existing", "automatic"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "automatic is true when the hub opened it on its own because the feature completed " +
			"with auto-PR set, so a pull request nobody clicked for is still attributable.",
	},

	// ── requirement ────────────────────────────────────────────────────────
	// What a project must keep doing (Task 20458). The definitions are audited
	// because a requirement's tests are commands its checks run; the checks
	// because "was this still true, and who asked" is a compliance question.
	{
		Action:    ActionRequirementCreate,
		Home:      HomeProject,
		Entity:    "requirement",
		Trigger:   "A requirement is added to the project, from the dashboard or with `cloop requirements add`.",
		Payload:   []string{"id", "title", "priority", "tests", "fingerprint"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "`tests` is each test's command, as it will run.",
	},
	{
		Action:    ActionRequirementUpdate,
		Home:      HomeProject,
		Entity:    "requirement",
		Trigger:   "A requirement's title, description, priority, tags or tests change.",
		Payload:   []string{"id", "title", "changed", "tests", "fingerprint", "previous_fingerprint"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "`changed` names the fields that differ. A new `fingerprint` means the verdicts recorded " +
			"before it are about a requirement that no longer reads that way, and the dashboard shows them stale.",
	},
	{
		Action:    ActionRequirementDelete,
		Home:      HomeProject,
		Entity:    "requirement",
		Trigger:   "A requirement, and the history of its checks, is deleted.",
		Payload:   []string{"id", "title", "checks"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:  ActionRequirementCheck,
		Home:    HomeProject,
		Entity:  "requirement",
		Trigger: "A check run ends — its tests ran on the project's executor, or it failed or was cancelled.",
		Payload: []string{
			"run_id", "state", "source", "requirement_ids", "assess", "executor_id",
			"commit", "dirty", "fulfilled", "unfulfilled", "unverified", "error", "reason",
		},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "One row per run, not per requirement: each requirement's verdict is a row of " +
			"requirement_checks. `assess` is true when the model was asked about the requirements with no tests.",
	},
	{
		Action:    ActionRequirementVerdict,
		Home:      HomeProject,
		Entity:    "requirement",
		Trigger:   "A person records a requirement's verdict by hand — fulfilled or unfulfilled, with a note.",
		Payload:   []string{"id", "verdict", "note", "fingerprint"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
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
		Action:    ActionForwarderEnroll,
		Home:      HomeControlPlane,
		Entity:    "forwarder",
		Trigger:   "An operator mints an enrollment token for a device forwarder.",
		Payload:   []string{"action", "forwarder_id", "name", "device", "expires_at"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "A forwarder bridges one on-prem USB or layer-2 device to the hub and runs no workload; it is not an executor.",
	},
	{
		Action:    ActionForwarderRevoke,
		Home:      HomeControlPlane,
		Entity:    "forwarder",
		Trigger:   "A device forwarder's enrollment token or long-lived credential is revoked.",
		Payload:   []string{"action", "forwarder_id", "kind"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionForwarderExpose,
		Home:      HomeControlPlane,
		Entity:    "forwarder",
		Trigger:   "An operator probes a forwarded device through the hub: a stream opened to the forwarder and, for USB, its device list read, handing the device to nothing.",
		Payload:   []string{"action", "forwarder_id", "device", "reachable", "member"},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionForwarderBind,
		Home:      HomeControlPlane,
		Entity:    "forwarder",
		Trigger:   "A forwarder's device is made available to a project's runs, optionally only on one virtual executor, by an operator or by approving a request.",
		Payload:   []string{"action", "forwarder_id", "binding_id", "project", "virtual_executor", "expires_at", "request_id"},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note:      "Gated on executor.manage, like enrollment. A run of the project gets the device in its sandbox while the binding is in force.",
	},
	{
		Action:    ActionForwarderUnbind,
		Home:      HomeControlPlane,
		Entity:    "forwarder",
		Trigger:   "A forwarder binding is revoked by an operator, by the forwarder's own revocation, or by its TTL lapsing; a run holding the device has it detached.",
		Payload:   []string{"action", "forwarder_id", "binding_id", "project", "reason"},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionForwarderBindRequest,
		Home:      HomeControlPlane,
		Entity:    "forwarder",
		Trigger:   "Someone without executor.manage asks for a forwarder binding through the grant-request flow.",
		Payload:   []string{"action", "forwarder_id", "request_id", "project", "virtual_executor", "ttl_seconds"},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionForwarderBindRequestApprove,
		Home:      HomeControlPlane,
		Entity:    "forwarder",
		Trigger:   "An administrator approves a forwarder binding request, minting the binding.",
		Payload:   []string{"action", "forwarder_id", "request_id", "binding_id", "expires_at"},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionForwarderBindRequestDeny,
		Home:      HomeControlPlane,
		Entity:    "forwarder",
		Trigger:   "An administrator denies a forwarder binding request.",
		Payload:   []string{"action", "forwarder_id", "request_id", "note"},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionForwarderBindRequestWithdraw,
		Home:      HomeControlPlane,
		Entity:    "forwarder",
		Trigger:   "The requester withdraws a pending forwarder binding request.",
		Payload:   []string{"action", "forwarder_id", "request_id"},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionForwarderBindRequestExpire,
		Home:      HomeControlPlane,
		Entity:    "forwarder",
		Trigger:   "A forwarder binding request lapses undecided.",
		Payload:   []string{"action", "forwarder_id", "request_id"},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionForwarderAttach,
		Home:      HomeControlPlane,
		Entity:    "forwarder",
		Trigger:   "A run starts with a forwarded device: the hub relays the forwarder's stream to the executor that attaches it and gives it to the run's sandbox.",
		Payload:   []string{"action", "forwarder_id", "binding_id", "project", "executor_id", "handle_id", "run_id"},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionForwarderDetach,
		Home:      HomeControlPlane,
		Entity:    "forwarder",
		Trigger:   "A forwarded device is taken back from a run: the run ended, its binding or forwarder was revoked, or a side disconnected.",
		Payload:   []string{"action", "forwarder_id", "binding_id", "project", "executor_id", "handle_id", "reason"},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
	},
	{
		Action: ActionExecutorUpgrade,
		Home:   HomeControlPlane,
		Entity: "executor",
		Trigger: "The control plane asks an enrolled device to replace its own binary with a " +
			"published release and restart.",
		Payload: []string{"action", "executor_id", "requested_version", "force", "accepted",
			"from_version", "target_version", "reason"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action: ActionExecutorAutoUpdate,
		Home:   HomeControlPlane,
		Entity: "executor",
		Trigger: "An administrator changes whether the control plane upgrades executors " +
			"unattended, which release they converge on, or how many move at once.",
		Payload:   []string{"action", "enabled", "target_version", "max_in_flight"},
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
		Action:  ActionExecutorSandbox,
		Home:    HomeControlPlane,
		Entity:  "executor",
		Trigger: "An admin sets where an executor's payloads run: the device's host, or a container on it.",
		// `from` and `to` are rendered descriptions of the whole configuration,
		// not just the mode, because the runtime is what decides whether a
		// container is behind a hypervisor — a change from runc to kata is a
		// change of boundary with the mode untouched.
		Payload:   []string{"action", "executor_id", "from", "to", "mode", "cleared"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "One of two executor actions that record their previous value: it changes a containment " +
			"boundary, so `from` is what makes \"when did this device stop isolating its workloads\" " +
			"answerable from the trail alone. `cleared` is true when the configuration was removed " +
			"rather than replaced.",
	},
	{
		Action:    ActionExecutorLimits,
		Home:      HomeControlPlane,
		Entity:    "executor",
		Trigger:   "An admin sets the most CPU, memory, disk and processes any one workload on an executor may be given.",
		Payload:   []string{"action", "executor_id", "from", "to", "cleared"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "Records its previous ceiling as well as the new one. A raised cap is the change worth " +
			"reviewing, and it is invisible in the new value alone. `cleared` is true when the " +
			"ceiling was removed, which makes the executor uncapped rather than capped at zero.",
	},
	{
		Action:    ActionExecutorAudience,
		Home:      HomeControlPlane,
		Entity:    "executor",
		Trigger:   "An admin admits a user or group to an executor, or withdraws one.",
		Payload:   []string{"action", "executor_id", "principal_kind", "principal_value", "restricted", "members"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "`action` is \"admit\" or \"withdraw\"; `restricted` is whether the executor is " +
			"access-controlled *after* the change, and `members` how many principals remain. " +
			"Withdrawing the last entry sets restricted=false, which widens the executor to the " +
			"whole fleet — the one edit here that grants rather than revokes.",
	},
	{
		Action:    ActionExecutorLabels,
		Home:      HomeControlPlane,
		Entity:    "executor",
		Trigger:   "An admin replaces an enrolled device's labels, the ones label grants are matched against.",
		Payload:   []string{"action", "executor_id", "from", "to", "leases", "sessions", "taken_back"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "`from` and `to` are the device's labels before and after. `leases` and `sessions` count the " +
			"live secret leases and egress sessions — the device's and its virtual executors' — that were " +
			"re-judged by the new labels, and `taken_back` how many label grants they no longer matched; each " +
			"of those has its own lease.revoke_sent or egress.close row naming the grant.",
	},
	{
		Action:    ActionExecutorVirtual,
		Home:      HomeControlPlane,
		Entity:    "executor",
		Trigger:   "An admin creates, edits or deletes a virtual executor on an enrolled device.",
		Payload:   []string{"action", "executor_id", "parent_id", "name", "from", "to", "reason"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "`action` is \"create\", \"update\", \"delete\" or \"constrain\". `from` and `to` describe the " +
			"whole configuration — sandbox, firewall allow and deny lists, devices — so a widened firewall or an " +
			"added device is visible from this row alone. `reason` is set when the change was not asked for " +
			"directly: a device's virtual executors are deleted with it when it is revoked, and narrowed " +
			"(\"constrain\") when its firewall is tightened below what they allowed.",
	},
	{
		Action:    ActionExecutorFirewall,
		Home:      HomeControlPlane,
		Entity:    "executor",
		Trigger:   "An admin sets or clears a device's firewall rule set, the superset every sandbox on it must fit inside.",
		Payload:   []string{"action", "executor_id", "from", "to", "fingerprint", "cleared", "constrained"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "`from` and `to` describe the whole rule set — allowlist, denylist, ports, resolvers and the " +
			"public-Internet switch — so a widened device is legible from this row alone. `cleared` is true " +
			"when the rule set was removed, which leaves the device bounded only by its configuration. " +
			"`constrained` counts the virtual executors and project rule sets the save narrowed to fit; " +
			"each of those has its own row (`executor.virtual` with action \"constrain\", " +
			"`project.firewall` with action \"constrain\").",
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
		Action: ActionExecutorIsolationVerdict,
		Home:   HomeControlPlane,
		Entity: "executor",
		Trigger: "The isolation probe, run under an executor's runtime at reconcile, at a device's hello, " +
			"after a runtime change, daily or on request, reaches a verdict that differs from the last one " +
			"recorded for that executor and runtime.",
		Payload:   []string{"runtime", "claim", "verdict", "status", "previous_verdict", "previous_status", "point", "detail"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "`claim` is what the runtime's name claims (vm, userspace-kernel, host-kernel) and `verdict` what " +
			"the probe found; `status` is contradicted when the evidence shows less isolation than the claim, " +
			"which refuses projects that require kernel isolation or virtualization. `previous_*` are empty " +
			"for an executor's first verdict. A probe that could not run is recorded on the evidence row, " +
			"not here.",
	},
	{
		Action:    ActionExecutorFailover,
		Home:      HomeControlPlane,
		Entity:    "executor_session",
		Trigger:   "A session is moved off an executor that stopped answering, or fails to be placed anywhere.",
		Payload:   []string{"session_id", "from", "to", "attempt", "max_attempts", "project_path", "task_id", "running_tasks", "placed", "acted_for", "error"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "`placed` distinguishes a successful move from one with nowhere to go; then `to` is empty and `error` says why. " +
			"On a hub with single sign-on `acted_for` names whom the replacement acts for — the person who started the " +
			"run it continues, whose Claude account it runs on — and is absent when it acts for no one. " +
			"A session past executors.failover.max_attempts is recorded as executor.failover_exhausted instead.",
	},
	{
		Action:  ActionExecutorFailoverExhausted,
		Home:    HomeControlPlane,
		Entity:  "executor_session",
		Trigger: "An executor goes unreachable holding a session that was already re-dispatched as often as executors.failover.max_attempts allows, so nothing re-dispatches it.",
		Payload: []string{
			"session_id", "from", "attempt", "max_attempts", "project_path", "running_tasks", "nodes", "error",
		},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "`nodes` names every executor the run was lost on, oldest first, each with when it went unreachable. " +
			"A workload that takes down every node it lands on ends here instead of on the next node.",
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
		Trigger:   "A live lease is renewed before it expires: re-issued to the same holder, extended in place while its run is live, or taken over by the hub process that adopted its run after the one holding it stopped. Also a credential renewed in place: a GitHub App installation token re-minted, or a Kubernetes share's ServiceAccount token replaced — by the hub at half its life, or by its owner from the terminal.",
		Payload:   secretPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "A Kubernetes share's renewal (Task 20416) is attributed to `hub` when the hub renewed it and to the owner " +
			"when they pushed a token with `cloop remote kube renew`; `reason` names the ServiceAccount and both " +
			"expiries, `expires_at` the new one. A renewal that failed is a `deny` row, written once per distinct cause.",
	},
	{
		Action:    ActionSecretRelease,
		Home:      HomeControlPlane,
		Entity:    "secret",
		Trigger:   "A workload finishes with a lease and it is dropped from the server-side record — or a recorded lease nobody holds any more is retired: its run ended while no hub process held it, or it lapsed after its holder stopped.",
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
		Action:    ActionSecretUnguardedAck,
		Home:      HomeControlPlane,
		Entity:    "secret",
		Trigger:   "An administrator records that a kubeconfig grant whose namespaces or verbs only the Kubernetes access monitor enforces may be delivered on a hub that runs no monitor — or the attempt is refused.",
		Payload:   secretPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "Without it such a grant is refused at every lease (Task 20420). `reason` names what goes unenforced and " +
			"the administrator's own justification; `grant_id` the grant, which carries the acknowledgement until it " +
			"is withdrawn.",
	},
	{
		Action:    ActionSecretUnguardedWithdraw,
		Home:      HomeControlPlane,
		Entity:    "secret",
		Trigger:   "An unguarded acknowledgement on a kubeconfig grant is withdrawn, so the grant is refused again on a hub with no Kubernetes access monitor.",
		Payload:   secretPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
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
	{
		Action:  ActionLeaseRefresh,
		Home:    HomeControlPlane,
		Entity:  "lease",
		Trigger: "A GitHub App token re-minted before its hour ran out is delivered to an executor holding the lease's token file, or cannot be.",
		Payload: []string{"decision", "lease_id", "grant_id", "executor_id", "project_id", "files", "handles",
			"eventual", "error", "reason"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "The re-mint itself is a secret.renew row; this one says whether the workload got the new token. " +
			"A deny means it did not — an agent too old for the refresh frame, a device offline, a Role without " +
			"patch on secrets — and the run's GitHub access ends when the token it holds expires.",
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
	{
		Action:    ActionEgressRenew,
		Home:      HomeControlPlane,
		Entity:    "secret",
		Trigger:   "A hub renews a live proxy session for a run that is still going, after re-reading its grant.",
		Payload:   secretPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "Allowed rows carry the new `expires_at`. A refused renewal is a `deny` row; " +
			"the session it concerned then closes with an `egress.close` row saying why.",
	},
	{
		Action:    ActionEgressRestore,
		Home:      HomeControlPlane,
		Entity:    "secret",
		Trigger:   "The hub process that adopted a run after the one serving it stopped restores the run's proxy session, after re-reading its grant.",
		Payload:   secretPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "Allowed rows carry the counters the session resumes from (`bytes_up`, `bytes_down`), " +
			"which keep counting against the grant's quota, and the reason names the process that held it. " +
			"A `deny` row is a session that will not come back: its grant was revoked or expired, or it " +
			"lapsed, while no hub process held it (Task 20383).",
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
		Note: "Also written for a session that ended while no hub process served it — not restored with " +
			"its run, or retired by the leader's janitor once it lapsed — with the reason in `detail`.",
	},
	{
		Action:    ActionGitProxySessionRestored,
		Home:      HomeControlPlane,
		Entity:    "gitproxy",
		Trigger:   "The hub process that adopted a run restores the run's proxy session under its original id and token, with an upstream credential re-derived from the run's lease.",
		Payload:   gitProxyPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "`detail` names the hub process that held the session until then. A session that could not " +
			"be restored gets a `gitproxy.session_closed` row instead (Task 20383).",
	},
	{
		Action:    ActionGitProxySessionRenewed,
		Home:      HomeControlPlane,
		Entity:    "gitproxy",
		Trigger:   "A workspace's pinned proxy session nears its end while its run is still alive, and the hub renews it for another session_minutes.",
		Payload:   gitProxyPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "`detail` gives the new deadline. Renewed only while the workspace lease it stands on is kept alive " +
			"and the run's executor still holds the workload; the session is closed once the run is done with it " +
			"(Task 20422).",
	},
	{
		Action:    ActionGitProxyPushAllowed,
		Home:      HomeControlPlane,
		Entity:    "gitproxy",
		Trigger:   "A push is checked against the session's branch allowlist, scanned for the credentials its run was given (unless executors.git_proxy.push_scan is off), and forwarded.",
		Payload:   gitProxyPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionGitProxyPushDenied,
		Home:      HomeControlPlane,
		Entity:    "gitproxy",
		Trigger:   "A push is refused because it names a ref the session may not write — or because its pack could not be scanned for the run's credentials: past a push_scan limit, or unreadable.",
		Payload:   gitProxyScanPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "The row that matters in this family: it is the only place a sandbox's " +
			"attempt to write outside its lane is recorded. `refs` names what it tried to push. A push the " +
			"scan could not finish carries `scan` (`limit` or `unreadable`) and `run_id`, and `detail` names " +
			"the limit and its setting (Task 20436).",
	},
	{
		Action:    ActionGitProxyPushSecretRefused,
		Home:      HomeControlPlane,
		Entity:    "gitproxy",
		Trigger:   "A push the branch policy allowed is refused because it carries a credential the session's run was given: an env value, a kubeconfig token or client key, registry auth, an egress proxy credential, a GitHub token — as delivered, base64-encoded or percent-encoded — found in a commit, tree, blob, tag, delta insert, ref name or push option.",
		Payload:   gitProxyScanPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "`findings` name each object, its path and commit where the pack says, and the grant and secret " +
			"the value came from; nothing records the value. The forge got no complete pack and no ref moved. " +
			"A push refused because it could not be scanned — past a `push_scan_*` limit, or a pack the proxy " +
			"cannot read — is a `gitproxy.push_denied` row with `scan` set (Task 20436).",
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
		Note:      "Also written for a session that ended while no hub process served it, with the reason in `detail`.",
	},
	{
		Action:    ActionKubeGuardSessionRestored,
		Home:      HomeControlPlane,
		Entity:    "kubeguard",
		Trigger:   "The hub process that adopted a run restores the run's Kubernetes proxy session under its original id and token, with the cluster credential re-derived from the run's lease and its policy narrowed to what the grant and the hub allow now.",
		Payload:   kubeGuardPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "`detail` names the hub process that held the session until then (Task 20383).",
	},
	{
		Action:    ActionKubeGuardRequestDenied,
		Home:      HomeControlPlane,
		Entity:    "kubeguard",
		Trigger:   "A Kubernetes request is refused by the session's verb and resource policy, or because it would hand the workload a credential of its own.",
		Payload:   kubeGuardPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "This is what enforces a read-only grant on a cluster from outside the sandbox: `verb`, `resource` and `namespace` say exactly what was attempted. `reason` classifies it; `service_account_token_secret`, `workload_service_account`, `host_access`, `rbac_binding`, `rbac_role`, `certificate_signing_request` and `unreadable_body` are a write grant's attempts to obtain a credential that would bypass the monitor (Task 20420).",
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
		Note: "Also written for a suspended session — one no hub process serves — whose record the " +
			"revocation ends, so its job's next call is refused rather than restored (Task 20390).",
	},
	{
		Action:    ActionCISessionSuspended,
		Home:      HomeControlPlane,
		Entity:    "ci_session",
		Trigger:   "A hub process stops serving a recorded relay session without ending it here: it is stopping gracefully, and the session's spend is written and its record stays open; or the record was closed or taken over by another hub process, whose row says why.",
		Payload:   ciPayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note: "After a graceful stop the session is restored by the hub process that receives its job's next call " +
			"(Task 20390); a session with no record is closed instead, with a `ci.session.closed` row. One whose " +
			"record another process closed or took over is ended, or served, there.",
	},
	{
		Action:    ActionCISessionRestored,
		Home:      HomeControlPlane,
		Entity:    "ci_session",
		Trigger:   "A hub process receives a call presenting the token of a recorded relay session whose holder stopped, takes the record over, holds the session to its rule as the rule stands now, and serves it under its original id and token.",
		Payload:   ciPayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note: "`detail` names the hub process that held it until then and anything its rule narrowed. A " +
			"session whose rule was deleted, disabled or no longer admits the pipeline gets a " +
			"`ci.session.closed` row instead, and its call a 401 (Task 20390).",
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

	// ── model_relay ────────────────────────────────────────────────────────
	// The hub's model relay for sandboxed runs (Task 20435): a run's Claude
	// credential stays on the hub, and the sandbox presents a session that
	// stands on the run's lease. A relayed call that is allowed is counted in
	// the session and the relay's metrics, not written here one row per call:
	// a run makes hundreds, and what a reviewer needs is the decisions.
	{
		Action:    ActionModelRelaySessionMinted,
		Home:      HomeControlPlane,
		Entity:    "model_relay_session",
		Trigger:   "A run on an isolating executor is dispatched with a model relay session in place of its Claude credential.",
		Payload:   modelRelayPayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionModelRelaySessionClosed,
		Home:      HomeControlPlane,
		Entity:    "model_relay_session",
		Trigger:   "A run's relay session ends: its run ended or did not start, its lease was released, revoked or lapsed, its grant was revoked, or it expired.",
		Payload:   modelRelayPayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note: "`input_tokens` and `output_tokens` are what the session spent in all, as the API counted it; " +
			"`input_tokens` includes cache reads and writes.",
	},
	{
		Action:    ActionModelRelaySessionSuspended,
		Home:      HomeControlPlane,
		Entity:    "model_relay_session",
		Trigger:   "A hub process stops serving a recorded relay session without ending it: it is stopping gracefully, or another process took the session's record over with the run's lease.",
		Payload:   modelRelayPayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionModelRelaySessionRestored,
		Home:      HomeControlPlane,
		Entity:    "model_relay_session",
		Trigger:   "The hub process adopting a run takes its relay session over with the run's lease, re-deriving the credential from the grant and holding the session to today's model allowlist.",
		Payload:   modelRelayPayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionModelRelayDenied,
		Home:      HomeControlPlane,
		Entity:    "model_relay_session",
		Trigger:   "A relayed model call is refused before it reaches the API: its model is not allowed, the identity paying for the run has spent a daily budget, or the request is not one a run may make.",
		Payload:   modelRelayPayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note:      "`reason` is the relay's refusal code: `budget_exhausted`, `model_not_allowed`, `path_not_allowed`, `method_not_allowed`, `body_too_large` or `body_malformed`.",
	},
	{
		Action:    ActionModelRelayRejected,
		Home:      HomeControlPlane,
		Entity:    "model_relay_session",
		Trigger:   "A model call presents the token of a relay session that has ended, and is refused with the reason it ended.",
		Payload:   modelRelayPayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note:      "A call with no usable token at all is counted in `cloop_model_relay_requests_total` and not written here.",
	},
	{
		Action:    ActionModelRelayUsageGap,
		Home:      HomeControlPlane,
		Entity:    "project",
		Trigger:   "A relayed run ends and the usage it reported to its project's ledger differs from what the relay counted from the API's own responses.",
		Payload:   []string{"project", "run_id", "session_ids", "payer", "relay_tokens", "relay_usd", "reported_tokens", "reported_usd", "gap_tokens", "gap_usd"},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note: "The relay's count is what the payer was charged; the run's ledger gains a row bringing its total to it. " +
			"A claudecode run reports no tokens at all, so its whole relayed spend shows as the gap.",
	},
	{
		Action:    ActionModelRelayNotRelayed,
		Home:      HomeControlPlane,
		Entity:    "project",
		Trigger:   "The model relay is on, and a run on an isolating executor is dispatched with its Claude credential delivered to the sandbox as before.",
		Payload:   []string{"project", "run_id", "executor_id", "credential_kind", "reason"},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note: "`reason` says why: the credential's kind has not been proven through the relay against the real API, " +
			"or the device's agent predates handing the hub's CA to the harness.",
	},
	{
		Action:    ActionModelRelayModelsSet,
		Home:      HomeControlPlane,
		Entity:    "project",
		Trigger:   "A project's maintainer narrows, or clears, the models its relayed runs may use.",
		Payload:   []string{"project", "models"},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note:      "An empty `models` clears the project's list, and the hub's allowlist applies to its runs again.",
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
		Payload:   []string{"name", "roles", "project_scope", "expires_at", "kind", "owner", "minted_under"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "`kind` distinguishes a service-account token from a glasses link, which is a token with one " +
			"narrow role and a URL as its only delivery mechanism. `minted_under` is `policy` when the hub's " +
			"role policy was in force, `no_policy` when it was not, `operator` from the CLI (Task 20422).",
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
			"action by `ip` is the credential-stuffing signal. `awaiting_approval` is a token " +
			"minted with no role policy in force, refused on a hub that enforces one until an " +
			"administrator approves it.",
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
	{
		Action:    ActionAPITokenApproved,
		Home:      HomeControlPlane,
		Entity:    "api_token",
		Trigger:   "An administrator approves a token minted with no role policy in force, which a hub enforcing one refuses until then (Task 20422).",
		Payload:   []string{"name", "roles", "project_scope", "minted_under", "created_by", "created_at", "via"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "From the dashboard the approver must hold every role the token carries, under the policy now in " +
			"force; `via: cli` is an operator at the control plane.",
	},
	{
		Action:    ActionAPITokenApproveDenied,
		Home:      HomeControlPlane,
		Entity:    "api_token",
		Trigger:   "An approval is refused: no role policy is in force, or the approver does not hold the token's roles.",
		Payload:   []string{"reason", "roles", "project_scope"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},

	// ── static_token ───────────────────────────────────────────────────────
	// The deprecated --token / CLOOP_UI_TOKEN: an administrator credential
	// outside RBAC with no expiry. Retiring it is the one lifecycle event it
	// has, and the only way to end it short of redeploying every member.
	{
		Action:    ActionStaticTokenRetired,
		Home:      HomeControlPlane,
		Entity:    "static_token",
		Trigger:   "The static admin token is retired, from the Settings card or `cloop hub token static retire`.",
		Payload:   []string{"fingerprint", "reason", "via", "forced", "self", "os_user"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "Filed against the token's fingerprint — a SHA-256 of the value, never the value. " +
			"`self` is true when the static token retired itself; `forced` when the retirement " +
			"overrode the refusal to leave a hub without single sign-on or an admin API token " +
			"with no way in. Recorded in the same commit as the retirement, so a retirement " +
			"with no row cannot happen.",
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
		Note: "`prior_role` and `role` bracket the demotion; `dropped_claims` names what the IdP stopped asserting. " +
			"`via` is `browser_renewal` when the narrowed claims arrived through a silent renewal from the " +
			"user's browser, and absent when the hub's own refresh found them.",
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
	{
		Action:    ActionSessionRenewalMismatch,
		Home:      HomeControlPlane,
		Entity:    "session",
		Trigger:   "A silent renewal from the user's browser is answered by the identity provider for a different subject than the session belongs to.",
		Payload:   sessionPayload,
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "The session is left exactly as it was: nothing of the other identity is applied or recorded. " +
			"The benign reading is a user who switched accounts at the provider in another tab; the other is a " +
			"browser signed into somebody else's account at the provider in the hope that the renewal adopts it. " +
			"`ip` and `user_agent` are the browser that performed the renewal.",
	},
	{
		Action:    ActionSessionReauth,
		Home:      HomeControlPlane,
		Entity:    "session",
		Trigger:   "A privileged request reaches the hub on a session whose last interactive sign-in is older than `ui.oidc.sudo_max_age_minutes` (sudo mode), or the confirm-it's-you sign-in that answers one completes.",
		Payload:   reauthPayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note: "`outcome` is `stale-refused` for the refused request — `method` and `path` name it, `authenticated_at` is " +
			"the session's last interactive sign-in (absent: none on record) and `max_age_seconds` the window it missed; " +
			"at most thirty such rows a minute are written, the next one carrying `suppressed`, while " +
			"`cloop_session_reauth_total` counts every one. `granted` is a sign-in the hub started with " +
			"`prompt=login&max_age=0` that the provider answered for the same person: `session_id` is the fresh " +
			"session it created and `replaces` the one that asked. `refused` is one that did not count — `reason` " +
			"`subject_mismatch` (another account signed in), `not_reauthenticated` (the provider's `auth_time` is older " +
			"than the request, so it did not ask), or `idp_error: <code>`; nothing is created then. API tokens and the " +
			"static token are not sessions and never produce this row.",
	},

	// ── device ─────────────────────────────────────────────────────────────
	// A terminal signing in to a hub with single sign-on (Task 20412). The
	// session it becomes is an ordinary session row of kind "cli", so its
	// creation, expiry and revocation are the session.* events above; these
	// three are the grant itself — who asked, from where, and who said yes.
	{
		Action:    ActionDeviceCodeIssued,
		Home:      HomeControlPlane,
		Entity:    "device_authorization",
		Trigger:   "A terminal asks the hub for a sign-in code (`cloop login`): POST /api/device/code.",
		Payload:   devicePayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note: "Unauthenticated by design — the terminal has no credential yet — and rate-limited per address. " +
			"`device_id` is a prefix of the device code's digest, never the code; `client_hostname` is what the " +
			"terminal reported and proves nothing.",
	},
	{
		Action:    ActionDeviceApproved,
		Home:      HomeControlPlane,
		Entity:    "device_authorization",
		Trigger:   "A signed-in browser approves a terminal's code at /device and completes the identity provider round trip that writes the CLI session.",
		Payload:   devicePayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note: "`session_id` is the CLI session's id, whose own `session.created` row (kind `cli`, `via` " +
			"`device_grant`) follows; `ip` and `user_agent` are the approving browser's, the `client_*` keys the " +
			"terminal's. `reauth` is true when the browser session was older than " +
			"`ui.oidc.device_approval_max_age_minutes` and the provider was asked for a fresh sign-in.",
	},
	{
		Action:    ActionDeviceDenied,
		Home:      HomeControlPlane,
		Entity:    "device_authorization",
		Trigger:   "A terminal's code is denied at /device, or the hub refuses the approval on the approver's behalf.",
		Payload:   devicePayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note: "`reason` is `denied_at_approval_page` for a person pressing Deny; `identity_refused` when a runtime " +
			"deny binding (an offboarding) matched the approving identity; `session_error` when the session " +
			"could not be written. The actor is `hub` for the last two.",
	},

	// ── request ────────────────────────────────────────────────────────────
	{
		Action:    ActionRequestOriginRefused,
		Home:      HomeControlPlane,
		Entity:    "request",
		Trigger:   "The hub refuses a state-changing request or a WebSocket handshake because a page on another origin made it, or because its body is form data or text/plain.",
		Payload:   requestRefusalPayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note: "The browser that sent it belongs to whoever was using it: the row records the page that asked " +
			"(`origin`, `sec_fetch_site`), not an identity, and `session` says only whether that browser carried " +
			"a sign-in cookie. `reason` is a `cloop_cross_origin_refusals_total` label. Rows are written at most " +
			"30 a minute; `suppressed` counts the refusals since the previous row that were not.",
	},
	{
		Action:    ActionRequestHostRefused,
		Home:      HomeControlPlane,
		Entity:    "request",
		Trigger:   "A hub without sign-in refuses a request addressed to a host name it does not answer to — the shape DNS rebinding takes.",
		Payload:   requestRefusalPayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note: "Only a hub with neither SSO nor a static token checks the Host: rebinding cannot carry a credential " +
			"to a hub that has one. A burst after a new DNS name was pointed at the hub is that name missing from " +
			"`ui.allowed_hosts`. Rate-limited like `request.origin_refused`.",
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
		Action:    ActionResourceCeilingSet,
		Home:      HomeControlPlane,
		Entity:    "project_resource_limit",
		Trigger:   "A per-project resource ceiling is written with `cloop hub limits set`.",
		Payload:   []string{"target", "project", "cpu_millis", "memory_mb", "disk_mb", "pids", "reason", "via", "os_user"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "The values are the merged ceiling that was stored, not the flags that were " +
			"passed: `set` merges onto the existing row, so the flags alone would not say " +
			"what the project ended up capped at.",
	},
	{
		Action:    ActionResourceCeilingCleared,
		Home:      HomeControlPlane,
		Entity:    "project_resource_limit",
		Trigger:   "A per-project ceiling is removed and the project returns to the fleet ceiling alone.",
		Payload:   []string{"target", "project", "reason", "via", "os_user"},
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
	{
		Action: ActionSealingKeyRootChanged,
		Home:   HomeControlPlane,
		Entity: "sealing_key",
		Trigger: "`cloop hub key rotate --retire-previous` finishes a change of root — of CLOOP_SECRET_KEY, onto " +
			"a KMS or off one: every hub member held the new root (and, for a passphrase root, an escrow of it " +
			"was on record), every sealed row was rewrapped onto a key of it, and every key of the previous root " +
			"was retired. Written when the run ends, finished or not.",
		Payload: []string{"root", "previous_root", "minted", "to_key", "rewrapped", "skipped", "failed",
			"retired", "remaining", "members", "escrow_id", "complete", "via"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "Roots are named by fingerprint, the name every checkpoint and escrow carries, never by value, " +
			"and a KMS root by its name (Task 20433), so moving onto a KMS or off one is recorded here too. " +
			"The rotation and each retirement are recorded as sealing_key.rotated and sealing_key.retired as well.",
	},
	{
		Action: ActionSealingKeyKMSRewrapped,
		Home:   HomeControlPlane,
		Entity: "sealing_key",
		Trigger: "A key-encryption key held by a KMS is wrapped again under the key the KMS now encrypts " +
			"under — by the hub's cluster leader when the KMS reports a rotation of its key, or by " +
			"`cloop hub key rewrap`. Nothing sealed under the key changes.",
		Payload:   []string{"key_id", "kms", "from_kms_key", "to_kms_key", "via"},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note: "Carries KMS key ids, never a ciphertext. Once no live key names the KMS's old key version " +
			"in `cloop hub key list`, that version holds nothing of the hub's and can be disabled in the KMS.",
	},
	{
		Action: ActionSealingKeyEscrowed,
		Home:   HomeControlPlane,
		Entity: "sealing_key",
		Trigger: "`cloop hub key escrow export` wraps CLOOP_SECRET_KEY under an operator's passphrase, or " +
			"`cloop hub key escrow verify --record` records a verified escrow again after a restore.",
		Payload:   []string{"escrow_id", "key_fingerprint", "kdf", "created_at", "recorded", "via"},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note: "Carries the key's fingerprint, never the key or the passphrase. `cloop hub doctor` compares " +
			"the escrow on record against the key in use and fails when they differ.",
	},

	// ── hub_ca ─────────────────────────────────────────────────────────────
	// The certificate authority the hub issues its credential monitors'
	// certificates from under tls: auto (Task 20409). Certificates only: the
	// private keys are sealed in hub_tls and appear in no payload.
	{
		Action:    ActionHubCAMinted,
		Home:      HomeControlPlane,
		Entity:    "hub_ca",
		Trigger:   "A hub process mints the control plane's certificate authority, the first time any starts a credential monitor under `tls: auto`.",
		Payload:   []string{"serial", "not_after", "fingerprint"},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note: "Every sandbox is told to trust this CA for the monitors' URLs, so a second `hub_ca.minted` row " +
			"for one control plane — its `hub_tls` table lost or restored without it — means sandboxes " +
			"holding the previous CA will refuse the next certificate the monitors serve.",
	},
	{
		Action:    ActionHubCALeafIssued,
		Home:      HomeControlPlane,
		Entity:    "hub_ca",
		Trigger:   "A hub process issues a credential monitor's serving certificate from the hub CA: at its first start, when the cluster leader renews one, when a member needs a name the stored one lacks, or when a rotation activated another CA.",
		Payload:   []string{"monitor", "serial", "names", "not_after", "replaced", "issuer", "reason"},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note: "`reason` is first, renewal, names, activation or unreadable; `issuer` is the serial of the CA that " +
			"signed it.",
	},
	{
		Action:    ActionHubCARotationStaged,
		Home:      HomeControlPlane,
		Entity:    "hub_ca",
		Trigger:   "`cloop hub ca rotate --stage` (or Settings → Hub health) mints a CA to replace the hub's, sealed under the KEK registry like the first (Task 20438).",
		Payload:   []string{"rotation", "from", "to", "fingerprint", "not_after", "names", "emergency", "via"},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note: "From this row on every dispatch trusts both CAs; leaves still come from `from`. `names` are the new " +
			"CA's X.509 name constraints, empty when it was minted without them.",
	},
	{
		Action:    ActionHubCARotationActivated,
		Home:      HomeControlPlane,
		Entity:    "hub_ca",
		Trigger:   "`cloop hub ca rotate --activate` makes the staged CA the one leaves are issued from; the cluster leader then reissues every leaf.",
		Payload:   []string{"rotation", "from", "to", "forced", "emergency", "via"},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note: "`forced` names the runs dispatched before the stage that an operator activated past with --force: " +
			"they stop verifying the credential monitors.",
	},
	{
		Action:    ActionHubCAPreviousRetired,
		Home:      HomeControlPlane,
		Entity:    "hub_ca",
		Trigger:   "`cloop hub ca rotate --retire-previous` deletes the replaced CA with secure_delete on, so its sealed key is gone from the database file, and drops it from every bundle.",
		Payload:   []string{"rotation", "retired", "active", "cut_runs", "emergency", "via"},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note:      "A backup taken before this row still holds the retired CA's sealed key.",
	},
	{
		Action:    ActionHubCARotationAbandoned,
		Home:      HomeControlPlane,
		Entity:    "hub_ca",
		Trigger:   "`cloop hub ca rotate --abort` destroys a staged CA that was never activated, or an emergency rotation abandons one.",
		Payload:   []string{"rotation", "abandoned", "active", "detail", "emergency", "via"},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionHubCAEmergencyRotated,
		Home:      HomeControlPlane,
		Entity:    "hub_ca",
		Trigger:   "`cloop hub ca rotate --now` replaces every hub CA at once with a fresh one, for a key believed compromised.",
		Payload:   []string{"rotation", "replaced", "active", "names", "cut_runs", "via"},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note: "Alert on it. `cut_runs` are the runs that trusted only the replaced CAs; each hub member ends their " +
			"proxy sessions and records `hub_ca.sessions_ended`.",
	},
	{
		Action:    ActionHubCASessionsEnded,
		Home:      HomeControlPlane,
		Entity:    "hub_ca",
		Trigger:   "A hub member ends the git proxy, Kubernetes monitor and model relay sessions of the runs an emergency rotation named, within a minute of it.",
		Payload:   []string{"rotation", "member", "runs", "git_proxy", "kube_guard", "model_relay"},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note: "Counts per monitor are what this member held; a run's sessions on another member are in that " +
			"member's row.",
	},

	// ── oidc ───────────────────────────────────────────────────────────────
	{
		Action:  ActionOIDCConfigUpdated,
		Home:    HomeControlPlane,
		Entity:  "config",
		Trigger: "The hub's single sign-on configuration is changed, from the Settings panel or `cloop config set ui.oidc.*`.",
		Payload: []string{"changed", "enabled", "was_enabled", "issuer", "default_role",
			"admin_emails", "role_mappings", "require_idp", "require_rbac", "rbac_enforced",
			"was_rbac_enforced", "restart_required"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "`changed` lists the field names that moved, so the row answers what was touched without storing two copies of the block. " +
			"The client secret appears in `changed` when it moves and nowhere else — not its value, not its length. " +
			"`admin_emails` and `role_mappings` are counts, not contents. " +
			"`rbac_enforced` and `was_rbac_enforced` say whether the saved block puts a role policy in force after and before the change, " +
			"so the rows where RBAC switched on or off are a filter, not a reconstruction; the Settings panel makes either switch only " +
			"when the request confirms it. " +
			"`restart_required` records whether the change was live yet, because the authenticator is built at startup: " +
			"a row with it set means the hub was still running the previous configuration when the change landed.",
	},
	{
		Action:  ActionOIDCRBACEnforced,
		Home:    HomeControlPlane,
		Entity:  "config",
		Trigger: "An admin enforces deny-by-default from Settings → Single sign-on on a hub whose single sign-on ran without a role policy: `default_role: none`, plus a hub-wide admin mapping for them unless they already hold admin.",
		Payload: []string{"issuer", "default_role", "bound", "admin_emails", "role_mappings",
			"restart_required"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "It changes ui.oidc as `oidc.config.updated` does, and is written instead of it, so a query for who last changed " +
			"single sign-on reads both. `bound` is the mapping added for the acting admin as `sub=<subject>` — the subject, " +
			"because an email can be renamed at some providers — and empty when they were already an admin. " +
			"`admin_emails` and `role_mappings` are counts. Not live until the hub restarts, which `restart_required` records.",
	},

	// ── telemetry ──────────────────────────────────────────────────────────
	{
		Action:    ActionTelemetryConfigUpdated,
		Home:      HomeControlPlane,
		Entity:    "config",
		Trigger:   "Front-end telemetry collection is switched on or off, or narrowed to particular front ends, from Settings → Telemetry.",
		Payload:   []string{"enabled", "was_enabled", "sources", "was_sources"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "Collection is off unless an operator turned it on, and this row is when they did. " +
			"It exists so that \"was this hub recording its users at the time, and who decided that\" is answerable afterwards — " +
			"including by the people who were recorded. " +
			"`sources` is empty when every front end is collected. A save that changed nothing emits no row.",
	},

	// ── notifications ──────────────────────────────────────────────────────
	{
		Action:    ActionNotificationsConfigUpdated,
		Home:      HomeControlPlane,
		Entity:    "config",
		Trigger:   "The webhooks the hub tells approvers through — when a grant request or an API token waits on them — are added, changed or removed, or the dashboard link they carry is, from Settings → Notifications.",
		Payload:   []string{"webhooks", "was_webhooks", "url_changed", "dashboard_url", "was_dashboard_url"},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note: "A webhook decides where a stream about who asked for which credential leaves the hub, so this row is when " +
			"that destination was chosen, and by whom. Each webhook is described as `name (type) scheme://host`, or " +
			"`secret:<name>` when its URL is kept in the secret store, with its events and allowed addresses — never " +
			"the URL itself, which is the channel's credential. `url_changed` names the webhooks whose URL was " +
			"replaced. A save that changed nothing emits no row.",
	},

	// ── disk ───────────────────────────────────────────────────────────────
	{
		Action:    ActionDiskFloorUpdated,
		Home:      HomeControlPlane,
		Entity:    "config",
		Trigger:   "The hub's free-space floor (orchestrator.min_free_disk_mb) is changed from Settings → Disk & Retention.",
		Payload:   []string{"min_free_disk_mb", "was_min_free_disk_mb", "file"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "0 means the check is off: runs then start on any disk, and a task's outcome written onto a full one " +
			"has no reserve to fall back on. `file` names where the value was written — the hub's per-instance " +
			"overlay or config.yaml. A save that changed nothing emits no row.",
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
		Action:  ActionUserOffboard,
		Home:    HomeControlPlane,
		Entity:  "user",
		Trigger: "An identity is offboarded, summarising every surface the operation touched.",
		Payload: append([]string{"sessions", "tokens", "glasses", "denies", "leases", "tasks", "projects", "memberships",
			"personal_secrets", "personal_grants", "grant_requests", "claude_homes", "legal_hold", "warnings"}, offboardPayload...),
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
	// The stored footprint (Task 20400): what the identity keeps on the hub
	// rather than holds open. Written after the credential transaction, one
	// row per part that changed, so a partial run says which part survived.
	{
		Action:    ActionUserOffboardGrant,
		Home:      HomeControlPlane,
		Entity:    "user",
		Trigger:   "Offboarding revokes every live grant over the identity's personal secrets, under a legal hold too.",
		Payload:   append([]string{"count", "grants"}, offboardPayload...),
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "Each grant also has its own `secret.revoke` row from the broker, naming the reason. `grants` names each " +
			"one with its secret and subject, which is where a shared project that loses the credential shows up.",
	},
	{
		Action:    ActionUserOffboardSecret,
		Home:      HomeControlPlane,
		Entity:    "user",
		Trigger:   "Offboarding destroys the identity's personal secrets through the broker.",
		Payload:   append([]string{"count", "secrets", "action"}, offboardPayload...),
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "Each secret also has its own `secret.delete` row. The sealed columns are overwritten before the row is " +
			"deleted, and a tombstone keeps the name so a later lease can say which credential a project lost. " +
			"Not written under a legal hold — `user.offboard_hold` says what was kept instead.",
	},
	{
		Action:    ActionUserOffboardRequest,
		Home:      HomeControlPlane,
		Entity:    "user",
		Trigger:   "Offboarding withdraws the self-service grant requests the identity left pending.",
		Payload:   append([]string{"count", "requests"}, offboardPayload...),
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "Each request also has a `secret.request_withdraw` row whose reason says it was withdrawn at offboarding rather than by its requester.",
	},
	{
		Action:  ActionUserOffboardClaude,
		Home:    HomeControlPlane,
		Entity:  "user",
		Trigger: "Offboarding ends the identity's Claude Code logins on every hub member: cancels one in flight, logs each home out and removes it.",
		Payload: append([]string{"copies", "removed", "logged_out", "logins_cancelled", "unreached", "kept"},
			offboardPayload...),
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "`copies` names each home by member and directory with what became of it. `unreached` lists hub members " +
			"that could not be asked — a copy there may still hold a refresh token.",
	},
	{
		Action: ActionUserClaudeHomeSwept,
		Home:   HomeControlPlane,
		Entity: "user",
		Trigger: "A hub member, as it starts and then hourly, removes from its own tree the Claude Code home of an " +
			"identity the control plane denies hub-wide — a copy an offboarding did not reach.",
		Payload: []string{"identity", "member", "host", "dir", "denies", "had_login", "login_cancelled",
			"logged_out", "logout", "removed", "error", "trigger"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "One row per home, `trigger` `startup` or `timer`. `logout` says why it was not logged out at Anthropic " +
			"first — strict no-host-execution, a symbolic link — and `error` why it could not be removed, which the " +
			"next sweep tries again. An identity under a legal hold, or denied only by a SCIM suspension still in " +
			"force, keeps its home; `cloop hub doctor` reports the homes left on its host (offboard.claude_homes).",
	},
	{
		Action:    ActionUserOffboardHold,
		Home:      HomeControlPlane,
		Entity:    "user",
		Trigger:   "An offboarding runs under a legal hold (`--keep-credentials`): access is severed and the stored credentials are kept.",
		Payload:   append([]string{"secrets", "claude_homes", "grants_revoked", "requests_withdrawn"}, offboardPayload...),
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "Written whether or not anything was found to keep, so whether a hold was in force does not depend on what the person had stored.",
	},

	{
		Action:    ActionUserHoldPlace,
		Home:      HomeControlPlane,
		Entity:    "user",
		Trigger:   "A legal hold is placed on an identity, or its reason restated (`cloop hub user hold`), or an offboarding run with --keep-credentials records the hold it was given.",
		Payload:   []string{"identity", "hold_reason", "placed_at", "reason", "via", "os_user", "identity_input", "subjects", "emails"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "Every offboarding of the identity from then on — an operator's, the identity provider " +
			"deleting the account, or ui.oidc.scim.offboard_after_days — keeps its personal secrets and " +
			"Claude Code homes, as --keep-credentials does, and writes user.offboard_hold; so does every hub " +
			"member's sweep of denied identities' Claude homes (Task 20422). An offboarding asked to keep " +
			"credentials records its hold here before it denies anything, carrying the run's reason as " +
			"hold_reason and the identity's resolved spellings.",
	},
	{
		Action:    ActionUserHoldRelease,
		Home:      HomeControlPlane,
		Entity:    "user",
		Trigger:   "A legal hold is released.",
		Payload:   []string{"identity", "hold_reason", "placed_at", "placed_by", "reason", "via", "os_user"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},

	// ── scim ───────────────────────────────────────────────────────────────
	// SCIM 2.0 provisioning (Task 20415). Every change the identity provider
	// makes is one row, written in the transaction that applies it, with
	// actor scim:<credential name>; a deactivation's row lists everything the
	// hub severed with it.
	{
		Action:    ActionSCIMCredentialCreate,
		Home:      HomeControlPlane,
		Entity:    "scim_credential",
		Trigger:   "A SCIM bearer credential is minted for an identity provider.",
		Payload:   []string{"id", "name", "reason", "via", "os_user"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "The secret is shown once and stored only as an HMAC; no row carries it.",
	},
	{
		Action:    ActionSCIMCredentialRotate,
		Home:      HomeControlPlane,
		Entity:    "scim_credential",
		Trigger:   "A SCIM credential's secret is replaced.",
		Payload:   []string{"id", "name", "grace_seconds", "previous_valid_until", "reason", "via", "os_user"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionSCIMCredentialRevoke,
		Home:      HomeControlPlane,
		Entity:    "scim_credential",
		Trigger:   "A SCIM credential is revoked, both its secrets at once.",
		Payload:   []string{"id", "name", "reason", "via", "os_user"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionSCIMRequestRefused,
		Home:      HomeControlPlane,
		Entity:    "scim",
		Trigger:   "A request to /scim/v2 is refused before it reaches the directory.",
		Payload:   []string{"reason", "method", "path", "ip", "user_agent", "client", "suppressed"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "reason is unauthenticated, unknown, revoked, locked_out (a wrong credential past SCIM's own " +
			"lockout), rate_limited, unavailable (the credential store could not be read) or sso_disabled. " +
			"At most 30 rows a minute; suppressed counts the ones the limit did not write.",
	},
	{
		Action:    ActionSCIMUserCreate,
		Home:      HomeControlPlane,
		Entity:    "scim_user",
		Trigger:   "The identity provider provisions a user.",
		Payload:   []string{"id", "user_name", "external_id", "email", "active", "match_claim", "match_value"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "A user provisioned inactive is suspended at once, and gets a scim.user_suspend row too.",
	},
	{
		Action:  ActionSCIMUserUpdate,
		Home:    HomeControlPlane,
		Entity:  "scim_user",
		Trigger: "The identity provider changes a provisioned user's attributes with PUT or PATCH.",
		Payload: []string{"id", "user_name", "external_id", "email", "active", "method", "changed",
			"match_claim", "match_value"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:  ActionSCIMUserSuspend,
		Home:    HomeControlPlane,
		Entity:  "scim_user",
		Trigger: "The identity provider deactivates a user (active: false).",
		Payload: []string{"id", "user_name", "identity", "subjects", "emails", "usernames", "oids", "ambiguous",
			"denies_written", "denies_in_force", "sessions", "api_tokens", "glasses", "grants_suspended",
			"leases", "tasks", "warnings"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "Written in the transaction that writes the deny bindings, deletes the sessions, revokes the " +
			"API tokens and glasses links and suspends the grants over the person's personal secrets. Leases " +
			"and tasks are listed as planned; they end after the commit, and a failure there is " +
			"scim.user_suspend_incomplete. Memberships and stored credentials are kept.",
	},
	{
		Action:    ActionSCIMUserSuspendIncomplete,
		Home:      HomeControlPlane,
		Entity:    "scim_user",
		Trigger:   "A lease or task of a suspended user could not be ended after the suspension committed.",
		Payload:   []string{"id", "user_name", "failures"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:  ActionSCIMUserReactivate,
		Home:    HomeControlPlane,
		Entity:  "scim_user",
		Trigger: "The identity provider reactivates a user (active: true).",
		Payload: []string{"id", "user_name", "denies_lifted", "denies_kept", "grants_resumed", "offboarded_at",
			"note"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "Lifts only what the suspension wrote: a deny an administrator wrote for the same identity " +
			"stays (denies_kept). Sessions, tokens, leases and tasks the suspension ended are not restored, " +
			"and after an offboarding nothing is lifted.",
	},
	{
		Action:    ActionSCIMUserDelete,
		Home:      HomeControlPlane,
		Entity:    "scim_user",
		Trigger:   "The identity provider deletes a user; the full offboarding runs first.",
		Payload:   []string{"id", "user_name", "identity", "legal_hold", "failures"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "The offboarding writes its own user.offboard* rows, with via scim.",
	},
	{
		Action:    ActionSCIMUserOffboardExpired,
		Home:      HomeControlPlane,
		Entity:    "scim_user",
		Trigger:   "A user inactive for ui.oidc.scim.offboard_after_days is offboarded in full.",
		Payload:   []string{"id", "user_name", "identity", "deactivated_at", "legal_hold", "failures"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "The offboarding writes its own user.offboard* rows, with via scim-expiry.",
	},
	{
		Action:    ActionSCIMMatchAmbiguous,
		Home:      HomeControlPlane,
		Entity:    "scim_user",
		Trigger:   "A provisioned user's match value addresses more than one hub identity.",
		Payload:   []string{"id", "user_name", "match_claim", "match_value", "subjects", "emails", "operation"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "The hub does not choose among them: it acts on the matched claim alone — a deny binding on " +
			"it, and what carries it — and grants the user's provisioned groups to nobody.",
	},
	{
		Action:    ActionSCIMGroupCreate,
		Home:      HomeControlPlane,
		Entity:    "scim_group",
		Trigger:   "The identity provider provisions a group.",
		Payload:   []string{"id", "display_name", "external_id", "members", "unknown_members"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},
	{
		Action:    ActionSCIMGroupUpdate,
		Home:      HomeControlPlane,
		Entity:    "scim_group",
		Trigger:   "A provisioned group is renamed or its attributes change.",
		Payload:   []string{"id", "display_name", "previous_display_name", "external_id", "method"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note:      "A rename changes what a scim_group role binding naming the old name grants.",
	},
	{
		Action:    ActionSCIMGroupMembers,
		Home:      HomeControlPlane,
		Entity:    "scim_group",
		Trigger:   "Members are added to or removed from a provisioned group.",
		Payload:   []string{"id", "display_name", "added", "removed", "unknown_members", "method"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "A removal takes effect at the member's next authorization decision: provisioned groups " +
			"are read at every decision, not at the next claim refresh.",
	},
	{
		Action:    ActionSCIMGroupDelete,
		Home:      HomeControlPlane,
		Entity:    "scim_group",
		Trigger:   "The identity provider deletes a group.",
		Payload:   []string{"id", "display_name", "external_id", "members"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
	},

	// ── project ────────────────────────────────────────────────────────────
	// A project's directory is what the hub binds into a sandbox and what
	// ?delete_root=true removes, so where one was created, refused or deleted
	// is a question about the host as much as about the project (Task 20418).
	{
		Action:  ActionProjectCreate,
		Home:    HomeControlPlane,
		Entity:  "project",
		Trigger: "A project is created through the hub, or a creation is refused because of the directory it named.",
		Payload: []string{
			"outcome", "path", "requested", "name", "owner", "hub_made", "projects_root", "executor_id",
			"rule", "reason",
		},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note: "`outcome` is \"created\" or \"refused\". `path` is the canonical directory and `requested` " +
			"what the caller sent. `hub_made` says this hub made the directory itself under " +
			"`projects_root` — the only directories ?delete_root=true may remove. A refusal carries the " +
			"`rule` it broke (pkg/projectconfine: control_plane, hub, project, projects_root, " +
			"outside_projects_root, relocated, unsafe, unverifiable, unresolvable, or taken for a path another " +
			"creation holds) and the full `reason`, which the caller may have been answered more " +
			"vaguely than this: what exists at a path they cannot see is not theirs to learn.",
	},
	{
		Action:  ActionProjectDelete,
		Home:    HomeControlPlane,
		Entity:  "project",
		Trigger: "A project is removed from the hub, or the hub refuses to delete its directory.",
		Payload: []string{
			"outcome", "path", "name", "owner", "delete_root", "root_deleted", "hub_made", "reason",
		},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note: "`outcome` is \"removed\" or \"refused\". `delete_root` is what the caller asked for and " +
			"`root_deleted` what happened; a refused one names its `reason` — a directory the hub did not " +
			"make, or one that now overlaps something it must not touch — and the project stays registered.",
	},
	{
		Action:    ActionProjectFirewall,
		Home:      HomeControlPlane,
		Entity:    "project",
		Trigger:   "A project's maintainer sets or clears its firewall rule set, or a tightened executor narrows it.",
		Payload:   []string{"action", "project_path", "executor_id", "from", "to", "fingerprint", "cleared", "reason"},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "`action` is \"set\", \"clear\" or \"constrain\". A constrain row is written by the save that " +
			"tightened a device or a virtual executor, against the identity that saved it, and `reason` names " +
			"the executor and what had to be taken away. Stored in the control plane, where the rule set is.",
	},

	// ── project.member ─────────────────────────────────────────────────────
	// Who besides its owner may reach a project (Task 20366). Each row is
	// committed in the same transaction as the membership change it records,
	// so the roster and the trail cannot disagree. entity_id is
	// "<project path>|<identity>", so a reader filtering on either half finds it.
	{
		Action:    ActionProjectMemberGrant,
		Home:      HomeControlPlane,
		Entity:    "project_member",
		Trigger:   "An identity is added to a project's members at a role.",
		Payload:   projectMemberPayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note:      "`via` is \"api\" or \"cli\". A membership only adds access: the hub unions its role with whatever the identity already holds.",
	},
	{
		Action:    ActionProjectMemberChange,
		Home:      HomeControlPlane,
		Entity:    "project_member",
		Trigger:   "A member's role on a project is changed.",
		Payload:   projectMemberPayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note:      "`previous_role` is the role replaced; a change in either direction is recorded.",
	},
	{
		Action:    ActionProjectMemberRevoke,
		Home:      HomeControlPlane,
		Entity:    "project_member",
		Trigger:   "A member is removed from a project, or the project itself is removed from the hub.",
		Payload:   projectMemberPayload,
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note:      "`role` is the role the member held. A project removed from the hub drops its whole roster, one row per member, with `reason` saying so.",
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

	// ── audit ──────────────────────────────────────────────────────────────
	// The trail's record of itself. A row that could not be appended leaves
	// no trace in a hash chain — the next append links to the last one that
	// succeeded — so the loss is written down instead, as a row of its own.
	{
		Action: ActionAuditGap,
		Home:   HomeEither,
		Entity: "audit",
		Trigger: "A process could not append audit events to this chain, and records what was lost: " +
			"with the next append that succeeds, at a periodic flush, at shutdown, or when a later " +
			"process adopts the losses a crashed one left behind.",
		Payload: []string{
			"lost_events", "failed_appends", "first_failed_at", "last_failed_at",
			"first_error", "last_error", "actions", "reasons", "recorded", "host", "pids",
			"adopted_from",
		},
		Stability: StabilityStable,
		Read:      authz.PermAuditRead,
		Note: "Home is whichever chain lost the events: a failed write to the hub's control-plane " +
			"database is recorded there, a failed write to a project's database in that project's " +
			"chain — the gap has to sit in the chain it is a gap in. `actions` counts the lost " +
			"events by action name and `reasons` by cause (locked, readonly, full, io, closed, " +
			"other), each a list of {name, events} so redaction cannot withhold a count. " +
			"`recorded` says what wrote the row (recovery, flush, shutdown, exit) and " +
			"`adopted_from` names processes that exited owing it. `cloop hub audit verify` " +
			"reports a chain holding gap rows as intact with gaps and exits 3.",
	},
	{
		Action: ActionAuditRestored,
		Home:   HomeEither,
		Entity: "audit",
		Trigger: "`cloop db restore` puts a backup in place of a database, recorded in the chain it restored " +
			"as that chain's next row.",
		Payload: []string{
			"backup", "backup_sha256", "backup_time", "sidecar", "restored_id", "restored_row_hash",
			"restored_time", "superseded_id", "superseded_row_hash", "superseded_time", "lost_events",
			"reason", "accepted_loss", "lost_keys", "key_fingerprint", "checkpoint_record",
		},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note: "Home is whichever chain was restored: the control plane's, or a project's restored with the " +
			"same command — the record has to sit in the history it interrupts. The row takes the id after " +
			"the restored head, an id the superseded checkpoints saw with another hash; the restore record " +
			"`cloop db restore` seals to the checkpoint sinks pins it, and is what lets `cloop hub audit " +
			"verify --checkpoints` report the restore as acknowledged rather than as a truncation. " +
			"`accepted_loss` is true when the restore went ahead under --accept-secret-loss, and " +
			"`lost_keys` lists the sealing keys whose material it gave up, each with the rows sealed under it.",
	},

	// ── audit.forward ──────────────────────────────────────────────────────
	{
		Action: ActionAuditForwardConfigured,
		Home:   HomeControlPlane,
		Entity: "config",
		Trigger: "The cluster leader starts forwarding under an audit.forward configuration that differs from " +
			"the one it last recorded: a sink added, removed, or changed in where or how it sends.",
		Payload: []string{
			"added", "removed", "changed", "sinks", "refused", "previous_fingerprint", "fingerprint", "file",
		},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note: "Detected rather than reported by an editor: the leader compares a fingerprint of the sinks it " +
			"runs under — config.yaml merged with the hub's per-port overlay — against the one stored in the " +
			"control plane, so an edit made with any tool, while the hub was down or up, is recorded by the " +
			"next leader to run under it. `sinks` describes every sink in force (name, type, format, endpoint, " +
			"the secret-store references it reads — names, never values — and whether it sends plaintext to " +
			"loopback); `added`, `removed` and `changed` are sink names; `refused` names sinks the loader " +
			"switched off. The row is forwarded like any other, so the sinks that remain see what changed " +
			"about the ones that left.",
	},
	{
		Action: ActionAuditForwardDiscontinuity,
		Home:   HomeControlPlane,
		Entity: "audit",
		Trigger: "A sink's cursor no longer lines up with the chain it tails — its row was pruned past, " +
			"truncated away or rewritten — and the forwarder resumes from the last point that does.",
		Payload: []string{
			"sink", "source", "dir", "reason", "cursor_id", "cursor_row_hash", "resumed_from_id",
			"resume_prev_hash", "lost_rows",
		},
		Stability: StabilityBeta,
		Read:      authz.PermAuditRead,
		Note: "`reason` is pruned (rows were pruned before the sink acknowledged them, `lost_rows` of them — " +
			"a prune forced past the sink's cursor; they are in the prune's sealed archive, not at the sink), " +
			"truncated (the chain now ends before the cursor), rewritten (the cursor's row has another hash), or " +
			"broken (the cursor's row is intact and what follows it does not continue it: `lost_rows` rows are " +
			"missing inside the chain, or a row was relinked; the rows are forwarded as they stand). " +
			"For truncated and rewritten the forwarder resends from the newest point it acknowledged that the chain still " +
			"holds, so the sink receives the chain as it now stands beside what it already has: two rows with " +
			"one id and different hashes are the evidence, and `cloop hub audit verify --checkpoints` names " +
			"the truncation. Recorded in the control plane's chain whichever chain broke, because the cursor " +
			"is the control plane's.",
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

	// gitProxyScanPayload is a push the scan refused (Task 20436): the run it
	// came from, what the scan found and where — objects, paths, commits and
	// the grant and secret each value was delivered through, never a value.
	gitProxyScanPayload = []string{"kind", "session_id", "repo", "project_id", "task_id", "refs", "detail",
		"scan", "run_id", "findings"}

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

	// modelRelayPayload is a run relay session's event (Task 20435): which
	// run, lease, grant and executor it serves, who pays, what kind of
	// credential it spends — never the credential or the session token.
	modelRelayPayload = []string{
		"kind", "session_id", "project", "run_id", "lease_id", "grant_id", "executor_id",
		"payer", "upstream_kind", "method", "path", "model", "status", "reason",
		"input_tokens", "output_tokens", "detail", "at",
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
		"issued_at", "selector", "selected", "via", "os_user", "kind", "client",
	}

	// reauthPayload is what a session.reauth row says (Task 20448): the
	// session, the outcome, and either the request a stale sign-in was refused
	// for or the sign-in that answered it.
	reauthPayload = []string{
		"session_id", "subject", "email", "ip", "user_agent", "kind", "client",
		"outcome", "reason", "max_age_seconds", "authenticated_at", "method", "path",
		"replaces", "suppressed",
	}

	// devicePayload is what a device.* row says about a terminal's sign-in:
	// the authorization, who asked for it, and who decided it (Task 20412).
	devicePayload = []string{
		"device_id", "client_ip", "client_user_agent", "client_hostname", "expires_at",
		"session_id", "subject", "email", "ip", "user_agent", "reason", "reauth", "kind", "client",
	}

	// requestRefusalPayload is what a refused request said about where it came
	// from, plus the count of refusals the rate limit did not write.
	requestRefusalPayload = []string{
		"reason", "method", "path", "origin", "sec_fetch_site", "host", "content_type",
		"ip", "user_agent", "session", "open_hub", "own_origin", "suppressed",
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

	projectMemberPayload = []string{"project", "project_path", "identity", "role", "previous_role", "reason", "via", "left"}
)
