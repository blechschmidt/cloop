// Audit-event emission helpers (Task 20119).
//
// These wrap AppendAuditEvent with payload construction for each mutation
// type. They MUST NOT block the caller on failure: a stuck audit log must
// never abort user work. Errors are written to stderr — surfaced once
// per process via sync.Once to avoid log spam under sustained failure.

package statedb

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// auditEnabled is consulted before every emission. Tests that don't care
// about the audit log can flip it false to silence the writes; production
// code leaves it at the default true.
var auditEnabled = true

// SetAuditEnabled toggles audit emission globally. Intended for tests and
// for callers running cloop against a database where the audit_events table
// is not desired (e.g. one-shot CLI commands that read state).
func SetAuditEnabled(on bool) { auditEnabled = on }

var auditWarnOnce sync.Once

// auditWarn reports a single audit-emission failure via stderr. We swallow
// every subsequent failure to keep the audit log's "best-effort" contract
// from drowning logs when the database is read-only or full.
func auditWarn(format string, args ...any) {
	auditWarnOnce.Do(func() {
		fmt.Fprintf(os.Stderr, "[audit] "+format+" (further audit-log warnings will be suppressed)\n", args...)
	})
}

// emit is the single internal helper every public auditXxx helper calls.
func emit(d *DB, ev *AuditEvent) {
	if !auditEnabled || d == nil {
		return
	}
	if err := d.AppendAuditEvent(ev); err != nil {
		auditWarn("emit %s/%s: %v", ev.EventType, ev.EntityID, err)
	}
}

func auditTaskUpsert(d *DB, t *pm.Task, actor string) {
	if t == nil {
		return
	}
	if actor == "" {
		actor = "system"
	}
	emit(d, &AuditEvent{
		Actor:      actor,
		EventType:  string(auditaction.ActionTaskUpsert),
		EntityType: "task",
		EntityID:   fmt.Sprintf("%d", t.ID),
		Payload:    MarshalAuditPayload(t),
	})
}

// AuditTaskUpsert is the exported wrapper that callers outside this package
// (orchestrator, UI handlers) use to emit a task-mutation event with their
// own actor identity. Best-effort.
func AuditTaskUpsert(d *DB, t *pm.Task, actor string) {
	auditTaskUpsert(d, t, actor)
}

// AuditTaskDelete records a task removal. EntityID is the deleted task's id.
func AuditTaskDelete(d *DB, taskID int, actor string) {
	if actor == "" {
		actor = "system"
	}
	emit(d, &AuditEvent{
		Actor:      actor,
		EventType:  string(auditaction.ActionTaskDelete),
		EntityType: "task",
		EntityID:   fmt.Sprintf("%d", taskID),
		Payload:    MarshalAuditPayload(map[string]any{"id": taskID}),
	})
}

// AuditTaskStatus records a manual status flip (UI/CLI initiated).
func AuditTaskStatus(d *DB, taskID int, oldStatus, newStatus, actor string) {
	if actor == "" {
		actor = "system"
	}
	emit(d, &AuditEvent{
		Actor:      actor,
		EventType:  string(auditaction.ActionTaskStatus),
		EntityType: "task",
		EntityID:   fmt.Sprintf("%d", taskID),
		Payload: MarshalAuditPayload(map[string]any{
			"id":         taskID,
			"old_status": oldStatus,
			"new_status": newStatus,
		}),
	})
}

func auditStepAppend(d *DB, row StepRow, actor string) {
	if actor == "" {
		actor = "orchestrator"
	}
	emit(d, &AuditEvent{
		Actor:      actor,
		EventType:  string(auditaction.ActionStepAppend),
		EntityType: "step",
		EntityID:   fmt.Sprintf("%d", row.Step),
		Payload: MarshalAuditPayload(map[string]any{
			"step":          row.Step,
			"task":          row.Task,
			"exit_code":     row.ExitCode,
			"duration":      row.Duration,
			"time":          row.Time,
			"input_tokens":  row.InputTokens,
			"output_tokens": row.OutputTokens,
			// Output is intentionally omitted: it can be megabytes per row and
			// is already persisted in the steps table itself. Replay reads it
			// from there. The audit row is for *who/what/when*, not full content.
		}),
	})
}

// auditConfigSet records a config write.
//
// The blob is the entire serialised .cloop/config.yaml, which carries
// provider API keys — pkg/config.Save hands SetConfigBlob the same bytes it
// writes to disk. Storing it verbatim would put every API key the deployment
// has ever configured into an append-only table that an operator is expected
// to export to a SIEM. The YAML pass redacts the values of credential-bearing
// keys while preserving structure, so the row still answers "what did the
// config look like when this changed" without answering "what is the key".
func auditConfigSet(d *DB, yamlBlob, actor string) {
	if actor == "" {
		actor = "system"
	}
	emit(d, &AuditEvent{
		Actor:      actor,
		EventType:  string(auditaction.ActionConfigSet),
		EntityType: "config",
		EntityID:   "",
		Payload:    MarshalAuditPayload(map[string]any{"yaml": redactYAMLSecrets(yamlBlob)}),
	})
}

// ExecutorAuditInput carries one executor-fleet decision to the audit log
// (Task 20167).
//
// Executor lifecycle was the gap in the trail: enrolling a device grants an
// arbitrary machine the right to run project workloads and to request
// brokered credentials, and revoking, cordoning, draining, or re-binding one
// changes where a project's code executes. Those are exactly the events an
// operator needs to reconstruct — "who attached this machine, and when" —
// and none of them were recorded before.
type ExecutorAuditInput struct {
	// Action is the lifecycle verb: "enroll", "revoke", "cordon",
	// "uncordon", "drain", "bind", "unbind". It becomes the suffix of the
	// event type, so the whole family is filterable as event_type LIKE
	// 'executor.%' and each verb individually by exact match.
	Action string

	// ExecutorID is the fleet identifier the action targeted. Empty is
	// legitimate for "unbind", which names a project rather than a device.
	ExecutorID string

	// Actor is the acting identity, normally the OIDC subject label.
	Actor string

	// Detail is optional context: the device name, the cordon reason, the
	// project path a binding points at. Never credentials — the enrollment
	// token in particular must not appear here, and the central redaction
	// in MarshalAuditPayload enforces that even if a caller tries.
	Detail map[string]any
}

// AuditExecutorLifecycle records an executor-fleet mutation. Best-effort,
// like every other emitter in this file: a wedged audit log must not stop an
// operator from cordoning a misbehaving node.
func AuditExecutorLifecycle(d *DB, in ExecutorAuditInput) {
	if in.Action == "" {
		return
	}
	actor := in.Actor
	if actor == "" {
		actor = "system"
	}
	payload := map[string]any{"action": in.Action}
	if in.ExecutorID != "" {
		payload["executor_id"] = in.ExecutorID
	}
	for k, v := range in.Detail {
		payload[k] = v
	}
	emit(d, &AuditEvent{
		Actor:      actor,
		EventType:  string(auditaction.ExecutorLifecycle(in.Action)),
		EntityType: "executor",
		EntityID:   in.ExecutorID,
		Payload:    MarshalAuditPayload(payload),
	})
}

// ImagePolicyDenialInput carries one refused container image to the audit log
// (Task 20177).
//
// This is the one sandbox decision worth a permanent row. The others describe
// a project asking for less than it could have; this one describes a project
// asking to execute code from somewhere the operator does not trust, and the
// question it has to answer later is "was this a typo in one repo, or did the
// same unknown registry get named across six projects in an hour". Only a
// durable, queryable trail answers the second.
type ImagePolicyDenialInput struct {
	// ProjectPath identifies the project whose .cloop/sandbox.yaml was
	// refused. It is the entity the row is filed under.
	ProjectPath string
	// Image is the reference as the project wrote it, unmodified — the
	// normalized form would hide exactly the homograph or confusion attempt
	// that is the reason to look.
	Image string
	// Rule is the imagepolicy rule that refused it ("registry-allowlist",
	// "digest-required", …). Kept as the same string the API and the error
	// text use, so filtering the trail and reading a bug report agree.
	Rule string
	// Reason is the human-readable observation.
	Reason string
	// Registry and Repository are the parsed components, empty when the
	// reference did not parse. They are what makes "show me every denial for
	// this registry" a query rather than a grep.
	Registry   string
	Repository string
	// Actor is the acting identity, normally the OIDC subject label.
	Actor string
}

// AuditImagePolicyDenial records a container image refused by the hub's trust
// policy. Best-effort, like every other emitter here.
func AuditImagePolicyDenial(d *DB, in ImagePolicyDenialInput) {
	if in.Image == "" && in.Rule == "" {
		return
	}
	actor := in.Actor
	if actor == "" {
		actor = "system"
	}
	payload := map[string]any{
		"image":  in.Image,
		"rule":   in.Rule,
		"reason": in.Reason,
	}
	if in.ProjectPath != "" {
		payload["project"] = in.ProjectPath
	}
	if in.Registry != "" {
		payload["registry"] = in.Registry
	}
	if in.Repository != "" {
		payload["repository"] = in.Repository
	}
	emit(d, &AuditEvent{
		Actor:      actor,
		EventType:  string(auditaction.ActionSandboxImageDenied),
		EntityType: "project",
		EntityID:   in.ProjectPath,
		Payload:    MarshalAuditPayload(payload),
	})
}

// WorkspaceAuditInput carries one workspace-provisioning observation to the
// audit log (Task 20179).
//
// Provisioning earns its own rows rather than being folded into the run's,
// because it is the moment a brokered credential is used against an external
// service on behalf of a project. "Which grant fetched which repository onto
// which executor, and did it work" is the question an operator has after an
// incident, and the run's own record cannot answer it: a run looks identical
// whether the tree arrived or not, which is the entire reason the workspace
// subsystem exists.
//
// No field here can carry a credential. The Workspace the executor dispatched
// is structurally incapable of holding one — pkg/executor.Workspace has no
// field a token could go in, by design, because a Spec is persisted, logged
// and shipped across the remote-executor boundary — and GrantID/LeaseID are
// identifiers, not material. The token never enters this package's scope.
type WorkspaceAuditInput struct {
	// Phase is "start" or "end", matching executor.WorkspaceProvisionStart /
	// WorkspaceProvisionEnd. It becomes the suffix of the event type, so the
	// family is filterable as event_type LIKE 'workspace.%' and each phase
	// individually by exact match. Anything else is dropped rather than
	// written, so a typo cannot create a third, unqueryable event family.
	Phase string

	// ProjectPath is the project whose tree was being materialised. It is the
	// entity the row is filed under, matching how image denials are filed.
	ProjectPath string

	// ExecutorID and ExecutorKind name the backend doing the fetch. Both are
	// recorded because an ID is stable but says nothing about *where* the code
	// landed, and "was this on a Pod or on someone's laptop" is the first
	// question asked of a provisioning row.
	ExecutorID   string
	ExecutorKind string

	// HandleID correlates the two phases with each other and with the run.
	HandleID string

	// Kind, Repo, Ref and Depth are the workspace as dispatched — the clone
	// URL exactly as the executor was told to fetch it, which is the only form
	// that can be compared against what the operator believes is configured.
	Kind  string
	Repo  string
	Ref   string
	Depth int

	// GrantID and LeaseID name the authority used. They are the join key back
	// into the secret-broker rows, which is what turns "this repo was fetched"
	// into "this grant was exercised at this time".
	GrantID string
	LeaseID string

	// DurationMS is set on the end phase only.
	DurationMS int64

	// Err is the failure, already redacted by the driver, or "" on success.
	Err string

	// Actor is the acting identity. Empty becomes "system": provisioning is
	// decided by the dispatching control plane, and on the failover path there
	// is no human to attribute it to.
	Actor string
}

// AuditWorkspaceProvision records one workspace-provisioning phase.
//
// Best-effort, like every other emitter in this file: an unavailable audit log
// must not stop a workload from getting its source tree.
func AuditWorkspaceProvision(d *DB, in WorkspaceAuditInput) {
	var suffix string
	switch in.Phase {
	case "start":
		suffix = "provision_start"
	case "end":
		suffix = "provision_end"
	default:
		return
	}
	actor := in.Actor
	if actor == "" {
		actor = "system"
	}
	payload := map[string]any{"phase": in.Phase}
	for k, v := range map[string]string{
		"executor_id":   in.ExecutorID,
		"executor_kind": in.ExecutorKind,
		"handle_id":     in.HandleID,
		"kind":          in.Kind,
		"repo":          in.Repo,
		"ref":           in.Ref,
		"grant_id":      in.GrantID,
		"lease_id":      in.LeaseID,
		"error":         in.Err,
		"project":       in.ProjectPath,
	} {
		if v != "" {
			payload[k] = v
		}
	}
	if in.Depth > 0 {
		payload["depth"] = in.Depth
	}
	if in.DurationMS > 0 {
		payload["duration_ms"] = in.DurationMS
	}
	emit(d, &AuditEvent{
		Actor:      actor,
		EventType:  string(auditaction.WorkspacePhase(suffix)),
		EntityType: "project",
		EntityID:   in.ProjectPath,
		Payload:    MarshalAuditPayload(payload),
	})
}

// TaskDispatchInput carries the placement facts for one task execution
// (Task 20282).
//
// It is filled by the orchestrator, which is the only layer that knows both a
// task id and the environment it was placed into: the hub chose the executor
// and started a whole `cloop run`, and by the time a task begins there is no
// placement decision left to read — the decision is why the process exists.
// What the hub leaves behind is .cloop/sandbox-run.json, and this struct is
// that record joined to the task it is about to run.
//
// No field can carry a credential. LeaseIDs are the broker's opaque handles,
// not material; the digest and hashes are content addresses; Actor is an
// identity label. The token behind a lease never enters this package's scope.
type TaskDispatchInput struct {
	// TaskID and TaskTitle identify the unit of work. The title is recorded
	// rather than joined later because a plan can be edited: an auditor reading
	// this row six weeks on should see what the task said when it ran.
	TaskID    int
	TaskTitle string

	// ProjectPath is the project the task belongs to.
	ProjectPath string

	// RunID names the execution. It is the join key to the secret.lease rows
	// the hub wrote for the same dispatch, and the reason leases attach to an
	// execution rather than to a task id that may run many times.
	RunID string

	// ExecutorID, ExecutorKind and Isolation are where the work landed, as
	// advertised at placement. Stored rather than derived by joining the
	// executor registry later, for the reason migration 0032 gives: an executor
	// re-enrolled under the same id would otherwise rewrite the history of
	// every task it ever ran.
	ExecutorID   string
	ExecutorKind string
	Isolation    string

	// RequestedImage is the reference the sandbox spec asked for; PinnedImage
	// is what actually ran, digest-pinned where the driver could resolve one.
	// Both, because the gap between them is the question — a spec naming a tag
	// and a run on a digest is reproducible, a run on the tag is not.
	RequestedImage string
	PinnedImage    string

	// SpecHash is the .cloop/sandbox.yaml content hash, empty when the project
	// has no spec and ran on the executor's defaults. SetupHash identifies
	// commands baked into a derived image.
	SpecHash  string
	SetupHash string

	// LeaseIDs are the secret leases handed to this run.
	LeaseIDs []string

	// Actor is who asked for the run.
	Actor string
}

// AuditTaskDispatch records one task entering execution.
//
// Best-effort, like every other emitter in this file: a wedged audit log must
// not stop a task from running. The chain verifier surfaces the resulting gap.
func AuditTaskDispatch(d *DB, in TaskDispatchInput) {
	actor := in.Actor
	if actor == "" {
		actor = "system"
	}
	payload := map[string]any{"task_id": in.TaskID}
	for k, v := range map[string]string{
		"title":           in.TaskTitle,
		"project":         in.ProjectPath,
		"run_id":          in.RunID,
		"executor_id":     in.ExecutorID,
		"executor_kind":   in.ExecutorKind,
		"isolation":       in.Isolation,
		"requested_image": in.RequestedImage,
		"pinned_image":    in.PinnedImage,
		"spec_sha256":     in.SpecHash,
		"setup_sha256":    in.SetupHash,
	} {
		if v != "" {
			payload[k] = v
		}
	}
	if len(in.LeaseIDs) > 0 {
		payload["lease_ids"] = in.LeaseIDs
	}
	// Recorded rather than omitted, for the reason the provisioning emitter
	// records an unbounded depth explicitly: an absent key reads as "nobody
	// asked", and "this execution held no brokered credentials" is a positive
	// and audit-relevant fact about the run.
	if len(in.LeaseIDs) == 0 {
		payload["lease_ids"] = []string{}
	}
	emit(d, &AuditEvent{
		Actor:      actor,
		EventType:  string(auditaction.ActionTaskDispatch),
		EntityType: "task",
		EntityID:   fmt.Sprintf("%d", in.TaskID),
		Payload:    MarshalAuditPayload(payload),
	})
}

// auditTaskLifecycle emits the terminal rows for one SaveState.
//
// The edges were computed inside the write transaction by diffTaskLifecycle;
// see task_runs.go for why detection lives at the write rather than at each of
// the orchestrator's exit paths.
//
// # Why only the terminal half
//
// The dispatch edge is detected here — the cursor has to move on it, or the
// terminal edge could never fire — but no row is written for it. Placement
// happens at exactly one point, and the orchestrator emits a full task.dispatch
// there with the image digest, spec hash and lease ids that this layer cannot
// see. Emitting a second, thinner row for the same placement would make the
// simplest possible audit query — "how many times did this task run" — return
// twice the truth for an orchestrator-run task and once for any other, which is
// worse than either answer alone.
//
// Termination is the opposite shape: it happens at a dozen points, several of
// them in processes that never dispatched the task, so the only place that sees
// all of them is the write every one of them must perform.
//
// A task moved into in_progress by something other than the orchestrator is not
// left unrecorded by this asymmetry. That is a human action, and it is covered
// by task.status — which names the person, where a synthesised dispatch row
// could only have said "system".
func auditTaskLifecycle(d *DB, edges []taskLifecycleEdge, projectPath string) {
	if !auditEnabled || d == nil || len(edges) == 0 {
		return
	}
	evs := make([]*AuditEvent, 0, len(edges))
	for _, e := range edges {
		if e.Task == nil || e.Dispatch() {
			continue
		}
		evs = append(evs, taskFinishEvent(e, projectPath))
	}
	if len(evs) == 0 {
		return
	}
	if err := d.AppendAuditEvents(evs); err != nil {
		auditWarn("emit %d task lifecycle events: %v", len(evs), err)
	}
}

// taskFinishEvent renders the terminal row: outcome, duration and reason.
//
// The reason is assembled from what the task itself records, rather than passed
// in by whichever exit path fired, because the exit paths do not all agree on
// where they write it — an abort lands in Task.Abort, a timeout only in the
// status, a kill in an annotation, a failure diagnosis in its own field. Reading
// them here means a new exit path gets a usable reason without having to know
// this function exists.
func taskFinishEvent(e taskLifecycleEdge, projectPath string) *AuditEvent {
	t := e.Task
	payload := map[string]any{
		"task_id": t.ID,
		"outcome": e.NewStatus,
	}
	for k, v := range map[string]string{
		"title":         t.Title,
		"project":       projectPath,
		"run_id":        e.RunID,
		"executor_id":   t.ExecutorID,
		"executor_kind": t.ExecutorKind,
		"isolation":     t.Isolation,
		"reason":        taskExitReason(t, e.NewStatus),
	} {
		if v != "" {
			payload[k] = v
		}
	}
	if t.StartedAt != nil {
		payload["started_at"] = t.StartedAt.UTC().Format(time.RFC3339Nano)
		end := t.CompletedAt
		if end != nil {
			payload["completed_at"] = end.UTC().Format(time.RFC3339Nano)
			payload["duration_ms"] = end.Sub(*t.StartedAt).Milliseconds()
		}
	}
	if t.Abort != nil {
		payload["abort_class"] = t.Abort.Class
		payload["abort_cleared"] = t.Abort.Cleared
	}
	if t.FailCount > 0 {
		payload["fail_count"] = t.FailCount
	}
	if t.WriteBackCommit != "" {
		payload["write_back_commit"] = t.WriteBackCommit
	}
	return &AuditEvent{
		Actor:      "system",
		EventType:  string(auditaction.ActionTaskFinish),
		EntityType: "task",
		EntityID:   fmt.Sprintf("%d", t.ID),
		Payload:    MarshalAuditPayload(payload),
	}
}

// maxExitReason bounds the free-text reason. A task result is the agent's own
// output and can be megabytes; the audit row is for what happened, not for the
// content, which the artifact already holds.
const maxExitReason = 400

// taskExitReason describes why an execution ended, in one line.
//
// Ordered most-specific first. A provider refusal is the reading that matters
// most when present, because a task whose status says "pending" after an abort
// looks from the status alone like a task that simply has not run.
func taskExitReason(t *pm.Task, outcome string) string {
	if t.Abort != nil && t.Abort.Reason != "" {
		return truncateReason("provider abort: " + t.Abort.Reason)
	}
	switch outcome {
	case string(pm.TaskTimedOut):
		return "execution exceeded its time budget"
	case string(pm.TaskPending):
		// Leaving in_progress for pending is not an outcome a task can reach on
		// its own: something reset it — a crash reconciliation that found no
		// signal, an operator, or an abort retry.
		return "returned to pending without a recorded outcome"
	}
	if t.FailureDiagnosis != "" {
		return truncateReason(t.FailureDiagnosis)
	}
	if t.Result != "" {
		return truncateReason(t.Result)
	}
	return ""
}

// truncateReason bounds and single-lines a free-text reason. Newlines are
// folded because an audit row is read in a table, and a reason containing the
// agent's multi-line output would break every renderer that shows one row per
// line.
func truncateReason(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxExitReason {
		return s[:maxExitReason] + "…"
	}
	return s
}

func auditStateSave(d *DB, s *State) {
	if s == nil {
		return
	}
	taskCount := 0
	planVersion := 0
	if s.Plan != nil {
		taskCount = len(s.Plan.Tasks)
		planVersion = s.Plan.Version
	}
	emit(d, &AuditEvent{
		Actor:      "system",
		EventType:  string(auditaction.ActionStateSave),
		EntityType: "plan",
		EntityID:   "",
		Payload: MarshalAuditPayload(map[string]any{
			"goal":                s.Goal,
			"status":              s.Status,
			"current_step":        s.CurrentStep,
			"evolve_step":         s.EvolveStep,
			"plan_version":        planVersion,
			"task_count":          taskCount,
			"total_input_tokens":  s.TotalInputTokens,
			"total_output_tokens": s.TotalOutputTokens,
			"auto_evolve":         s.AutoEvolve,
			"innovate_mode":       s.InnovateMode,
			"parallel":            s.Parallel,
			"max_parallel":        s.MaxParallel,
		}),
	})
}

// SecretAuditInput carries one secret-broker decision to the audit log
// (Task 20159). It exists so pkg/secretstore does not have to construct an
// AuditEvent — and, more to the point, so the entity_type is set in exactly
// one place and every broker row is filterable as entity_type='secret'.
type SecretAuditInput struct {
	Actor string
	// EventType is the registered action: auditaction.ActionSecretLease,
	// ActionSecretGrant, ActionSecretRevoke, and the rest of the secret,
	// lease, egress and github_app families.
	//
	// Typed rather than a bare string because the whole broker surface funnels
	// through this one struct, which makes it the single place a made-up
	// action could enter the trail. Requiring an auditaction.Action means the
	// value came from the registry, and tests/arch/auditaction_test.go can see
	// that it did.
	EventType auditaction.Action
	EntityID  string // secret ID, or grant ID when no secret is involved
	Timestamp time.Time
	// Payload is the decision's metadata. Callers are responsible for
	// redacting it; pkg/secretbroker.Redact runs over every event before it
	// reaches here, and again inside the secretstore auditor.
	Payload map[string]any
}

// AuditSecretDecision records a secret-broker mint, grant, lease, renew,
// revoke, or denial. Best-effort, like every other emitter in this file: an
// unavailable audit log must not stop an executor from receiving the
// credentials it was granted.
func AuditSecretDecision(d *DB, in SecretAuditInput) {
	if in.EventType == "" {
		return
	}
	actor := in.Actor
	if actor == "" {
		actor = "secretbroker"
	}
	emit(d, &AuditEvent{
		Timestamp:  in.Timestamp,
		Actor:      actor,
		EventType:  string(in.EventType),
		EntityType: "secret",
		EntityID:   in.EntityID,
		Payload:    MarshalAuditPayload(in.Payload),
	})
}

// auditPlanTasks emits the task-level audit rows for one SaveState.
//
// It records the delta saveStateLocked computed inside its transaction, not
// the plan: one row per task whose audit payload actually changed, plus one
// per task that disappeared. The previous version emitted one row per task in
// the plan on every save and conceded in its own comment that this was "one
// audit row per task per save. Acceptable given typical plans" — on this
// project's hub it produced 1,093,055 rows, 99.7% of the audit table, for a
// 417-task plan saved once per finished step.
//
// The whole batch goes through AppendAuditEvents so a save costs one
// transaction rather than one per row. Emission stays best-effort: a wedged
// audit log must not fail a state write that already committed.
func auditPlanTasks(d *DB, changed []taskAuditChange, deleted []int) {
	if !auditEnabled || d == nil || (len(changed) == 0 && len(deleted) == 0) {
		return
	}
	evs := make([]*AuditEvent, 0, len(changed)+len(deleted))
	for _, c := range changed {
		if c.Task == nil {
			continue
		}
		evs = append(evs, &AuditEvent{
			Actor:      "system",
			EventType:  string(auditaction.ActionTaskUpsert),
			EntityType: "task",
			EntityID:   fmt.Sprintf("%d", c.Task.ID),
			// Reuse the payload the diff already marshalled and redacted.
			// Re-marshalling here could produce a different string from the
			// one that was fingerprinted, which would make the next save see a
			// change that never happened.
			Payload: c.Payload,
		})
	}
	for _, id := range deleted {
		evs = append(evs, &AuditEvent{
			Actor:      "system",
			EventType:  string(auditaction.ActionTaskDelete),
			EntityType: "task",
			EntityID:   fmt.Sprintf("%d", id),
			Payload:    MarshalAuditPayload(map[string]any{"id": id}),
		})
	}
	if len(evs) == 0 {
		return
	}
	if err := d.AppendAuditEvents(evs); err != nil {
		auditWarn("emit %d plan task events: %v", len(evs), err)
	}
}
