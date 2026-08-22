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
	"sync"
	"time"

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
		EventType:  "task.upsert",
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
		EventType:  "task.delete",
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
		EventType:  "task.status",
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
		EventType:  "step.append",
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
		EventType:  "config.set",
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
		EventType:  "executor." + in.Action,
		EntityType: "executor",
		EntityID:   in.ExecutorID,
		Payload:    MarshalAuditPayload(payload),
	})
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
		EventType:  "state.save",
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
	Actor     string
	EventType string // "secret.lease", "secret.grant", "secret.revoke", ...
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
		EventType:  in.EventType,
		EntityType: "secret",
		EntityID:   in.EntityID,
		Payload:    MarshalAuditPayload(in.Payload),
	})
}

// auditPlanTasks emits a task.upsert event per task in the saved plan, but
// only when SaveState is the only mutation path the orchestrator uses. We
// rely on caller intent: the orchestrator's hot path goes through SaveState
// rather than UpsertTask, so without this we'd lose all task-level audit
// rows. Cost: one audit row per task per save. Acceptable given typical
// plans (50–500 tasks) and SaveState frequency (once per finished step).
func auditPlanTasks(d *DB, s *State) {
	if s == nil || s.Plan == nil {
		return
	}
	for _, t := range s.Plan.Tasks {
		auditTaskUpsert(d, t, "system")
	}
}
