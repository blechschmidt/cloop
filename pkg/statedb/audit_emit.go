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

func auditConfigSet(d *DB, yamlBlob, actor string) {
	if actor == "" {
		actor = "system"
	}
	emit(d, &AuditEvent{
		Actor:      actor,
		EventType:  "config.set",
		EntityType: "config",
		EntityID:   "",
		Payload:    MarshalAuditPayload(map[string]any{"yaml": yamlBlob}),
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
