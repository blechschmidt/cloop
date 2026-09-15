package statedb

import (
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
)

// This file records the two run-level events a subscription cap produces
// (Task 20285).
//
// state.save already carries the project's status, but "paused" there is a
// single opaque word shared by an approval gate, a spent budget, an operator's
// Ctrl-C and an exhausted usage window. A cap is the one pause that ends by
// itself at a time the provider has already told us, so it gets its own action
// and carries that instant — which is what makes the matching resume
// auditable rather than an unexplained restart.

// CapPauseInput is one run stopped by a Claude Code subscription cap.
type CapPauseInput struct {
	// ProjectPath is the working directory whose run was stopped.
	ProjectPath string
	// Windows names the tripped windows ("five_hour", "weekly", ...).
	Windows []string
	// Utilization and Cap are the global utilization and the configured
	// per-project ceiling that it reached, for the first tripped window.
	Utilization float64
	Cap         float64
	// ResumesAt is when every tripped window has rolled over. Zero when the
	// usage API did not report a reset, in which case the row says so rather
	// than inventing a time a resume could later be matched against.
	ResumesAt time.Time
	// Detail is the operator-facing phrase stored as the pause reason.
	Detail string
	Actor  string
}

// AuditCapPause records a run parked by a subscription cap.
func AuditCapPause(d *DB, in CapPauseInput) {
	actor := in.Actor
	if actor == "" {
		actor = "orchestrator"
	}
	payload := map[string]any{
		"project":     in.ProjectPath,
		"windows":     in.Windows,
		"utilization": in.Utilization,
		"cap":         in.Cap,
	}
	if in.Detail != "" {
		payload["detail"] = in.Detail
	}
	if !in.ResumesAt.IsZero() {
		payload["resumes_at"] = in.ResumesAt.UTC().Format(time.RFC3339)
	}
	emit(d, &AuditEvent{
		Actor:      actor,
		EventType:  string(auditaction.ActionRunCapPaused),
		EntityType: "plan",
		EntityID:   in.ProjectPath,
		Payload:    MarshalAuditPayload(payload),
	})
}

// CapResumeInput is one cap-paused run restarted by the hub on its own.
type CapResumeInput struct {
	ProjectPath string
	// PausedDetail is the pause reason the run carried, so the row names the
	// wall it was waiting on.
	PausedDetail string
	// ResumesAt is the instant the run was waiting for, and ResumedAt is when
	// the hub actually acted. The gap between them is the sweep interval, and
	// having both is what distinguishes a late sweep from a wrong reset time.
	ResumesAt time.Time
	ResumedAt time.Time
	Actor     string
}

// AuditCapResume records the hub restarting a cap-paused run with no human in
// the loop.
func AuditCapResume(d *DB, in CapResumeInput) {
	actor := in.Actor
	if actor == "" {
		actor = "hub"
	}
	payload := map[string]any{"project": in.ProjectPath}
	if in.PausedDetail != "" {
		payload["paused_detail"] = in.PausedDetail
	}
	if !in.ResumesAt.IsZero() {
		payload["resumes_at"] = in.ResumesAt.UTC().Format(time.RFC3339)
	}
	resumed := in.ResumedAt
	if resumed.IsZero() {
		resumed = time.Now()
	}
	payload["resumed_at"] = resumed.UTC().Format(time.RFC3339)
	emit(d, &AuditEvent{
		Actor:      actor,
		EventType:  string(auditaction.ActionRunCapResumed),
		EntityType: "plan",
		EntityID:   in.ProjectPath,
		Payload:    MarshalAuditPayload(payload),
	})
}
