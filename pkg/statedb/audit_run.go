package statedb

import (
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/runbuild"
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

// RunReexecInput is one run that replaced its image with a newer build at a
// task boundary (Task 20389).
type RunReexecInput struct {
	ProjectPath string
	RunID       string
	PID         int
	From, To    runbuild.Build
	Reason      string
	Reexecs     int
}

// AuditRunReexecuted records a run moving to a newer build. Written by the new
// image, on the project's chain: which build ran which of its tasks is a
// question about the project.
func AuditRunReexecuted(d *DB, in RunReexecInput) {
	payload := map[string]any{
		"project": in.ProjectPath,
		"pid":     in.PID,
		"from":    in.From,
		"to":      in.To,
		"reexecs": in.Reexecs,
	}
	if in.RunID != "" {
		payload["run_id"] = in.RunID
	}
	if in.Reason != "" {
		payload["reason"] = in.Reason
	}
	emit(d, &AuditEvent{
		Actor:      "orchestrator",
		EventType:  string(auditaction.ActionRunReexecuted),
		EntityType: "plan",
		EntityID:   in.ProjectPath,
		Payload:    MarshalAuditPayload(payload),
	})
}

// AdoptRequestInput is one request for a run to adopt the hub's build.
type AdoptRequestInput struct {
	ProjectPath string
	RequestID   string
	PID         int
	RunBuild    runbuild.Build
	HubBuild    runbuild.Build
	Behind      int
	Actor       string
}

// AuditAdoptRequested records somebody asking a run to adopt the hub's build
// at its next task boundary (Task 20389).
func AuditAdoptRequested(d *DB, in AdoptRequestInput) {
	actor := in.Actor
	if actor == "" {
		actor = "hub"
	}
	emit(d, &AuditEvent{
		Actor:      actor,
		EventType:  string(auditaction.ActionRunAdoptRequested),
		EntityType: "plan",
		EntityID:   in.ProjectPath,
		Payload: MarshalAuditPayload(map[string]any{
			"project":    in.ProjectPath,
			"request_id": in.RequestID,
			"pid":        in.PID,
			"run_build":  in.RunBuild,
			"hub_build":  in.HubBuild,
			"behind":     in.Behind,
		}),
	})
}
