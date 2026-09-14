package statedb

// audit_attach.go records interactive sandbox sessions in the tamper-evident
// trail (Task 20265).
//
// # Why this event is not optional
//
// Everywhere else in cloop, the answer to "who wrote this code" is "the agent,
// under this task, with this prompt" — and the artifact, the commit and the
// reproduction record all agree. An attach session is the one thing that
// breaks that: a human reached into the sandbox mid-run, and anything they did
// there is attributed to the agent by default. The trail row is the only
// artefact that will ever say otherwise.
//
// So the row carries the two facts a later reader actually needs — *who*, and
// *what command* — plus whether the session could type at all. A read-only
// session cannot have changed the work; a writable one might have, and the
// difference is the first thing an auditor asks.
//
// # Why the transcript is not here
//
// Keystrokes are not recorded. The output has already been scrubbed of the
// workload's declared credentials on its way to the operator, but a terminal
// reads arbitrary bytes and a full transcript would be a second, unscrubbed
// copy of whatever the sandbox holds — living on the control plane, outside
// the lease that governs the original, and readable by anyone with audit.read.
// The event is the accountability; the transcript would be an exfiltration
// route wearing accountability's clothes.

// AttachAuditInput carries one interactive-session lifecycle event.
type AttachAuditInput struct {
	// Event is the fully-qualified type: "sandbox.attach.open",
	// "sandbox.attach.close", or "sandbox.attach.denied".
	//
	// Passed in whole rather than assembled from an action suffix, because
	// these three are the complete set and a typo should be visible at the
	// call site rather than produce a plausible-looking new event type that
	// no retention rule or SIEM filter knows about.
	Event string
	// Actor is the acting identity — the OIDC subject label, the same
	// spelling auditAuthz writes, so filtering the trail by person returns a
	// whole session rather than half of it.
	Actor string
	// SessionID correlates the open with its close.
	SessionID string
	// ExecutorID and HandleID name the sandbox that was entered. Both,
	// because the executor alone does not identify which workload and the
	// handle alone does not survive as a lookup key once the run ends.
	ExecutorID string
	HandleID   string
	// TaskID is the work the sandbox was running, and the entity this row is
	// filed under: "show me everything that happened to task 41" is the query
	// an incident actually starts from.
	TaskID int
	// Command is the argv as the caller gave it, unmodified. Not normalised
	// and not shell-quoted — the point is to record what was asked for, and a
	// prettied-up rendering is a different string from the one that ran.
	Command string
	// Writable reports whether the session had an input channel at all.
	Writable bool
	// Detail is the refusal reason for a denial, or the close reason for a
	// close. Empty on a clean open.
	Detail string
}

// AuditAttachSession records one interactive-session event.
//
// Best-effort, like every other emitter in this package: a wedged journal must
// not stop an operator reaching a sandbox during an incident. That is a
// deliberate trade — an unrecorded session is worse than no session in theory,
// and much better than an unreachable sandbox at 3am in practice — and it is
// the same trade every other audit path here already makes.
func AuditAttachSession(d *DB, in AttachAuditInput) {
	if in.Event == "" {
		return
	}
	actor := in.Actor
	if actor == "" {
		actor = "system"
	}
	payload := map[string]any{
		"session_id": in.SessionID,
		"writable":   in.Writable,
	}
	if in.ExecutorID != "" {
		payload["executor_id"] = in.ExecutorID
	}
	if in.HandleID != "" {
		payload["handle_id"] = in.HandleID
	}
	if in.TaskID > 0 {
		payload["task_id"] = in.TaskID
	}
	if in.Command != "" {
		payload["command"] = in.Command
	}
	if in.Detail != "" {
		payload["detail"] = in.Detail
	}
	emit(d, &AuditEvent{
		Actor:      actor,
		EventType:  in.Event,
		EntityType: "sandbox_session",
		EntityID:   in.SessionID,
		Payload:    MarshalAuditPayload(payload),
	})
}
