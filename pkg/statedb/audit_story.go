// Single-task audit reconstruction (Task 20282).
//
// This is the function that makes the compliance claim checkable rather than
// merely stated. The claim is that audit_events, on its own, answers:
//
//	which executor ran task 63, under which secret leases, and how did it end?
//
// So this reads audit_events and nothing else. Not plan_tasks, not task_runs,
// not the cost ledger — those are the system's own working state, and a trail
// that needs them to be intelligible is not a trail, it is an index into a
// database an auditor may not have and a compromised host may have edited.
// task_runs in particular is tempting and deliberately not consulted: it holds
// exactly the task→run mapping this needs, and taking it from there would mean
// the reconstruction still worked on a database whose audit rows had been
// stripped of their run ids.
//
// The join it performs instead is the one an auditor would do by hand:
//
//  1. every row filed against this task (entity_type='task', entity_id='63'),
//  2. the run ids named by those rows' dispatch payloads,
//  3. every row anywhere in the trail carrying one of those run ids — which is
//     where the lease, renewal and release rows come from, since those are
//     filed under entity_type='secret' and would otherwise never be found by a
//     task-scoped query.
//
// Step 3 is why the run id had to exist. Filed against different entities and
// written by a different process, the credential rows and the task rows have no
// other point of contact; correlating them by timestamp means picking a window
// and hoping no other run of the same project overlapped it, which on a hub
// running a fleet is not a hope that survives contact with an incident.

package statedb

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// TaskStory is one task's reconstructed history.
type TaskStory struct {
	// TaskID is the task the story is about.
	TaskID int

	// Title is the task's title as the trail recorded it, from the most recent
	// row that carried one. Empty when no row named it — which is itself a
	// finding, not a formatting problem.
	Title string

	// Events are every row that belongs to this task's history, in trail order
	// (ascending id, which is the order they were appended and therefore the
	// order the hash chain fixes). Includes both the task-scoped rows and the
	// run-correlated rows from other entities.
	Events []AuditEvent

	// Runs are the executions this task was dispatched into, oldest first. A
	// task that ran five times has five entries, which is the distinction the
	// whole run-id mechanism exists to preserve.
	Runs []TaskRunStory

	// Unattributed counts lifecycle rows that named no run — history from
	// before run ids existed, or a dispatch whose provenance record was
	// missing. It is reported rather than silently dropped: executions the
	// trail cannot correlate are exactly what an auditor needs told.
	Unattributed int
}

// TaskRunStory is one execution of a task.
type TaskRunStory struct {
	RunID string

	// Dispatched and Finished are the boundary rows. Finished is nil for a run
	// still in flight — or for one whose hub died so hard it never wrote a
	// terminal row, which is a gap an auditor should see rather than have
	// smoothed over with an invented outcome.
	Dispatched *AuditEvent
	Finished   *AuditEvent

	// ExecutorID, ExecutorKind and Isolation are where the work ran, read from
	// the dispatch payload.
	ExecutorID   string
	ExecutorKind string
	Isolation    string

	// PinnedImage and SpecHash pin the environment.
	PinnedImage string
	SpecHash    string

	// LeaseIDs are the credentials the dispatch row claims were handed over.
	LeaseIDs []string

	// LeaseEvents are the broker's own rows for this run — the authoritative
	// half. They are kept separate from LeaseIDs on purpose: the dispatch row
	// is written by the orchestrator, which reads its lease ids from a file in
	// a directory the workload can write to, whereas these rows are written by
	// the hub and cannot be influenced from inside the sandbox. A reviewer
	// checking a hostile workload should believe these.
	LeaseEvents []AuditEvent

	// Outcome, Reason and DurationMS come from the terminal row.
	Outcome    string
	Reason     string
	DurationMS int64

	// Actor is who the dispatch row attributes the run to.
	Actor string
}

// RanOnHost reports whether this execution used the hub's own machine.
//
// Mirrors orchestrator.RanOnHost, deliberately reimplemented over the audit
// payload rather than over a pm.Task: the point of a reconstruction is that it
// works without the task record.
func (r TaskRunStory) RanOnHost() bool {
	return r.ExecutorKind == "localprocess" || (r.Isolation == "none" && r.ExecutorKind != "")
}

// maxStoryRows bounds each of the two queries the reconstruction makes. A task
// with more history than this has something pathological about it, and
// truncating loudly beats an unbounded read on a hub whose trail is millions of
// rows.
const maxStoryRows = 5000

// ReconstructTask assembles one task's whole story from audit_events alone.
//
// Returns a story with no events — rather than an error — for a task id the
// trail has never heard of. "No rows" is a legitimate and important answer: it
// is what an auditor sees for work that predates the trail, and turning it into
// an error would make the absence of evidence indistinguishable from a failure
// to look.
func (d *DB) ReconstructTask(taskID int) (TaskStory, error) {
	story := TaskStory{TaskID: taskID}

	// Step 1: everything filed against this task.
	taskRows, _, err := d.ListAuditEvents(AuditFilter{
		EntityType: "task",
		EntityID:   fmt.Sprintf("%d", taskID),
		Order:      "asc",
		Limit:      maxStoryRows,
	})
	if err != nil {
		return story, fmt.Errorf("read task audit rows: %w", err)
	}

	// Step 2: the runs those rows name, in first-seen order so the oldest
	// execution reads first.
	runs := make(map[string]*TaskRunStory)
	var runOrder []string
	for i := range taskRows {
		ev := taskRows[i]
		payload := decodeAuditPayload(ev.Payload)
		if title := payloadString(payload, "title"); title != "" {
			story.Title = title
		}
		// Only the lifecycle rows define an execution. task.upsert payloads are
		// the marshalled task, which now includes its run id, so treating any
		// row that mentions a run as evidence of one would conjure an execution
		// out of an unrelated field edit made long after the task last ran.
		if ev.EventType != "task.dispatch" && ev.EventType != "task.finish" {
			continue
		}
		runID := payloadString(payload, "run_id")
		if runID == "" {
			// A lifecycle row naming no run: pre-Task-20282 history, or a
			// dispatch whose provenance record was missing. Counted rather than
			// dropped, because "the trail records executions it cannot
			// correlate" is a finding.
			story.Unattributed++
			continue
		}
		r, ok := runs[runID]
		if !ok {
			r = &TaskRunStory{RunID: runID}
			runs[runID] = r
			runOrder = append(runOrder, runID)
		}
		applyTaskRow(r, ev, payload)
	}

	// Step 3: the rows other entities filed under the same run ids.
	//
	// The Search filter is a substring LIKE and is used only to narrow the scan
	// — it is deliberately not trusted as the join. Two reasons, and the second
	// is the one that matters: LIKE treats '_' as a single-character wildcard
	// and a run id contains one, and a substring match would in any case pull
	// in a row that merely quoted the id inside some other field. The
	// authoritative test is an exact match on the payload's run_id, applied
	// below, so the join survives both a change to the id format and a payload
	// that mentions a run without belonging to it.
	for _, runID := range runOrder {
		rows, _, err := d.ListAuditEvents(AuditFilter{
			Search: runID,
			Order:  "asc",
			Limit:  maxStoryRows,
		})
		if err != nil {
			return story, fmt.Errorf("read run %s audit rows: %w", runID, err)
		}
		r := runs[runID]
		for i := range rows {
			ev := rows[i]
			// A run's rows for tasks — this one or any other running in the
			// same execution — are not collected here. This task's own were
			// gathered in step 1; a sibling task's belong to that task's story,
			// not this one. The run is shared; the tasks are not.
			if ev.EntityType == "task" {
				continue
			}
			if payloadString(decodeAuditPayload(ev.Payload), "run_id") != runID {
				continue
			}
			story.Events = append(story.Events, ev)
			if strings.HasPrefix(ev.EventType, "secret.") || strings.HasPrefix(ev.EventType, "lease.") {
				r.LeaseEvents = append(r.LeaseEvents, ev)
			}
		}
	}

	story.Events = append(story.Events, taskRows...)
	sort.SliceStable(story.Events, func(i, j int) bool {
		return story.Events[i].ID < story.Events[j].ID
	})
	for _, runID := range runOrder {
		story.Runs = append(story.Runs, *runs[runID])
	}
	return story, nil
}

// applyTaskRow folds one task-scoped row into the run it belongs to.
func applyTaskRow(r *TaskRunStory, ev AuditEvent, payload map[string]any) {
	switch ev.EventType {
	case "task.dispatch":
		// First writer wins, and fields are only taken when the incoming row
		// carries them. One row per placement is the contract, but a trail is
		// append-only evidence rather than a schema: a duplicate — from a
		// replayed export, or from a future emitter — must degrade to a
		// redundant row, never to a half-blanked run.
		if r.Dispatched == nil {
			copyEv := ev
			r.Dispatched = &copyEv
		}
		setIfEmpty(&r.ExecutorID, payloadString(payload, "executor_id"))
		setIfEmpty(&r.ExecutorKind, payloadString(payload, "executor_kind"))
		setIfEmpty(&r.Isolation, payloadString(payload, "isolation"))
		setIfEmpty(&r.PinnedImage, payloadString(payload, "pinned_image"))
		setIfEmpty(&r.SpecHash, payloadString(payload, "spec_sha256"))
		setIfEmpty(&r.Actor, ev.Actor)
		if ids := payloadStrings(payload, "lease_ids"); len(ids) > 0 {
			r.LeaseIDs = ids
		}
	case "task.finish":
		copyEv := ev
		r.Finished = &copyEv
		r.Outcome = payloadString(payload, "outcome")
		r.Reason = payloadString(payload, "reason")
		r.DurationMS = payloadInt(payload, "duration_ms")
		setIfEmpty(&r.ExecutorID, payloadString(payload, "executor_id"))
		setIfEmpty(&r.ExecutorKind, payloadString(payload, "executor_kind"))
		setIfEmpty(&r.Isolation, payloadString(payload, "isolation"))
	}
}

func setIfEmpty(dst *string, v string) {
	if *dst == "" && v != "" {
		*dst = v
	}
}

// decodeAuditPayload parses a payload blob, yielding an empty map for anything
// that is not a JSON object. A payload that will not parse must not abort a
// reconstruction: the row is still evidence that something happened, and the
// hash chain — not this parser — is what attests to its integrity.
func decodeAuditPayload(blob string) map[string]any {
	if strings.TrimSpace(blob) == "" {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(blob), &m); err != nil || m == nil {
		return map[string]any{}
	}
	return m
}

func payloadString(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

// payloadInt reads a numeric payload field. JSON numbers decode as float64, so
// the conversion is explicit rather than a type assertion to int64 that would
// silently return zero for every value.
func payloadInt(m map[string]any, key string) int64 {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	}
	return 0
}

func payloadStrings(m map[string]any, key string) []string {
	v, ok := m[key]
	if !ok {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

// Duration renders the execution's wall time, or "" when the trail does not
// record one.
func (r TaskRunStory) Duration() string {
	if r.DurationMS <= 0 {
		return ""
	}
	return (time.Duration(r.DurationMS) * time.Millisecond).Round(time.Millisecond).String()
}
