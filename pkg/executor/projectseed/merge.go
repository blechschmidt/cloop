package projectseed

// merge.go is the hub's half of the return (Task 20339): folding what a run on
// another machine changed into the copy of the project the dashboard renders.
//
// The hub's copy is the authority. A Result is a report, from the least trusted
// party in the system, about work done out of the hub's sight — and the hub's
// copy may have moved on while the run was out: an operator can reset a task,
// delete one, or add new work at any time. So a merge takes the run's word only
// where the run is the one that knows, and only where the hub has not since
// said otherwise:
//
//   - A task's *outcome* — status, summary, timings, counters, the notes the
//     orchestrator attached — is the run's to report, because the run produced
//     it. It is taken as a unit, and only while the hub's outcome for that task
//     is still the one it sent. A task the operator reset, skipped or finished
//     by hand in the meantime keeps the operator's outcome; the later human
//     decision wins, and the report says so.
//   - Everything else about a task the hub already has — its title,
//     description, priority, dependencies, condition, schedule, approval — is
//     the hub's, and is never read from a result.
//   - A task deleted on the hub while the run was out stays deleted. One whose
//     ID now names a different task is left alone: the hub reuses IDs, so an ID
//     alone does not say "the same task", and applying a finished outcome to a
//     task that never ran is the worst mistake available here.
//   - A task the run created is added — renumbered if the hub has since given
//     its ID to a task of its own — carrying only what a plan entry needs.
//     Nothing that executes (a condition is a shell command), schedules
//     (recurrence), authorises (approval) or links out survives the trip.
//   - Where the run executed is the hub's to say. Tasks the run started are
//     stamped with the executor the hub dispatched to; the device's own record
//     is not consulted.
//   - Spend is billed to whoever the hub billed the dispatch to, and priced
//     from the hub's own table where it knows the model.

import (
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Field ceilings applied on the hub, whatever the device claims to have
// applied on its side.
const (
	maxTitleBytes       = 1 << 10
	maxDescriptionBytes = 64 << 10
	maxResultTextBytes  = 64 << 10
	maxDiagnosisBytes   = 16 << 10
	maxAnnotationBytes  = 4 << 10
	// maxAnnotationsAdded bounds how many notes one run may attach to one task.
	maxAnnotationsAdded = 50
	maxTags             = 20
	maxTagBytes         = 64
	maxCommandBytes     = 512
	maxCommands         = 20
	maxPauseDetailBytes = 1 << 10
	// maxTokenDelta bounds what one run may add to a project's token totals.
	// Far beyond any real run; there so a hostile report cannot overflow them.
	maxTokenDelta = 1 << 40
)

// eventTypePattern is what a journal event type looks like. Anything else is
// dropped rather than written: the dashboard switches on these.
var eventTypePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// Provenance is what the hub knows about a dispatch and the device does not get
// a say in.
type Provenance struct {
	// ExecutorID, ExecutorKind and Isolation are where the hub sent the run.
	ExecutorID   string
	ExecutorKind string
	Isolation    string
	// RunID is the execution id the hub minted for the dispatch; it joins the
	// tasks to the lease rows the broker wrote.
	RunID string
	// Identity is who the run's spend is billed to.
	Identity string
}

// MergeReport says what folding a Result into the hub's project did.
type MergeReport struct {
	// Updated are the tasks whose outcome was taken from the run, and
	// Outcomes their status afterwards, by ID.
	Updated  []int
	Outcomes map[int]pm.TaskStatus
	// Added are the tasks the run created, as numbered on the hub.
	Added []int
	// Renumbered maps a created task's ID on the device to the one it was
	// given here, for the tasks whose ID the hub had already used.
	Renumbered map[int]int
	// Kept are changes the hub declined, one sentence each.
	Kept []string
	// StatusFrom and StatusTo record the project status change, if any.
	StatusFrom, StatusTo string
	// Steps, Events and Costs count what was recorded.
	Steps, Events, Costs int
	// Omitted is what the device said it left out.
	Omitted []string
}

// Changed reports whether the merge altered the hub's project at all.
func (m MergeReport) Changed() bool {
	return len(m.Updated) > 0 || len(m.Added) > 0 || m.StatusTo != "" ||
		m.Steps > 0 || m.Events > 0 || m.Costs > 0
}

// Summary renders the report as one journal message.
func (m MergeReport) Summary() string {
	var parts []string
	if len(m.Updated) > 0 {
		ids := append([]int(nil), m.Updated...)
		sort.Ints(ids)
		var each []string
		for _, id := range ids {
			each = append(each, fmt.Sprintf("#%d %s", id, m.Outcomes[id]))
		}
		parts = append(parts, fmt.Sprintf("updated %s", plural(len(ids), "task", "tasks")+" ("+strings.Join(each, ", ")+")"))
	}
	if len(m.Added) > 0 {
		var each []string
		for _, id := range m.Added {
			each = append(each, fmt.Sprintf("#%d", id))
		}
		parts = append(parts, fmt.Sprintf("added %s (%s)", plural(len(m.Added), "task", "tasks"), strings.Join(each, ", ")))
	}
	var recorded []string
	if m.Steps > 0 {
		recorded = append(recorded, plural(m.Steps, "step", "steps"))
	}
	if m.Events > 0 {
		recorded = append(recorded, plural(m.Events, "journal event", "journal events"))
	}
	if m.Costs > 0 {
		recorded = append(recorded, plural(m.Costs, "cost row", "cost rows"))
	}
	if len(recorded) > 0 {
		parts = append(parts, "recorded "+strings.Join(recorded, ", "))
	}
	if m.StatusTo != "" {
		from := m.StatusFrom
		if from == "" {
			from = "unset"
		}
		parts = append(parts, fmt.Sprintf("project status %s → %s", from, m.StatusTo))
	}
	msg := "The run's results came back from the executor"
	if len(parts) == 0 {
		msg = "The run came back from the executor without changing the project"
	} else {
		msg += ": " + strings.Join(parts, "; ")
	}
	msg += "."
	if len(m.Kept) > 0 {
		msg += " Kept the hub's version where it had changed while the run was out: " + strings.Join(m.Kept, " ")
	}
	if len(m.Omitted) > 0 {
		msg += " The executor left out: " + strings.Join(m.Omitted, "; ") + "."
	}
	return msg
}

// Records are what a merge produced for the tables beside the plan.
type Records struct {
	Steps  []state.StepResult
	Events []statedb.EventRow
	Costs  []cost.LedgerEntry
}

// Merge folds r into st, the hub's copy of the project, and returns what it did
// together with the steps, events and cost rows to record. It performs no I/O;
// Apply is the caller that loads, merges and saves.
//
// scrub, when non-nil, is applied to every free-text field taken from r — the
// hub redacts what it leased to the run rather than trusting the device to have
// done it.
func Merge(st *state.ProjectState, r *Result, prov Provenance, scrub func(string) string, now time.Time) (MergeReport, Records) {
	if scrub == nil {
		scrub = func(s string) string { return s }
	}
	rep := MergeReport{Outcomes: map[int]pm.TaskStatus{}, Omitted: append([]string(nil), r.Omitted...)}
	var rec Records
	if st.Plan == nil {
		st.Plan = &pm.Plan{Goal: st.Goal}
	}

	byID := make(map[int]*pm.Task, len(st.Plan.Tasks))
	maxID := 0
	for _, t := range st.Plan.Tasks {
		if t == nil {
			continue
		}
		byID[t.ID] = t
		if t.ID > maxID {
			maxID = t.ID
		}
	}

	// Tasks the hub sent.
	for _, tc := range r.Tasks {
		if tc.Before == nil || tc.After == nil {
			continue
		}
		id := tc.After.ID
		h := byID[id]
		switch {
		case h == nil:
			if outcomeChanged(tc.Before, tc.After) {
				rep.Kept = append(rep.Kept, fmt.Sprintf("task #%d was deleted on the hub, so the run's outcome for it (%s) was not restored.",
					id, statusWord(tc.After.Status)))
			}
			continue
		case h.Title != tc.Before.Title:
			if outcomeChanged(tc.Before, tc.After) {
				rep.Kept = append(rep.Kept, fmt.Sprintf("task #%d is now %q on the hub, not the %q the run worked on, so the run's outcome (%s) was not applied to it.",
					id, clip(h.Title, 80), clip(tc.Before.Title, 80), statusWord(tc.After.Status)))
			}
			continue
		}
		if !outcomeChanged(tc.Before, tc.After) {
			// The run touched the task without changing its outcome — a note
			// added, say. Notes are history, and history is kept.
			if appendAnnotations(h, tc.Before, tc.After, scrub) {
				rep.Updated = append(rep.Updated, id)
				rep.Outcomes[id] = h.Status
			}
			continue
		}
		if !sameOutcome(h, tc.Before) {
			rep.Kept = append(rep.Kept, fmt.Sprintf("task #%d was set to %s on the hub while the run was out; the run reported %s.",
				id, statusWord(h.Status), statusWord(tc.After.Status)))
			continue
		}
		if !validStatus(tc.After.Status) {
			rep.Kept = append(rep.Kept, fmt.Sprintf("task #%d came back with an unknown status %q.", id, clip(string(tc.After.Status), 32)))
			continue
		}
		startedByRun := !sameTime(tc.Before.StartedAt, tc.After.StartedAt) || tc.Before.Status != tc.After.Status
		applyOutcome(h, tc.After, scrub)
		appendAnnotations(h, tc.Before, tc.After, scrub)
		if startedByRun {
			stamp(h, prov)
		}
		rep.Updated = append(rep.Updated, id)
		rep.Outcomes[id] = h.Status
	}

	// Tasks the run created. IDs are assigned for all of them before any is
	// built, so a created task that depends on another created task follows it
	// through a renumbering.
	//
	// Fresh IDs start above every ID either side is using, so a renumbered task
	// can never land on the ID a later created task still holds.
	for _, tc := range r.Tasks {
		if tc.Before == nil && tc.After != nil && tc.After.ID > maxID {
			maxID = tc.After.ID
		}
	}
	// assigned maps a created task's device ID to its ID here. A device ID
	// that appears twice is dropped after the first: a plan cannot hold two
	// tasks under one ID, and the device's could not have either.
	assigned := map[int]int{}
	var creations []TaskChange
	for _, tc := range r.Tasks {
		if tc.Before != nil || tc.After == nil {
			continue
		}
		id := tc.After.ID
		if _, dup := assigned[id]; dup {
			continue
		}
		if _, taken := byID[id]; taken {
			maxID++
			if rep.Renumbered == nil {
				rep.Renumbered = map[int]int{}
			}
			rep.Renumbered[id] = maxID
			assigned[id] = maxID
		} else {
			assigned[id] = id
		}
		creations = append(creations, tc)
	}
	for _, tc := range creations {
		newID := assigned[tc.After.ID]
		t := created(tc.After, newID, assigned, byID, scrub)
		if t.StartedAt != nil || t.Status != pm.TaskPending {
			stamp(t, prov)
		}
		st.Plan.Tasks = append(st.Plan.Tasks, t)
		byID[newID] = t
		rep.Added = append(rep.Added, newID)
	}

	taskRef := func(id int) int {
		if n, ok := assigned[id]; ok {
			return n
		}
		return id
	}

	// Steps: renumbered to follow the hub's own history.
	next := st.CurrentStep
	if st.StepCount > next {
		next = st.StepCount
	}
	stepMap := map[int]int{}
	for _, s := range r.Steps {
		s.Task = scrub(s.Task)
		s.Output = tail(scrub(s.Output), maxStepOutputBytes)
		s.InputTokens, s.OutputTokens = nonNegative(s.InputTokens), nonNegative(s.OutputTokens)
		if s.Time.IsZero() {
			s.Time = now
		}
		stepMap[s.Step] = next
		s.Step = next
		next++
		rec.Steps = append(rec.Steps, s)
	}
	st.CurrentStep = next
	rep.Steps = len(rec.Steps)

	// Events.
	for _, e := range r.Events {
		if !eventTypePattern.MatchString(e.Type) {
			continue
		}
		row := statedb.EventRow{
			Timestamp: e.Timestamp,
			Type:      statedb.EventType(e.Type),
			TaskID:    taskRef(e.TaskID),
			TaskTitle: truncate(scrub(e.TaskTitle), maxTitleBytes),
			Step:      statedb.NoStep,
			Message:   truncate(scrub(e.Message), maxEventMessageBytes),
			Details:   validDetails(scrub(e.Details)),
		}
		if row.Timestamp.IsZero() {
			row.Timestamp = now
		}
		if n, ok := stepMap[e.Step]; ok {
			row.Step = n
		}
		rec.Events = append(rec.Events, row)
	}
	rep.Events = len(rec.Events)

	// Costs.
	for _, c := range r.Costs {
		in, out, think := nonNegative(c.InputTokens), nonNegative(c.OutputTokens), nonNegative(c.ThinkingTokens)
		usd := c.EstimatedUSD
		if est := cost.EstimateSessionCost(c.Provider, c.Model, in, out); est > 0 {
			usd = est
		}
		if math.IsNaN(usd) || math.IsInf(usd, 0) || usd < 0 {
			usd = 0
		}
		entry := cost.LedgerEntry{
			Timestamp:      c.Timestamp,
			TaskID:         taskRef(c.TaskID),
			TaskTitle:      truncate(scrub(c.TaskTitle), maxTitleBytes),
			Provider:       truncate(c.Provider, 64),
			Model:          truncate(c.Model, 128),
			InputTokens:    in,
			OutputTokens:   out,
			ThinkingTokens: think,
			EstimatedUSD:   usd,
			Identity:       prov.Identity,
		}
		if entry.Timestamp.IsZero() {
			entry.Timestamp = now
		}
		rec.Costs = append(rec.Costs, entry)
	}
	rep.Costs = len(rec.Costs)

	st.TotalInputTokens += boundedDelta(r.InputTokens)
	st.TotalOutputTokens += boundedDelta(r.OutputTokens)
	st.EvolveStep += boundedDelta(r.EvolveSteps)

	mergeStatus(st, r, scrub, &rep)
	return rep, rec
}

// Apply loads the hub's copy of the project at workDir, merges r into it, and
// records the steps, events and cost rows the run brought back.
//
// When the plan could not be saved the report is empty, because nothing was
// merged. An error after the plan was saved — recording the journal or the cost
// rows — comes with the report of what did land, so the caller can say both.
func Apply(workDir string, r *Result, prov Provenance, scrub func(string) string) (MergeReport, error) {
	st, err := state.LoadLite(workDir)
	if err != nil {
		return MergeReport{}, fmt.Errorf("projectseed: load the hub's copy of %s: %w", workDir, err)
	}
	// The same refusal the hub's dead-run recovery makes: a project whose
	// state names another directory would have this merge saved into that
	// directory's plan instead of the one the run belonged to.
	if !sameDir(st.WorkDir, workDir) {
		return MergeReport{}, fmt.Errorf("projectseed: the state at %s belongs to %s; not merging a run into it",
			workDir, st.WorkDir)
	}
	rep, rec := Merge(st, r, prov, scrub, time.Now())
	if !rep.Changed() {
		return rep, nil
	}
	// LoadLite left Steps nil and SaveState upserts only the rows it is
	// given, so this writes the run's steps without rewriting the history.
	st.Steps = rec.Steps
	if err := st.SaveDirect(); err != nil {
		// Nothing was persisted, so there is nothing for a report to claim.
		return MergeReport{}, fmt.Errorf("projectseed: save the merged project at %s: %w", workDir, err)
	}
	if len(rec.Events) > 0 {
		if err := recordEvents(workDir, rec.Events); err != nil {
			return rep, err
		}
	}
	for _, c := range rec.Costs {
		// Through the ledger rather than straight into the table, so the row
		// also reaches the JSONL mirror and the hub's global budget ledger —
		// exactly where a run on the hub itself would have put it.
		if err := cost.AppendLedger(workDir, c); err != nil {
			return rep, fmt.Errorf("projectseed: record the run's cost for task #%d: %w", c.TaskID, err)
		}
	}
	return rep, nil
}

// recordEvents writes the run's journal rows through one database handle.
func recordEvents(workDir string, rows []statedb.EventRow) error {
	db, err := statedb.Open(state.DBPath(workDir))
	if err != nil {
		return fmt.Errorf("projectseed: open the journal of %s: %w", workDir, err)
	}
	defer db.Close()
	for _, row := range rows {
		if err := db.RecordEvent(row); err != nil {
			return fmt.Errorf("projectseed: record a %s event: %w", row.Type, err)
		}
	}
	return nil
}

// sameDir reports whether two paths name the same directory. An empty stored
// path matches: state.Load fills it from the path it read.
func sameDir(stored, dir string) bool {
	if stored == "" {
		return true
	}
	resolve := func(p string) string {
		abs, err := filepath.Abs(p)
		if err != nil {
			return filepath.Clean(p)
		}
		if real, err := filepath.EvalSymlinks(abs); err == nil {
			return real
		}
		return abs
	}
	return resolve(stored) == resolve(dir)
}

// mergeStatus adopts the status the run ended with.
//
// "running" and "evolving" are adopted too, although neither is true any more:
// they are what a run that was killed leaves behind, and the hub's dead-run
// recovery (which runs right after a merge) is the thing that knows how to
// settle them — it resets the tasks the run stranded and pauses the project
// with the executor's account of how the run ended. Adopting them hands that
// machinery the case it was built for.
func mergeStatus(st *state.ProjectState, r *Result, scrub func(string) string, rep *MergeReport) {
	from := st.Status
	switch r.Status {
	case "complete":
		if pending := unfinished(st.Plan); pending > 0 {
			// The run finished the plan it was sent; the hub's plan has grown
			// since. Calling that complete would hide work nobody has run.
			st.SetPaused(pausereason.New(pausereason.CodeIdle, fmt.Sprintf(
				"the run finished the plan it was sent, but %s here %s work left — added or reset on the hub while it was out",
				plural(pending, "task", "tasks"), stillHave(pending))))
		} else {
			st.Status, st.PauseReason = "complete", nil
		}
	case "paused":
		if r.PauseReason != nil && pausereason.Known(r.PauseReason.Code) {
			pr := *r.PauseReason
			pr.Detail = truncate(scrub(pr.Detail), maxPauseDetailBytes)
			st.SetPaused(pr)
		} else {
			// An older build on the device pauses without recording why, and a
			// code this hub does not know cannot be rendered. Either way the
			// operator is owed a reason rather than a bare "paused".
			st.SetPaused(pausereason.New(pausereason.CodeCancelled,
				"the run on the executor paused without recording a reason this hub understands"))
		}
	case "failed", "running", "evolving", "initialized":
		st.Status, st.PauseReason = r.Status, nil
	default:
		return
	}
	if st.Status != from {
		rep.StatusFrom, rep.StatusTo = from, st.Status
	}
}

// outcomeChanged reports whether the run changed a task's outcome.
func outcomeChanged(before, after *pm.Task) bool {
	return !sameOutcome(after, before)
}

// sameOutcome compares the outcome fields of two tasks. It is the test for
// "the hub's outcome is still the one it sent" as well as for "the run changed
// nothing that matters".
func sameOutcome(a, b *pm.Task) bool {
	return a.Status == b.Status &&
		a.Result == b.Result &&
		sameTime(a.StartedAt, b.StartedAt) &&
		sameTime(a.CompletedAt, b.CompletedAt) &&
		a.ActualMinutes == b.ActualMinutes &&
		a.FailureDiagnosis == b.FailureDiagnosis &&
		a.FailCount == b.FailCount &&
		a.HealAttempts == b.HealAttempts &&
		a.VerifyRetries == b.VerifyRetries &&
		a.TDDStatus == b.TDDStatus &&
		a.TDDScore == b.TDDScore &&
		sameJSON(a.Background, b.Background) &&
		sameJSON(a.Abort, b.Abort)
}

// applyOutcome copies the outcome fields from the run's task onto the hub's.
func applyOutcome(h, after *pm.Task, scrub func(string) string) {
	h.Status = after.Status
	h.Result = truncate(scrub(after.Result), maxResultTextBytes)
	h.StartedAt = cloneTime(after.StartedAt)
	h.CompletedAt = cloneTime(after.CompletedAt)
	h.ActualMinutes = nonNegative(after.ActualMinutes)
	h.FailureDiagnosis = truncate(scrub(after.FailureDiagnosis), maxDiagnosisBytes)
	h.FailCount = nonNegative(after.FailCount)
	h.HealAttempts = nonNegative(after.HealAttempts)
	h.VerifyRetries = nonNegative(after.VerifyRetries)
	h.TDDStatus = truncate(after.TDDStatus, 32)
	h.TDDScore = clampInt(after.TDDScore, 0, 100)
	h.Background = sanitizeBackground(after.Background, scrub)
	h.Abort = sanitizeAbort(after.Abort, h.Abort, scrub)
}

// appendAnnotations adds the notes the run attached to a task. It reports
// whether any were added.
func appendAnnotations(h, before, after *pm.Task, scrub func(string) string) bool {
	seen := make(map[string]bool, len(before.Annotations)+len(h.Annotations))
	key := func(a pm.Annotation) string {
		return a.Timestamp.UTC().Format(time.RFC3339Nano) + "\x00" + a.Author + "\x00" + a.Text
	}
	for _, a := range before.Annotations {
		seen[key(a)] = true
	}
	for _, a := range h.Annotations {
		seen[key(a)] = true
	}
	added := 0
	for _, a := range after.Annotations {
		if seen[key(a)] || added >= maxAnnotationsAdded {
			continue
		}
		seen[key(a)] = true
		h.Annotations = append(h.Annotations, pm.Annotation{
			Timestamp: a.Timestamp,
			Author:    authorOf(a.Author),
			Text:      truncate(scrub(a.Text), maxAnnotationBytes),
		})
		added++
	}
	return added > 0
}

// created builds the hub's copy of a task the run created, from the fields a
// plan entry needs and nothing else.
func created(t *pm.Task, id int, assigned map[int]int, known map[int]*pm.Task, scrub func(string) string) *pm.Task {
	title := strings.TrimSpace(truncate(scrub(t.Title), maxTitleBytes))
	if title == "" {
		title = fmt.Sprintf("Task #%d (created by a run on an executor)", id)
	}
	c := &pm.Task{
		ID:               id,
		Title:            title,
		Description:      truncate(scrub(t.Description), maxDescriptionBytes),
		Priority:         clampInt(t.Priority, 0, 1_000_000),
		Role:             pm.AgentRole(truncate(string(t.Role), 32)),
		EstimatedMinutes: clampInt(t.EstimatedMinutes, 0, 100_000),
		Status:           pm.TaskPending,
	}
	for _, dep := range t.DependsOn {
		if n, ok := assigned[dep]; ok {
			dep = n
		} else if known[dep] == nil {
			continue
		}
		if dep != id {
			c.DependsOn = append(c.DependsOn, dep)
		}
	}
	for _, tag := range t.Tags {
		if len(c.Tags) >= maxTags {
			break
		}
		if tag = strings.TrimSpace(truncate(scrub(tag), maxTagBytes)); tag != "" {
			c.Tags = append(c.Tags, tag)
		}
	}
	if validStatus(t.Status) {
		applyOutcome(c, t, scrub)
	}
	appendAnnotations(c, &pm.Task{}, t, scrub)
	return c
}

// stamp records where a task ran, from the hub's own dispatch record.
func stamp(t *pm.Task, prov Provenance) {
	if prov.ExecutorID == "" && prov.ExecutorKind == "" {
		return
	}
	t.ExecutorID, t.ExecutorKind, t.Isolation = prov.ExecutorID, prov.ExecutorKind, prov.Isolation
	if prov.RunID != "" {
		t.RunID = prov.RunID
	}
}

// sanitizeBackground bounds a background-work record.
func sanitizeBackground(b *pm.BackgroundWork, scrub func(string) string) *pm.BackgroundWork {
	if b == nil {
		return nil
	}
	c := *b
	c.Commands = nil
	for _, cmd := range b.Commands {
		if len(c.Commands) >= maxCommands {
			break
		}
		c.Commands = append(c.Commands, truncate(scrub(cmd), maxCommandBytes))
	}
	switch c.State {
	case pm.BackgroundWaiting, pm.BackgroundDrained, pm.BackgroundAbandoned:
	default:
		c.State = pm.BackgroundAbandoned
	}
	c.Detected, c.WaitedSeconds, c.Terminated = nonNegative(c.Detected), nonNegative(c.WaitedSeconds), nonNegative(c.Terminated)
	return &c
}

// sanitizeAbort bounds an abort record and strips any clearance the run claims
// to have made. A clearance is an operator's verdict that the work exists
// despite a refusal; it is kept only if the hub's own record already carried it
// for the same summary.
func sanitizeAbort(a, hub *pm.TaskAbort, scrub func(string) string) *pm.TaskAbort {
	if a == nil {
		return nil
	}
	c := pm.TaskAbort{
		Class:              truncate(a.Class, 64),
		Reason:             truncate(scrub(a.Reason), maxDiagnosisBytes),
		Evidence:           truncate(scrub(a.Evidence), maxDiagnosisBytes),
		DetectedAt:         a.DetectedAt,
		SummaryFingerprint: truncate(a.SummaryFingerprint, 128),
	}
	if hub != nil && hub.Cleared && hub.SummaryFingerprint == c.SummaryFingerprint {
		c.Cleared, c.ClearedBy, c.ClearedNote, c.ClearedAt = hub.Cleared, hub.ClearedBy, hub.ClearedNote, cloneTime(hub.ClearedAt)
	}
	return &c
}

// validDetails keeps an event's details only if they are bounded, valid JSON.
func validDetails(d string) string {
	if d == "" || len(d) > maxEventDetailBytes || !json.Valid([]byte(d)) {
		return ""
	}
	return d
}

func validStatus(s pm.TaskStatus) bool {
	switch s {
	case pm.TaskPending, pm.TaskInProgress, pm.TaskDone, pm.TaskFailed, pm.TaskSkipped, pm.TaskTimedOut:
		return true
	}
	return false
}

// unfinished counts the tasks in p that still have work to do.
func unfinished(p *pm.Plan) int {
	if p == nil {
		return 0
	}
	n := 0
	for _, t := range p.Tasks {
		if t != nil && (t.Status == pm.TaskPending || t.Status == pm.TaskInProgress) {
			n++
		}
	}
	return n
}

func authorOf(a string) string {
	if a == "user" {
		return "user"
	}
	return "ai"
}

func statusWord(s pm.TaskStatus) string {
	if s == "" {
		return "no status"
	}
	return string(s)
}

func sameTime(a, b *time.Time) bool {
	switch {
	case a == nil || b == nil:
		return a == nil && b == nil
	default:
		return a.Equal(*b)
	}
}

func cloneTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}

// sameJSON compares two values by their JSON encodings with every timestamp in
// UTC, which is how the same record read from two databases compares equal.
func sameJSON(a, b any) bool {
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	return normalizeTimes(string(ja)) == normalizeTimes(string(jb))
}

// rfc3339 matches an RFC 3339 timestamp inside JSON.
var rfc3339 = regexp.MustCompile(`"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})"`)

func normalizeTimes(s string) string {
	return rfc3339.ReplaceAllStringFunc(s, func(m string) string {
		t, err := time.Parse(time.RFC3339Nano, strings.Trim(m, `"`))
		if err != nil {
			return m
		}
		return `"` + t.UTC().Format(time.RFC3339Nano) + `"`
	})
}

func boundedDelta(n int) int {
	return clampInt(n, 0, maxTokenDelta)
}

func clampInt(n, lo, hi int) int {
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return truncate(s, n) + "…"
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func stillHave(n int) string {
	if n == 1 {
		return "still has"
	}
	return "still have"
}
