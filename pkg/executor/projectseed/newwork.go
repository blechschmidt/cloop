package projectseed

// newwork.go: work the hub's plan gained while a seeded run was out (Task
// 20516).
//
// A run on an executor that cannot read the hub's filesystem works from the
// copy of the plan it was sent. A task added on the hub after the copy was
// made — or reset there — is in no plan that run can see, so the run reaches
// the end of its own plan and stops with that task still waiting. A run on the
// hub's host reads the plan as it changes and would simply have carried on.
// Before this file the hub paused the project instead ("the run finished the
// plan it was sent, but 1 task here still has work left"), and someone had to
// press Run once for every batch of tasks they added while a device worked.
//
// So the hub records, when it builds a seed, which tasks the run could start
// (SeedWork). When the run comes back at the ordinary end of its plan, a task
// of the hub's plan that a run starting now would start, and that is not one
// of those, is work the run never had: the project is paused work_added, which
// the hub resumes at once with a run of the plan as it stands now.
//
// Only work the run could not have started counts. A task it was sent able to
// start and came back without starting — a device that holds it for a reason
// of its own — would be sent again by the next run, and declined again, and
// the hub would go on starting runs for it. So would a task the run created
// itself, which it was free to start and did not, and a task the run reported
// on at all: one it set back to pending, or worked on under a title the hub
// has changed since. Those are left for a person, as before.
//
// Nor does the hub carry on where a person decides: a run the hub was asked to
// stop as it finished stays stopped, and a project bound to an executor pool
// is queued for a runner only when someone presses Run.

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// SeedWork is what the plan a seed carried held for its run to start, as the
// hub recorded it when it built the seed (Task 20516).
type SeedWork struct {
	// Startable maps each task the run could start as it began — the plan's
	// pm.Plan.StartableTasks — to the digest of the title it was sent under
	// (TitleDigest). The title is part of the identity because the hub reuses
	// an ID once its task is deleted, as the merge's own rules say.
	Startable map[int]string `json:"startable,omitempty"`
}

// StartableWork records what plan holds for a run to start: each of its
// startable tasks by ID, with the digest of its title. Never nil, so a plan
// with nothing to start is recorded as having nothing, not as unknown.
func StartableWork(plan *pm.Plan) map[int]string {
	out := map[int]string{}
	for _, t := range plan.StartableTasks() {
		out[t.ID] = TitleDigest(t.Title)
	}
	return out
}

// TitleDigest identifies a task's title without carrying it: the record of a
// seed is kept with the run and copied to the run's owner row, and a plan's
// titles are a hub's to keep.
func TitleDigest(title string) string {
	sum := sha256.Sum256([]byte(title))
	return hex.EncodeToString(sum[:8])
}

// SeedTasks records every task of plan by ID with the digest of its title and
// description (TaskDigest): what a run sent this plan has under each ID, so
// the hub can tell whether a model call made on the run's copy of the project
// would read the task as the hub has it (Task 20517). Never nil.
func SeedTasks(plan *pm.Plan) map[int]string {
	out := map[int]string{}
	if plan == nil {
		return out
	}
	for _, t := range plan.Tasks {
		if t != nil {
			out[t.ID] = TaskDigest(t)
		}
	}
	return out
}

// TaskDigest identifies a task's title and description without carrying them.
func TaskDigest(t *pm.Task) string {
	sum := sha256.Sum256([]byte(t.Title + "\x00" + t.Description))
	return hex.EncodeToString(sum[:8])
}

// newWork returns the tasks of plan a run starting now would start that the
// run which came back could not have started: not among the tasks its seed
// held startable, by ID and title, not created by the run, and not one the run
// reported on (reported, by the hub's IDs).
//
// A dispatch recorded before Task 20516 (sent nil) says nothing about what its
// seed held, and every startable task the run did not touch counts. That can
// count one the run was sent and declined — once: the run started for it is
// recorded, so what that one declines is not counted again.
func newWork(plan *pm.Plan, sent *SeedWork, created []int, reported map[int]bool) []*pm.Task {
	own := make(map[int]bool, len(created))
	for _, id := range created {
		own[id] = true
	}
	var out []*pm.Task
	for _, t := range plan.StartableTasks() {
		if own[t.ID] || reported[t.ID] {
			continue
		}
		if sent != nil {
			// A title is no secret, but a digest is compared the way every
			// digest here is (tests/security's timing gate).
			if d, ok := sent.Startable[t.ID]; ok &&
				subtle.ConstantTimeCompare([]byte(d), []byte(TitleDigest(t.Title))) == 1 {
				continue
			}
		}
		out = append(out, t)
	}
	return out
}

// ordinaryEnd reports whether a run's pause is the ordinary end of the plan it
// was sent rather than a reason to stop: nothing left it could start (idle),
// or a closed review gate it reached (Task 20477), which the hub's copy may
// have opened since. Every other pause stopped the run for a reason of its own
// — a cap, a budget, a person — and keeps it.
func ordinaryEnd(st *state.ProjectState, pr *pausereason.Reason) bool {
	if pr == nil {
		return false
	}
	switch pr.Code {
	case pausereason.CodeIdle:
		return true
	case pausereason.CodeApproval:
		// A gate, not a work task whose approval was declined: that is a
		// person's decision, and the hub's copy of it is the run's.
		if pr.TaskID <= 0 || st.Plan == nil {
			return false
		}
		g := st.Plan.TaskByID(pr.TaskID)
		return g != nil && !g.IsWork()
	}
	return false
}

// finishPlan records how the hub's plan stands once a run came back at the
// ordinary end of the plan it was sent (Task 20516): status "complete", or
// paused with devicePause, the run's own account of where it stopped (idle, or
// at a review gate). It reports whether it decided; when it did not, the run's
// pause is adopted as any other.
//
// Work the hub's plan gained while the run was out (newWork) is carried on
// with: the project is paused work_added, which the hub restarts at once —
// unless the hub was asked to stop the run, which then stays stopped, or the
// project runs on an executor pool, whose runs the hub does not queue by
// itself. With no new work the plan settles as a run on the hub's host would
// have left it (settleFinishedPlan), except that a run stopped at a review gate
// keeps its own pause.
func finishPlan(st *state.ProjectState, devicePause *pausereason.Reason, prov Provenance, rep *MergeReport,
	now time.Time, opt mergeOptions) bool {
	work := newWork(st.Plan, prov.Sent, rep.Added, rep.reported)
	if len(work) > 0 {
		rep.NewWork = make([]int, 0, len(work))
		for _, t := range work {
			rep.NewWork = append(rep.NewWork, t.ID)
		}
		added := newWorkPhrase(rep.NewWork) + " added or reset here while the run was out"
		switch {
		case opt.stopRequested:
			rep.HeldBy = HeldByStop
			st.SetPaused(pausereason.New(pausereason.CodeOperator, "run stopped; "+added))
		case prov.Pooled:
			rep.HeldBy = HeldByPool
			st.SetPaused(pausereason.New(pausereason.CodeIdle, added+
				"; this project runs on an executor pool, so press Run to queue a run for them"))
		default:
			st.SetPaused(pausereason.NewUntil(pausereason.CodeWorkAdded, added, now))
		}
		return true
	}
	if devicePause != nil && devicePause.Code != pausereason.CodeIdle {
		return false
	}
	settleFinishedPlan(st)
	return true
}

// settleFinishedPlan records how the hub's plan stands once a run that
// finished the plan it was sent came back, with no new work for another run
// to start (Task 20516) — as a run on the hub's host, reading this plan, would
// have recorded it.
//
// Complete when nothing is left that any run could start: every task done,
// skipped or failed, or blocked for good behind a failed dependency. Paused at
// a closed review gate a person has to open, when that is what holds the rest.
// Otherwise paused idle, naming what is left: tasks the run was sent able to
// start and came back without starting, tasks it reported on, or tasks nothing
// can start, such as two that wait on each other. Starting another run by
// itself would only have it decline them again, so they wait for a person.
func settleFinishedPlan(st *state.ProjectState) {
	plan := st.Plan
	if unfinished(plan) == 0 || plan.IsComplete() {
		st.Status, st.PauseReason = "complete", nil
		return
	}
	if g := plan.WaitingGate(); g != nil {
		st.SetPaused(pausereason.NewForTask(pausereason.CodeApproval,
			fmt.Sprintf("waiting for human review at gate #%d: %s", g.ID, clip(g.Title, 120)), g.ID))
		return
	}
	var left []int
	for _, t := range plan.Tasks {
		if t != nil && (t.Status == pm.TaskPending || t.Status == pm.TaskInProgress) {
			left = append(left, t.ID)
		}
	}
	st.SetPaused(pausereason.New(pausereason.CodeIdle, fmt.Sprintf(
		"the run finished the plan it was sent; %s here %s still pending (%s)",
		plural(len(left), "task", "tasks"), isAre(len(left)), taskRefs(left, maxRefsInDetail))))
}

// isAre is "is" for one and "are" for any other count.
func isAre(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

// HeldBy names why the hub did not start a run for new work it found.
type HeldBy string

const (
	// HeldByStop: the hub was asked to stop the run as it finished.
	HeldByStop HeldBy = "stop"
	// HeldByPool: the project runs on an executor pool, whose runs the hub
	// queues only when a person starts them.
	HeldByPool HeldBy = "pool"
)

// maxRefsInDetail bounds the task references a pause's detail lists: it is one
// line on a badge, and the journal row names every task.
const maxRefsInDetail = 5

// newWorkPhrase names the tasks of new work as the subject of a sentence:
// "task #4 was", "tasks #4 and #5 were", "7 tasks (#4, #5, #6, #8, #9, …) were".
func newWorkPhrase(ids []int) string {
	switch len(ids) {
	case 0:
		return "no task was"
	case 1:
		return fmt.Sprintf("task #%d was", ids[0])
	case 2:
		return fmt.Sprintf("tasks #%d and #%d were", ids[0], ids[1])
	}
	return fmt.Sprintf("%d tasks (%s) were", len(ids), taskRefs(ids, maxRefsInDetail))
}

// taskRefs lists ids as "#1, #2, #3", the first max of them and an ellipsis
// for the rest.
func taskRefs(ids []int, max int) string {
	var b strings.Builder
	for i, id := range ids {
		if i == max {
			b.WriteString(", …")
			break
		}
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "#%d", id)
	}
	return b.String()
}
