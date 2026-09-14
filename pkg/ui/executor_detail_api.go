package ui

// GET /api/executors/{id} — one executor, and what it has actually run
// (Task 20244).
//
// The list route answers "what is in the fleet". This answers the question an
// operator asks next, and which nothing could answer before: "what has this
// device been running?" That question is the whole point of recording executor
// attribution on tasks — a hub that claims never to spawn a harness on the
// host has to be able to show its work, per executor, after the fact.
//
// Why it does not simply list the executor's bound projects' tasks: a binding
// says where a project's *next* task would go. Rebind a project and the
// binding now describes a placement that never happened for anything already
// run — which is precisely the case an audit is looking for. So the scan is
// over every registered project and filters on the attribution stamped on each
// task, and the binding list is reported separately, as a different fact.

import (
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// maxExecutorDetailCompleted bounds the completed-task list. An executor that
// has run thousands of tasks must not turn one panel refresh into a
// multi-megabyte response — the amplification defect Task 20188 fixed
// elsewhere in this API.
const maxExecutorDetailCompleted = 25

// maxExecutorDetailTitleLen bounds one title. This route fans out across every
// project, so an unbounded title is multiplied by the whole sweep rather than
// by one plan — the shape of the amplification defect Task 20188 fixed on the
// analytics endpoint. Titles on this project's own plan already run to a
// paragraph, so the cap is reached in practice, not just in theory.
const maxExecutorDetailTitleLen = 160

// maxExecutorDetailProjects bounds the scan. Each project costs one SQLite
// open and a lite state read; an unbounded fleet would make this route's cost
// a function of how many projects the hub has ever seen. When the cap bites,
// the response says so rather than quietly presenting a partial history as a
// complete one.
const maxExecutorDetailProjects = 200

// executorTaskRef is one task this executor ran, projected down to what a
// fleet view needs.
//
// Deliberately not the whole pm.Task. This route is reachable with a
// fleet-scoped permission rather than a project-scoped one, so it is the one
// place where tasks from projects the caller never selected become visible;
// the projection keeps that to identity and lifecycle and leaves descriptions,
// results and annotations to the project's own endpoints.
type executorTaskRef struct {
	ProjectName string     `json:"project_name"`
	ProjectPath string     `json:"project_path"`
	ID          int        `json:"id"`
	Title       string     `json:"title"`
	Status      string     `json:"status"`
	Isolation   string     `json:"isolation,omitempty"`
	OnHost      bool       `json:"on_host"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// executorWorkload is the attribution half of the detail payload.
type executorWorkload struct {
	// InFlight is every task currently marked in_progress on this executor.
	// Unbounded on purpose: an executor with more in-flight tasks than fit in
	// a response is itself the finding, and truncating it would hide it.
	InFlight []executorTaskRef `json:"in_flight"`
	// Completed is the most recently finished tasks, newest first.
	Completed []executorTaskRef `json:"completed"`
	// CompletedTotal is how many were found before the cap, so the panel can
	// say "25 of 400" rather than implying it is showing everything.
	CompletedTotal int `json:"completed_total"`
	// HostTotal counts attributed tasks that ran on the host. It is the number
	// the no-host-execution claim is audited against, so it counts every one
	// found — not merely the ones that survived the display cap, and not
	// merely the ones still in a lifecycle state that puts them in a list
	// above. Undercounting here would let a fleet that did run work on the
	// host report that it had not.
	HostTotal int `json:"host_total"`
	// NotRunning counts attributed tasks that are neither in flight nor
	// finished — reset after a previous run, most often. They keep the
	// attribution from the run that did happen, which is why they are counted
	// in HostTotal, but listing them as completed work would report a task
	// that never finished as one that did.
	//
	// Reported rather than silently dropped because without it a caller sees
	// a non-zero HostTotal above two empty lists and has no way to tell a
	// real discrepancy from a bug. `GET /api/tasks?executor_id=<id>` is where
	// the individual rows are.
	NotRunning int `json:"not_running"`
	// ProjectsScanned and ProjectsTruncated describe the sweep's coverage, so
	// an empty result can be told apart from an incomplete one.
	ProjectsScanned   int  `json:"projects_scanned"`
	ProjectsTruncated bool `json:"projects_truncated"`
}

// executorDetailView is the payload: the fleet card, plus what ran on it.
//
// executorView is embedded rather than nested so the detail response is a
// superset of a list entry, and the frontend can render either with the same
// code — capabilities, agent build version and bound projects all arrive
// under the names the panel already knows.
type executorDetailView struct {
	executorView
	Workload executorWorkload `json:"workload"`
}

// handleExecutorDetail serves GET /api/executors/{id}.
func (s *Server) handleExecutorDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonErr(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		jsonErr(w, "executor id is required", http.StatusBadRequest)
		return
	}

	// As on the list route, a database that will not open is not fatal: the
	// registry alone still describes the built-in drivers, and a card that
	// renders beats an error page.
	db, err := s.controlPlaneDB()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: executor detail %s: control-plane database unavailable: %v\n", id, err)
	} else {
		defer db.Close()
	}

	var (
		live executor.Executor
		row  statedb.ExecutorRow
	)
	for _, ex := range executor.List() {
		if ex.ID() == id {
			live = ex
			break
		}
	}
	if db != nil {
		if got, err := db.GetExecutor(id); err == nil {
			row = got
		}
	}
	// Unknown to both the registry and the store is a 404. An executor that
	// exists in only one of them is not: a device whose config section was
	// removed still has a history worth reading, and that is exactly when
	// someone goes looking for it.
	if live == nil && row.ID == "" {
		jsonErr(w, "executor not found", http.StatusNotFound)
		return
	}

	var bound []string
	if db != nil {
		if bindings, err := db.ListProjectExecutorBindings(); err == nil {
			for _, b := range bindings {
				if b.ExecutorID == id {
					bound = append(bound, b.ProjectPath)
				}
			}
		} else {
			fmt.Fprintf(os.Stderr, "ui: executor detail %s: list bindings: %v\n", id, err)
		}
	}

	view := s.buildExecutorView(r.Context(), id, live, row, bound,
		executor.DefaultRegistry.DefaultID(), schedulerFor(db))

	jsonOK(w, executorDetailView{
		executorView: view,
		Workload:     s.collectExecutorWorkload(id),
	})
}

// collectExecutorWorkload sweeps the registered projects for tasks attributed
// to this executor.
//
// Every failure is skipped rather than propagated. A project directory that
// was deleted, moved, or never initialised must not take down the fleet view
// of an executor that is running fine — and ProjectsScanned below reports how
// much of the sweep actually landed, so a partial answer is visibly partial.
func (s *Server) collectExecutorWorkload(id string) executorWorkload {
	out := executorWorkload{
		InFlight:  []executorTaskRef{},
		Completed: []executorTaskRef{},
	}
	// allProjectEntries, not multiui.Load: the registry is only part of the
	// hub's view. A deployment launched as `cloop ui` in a directory, or with
	// --projects, serves projects that were never registered — and sweeping
	// only the registry would report those executors as having run nothing,
	// which is the exact false negative this route exists to prevent.
	projects := s.allProjectEntries()
	if len(projects) > maxExecutorDetailProjects {
		projects = projects[:maxExecutorDetailProjects]
		out.ProjectsTruncated = true
	}

	for _, p := range projects {
		// LoadLite is the same reader the projects panel uses for other
		// projects' counts: it skips the step history, which this route has no
		// use for and which is the expensive part of a large project's state.
		st, err := state.LoadLite(p.Path)
		if err != nil || st == nil || st.Plan == nil {
			continue
		}
		out.ProjectsScanned++
		for _, t := range st.Plan.Tasks {
			if t == nil || t.ExecutorID != id {
				continue
			}
			ref := executorTaskRef{
				ProjectName: p.Name,
				ProjectPath: p.Path,
				ID:          t.ID,
				Title:       boundTitle(t.Title),
				Status:      taskStatusOrPendingRef(t),
				Isolation:   t.Isolation,
				OnHost:      taskRanOnHost(t),
				StartedAt:   t.StartedAt,
				CompletedAt: t.CompletedAt,
			}
			if ref.OnHost {
				out.HostTotal++
			}
			if t.Status == pm.TaskInProgress {
				out.InFlight = append(out.InFlight, ref)
				continue
			}
			if t.CompletedAt == nil {
				// Neither running nor finished — reset after a previous run,
				// most often. It carries that run's attribution, so it stays
				// in HostTotal, but listing it as completed work would report
				// a task that never finished as one that did.
				out.NotRunning++
				continue
			}
			out.CompletedTotal++
			out.Completed = append(out.Completed, ref)
		}
	}

	sort.Slice(out.InFlight, func(i, j int) bool {
		return executorRefStart(out.InFlight[i]).After(executorRefStart(out.InFlight[j]))
	})
	sort.Slice(out.Completed, func(i, j int) bool {
		return out.Completed[i].CompletedAt.After(*out.Completed[j].CompletedAt)
	})
	if len(out.Completed) > maxExecutorDetailCompleted {
		out.Completed = out.Completed[:maxExecutorDetailCompleted]
	}
	return out
}

// boundTitle truncates a title to the display cap, counting runes rather than
// bytes so a multi-byte character is never cut in half into invalid UTF-8.
func boundTitle(s string) string {
	r := []rune(s)
	if len(r) <= maxExecutorDetailTitleLen {
		return s
	}
	return string(r[:maxExecutorDetailTitleLen]) + "…"
}

// executorRefStart is a sortable start time; a task with none sorts last.
func executorRefStart(ref executorTaskRef) time.Time {
	if ref.StartedAt == nil {
		return time.Time{}
	}
	return *ref.StartedAt
}

// taskStatusOrPendingRef mirrors the list endpoints' treatment of an empty
// status, so one task does not read as "" here and "pending" there.
func taskStatusOrPendingRef(t *pm.Task) string {
	if t.Status == "" {
		return string(pm.TaskPending)
	}
	return string(t.Status)
}

// taskRanOnHost reports whether a task's attribution says the harness ran as a
// process on the hub's own machine.
//
// Duplicated from the orchestrator's RanOnHost rather than imported: pkg/ui
// does not depend on pkg/orchestrator, and a route that renders a warning
// badge is not a reason to make it. The predicate is two string comparisons
// and TestExecutorDetail_HostPredicateMatchesOrchestrator pins the two
// together so they cannot drift apart silently.
func taskRanOnHost(t *pm.Task) bool {
	if t == nil {
		return false
	}
	return t.ExecutorKind == executor.KindLocalProcess ||
		(t.Isolation == string(executor.IsolationNone) && t.ExecutorKind != "")
}
