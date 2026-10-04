package configvalidate

// statedb.go: the state-database checks, and what --fix may do about them.
//
// --fix used to reset every in_progress task to pending with a bare UPDATE on a
// bare connection (Task 20374). That was wrong in two ways at once. A task is
// in progress for one of two reasons — a run is executing it, or a run died
// while it was — and the old fix could not tell them apart: run beside a live
// run, it reset the task under the process executing it, so the task ran twice.
// And even for the dead run it skipped everything cloop does when it recovers
// one: the kill-request path that stops a live task properly (Task 20140), the
// verdict sidecar that keeps a task the review gate failed from coming back as
// pending (Task 20365), the live artifact that keeps a finished task from
// running again (taskrecover), the events journal and the audit trail.
//
// So the checks now ask first whether a run of the project is live, the way the
// hub asks before it repairs a dead run (pkg/runprobe). While one is, a task in
// progress is simply being executed, and --fix leaves the plan alone: stopping
// a run is what the Stop button and the kill-request path are for. When none
// is, the tasks a dead run left are recovered by pkg/taskrecover — the code the
// hub and the orchestrator recover them with — and saved through statedb.

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/runprobe"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/taskrecover"
)

// probeRun reports whether a run of the project at dir is live. A variable so
// tests can stand in for /proc and the hubs on the host.
var probeRun = runprobe.Project

// staleRunDetail is the pause reason a dead run's stale status is replaced
// with: the words the hub uses for the same repair, so the dashboard shows one
// explanation whichever of them made it.
const staleRunDetail = "previous run ended without reporting an outcome"

// taskRow is one task as the read-only check sees it.
type taskRow struct {
	id     int
	title  string
	status string
}

// checkStateDB validates the task statuses and the run status stored in the
// project database at dbPath, and with fix repairs what it safely can.
func checkStateDB(workdir, dbPath string, fix bool, rep *Report, add func(Finding)) error {
	tasks, runStatus, err := readStateForValidation(dbPath)
	if err != nil {
		return err
	}

	var invalid, inProgress []taskRow
	for _, t := range tasks {
		switch {
		case !validTaskStatuses[t.status]:
			invalid = append(invalid, t)
		case t.status == string(pm.TaskInProgress):
			inProgress = append(inProgress, t)
		}
	}
	claimsRun := runStatus == "running" || runStatus == "evolving"
	if len(invalid) == 0 && len(inProgress) == 0 && !claimsRun {
		return nil
	}

	run := probeRun(workdir)

	for _, t := range invalid {
		note := `will be reset to "pending"`
		if run.Live {
			note = "none while a run of this project is live; stop it first"
		}
		add(Finding{
			Severity: SeverityError,
			Field:    taskField(t.id),
			Message:  fmt.Sprintf("task %q has invalid status %q — not a known status value", t.title, t.status),
			FixNote:  note,
		})
	}
	for _, t := range inProgress {
		if run.Live {
			add(Finding{
				Severity: SeverityInfo,
				Field:    taskField(t.id),
				Message:  fmt.Sprintf("task %q is in progress, and a run of this project is live: %s", t.title, run.Reason),
			})
			continue
		}
		add(Finding{
			Severity: SeverityWarn,
			Field:    taskField(t.id),
			Message:  fmt.Sprintf("task %q is in progress but no run of this project is live — a run ended without recording its outcome", t.title),
			FixNote:  `will be recovered as after any dead run: its outcome adopted if the agent had finished, otherwise reset to "pending"`,
		})
	}
	if claimsRun && !run.Live {
		add(Finding{
			Severity: SeverityWarn,
			Field:    "state.db:status",
			Message:  fmt.Sprintf("the project's status is %q but no run of it is live — a run ended without recording an outcome", runStatus),
			FixNote:  `will be set to "paused" so the project can be started again`,
		})
	}

	if !fix {
		return nil
	}
	if run.Live {
		if len(invalid) > 0 {
			add(Finding{
				Severity: SeverityWarn,
				Field:    "state.db",
				Message: fmt.Sprintf("--fix did not reset the %d invalid status(es): a run of this project is live (%s), "+
					"and it saves its whole plan, so it would write its own copy of each task back over the fix — "+
					"stop the run, then run --fix again", len(invalid), run.Reason),
			})
		}
		if len(inProgress) > 0 {
			add(Finding{
				Severity: SeverityInfo,
				Field:    "state.db",
				Message: fmt.Sprintf("--fix left the %d in-progress task(s) alone: they belong to the live run; "+
					"if one is stuck, stop it from the dashboard or by setting its status, which aborts it", len(inProgress)),
			})
		}
		return nil
	}
	repairDeadRun(workdir, rep, add)
	return nil
}

// repairDeadRun applies --fix to a project no run is executing: invalid
// statuses reset to pending, the tasks a dead run left in progress recovered by
// pkg/taskrecover, a stale run status paused — all in one save through statedb,
// and each recorded in the events journal.
func repairDeadRun(workdir string, rep *Report, add func(Finding)) {
	refuse := func(format string, args ...any) {
		add(Finding{Severity: SeverityWarn, Field: "state.db", Message: "--fix: " + fmt.Sprintf(format, args...)})
	}

	st, err := state.Load(workdir)
	if err != nil {
		refuse("the project could not be loaded, so nothing was changed: %v", err)
		return
	}
	// The stored WorkDir is where SaveDirect writes. A project copied or moved
	// from elsewhere still names its old directory there, and repairing it
	// would judge this project by another's artifacts and write the result
	// into the other one — the reason the hub's own recovery refuses too.
	if !sameDir(st.WorkDir, workdir) && !sameDir(st.WorkDir, state.ActiveDir(workdir)) {
		refuse("the project's state names %s as its directory, not %s, so nothing was changed", st.WorkDir, workdir)
		return
	}

	type reset struct {
		id     int
		title  string
		status string
	}
	var resets []reset
	if st.Plan != nil {
		for _, t := range st.Plan.Tasks {
			if t == nil || validTaskStatuses[string(t.Status)] {
				continue
			}
			resets = append(resets, reset{id: t.ID, title: t.Title, status: string(t.Status)})
			t.Status = pm.TaskPending
			t.StartedAt = nil
			pm.AddAnnotation(t, "cloop", fmt.Sprintf(
				"Reset to pending by `cloop config validate --fix`: its status %q is not one cloop knows.", resets[len(resets)-1].status))
		}
	}

	outcomes := taskrecover.Reconcile(workdir, st.Plan)

	claimed := st.Status
	stale := claimed == "running" || claimed == "evolving"
	if stale {
		st.SetPaused(pausereason.New(pausereason.CodeStale, staleRunDetail))
	}
	if len(resets) == 0 && len(outcomes) == 0 && !stale {
		return
	}

	// Again, immediately before writing: a run may have started since the
	// probe, and its first act would be to execute the tasks this is about to
	// rewrite. Dropping the repair costs nothing; the run recovers what it
	// finds before it schedules anything.
	if again := probeRun(workdir); again.Live {
		refuse("nothing was changed: a run of this project started while the repair was being prepared (%s)", again.Reason)
		return
	}
	if err := st.SaveDirect(); err != nil {
		refuse("saving the repaired plan failed, so nothing was changed: %v", err)
		return
	}

	for _, r := range resets {
		state.LogEvent(workdir, state.EventRow{
			Type:      state.EventTaskStatusChange,
			TaskID:    r.id,
			TaskTitle: r.title,
			Step:      state.NoStep,
			Message: fmt.Sprintf("Task #%d reset to pending by cloop config validate --fix: its status %q is not one cloop knows.",
				r.id, r.status),
		})
		rep.Fixed = append(rep.Fixed, fmt.Sprintf("reset task %d (%q) from invalid status %q to \"pending\"", r.id, r.title, r.status))
	}
	for _, oc := range outcomes {
		taskrecover.LogOutcome(workdir, oc)
		switch oc.Action {
		case taskrecover.ActionAdopted:
			rep.Fixed = append(rep.Fixed, fmt.Sprintf("recovered task %d (%q) as %s: the interrupted run had already reached that outcome",
				oc.TaskID, oc.Title, oc.Status))
		default:
			rep.Fixed = append(rep.Fixed, fmt.Sprintf("reset task %d (%q) to \"pending\": %s", oc.TaskID, oc.Title, oc.Reason))
		}
	}
	if stale {
		recovered := ""
		if n := len(outcomes); n > 0 {
			recovered = fmt.Sprintf(", and the %d task(s) it left in progress were recovered", n)
		}
		state.LogEvent(workdir, state.EventRow{
			Type: state.EventSessionFailed,
			Step: state.NoStep,
			Message: fmt.Sprintf("The run ended without recording an outcome. Its status was reset from %s to paused "+
				"by cloop config validate --fix so the project can be started again%s.", claimed, recovered),
		})
		rep.Fixed = append(rep.Fixed, fmt.Sprintf("set the project's status from %q to \"paused\": no run of it is live", claimed))
	}
}

// readStateForValidation reads every task's status and the project's run status
// through a read-only handle, so validating cannot change the database. A
// database without a plan_tasks table yields no tasks and no error.
func readStateForValidation(dbPath string) (tasks []taskRow, runStatus string, err error) {
	conn, err := statedb.OpenConn(dbPath, statedb.ReadOnly)
	if err != nil {
		return nil, "", err
	}
	defer conn.Close()

	rows, err := conn.Query(`SELECT id, title, status FROM plan_tasks ORDER BY id`)
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return nil, "", nil
		}
		return nil, "", fmt.Errorf("read plan_tasks: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var t taskRow
		if err := rows.Scan(&t.id, &t.title, &t.status); err != nil {
			return nil, "", fmt.Errorf("read plan_tasks: %w", err)
		}
		tasks = append(tasks, t)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("read plan_tasks: %w", err)
	}

	err = conn.QueryRow(`SELECT value FROM metadata WHERE key = 'status'`).Scan(&runStatus)
	if err != nil && !errors.Is(err, sql.ErrNoRows) && !strings.Contains(err.Error(), "no such table") {
		return nil, "", fmt.Errorf("read the run status: %w", err)
	}
	return tasks, runStatus, nil
}

func taskField(id int) string {
	return fmt.Sprintf("state.db:plan_tasks[%d].status", id)
}

// sameDir reports whether two paths denote the same directory, resolving
// symlinks where it can. An empty stored directory matches: Load fills it from
// the path it read, so there is nothing else it could mean.
func sameDir(a, b string) bool {
	if a == "" {
		return true
	}
	resolve := func(p string) string {
		abs, err := filepath.Abs(p)
		if err != nil {
			return p
		}
		if real, err := filepath.EvalSymlinks(abs); err == nil {
			return real
		}
		return abs
	}
	return resolve(a) == resolve(b)
}
