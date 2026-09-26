package ui

// run_result.go brings a run on an isolating executor home (Task 20339).
//
// A project bound to an executor that cannot read this hub's filesystem is
// carried out as a seed (workspace.go), and the run on the far side records its
// outcomes in its own copy. The dashboard renders *this* hub's copy. Until this
// file nothing connected the two, and the operator saw exactly what the task
// that motivated it reported: start the run, watch a transcript end with "All
// tasks complete", and find the task still pending — the run "completed
// immediately although there is one remaining task". Starting it again ran the
// task again.
//
// Now the executor reads back what the run changed and sends it before the
// run's final status (see pkg/executor/agent/projectresult.go), and runEnded —
// the one place every dispatch path settles a finished run — merges it into the
// hub's copy before anything else looks at the plan. Dead-run recovery runs
// after the merge, so a task the run left in progress is recovered from the
// run's own account of it rather than from a plan that never heard it started.
//
// Every outcome is written to the project's journal, including the ones where
// nothing could be merged: "this executor is too old to report back" and "the
// run ended without reporting" are the two cases in which the dashboard is
// stale, and a journal row naming why is the difference between an explained
// stale task and the bug this file fixes.

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/state"
)

// seededDispatch is what the hub knew about a dispatch that carried its project
// out: the provenance a merge stamps, which the device does not get a say in.
type seededDispatch struct {
	prov projectseed.Provenance
}

// maxSeededDispatches bounds the registry. An entry lives from dispatch to
// runEnded; the few paths that start a run and then lose sight of it (a stream
// that cannot be opened) would otherwise leak one entry each for the life of
// the process. Far above any real number of concurrent runs.
const maxSeededDispatches = 1024

var (
	seededMu    sync.Mutex
	seeded      = map[string]seededDispatch{}
	seededOrder []string
)

func seededKey(executorID, handleID string) string { return executorID + "\x00" + handleID }

// rememberSeededDispatch records that handleID on ex was sent the project.
func rememberSeededDispatch(ex executor.Executor, handleID string, prov projectseed.Provenance) {
	key := seededKey(ex.ID(), handleID)
	seededMu.Lock()
	defer seededMu.Unlock()
	if _, ok := seeded[key]; !ok {
		seededOrder = append(seededOrder, key)
	}
	seeded[key] = seededDispatch{prov: prov}
	for len(seededOrder) > maxSeededDispatches {
		delete(seeded, seededOrder[0])
		seededOrder = seededOrder[1:]
	}
}

// takeSeededDispatch returns and forgets the record for handleID on ex.
func takeSeededDispatch(ex executor.Executor, handleID string) (seededDispatch, bool) {
	key := seededKey(ex.ID(), handleID)
	seededMu.Lock()
	defer seededMu.Unlock()
	d, ok := seeded[key]
	if !ok {
		return seededDispatch{}, false
	}
	delete(seeded, key)
	for i, k := range seededOrder {
		if k == key {
			seededOrder = append(seededOrder[:i], seededOrder[i+1:]...)
			break
		}
	}
	return d, true
}

// collectRunResult merges what ex brought back of the run behind handleID into
// the hub's copy of workDir, and journals what happened. A run that was not
// sent the project — every run on an executor that shares this filesystem —
// has nothing to bring back and returns at once.
func (s *Server) collectRunResult(workDir string, ex executor.Executor, handleID string) {
	defer recoverGoroutine("collect run result: " + workDir)
	if workDir == "" || ex == nil || handleID == "" {
		return
	}
	d, ok := takeSeededDispatch(ex, handleID)
	if !ok {
		return
	}

	journal := func(msg string, details map[string]any) {
		if details == nil {
			details = map[string]any{}
		}
		details["executor_id"] = ex.ID()
		if d.prov.RunID != "" {
			details["run_id"] = d.prov.RunID
		}
		state.LogEventDetails(workDir, state.EventRow{
			Type:    state.EventProjectResult,
			Step:    state.NoStep,
			Message: msg,
		}, details)
	}

	fetcher, canFetch := ex.(executor.ProjectResultFetcher)
	if !canFetch || !ex.Capabilities().ReturnsProjectState {
		journal(fmt.Sprintf("Executor %q ran this project from a copy of its plan and cannot send the "+
			"outcome back, so tasks it ran still show their earlier status here — and will run again "+
			"if the project is started again. Upgrade its agent to protocol v%d or later — Upgrade on "+
			"its card in the Executors tab, or `cloop executor agent install --upgrade` on the device.",
			ex.ID(), remote.MinProjectResultVersion), nil)
		return
	}

	res, err := fetcher.ProjectResult(handleID)
	if err != nil {
		if errors.Is(err, executor.ErrProjectResultUnavailable) {
			journal(fmt.Sprintf("The run on executor %q ended without sending its results back — "+
				"typically because the connection dropped before it finished — so tasks it ran still "+
				"show their earlier status here. Check the run's log for how far it got.", ex.ID()), nil)
		} else {
			journal(fmt.Sprintf("The run's results could not be collected from executor %q: %v", ex.ID(), err), nil)
		}
		return
	}
	if res.Err != "" {
		journal(fmt.Sprintf("Executor %q could not read the run's results back: %s. Tasks it ran still "+
			"show their earlier status here.", ex.ID(), res.Redact(res.Err)), nil)
		return
	}

	result, err := projectseed.DecodeResult(res.Data)
	if err != nil {
		journal(fmt.Sprintf("Executor %q sent back a report of the run that could not be read (%v); "+
			"nothing from it was merged.", ex.ID(), err), nil)
		return
	}

	rep, err := projectseed.Apply(workDir, result, d.prov, res.Redact)
	details := map[string]any{
		"updated": rep.Updated, "added": rep.Added, "kept": len(rep.Kept),
		"steps": rep.Steps, "events": rep.Events, "costs": rep.Costs,
	}
	if len(rep.Renumbered) > 0 {
		details["renumbered"] = rep.Renumbered
	}
	msg := rep.Summary()
	switch {
	case err != nil && !rep.Changed():
		msg = fmt.Sprintf("The run's results came back from executor %q but could not be merged: %v. "+
			"Tasks it ran still show their earlier status here.", ex.ID(), err)
	case err != nil:
		msg += fmt.Sprintf(" Recording it failed part-way: %v", err)
	}
	if err != nil {
		details["error"] = err.Error()
		s.log().Warn(logger.EventCheckpoint, 0, "remote run result: merge failed",
			map[string]interface{}{"project": workDir, "executor": ex.ID(), "error": err.Error()})
	}
	journal(msg, details)

	if rep.Changed() {
		if st, loadErr := state.LoadLite(workDir); loadErr == nil {
			s.broadcastStateDiff(workDir, st)
		} else {
			fmt.Fprintf(os.Stderr, "ui: reload %s after merging a run: %v\n", workDir, loadErr)
		}
		s.refreshProjectStatuses()
		s.broadcastProjectsUpdate()
	}
}
