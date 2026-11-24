package ui

import "github.com/blechschmidt/cloop/pkg/state"

// loadStateView reads workDir's project as the dashboard shows it: the hub's
// copy, with a seeded run in flight folded in exactly as /api/state and the
// state pushes fold it (overlaySeededRun). Every read-only view of a project's
// tasks reads it (Task 20518).
//
// A run on an executor that cannot read this filesystem works through its own
// copy of the project and brings its outcomes back when it ends. Until then the
// hub's copy holds the status each task had when the run was sent. The task
// list showed the run's own account, and a task's details did not: on
// sgx-rust-attestation, task #21 opened as "pending" with nothing recorded for
// the 38 minutes the device worked on it and after the list showed it done,
// and a task the run had created opened as "not found". The glasses' task
// screens, GET /api/tasks, the blocker heuristics, the Requirements tab and the
// charts read the same stale copy.
//
// What it returns is a view, never the record: a handler that changes the
// project loads it with state.Load and saves that, and the merge that writes a
// run's outcomes down happens once, when the run ends (collectRunResult).
// TestReadOnlyRoutesShowASeededRunsPlan keeps the GET routes on it; planView is
// the same view of the plan alone, for the Requirements tab.
func (s *Server) loadStateView(workDir string) (*state.ProjectState, error) {
	ps, err := state.Load(workDir)
	if err != nil {
		return nil, err
	}
	s.overlaySeededRun(workDir, ps)
	return ps, nil
}
