package cmd

import (
	"testing"

	"github.com/blechschmidt/cloop/pkg/blocker"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/state"
)

// TestBlockerRunNeverReportsGoneForARunItCannotSee: the blocker calls a task
// in progress stalled only when it is told nothing is executing the project
// (Task 20479). From a terminal, a status that claims a run may still be right
// with no local process — the run can be in a container or on an edge device —
// so that is "unknown", never "gone". Only a status that claims no run, with no
// local process either, is "gone". (The directory here has no `cloop run` in
// it, so the local-process branch never answers.)
func TestBlockerRunNeverReportsGoneForARunItCannotSee(t *testing.T) {
	dir := tempCmdDir(t)
	diskLow := pausereason.New(pausereason.CodeDiskLow, "waiting for disk space")
	stopped := pausereason.New(pausereason.CodeOperator, "run stopped")
	cases := []struct {
		status string
		reason *pausereason.Reason
		want   blocker.Run
	}{
		{"running", nil, blocker.RunUnknown},
		{"evolving", nil, blocker.RunUnknown},
		// A run waiting out a full disk holds its pause in a live process.
		{"paused", &diskLow, blocker.RunUnknown},
		{"paused", &stopped, blocker.RunGone},
		{"complete", nil, blocker.RunGone},
		{"initialized", nil, blocker.RunGone},
	}
	for _, tc := range cases {
		s := &state.ProjectState{Status: tc.status, PauseReason: tc.reason}
		if got := blockerRun(dir, s); got != tc.want {
			t.Errorf("status %q (reason %v): blockerRun = %q, want %q", tc.status, tc.reason, got, tc.want)
		}
	}
}
