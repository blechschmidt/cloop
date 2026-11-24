package ui

// readonly_resume.go: restarting at once a run paused for a reason that lifts
// the moment it is recorded.
//
// A run given other projects to read stops at a task boundary when one of them
// no longer lists its project, paused readers_changed with a ResumesAt of the
// moment it stopped, so that its next task starts in a run given only what the
// lists name now (Task 20501). A run on an executor that works from a copy of
// the plan comes back paused work_added when tasks were added or reset on the
// hub while it was out, so that a run of the plan as it stands now carries on
// with them (Task 20516). The auto-resume sweep would restart either within
// its interval; this restarts it as soon as the member following the run has
// settled it.

import (
	"context"
)

// resumeNowBacklog bounds the restarts waiting for watchResumeAtOnce; past it
// they are left to the sweep.
const resumeNowBacklog = 64

// watchResumeAtOnce restarts, one at a time, the runs runEnded hands it, until
// ctx ends.
func (s *Server) watchResumeAtOnce(ctx context.Context) {
	defer recoverGoroutine("watchResumeAtOnce")
	s.resumeNowMu.Lock()
	if s.resumeNow == nil {
		s.resumeNow = make(chan string, resumeNowBacklog)
	}
	ch := s.resumeNow
	s.resumeNowMu.Unlock()
	for {
		select {
		case <-ctx.Done():
			return
		case workDir := <-ch:
			// As the sweep would: a pause that changed to a usage cap since
			// the run ended waits for the operator's setting.
			s.maybeAutoResumeFor(workDir, s.autoResumeEnabled())
		}
	}
}
