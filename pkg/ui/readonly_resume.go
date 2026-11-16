package ui

// readonly_resume.go: restarting at once a run a readers change paused (Task
// 20501).
//
// A run given other projects to read stops at a task boundary when one of them
// no longer lists its project, paused readers_changed with a ResumesAt of the
// moment it stopped, so that its next task starts in a run given only what the
// lists name now. The auto-resume sweep would restart it within its interval;
// this restarts it as soon as the member following the run has settled it.

import (
	"context"
)

// readersResumeBacklog bounds the restarts waiting for watchReadersResume;
// past it they are left to the sweep.
const readersResumeBacklog = 64

// watchReadersResume restarts, one at a time, the runs runEnded hands it,
// until ctx ends.
func (s *Server) watchReadersResume(ctx context.Context) {
	defer recoverGoroutine("watchReadersResume")
	s.readersResumeMu.Lock()
	if s.readersResume == nil {
		s.readersResume = make(chan string, readersResumeBacklog)
	}
	ch := s.readersResume
	s.readersResumeMu.Unlock()
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
