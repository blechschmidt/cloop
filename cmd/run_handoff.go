package cmd

// run_handoff.go: the start of an image that took a run over from another
// (Task 20389).
//
// A run that adopts a newer build at a task boundary execs the new binary with
// its own argv and environment plus CLOOP_RUN_HANDOFF. To the kernel nothing
// started — same pid, same parent, same stdout — and the new image must behave
// the same way: continue the run, not begin one. So it reads the handoff, and
// it keeps the command line from doing again what it did when the run first
// started: --replan would discard the plan the run has been working through,
// --auto-evolve or --innovate would undo a toggle flipped on the dashboard
// since, --add-steps would add the steps twice.

import (
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/outlive"
	"github.com/blechschmidt/cloop/pkg/runbuild"
)

// earlyStop holds a stop that arrived between the exec and the run's own
// signal handling, which would otherwise have killed the run outright.
var earlyStop = make(chan os.Signal, 1)

func init() {
	if _, ok := os.LookupEnv(runbuild.EnvHandoff); !ok {
		return
	}
	// Before anything can print: the hub may have restarted since this run
	// began, leaving stdout a broken pipe that a single warning line would
	// otherwise turn into a fatal SIGPIPE (see pkg/outlive).
	outlive.ControlPlane()
	signal.Notify(earlyStop, syscall.SIGINT, syscall.SIGTERM)
	// The exec went through /proc/self/fd/<n>, which named the process "<n>".
	runbuild.RestoreComm(filepath.Base(os.Args[0]))
}

// runResume is what this process knows about the run it continues.
type runResume struct {
	// active is set when CLOOP_RUN_HANDOFF was present at all.
	active  bool
	handoff *runbuild.Handoff
	// err says why a handoff that was announced could not be used.
	err string
}

// takeRunHandoff reads and removes the handoff, and takes the variable out of
// the environment so nothing this run starts inherits it.
func takeRunHandoff() runResume {
	path, ok := os.LookupEnv(runbuild.EnvHandoff)
	if !ok {
		return runResume{}
	}
	_ = os.Unsetenv(runbuild.EnvHandoff)
	r := runResume{active: true}
	self, err := runbuild.SelfIdent()
	if err != nil {
		r.err = "this process could not be identified: " + err.Error()
		_ = os.Remove(path)
		return r
	}
	h, err := runbuild.TakeHandoff(path, self, time.Now())
	if err != nil {
		r.err = err.Error()
		return r
	}
	r.handoff = h
	return r
}

// stopArrivedEarly reports whether a stop was delivered before the run's own
// handler was in place, and stops buffering them.
func stopArrivedEarly() bool {
	defer signal.Stop(earlyStop)
	select {
	case <-earlyStop:
		return true
	default:
		return false
	}
}
