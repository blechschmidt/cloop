package multiui

import (
	"path/filepath"
)

// RunningDirs is a snapshot of where every "cloop run" process on this host is
// executing, prepared for repeated containment queries.
//
// It exists because the hub's project sweep asked "is a run executing in this
// project?" once per registered project, and every one of those questions
// walked the whole of /proc. That made the sweep cost (projects × processes) on
// a timer that fires every two seconds, so a hub paid for tenants that were
// doing nothing at all — see BenchmarkWatchProjectsTick in pkg/ui. One walk per
// tick answers the same question for every project.
//
// The zero value is usable and reports every project as not running, which is
// the same answer IsCloopRunningInDir gives on a host without a readable /proc.
type RunningDirs struct {
	// dirs holds each run's working directory and every ancestor of it, so a
	// query is one map lookup rather than a scan over the runs. Ancestors are
	// what make the lookup equivalent to the prefix test in dirScopeMatch: a
	// run counts for a project when it executes in the project directory or
	// anywhere below it, because a parallel task running in
	// .cloop/worktrees/task-42 still belongs to that project.
	dirs map[string]struct{}
}

// ScanRunningDirs walks /proc once and records where every cloop run process is
// executing. It returns an empty snapshot when /proc cannot be read (non-Linux
// hosts, restricted containers), matching cloopRunPIDs.
func ScanRunningDirs() RunningDirs {
	var ix RunningDirs
	forEachCloopRun(func(_ int, cwd string) {
		if ix.dirs == nil {
			ix.dirs = make(map[string]struct{}, 16)
		}
		for d := filepath.Clean(cwd); ; {
			if _, seen := ix.dirs[d]; seen {
				// Another run already contributed this directory, so every
				// remaining ancestor is recorded too.
				break
			}
			ix.dirs[d] = struct{}{}
			parent := filepath.Dir(d)
			if parent == d {
				break // reached the root
			}
			d = parent
		}
	})
	return ix
}

// Any reports whether any cloop run process was found at all. A hub whose
// tenants are all idle gets a false here and can skip per-project work.
func (r RunningDirs) Any() bool { return len(r.dirs) > 0 }

// Contains reports whether a cloop run is executing in dir or anywhere below
// it. It is the batched equivalent of IsCloopRunningInDir(dir).
func (r RunningDirs) Contains(dir string) bool {
	if len(r.dirs) == 0 {
		return false
	}
	cleaned := filepath.Clean(dir)
	if _, ok := r.dirs[cleaned]; ok {
		return true
	}
	// /proc always reports kernel-canonical paths, so a project registered
	// through a symlink only compares equal once resolved (Task 20153). Tried
	// second because resolving costs a syscall per path component, and the
	// cleaned form already matches for every project not reached through a
	// link — which is nearly all of them.
	if resolved := canonicalDir(dir); resolved != cleaned {
		_, ok := r.dirs[resolved]
		return ok
	}
	return false
}
