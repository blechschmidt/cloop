package executor

import "sync/atomic"

// policyProjectMapper maps a project path onto the project whose policy
// governs it — for a feature worktree (Task 20341), its parent project.
//
// A feature is a git worktree nested in its parent's directory with its own
// task list, and for everything that decides *where* and *with what* it runs —
// the executor it is pinned to, the resource ceiling it gets — it must be the
// parent. Otherwise creating a feature would be a way to run a sandboxed
// project's code on the host: the feature's path has no binding of its own, so
// Resolve would fall through to the registry default.
//
// A hook rather than a rule written here because the layout that makes a path
// a feature belongs to cloop's control plane, and this package is also the
// edge agent's, which has no business knowing it. The control plane installs
// it; a process that never does maps every path to itself.
var policyProjectMapper atomic.Pointer[func(string) string]

// SetPolicyProjectMapper installs the mapper. Pass nil to remove it.
func SetPolicyProjectMapper(fn func(projectPath string) string) {
	if fn == nil {
		policyProjectMapper.Store(nil)
		return
	}
	policyProjectMapper.Store(&fn)
}

// PolicyProjectPath returns the project whose policy governs projectPath:
// projectPath itself unless the installed mapper says otherwise.
func PolicyProjectPath(projectPath string) string {
	p := policyProjectMapper.Load()
	if p == nil || projectPath == "" {
		return projectPath
	}
	if mapped := (*p)(projectPath); mapped != "" {
		return mapped
	}
	return projectPath
}
