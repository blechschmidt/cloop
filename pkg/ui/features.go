package ui

// features.go is how the hub sees features (Task 20341): git worktrees of a
// project, each with its own task list and run settings, living at
// <project>/.cloop/features/<slug>.
//
// # A feature is a project
//
// Everything the dashboard does to a project — show its tasks, start and stop
// its run, toggle auto-evolve and innovate mode — it can do to a feature without
// knowing the difference, because a feature has its own .cloop/ directory and
// the orchestrator runs in it like anywhere else. So the hub lists each feature
// as one more entry in the project list (appendFeatureEntries), and every
// index-addressed route works on it unchanged. The entry carries its parent's
// path so the dashboard can nest it under the project it belongs to.
//
// Features are discovered, never registered: the list is read from each
// project's .cloop/features on every refresh. A feature created from a terminal
// with `cloop feature new` therefore shows up in the dashboard too, and a
// feature cannot outlive its project in the registry.
//
// # A feature is not a tenant
//
// For every decision about what a project may do rather than what it is
// working on, a feature is its parent: the executor it runs on, the resource
// ceiling it gets, the credentials it may lease, and who may see and operate
// it. That is enforced by mapping the feature's path to its parent's
// (policyProjectPath) wherever such a decision is keyed by path. The mapping is
// lexical, so it fails closed: a feature whose record is damaged still runs
// in its parent's sandbox with its parent's grants, never on the hub's default
// executor with none.

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/feature"
	"github.com/blechschmidt/cloop/pkg/multiui"
)

// policyProjectPath returns the project whose policy governs path: the parent
// project for a feature worktree, path itself otherwise.
func policyProjectPath(path string) string {
	if parent, _, ok := feature.ParentOf(path); ok {
		return parent
	}
	return path
}

// installFeaturePolicy makes pkg/executor resolve a feature's executor binding
// and resource ceiling through its parent. Idempotent.
func installFeaturePolicy() {
	executor.SetPolicyProjectMapper(policyProjectPath)
}

// appendFeatureEntries appends every feature of the listed projects to
// entries, after all of them.
//
// After, not interleaved: the dashboard addresses projects by index, and a
// feature created in the first project must not renumber every project after
// it. Features come and go far more often than projects do.
//
// A feature inherits its parent's owner, so it is visible to exactly the
// people who can see the project, and its parent's hidden-by set, so hiding a
// project hides its features with it.
func appendFeatureEntries(entries []multiui.ProjectEntry, seen map[string]bool) []multiui.ProjectEntry {
	n := len(entries)
	for i := 0; i < n; i++ {
		parent := entries[i]
		if parent.IsFeature() {
			continue
		}
		if _, _, nested := feature.ParentOf(parent.Path); nested {
			continue
		}
		infos, err := feature.List(parent.Path)
		if err != nil {
			continue
		}
		for _, in := range infos {
			if seen[in.Path] {
				continue
			}
			seen[in.Path] = true
			entries = append(entries, multiui.ProjectEntry{
				Name:      parent.Name + "/" + in.Meta.Slug,
				Path:      in.Path,
				Owner:     parent.Owner,
				HiddenFor: parent.HiddenFor,
				Parent:    parent.Path,
				Feature:   in.Meta.Slug,
			})
		}
	}
	return entries
}

// featureExecutorError refuses to run a feature on an executor that isolates
// from the hub's filesystem.
//
// A feature is a *linked* git worktree: its .git is a one-line file pointing at
// the parent repository's .git/worktrees/<slug>, by absolute path. A container
// mounts only the feature directory, at a different path; a remote device or a
// Pod gets a fresh clone. In none of them does that pointer resolve, so the
// harness would start in a directory git does not recognise, edit files it can
// never commit, and report success. Refusing names the constraint instead.
type featureExecutorError struct {
	FeaturePath  string
	ExecutorID   string
	ExecutorKind string
}

func (e *featureExecutorError) Error() string {
	return fmt.Sprintf("feature %s cannot run on executor %s (%s): a feature is a git worktree of its project's "+
		"repository on this hub, and that executor does not share the hub's filesystem, so git would not work inside it",
		filepath.Base(e.FeaturePath), e.ExecutorID, e.ExecutorKind)
}

// Remediation says what to do about it.
func (e *featureExecutorError) Remediation() string {
	return "Run the project on an executor that shares this hub's filesystem (the local executor), " +
		"or develop in the project itself rather than in a feature."
}

// errFeatureExecutor lets callers test for the refusal without the type.
var errFeatureExecutor = errors.New("feature executor unsupported")

func (e *featureExecutorError) Is(target error) bool { return target == errFeatureExecutor }

// checkFeatureExecutor refuses dispatching a feature's workload to ex when ex
// isolates from the host. Non-feature paths always pass.
func checkFeatureExecutor(workDir string, ex executor.Executor) error {
	if ex == nil {
		return nil
	}
	if _, _, ok := feature.ParentOf(workDir); !ok {
		return nil
	}
	if !executor.IsolatesFromHost(ex) {
		return nil
	}
	return &featureExecutorError{FeaturePath: workDir, ExecutorID: ex.ID(), ExecutorKind: string(ex.Kind())}
}
