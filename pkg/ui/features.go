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

// featureExecutorError refuses to run a feature on an executor that cannot
// carry one.
//
// A feature is a *linked* git worktree: its .git is a one-line file pointing at
// the parent repository's .git/worktrees/<slug>, by absolute path, so the
// worktree itself can only be used on the hub. On an executor that isolates
// from the hub a feature therefore runs as a standalone checkout of its branch,
// shipped from the hub, with its work returned as a bundle (Task 20367; see
// features_isolated.go) — and an executor that cannot receive the branch, take
// the feature's state, or return either cannot run one. Refusing names which,
// instead of starting a harness on a tree that is not the feature's.
type featureExecutorError struct {
	FeaturePath  string
	ExecutorID   string
	ExecutorKind string
	// Missing lists what the executor cannot do.
	Missing string
}

func (e *featureExecutorError) Error() string {
	return fmt.Sprintf("feature %s cannot run on executor %s (%s): a feature runs on an isolating executor as "+
		"a standalone checkout of its branch shipped from the hub, and this executor cannot %s",
		filepath.Base(e.FeaturePath), e.ExecutorID, e.ExecutorKind, e.Missing)
}

// Remediation says what to do about it.
func (e *featureExecutorError) Remediation() string {
	return "Bind the project to a container executor or a remote agent of protocol v16 or later " +
		"(upgrade an older agent with `cloop executor agent install --upgrade`); a Kubernetes executor " +
		"has no channel from the hub into a Pod to carry the branch through."
}

// errFeatureExecutor lets callers test for the refusal without the type.
var errFeatureExecutor = errors.New("feature executor unsupported")

func (e *featureExecutorError) Is(target error) bool { return target == errFeatureExecutor }

// checkFeatureExecutor refuses dispatching a feature's workload to ex when ex
// isolates from the host and cannot carry a feature there. Non-feature paths,
// and executors that share the hub's filesystem, always pass.
func checkFeatureExecutor(workDir string, ex executor.Executor) error {
	if !featureRunsIsolated(workDir, ex) {
		return nil
	}
	if gap := featureCapabilityGap(ex); gap != "" {
		return &featureExecutorError{FeaturePath: workDir, ExecutorID: ex.ID(), ExecutorKind: string(ex.Kind()), Missing: gap}
	}
	return nil
}
