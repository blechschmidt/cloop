// Concrete collaborators for a real hub.
//
// These live here, rather than in cmd/ and pkg/ui separately, for the reason
// the package doc gives: two implementations of "which projects are theirs" or
// "which leases are theirs" would eventually disagree, and the disagreement
// would be invisible — one front end quietly severing less than the other.

package offboard

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// ---------------------------------------------------------------------------
// Projects
// ---------------------------------------------------------------------------

// RegistryProjects reports ownership from an already-loaded project list.
//
// It takes entries rather than calling multiui.Load itself because Load misses
// the hub's own WorkDir and anything passed via --projects; the dashboard
// assembles the full set separately, and an offboarding that swept only the
// registry file would under-report which projects need reassigning.
func RegistryProjects(entries []multiui.ProjectEntry) Projects {
	return registryProjects{entries: entries}
}

type registryProjects struct{ entries []multiui.ProjectEntry }

func (p registryProjects) Owned(ownerKeys []string) ([]ProjectRef, error) {
	if len(ownerKeys) == 0 {
		return nil, nil
	}
	want := make(map[string]struct{}, len(ownerKeys))
	for _, k := range ownerKeys {
		if k = strings.ToLower(strings.TrimSpace(k)); k != "" {
			want[k] = struct{}{}
		}
	}
	seen := map[string]struct{}{}
	var out []ProjectRef
	for _, e := range p.entries {
		owner := strings.ToLower(strings.TrimSpace(e.Owner))
		if owner == "" {
			// Unowned means shared with every authenticated user. It is not
			// this person's to hand over.
			continue
		}
		if _, ok := want[owner]; !ok {
			continue
		}
		if _, dup := seen[e.Path]; dup {
			continue
		}
		seen[e.Path] = struct{}{}
		out = append(out, ProjectRef{Name: e.Name, Path: e.Path, Owner: e.Owner})
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Tasks
// ---------------------------------------------------------------------------

// LocalTasks reads and aborts tasks through each project's own state database,
// which is where a project's plan lives — the hub's control plane does not hold
// other projects' tasks.
func LocalTasks() Tasks { return localTasks{} }

type localTasks struct{}

func (localTasks) Running(projectPath string) ([]TaskRef, error) {
	if strings.TrimSpace(projectPath) == "" {
		return nil, nil
	}
	// LoadLite skips the heavy history columns: this needs task id, title,
	// status and started_at, and a full load of a large plan is expensive
	// enough to matter when a dry run walks every project a person owns.
	st, err := state.LoadLite(projectPath)
	if err != nil {
		return nil, fmt.Errorf("load project state: %w", err)
	}
	if st == nil || st.Plan == nil {
		return nil, nil
	}
	var out []TaskRef
	for _, t := range st.Plan.Tasks {
		if t == nil || t.Status != pm.TaskInProgress {
			continue
		}
		out = append(out, TaskRef{
			ProjectPath: projectPath,
			ID:          t.ID,
			Title:       t.Title,
			Status:      string(t.Status),
			Attempt:     state.AttemptToken(t),
		})
	}
	return out, nil
}

// Stop files an abort request against the exact execution that was observed.
//
// The task is left as failed rather than skipped: "skipped" reads as a decision
// about the work, and this is not one — the work was interrupted because the
// person running it was offboarded mid-flight, and whoever inherits the project
// needs to see that it stopped short.
func (localTasks) Stop(t TaskRef, actor, reason string) error {
	if t.ProjectPath == "" || t.ID <= 0 {
		return nil
	}
	by := actor
	if by == "" {
		by = "offboard"
	}
	return state.RequestTaskKill(t.ProjectPath, t.ID, string(pm.TaskFailed), by, t.Attempt)
}
