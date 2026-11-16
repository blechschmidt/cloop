package ui

// readonly.go: giving a run the other projects it may read (Task 20501).
//
// When the readers list of project B names project A, every run of A is given
// B's source tree read-only — and only then. The list is resolved once, at
// dispatch (resolveReadOnly), and what the run was given is recorded with it:
// in its knowledge session, which the run asks at every task boundary whether
// each project still lists it; in the project's event history; on the spec's
// labels; and on every task the run dispatches (the run's placement record,
// stamped onto each task.dispatch row).
//
// How the tree reaches the run is the executor's to say
// (Capabilities.ReadOnlyProjects), and applyReadOnly takes its word:
//
//   - a container on the hub's host binds B's directory read-only at
//     /readonly/<slug>, B's hidden entries covered;
//   - a workload forked on the hub's host reads B where it is, granted
//     read-only by the host sandbox's Landlock policy;
//   - a Kubernetes Pod or a remote device fetches a snapshot of B from the
//     hub with the run's own session, and the hub builds it only while B's
//     list names A (readonly_run_api.go).
//
// The run is told which projects, and where, in executor.EnvReadOnlyProjects.
// A project the executor cannot deliver, or a run the hub cannot tell when its
// access ends, is given nothing and the journal says why: a run is never told
// of a tree it does not have.

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/knowledgerun"
	"github.com/blechschmidt/cloop/pkg/projectreaders"
	"github.com/blechschmidt/cloop/pkg/state"
)

// LabelReadOnlyProjects marks a workload given other projects to read, for
// the dispatch record: their slugs, comma-separated.
const LabelReadOnlyProjects = "read_only_projects"

// readOnlyGrant is another project a run of the dispatched directory may
// read, as resolved at dispatch.
type readOnlyGrant struct {
	Slug    string `json:"slug"`
	Project string `json:"project"`
	Name    string `json:"name,omitempty"`
}

// resolveReadOnly is what a dispatch of argv in workDir is given to read: the
// registered projects whose readers lists name workDir, by path, each with a
// slug — and, in notes, why any of them is left out. Only a run of a project
// is given anything: a dashboard model call, a probe or a feature's run reads
// no other project (a feature is not on any list, as runMayRead says).
func resolveReadOnly(workDir string, argv []string) (grants []readOnlyGrant, notes []string) {
	if strings.TrimSpace(workDir) == "" || !isRunArgv(argv) || projectreaders.InsideControlDir(workDir) {
		return nil, nil
	}
	db, err := knowledgeRecordDB()
	if err != nil {
		return nil, []string{"The hub could not read the readers lists for this run, so it was given no other " +
			"project to read (" + oneLineText(err.Error()) + ")."}
	}
	paths := readableProjects(db, workDir)
	_ = db.Close()
	if len(paths) == 0 {
		return nil, nil
	}
	sort.Strings(paths)
	taken := map[string]bool{}
	for _, p := range paths {
		entry, ok := registeredProjectAt(p)
		if !ok {
			continue
		}
		if why := readOnlyRefusal(p); why != "" {
			notes = append(notes, fmt.Sprintf("%s is not given to it: %s.", p, why))
			continue
		}
		if len(grants) == executor.MaxReadOnlyProjects {
			notes = append(notes, fmt.Sprintf("%s is not given to it: a run is given at most %d other projects.",
				p, executor.MaxReadOnlyProjects))
			continue
		}
		grants = append(grants, readOnlyGrant{
			Slug: executor.ReadOnlySlug(entry.Name, p, taken), Project: projectreaders.NormalizePath(p),
			Name: strings.TrimSpace(entry.Name),
		})
	}
	return grants, notes
}

// readOnlyRefusal says why the project at path is never given to another
// project's run whatever its list says, or "".
func readOnlyRefusal(path string) string {
	if cp := controlPlaneDir(); cp != "" && samePath(path, cp) {
		return "it is the hub's own directory, whose .cloop holds the control plane"
	}
	if err := checkDispatchConfinement(path); err != nil {
		return "its directory breaks the hub's project confinement (" + oneLineText(err.Error()) + ")"
	}
	fi, err := os.Stat(path)
	if err != nil || !fi.IsDir() {
		return "it has no directory on this hub"
	}
	visible, _, err := executor.ReadOnlyEntries(path)
	if err != nil {
		return oneLineText(err.Error())
	}
	if len(visible) == 0 {
		return "it keeps no source on this hub — nothing but its control directory, as a project whose tree " +
			"lives on its executor does"
	}
	return ""
}

// applyReadOnly gives the run grants in the one way ex can deliver them, with
// session, the run's knowledge session, to ask about them at each task
// boundary and to fetch snapshots with. It returns
// spec unchanged — and says why in the journal — when ex can deliver none, or
// there is no session.
func applyReadOnly(spec executor.Spec, ex executor.Executor, workDir string, grants []readOnlyGrant,
	notes []string, session *runKnowledge) executor.Spec {
	base := ""
	if session != nil {
		base = session.base
	}
	if ex == nil || len(grants) == 0 {
		journalReadOnly(workDir, nil, notes, "")
		return spec
	}
	delivery := ex.Capabilities().ReadOnlyProjects
	switch {
	case session == nil || strings.TrimSpace(base) == "":
		journalReadOnly(workDir, nil, notes, fmt.Sprintf("Its readers lists name %d project(s) this run may read, but "+
			"it was given none: the hub could not give the run a session to ask, at each task boundary, whether "+
			"they still list it — set ui.external_url to an address the run reaches the hub at.", len(grants)))
		return spec
	}
	projects := make([]executor.ReadOnlyProject, 0, len(grants))
	for _, g := range grants {
		p := executor.ReadOnlyProject{Slug: g.Slug, Project: g.Project, Name: g.Name}
		switch delivery {
		case executor.ReadOnlyBind, executor.ReadOnlyInPlace:
			p.Source = g.Project
		case executor.ReadOnlySnapshot:
			p.Snapshot = &executor.ReadOnlySnapshotRef{
				URL:      strings.TrimRight(base, "/") + knowledgerun.PathReadOnlySnapshot,
				TokenEnv: knowledgerun.EnvReadersToken,
			}
		}
		projects = append(projects, p)
	}
	manifest := executor.ReadOnlyManifest(projects, func(p executor.ReadOnlyProject) string {
		if delivery == executor.ReadOnlyInPlace {
			return p.Source
		}
		return p.Target()
	})
	env := spec.Env
	if env == nil && !executor.IsolatesFromHost(ex) {
		// nil inherits the hub's environment on the host driver; a list
		// holding only this would strip PATH and HOME from the harness.
		env = os.Environ()
	}
	spec.Env = executor.WithReadOnlyManifest(env, manifest)
	spec.ReadOnly = projects
	labels := make(map[string]string, len(spec.Labels)+1)
	for k, v := range spec.Labels {
		labels[k] = v
	}
	slugs := make([]string, 0, len(projects))
	for _, p := range projects {
		slugs = append(slugs, p.Slug)
	}
	labels[LabelReadOnlyProjects] = strings.Join(slugs, ",")
	spec.Labels = labels
	journalReadOnly(workDir, manifest, notes, readOnlyHow(delivery, ex))
	return spec
}

// deliverableReadOnly keeps of grants what ex can deliver to the run spec
// describes, and says in notes why it leaves any out: an executor that
// delivers none, a run with no network to ask the hub with at its task
// boundaries, a container's mount flag that cannot carry a path or a hidden
// entry's name holding a colon or a comma, and the host sandbox's policy,
// which holds at most executor.MaxReadOnlyEntriesTotal entries. Run before the
// session is minted, so that the session records exactly what the run is
// given.
func deliverableReadOnly(grants []readOnlyGrant, spec executor.Spec, ex executor.Executor,
	notes []string) ([]readOnlyGrant, []string) {
	if ex == nil || len(grants) == 0 {
		return nil, notes
	}
	delivery := ex.Capabilities().ReadOnlyProjects
	switch {
	case delivery == executor.ReadOnlyNone:
		return nil, append(notes, fmt.Sprintf("Its readers lists name %d project(s) this run may read, but executor "+
			"%s cannot give a run another project's tree, so it was given none.", len(grants), ex.ID()))
	case spec.DisableNetwork || spec.EgressScope.RemovesNetwork() ||
		(spec.EgressRules != nil && !spec.EgressRules.HasDestination()):
		return nil, append(notes, fmt.Sprintf("Its readers lists name %d project(s) this run may read, but it was "+
			"given none: it has no network to ask the hub with, at each task boundary, whether they still list it.",
			len(grants)))
	}
	kept := make([]readOnlyGrant, 0, len(grants))
	entries := 0
	for _, g := range grants {
		switch delivery {
		case executor.ReadOnlyBind:
			if err := executor.ReadOnlyBindable(g.Project); err != nil {
				notes = append(notes, fmt.Sprintf("%s is not given to it: %s.", g.Project, oneLineText(err.Error())))
				continue
			}
		case executor.ReadOnlyInPlace:
			visible, _, err := executor.ReadOnlyEntries(g.Project)
			if err != nil || entries+len(visible) > executor.MaxReadOnlyEntriesTotal {
				notes = append(notes, fmt.Sprintf("%s is not given to it: the projects a run reads in place may have "+
					"at most %d top-level entries between them.", g.Project, executor.MaxReadOnlyEntriesTotal))
				continue
			}
			entries += len(visible)
		}
		kept = append(kept, g)
	}
	return kept, notes
}

// readOnlyHow says, for the journal, how ex delivers the projects.
func readOnlyHow(delivery executor.ReadOnlyDelivery, ex executor.Executor) string {
	switch delivery {
	case executor.ReadOnlyBind:
		return "Each is bound read-only into the run's sandbox, its .cloop, .git and credential files covered."
	case executor.ReadOnlyInPlace:
		return "Each is read where it is on this hub; the host sandbox grants it read-only, its .cloop, .git and " +
			"credential files left out."
	case executor.ReadOnlySnapshot:
		return fmt.Sprintf("Executor %s fetches a snapshot of each from the hub and places it where the run cannot "+
			"write it.", ex.ID())
	}
	return ""
}

// readOnlyUnenforced is the journal's warning for a run that runs outside the
// host sandbox as a process on the hub's host, or on a device's: it reaches
// every file its user can, the projects it was given to read included, so
// "read-only" is not a boundary there.
func readOnlyUnenforced(spec executor.Spec, ex executor.Executor, workDir string) {
	if len(spec.ReadOnly) == 0 || ex == nil {
		return
	}
	where := ""
	switch {
	case ex.Capabilities().ReadOnlyProjects == executor.ReadOnlyInPlace && spec.HostSandbox == nil:
		where = "is not in the host sandbox (executors.host_sandbox), so it can write to the projects it was " +
			"given to read as to every file the hub's user can"
	case !spec.ConfineToProject && deviceRunsHostProcesses(ex):
		where = "runs as a process on device " + ex.ID() + "'s host outside the host sandbox — the project is " +
			"opted out, or the device cannot sandbox — so it can write to its snapshots of the projects it was " +
			"given to read"
	default:
		return
	}
	state.LogEvent(workDir, state.EventRow{Type: state.EventKnowledge, Step: state.NoStep, Message: "This run " +
		where + ": read-only is not enforced for it. Run it in the host sandbox, or in a container, to make it so."})
}

// deviceRunsHostProcesses reports whether ex is a device that runs its
// payloads on its own host rather than in containers.
func deviceRunsHostProcesses(ex executor.Executor) bool {
	r, ok := ex.(*remote.Executor)
	return ok && r.RunsHostProcesses()
}

// journalReadOnly writes what the run was given to read, and what it was not
// and why, to the project's event history.
func journalReadOnly(workDir string, given []executor.ReadOnlyManifestEntry, notes []string, how string) {
	if strings.TrimSpace(workDir) == "" || (len(given) == 0 && len(notes) == 0 && how == "") {
		return
	}
	var b strings.Builder
	if len(given) > 0 {
		fmt.Fprintf(&b, "This run may read %d other project(s), read-only, because their readers lists name this "+
			"project: ", len(given))
		for i, g := range given {
			if i > 0 {
				b.WriteString("; ")
			}
			fmt.Fprintf(&b, "%s at %s", g.Project, g.Path)
		}
		b.WriteString(". ")
	}
	if how != "" {
		b.WriteString(how + " ")
	}
	for _, n := range notes {
		b.WriteString(n + " ")
	}
	state.LogEvent(workDir, state.EventRow{Type: state.EventKnowledge, Step: state.NoStep,
		Message: strings.TrimSpace(b.String())})
}

// readOnlyProjectsOf lists the projects a spec gives its run, for the run's
// placement record.
func readOnlyProjectsOf(spec executor.Spec) []string {
	if len(spec.ReadOnly) == 0 {
		return nil
	}
	out := make([]string, 0, len(spec.ReadOnly))
	for _, p := range spec.ReadOnly {
		out = append(out, p.Project)
	}
	return out
}

// oneLineText keeps text on one line.
func oneLineText(s string) string { return strings.Join(strings.Fields(s), " ") }
