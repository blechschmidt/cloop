package ui

// run_reads.go: the one way a run's credentials reach past its own project
// (Task 20499).
//
// Every credential the hub mints for a run names the run's project when it is
// minted, and the server reads that project off the credential — never off
// anything the request says (docs/security/model.md, "What a run's credentials
// reach"). The single exception is a read: a run may search another project's
// knowledge, and fetch another project's repository through the git proxy,
// when that project's readers list (pkg/projectreaders) names the run's
// project. Nothing else crosses: a write, a task, an attachment, a citation or
// a session of another project is refused whatever the list says.
//
// runMayRead is the question both of those reads ask, at every request, so a
// project taken off a list stops being read at the next request rather than at
// the end of the run: the knowledge routes ask it for a search or a lookup that
// names another project, and the git proxy asks it before serving a foreign
// read (gitproxy.Options.Readers). The list is read from the control plane each
// time; it is small, and a cache would be one more thing a removal had to wait
// for.

import (
	"errors"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/projectreaders"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// errRunRead refuses a run's read of another project. Its message is the
// refusal the audit trail records; what the run is told is runReadNotFound,
// which says the same whether the path names no project or one the run may
// not read, so a run cannot map the hub's projects by asking.
var errRunRead = errors.New("refused")

// runReadNotFound is what a run is told when a read of another project is
// refused.
const runReadNotFound = "no project this run may read is at that path: another project is read only when its " +
	"readers list names this run's project"

// runMayRead reports whether a run working in reader — the directory it was
// dispatched to, a feature's own path for a feature's run — may read project,
// another project on this hub: nil when project's readers list names reader,
// else an error wrapping errRunRead that says why not.
//
// It never answers yes for anything but a listed pair: a project that is not
// registered on this hub is refused even if a stale row names it, a feature's
// run is refused because the list names projects and never their features
// (pkg/projectreaders), and a list that cannot be read refuses every read.
func runMayRead(db *statedb.DB, reader, project string) error {
	reader, project = projectreaders.NormalizePath(reader), projectreaders.NormalizePath(project)
	switch {
	case reader == "" || project == "":
		return fmt.Errorf("%w: a read names no reader or no project", errRunRead)
	case reader == project:
		// Not a read of another project at all: the caller asked the wrong
		// question, and the answer must not be a grant.
		return fmt.Errorf("%w: %s is the run's own project, which it reads with no list", errRunRead, project)
	case db == nil:
		return fmt.Errorf("%w: the hub's database is not available to read %s's readers list", errRunRead, project)
	}
	// The lists first and the registry after, whatever either says, so the
	// answer takes as long for a path that names no project as for one that
	// does.
	lists, err := projectreaders.Load(db)
	if err != nil {
		return fmt.Errorf("%w: the readers lists could not be read: %v", errRunRead, err)
	}
	listed := lists.CanRead(reader, project)
	if _, ok := registeredProjectAt(project); !ok {
		return fmt.Errorf("%w: no project is registered on this hub at %s", errRunRead, project)
	}
	if listed {
		return nil
	}
	if projectreaders.InsideControlDir(reader) {
		return fmt.Errorf("%w: %s is a feature's run; a readers list names projects, never their features, "+
			"so a feature's run reads only its own project", errRunRead, reader)
	}
	return fmt.Errorf("%w: %s's readers list does not name %s", errRunRead, project, reader)
}

// readableProjects lists the registered projects whose readers lists name
// reader, in the list's order.
func readableProjects(db *statedb.DB, reader string) []string {
	if db == nil || strings.TrimSpace(reader) == "" {
		return nil
	}
	lists, err := projectreaders.Load(db)
	if err != nil {
		return nil
	}
	var out []string
	for _, p := range lists.ReadableBy(projectreaders.NormalizePath(reader)) {
		if _, ok := registeredProjectAt(p); ok {
			out = append(out, p)
		}
	}
	return out
}

// registeredProjectAt returns the project registered at path — a project, not
// a feature — as the hub lists them.
func registeredProjectAt(path string) (multiui.ProjectEntry, bool) {
	path = projectreaders.NormalizePath(path)
	if path == "" {
		return multiui.ProjectEntry{}, false
	}
	projectListSource.mu.RLock()
	fn := projectListSource.fn
	projectListSource.mu.RUnlock()
	var entries []multiui.ProjectEntry
	if fn != nil {
		entries = fn()
	} else {
		entries, _ = multiui.Load()
	}
	for _, e := range entries {
		if e.IsFeature() || projectreaders.InsideControlDir(e.Path) {
			continue
		}
		if projectreaders.NormalizePath(e.Path) == path {
			return e, true
		}
	}
	return multiui.ProjectEntry{}, false
}

// gitProxyReaders is the git proxy's Options.Readers (Task 20499): a foreign
// read is served while runMayRead says so, asked through the proxy's own
// handle on the control plane, and only for the read project's own
// repository — the origin its checkout on the hub names — so a session lent to
// read one project cannot be pointed at any other repository its credential
// reaches.
func gitProxyReaders(db *statedb.DB) func(gitproxy.ForeignRead) error {
	return func(f gitproxy.ForeignRead) error {
		if err := runMayRead(db, f.Reader, f.Project); err != nil {
			return fmt.Errorf("refused by the readers list: %s",
				strings.TrimPrefix(err.Error(), errRunRead.Error()+": "))
		}
		host, repo, err := projectRepository(f.Project)
		if err != nil {
			return fmt.Errorf("refused: %s has no repository this run may read: %v", f.Project, err)
		}
		if !strings.EqualFold(host, f.ForgeHost) || !strings.EqualFold(repo, f.Repo) {
			return fmt.Errorf("refused: %s/%s is not %s's repository, which is %s/%s", f.ForgeHost, f.Repo,
				f.Project, host, repo)
		}
		return nil
	}
}

// projectRepository is the forge host and owner/name of the origin a project's
// checkout on the hub names.
func projectRepository(project string) (host, repo string, err error) {
	origin, err := readGitOrigin(project)
	if err != nil {
		return "", "", err
	}
	if repo, err = gitproxy.UpstreamRepoPath(origin.Remote); err != nil {
		return "", "", err
	}
	if host, err = repoURLHost(origin.Remote); err != nil {
		return "", "", err
	}
	return host, repo, nil
}
