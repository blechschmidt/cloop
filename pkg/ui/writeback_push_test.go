package ui

// executors.write_back: push (Task 20390): a run on an executor that does not
// share this hub's filesystem is asked to push its work back, its workspace
// pinned to the commit the push is measured from — and nothing changes for a
// hub that has not asked, or a dispatch that cannot carry it.

import (
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// writeBackExec is an executor that does not share the hub's filesystem and
// can return a workload's work.
type writeBackExec struct {
	takeoverExecutor
	canWriteBack bool
}

func (e *writeBackExec) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: executor.IsolationRemote, SupportsWriteBack: e.canWriteBack}
}

// pushWriteBackHub is a control plane whose configuration says write_back
// (or not), and a project checkout whose origin tip the hub has fetched.
func pushWriteBackHub(t *testing.T, writeBack string) (project, tip string) {
	t.Helper()
	hub := t.TempDir()
	statedbtest.SeedDir(t, hub)
	cfg := config.Default()
	cfg.Executors.WriteBack = writeBack
	if err := config.Save(hub, cfg); err != nil {
		t.Fatal(err)
	}
	controlPlaneDirMu.Lock()
	prevDir, prevPort := controlPlaneDirValue, controlPlanePortValue
	controlPlaneDirValue, controlPlanePortValue = hub, 0
	controlPlaneDirMu.Unlock()
	t.Cleanup(func() {
		controlPlaneDirMu.Lock()
		controlPlaneDirValue, controlPlanePortValue = prevDir, prevPort
		controlPlaneDirMu.Unlock()
	})

	project = t.TempDir()
	statedbtest.SeedDir(t, project)
	if _, err := state.Init(project, "write back", 0); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = project
		cmd.Env = []string{"HOME=" + t.TempDir(), "PATH=/usr/bin:/bin:/usr/local/bin", "GIT_CONFIG_NOSYSTEM=1",
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t",
			"GIT_COMMITTER_EMAIL=t@example.com"}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	run("init", "-q", "-b", "main")
	run("commit", "-q", "--allow-empty", "-m", "first")
	run("remote", "add", "origin", "https://github.com/acme/tool")
	run("update-ref", "refs/remotes/origin/main", "HEAD")
	tip = run("rev-parse", "HEAD")
	// A local commit the origin does not have: the run must not start from it.
	run("commit", "-q", "--allow-empty", "-m", "unpushed")
	return project, tip
}

func pushWriteBackWorkspace() executor.Workspace {
	return executor.Workspace{Kind: executor.WorkspaceGit, Repo: "https://github.com/acme/tool", Ref: "main",
		CredentialGrant: "acme-app"}
}

func TestPushWriteBackPinsTheWorkspaceToTheOriginsTip(t *testing.T) {
	project, tip := pushWriteBackHub(t, "push")
	ex := &writeBackExec{takeoverExecutor: *newTakeoverExecutor("edge-wb"), canWriteBack: true}
	spec, ws := applyPushWriteBack(executor.Spec{Argv: []string{"x"}}, pushWriteBackWorkspace(), ex, project,
		gitOrigin{Remote: "https://github.com/acme/tool", Ref: "main"})
	if ws.Ref != tip {
		t.Fatalf("the workspace is pinned to %q, want the origin's tip %s", ws.Ref, tip)
	}
	if spec.WriteBack.Mode != executor.WriteBackPush ||
		!regexp.MustCompile(`^cloop/run-\d{8}-\d{6}-[0-9a-f]{6}$`).MatchString(spec.WriteBack.Branch) {
		t.Fatalf("write-back = %+v", spec.WriteBack)
	}
	spec.Workspace = ws
	if err := spec.WriteBack.Validate(); err != nil {
		t.Fatalf("the write-back the hub asks for is not valid: %v", err)
	}
	if err := executor.ValidateCommitSHA(spec.Workspace.Ref); err != nil {
		t.Fatalf("the pinned ref is not a commit: %v", err)
	}
}

func TestPushWriteBackIsOnlyAskedForWhenItCanBeCarried(t *testing.T) {
	for _, tc := range []struct {
		name      string
		writeBack string
		canWB     bool
		grant     string
		network   bool
		ref       string
		journal   string
	}{
		{name: "not configured", writeBack: "", canWB: true, grant: "acme-app", ref: "main"},
		{name: "an executor that cannot return work", writeBack: "push", canWB: false, grant: "acme-app", ref: "main",
			journal: "cannot return a workload's work"},
		{name: "no grant to push with", writeBack: "push", canWB: true, ref: "main", journal: "no GitHub grant"},
		{name: "no network", writeBack: "push", canWB: true, grant: "acme-app", network: true, ref: "main",
			journal: "no network"},
		{name: "detached", writeBack: "push", canWB: true, grant: "acme-app", ref: "", journal: "no branch checked out"},
		{name: "no origin ref", writeBack: "push", canWB: true, grant: "acme-app", ref: "feature", journal: "fetch the origin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			project, _ := pushWriteBackHub(t, tc.writeBack)
			ex := &writeBackExec{takeoverExecutor: *newTakeoverExecutor("edge-wb"), canWriteBack: tc.canWB}
			in := pushWriteBackWorkspace()
			in.CredentialGrant = tc.grant
			spec, ws := applyPushWriteBack(executor.Spec{Argv: []string{"x"}, DisableNetwork: tc.network}, in, ex,
				project, gitOrigin{Remote: in.Repo, Ref: tc.ref})
			if spec.WriteBack.Enabled() || ws != in {
				t.Fatalf("asked for %+v and pinned %+v; want the dispatch unchanged", spec.WriteBack, ws)
			}
			events := journalEvents(t, project, statedb.EventWriteBack)
			if tc.journal == "" {
				if len(events) != 0 {
					t.Fatalf("the journal says %v for a hub that asked for nothing", events)
				}
				return
			}
			if len(events) != 1 || !strings.Contains(events[0], tc.journal) {
				t.Fatalf("journal = %v, want one line saying %q", events, tc.journal)
			}
		})
	}
}

func TestPushWriteBackOutcomeIsJournaled(t *testing.T) {
	project := t.TempDir()
	statedbtest.SeedDir(t, project)
	if _, err := state.Init(project, "write back", 0); err != nil {
		t.Fatal(err)
	}
	ex := newTakeoverExecutor("edge-wb")
	sha := strings.Repeat("ab", 20)
	journalPushWriteBack(project, ex, executor.Status{WriteBack: &executor.WriteBackResult{
		Mode: executor.WriteBackPush, Branch: "cloop/run-1", CommitSHA: sha}})
	journalPushWriteBack(project, ex, executor.Status{WriteBack: &executor.WriteBackResult{
		Mode: executor.WriteBackPush, Branch: "cloop/run-2", Err: "remote rejected"}})
	// A feature's bundle is landed by its own path, not journaled here.
	journalPushWriteBack(project, ex, executor.Status{WriteBack: &executor.WriteBackResult{
		Mode: executor.WriteBackBundle, Branch: "cloop/feature/x"}})
	events := journalEvents(t, project, statedb.EventWriteBack)
	if len(events) != 2 || !strings.Contains(events[0], "pushed to cloop/run-1 at "+sha) ||
		!strings.Contains(events[1], "could not be pushed back") || !strings.Contains(events[1], "remote rejected") {
		t.Fatalf("journal = %v", events)
	}
}

// journalEvents returns the messages of dir's journal rows of one type,
// oldest first.
func journalEvents(t *testing.T, dir string, eventType statedb.EventType) []string {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return nil
	}
	defer db.Close()
	rows, _, err := db.ListEvents(0, 500)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for i := len(rows) - 1; i >= 0; i-- {
		if rows[i].Type == eventType {
			out = append(out, rows[i].Message)
		}
	}
	return out
}
