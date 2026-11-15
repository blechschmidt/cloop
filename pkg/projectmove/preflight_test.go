package projectmove

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitstate"
	"github.com/blechschmidt/cloop/pkg/fwpolicy"
	"github.com/blechschmidt/cloop/pkg/isolationprobe"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// scenario is one table row: an environment change, a target, options, and
// the findings it must produce.
type scenario struct {
	name   string
	setup  func(*fakeEnv)
	target string
	opts   Options
	wants  []want
	// none lists kinds (at any severity) that must not appear.
	none []Kind
	// blocked is whether the move must be reported blocked.
	blocked bool
}

func runScenarios(t *testing.T, cases []scenario) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newEnv()
			if tc.setup != nil {
				tc.setup(env)
			}
			target := tc.target
			if target == "" {
				target = "dev1"
			}
			rep := preflightOf(t, env, target, tc.opts)
			expect(t, rep, tc.wants...)
			for _, k := range tc.none {
				expectNone(t, rep, k, "")
			}
			if rep.Blocked != tc.blocked {
				t.Errorf("blocked = %v, want %v\n%s", rep.Blocked, tc.blocked, dump(rep))
			}
		})
	}
}

func gatePlan() *pm.Plan {
	return &pm.Plan{Tasks: []*pm.Task{
		{ID: 1, Title: "build it", Status: pm.TaskDone, Priority: 1},
		{ID: 2, Title: "Review the build", Kind: pm.KindHumanGate, Status: pm.TaskPending, Priority: 2},
		{ID: 3, Title: "ship it", Status: pm.TaskPending, Priority: 3},
	}}
}

// (a) a run that is active, paused or waiting at a human review gate.
func TestRunFindings(t *testing.T) {
	featurePath := testProject.Path + "/.cloop/features/widget"
	runScenarios(t, []scenario{
		{name: "nothing running", none: []Kind{KindRun}},
		{name: "an executing run blocks", blocked: true,
			setup: func(e *fakeEnv) {
				e.runs[testProject.Path] = RunFacts{Executing: true, ExecutingDetail: "a workload on executor local", Status: "running"}
			},
			wants: []want{{KindRun, SeverityBlocker, "a workload on executor local"}}},
		{name: "a run queued for a pool blocks", blocked: true,
			setup: func(e *fakeEnv) {
				e.runs[testProject.Path] = RunFacts{Queued: &QueuedRun{PoolID: "pool-abc", State: "waiting"},
					Status: "paused", Pause: &pausereason.Reason{Code: pausereason.CodePoolCapacity}}
			},
			wants: []want{{KindRun, SeverityBlocker, "pool-abc's queue"}}},
		{name: "a run waiting out low disk is alive and blocks", blocked: true,
			setup: func(e *fakeEnv) {
				e.runs[testProject.Path] = RunFacts{Status: "paused", Pause: &pausereason.Reason{Code: pausereason.CodeDiskLow, Detail: "disk below 1 GB"}}
			},
			wants: []want{{KindRun, SeverityBlocker, "waiting for disk space"}}},
		{name: "a usage-cap pause the hub will resume blocks", blocked: true,
			setup: func(e *fakeEnv) {
				r := pausereason.NewUntil(pausereason.CodeUsageCap, "5-hour cap reached", time.Date(2026, 11, 15, 14, 50, 0, 0, time.UTC))
				e.runs[testProject.Path] = RunFacts{Status: "paused", Pause: &r}
			},
			wants: []want{{KindRun, SeverityBlocker, "restarts it at 2026-11-15T14:50:00Z"}}},
		{name: "a pause waiting for a decision carries with a warning",
			setup: func(e *fakeEnv) {
				r := pausereason.New(pausereason.CodeBudget, "daily budget spent")
				e.runs[testProject.Path] = RunFacts{Status: "paused", Pause: &r}
			},
			wants: []want{{KindRun, SeverityWarning, "daily budget spent"}}},
		{name: "a run that ended normally carries",
			setup: func(e *fakeEnv) {
				r := pausereason.New(pausereason.CodeOperator, "")
				e.runs[testProject.Path] = RunFacts{Status: "paused", Pause: &r}
			},
			wants: []want{{KindRun, SeverityWillCarry, "nothing is waiting on it"}}},
		{name: "a run lost with its executor is a warning",
			setup: func(e *fakeEnv) {
				r := pausereason.New(pausereason.CodeExecutorLost, "the device went away")
				e.runs[testProject.Path] = RunFacts{Status: "paused", Pause: &r}
			},
			wants: []want{{KindRun, SeverityWarning, "because of its executor"}}},
		{name: "a run waiting at a review gate is a warning",
			setup: func(e *fakeEnv) {
				r := pausereason.NewForTask(pausereason.CodeApproval, "", 2)
				e.runs[testProject.Path] = RunFacts{Status: "paused", Pause: &r, Plan: gatePlan()}
			},
			wants: []want{
				{KindRun, SeverityWarning, "review gate #2"},
				{KindRun, SeverityWarning, "Review the build"},
			}},
		{name: "a feature's executing run blocks", blocked: true,
			setup: func(e *fakeEnv) {
				e.features = []Feature{{Slug: "widget", Path: featurePath}}
				e.runs[featurePath] = RunFacts{Executing: true, Status: "running"}
			},
			wants: []want{{KindRun, SeverityBlocker, "feature widget"}}},
		{name: "unreadable run state blocks", blocked: true,
			setup: func(e *fakeEnv) {
				e.runs[testProject.Path] = RunFacts{Error: "database is locked"}
			},
			wants: []want{{KindRun, SeverityBlocker, "database is locked"}}},
		{name: "unlistable features block", blocked: true,
			setup: func(e *fakeEnv) { e.featuresErr = errors.New("permission denied") },
			wants: []want{{KindRun, SeverityBlocker, "permission denied"}}},
	})
}

// dirtyTree is a hub tree whose main worktree and a feature's hold changes.
func dirtyTree() Tree {
	return Tree{Git: GitState{Dir: testProject.Path, Repository: true, Remotes: []string{"origin"},
		Worktrees: []gitstate.Worktree{
			{Path: testProject.Path, Branch: "main", Changed: 2, ChangedPaths: []string{"main.go", "go.mod"},
				Untracked: 1, UntrackedPaths: []string{"notes.txt"}},
			{Path: testProject.Path + "/.cloop/features/widget", Rel: ".cloop/features/widget",
				Branch: "cloop/feature/widget", Untracked: 1, UntrackedPaths: []string{"wip.go"}},
		}}}
}

// (b) uncommitted changes and untracked files on the source.
func TestWorkingTreeFindings(t *testing.T) {
	runScenarios(t, []scenario{
		{name: "a clean tree reports nothing", none: []Kind{KindWorkingTree}},
		{name: "changes are captured for a device",
			setup: func(e *fakeEnv) { e.tree = dirtyTree() },
			wants: []want{
				{KindWorkingTree, SeverityWillCarry, "2 changed and 2 untracked"},
				{KindWorkingTree, SeverityWillCarry, "feature widget"},
				{KindWorkingTree, SeverityWillCarry, "main.go"},
			}},
		{name: "changes stay put for a container on the hub", target: "box",
			setup: func(e *fakeEnv) { e.tree = dirtyTree() },
			wants: []want{{KindWorkingTree, SeverityWillCarry, "stay where they are"}}},
		{name: "changes a Pod would never see block", target: "k8s", blocked: true,
			setup: func(e *fakeEnv) { e.tree = dirtyTree() },
			wants: []want{{KindWorkingTree, SeverityBlocker, "from the forge"}}},
		{name: "a worktree that could not be inspected is a warning",
			setup: func(e *fakeEnv) {
				e.tree.Git.Worktrees = []gitstate.Worktree{{Path: testProject.Path + "/.cloop/worktrees/task-3",
					Rel: ".cloop/worktrees/task-3", Error: "git status: index file corrupt"}}
			},
			wants: []want{{KindWorkingTree, SeverityWarning, "index file corrupt"}}},
		{name: "an unreadable tree blocks", blocked: true,
			setup: func(e *fakeEnv) { e.treeErr = errors.New("permission denied") },
			wants: []want{{KindWorkingTree, SeverityBlocker, "permission denied"}}},
		{name: "a project with no repository has no working tree to report",
			setup: func(e *fakeEnv) { e.tree = Tree{Git: GitState{NotARepository: "it has no .git"}} },
			none:  []Kind{KindWorkingTree, KindLocalCommits}},
	})
}

// (c) commits no remote holds, per branch, the features' included.
func TestLocalCommitFindings(t *testing.T) {
	ahead := func(e *fakeEnv) {
		e.tree.Git.Branches = []gitstate.Branch{
			{Name: "main", Unpushed: 2, Upstream: "refs/remotes/origin/main"},
			{Name: "cloop/feature/widget", Unpushed: 1},
			{Name: "published"},
		}
		e.tree.Git.Worktrees = []gitstate.Worktree{{Path: testProject.Path + "/.cloop/worktrees/task-7",
			Rel: ".cloop/worktrees/task-7", Detached: true, Orphaned: 1}}
		e.tree.Git.Stash = 2
	}
	runScenarios(t, []scenario{
		{name: "pushed branches report nothing",
			setup: func(e *fakeEnv) { e.tree.Git.Branches = []gitstate.Branch{{Name: "main"}} },
			none:  []Kind{KindLocalCommits}},
		{name: "unpushed commits are bundled for a device", setup: ahead,
			wants: []want{
				{KindLocalCommits, SeverityWillCarry, "4 commit(s)"},
				{KindLocalCommits, SeverityWillCarry, "upstream origin/main"},
				{KindLocalCommits, SeverityWillCarry, "cloop/feature/widget"},
				{KindLocalCommits, SeverityWillCarry, "detached HEAD in .cloop/worktrees/task-7"},
				{KindLocalCommits, SeverityWillCarry, "stash"},
				{KindLocalCommits, SeverityWillCarry, "nothing was fetched"},
			}},
		{name: "unpushed commits a Pod would never see block", target: "k8s", blocked: true, setup: ahead,
			wants: []want{{KindLocalCommits, SeverityBlocker, "Push these branches"}}},
		{name: "a repository with no remote says so", target: "k8s", blocked: true,
			setup: func(e *fakeEnv) {
				e.tree.Git.Remotes = nil
				e.tree.Git.Branches = []gitstate.Branch{{Name: "main", Unpushed: 3}}
			},
			wants: []want{{KindLocalCommits, SeverityBlocker, "no remote at all"}}},
		{name: "a branch that could not be counted is listed",
			setup: func(e *fakeEnv) {
				e.tree.Git.Branches = []gitstate.Branch{{Name: "odd", Error: "bad object"}}
			},
			wants: []want{{KindLocalCommits, SeverityWillCarry, "could not be counted: bad object"}}},
	})
}

// (d) files under .cloop that no database holds.
func TestProjectFileFindings(t *testing.T) {
	files := func(e *fakeEnv) {
		e.tree.Files = FileInventory{Dir: testProject.Path + "/.cloop", Categories: []FileCategory{
			{Name: FilesArtifacts, Files: 3, Bytes: 4096},
			{Name: FilesAttachmentOutbox, Files: 1, Bytes: 10, Examples: []string{".cloop/attachments/outbox/4/report.pdf"}},
			{Name: FilesSandboxSpec, Files: 1, Bytes: 120},
			{Name: FilesRequirementsSpec, Files: 1, Bytes: 900},
		}}
		e.features = []Feature{{Slug: "widget", Path: testProject.Path + "/.cloop/features/widget"}}
		e.tree.FeatureFiles = map[string]FileInventory{"widget": {Categories: []FileCategory{{Name: FilesCheckpoints, Files: 2}}}}
	}
	runScenarios(t, []scenario{
		{name: "no files report nothing", none: []Kind{KindProjectFiles}},
		{name: "files are listed by category and carried", setup: files,
			wants: []want{
				{KindProjectFiles, SeverityWillCarry, "8 file(s)"},
				{KindProjectFiles, SeverityWillCarry, FilesSandboxSpec},
				{KindProjectFiles, SeverityWillCarry, FilesRequirementsSpec},
				{KindProjectFiles, SeverityWillCarry, "feature widget: checkpoints"},
				{KindProjectFiles, SeverityWarning, "report.pdf"},
			}},
		// Task 20497: the finding says which of the listed files never leave.
		{name: "the configuration is listed and never sent", setup: func(e *fakeEnv) {
			files(e)
			e.tree.Files.Categories = append(e.tree.Files.Categories, FileCategory{Name: FilesConfig, Files: 1, Bytes: 260})
		},
			wants: []want{{KindProjectFiles, SeverityWillCarry, "never sent to the target — the project's configuration (.cloop/config.yaml): the project's configuration can hold API keys"}}},
		{name: "the outbox is no concern when the tree stays", target: "box", setup: files,
			wants: []want{{KindProjectFiles, SeverityWillCarry, "stay where they are"}},
			none:  nil},
		{name: "an unwalkable .cloop is a warning",
			setup: func(e *fakeEnv) { e.tree.Files = FileInventory{Dir: "/x/.cloop", Error: "permission denied"} },
			wants: []want{{KindProjectFiles, SeverityWarning, "permission denied"}}},
	})
	t.Run("no outbox warning when the tree stays", func(t *testing.T) {
		env := newEnv()
		files(env)
		rep := preflightOf(t, env, "box", Options{})
		for _, f := range rep.Of(KindProjectFiles) {
			if f.Severity == SeverityWarning {
				t.Errorf("the outbox is drained in place when the tree stays; got %q", f.Title)
			}
		}
	})
}

// (e) whether the source can be reached, and what abandoning it loses.
func TestSourceReachabilityFindings(t *testing.T) {
	offline := func(e *fakeEnv) {
		e.binding = "dev2"
		e.execs["dev2"].(*fakeExec).health = errors.New("no session: last seen 3 days ago")
	}
	runScenarios(t, []scenario{
		{name: "an offline device blocks", target: "dev1", blocked: true, setup: offline,
			wants: []want{{KindSourceUnreachable, SeverityBlocker, "last seen 3 days ago"}},
			none:  []Kind{KindAbandoned}},
		{name: "abandoning an offline device lists what is lost", target: "dev1",
			opts: Options{AbandonSource: true}, setup: offline,
			wants: []want{
				{KindSourceUnreachable, SeverityWarning, "last seen 3 days ago"},
				{KindAbandoned, SeverityWarning, "/srv/work/" + executor.DeviceWorkDir(testProject.Path)},
				{KindAbandoned, SeverityWarning, "run homes"},
			}},
		{name: "a binding to an executor the hub no longer has blocks", blocked: true,
			setup: func(e *fakeEnv) { e.binding = "gone" },
			wants: []want{{KindSourceUnreachable, SeverityBlocker, "not registered"}}},
		{name: "a reachable device's working copy cannot be read", target: "dev1",
			setup: func(e *fakeEnv) { e.binding = "dev2" },
			wants: []want{{KindSourceUnseen, SeverityWarning, "/srv/work/" + executor.DeviceWorkDir(testProject.Path)}},
			none:  []Kind{KindSourceUnreachable}},
		{name: "a virtual executor's work is on its device", target: "dev2",
			setup: func(e *fakeEnv) { e.binding = "vx-hsm" },
			wants: []want{{KindSourceUnseen, SeverityWarning, "Device dev1 keeps"}}},
		{name: "a pool's volumes cannot be read", target: "dev1",
			setup: func(e *fakeEnv) {
				e.binding = "pool:pool-a"
				e.pools["pool-a"] = PoolFacts{Found: true, Name: "ci", Tenant: "prj-1234"}
			},
			wants: []want{{KindSourceUnseen, SeverityWarning, "prj-1234"}}},
		{name: "a pool that is gone is unreachable", target: "dev1", blocked: true,
			setup: func(e *fakeEnv) { e.binding = "pool:pool-gone" },
			wants: []want{{KindSourceUnreachable, SeverityBlocker, "no longer exists"}}},
		{name: "a Kubernetes source keeps nothing", target: "dev1",
			setup: func(e *fakeEnv) { e.binding = "k8s" },
			wants: []want{{KindWorkingTree, SeverityWillCarry, "Nothing is kept"}},
			none:  []Kind{KindSourceUnseen, KindSourceUnreachable}},
		{name: "abandoning the hub tree lists what stays behind", opts: Options{AbandonSource: true},
			setup: func(e *fakeEnv) {
				e.tree = dirtyTree()
				e.tree.Git.Branches = []gitstate.Branch{{Name: "main", Unpushed: 2}}
				e.tree.Files = FileInventory{Dir: testProject.Path + "/.cloop", Categories: []FileCategory{{Name: FilesArtifacts, Files: 4}}}
			},
			wants: []want{
				{KindAbandoned, SeverityWarning, "changes in the project"},
				{KindAbandoned, SeverityWarning, "branch main"},
				{KindAbandoned, SeverityWarning, FilesArtifacts},
			},
			none: []Kind{KindWorkingTree, KindLocalCommits, KindProjectFiles}},
		{name: "abandoning a clean hub tree loses nothing", opts: Options{AbandonSource: true},
			wants: []want{{KindAbandoned, SeverityWillCarry, "loses nothing"}}},
	})
}

// (f) the target itself.
func TestTargetFindings(t *testing.T) {
	runScenarios(t, []scenario{
		{name: "an unknown executor blocks", target: "nope", blocked: true,
			wants: []want{{KindTarget, SeverityBlocker, "not registered"}}},
		{name: "the binding the project already has blocks", target: "local", blocked: true,
			wants: []want{{KindTarget, SeverityBlocker, "nothing to move"}}},
		{name: "an unbound project's default executor is where it already runs", target: "local", blocked: true,
			setup: func(e *fakeEnv) { e.binding = "" },
			wants: []want{{KindTarget, SeverityBlocker, "nothing to move"}}},
		{name: "local is refused where host execution is off", target: "local", blocked: true,
			setup: func(e *fakeEnv) { e.binding = "box"; e.hostAllowed = false },
			wants: []want{{KindTarget, SeverityBlocker, "allow_host_process is off"}}},
		{name: "a pool runner is refused", target: "runner1", blocked: true,
			setup: func(e *fakeEnv) {
				r := deviceExec("runner1")
				r.ephem = true
				e.execs["runner1"] = r
			},
			wants: []want{{KindTarget, SeverityBlocker, "pool's runner"}}},
		{name: "an offline target blocks", target: "dev2", blocked: true,
			setup: func(e *fakeEnv) { e.execs["dev2"].(*fakeExec).health = errors.New("connection lost") },
			wants: []want{{KindTarget, SeverityBlocker, "connection lost"}}},
		{name: "a non-isolating target is refused under strict mode", target: "hostish", blocked: true,
			setup: func(e *fakeEnv) {
				e.binding = "box"
				e.hostAllowed = false
				h := hostExec()
				h.id = "hostish"
				e.execs["hostish"] = h
			},
			wants: []want{{KindTarget, SeverityBlocker, "allow_host_process is off"}}},
		{name: "a pool that does not exist blocks", target: "pool:pool-x", blocked: true,
			wants: []want{{KindTarget, SeverityBlocker, "no executor pool pool-x"}}},
		{name: "a revoked pool blocks", target: "pool:pool-r", blocked: true,
			setup: func(e *fakeEnv) {
				e.pools["pool-r"] = PoolFacts{Found: true, Revoked: true, Admitted: true, OwnerMayRead: true}
			},
			wants: []want{{KindTarget, SeverityBlocker, "was revoked"}}},
		{name: "a pool the caller may not use blocks", target: "pool:pool-p", blocked: true,
			setup: func(e *fakeEnv) { e.pools["pool-p"] = PoolFacts{Found: true, OwnerMayRead: true} },
			wants: []want{{KindAudience, SeverityBlocker, "access list"}}},
		{name: "a pool whose owner may not read the project blocks", target: "pool:pool-o", blocked: true,
			setup: func(e *fakeEnv) { e.pools["pool-o"] = PoolFacts{Found: true, Admitted: true} },
			wants: []want{{KindTarget, SeverityBlocker, "may not read this project"}}},
		{name: "a pool whose runners do not fit blocks", target: "pool:pool-f", blocked: true,
			setup: func(e *fakeEnv) {
				e.pools["pool-f"] = PoolFacts{Found: true, Admitted: true, OwnerMayRead: true, Fits: "its runners share the node's kernel"}
			},
			wants: []want{{KindTarget, SeverityBlocker, "share the node's kernel"}}},
		{name: "a fitting pool is a valid target", target: "pool:pool-ok",
			setup: func(e *fakeEnv) {
				e.pools["pool-ok"] = PoolFacts{Found: true, Admitted: true, OwnerMayRead: true, Template: deviceExec("pool:pool-ok")}
			}},
		{name: "a project the target cannot get the source of blocks", blocked: true,
			setup: func(e *fakeEnv) {
				e.workspace = []WorkspaceIssue{{Who: "the project", Problem: "it is a git repository with no remote", Remedy: "Add an https remote and push."}}
			},
			wants: []want{{KindTarget, SeverityBlocker, "no remote"}}},
		{name: "an unreadable sandbox spec is a warning",
			setup: func(e *fakeEnv) { e.sandboxErr = errors.New("line 3: unknown key") },
			wants: []want{{KindTarget, SeverityWarning, "line 3: unknown key"}}},
		{name: "a sandbox spec the target cannot honour blocks", target: "k8s", blocked: true,
			setup: func(e *fakeEnv) {
				e.sandboxReq = executor.Requirements{RequireImageOverride: true, RequireSandboxMounts: true}
			},
			wants: []want{
				{KindTarget, SeverityBlocker, string(executor.ConstraintImageOverride)},
				{KindTarget, SeverityBlocker, string(executor.ConstraintSandboxMounts)},
			}},
	})
}

// (f) the caller on the target's access list.
func TestAudienceFindings(t *testing.T) {
	runScenarios(t, []scenario{
		{name: "an unrestricted target admits", none: []Kind{KindAudience}},
		{name: "a caller not on the list is blocked", blocked: true,
			setup: func(e *fakeEnv) { e.audience["dev1"] = false },
			wants: []want{{KindAudience, SeverityBlocker, "not on its access list"}}},
		{name: "an unreadable list fails closed", blocked: true,
			setup: func(e *fakeEnv) { e.audienceErr = errors.New("database is locked") },
			wants: []want{{KindAudience, SeverityBlocker, "database is locked"}}},
	})
}

// (f) a harness credential for a sandboxed target.
func TestHarnessCredentialFindings(t *testing.T) {
	runScenarios(t, []scenario{
		{name: "no credential needed reports nothing", none: []Kind{KindHarnessCredential}},
		{name: "a missing credential blocks", blocked: true,
			setup: func(e *fakeEnv) {
				e.harness = HarnessFacts{Applies: true, State: HarnessMissing, Provider: "claudecode",
					Detail: "no grant carries CLAUDE_CODE_OAUTH_TOKEN to dev1", Remedy: "Grant a Claude credential."}
			},
			wants: []want{{KindHarnessCredential, SeverityBlocker, "CLAUDE_CODE_OAUTH_TOKEN"}}},
		{name: "an expiring credential is a warning",
			setup: func(e *fakeEnv) {
				e.harness = HarnessFacts{Applies: true, State: HarnessExpiring, Provider: "claudecode"}
			},
			wants: []want{{KindHarnessCredential, SeverityWarning, "about to lapse"}}},
		{name: "a granted credential carries",
			setup: func(e *fakeEnv) {
				e.harness = HarnessFacts{Applies: true, State: HarnessOK, Provider: "claudecode", Sources: []string{"claude-code-harness"}}
			},
			wants: []want{{KindHarnessCredential, SeverityWillCarry, "claude-code-harness"}}},
		{name: "an unanswerable check is a warning",
			setup: func(e *fakeEnv) { e.harnessErr = errors.New("broker unavailable") },
			wants: []want{{KindHarnessCredential, SeverityWarning, "broker unavailable"}}},
	})
}

// (f) the project's secret grants on the target.
func TestSecretGrantFindings(t *testing.T) {
	pat := GrantFacts{ID: "g1", SecretRef: "gh-pat", Kind: "github_pat", Subject: "project:" + testProject.Path,
		ReachesSource: true, ReachesTarget: true, Files: true}
	pinned := GrantFacts{ID: "g2", SecretRef: "build-env", Kind: "env", Subject: "executor:local", ReachesSource: true}
	repo := GrantFacts{ID: "g3", SecretRef: "monorepo", Kind: "local_repo", Subject: "project:" + testProject.Path,
		ReachesSource: true, ReachesTarget: true, HostPath: true}
	runScenarios(t, []scenario{
		{name: "no grants report nothing", none: []Kind{KindSecretGrants}},
		{name: "a project grant carries",
			setup: func(e *fakeEnv) { e.grants = []GrantFacts{pat} },
			wants: []want{{KindSecretGrants, SeverityWillCarry, "gh-pat"}}},
		{name: "a grant pinned to the source is lost",
			setup: func(e *fakeEnv) { e.grants = []GrantFacts{pinned} },
			wants: []want{{KindSecretGrants, SeverityWarning, "executor:local"}}},
		{name: "credential files a target cannot receive block", blocked: true,
			setup: func(e *fakeEnv) {
				e.grants = []GrantFacts{pat}
				e.execs["dev1"].(*fakeExec).caps.SupportsSecretFiles = false
			},
			wants: []want{{KindSecretGrants, SeverityBlocker, "cannot receive"}}},
		{name: "a hub directory a device cannot mount blocks", blocked: true,
			setup: func(e *fakeEnv) { e.grants = []GrantFacts{repo} },
			wants: []want{{KindSecretGrants, SeverityBlocker, "binds a directory of the hub"}}},
		{name: "a target that cannot take a credential back blocks", blocked: true,
			setup: func(e *fakeEnv) {
				e.grants = []GrantFacts{pat}
				e.execs["dev1"].(*fakeExec).noRevoke = true
			},
			wants: []want{{KindSecretGrants, SeverityBlocker, "cannot take a credential back"}}},
		{name: "an unlistable grant set is a warning",
			setup: func(e *fakeEnv) { e.grantsErr = errors.New("sealing key unavailable") },
			wants: []want{{KindSecretGrants, SeverityWarning, "sealing key unavailable"}}},
	})
}

// (f) the project's firewall against the target's device rules.
func TestFirewallFindings(t *testing.T) {
	device := &fwpolicy.Rules{AllowCIDRs: []string{"10.0.0.0/8"}, AllowPorts: []int{443}}
	runScenarios(t, []scenario{
		{name: "no rules report nothing", none: []Kind{KindFirewall}},
		{name: "project rules inside the target's carry",
			setup: func(e *fakeEnv) {
				e.firewall = FirewallFacts{Target: device, Enforceable: true,
					Project: &fwpolicy.Rules{AllowCIDRs: []string{"10.1.0.0/16"}, AllowPorts: []int{443}}}
			},
			wants: []want{{KindFirewall, SeverityWillCarry, "fit the target's"}}},
		{name: "project rules beyond the target's are narrowed",
			setup: func(e *fakeEnv) {
				e.firewall = FirewallFacts{Target: device, Enforceable: true,
					Project: &fwpolicy.Rules{AllowCIDRs: []string{"10.0.0.0/8", "192.168.0.0/16"}, AllowPorts: []int{22, 443}}}
			},
			wants: []want{
				{KindFirewall, SeverityWarning, "narrows them"},
				{KindFirewall, SeverityWarning, "192.168"},
			}},
		{name: "rules on a target that cannot enforce them block", blocked: true,
			setup: func(e *fakeEnv) {
				e.firewall = FirewallFacts{Project: &fwpolicy.Rules{AllowCIDRs: []string{"10.1.0.0/16"}, AllowPorts: []int{443}},
					Reason: "the agent has no packet filter"}
			},
			wants: []want{{KindFirewall, SeverityBlocker, "the agent has no packet filter"}}},
		{name: "target rules that do not compose block", blocked: true,
			setup: func(e *fakeEnv) { e.firewall = FirewallFacts{Error: "the virtual executor reaches beyond its device"} },
			wants: []want{{KindFirewall, SeverityBlocker, "reaches beyond its device"}}},
		{name: "an unreadable rule set is a warning",
			setup: func(e *fakeEnv) { e.firewallErr = errors.New("no such table") },
			wants: []want{{KindFirewall, SeverityWarning, "no such table"}}},
	})
}

// (f) devices, interfaces and forwarded hardware.
func TestDeviceFeatureFindings(t *testing.T) {
	hsm := GrantFacts{ID: "g5", SecretRef: "yubihsm", Kind: "host_device", Subject: "project:" + testProject.Path,
		ReachesSource: true, ReachesTarget: true, Devices: []string{"yubihsm"}}
	lan := GrantFacts{ID: "g6", SecretRef: "lab-lan", Kind: "host_interface", Subject: "project:" + testProject.Path,
		ReachesSource: true, ReachesTarget: true, Interfaces: []string{"eth1"}}
	runScenarios(t, []scenario{
		{name: "no devices report nothing", none: []Kind{KindDeviceFeatures}},
		{name: "granted devices the target can expose carry",
			setup: func(e *fakeEnv) { e.grants = []GrantFacts{hsm, lan} },
			wants: []want{{KindDeviceFeatures, SeverityWillCarry, "yubihsm"}}},
		{name: "a device grant on a target without device support blocks", target: "vx-hsm", blocked: true,
			setup: func(e *fakeEnv) { e.grants = []GrantFacts{hsm} },
			wants: []want{{KindDeviceFeatures, SeverityBlocker, "cannot expose host devices"}}},
		{name: "an interface grant on a target that cannot move one blocks", target: "vx-hsm", blocked: true,
			setup: func(e *fakeEnv) { e.grants = []GrantFacts{lan} },
			wants: []want{{KindDeviceFeatures, SeverityBlocker, "cannot move a host interface"}}},
		{name: "a device grant reaching only the source is lost",
			setup: func(e *fakeEnv) {
				g := hsm
				g.Subject, g.ReachesTarget = "executor:local", false
				e.grants = []GrantFacts{g}
			},
			wants: []want{{KindDeviceFeatures, SeverityWarning, "reaches the source only"}}},
		{name: "a source virtual executor's devices are lost", target: "dev2",
			setup: func(e *fakeEnv) {
				e.binding = "vx-hsm"
				e.virtualDevs = map[string][]string{"vx-hsm": {"yubihsm"}}
			},
			wants: []want{{KindDeviceFeatures, SeverityWarning, "source virtual executor"}}},
		{name: "a forwarded device bound to another executor is lost",
			setup: func(e *fakeEnv) {
				e.forwarded = []ForwardedFacts{{ID: "fb1", Name: "bench", Kind: "usb", Forwarder: "edge-1", Online: true, Executor: "vx-hsm"}}
			},
			wants: []want{{KindDeviceFeatures, SeverityWarning, "bound to executor vx-hsm only"}}},
		{name: "a forwarded device the target cannot take blocks", blocked: true,
			setup: func(e *fakeEnv) {
				e.forwarded = []ForwardedFacts{{ID: "fb1", Name: "bench", Kind: "usb", Forwarder: "edge-1", Online: true}}
				e.takes = errors.New("the agent speaks protocol v21, forwarded devices need v22")
			},
			wants: []want{{KindDeviceFeatures, SeverityBlocker, "need v22"}}},
		{name: "a forwarded device that applies carries",
			setup: func(e *fakeEnv) {
				e.forwarded = []ForwardedFacts{{ID: "fb1", Name: "bench", Kind: "l2", Forwarder: "edge-1"}}
			},
			wants: []want{{KindDeviceFeatures, SeverityWillCarry, "the forwarder is offline now"}}},
		{name: "sandbox device selectors on a target without device support block", target: "vx-hsm", blocked: true,
			setup: func(e *fakeEnv) { e.sandboxReq = executor.Requirements{RequireDevices: true} },
			wants: []want{{KindDeviceFeatures, SeverityBlocker, string(executor.ConstraintDevices)}}},
		{name: "an unlistable forwarded set is a warning",
			setup: func(e *fakeEnv) { e.forwardedErr = errors.New("table missing") },
			wants: []want{{KindDeviceFeatures, SeverityWarning, "table missing"}}},
	})
}

// (f) the isolation the project demands, and whether the target's claims hold.
func TestIsolationFindings(t *testing.T) {
	gvisor := func(e *fakeEnv) {
		d := e.execs["dev1"].(*fakeExec)
		d.caps.KernelIsolated = true
		d.runtime = "runsc"
	}
	contradicted := func(t *testing.T) {
		prev := executor.SetIsolationEvidenceSource(func(id, runtime string) (executor.IsolationRecord, bool) {
			return executor.IsolationRecord{ExecutorID: id, Runtime: runtime, Claim: isolationprobe.KindUserspaceKernel,
				Verdict: isolationprobe.KindHostKernel, ProbedAt: time.Now()}, true
		})
		t.Cleanup(func() { executor.SetIsolationEvidenceSource(prev) })
	}
	runScenarios(t, []scenario{
		{name: "no demand and no weakening reports nothing", target: "box", none: []Kind{KindIsolation}},
		{name: "a demanded kernel isolation the target lacks blocks", blocked: true,
			setup: func(e *fakeEnv) { e.sandboxReq = executor.Requirements{RequireKernelIsolation: true} },
			wants: []want{{KindIsolation, SeverityBlocker, string(executor.ConstraintKernelIsolation)}}},
		{name: "an unverified claim is a warning",
			setup: func(e *fakeEnv) {
				gvisor(e)
				e.sandboxReq = executor.Requirements{RequireKernelIsolation: true}
			},
			wants: []want{{KindIsolation, SeverityWarning, "unverified"}}},
		{name: "a weaker target is a warning", target: "dev1",
			setup: func(e *fakeEnv) {
				e.binding = "dev2"
				e.execs["dev2"].(*fakeExec).caps.KernelIsolated = true
			},
			wants: []want{{KindIsolation, SeverityWarning, "isolates runs less than the source"}}},
	})
	t.Run("a contradicted claim blocks a demand", func(t *testing.T) {
		contradicted(t)
		env := newEnv()
		gvisor(env)
		env.sandboxReq = executor.Requirements{RequireKernelIsolation: true}
		rep := preflightOf(t, env, "dev1", Options{})
		expect(t, rep, want{KindIsolation, SeverityBlocker, string(executor.ConstraintIsolationEvidence)})
	})
	t.Run("a contradicted claim warns without a demand", func(t *testing.T) {
		contradicted(t)
		env := newEnv()
		gvisor(env)
		rep := preflightOf(t, env, "dev1", Options{})
		expect(t, rep, want{KindIsolation, SeverityWarning, "contradicted"})
		if rep.Blocked {
			t.Errorf("an unrequired claim must not block\n%s", dump(rep))
		}
	})
}

// (g) knowledge, requirement and policy bindings keyed by the project's path.
func TestPathBindingFindings(t *testing.T) {
	runScenarios(t, []scenario{
		{name: "no records report nothing", none: []Kind{KindPathBindings}},
		{name: "records keyed by path carry",
			setup: func(e *fakeEnv) {
				e.paths = []PathBinding{
					{Store: "knowledge_bindings", What: "knowledge sources the project searches", Count: 2},
					{Store: "project_members", What: "people and teams it is shared with", Count: 3},
					{Store: "project_firewall_rules", What: "its firewall rule set", Count: 0},
				}
			},
			wants: []want{
				{KindPathBindings, SeverityWillCarry, "5 record(s)"},
				{KindPathBindings, SeverityWillCarry, "knowledge_bindings"},
				{KindPathBindings, SeverityWillCarry, "would have to rewrite"},
			}},
		{name: "an unreadable store is a warning",
			setup: func(e *fakeEnv) { e.pathsErr = errors.New("database is locked") },
			wants: []want{{KindPathBindings, SeverityWarning, "database is locked"}}},
	})
}

func TestPreflightRefusesWhatIsNotAMove(t *testing.T) {
	cases := map[string]struct {
		project Project
		target  string
		is      error
	}{
		"an empty target":       {testProject, "", ErrInvalidTarget},
		"a grant subject":       {testProject, "executor:dev1", ErrInvalidTarget},
		"a malformed pool":      {testProject, "pool:", ErrInvalidTarget},
		"a feature":             {Project{Path: testProject.Path + "/.cloop/features/widget"}, "dev1", ErrFeature},
		"a relative path":       {Project{Path: "srv/app"}, "dev1", ErrInvalidProject},
		"a newline in a target": {testProject, "dev1\nx", ErrInvalidTarget},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Preflight(t.Context(), newEnv(), tc.project, tc.target, Options{})
			if !errors.Is(err, tc.is) {
				t.Fatalf("err = %v, want %v", err, tc.is)
			}
		})
	}
	t.Run("an unknown binding is an error, not a finding", func(t *testing.T) {
		env := newEnv()
		env.bindingErr = errors.New("database is locked")
		if _, err := Preflight(t.Context(), env, testProject, "dev1", Options{}); err == nil {
			t.Fatal("a preflight that cannot say where the project runs must fail")
		}
	})
}

func TestReportShape(t *testing.T) {
	env := newEnv()
	env.tree = dirtyTree()
	env.audience["dev1"] = false
	env.paths = []PathBinding{{Store: "project_members", Count: 1}}
	rep := preflightOf(t, env, "dev1", Options{})

	if rep.Source.Workspace != WorkspaceHubTree || rep.Source.WorkDir != testProject.Path || rep.Source.ExecutorID != "local" {
		t.Errorf("source = %+v, want the hub tree at %s", rep.Source, testProject.Path)
	}
	wantDir := "/var/lib/cloop-executor/work/" + executor.DeviceWorkDir(testProject.Path)
	if rep.Target.Workspace != WorkspaceDevice || rep.Target.WorkDir != wantDir {
		t.Errorf("target = %+v, want the device working copy %s", rep.Target, wantDir)
	}
	if rep.Target.Reachable == nil || !*rep.Target.Reachable {
		t.Errorf("target reachability not recorded: %+v", rep.Target)
	}
	// Blockers first, then warnings, then what is carried.
	last := -1
	for _, f := range rep.Findings {
		if r := f.Severity.rank(); r < last {
			t.Fatalf("findings out of order:\n%s", dump(rep))
		} else {
			last = r
		}
	}
	if !rep.Blocked || rep.Counts.Blockers == 0 || rep.Counts.WillCarry == 0 {
		t.Errorf("counts = %+v blocked=%v", rep.Counts, rep.Blocked)
	}

	// The JSON form is the machine-readable one: stable names, round-trips.
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"blocked":true`, `"severity":"will-carry"`, `"severity":"blocker"`,
		`"kind":"audience"`, `"workspace":"device_working_copy"`, `"counts":{"blockers":1`} {
		if !strings.Contains(string(raw), key) {
			t.Errorf("JSON lacks %s:\n%s", key, raw)
		}
	}
	var back Report
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Findings) != len(rep.Findings) || back.Counts != rep.Counts {
		t.Errorf("JSON round trip lost findings: %d → %d", len(rep.Findings), len(back.Findings))
	}

	text := dump(rep)
	for _, s := range []string{"Move preflight for app", "Blocked: 1 blocker(s)", "✗ [blocker]", "→ [will-carry]", "main.go"} {
		if !strings.Contains(text, s) {
			t.Errorf("text rendering lacks %q:\n%s", s, text)
		}
	}
}

func TestAPreflightStartsNothingAndAsksOnlyTheEndsOfTheMove(t *testing.T) {
	env := newEnv()
	env.binding = "dev2"
	rep := preflightOf(t, env, "dev1", Options{})
	if rep.Blocked {
		t.Fatalf("an idle move between two devices should not be blocked:\n%s", dump(rep))
	}
	asked := strings.Join(env.reachableAsked, ",")
	if asked != "dev1,dev2" && asked != "dev2,dev1" {
		t.Errorf("probed %q, want exactly the target and the source", asked)
	}
	// fakeExec.Start fails loudly; reaching here means nothing started.
}

// deviceTreeOf is what a device's agent reports of a dirty working copy with
// a branch no remote holds.
func deviceTreeOf() *Tree {
	wd := "/var/lib/cloop-executor/work/" + executor.DeviceWorkDir(testProject.Path)
	return &Tree{
		Git: GitState{Dir: wd, Repository: true, Remotes: []string{"origin"},
			Worktrees: []gitstate.Worktree{{Path: wd, Branch: "main", Changed: 1, ChangedPaths: []string{"app.go"},
				Untracked: 1, UntrackedPaths: []string{"draft.md"}}},
			Branches: []gitstate.Branch{{Name: "main", Unpushed: 3}}},
		Files: FileInventory{Dir: wd + "/.cloop", Categories: []FileCategory{{Name: FilesArtifacts, Files: 2, Bytes: 40}}},
	}
}

// TestDeviceSourceFindings (Task 20495): a device's working copy is read over
// the agent protocol, and the findings are the hub tree's, judged against
// where the target keeps its work.
func TestDeviceSourceFindings(t *testing.T) {
	onDev1 := func(e *fakeEnv) {
		e.binding = "dev1"
		e.deviceTree = deviceTreeOf()
	}
	runScenarios(t, []scenario{
		{name: "a device's changes are captured for another device", target: "dev2", setup: onDev1,
			wants: []want{
				{KindWorkingTree, SeverityWillCarry, "1 changed and 1 untracked"},
				{KindLocalCommits, SeverityWillCarry, "3 commit(s)"},
				{KindProjectFiles, SeverityWillCarry, "source's own"},
			},
			none: []Kind{KindSourceUnseen, KindSourceAgent}},
		{name: "a device's changes are captured for the hub's tree", target: "local", setup: onDev1,
			wants: []want{{KindWorkingTree, SeverityWillCarry, "captures these changes"}},
			none:  []Kind{KindTarget}},
		{name: "the hub's directory holding a working copy blocks", target: "local", blocked: true,
			setup: func(e *fakeEnv) { onDev1(e); e.hubEntries = []string{".git", "README.md"} },
			wants: []want{{KindTarget, SeverityBlocker, "already holds 2 entr(ies)"}}},
		// Task 20497: the copy a move left there, untouched, is rebuilt in
		// place; one changed since still blocks, saying what changed.
		{name: "the copy the project left in the hub's directory is rebuilt in place", target: "local",
			setup: func(e *fakeEnv) {
				onDev1(e)
				e.hubEntries = []string{".git", "README.md"}
				e.leftBehind = &LeftBehindCopy{MoveID: "5eedc0de5eedc0de", Target: "dev1"}
			},
			wants: []want{{KindTarget, SeverityWillCarry, "move 5eedc0de5eedc0de captured there"}}},
		{name: "the copy the project left in the hub's directory, changed since, blocks", target: "local", blocked: true,
			setup: func(e *fakeEnv) {
				onDev1(e)
				e.hubEntries = []string{".git", "README.md"}
				e.leftBehind = &LeftBehindCopy{MoveID: "5eedc0de5eedc0de", Target: "dev1", Problems: []string{"files on disk changed"}}
			},
			wants: []want{{KindTarget, SeverityBlocker, "files on disk changed"}}},
		{name: "a Pod would never see a device's changes", target: "k8s", blocked: true, setup: onDev1,
			wants: []want{
				{KindWorkingTree, SeverityBlocker, "from the forge"},
				{KindLocalCommits, SeverityBlocker, "3 commit(s)"},
			}},
		{name: "the device's own virtual executor works in the same copy", target: "vx-hsm", setup: onDev1,
			wants: []want{{KindWorkingTree, SeverityWillCarry, "stay where they are"}}},
		{name: "a device that never ran the project holds nothing", target: "dev2",
			setup: func(e *fakeEnv) { e.binding = "dev1"; e.deviceTree = &Tree{Absent: true} },
			wants: []want{{KindWorkingTree, SeverityWillCarry, "holds no working copy"}},
			none:  []Kind{KindLocalCommits, KindProjectFiles}},
		{name: "an agent too old to capture blocks, naming the upgrade", target: "dev2", blocked: true,
			setup: func(e *fakeEnv) {
				e.binding = "dev1"
				e.upgrade = &AgentUpgradeError{Device: "dev1", Have: 28, Need: 29,
					Message: "Device dev1's agent speaks protocol v28, and the hub needs v29.",
					Remedy:  "Upgrade the agent from the Executors panel."}
			},
			wants: []want{{KindSourceAgent, SeverityBlocker, "Upgrade the agent"}},
			none:  []Kind{KindWorkingTree, KindLocalCommits}},
		{name: "abandoning a device whose agent is too old", target: "dev2", opts: Options{AbandonSource: true},
			setup: func(e *fakeEnv) {
				e.binding = "dev1"
				e.upgrade = &AgentUpgradeError{Device: "dev1", Have: 28, Need: 29, Message: "too old", Remedy: "upgrade"}
			},
			wants: []want{
				{KindSourceAgent, SeverityWarning, "Abandoning the source"},
				{KindAbandoned, SeverityWarning, "loses its working copy"},
			}},
		{name: "a pool that keeps no volumes keeps nothing", target: "dev1",
			setup: func(e *fakeEnv) {
				e.binding = "pool:pool-a"
				e.pools["pool-a"] = PoolFacts{Found: true, Name: "ci", Tenant: "prj-1234", Volumes: VolumesNone}
			},
			wants: []want{{KindWorkingTree, SeverityWillCarry, "keeps nothing between runs"}},
			none:  []Kind{KindSourceUnseen}},
		{name: "a pool's volume is captured through a runner on it", target: "dev1",
			setup: func(e *fakeEnv) {
				e.binding = "pool:pool-a"
				e.pools["pool-a"] = PoolFacts{Found: true, Name: "ci", Tenant: "prj-1234", Volumes: VolumesKept}
			},
			wants: []want{{KindSourceUnseen, SeverityWarning, "asks the pool for a runner"}}},
	})
}

// TestAPoolSourceChecksTheHubsDirectory: where a pool's volume goes is
// checked at the preflight even though what the volume holds is read only
// at the capture.
func TestAPoolSourceChecksTheHubsDirectory(t *testing.T) {
	runScenarios(t, []scenario{
		{name: "an occupied hub directory blocks a pool's move onto the hub", target: "box", blocked: true,
			setup: func(e *fakeEnv) {
				e.binding = "pool:pool-a"
				e.pools["pool-a"] = PoolFacts{Found: true, Name: "ci", Tenant: "prj-1234", Volumes: VolumesKept}
				e.hubEntries = []string{"README.md"}
			},
			wants: []want{{KindTarget, SeverityBlocker, "already holds 1 entr(ies)"}}},
		{name: "an empty hub directory takes a pool's volume", target: "box",
			setup: func(e *fakeEnv) {
				e.binding = "pool:pool-a"
				e.pools["pool-a"] = PoolFacts{Found: true, Name: "ci", Tenant: "prj-1234", Volumes: VolumesKept}
			},
			none: []Kind{KindTarget}},
	})
}

// TestAPoolThatCannotAttachTheVolumeBlocks: a pool whose runners are handed
// nothing, or whose controller cannot start them, cannot give the capture a
// runner on the project's volume.
func TestAPoolThatCannotAttachTheVolumeBlocks(t *testing.T) {
	on := func(pf PoolFacts) func(e *fakeEnv) {
		return func(e *fakeEnv) {
			e.binding = "pool:pool-a"
			pf.Found, pf.Name, pf.Tenant, pf.Volumes = true, "ci", "prj-1234", VolumesKept
			e.pools["pool-a"] = pf
		}
	}
	runScenarios(t, []scenario{
		{name: "a cordoned pool", target: "dev1", blocked: true, setup: on(PoolFacts{Cordoned: true}),
			wants: []want{{KindSourceUnreachable, SeverityBlocker, "cordoned"}}},
		{name: "a controller that cannot start runners", target: "dev1", blocked: true,
			setup: on(PoolFacts{Trouble: "StoragePending: no volume could be bound"}),
			wants: []want{{KindSourceUnreachable, SeverityBlocker, "no volume could be bound"}}},
		{name: "abandoning it goes ahead", target: "dev1", opts: Options{AbandonSource: true},
			setup: on(PoolFacts{Cordoned: true}),
			wants: []want{{KindAbandoned, SeverityWarning, "runner volumes"}}},
	})
}
