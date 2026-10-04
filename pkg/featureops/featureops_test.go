package featureops

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/feature"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// hermeticGit points git at a throwaway home so no test reads the developer's
// own configuration — or, worse, their credential store: the credential tests
// below would otherwise resolve a real token.
func hermeticGit(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(home, ".gitconfig"))
	for _, v := range []string{EnvToken, "GITHUB_TOKEN", "GH_TOKEN", EnvAPIURL, "GIT_CONFIG_COUNT", "CLOOP_HOME"} {
		t.Setenv(v, "")
		os.Unsetenv(v)
	}
	// PATH without gh: its login would otherwise be a token source.
	gitBin, _ := exec.LookPath("git")
	bin := filepath.Join(home, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(gitBin, filepath.Join(bin, "git")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	gitRun(t, home, "config", "--global", "user.email", "test@example.com")
	gitRun(t, home, "config", "--global", "user.name", "Test")
	gitRun(t, home, "config", "--global", "init.defaultBranch", "main")
	return home
}

func gitRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := runGit(context.Background(), dir, args...)
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return out
}

// newProject makes a git repository with one commit, a bare origin it has
// pushed main to, and an initialised cloop state.
func newProject(t *testing.T) (project, origin string) {
	t.Helper()
	hermeticGit(t)
	root := t.TempDir()
	origin = filepath.Join(root, "origin.git")
	project = filepath.Join(root, "proj")
	gitRun(t, root, "init", "-q", "--bare", origin)
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, project, "init", "-q")
	if err := os.WriteFile(filepath.Join(project, "README.md"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, project, "add", "README.md")
	gitRun(t, project, "commit", "-qm", "init")
	gitRun(t, project, "remote", "add", "origin", origin)
	gitRun(t, project, "push", "-q", "origin", "main")

	statedbtest.SeedDir(t, project)
	st, err := state.Init(project, "Parent goal", 0)
	if err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	st.Provider = "mock"
	st.Model = "mock-model"
	st.Effort = "high"
	st.Instructions = "Always write tests."
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, ".cloop", "config.yaml"), []byte("provider: mock\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return project, origin
}

func commitIn(t *testing.T, dir, file, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "add", file)
	gitRun(t, dir, "commit", "-qm", "change "+file)
}

func TestCreate_WorktreeBranchLockStateAndConfig(t *testing.T) {
	project, _ := newProject(t)
	ctx := context.Background()
	info, err := Create(ctx, CreateOptions{
		ProjectDir: project, Name: "Dark mode", Description: "Add a dark theme",
		AutoEvolve: true, Innovate: true, Parallel: true, MaxParallel: 3,
		Tasks:     []string{" CSS variables ", "", "Toggle"},
		AutoPR:    true,
		CreatedBy: "alice@example.com",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	dir := feature.Path(project, "dark-mode")
	if info.Path != dir {
		t.Fatalf("path = %s, want %s", info.Path, dir)
	}
	m := info.Meta
	if m.Slug != "dark-mode" || m.Title != "Dark mode" || m.Branch != "cloop/feature/dark-mode" ||
		m.Base != "main" || m.BaseCommit == "" || m.Parent != project || !m.AutoPR || m.CreatedBy != "alice@example.com" {
		t.Errorf("record = %+v", m)
	}
	if !feature.IsFeature(dir) {
		t.Fatal("the created directory is not recognised as a feature")
	}

	// The worktree is on the branch, cut from main, and locked.
	if head := gitRun(t, dir, "symbolic-ref", "--short", "HEAD"); head != m.Branch {
		t.Errorf("worktree HEAD = %s", head)
	}
	if got, want := gitRun(t, dir, "rev-parse", "HEAD"), gitRun(t, project, "rev-parse", "main"); got != want {
		t.Errorf("feature starts at %s, main is %s", got, want)
	}
	list := gitRun(t, project, "worktree", "list", "--porcelain")
	if !strings.Contains(list, "worktree "+dir) || !strings.Contains(list, "locked cloop feature dark-mode") {
		t.Errorf("worktree not registered and locked:\n%s", list)
	}
	// A plain `git push` from the worktree publishes the feature under its
	// own name.
	if r := gitRun(t, project, "config", "branch.cloop/feature/dark-mode.remote"); r != "origin" {
		t.Errorf("branch remote = %q", r)
	}
	if r := gitRun(t, project, "config", "branch.cloop/feature/dark-mode.merge"); r != "refs/heads/cloop/feature/dark-mode" {
		t.Errorf("branch merge = %q", r)
	}

	// Its own state: the parent's provider settings, its own run settings,
	// its own plan, and the note about where it is working.
	st, err := state.Load(dir)
	if err != nil {
		t.Fatalf("load feature state: %v", err)
	}
	if st.Goal != "Add a dark theme" || st.Provider != "mock" || st.Model != "mock-model" || st.Effort != "high" {
		t.Errorf("inherited settings wrong: goal=%q provider=%q model=%q effort=%q", st.Goal, st.Provider, st.Model, st.Effort)
	}
	if !st.AutoEvolve || !st.InnovateMode || !st.Parallel || st.MaxParallel != 3 || !st.PMMode {
		t.Errorf("run settings wrong: %+v", st)
	}
	if st.Plan == nil || len(st.Plan.Tasks) != 2 || st.Plan.Tasks[0].Title != "CSS variables" ||
		st.Plan.Tasks[1].Title != "Toggle" || st.Plan.Tasks[1].ID != 2 || st.Plan.Tasks[0].Status != pm.TaskPending {
		t.Errorf("plan = %+v", st.Plan)
	}
	if !strings.HasPrefix(st.Instructions, "Always write tests.") ||
		!strings.Contains(st.Instructions, "branch `cloop/feature/dark-mode`") ||
		!strings.Contains(st.Instructions, "never merge into or push to `main`") {
		t.Errorf("instructions = %q", st.Instructions)
	}

	// The parent is untouched: its own plan and settings are unchanged.
	parent, err := state.Load(project)
	if err != nil {
		t.Fatal(err)
	}
	if parent.AutoEvolve || parent.InnovateMode || parent.Goal != "Parent goal" {
		t.Errorf("creating a feature changed the parent: %+v", parent)
	}

	// The parent's config was copied, with its mode.
	fi, err := os.Stat(filepath.Join(dir, ".cloop", "config.yaml"))
	if err != nil {
		t.Fatalf("config not copied: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("config mode = %v", fi.Mode().Perm())
	}

	// Neither the parent nor the feature sees cloop's state as a change.
	if out := gitRun(t, project, "status", "--porcelain"); out != "" {
		t.Errorf("parent is dirty after creating a feature:\n%s", out)
	}
	if out := gitRun(t, dir, "status", "--porcelain"); out != "" {
		t.Errorf("feature is dirty after creation:\n%s", out)
	}
	exclude, _ := os.ReadFile(filepath.Join(project, ".git", "info", "exclude"))
	if !strings.Contains(string(exclude), "\n/.cloop/\n") {
		t.Errorf("exclude file lacks /.cloop/:\n%s", exclude)
	}

	// A second feature does not add the exclude line again.
	if _, err := Create(ctx, CreateOptions{ProjectDir: project, Name: "login"}); err != nil {
		t.Fatal(err)
	}
	exclude2, _ := os.ReadFile(filepath.Join(project, ".git", "info", "exclude"))
	if strings.Count(string(exclude2), "/.cloop/") != 1 {
		t.Errorf("exclude line duplicated:\n%s", exclude2)
	}
	infos, err := feature.List(project)
	if err != nil || len(infos) != 2 {
		t.Fatalf("List = %v, %v", infos, err)
	}
}

func TestCreate_Refusals(t *testing.T) {
	project, _ := newProject(t)
	ctx := context.Background()
	if _, err := Create(ctx, CreateOptions{ProjectDir: project, Name: "x"}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		opts CreateOptions
		want error
		msg  string
	}{
		{"duplicate", CreateOptions{ProjectDir: project, Name: "x"}, ErrExists, "already present"},
		{"nested", CreateOptions{ProjectDir: feature.Path(project, "x"), Name: "y"}, ErrNested, ""},
		{"empty name", CreateOptions{ProjectDir: project, Name: "!!!"}, nil, "cannot name a feature"},
		{"bad slug", CreateOptions{ProjectDir: project, Slug: "Bad Slug"}, nil, "lowercase"},
		{"relative", CreateOptions{ProjectDir: "proj", Name: "z"}, nil, "not absolute"},
		{"missing base", CreateOptions{ProjectDir: project, Name: "z", Base: "nope"}, nil, "exists neither locally"},
		{"feature base", CreateOptions{ProjectDir: project, Name: "z", Base: "cloop/feature/x"}, nil, "itself a feature branch"},
		{"option base", CreateOptions{ProjectDir: project, Name: "z", Base: "-f"}, nil, "dash"},
		{"negative parallel", CreateOptions{ProjectDir: project, Name: "z", MaxParallel: -1}, nil, "negative"},
		{"subdirectory", CreateOptions{ProjectDir: filepath.Join(project, "sub"), Name: "z"}, nil, "top of its git repository"},
		{"not a repo", CreateOptions{ProjectDir: t.TempDir(), Name: "z"}, nil, "not a git repository"},
		{"too many tasks", CreateOptions{ProjectDir: project, Name: "z", Tasks: make200()}, nil, "more than"},
	}
	if err := os.MkdirAll(filepath.Join(project, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Create(ctx, c.opts)
			if err == nil {
				t.Fatal("Create succeeded")
			}
			if c.want != nil && !errors.Is(err, c.want) {
				t.Errorf("err = %v, want %v", err, c.want)
			}
			if c.msg != "" && !strings.Contains(err.Error(), c.msg) {
				t.Errorf("err = %v, want it to mention %q", err, c.msg)
			}
		})
	}

	// A branch left behind by a removed feature blocks its name.
	gitRun(t, project, "branch", "cloop/feature/taken")
	if _, err := Create(ctx, CreateOptions{ProjectDir: project, Name: "taken"}); !errors.Is(err, ErrExists) {
		t.Errorf("existing branch: err = %v", err)
	}
	// None of the refused creations left anything behind.
	infos, _ := feature.List(project)
	if len(infos) != 1 {
		t.Errorf("refusals left features behind: %v", infos)
	}
	if out := gitRun(t, project, "branch", "--list", "cloop/feature/z"); out != "" {
		t.Errorf("a refused creation left branch %q", out)
	}
}

func make200() []string {
	out := make([]string, maxTasks+1)
	for i := range out {
		out[i] = "t"
	}
	return out
}

func TestCreate_RollsBackWhenSeedingFails(t *testing.T) {
	project, _ := newProject(t)
	// A directory where the feature's config.yaml would be copied to makes
	// the copy fail after the worktree already exists.
	orig := controlFiles
	t.Cleanup(func() { controlFiles = orig })
	controlFiles = append(controlFiles, struct {
		name string
		mode os.FileMode
	}{"nested/impossible.yaml", 0o600})
	if err := os.MkdirAll(filepath.Join(project, ".cloop", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, ".cloop", "nested", "impossible.yaml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Create(context.Background(), CreateOptions{ProjectDir: project, Name: "doomed"}); err == nil {
		t.Fatal("Create succeeded although copying a control file must fail")
	}
	if _, err := os.Stat(feature.Path(project, "doomed")); !os.IsNotExist(err) {
		t.Errorf("worktree directory left behind: %v", err)
	}
	if out := gitRun(t, project, "branch", "--list", "cloop/feature/doomed"); out != "" {
		t.Errorf("branch left behind: %q", out)
	}
	if list := gitRun(t, project, "worktree", "list"); strings.Contains(list, "doomed") {
		t.Errorf("worktree still registered:\n%s", list)
	}
	// And the name is free again once the cause is gone.
	controlFiles = orig
	if _, err := Create(context.Background(), CreateOptions{ProjectDir: project, Name: "doomed"}); err != nil {
		t.Fatalf("retry after rollback: %v", err)
	}
}

func TestDefaultBase(t *testing.T) {
	project, _ := newProject(t)
	ctx := context.Background()
	if b, err := DefaultBase(ctx, project); err != nil || b != "main" {
		t.Errorf("DefaultBase = %q, %v; want main", b, err)
	}
	// origin/HEAD wins over the conventional names.
	gitRun(t, project, "branch", "develop")
	gitRun(t, project, "push", "-q", "origin", "develop")
	gitRun(t, project, "fetch", "-q", "origin")
	gitRun(t, project, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/develop")
	if b, err := DefaultBase(ctx, project); err != nil || b != "develop" {
		t.Errorf("DefaultBase with origin/HEAD = %q, %v; want develop", b, err)
	}
	info, err := Create(ctx, CreateOptions{ProjectDir: project, Name: "f"})
	if err != nil {
		t.Fatal(err)
	}
	if info.Meta.Base != "develop" {
		t.Errorf("feature base = %s", info.Meta.Base)
	}
}

func TestRemove(t *testing.T) {
	project, _ := newProject(t)
	ctx := context.Background()
	info, err := Create(ctx, CreateOptions{ProjectDir: project, Name: "work"})
	if err != nil {
		t.Fatal(err)
	}
	dir := info.Path
	commitIn(t, dir, "a.txt", "committed\n")
	if err := os.WriteFile(filepath.Join(dir, "scratch.txt"), []byte("not committed"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Uncommitted work refuses the removal, naming the file.
	_, err = Remove(ctx, RemoveOptions{ProjectDir: project, Slug: "work"})
	var dirty *DirtyError
	if !errors.As(err, &dirty) || !strings.Contains(err.Error(), "scratch.txt") {
		t.Fatalf("dirty removal: err = %v", err)
	}
	if !feature.IsFeature(dir) {
		t.Fatal("a refused removal touched the feature")
	}
	if list := gitRun(t, project, "worktree", "list", "--porcelain"); !strings.Contains(list, "locked") {
		t.Errorf("a refused removal left the worktree unlocked:\n%s", list)
	}

	// Committing makes it removable; the unmerged branch survives a plain
	// delete request.
	gitRun(t, dir, "add", "scratch.txt")
	gitRun(t, dir, "commit", "-qm", "scratch")
	res, err := Remove(ctx, RemoveOptions{ProjectDir: project, Slug: "work", DeleteBranch: true})
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if res.BranchDeleted || res.BranchKept == "" {
		t.Errorf("an unmerged branch was deleted, or no reason was given: %+v", res)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("worktree still on disk: %v", err)
	}
	if out := gitRun(t, project, "branch", "--list", "cloop/feature/work"); out == "" {
		t.Error("the unmerged branch — the only copy of the work — is gone")
	}

	// A merged feature's branch is deleted when asked.
	merged, err := Create(ctx, CreateOptions{ProjectDir: project, Name: "merged"})
	if err != nil {
		t.Fatal(err)
	}
	commitIn(t, merged.Path, "m.txt", "m\n")
	gitRun(t, project, "merge", "-q", "--ff-only", "cloop/feature/merged")
	res, err = Remove(ctx, RemoveOptions{ProjectDir: project, Slug: "merged", DeleteBranch: true})
	if err != nil || !res.BranchDeleted {
		t.Fatalf("merged removal: %+v, %v", res, err)
	}
	if out, _ := runGit(ctx, project, "config", "--get", "branch.cloop/feature/merged.remote"); out != "" {
		t.Errorf("branch config left behind: %q", out)
	}

	// Force discards uncommitted work and deletes an unmerged branch.
	forced, err := Create(ctx, CreateOptions{ProjectDir: project, Name: "forced"})
	if err != nil {
		t.Fatal(err)
	}
	commitIn(t, forced.Path, "f.txt", "f\n")
	if err := os.WriteFile(filepath.Join(forced.Path, "junk"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err = Remove(ctx, RemoveOptions{ProjectDir: project, Slug: "forced", DeleteBranch: true, Force: true})
	if err != nil || !res.BranchDeleted {
		t.Fatalf("forced removal: %+v, %v", res, err)
	}

	if _, err := Remove(ctx, RemoveOptions{ProjectDir: project, Slug: "never-existed"}); err == nil {
		t.Error("removing a feature that never existed succeeded")
	}
}

// fakeGitHub is the slice of the GitHub REST API that OpenPR uses.
type fakeGitHub struct {
	mu      sync.Mutex
	token   string
	prs     map[int]map[string]any
	next    int
	creates []map[string]any
	// refuseCreate answers every create with this status when set.
	refuseCreate int
}

func newFakeGitHub(t *testing.T, token string) (*fakeGitHub, *httptest.Server) {
	f := &fakeGitHub{token: token, prs: map[int]map[string]any{}, next: 41}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
		return
	}
	const prefix = "/repos/acme/app/pulls"
	switch {
	case r.Method == http.MethodPost && r.URL.Path == prefix:
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.creates = append(f.creates, body)
		if f.refuseCreate != 0 {
			w.WriteHeader(f.refuseCreate)
			_, _ = io.WriteString(w, `{"message":"Validation Failed","errors":[{"message":"A pull request already exists for acme:`+body["head"].(string)+`."}]}`)
			return
		}
		f.next++
		pr := map[string]any{
			"number": f.next, "state": "open", "draft": body["draft"],
			"html_url": "https://github.com/acme/app/pull/" + itoa(f.next),
			"head":     map[string]any{"ref": body["head"]},
			"base":     map[string]any{"ref": body["base"]},
		}
		f.prs[f.next] = pr
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(pr)
	case r.Method == http.MethodGet && r.URL.Path == prefix:
		head := r.URL.Query().Get("head")
		var out []map[string]any
		for _, pr := range f.prs {
			if "acme:"+pr["head"].(map[string]any)["ref"].(string) == head && pr["state"] == "open" {
				out = append(out, pr)
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, prefix+"/"):
		n := atoi(strings.TrimPrefix(r.URL.Path, prefix+"/"))
		pr, ok := f.prs[n]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(pr)
	default:
		http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusTeapot)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func TestOpenPR_PushesCreatesAndIsIdempotent(t *testing.T) {
	project, origin := newProject(t)
	ctx := context.Background()
	info, err := Create(ctx, CreateOptions{ProjectDir: project, Name: "Login", Description: "Users can sign in.",
		Tasks: []string{"Form", "Hashing"}})
	if err != nil {
		t.Fatal(err)
	}
	dir := info.Path

	// Nothing committed yet: nothing to propose.
	gh, srv := newFakeGitHub(t, "s3cret")
	opts := PROptions{FeatureDir: dir, Token: "s3cret", Repo: "acme/app", APIURL: srv.URL,
		Now: func() time.Time { return time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC) }}
	if _, err := OpenPR(ctx, opts); !errors.Is(err, ErrNothingToPropose) {
		t.Fatalf("empty feature: err = %v", err)
	}

	// Complete a task and commit, as a harness would.
	st, _ := state.Load(dir)
	st.Plan.Tasks[0].Status = pm.TaskDone
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	commitIn(t, dir, "login.go", "package login\n")

	res, err := OpenPR(ctx, opts)
	if err != nil {
		t.Fatalf("OpenPR: %v", err)
	}
	if !res.Pushed || res.Existing || res.Ahead != 1 || res.TokenSource != "flag" {
		t.Errorf("result = %+v", res)
	}
	if res.PR == nil || res.PR.Number != 42 || res.PR.State != "open" || res.PR.Head != "cloop/feature/login" ||
		res.PR.Base != "main" || res.PR.Repo != "acme/app" || res.PR.HeadSHA == "" {
		t.Errorf("PR = %+v", res.PR)
	}
	// The branch really reached origin, at the commit the PR records.
	if sha := gitRun(t, origin, "rev-parse", "refs/heads/cloop/feature/login"); sha != res.PR.HeadSHA {
		t.Errorf("origin has %s, PR records %s", sha, res.PR.HeadSHA)
	}
	if len(gh.creates) != 1 {
		t.Fatalf("creates = %d", len(gh.creates))
	}
	c := gh.creates[0]
	if c["head"] != "cloop/feature/login" || c["base"] != "main" || c["title"] != "Login" {
		t.Errorf("create request = %v", c)
	}
	body, _ := c["body"].(string)
	if !strings.Contains(body, "Users can sign in.") || !strings.Contains(body, "- [x] #1 Form") ||
		!strings.Contains(body, "- [ ] #2 Hashing") {
		t.Errorf("PR body:\n%s", body)
	}
	// Recorded on the feature.
	m, _ := feature.LoadMeta(dir)
	if m.PR == nil || m.PR.Number != 42 || m.PR.URL == "" {
		t.Errorf("record = %+v", m.PR)
	}

	// Asked again after another commit: pushes, returns the same PR, creates
	// nothing new.
	commitIn(t, dir, "more.go", "package login\n")
	res2, err := OpenPR(ctx, opts)
	if err != nil {
		t.Fatalf("second OpenPR: %v", err)
	}
	if !res2.Existing || res2.PR.Number != 42 || res2.Ahead != 2 || len(gh.creates) != 1 {
		t.Errorf("second call = %+v, creates = %d", res2, len(gh.creates))
	}
	if sha := gitRun(t, origin, "rev-parse", "refs/heads/cloop/feature/login"); sha != gitRun(t, dir, "rev-parse", "HEAD") {
		t.Error("the second call did not push the new commit")
	}
	if !res2.PR.CreatedAt.Equal(res.PR.CreatedAt) {
		t.Error("re-reporting an existing PR changed when it was opened")
	}

	// RefreshPR picks up a merge.
	gh.mu.Lock()
	gh.prs[42]["state"] = "closed"
	gh.prs[42]["merged"] = true
	gh.mu.Unlock()
	pr, err := RefreshPR(ctx, dir, "s3cret", srv.URL)
	if err != nil || pr.State != "merged" {
		t.Fatalf("RefreshPR = %+v, %v", pr, err)
	}
	if m, _ := feature.LoadMeta(dir); m.PR.State != "merged" {
		t.Errorf("merged state not recorded: %+v", m.PR)
	}

	// Merged with nothing new: reported, not proposed a second time.
	res3, err := OpenPR(ctx, opts)
	if err != nil || !res3.Existing || res3.PR.Number != 42 || res3.PR.State != "merged" || len(gh.creates) != 1 {
		t.Fatalf("merged, nothing new: %+v, %v (creates %d)", res3, err, len(gh.creates))
	}
	// New work after the merge is a new pull request.
	commitIn(t, dir, "followup.go", "package login\n")
	res4, err := OpenPR(ctx, opts)
	if err != nil || res4.Existing || res4.PR.Number != 43 || len(gh.creates) != 2 {
		t.Fatalf("follow-up after merge: %+v, %v (creates %d)", res4, err, len(gh.creates))
	}
}

func TestOpenPR_FindsExistingOnConflict(t *testing.T) {
	project, _ := newProject(t)
	ctx := context.Background()
	info, err := Create(ctx, CreateOptions{ProjectDir: project, Name: "x"})
	if err != nil {
		t.Fatal(err)
	}
	commitIn(t, info.Path, "x.txt", "x\n")
	gh, srv := newFakeGitHub(t, "tok")
	// A PR someone opened by hand, before cloop's record existed.
	gh.prs[7] = map[string]any{"number": 7, "state": "open", "html_url": "https://github.com/acme/app/pull/7",
		"head": map[string]any{"ref": "cloop/feature/x"}, "base": map[string]any{"ref": "main"}}
	gh.refuseCreate = http.StatusUnprocessableEntity

	res, err := OpenPR(ctx, PROptions{FeatureDir: info.Path, Token: "tok", Repo: "acme/app", APIURL: srv.URL})
	if err != nil {
		t.Fatalf("OpenPR: %v", err)
	}
	if !res.Existing || res.PR.Number != 7 {
		t.Errorf("result = %+v", res)
	}
}

// githubOrigin points the project's origin at a GitHub URL that git rewrites
// to the local bare repository, so the forge's identity is github.com — which
// ambient tokens may be sent to — while every push stays on this machine.
func githubOrigin(t *testing.T, project, origin string) {
	t.Helper()
	gitRun(t, project, "remote", "set-url", "origin", "https://github.com/acme/app.git")
	gitRun(t, project, "config", "url."+origin+".insteadOf", "https://github.com/acme/app.git")
}

func TestOpenPR_TokenProblems(t *testing.T) {
	project, origin := newProject(t)
	githubOrigin(t, project, origin)
	ctx := context.Background()
	info, err := Create(ctx, CreateOptions{ProjectDir: project, Name: "y"})
	if err != nil {
		t.Fatal(err)
	}
	commitIn(t, info.Path, "y.txt", "y\n")
	_, srv := newFakeGitHub(t, "right")

	// No token anywhere: the branch is pushed, the PR is not opened, and the
	// error says so.
	res, err := OpenPR(ctx, PROptions{FeatureDir: info.Path, APIURL: srv.URL})
	if !errors.Is(err, ErrNoToken) || res == nil || !res.Pushed {
		t.Fatalf("no token: res=%+v err=%v", res, err)
	}
	if _, gerr := runGit(ctx, origin, "rev-parse", "--verify", "refs/heads/cloop/feature/y"); gerr != nil {
		t.Error("the branch was not pushed although only the API step needed a token")
	}

	// A token the API refuses is reported with where it came from.
	t.Setenv("GITHUB_TOKEN", "wrong")
	_, err = OpenPR(ctx, PROptions{FeatureDir: info.Path, APIURL: srv.URL})
	if err == nil || !strings.Contains(err.Error(), "GITHUB_TOKEN") || !strings.Contains(err.Error(), "401") {
		t.Errorf("refused token: err = %v", err)
	}
}

func TestOpenPR_RefusesAWorktreeOffItsBranch(t *testing.T) {
	project, _ := newProject(t)
	ctx := context.Background()
	info, err := Create(ctx, CreateOptions{ProjectDir: project, Name: "z"})
	if err != nil {
		t.Fatal(err)
	}
	commitIn(t, info.Path, "z.txt", "z\n")
	gitRun(t, info.Path, "checkout", "-q", "-b", "elsewhere")
	if _, err := OpenPR(ctx, PROptions{FeatureDir: info.Path, Token: "t", Repo: "acme/app", APIURL: "http://127.0.0.1:1"}); err == nil ||
		!strings.Contains(err.Error(), "not on its branch") {
		t.Errorf("err = %v", err)
	}
}

func TestResolveToken_Precedence(t *testing.T) {
	home := hermeticGit(t)
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q")
	gh := Remote{Host: "github.com", Repo: "acme/app", HTTPS: true}
	ctx := context.Background()

	if tok, src := ResolveToken(ctx, dir, gh, "", ""); tok != "" || src != "" {
		t.Fatalf("hermetic home resolved %q from %q", tok, src)
	}

	// The hub's hand-over is the last resort.
	t.Setenv(EnvToken, "from-hub")
	if tok, src := ResolveToken(ctx, dir, gh, "", ""); tok != "from-hub" || src != EnvToken {
		t.Errorf("hub token: %q from %q", tok, src)
	}
	// git's credential store for the host beats it.
	store := filepath.Join(home, "creds")
	if err := os.WriteFile(store, []byte("https://bot:from-store@github.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitRun(t, home, "config", "--global", "credential.helper", "store --file="+store)
	if tok, src := ResolveToken(ctx, dir, gh, "", ""); tok != "from-store" || src != "git credential helper" {
		t.Errorf("credential store: %q from %q", tok, src)
	}
	// The project's config beats the store.
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"), []byte("github:\n  token: from-config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if tok, src := ResolveToken(ctx, dir, gh, "", ""); tok != "from-config" || src != "config github.token" {
		t.Errorf("config: %q from %q", tok, src)
	}
	t.Setenv("GH_TOKEN", "from-gh-env")
	if tok, src := ResolveToken(ctx, dir, gh, "", ""); tok != "from-gh-env" || src != "GH_TOKEN" {
		t.Errorf("GH_TOKEN: %q from %q", tok, src)
	}
	t.Setenv("GITHUB_TOKEN", "from-github-env")
	if tok, src := ResolveToken(ctx, dir, gh, "", ""); tok != "from-github-env" || src != "GITHUB_TOKEN" {
		t.Errorf("GITHUB_TOKEN: %q from %q", tok, src)
	}
	if tok, src := ResolveToken(ctx, dir, gh, " explicit ", ""); tok != "explicit" || src != "flag" {
		t.Errorf("explicit: %q from %q", tok, src)
	}

	// None of the ambient GitHub tokens go to a host that is not GitHub's.
	gitlab := Remote{Host: "gitlab.com", Repo: "acme/app", HTTPS: true}
	if tok, src := ResolveToken(ctx, dir, gitlab, "", ""); tok != "" {
		t.Errorf("a GitHub token was offered to gitlab.com: %q from %q", tok, src)
	}
	// A credential git itself holds for that host is that host's to use.
	if err := os.WriteFile(store, []byte("https://bot:gitlab-own@gitlab.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if tok, src := ResolveToken(ctx, dir, gitlab, "", ""); tok != "gitlab-own" || src != "git credential helper" {
		t.Errorf("gitlab's own credential: %q from %q", tok, src)
	}
	// And a GitHub Enterprise host named as the API endpoint is GitHub's.
	ghe := Remote{Host: "ghe.corp.example", Repo: "acme/app", HTTPS: true}
	if tok, src := ResolveToken(ctx, dir, ghe, "", "https://ghe.corp.example/api/v3"); tok != "from-github-env" || src != "GITHUB_TOKEN" {
		t.Errorf("configured GHE host: %q from %q", tok, src)
	}
}

func TestTokenMayReach(t *testing.T) {
	cases := []struct {
		host, override string
		want           bool
	}{
		{"github.com", "", true},
		{"GitHub.com", "", true},
		{"gitlab.com", "", false},
		{"github.com.evil.example", "", false},
		{"ghe.corp", "https://ghe.corp/api/v3", true},
		{"ghe.corp", "https://other.corp/api/v3", false},
		{"", "https://x/api/v3", false},
	}
	for _, c := range cases {
		if got := tokenMayReach(c.host, c.override); got != c.want {
			t.Errorf("tokenMayReach(%q, %q) = %v", c.host, c.override, got)
		}
	}
}

func TestParseRemote(t *testing.T) {
	cases := []struct {
		in    string
		host  string
		repo  string
		https bool
		ok    bool
	}{
		{"https://github.com/acme/app.git", "github.com", "acme/app", true, true},
		{"https://x-access-token:tok@github.com/acme/app", "github.com", "acme/app", true, true},
		{"git@github.com:acme/app.git", "github.com", "acme/app", false, true},
		{"ssh://git@GitHub.com:22/acme/app.git", "github.com", "acme/app", false, true},
		{"https://ghe.corp/acme/app/", "ghe.corp", "acme/app", true, true},
		{"/srv/git/app.git", "", "", false, false},
		{"file:///srv/git/app.git", "", "", false, false},
		{"https://github.com/acme", "", "", false, false},
		{"https://github.com/a/b/c", "", "", false, false},
		{"", "", "", false, false},
		// Malformed inputs that once indexed past the host.
		{"host:o/re@po", "", "", false, false},
		{"user:pw@host:o/r", "", "", false, false},
	}
	for _, c := range cases {
		r, err := ParseRemote(c.in)
		if (err == nil) != c.ok {
			t.Errorf("ParseRemote(%q) err = %v, want ok=%v", c.in, err, c.ok)
			continue
		}
		if c.ok && (r.Host != c.host || r.Repo != c.repo || r.HTTPS != c.https) {
			t.Errorf("ParseRemote(%q) = %+v", c.in, r)
		}
	}
	if APIBaseURL("github.com") != "https://api.github.com" || APIBaseURL("ghe.corp") != "https://ghe.corp/api/v3" {
		t.Error("APIBaseURL")
	}
	// Credentials in a remote never reach an error message.
	for _, in := range []string{"https://user:s3cret@gitlab.com/a/b/c", "user:s3cret@host:o/r", "ftp://u:s3cret@h/x"} {
		if _, err := ParseRemote(in); err == nil || strings.Contains(err.Error(), "s3cret") {
			t.Errorf("ParseRemote(%q) error = %v", in, err)
		}
	}
}

func TestAppendGitConfigEnv(t *testing.T) {
	got := appendGitConfigEnv("", "k", "v")
	if strings.Join(got, "|") != "GIT_CONFIG_COUNT=1|GIT_CONFIG_KEY_0=k|GIT_CONFIG_VALUE_0=v" {
		t.Errorf("fresh = %v", got)
	}
	// Entries the environment already carries keep their slots.
	got = appendGitConfigEnv("2", "k", "v")
	if strings.Join(got, "|") != "GIT_CONFIG_COUNT=3|GIT_CONFIG_KEY_2=k|GIT_CONFIG_VALUE_2=v" {
		t.Errorf("existing = %v", got)
	}
	if got := appendGitConfigEnv("garbage", "k", "v"); got[0] != "GIT_CONFIG_COUNT=1" {
		t.Errorf("garbage count = %v", got)
	}
}

func TestRedactArgs(t *testing.T) {
	args := []string{"-c", "http.https://github.com/.extraheader=AUTHORIZATION: basic c2VjcmV0", "push"}
	out := strings.Join(redactArgs(args), " ")
	if strings.Contains(out, "c2VjcmV0") || !strings.Contains(out, "<redacted>") {
		t.Errorf("redactArgs = %s", out)
	}
}

func TestStatus(t *testing.T) {
	project, _ := newProject(t)
	ctx := context.Background()
	info, err := Create(ctx, CreateOptions{ProjectDir: project, Name: "s"})
	if err != nil {
		t.Fatal(err)
	}
	commitIn(t, info.Path, "a", "a")
	commitIn(t, info.Path, "b", "b")
	commitIn(t, project, "main-only", "m")
	if err := os.WriteFile(filepath.Join(info.Path, "dirty"), []byte("d"), 0o644); err != nil {
		t.Fatal(err)
	}
	st := Status(ctx, *info)
	if st.Ahead != 2 || st.Behind != 1 || st.Dirty != 1 || !st.OnBranch || st.Error != "" || st.Head == "" {
		t.Errorf("Status = %+v", st)
	}
}

// TestCreate_RepositoryThatCommitsItsControlDir covers a repository with
// .cloop/ committed — the cloop-hello-world test repository has its state.db
// and config.yaml in history. The feature's own state database overwrites the
// committed one in the worktree, and must not show up as a change or be
// committed onto the feature's branch.
func TestCreate_RepositoryThatCommitsItsControlDir(t *testing.T) {
	project, _ := newProject(t)
	ctx := context.Background()
	// Commit the parent's .cloop, as that repository did.
	gitRun(t, project, "add", "-f", ".cloop/state.db", ".cloop/config.yaml")
	gitRun(t, project, "commit", "-qm", "commit cloop state")

	info, err := Create(ctx, CreateOptions{ProjectDir: project, Name: "tracked"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	st, err := state.Load(info.Path)
	if err != nil || st.Goal != "tracked" {
		t.Fatalf("the feature's own state was not written over the committed one: %v %+v", err, st)
	}
	if out := gitRun(t, info.Path, "status", "--porcelain"); out != "" {
		t.Errorf("the feature's state shows as a change:\n%s", out)
	}
	// A harness's reflexive `git add -A` commits its work and nothing of cloop's.
	commitIn(t, info.Path, "work.txt", "work\n")
	gitRun(t, info.Path, "add", "-A")
	if out, _ := runGit(ctx, info.Path, "diff", "--cached", "--name-only"); out != "" {
		t.Errorf("git add -A staged cloop state: %s", out)
	}
	if files := gitRun(t, info.Path, "diff", "--name-only", info.Meta.Base+"..HEAD"); files != "work.txt" {
		t.Errorf("the feature's branch carries %q, want only work.txt", files)
	}
	if st := Status(ctx, *info); st.Dirty != 0 {
		t.Errorf("Status reports %d dirty files", st.Dirty)
	}
	// And the project's own checkout is unaffected.
	if out := gitRun(t, project, "ls-files", "-v", ".cloop/state.db"); !strings.HasPrefix(out, "H ") {
		t.Errorf("the project's index flag changed: %q", out)
	}
}

// TestRemove_RefusesToLoseWorkItCannotSee covers work a plain status check
// misses: commits on a detached HEAD, which only the worktree's own reflog
// holds, and a parallel run's task worktrees under the feature's .cloop/.
func TestRemove_RefusesToLoseWorkItCannotSee(t *testing.T) {
	project, _ := newProject(t)
	ctx := context.Background()

	detached, err := Create(ctx, CreateOptions{ProjectDir: project, Name: "detached"})
	if err != nil {
		t.Fatal(err)
	}
	gitRun(t, detached.Path, "checkout", "-q", "--detach")
	commitIn(t, detached.Path, "orphan.txt", "only here\n")
	if _, err := Remove(ctx, RemoveOptions{ProjectDir: project, Slug: "detached"}); err == nil ||
		!strings.Contains(err.Error(), "detached") {
		t.Fatalf("removing a feature with commits on a detached HEAD: %v", err)
	}
	if _, err := Remove(ctx, RemoveOptions{ProjectDir: project, Slug: "detached", Force: true}); err != nil {
		t.Fatalf("forced: %v", err)
	}

	nested, err := Create(ctx, CreateOptions{ProjectDir: project, Name: "nested"})
	if err != nil {
		t.Fatal(err)
	}
	task := filepath.Join(nested.Path, ".cloop", "worktrees", "task-1")
	gitRun(t, nested.Path, "worktree", "add", "-q", "-b", "cloop/feature-task/nested/1-x", task)
	if err := os.WriteFile(filepath.Join(task, "wip.txt"), []byte("uncommitted"), 0o644); err != nil {
		t.Fatal(err)
	}
	var dirty *DirtyError
	if _, err := Remove(ctx, RemoveOptions{ProjectDir: project, Slug: "nested"}); !errors.As(err, &dirty) ||
		!strings.Contains(err.Error(), "task worktree") {
		t.Fatalf("removing a feature with a task worktree under it: %v", err)
	}
	if _, err := Remove(ctx, RemoveOptions{ProjectDir: project, Slug: "nested", Force: true}); err != nil {
		t.Fatalf("forced: %v", err)
	}
	if list := gitRun(t, project, "worktree", "list"); strings.Contains(list, "task-1") || strings.Contains(list, "nested") {
		t.Errorf("worktree records left behind:\n%s", list)
	}
}

// TestRemove_DeleteBranchMeansMergedIntoTheBase: a pushed feature's upstream
// is its own remote copy, so `git branch -d` would call it merged. Merged
// means merged into the base.
func TestRemove_DeleteBranchMeansMergedIntoTheBase(t *testing.T) {
	project, _ := newProject(t)
	ctx := context.Background()
	info, err := Create(ctx, CreateOptions{ProjectDir: project, Name: "pushed"})
	if err != nil {
		t.Fatal(err)
	}
	commitIn(t, info.Path, "p.txt", "p\n")
	gitRun(t, info.Path, "push", "-q") // upstream is origin/cloop/feature/pushed
	res, err := Remove(ctx, RemoveOptions{ProjectDir: project, Slug: "pushed", DeleteBranch: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.BranchDeleted || !strings.Contains(res.BranchKept, "not merged into main") {
		t.Errorf("a pushed, unmerged branch: %+v", res)
	}
	if out := gitRun(t, project, "branch", "--list", "cloop/feature/pushed"); out == "" {
		t.Error("the branch is gone")
	}
}
