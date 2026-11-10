package agent

// Task 20484: an agent whose workloads' trees live on a persistent volume —
// an executor pool runner's — keeps them there, and keeps every credential,
// every payload home and its own scratch off it.

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/executorpool"
)

func TestStorageRootsRefuseALayoutThatPutsACredentialOnTheVolume(t *testing.T) {
	base := t.TempDir()
	vol := filepath.Join(base, "volume")
	scratch := filepath.Join(base, "scratch")
	mem := filepath.Join(base, "mem")
	for name, c := range map[string]Config{
		"a home on the volume":         {WorkDirRoot: scratch, WorkspaceRoot: vol, HomeRoot: filepath.Join(vol, "homes")},
		"a secret dir on the volume":   {WorkDirRoot: scratch, WorkspaceRoot: vol, HomeRoot: mem, SecretDir: filepath.Join(vol, "s")},
		"the volume inside a home":     {WorkDirRoot: scratch, WorkspaceRoot: filepath.Join(mem, "vol"), HomeRoot: mem},
		"the volume inside scratch":    {WorkDirRoot: scratch, WorkspaceRoot: filepath.Join(scratch, "vol"), HomeRoot: mem},
		"scratch inside the volume":    {WorkDirRoot: filepath.Join(vol, "scratch"), WorkspaceRoot: vol, HomeRoot: mem},
		"an ephemeral runner, no home": {WorkDirRoot: scratch, WorkspaceRoot: vol, Ephemeral: true, Token: testRunnerToken},
	} {
		c.Server = "wss://hub.invalid/api/executors/connect"
		if c.Token == "" {
			c.Token = "clet1.id.secret.mac"
		}
		c.CredentialPath = filepath.Join(t.TempDir(), "agent.json")
		if _, err := New(c); err == nil {
			t.Errorf("%s: New accepted it", name)
		}
	}
}

func TestPayloadHomesGoBeneathTheHomeRootOnePerTree(t *testing.T) {
	base := t.TempDir()
	a, err := New(Config{Server: "wss://hub.invalid/api/executors/connect", Token: "clet1.id.secret.mac",
		CredentialPath: filepath.Join(base, "agent.json"), WorkDirRoot: filepath.Join(base, "scratch"),
		WorkspaceRoot: filepath.Join(base, "volume"), HomeRoot: filepath.Join(base, "mem"),
		CacheDir: filepath.Join(base, "volume-cache")})
	if err != nil {
		t.Fatal(err)
	}
	reapOnCleanup(t, a)
	tree, err := a.resolveWorkDir("web-1a2b3c4d")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tree, a.workspaceRoot+string(os.PathSeparator)) {
		t.Fatalf("the tree %s is not beneath the workspace root %s", tree, a.workspaceRoot)
	}
	if _, err := a.resolveWorkDir(filepath.Join(a.root, "x")); err == nil {
		t.Fatal("a tree in the agent's scratch was accepted")
	}
	home, root := a.payloadHome(tree)
	if root != a.homeRoot || filepath.Dir(home) != a.homeRoot || filepath.Base(home) != "web-1a2b3c4d.home" {
		t.Fatalf("home %s beneath %s", home, root)
	}
	nested, _ := a.resolveWorkDir("web-1a2b3c4d/sub")
	if other, _ := a.payloadHome(nested); other == home {
		t.Fatal("two trees share a home")
	}
	env, err := withPayloadHomeAt([]string{"PATH=/bin"}, home, root)
	if err != nil {
		t.Fatal(err)
	}
	env, err = a.withCacheEnv(append(env, "GOCACHE=/mine"))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		got[k] = v
	}
	if got["HOME"] != home || got["GOCACHE"] != "/mine" || got["GOMODCACHE"] != filepath.Join(a.cacheDir, "go-mod") ||
		got["npm_config_cache"] != filepath.Join(a.cacheDir, "npm") {
		t.Fatalf("the payload's environment: %v", got)
	}
	for _, kv := range env {
		if strings.HasPrefix(kv, "HOME=") && strings.HasPrefix(strings.TrimPrefix(kv, "HOME="), a.workspaceRoot) {
			t.Fatalf("a home on the volume: %s", kv)
		}
	}
	if fi, err := os.Stat(filepath.Join(a.cacheDir, "pip")); err != nil || !fi.IsDir() {
		t.Fatalf("the pip cache directory was not created: %v", err)
	}
	if env, _ := a.withCacheEnv(nil); env != nil {
		t.Fatal("a payload inheriting the agent's environment was given one")
	}
}

// TestAnEphemeralRunnerKeepsItsTreeOnTheVolumeAndWipesTheRest is the runner's
// side of persistent storage: the volume may already hold the project's tree,
// the run's tree stays on it, and on exit everything else — scratch, homes,
// credential files — is gone and the report says how full the volume is.
func TestAnEphemeralRunnerKeepsItsTreeOnTheVolumeAndWipesTheRest(t *testing.T) {
	base := t.TempDir()
	vol := filepath.Join(base, "volume")
	mem := filepath.Join(base, "mem")
	secrets := filepath.Join(base, "secrets")
	for _, d := range []string{filepath.Join(vol, "proj"), mem, secrets} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(vol, "proj", "kept-from-last-run.txt"), []byte("kept\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newEphemeralAgent(t, func(c *Config) {
		c.WorkspaceRoot, c.HomeRoot, c.SecretDir = vol, mem, secrets
	})
	_, done := runAgent(r.a)
	cp := <-r.conns
	welcomeRunner(t, cp, true)

	start, err := remote.NewFrame(remote.TypeStart, "start-1", "h1", remote.StartPayload{HandleID: "h1",
		Spec: executor.Spec{WorkDir: "proj", Env: []string{"PATH=/usr/bin:/bin"},
			Argv: []string{"/bin/sh", "-c", `echo "$HOME" > home.txt; test -f kept-from-last-run.txt && echo ok > saw-kept.txt; echo secret > "$HOME/.claude.json"`}},
		SecretFiles: []remote.SecretFile{{Dir: "/run/secrets/lease-1", Name: "token", Content: []byte("tok-1234567890abcdef"), Mode: 0o400}},
	})
	if err != nil {
		t.Fatal(err)
	}
	cp.write(start)
	if f := cp.readUntil(remote.TypeStarted, 10*time.Second); f.Type != remote.TypeStarted {
		t.Fatalf("started: %+v", f)
	}
	var sawBye bool
	deadline := time.Now().Add(15 * time.Second)
	for !sawBye && time.Now().Before(deadline) {
		f, err := cp.read(time.Until(deadline))
		if err != nil {
			break
		}
		sawBye = f.Type == remote.TypeBye
	}
	if err := waitRun(t, done); err != nil {
		t.Fatalf("Run: %v", err)
	}
	homeTxt, err := os.ReadFile(filepath.Join(vol, "proj", "home.txt"))
	if err != nil {
		t.Fatalf("the run's tree did not stay on the volume: %v", err)
	}
	if home := strings.TrimSpace(string(homeTxt)); !strings.HasPrefix(home, mem+string(os.PathSeparator)) {
		t.Fatalf("the payload's home was %s, not beneath the memory-backed %s", home, mem)
	}
	if _, err := os.Stat(filepath.Join(vol, "proj", "saw-kept.txt")); err != nil {
		t.Fatal("the run did not find what the volume kept from the last run")
	}
	for _, dir := range []string{mem, r.root} {
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("%s holds %d entries after the wipe", dir, len(entries))
		}
	}
	if entries, _ := os.ReadDir(secrets); len(entries) != 0 {
		t.Errorf("the secret directory holds %v after the wipe", entries)
	}
	walkNoSecret(t, vol, "tok-1234567890abcdef")
	walkNoSecret(t, vol, "secret\n")
	rep := r.report(t)
	if !rep.Retired || !rep.Wiped || rep.Storage == nil || rep.Storage.Path != r.a.workspaceRoot ||
		rep.Storage.CapacityBytes <= 0 || rep.Storage.UsedBytes <= 0 {
		t.Fatalf("report %+v (storage %+v)", rep, rep.Storage)
	}
}

// walkNoSecret fails when any file beneath root holds needle.
func walkNoSecret(t *testing.T, root, needle string) {
	t.Helper()
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		if b, _ := os.ReadFile(p); strings.Contains(string(b), needle) {
			t.Errorf("%s holds %q", p, strings.TrimSpace(needle))
		}
		return nil
	})
}

// TestARunThatNeverStartedIsReported: the runner's report says its one run
// never started, which its controller reads as "wipe this volume next time".
func TestARunThatNeverStartedIsReported(t *testing.T) {
	r := newEphemeralAgent(t, nil)
	_, done := runAgent(r.a)
	cp := <-r.conns
	welcomeRunner(t, cp, true)
	start, err := remote.NewFrame(remote.TypeStart, "start-1", "h1", remote.StartPayload{HandleID: "h1",
		Spec: executor.Spec{WorkDir: "/etc", Argv: []string{"/bin/true"}}})
	if err != nil {
		t.Fatal(err)
	}
	cp.write(start)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		f, err := cp.read(time.Until(deadline))
		if err != nil || f.Type == remote.TypeBye {
			break
		}
	}
	if err := waitRun(t, done); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep := r.report(t); rep.StartFailed == "" || rep.Runs != 1 {
		t.Fatalf("report %+v", rep)
	}
}

func TestInheritedScratchCachesReachAPayloadWithItsOwnEnvironment(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", "/var/lib/cloop-runner/caches/xdg")
	base := t.TempDir()
	a, err := New(Config{Server: "wss://hub.invalid/api/executors/connect", Token: "clet1.id.secret.mac",
		CredentialPath: filepath.Join(base, "agent.json"), WorkDirRoot: filepath.Join(base, "scratch"),
		WorkspaceRoot: filepath.Join(base, "volume"), HomeRoot: filepath.Join(base, "mem")})
	if err != nil {
		t.Fatal(err)
	}
	reapOnCleanup(t, a)
	env, err := a.withCacheEnv([]string{"PATH=/bin"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(env, "XDG_CACHE_HOME=/var/lib/cloop-runner/caches/xdg") {
		t.Fatalf("env %v", env)
	}
	mine, _ := a.withCacheEnv([]string{"PATH=/bin", "XDG_CACHE_HOME=/mine"})
	if slices.Contains(mine, "XDG_CACHE_HOME=/var/lib/cloop-runner/caches/xdg") {
		t.Fatalf("a payload's own cache was overridden: %v", mine)
	}
}

// TestARunnerHoldingAProjectsVolumeTakesOnlyThatProjectsRun: a runner its
// controller started on a volume holding one project's data refuses a start
// that names another project's tenant, or none — what a hub member too old to
// keep volumes apart sends — before anything touches the volume, and still
// takes the run of the project the volume holds.
func TestARunnerHoldingAProjectsVolumeTakesOnlyThatProjectsRun(t *testing.T) {
	held := executorpool.ProjectTenant("pool-1", "/srv/web", "alice@example.com")
	other := executorpool.ProjectTenant("pool-1", "/srv/api", "alice@example.com")
	base := t.TempDir()
	vol, mem := filepath.Join(base, "volume"), filepath.Join(base, "mem")
	for _, d := range []string{vol, mem} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	r := newEphemeralAgent(t, func(c *Config) {
		c.WorkspaceRoot, c.HomeRoot, c.Holds = vol, mem, held
	})
	_, done := runAgent(r.a)
	cp := <-r.conns
	welcomeRunner(t, cp, true)

	startFrame := func(id, workDir string, labels map[string]string) remote.Frame {
		f, err := remote.NewFrame(remote.TypeStart, id, "h-"+id, remote.StartPayload{HandleID: "h-" + id,
			Spec: executor.Spec{WorkDir: workDir, Labels: labels, Argv: []string{"/bin/sh", "-c", "echo ran > ran.txt"}}})
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	for _, c := range []struct {
		id     string
		labels map[string]string
		want   string
	}{
		{"unlabelled", map[string]string{"project": "/srv/api"}, "names no project's tenant"},
		{"other", map[string]string{executor.LabelPoolTenant: other}, "another project's data"},
	} {
		cp.write(startFrame(c.id, "intruder-"+c.id, c.labels))
		f := cp.readUntil(remote.TypeError, 5*time.Second)
		p, _ := remote.DecodeError(f)
		if f.ID != c.id || p.Code != remote.CodeStartFailed || !strings.Contains(p.Message, c.want) {
			t.Fatalf("start %s: %s %q, want a refusal saying %q", c.id, p.Code, p.Message, c.want)
		}
		if _, err := os.Lstat(filepath.Join(vol, "intruder-"+c.id)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a refused start left %s on the volume (%v)", "intruder-"+c.id, err)
		}
	}

	// The refusals took nothing: the run of the project the volume holds is
	// still this runner's one run.
	cp.write(startFrame("held", "web", map[string]string{executor.LabelPoolTenant: held}))
	if f := cp.readUntil(remote.TypeStarted, 10*time.Second); f.ID != "held" {
		t.Fatalf("started: %+v", f)
	}
	deadline := time.Now().Add(15 * time.Second)
	for sawBye := false; !sawBye && time.Now().Before(deadline); {
		f, err := cp.read(time.Until(deadline))
		if err != nil {
			break
		}
		sawBye = f.Type == remote.TypeBye
	}
	if err := waitRun(t, done); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(vol, "web", "ran.txt")); err != nil || strings.TrimSpace(string(b)) != "ran" {
		t.Fatalf("the held project's run did not run on the volume: %q %v", b, err)
	}
}

// TestHoldsIsARunnersOnlyAndNamesATenant: --holds is for an ephemeral runner,
// and names a tenant a controller declares.
func TestHoldsIsARunnersOnlyAndNamesATenant(t *testing.T) {
	dir := t.TempDir()
	_, err := New(Config{Server: "wss://control-plane.invalid/api/executors/connect", Token: "enroll-token",
		CredentialPath: filepath.Join(dir, "agent.json"), WorkDirRoot: filepath.Join(dir, "work"),
		Holds: executorpool.ProjectTenant("p", "/srv/web", "")})
	if err == nil || !strings.Contains(err.Error(), "--ephemeral") {
		t.Fatalf("a permanent device with --holds: %v", err)
	}
	cfg := Config{Server: "wss://control-plane.invalid/api/executors/connect", Token: testRunnerToken,
		CredentialPath: filepath.Join(dir, "agent2.json"), WorkDirRoot: filepath.Join(dir, "work2"), Ephemeral: true,
		Holds: "/srv/web"}
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "not a tenant") {
		t.Fatalf("--holds naming a path: %v", err)
	}
}
