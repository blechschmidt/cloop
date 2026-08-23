package agent

// Device-side placement tests: where a lease's credential files actually land,
// what the workload's environment ends up naming, and what a crafted frame is
// not allowed to do.
//
// The hub's half — the frame field, the version floor, the redaction — lives in
// pkg/executor/remote's secretfiles_test.go. What only the device can get wrong
// is here, and the two properties worth stating up front are:
//
//   - the hub's Dir is a declaration, not an instruction. Honouring an absolute
//     path out of a start frame would hand whoever holds the control plane a
//     file write on every enrolled machine; and
//   - the Spec has to be relocated onto what was really written, because
//     vault.bind indexes those paths for revocation. A revoke naming a path this
//     agent never wrote is a revoke that reports success and deletes nothing.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

const (
	// placedToken is the material under test. Asserting on a placeholder would
	// pass against an implementation that wrote an empty file.
	placedToken = "ghp_device_placed_token"
	// declaredDir is what the hub says. It exists on no machine — that is the
	// point — and the device must not create it.
	declaredDir = "/run/cloop/cloop-lease-devicetest"
)

// secretTestAgent builds the minimum Agent materialisation needs. It touches no
// network, no credential file and no confinement root: placement is a pure
// filesystem operation plus the Spec rewrite.
func secretTestAgent(t *testing.T) *Agent {
	t.Helper()
	return &Agent{cfg: Config{Logf: func(string, ...any) {}}}
}

// leasedFileSpec is a workload dispatched with one credential file, shaped the
// way the broker shapes it: the environment already names the paths, and the
// binding names them for revocation.
func leasedFileSpec() (executor.Spec, []executor.SecretFile) {
	spec := executor.Spec{
		WorkDir: "/tmp/does-not-matter",
		Argv:    []string{"/bin/sh", "-c", "true"},
		Env: []string{
			"CLOOP_LEASE_DIR=" + declaredDir,
			"GIT_CONFIG_GLOBAL=" + declaredDir + "/gitconfig",
			// An unrelated variable, to prove relocation is a prefix rewrite of
			// lease paths and not a blanket substitution.
			"PATH=/usr/bin:/bin",
		},
		Secrets: []executor.SecretBinding{{
			LeaseID:    "lease_device",
			GrantID:    "grant_device",
			SecretName: "github-ci",
			Kind:       "github_pat",
			Dir:        declaredDir,
			Files:      []string{declaredDir + "/token", declaredDir + "/gitconfig"},
		}},
	}
	files := []executor.SecretFile{
		{
			LeaseID: "lease_device", GrantID: "grant_device",
			Dir: declaredDir, Name: "token", Mode: 0o600, Content: []byte(placedToken),
		},
		{
			LeaseID: "lease_device", GrantID: "grant_device",
			Dir: declaredDir, Name: "gitconfig", Mode: 0o400,
			Content: []byte("[credential]\n\thelper = store\n"),
		},
	}
	return spec, files
}

// TestSecretFilesLandInADirectoryTheAgentOwns is the central device-side
// assertion: the files exist, with the right bytes and modes, in a directory
// this agent chose — and the workload's view has been moved onto it.
func TestSecretFilesLandInADirectoryTheAgentOwns(t *testing.T) {
	a := secretTestAgent(t)
	spec, files := leasedFileSpec()

	placed, err := a.materializeSecretFiles(&spec, files)
	if err != nil {
		t.Fatalf("materializeSecretFiles: %v", err)
	}
	if placed == nil {
		t.Fatal("a lease with files must produce a placement")
	}
	t.Cleanup(func() { placed.wipe(nil) })

	if len(placed.dirs) != 1 {
		t.Fatalf("one declared directory should produce one real one; got %v", placed.dirs)
	}
	dir := placed.dirs[0]

	// Not the hub's path, and not anywhere near it.
	if dir == declaredDir || strings.HasPrefix(dir, "/run/cloop") {
		t.Fatalf("the agent used the control plane's declared directory: %s", dir)
	}
	if _, err := os.Stat(declaredDir); err == nil {
		t.Errorf("%s was created; the hub's Dir is a declaration, not an instruction", declaredDir)
	}
	// The prefix is load-bearing rather than cosmetic: vault.go's
	// checkLeaseOwned refuses to unlink anything outside a cloop-lease-*
	// directory, so a placement that did not carry it could never be scrubbed.
	if base := filepath.Base(dir); !strings.HasPrefix(base, leaseDirPrefix) {
		t.Errorf("lease directory %s must start with %s or nothing could ever remove it",
			base, leaseDirPrefix)
	}
	if info, err := os.Stat(dir); err != nil {
		t.Errorf("stat lease directory: %v", err)
	} else if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("lease directory mode = %04o, want 0700: a traversable directory makes every "+
			"file inside it reachable whatever its own mode", perm)
	}

	// The bytes and the modes the grant asked for.
	for _, tc := range []struct {
		name string
		want string
		mode os.FileMode
	}{
		{"token", placedToken, 0o600},
		{"gitconfig", "[credential]\n\thelper = store\n", 0o400},
	} {
		path := filepath.Join(dir, tc.name)
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", tc.name, err)
		}
		if string(body) != tc.want {
			t.Errorf("%s content = %q, want %q", tc.name, body, tc.want)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", tc.name, err)
		}
		if perm := info.Mode().Perm(); perm != tc.mode {
			t.Errorf("%s mode = %04o, want %04o", tc.name, perm, tc.mode)
		}
	}

	// The environment now names what exists. Without this the harness reads the
	// hub's path and finds nothing, which is the failure the whole feature
	// exists to remove — moved one hop rather than fixed.
	wantEnv := map[string]string{
		"CLOOP_LEASE_DIR":   dir,
		"GIT_CONFIG_GLOBAL": filepath.Join(dir, "gitconfig"),
		"PATH":              "/usr/bin:/bin",
	}
	for _, kv := range spec.Env {
		k, v, _ := strings.Cut(kv, "=")
		want, tracked := wantEnv[k]
		if !tracked {
			continue
		}
		if v != want {
			t.Errorf("env %s = %q, want %q", k, v, want)
		}
		delete(wantEnv, k)
	}
	if len(wantEnv) != 0 {
		t.Errorf("environment lost entries: %v", wantEnv)
	}

	// And so does the binding the vault will index. This is what makes a later
	// revoke able to find anything at all.
	if got := spec.Secrets[0].Dir; got != dir {
		t.Errorf("binding Dir = %q, want the real directory %q", got, dir)
	}
	for _, f := range spec.Secrets[0].Files {
		if !strings.HasPrefix(f, dir+"/") {
			t.Errorf("binding file %q was not relocated onto %s", f, dir)
		}
		if _, err := os.Stat(f); err != nil {
			t.Errorf("binding names %s, which does not exist: a revoke would delete nothing", f)
		}
	}

	// The vault accepts the relocated paths — the property the relocation is
	// for. Before relocation these were /run/cloop/... paths that the device
	// would have indexed and then failed to unlink.
	v := newVault()
	v.bind("handle-1", spec.Secrets)
	report := v.scrub("lease_device", "", nil)
	if !report.Known {
		t.Fatal("the vault should hold the relocated lease")
	}
	if report.FilesRemoved != 2 {
		t.Errorf("scrub removed %d files, want 2 (errors: %v)", report.FilesRemoved, report.Errors)
	}
	if len(report.Errors) != 0 {
		t.Errorf("a scrub of the agent's own placement must not be refused: %v", report.Errors)
	}
}

// TestPlacedSecretFilesAreWiped covers the teardown path forget() drives: when a
// workload ends, the plaintext goes with it. An edge device that kept a copy
// from every run would accumulate the credentials of every project it has ever
// been lent.
func TestPlacedSecretFilesAreWiped(t *testing.T) {
	a := secretTestAgent(t)
	spec, files := leasedFileSpec()

	placed, err := a.materializeSecretFiles(&spec, files)
	if err != nil {
		t.Fatalf("materializeSecretFiles: %v", err)
	}
	dir := placed.dirs[0]
	paths := placed.paths()
	if len(paths) != 2 {
		t.Fatalf("placement recorded %d files, want 2", len(paths))
	}

	placed.wipe(nil)
	for _, p := range paths {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived the wipe: %v", p, err)
		}
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("lease directory %s survived the wipe: %v", dir, err)
	}
	// Idempotent: a revoke that already scrubbed the files leaves nothing to do,
	// and forget() runs afterwards on every workload.
	placed.wipe(nil)
	if got := placed.paths(); got != nil {
		t.Errorf("a wiped placement should hold no paths; got %v", got)
	}
}

// TestCraftedSecretFileNameIsRefused is the device's confinement boundary for
// this field.
//
// In this system's threat model the control plane is a party that can be
// compromised (see the note at the top of vault.go). The file name is the field
// that becomes a path, so a device that trusted it would be offering an
// arbitrary-file-write primitive to whoever holds the hub. It is checked twice
// on purpose: once at decode, before the frame is acted on at all, and once at
// the point of the write, which is the check no future call path can skip.
func TestCraftedSecretFileNameIsRefused(t *testing.T) {
	victimDir := t.TempDir()
	victim := filepath.Join(victimDir, "evil")

	crafted := []executor.SecretFile{{
		LeaseID: "lease_crafted",
		Dir:     filepath.Join(victimDir, "cloop-lease-crafted"),
		Name:    "../evil",
		Mode:    0o600,
		Content: []byte(placedToken),
	}}

	// The frame itself must not survive decode. This is the first line: the
	// agent should never reach placement code with a name like this.
	frame, err := remote.NewFrame(remote.TypeStart, "corr-1", "h-1", remote.StartPayload{
		HandleID:    "h-1",
		SecretFiles: remote.NewSecretFiles(crafted),
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}
	if _, err := remote.DecodeStart(frame); err == nil {
		t.Fatal("a start frame naming ../evil must be refused at decode")
	}

	// And placement refuses it independently, so a caller that reached it some
	// other way still writes nothing.
	a := secretTestAgent(t)
	spec := executor.Spec{WorkDir: "/tmp/x", Argv: []string{"true"}}
	placed, err := a.materializeSecretFiles(&spec, crafted)
	if err == nil {
		placed.wipe(nil)
		t.Fatal("materializeSecretFiles accepted a traversal file name")
	}
	if !strings.Contains(err.Error(), "unsafe secret file name") {
		t.Errorf("the refusal should name the problem; got %v", err)
	}
	if _, err := os.Stat(victim); !os.IsNotExist(err) {
		t.Fatalf("%s was written outside the lease directory: %v", victim, err)
	}
	// Nothing at all was left behind: a partial placement is plaintext on a
	// device nobody will ever come back to clean up.
	entries, err := os.ReadDir(victimDir)
	if err != nil {
		t.Fatalf("read victim dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("a refused placement left %d entries behind: %v", len(entries), entries)
	}
}

// TestUnsafeSecretFilePlacementIsRefused walks the rest of the invariants
// materialisation must not let through, each of which is a different way for a
// credential to end up somewhere it can be read.
func TestUnsafeSecretFilePlacementIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		file executor.SecretFile
	}{
		{"relative directory", executor.SecretFile{Dir: "run/cloop", Name: "token", Mode: 0o600}},
		{"unclean directory", executor.SecretFile{Dir: "/run/cloop/../cloop", Name: "token", Mode: 0o600}},
		{"empty name", executor.SecretFile{Dir: declaredDir, Name: "", Mode: 0o600}},
		{"dot name", executor.SecretFile{Dir: declaredDir, Name: "..", Mode: 0o600}},
		{"world readable", executor.SecretFile{Dir: declaredDir, Name: "token", Mode: 0o644}},
		{"group readable", executor.SecretFile{Dir: declaredDir, Name: "token", Mode: 0o640}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.file.LeaseID = "lease_bad"
			tc.file.Content = []byte(placedToken)
			a := secretTestAgent(t)
			spec := executor.Spec{WorkDir: "/tmp/x", Argv: []string{"true"}}
			placed, err := a.materializeSecretFiles(&spec, []executor.SecretFile{tc.file})
			if err == nil {
				placed.wipe(nil)
				t.Fatal("placement accepted a credential file it should have refused")
			}
			if placed != nil {
				t.Error("a refused placement must return nothing to wipe")
			}
		})
	}
}

// TestNoSecretFilesIsNotAPlacement keeps the common case free: most workloads
// lease only environment variables, and they must not acquire a directory, a
// teardown, or a rewritten Spec.
func TestNoSecretFilesIsNotAPlacement(t *testing.T) {
	a := secretTestAgent(t)
	spec := executor.Spec{
		WorkDir: "/tmp/x",
		Argv:    []string{"true"},
		Env:     []string{"GITHUB_TOKEN=" + placedToken},
	}
	before := append([]string(nil), spec.Env...)

	placed, err := a.materializeSecretFiles(&spec, nil)
	if err != nil {
		t.Fatalf("materializeSecretFiles: %v", err)
	}
	if placed != nil {
		t.Errorf("a lease with no files produced a placement: %+v", placed)
	}
	if strings.Join(spec.Env, "\x00") != strings.Join(before, "\x00") {
		t.Errorf("the environment was rewritten for a workload with no credential files: %v", spec.Env)
	}
	// wipe on the nil placement is what forget() calls for every ordinary
	// workload, so it has to be safe.
	placed.wipe(nil)
}

// TestSecretFileBaseIsWritable pins the directory choice. tmpfs is preferred so
// the plaintext never reaches a block device; the fallback exists for a device
// with no /dev/shm, where the wipe is the only thing carrying the guarantee.
func TestSecretFileBaseIsWritable(t *testing.T) {
	base := secretFileBase()
	if base == "" {
		t.Fatal("no base directory chosen")
	}
	dir, err := os.MkdirTemp(base, leaseDirPrefix)
	if err != nil {
		t.Fatalf("the chosen base %s is not writable: %v", base, err)
	}
	_ = os.Remove(dir)
}

// TestTwoLeasesGetSeparateDirectories: revoking one lease must not take the
// other's material with it, which a shared directory would make impossible.
func TestTwoLeasesGetSeparateDirectories(t *testing.T) {
	a := secretTestAgent(t)
	dirA := "/run/cloop/cloop-lease-aaaa"
	dirB := "/run/cloop/cloop-lease-bbbb"
	spec := executor.Spec{
		WorkDir: "/tmp/x",
		Argv:    []string{"true"},
		Env:     []string{"A_DIR=" + dirA, "B_DIR=" + dirB},
		Secrets: []executor.SecretBinding{
			{LeaseID: "lease_a", Dir: dirA, Files: []string{dirA + "/token"}},
			{LeaseID: "lease_b", Dir: dirB, Files: []string{dirB + "/token"}},
		},
	}
	files := []executor.SecretFile{
		{LeaseID: "lease_a", Dir: dirA, Name: "token", Mode: 0o600, Content: []byte("token-a")},
		{LeaseID: "lease_b", Dir: dirB, Name: "token", Mode: 0o600, Content: []byte("token-b")},
	}

	placed, err := a.materializeSecretFiles(&spec, files)
	if err != nil {
		t.Fatalf("materializeSecretFiles: %v", err)
	}
	t.Cleanup(func() { placed.wipe(nil) })

	if len(placed.dirs) != 2 {
		t.Fatalf("two leases should get two directories; got %v", placed.dirs)
	}
	if placed.dirs[0] == placed.dirs[1] {
		t.Fatal("two leases share a directory; revoking one would take both")
	}
	if spec.Secrets[0].Dir == spec.Secrets[1].Dir {
		t.Fatalf("both bindings relocated onto %s", spec.Secrets[0].Dir)
	}
	for i, want := range []string{"token-a", "token-b"} {
		body, err := os.ReadFile(filepath.Join(spec.Secrets[i].Dir, "token"))
		if err != nil {
			t.Fatalf("read lease %d token: %v", i, err)
		}
		if string(body) != want {
			t.Errorf("lease %d token = %q, want %q", i, body, want)
		}
	}
}
