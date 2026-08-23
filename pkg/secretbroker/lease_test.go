package secretbroker

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// testLease builds a lease carrying one file-bearing material. baseDir is
// supplied by the caller so materialisation never depends on /dev/shm being
// present or writable in the test environment.
func testLease() *Lease {
	issued := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	return &Lease{
		ID:         "lease_deadbeefdeadbeef",
		ExecutorID: "exec-1",
		ProjectID:  "proj-1",
		IssuedAt:   issued,
		ExpiresAt:  issued.Add(15 * time.Minute),
		Materials: []Material{
			{
				GrantID:    "grant-kube",
				SecretName: "kube",
				Kind:       KindKubeconfig,
				Env:        map[string]string{"CLOOP_K8S_NAMESPACE": "team-a"},
				Files: []File{{
					Name:    "kubeconfig",
					Content: []byte("apiVersion: v1\nkind: Config\n"),
					Mode:    0o600,
					EnvVar:  "KUBECONFIG",
				}},
			},
			{
				GrantID:    "grant-registry",
				SecretName: "registry",
				Kind:       KindRegistry,
				Files: []File{
					{
						Name:     "config.json",
						Content:  []byte(`{"auths":{"ghcr.io":{}}}`),
						Mode:     0o600,
						EnvVar:   "DOCKER_CONFIG",
						EnvIsDir: true,
					},
					{
						Name:    credentialHelperName,
						Content: []byte("#!/bin/sh\nexit 0\n"),
						Mode:    0o700,
					},
					{
						// Mode 0 must default to 0600 rather than to whatever
						// the process umask happens to allow.
						Name:    "defaulted-mode",
						Content: []byte("x"),
					},
				},
			},
		},
	}
}

func envValue(env []string, key string) (string, bool) {
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return v, true
		}
	}
	return "", false
}

// TestMaterializeWritesPrivateFiles: the directory and the files are the only
// thing between a credential and every other uid on the host, so their modes
// are asserted rather than assumed.
func TestMaterializeWritesPrivateFiles(t *testing.T) {
	base := t.TempDir()
	mnt, err := testLease().Materialize(base)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	defer mnt.Close()

	if filepath.Dir(mnt.Dir) != base {
		t.Errorf("mount %q is not inside baseDir %q", mnt.Dir, base)
	}
	dirInfo, err := os.Stat(mnt.Dir)
	if err != nil {
		t.Fatalf("stat mount dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("mount dir mode = %o, want 700", perm)
	}

	want := []struct {
		name    string
		content string
		mode    os.FileMode
	}{
		{"kubeconfig", "apiVersion: v1\nkind: Config\n", 0o600},
		{"config.json", `{"auths":{"ghcr.io":{}}}`, 0o600},
		{credentialHelperName, "#!/bin/sh\nexit 0\n", 0o700},
		{"defaulted-mode", "x", 0o600},
	}
	for _, w := range want {
		path := filepath.Join(mnt.Dir, w.name)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("stat %s: %v", w.name, err)
			continue
		}
		if perm := info.Mode().Perm(); perm != w.mode {
			t.Errorf("%s mode = %o, want %o", w.name, perm, w.mode)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("read %s: %v", w.name, err)
			continue
		}
		if string(got) != w.content {
			t.Errorf("%s = %q, want %q", w.name, got, w.content)
		}
	}
}

// TestMaterializeResolvesEnvVars: EnvVar points at the file, EnvIsDir at the
// directory holding it (which is what DOCKER_CONFIG expects).
func TestMaterializeResolvesEnvVars(t *testing.T) {
	base := t.TempDir()
	mnt, err := testLease().Materialize(base)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	defer mnt.Close()

	env := mnt.Env()

	kubeconfig, ok := envValue(env, "KUBECONFIG")
	if !ok {
		t.Fatalf("KUBECONFIG missing from env %v", env)
	}
	if kubeconfig != filepath.Join(mnt.Dir, "kubeconfig") {
		t.Errorf("KUBECONFIG = %q, want the kubeconfig file's path", kubeconfig)
	}
	if !filepath.IsAbs(kubeconfig) {
		t.Errorf("KUBECONFIG = %q, want an absolute path", kubeconfig)
	}
	if _, err := os.Stat(kubeconfig); err != nil {
		t.Errorf("KUBECONFIG does not point at a real file: %v", err)
	}

	dockerCfg, ok := envValue(env, "DOCKER_CONFIG")
	if !ok {
		t.Fatalf("DOCKER_CONFIG missing from env %v", env)
	}
	if dockerCfg != mnt.Dir {
		t.Errorf("DOCKER_CONFIG = %q, want the containing directory %q", dockerCfg, mnt.Dir)
	}

	// A file with no EnvVar contributes no variable.
	if v, ok := envValue(env, "defaulted-mode"); ok {
		t.Errorf("file without EnvVar leaked into env as %q", v)
	}
}

// TestMountEnvShape: the slice is appended straight onto an executor's
// environment, so every entry has to be parseable as K=V and the ordering has
// to be stable for reproducible specs and diffs.
func TestMountEnvShape(t *testing.T) {
	base := t.TempDir()
	l := testLease()
	mnt, err := l.Materialize(base)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	defer mnt.Close()

	env := mnt.Env()
	if len(env) == 0 {
		t.Fatal("Env() is empty")
	}
	for _, kv := range env {
		if !strings.Contains(kv, "=") {
			t.Errorf("env entry %q is not in K=V form", kv)
		}
	}
	if !sort.StringsAreSorted(env) {
		t.Errorf("Env() is not sorted: %v", env)
	}

	if got, ok := envValue(env, "CLOOP_LEASE_DIR"); !ok || got != mnt.Dir {
		t.Errorf("CLOOP_LEASE_DIR = %q (present=%v), want %q", got, ok, mnt.Dir)
	}
	if got, ok := envValue(env, "CLOOP_LEASE_ID"); !ok || got != l.ID {
		t.Errorf("CLOOP_LEASE_ID = %q (present=%v), want %q", got, ok, l.ID)
	}
	if got, ok := envValue(env, "CLOOP_LEASE_EXPIRES_AT"); !ok || got != l.ExpiresAt.UTC().Format(time.RFC3339) {
		t.Errorf("CLOOP_LEASE_EXPIRES_AT = %q (present=%v)", got, ok)
	}
	// Material-supplied env survives alongside the injected variables.
	if got, ok := envValue(env, "CLOOP_K8S_NAMESPACE"); !ok || got != "team-a" {
		t.Errorf("CLOOP_K8S_NAMESPACE = %q (present=%v), want team-a", got, ok)
	}

	// Env() must hand out a copy: a caller appending to the returned slice
	// must not be able to reach back into the mount's own state.
	env[0] = "TAMPERED=1"
	if again := mnt.Env(); again[0] == "TAMPERED=1" {
		t.Error("Env() returned the mount's own backing array")
	}
}

// TestMountCloseWipes: the lease's whole point is that credentials do not
// outlive the workload. Close must actually remove them, and must be safe in
// the defer-plus-explicit-call pattern the package documents.
func TestMountCloseWipes(t *testing.T) {
	base := t.TempDir()
	mnt, err := testLease().Materialize(base)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	kubeconfig := filepath.Join(mnt.Dir, "kubeconfig")
	if _, err := os.Stat(kubeconfig); err != nil {
		t.Fatalf("credential file missing before Close: %v", err)
	}
	dir := mnt.Dir

	if err := mnt.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(kubeconfig); !os.IsNotExist(err) {
		t.Errorf("credential file survived Close: err = %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("mount dir survived Close: err = %v", err)
	}
	if entries, err := os.ReadDir(base); err != nil {
		t.Fatalf("read baseDir: %v", err)
	} else if len(entries) != 0 {
		t.Errorf("baseDir still holds %d entries after Close", len(entries))
	}

	// Idempotent: a second Close (from a defer, after an explicit one) must
	// not panic or report a spurious failure.
	if err := mnt.Close(); err != nil {
		t.Errorf("second Close = %v, want nil", err)
	}
	if env := mnt.Env(); len(env) != 0 {
		t.Errorf("Env() after Close = %v, want empty", env)
	}
}

// TestMaterializeRejectsUnsafeFileNames: a crafted file name is an
// arbitrary-file-write primitive running with the executor's privileges, so
// Materialize must refuse rather than normalise, and must not leave a
// half-written lease directory behind when it does.
func TestMaterializeRejectsUnsafeFileNames(t *testing.T) {
	tests := []struct {
		name         string
		wantSentinel bool
	}{
		{"../escape", true},
		{"a/b", true},
		{"..", true},
		{"../../etc/cron.d/pwn", true},
		{"/etc/passwd", true},
		{`sub\file`, true},
		{"", true},
		{"   ", true},
		// "." needs an explicit clause in the guard, because
		// filepath.Base(".") is "." and Join(dir, ".") is the lease
		// directory itself. Without it the rejection arrives as a raw "is a
		// directory" error and a caller matching on errors.Is would read a
		// malformed name as a disk problem.
		{".", true},
	}

	for _, tc := range tests {
		name := tc.name
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			l := &Lease{
				ID:        "lease_unsafe",
				ExpiresAt: time.Now().Add(time.Minute),
				Materials: []Material{{
					SecretName: "hostile",
					Files:      []File{{Name: name, Content: []byte("pwned"), Mode: 0o600}},
				}},
			}
			mnt, err := l.Materialize(base)
			if err == nil {
				_ = mnt.Close()
				t.Fatalf("file name %q must be rejected", name)
			}
			if tc.wantSentinel && !errors.Is(err, ErrInvalidSecret) {
				t.Errorf("err = %v, want ErrInvalidSecret", err)
			}
			if mnt != nil {
				t.Errorf("a rejected lease must not yield a Mount, got %+v", mnt)
			}

			// Nothing was written outside the (now removed) lease dir.
			if _, err := os.Stat(filepath.Join(base, "escape")); err == nil {
				t.Errorf("file name %q escaped into baseDir", name)
			}

			// And the temp dir Materialize created for the attempt is gone:
			// a leftover would be a credential directory nobody owns.
			entries, err := os.ReadDir(base)
			if err != nil {
				t.Fatalf("read baseDir: %v", err)
			}
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), "cloop-lease-") {
					t.Errorf("failed Materialize left %q behind in baseDir", e.Name())
				}
			}
		})
	}
}

// TestMaterializeNilLease: a nil lease is a lookup failure, not a mount of
// nothing.
func TestMaterializeNilLease(t *testing.T) {
	var l *Lease
	mnt, err := l.Materialize(t.TempDir())
	if !errors.Is(err, ErrLeaseNotFound) {
		t.Fatalf("err = %v, want ErrLeaseNotFound", err)
	}
	if mnt != nil {
		t.Errorf("nil lease produced a mount: %+v", mnt)
	}
}

// TestLeaseExpiryAndTTL: the TTL is the bound on a compromised executor's
// window, so the boundary case (exactly at ExpiresAt) has to read as expired
// and TTL must never go negative and start looking like time remaining.
func TestLeaseExpiryAndTTL(t *testing.T) {
	expires := time.Date(2026, 3, 1, 12, 15, 0, 0, time.UTC)
	l := &Lease{ID: "lease_ttl", IssuedAt: expires.Add(-15 * time.Minute), ExpiresAt: expires}

	tests := []struct {
		name        string
		now         time.Time
		wantExpired bool
		wantTTL     time.Duration
	}{
		{"well before expiry", expires.Add(-10 * time.Minute), false, 10 * time.Minute},
		{"one second before", expires.Add(-time.Second), false, time.Second},
		{"exactly at expiry", expires, true, 0},
		{"after expiry", expires.Add(time.Hour), true, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := l.Expired(tc.now); got != tc.wantExpired {
				t.Errorf("Expired(%v) = %v, want %v", tc.now, got, tc.wantExpired)
			}
			if got := l.TTL(tc.now); got != tc.wantTTL {
				t.Errorf("TTL(%v) = %v, want %v", tc.now, got, tc.wantTTL)
			}
			if got := l.TTL(tc.now); got < 0 {
				t.Errorf("TTL(%v) = %v, must never be negative", tc.now, got)
			}
		})
	}

	// A nil lease is expired and holds no time, so a caller that forgot a nil
	// check fails closed rather than treating it as valid forever.
	var nilLease *Lease
	if !nilLease.Expired(expires.Add(-time.Hour)) {
		t.Error("nil lease must read as expired")
	}
	if got := nilLease.TTL(expires.Add(-time.Hour)); got != 0 {
		t.Errorf("nil lease TTL = %v, want 0", got)
	}
}

// TestLeaseEmptyAndSecretNames: an empty lease is a legitimate "run with no
// secrets", so Empty must be nil-safe and SecretNames must not panic on one.
func TestLeaseEmptyAndSecretNames(t *testing.T) {
	var nilLease *Lease
	if !nilLease.Empty() {
		t.Error("(*Lease)(nil).Empty() must be true")
	}
	if names := nilLease.SecretNames(); names != nil {
		t.Errorf("(*Lease)(nil).SecretNames() = %v, want nil", names)
	}

	noMaterials := &Lease{ID: "lease_empty"}
	if !noMaterials.Empty() {
		t.Error("a lease with no materials must be Empty")
	}
	if names := noMaterials.SecretNames(); len(names) != 0 {
		t.Errorf("SecretNames() = %v, want empty", names)
	}

	l := &Lease{Materials: []Material{
		{SecretName: "zeta"},
		{SecretName: "alpha"},
		{SecretName: "mid"},
	}}
	if l.Empty() {
		t.Error("a lease with materials must not be Empty")
	}
	got := l.SecretNames()
	want := []string{"alpha", "mid", "zeta"}
	if len(got) != len(want) {
		t.Fatalf("SecretNames() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SecretNames() = %v, want %v (sorted)", got, want)
		}
	}
}

// TestNilMountIsSafe: Close is documented as safe in a defer, which means the
// nil returned alongside a Materialize error must not turn a credential
// failure into a panic.
func TestNilMountIsSafe(t *testing.T) {
	var m *Mount
	if err := m.Close(); err != nil {
		t.Errorf("(*Mount)(nil).Close() = %v, want nil", err)
	}
	if env := m.Env(); env != nil {
		t.Errorf("(*Mount)(nil).Env() = %v, want nil", env)
	}
}

// TestMaterializeEmptyLease: a lease with no materials still gets a directory
// and the locating variables, so a workload can be told "here is your (empty)
// lease" uniformly.
func TestMaterializeEmptyLease(t *testing.T) {
	base := t.TempDir()
	l := &Lease{ID: "lease_none", ExpiresAt: time.Now().Add(time.Minute)}
	mnt, err := l.Materialize(base)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	defer mnt.Close()

	if got, ok := envValue(mnt.Env(), "CLOOP_LEASE_DIR"); !ok || got != mnt.Dir {
		t.Errorf("CLOOP_LEASE_DIR = %q (present=%v), want %q", got, ok, mnt.Dir)
	}
	entries, err := os.ReadDir(mnt.Dir)
	if err != nil {
		t.Fatalf("read mount dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("empty lease materialised %d files", len(entries))
	}
}

// TestMountCloseSurfacesAWipeItCouldNotPerform is the caller-side half of the
// "stop swallowing wipe errors" contract.
//
// Close's own error return existed already, but everything under it discarded
// failures: wipeFile returned nil whatever happened, and os.RemoveAll unlinked
// stragglers without zeroing them. A hub calling Close and getting nil would
// log "secret lease wiped" over plaintext still on disk.
func TestMountCloseSurfacesAWipeItCouldNotPerform(t *testing.T) {
	lease := &Lease{
		ID:        "lease_stuck",
		ExpiresAt: time.Now().Add(time.Hour),
		Materials: []Material{{
			GrantID:    "grant_1",
			SecretName: "github-ci",
			Kind:       KindGitHubPAT,
			Files:      []File{{Name: "token", Content: []byte("ghp_canary"), Mode: 0o600}},
		}},
	}
	mount, err := lease.Materialize(t.TempDir())
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	// The confined wipe refuses to recurse, so a subdirectory is a
	// deterministic, root-safe way to make destruction genuinely fail.
	if err := os.Mkdir(filepath.Join(mount.Dir, "nested"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if err := mount.Close(); err == nil {
		t.Fatal("Close returned nil while the lease directory was still on disk; " +
			"the caller would report the credential as destroyed")
	}
	if _, err := os.Stat(mount.Dir); err != nil {
		t.Errorf("the directory should still be there — that is what makes it worth reporting: %v", err)
	}
}

// TestMountCloseZeroesFilesTheWorkloadWrote covers what os.RemoveAll used to
// miss. m.files tracks only what the broker placed; a harness that dropped its
// own credential in the lease directory — a git helper's scratch file, a
// kubectl cache — had it unlinked without ever being overwritten.
func TestMountCloseZeroesFilesTheWorkloadWrote(t *testing.T) {
	lease := &Lease{
		ID:        "lease_extra",
		ExpiresAt: time.Now().Add(time.Hour),
		Materials: []Material{{
			GrantID: "grant_1", SecretName: "kube", Kind: KindKubeconfig,
			Files: []File{{Name: "config", Content: []byte("apiVersion: v1"), Mode: 0o600}},
		}},
	}
	mount, err := lease.Materialize(t.TempDir())
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	stray := filepath.Join(mount.Dir, "workload-wrote-this")
	if err := os.WriteFile(stray, []byte("ghp_stray_canary"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	witness, err := os.Open(stray)
	if err != nil {
		t.Fatalf("open witness: %v", err)
	}
	defer witness.Close()

	if err := mount.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	buf := make([]byte, len("ghp_stray_canary"))
	if _, err := witness.ReadAt(buf, 0); err != nil {
		t.Fatalf("read through witness: %v", err)
	}
	if strings.Contains(string(buf), "ghp_") {
		t.Errorf("an untracked file in the lease directory was unlinked but not zeroed: %q", buf)
	}
}

// TestMaterializeAtRefusesADirectoryNothingCouldSweep guards the invariant the
// whole destruction story rests on: every wipe path in this system recognises a
// lease directory by its name prefix, so one created without it could never be
// swept, revoked, or reconciled.
func TestMaterializeAtRefusesADirectoryNothingCouldSweep(t *testing.T) {
	lease := &Lease{ID: "lease_x", ExpiresAt: time.Now().Add(time.Hour)}
	for _, dir := range []string{
		filepath.Join(t.TempDir(), "plain-directory"),
		"relative/cloop-lease-x",
		"",
	} {
		if _, err := lease.MaterializeAt(dir); err == nil {
			t.Errorf("MaterializeAt(%q) was accepted; nothing would ever recognise it as lease-owned", dir)
		}
	}
}

// TestNewLeaseDirPathCreatesNothing is what makes the write-ahead ordering
// possible: the caller records its intent to materialise before any plaintext
// exists, so a crash always leaves either nothing or a reconcilable trace, and
// never plaintext with no record.
func TestNewLeaseDirPathCreatesNothing(t *testing.T) {
	base := t.TempDir()
	dir, err := NewLeaseDirPath(base)
	if err != nil {
		t.Fatalf("NewLeaseDirPath: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("%s exists already; the intent row could not precede the plaintext: %v", dir, err)
	}
	if !strings.HasPrefix(filepath.Base(dir), leaseDirPrefix) {
		t.Errorf("%s does not carry the lease prefix", dir)
	}
	other, err := NewLeaseDirPath(base)
	if err != nil {
		t.Fatalf("NewLeaseDirPath: %v", err)
	}
	if other == dir {
		t.Error("two calls returned the same path; two hubs sharing /dev/shm would collide")
	}
}
