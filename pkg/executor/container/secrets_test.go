package container

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// leaseSpec builds a Spec carrying one lease's credential files at dir.
func leaseSpec(workDir, dir string, files ...executor.SecretFile) executor.Spec {
	for i := range files {
		files[i].Dir = dir
		if files[i].LeaseID == "" {
			files[i].LeaseID = "lease_abc"
		}
	}
	return executor.Spec{
		WorkDir:     workDir,
		Argv:        []string{"/bin/sh", "-c", "true"},
		SecretFiles: files,
		Env:         []string{"CLOOP_LEASE_DIR=" + dir},
	}
}

// TestStageSecretFilesWritesThemPrivatelyAndBindsReadOnly is the unit-level
// half of the delivery: the bytes land somewhere only the sandbox user can
// read, and the bind that carries them cannot be written through.
func TestStageSecretFilesWritesThemPrivatelyAndBindsReadOnly(t *testing.T) {
	const dir = "/run/cloop/cloop-lease-deadbeef"
	spec := leaseSpec(t.TempDir(), dir,
		executor.SecretFile{Name: "github-token", Content: []byte("ghp_unit"), Mode: 0o600},
		executor.SecretFile{Name: "git-credential-cloop", Content: []byte("#!/bin/sh\n"), Mode: 0o700},
	)

	stage, err := stageSecretFiles(spec, "")
	if err != nil {
		t.Fatalf("stageSecretFiles: %v", err)
	}
	defer stage.remove()

	if len(stage.mounts) != 1 {
		t.Fatalf("staged %d mounts, want 1 for a single lease directory", len(stage.mounts))
	}
	m := stage.mounts[0]
	if m.TargetPath != dir {
		t.Errorf("bind target = %q, want the directory the environment names (%q)", m.TargetPath, dir)
	}
	if !m.ReadOnly {
		t.Error("the credential bind is writable: the workload could rewrite the credential helper " +
			"into one that answers for repositories the grant excluded")
	}
	if got := m.String(); !strings.HasSuffix(got, ":ro") {
		t.Errorf("rendered mount %q does not carry :ro", got)
	}

	info, err := os.Stat(m.HostPath)
	if err != nil {
		t.Fatalf("stat staging dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("staging directory is %04o, want 0700", perm)
	}

	for _, f := range spec.SecretFiles {
		path := filepath.Join(m.HostPath, f.Name)
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", f.Name, err)
		}
		if perm := fi.Mode().Perm(); perm != f.Mode.Perm() {
			t.Errorf("%s is %04o, want the mode the grant asked for (%04o)", f.Name, perm, f.Mode.Perm())
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", f.Name, err)
		}
		if string(body) != string(f.Content) {
			t.Errorf("%s content = %q, want %q", f.Name, body, f.Content)
		}
	}

	// The wipe has to actually remove it. A staged credential that outlives its
	// run is the same exposure, deferred until the next reboot.
	hostDir := m.HostPath
	stage.remove()
	if _, err := os.Stat(hostDir); !os.IsNotExist(err) {
		t.Errorf("staging directory survived remove(): %v", err)
	}
}

// TestStageSecretFilesRefusesAnUnsafeName is the arbitrary-write guard. The
// name reaches this function from a stored constraint, and the cost of not
// checking is a file written wherever the string points.
func TestStageSecretFilesRefusesAnUnsafeName(t *testing.T) {
	for _, name := range []string{"../escape", "sub/dir", "..", "."} {
		t.Run(name, func(t *testing.T) {
			spec := leaseSpec(t.TempDir(), "/run/cloop/cloop-lease-deadbeef",
				executor.SecretFile{Name: name, Content: []byte("x")})
			stage, err := stageSecretFiles(spec, "")
			if err == nil {
				stage.remove()
				t.Fatalf("staged a file named %q", name)
			}
			if !errors.Is(err, executor.ErrInvalidSpec) {
				t.Errorf("refusal does not wrap ErrInvalidSpec: %v", err)
			}
		})
	}
}

// TestSecretFilesReachTheContainer is the integration half, and the only test
// that answers the question the unit tests cannot: does a read-only bind at
// /run/cloop/... actually work inside a sandbox whose rootfs is read-only?
//
// The runtime has to create the mount point in a filesystem it is about to
// remount read-only. It does — the mounts are set up before the remount — but
// "it does" is a claim about docker and podman rather than about this code, and
// the whole feature is worthless if it is wrong.
func TestSecretFilesReachTheContainer(t *testing.T) {
	ex := newTestExecutor(t, defaultTestImage, nil)
	workDir := t.TempDir()

	const dir = "/run/cloop/cloop-lease-integration"
	const token = "ghp_integrationcanary"
	spec := executor.Spec{
		WorkDir: workDir,
		// Read the token back out, and prove the mount is read-only in the same
		// breath: a successful write would mean the helper is rewritable.
		Argv: []string{"/bin/sh", "-c",
			`cat "$CLOOP_LEASE_DIR/github-token"; ` +
				`if echo tampered > "$CLOOP_LEASE_DIR/github-token" 2>/dev/null; then echo WRITABLE; fi; ` +
				`stat -c %a "$CLOOP_LEASE_DIR/github-token"`},
		Env: []string{"CLOOP_LEASE_DIR=" + dir},
		SecretFiles: []executor.SecretFile{{
			LeaseID: "lease_integration", Dir: dir,
			Name: "github-token", Content: []byte(token + "\n"), Mode: 0o600,
		}},
	}

	// executor.Run directly rather than runInSandbox: the helper builds its own
	// Spec and would drop SecretFiles, which is the whole subject here.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := executor.Run(ctx, ex, spec)
	if err != nil {
		t.Fatalf("run with a credential file: %v", err)
	}
	out := string(res.Output)
	if !strings.Contains(out, token) {
		t.Fatalf("the sandbox could not read its credential file.\noutput: %s", out)
	}
	if strings.Contains(out, "WRITABLE") {
		t.Error("the credential directory is writable inside the sandbox")
	}
	if !strings.Contains(out, "600") {
		t.Errorf("the credential is not 0600 inside the sandbox.\noutput: %s", out)
	}
}
