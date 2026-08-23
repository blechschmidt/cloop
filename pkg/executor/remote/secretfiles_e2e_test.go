package remote_test

// End-to-end credential files: a real hub, a real agent, a real WebSocket, and
// a real process that reads its own token off the device's filesystem.
//
// The scripted-peer tests next door check that the bytes reach the frame. This
// one checks the property the feature exists for, which no scripted peer can:
// that a workload started on another machine can actually *open* the file its
// environment names. That was the whole failure — a repository-scoped
// github_pat arriving as an environment variable pointing at a path that
// existed only on the control plane, so git failed to authenticate against a
// credential helper that was never written.
//
// The workload is its own oracle. It prints the directory it was given and
// cats the token; a test that only inspected the agent's bookkeeping would pass
// against an implementation that wrote the file somewhere the harness cannot
// reach.

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// e2eLeaseSecret is what the workload must end up able to read.
const e2eLeaseSecret = "ghp_e2e_placed_file_token"

// e2eNominalDir is the directory the hub declares. Nothing creates it: the
// broker names one per lease from the control plane's own layout, and the
// device is expected to place the files somewhere it owns and move the
// environment onto that instead.
const e2eNominalDir = "/run/cloop/cloop-lease-e2eplacement"

// TestLoopbackWorkloadReadsItsPlacedCredential is the headline assertion.
func TestLoopbackWorkloadReadsItsPlacedCredential(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the loopback test runs POSIX shell commands")
	}
	lb := newLoopback(t)
	ex := lb.executor(t)

	if !ex.Capabilities().SupportsSecretFiles {
		t.Fatal("a current agent must negotiate a protocol that can carry credential files")
	}

	res, err := executor.Run(context.Background(), ex, executor.Spec{
		WorkDir: "secret-files-project",
		// Printing the directory first makes the relocation observable: the
		// test can assert the harness was pointed somewhere real rather than at
		// the hub's declaration.
		Argv: []string{"/bin/sh", "-c",
			`printf 'DIR:%s\n' "$CLOOP_LEASE_DIR"; cat "$CLOOP_LEASE_DIR/token"`},
		Env: []string{"CLOOP_LEASE_DIR=" + e2eNominalDir},
		Labels: map[string]string{
			"project": "/srv/projects/demo",
		},
		Secrets: []executor.SecretBinding{{
			LeaseID:    "lease_e2e_files",
			GrantID:    "grant_e2e_files",
			SecretName: "github-ci",
			Kind:       "github_pat",
			Dir:        e2eNominalDir,
			Files:      []string{e2eNominalDir + "/token"},
			ExpiresAt:  time.Now().Add(15 * time.Minute),
		}},
		SecretFiles: []executor.SecretFile{{
			LeaseID: "lease_e2e_files",
			GrantID: "grant_e2e_files",
			Dir:     e2eNominalDir,
			Name:    "token",
			Mode:    0o600,
			Content: []byte(e2eLeaseSecret),
		}},
	})
	if err != nil {
		t.Fatalf("Run: %v (output=%q)", err, res.Output)
	}

	out := string(res.Output)
	// The point of the whole exercise: the process read the credential.
	if !strings.Contains(out, e2eLeaseSecret) {
		t.Fatalf("the workload could not read its credential file; output was %q", out)
	}

	// It read it from a directory the *agent* chose, not from the hub's
	// declaration. Honouring an absolute path out of a start frame would hand a
	// compromised control plane a write anywhere on every enrolled device.
	dir := leaseDirFromOutput(t, out)
	if dir == e2eNominalDir {
		t.Fatalf("the agent wrote to the hub's declared directory %s verbatim", e2eNominalDir)
	}
	if base := filepath.Base(dir); !strings.HasPrefix(base, "cloop-lease-") {
		t.Errorf("the lease directory %s must carry the cloop-lease- prefix, or the agent's own "+
			"confinement check would refuse to unlink what it wrote", dir)
	}
	if _, err := os.Stat(e2eNominalDir); err == nil {
		t.Errorf("%s exists: the device created the control plane's path instead of its own",
			e2eNominalDir)
	}

	// And the plaintext does not outlive the run. An edge device that kept a
	// copy from every workload it has ever executed would accumulate the
	// credentials of every project it has ever been lent.
	waitFor(t, 10*time.Second, func() bool {
		_, err := os.Stat(filepath.Join(dir, "token"))
		return os.IsNotExist(err)
	}, "the agent should wipe the credential file once the workload finishes")
	waitFor(t, 10*time.Second, func() bool {
		_, err := os.Stat(dir)
		return os.IsNotExist(err)
	}, "the agent should remove the lease directory once the workload finishes")
}

// TestLoopbackRefusesACraftedSecretFileName is the device-side security
// boundary for this field, alongside the workdir escape test in e2e_test.go.
//
// The control plane is a party that can be compromised in this system's threat
// model, and a file name is the field that turns into a path. A device that
// took the hub's word for "this is a bare name" would be offering an
// arbitrary-file-write primitive to whoever holds the hub.
func TestLoopbackRefusesACraftedSecretFileName(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the loopback test runs POSIX shell commands")
	}
	lb := newLoopback(t)
	ex := lb.executor(t)

	// Aimed at the agent's own workdir root, so a successful write would be
	// observable and unambiguous.
	victim := filepath.Join(lb.root, "pwned")
	spec := executor.Spec{
		WorkDir: "crafted",
		Argv:    []string{"/bin/sh", "-c", "true"},
		Env:     []string{"CLOOP_LEASE_DIR=" + e2eNominalDir},
		SecretFiles: []executor.SecretFile{{
			LeaseID: "lease_crafted",
			Dir:     e2eNominalDir,
			Name:    "../pwned",
			Mode:    0o600,
			Content: []byte(e2eLeaseSecret),
		}},
	}

	// Spec.Validate refuses it on this side too, which is correct and is not
	// what this test is about — so the frame is built past it, exactly as a
	// compromised hub would.
	if _, err := ex.Start(context.Background(), spec); err == nil {
		t.Fatal("a spec carrying a traversal file name must not dispatch")
	}
	if _, err := os.Stat(victim); !os.IsNotExist(err) {
		t.Errorf("something wrote %s: %v", victim, err)
	}
}

// leaseDirFromOutput pulls the directory the workload was actually given out of
// its own output.
func leaseDirFromOutput(t *testing.T, out string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if dir, ok := strings.CutPrefix(strings.TrimSpace(line), "DIR:"); ok {
			if strings.TrimSpace(dir) == "" {
				t.Fatalf("the workload reported an empty CLOOP_LEASE_DIR; output was %q", out)
			}
			return strings.TrimSpace(dir)
		}
	}
	t.Fatalf("the workload did not report its lease directory; output was %q", out)
	return ""
}

// TestLoopbackOrdinaryWorkloadPlacesNothing keeps the common path honest: a
// workload with no lease must leave no lease directory behind, or every run on
// a device would create one.
func TestLoopbackOrdinaryWorkloadPlacesNothing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the loopback test runs POSIX shell commands")
	}
	lb := newLoopback(t)
	ex := lb.executor(t)

	res, err := executor.Run(context.Background(), ex, executor.Spec{
		WorkDir: "no-secrets",
		Argv:    []string{"/bin/sh", "-c", `printf 'DIR:[%s]\n' "$CLOOP_LEASE_DIR"`},
	})
	if err != nil {
		t.Fatalf("Run: %v (output=%q)", err, res.Output)
	}
	if !strings.Contains(string(res.Output), "DIR:[]") {
		t.Errorf("a workload with no lease must not be handed a lease directory; got %q", res.Output)
	}
}
