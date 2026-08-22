package remote_test

// End-to-end revocation: a real broker lease, a real agent, a real running
// process, and a revoke that takes the credential away underneath it.
//
// The scripted-peer tests next door check the hub's state machine. This one
// checks the property the feature actually exists for, which no scripted peer
// can: that after a revoke lands, the credential is *gone from the device* —
// verified by the running workload itself noticing its token file disappear
// while it is still executing.

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// leaseSecret is the material under test. A test that asserted on a
// placeholder would pass just as happily against an implementation that never
// wrote the credential at all.
const leaseSecret = "ghp_e2e_secret_token"

// mintLease builds and materialises a lease the way the broker does for a
// real workload: a PAT in the environment plus a token file on a private
// directory, with the per-grant attribution the executor needs to take either
// one back.
//
// It constructs the Lease directly rather than going through Broker.LeaseFor
// so the test needs no secret store or CLOOP_SECRET_KEY. Materialize — the
// step that decides where credentials land, what the bindings say, and what a
// revocation will therefore be able to find — is the real one.
func mintLease(t *testing.T, baseDir string) (*secretbroker.Lease, *secretbroker.Mount) {
	t.Helper()
	lease := &secretbroker.Lease{
		ID:         "lease_e2e",
		ExecutorID: "agent-1",
		ProjectID:  "e2e-project",
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(15 * time.Minute),
		Materials: []secretbroker.Material{{
			GrantID:    "grant_e2e",
			SecretID:   "sec_e2e",
			SecretName: "github-ci",
			Kind:       secretbroker.KindGitHubPAT,
			Env:        map[string]string{"GITHUB_TOKEN": leaseSecret},
			Files: []secretbroker.File{{
				Name:    "token",
				Content: []byte(leaseSecret),
				Mode:    0o600,
				EnvVar:  "GITHUB_TOKEN_FILE",
			}},
			Summary: "github-ci for org/*",
		}},
	}
	mount, err := lease.Materialize(baseDir)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	t.Cleanup(func() { _ = mount.Close() })
	return lease, mount
}

// leaseBindings projects a mount's attribution onto the driver-facing shape,
// mirroring what pkg/ui does at spawn time.
func leaseBindings(lease *secretbroker.Lease, mount *secretbroker.Mount) []executor.SecretBinding {
	var out []executor.SecretBinding
	for _, b := range mount.Bindings() {
		out = append(out, executor.SecretBinding{
			LeaseID:    lease.ID,
			GrantID:    b.GrantID,
			SecretName: b.SecretName,
			Kind:       string(b.Kind),
			EnvKeys:    b.EnvKeys,
			Files:      b.Files,
			Dir:        b.Dir,
			ExpiresAt:  lease.ExpiresAt,
		})
	}
	return out
}

// TestLoopbackRevokeScrubsMaterialMidRun is the headline assertion: a task is
// running, holding a leased credential, and a revocation takes the credential
// away without waiting for the task to exit.
//
// The workload is its own oracle. It polls for its token file and prints when
// the file goes away, so the test does not merely check that the hub *sent* a
// revoke or that a status field flipped — it observes the running process
// losing access to the credential while it is still alive.
func TestLoopbackRevokeScrubsMaterialMidRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the loopback test runs POSIX shell commands")
	}
	lb := newLoopback(t)
	ex := lb.executor(t)

	if !ex.SupportsRevocation() {
		t.Fatal("a current agent must negotiate a protocol that honours revocation")
	}

	// The lease directory is under the agent's own temp space, which on this
	// loopback is the same filesystem: hub and agent are one process here, so
	// the paths the binding names really do exist for the agent to unlink.
	lease, mount := mintLease(t, t.TempDir())
	tokenPath := filepath.Join(mount.Dir, "token")

	if body, err := os.ReadFile(tokenPath); err != nil || string(body) != leaseSecret {
		t.Fatalf("the lease should have materialised the token file: %v / %q", err, body)
	}

	spec := executor.Spec{
		WorkDir: "revoke-project",
		// Prove the credential was readable, then watch it disappear. The
		// second line only ever prints if something removed the file out from
		// under a live process.
		Argv: []string{"/bin/sh", "-c",
			`cat "$GITHUB_TOKEN_FILE"; echo; ` +
				`n=0; while [ -f "$GITHUB_TOKEN_FILE" ] && [ $n -lt 300 ]; do n=$((n+1)); sleep 0.1; done; ` +
				`[ -f "$GITHUB_TOKEN_FILE" ] && echo STILL_THERE || echo TOKEN_FILE_GONE`},
		Env:     append(os.Environ(), mount.Env()...),
		Secrets: leaseBindings(lease, mount),
	}

	handle, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	lines, err := ex.Stream(context.Background(), handle.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}

	// Wait until the workload has actually read the credential, so the
	// revocation lands mid-run rather than before the process got going.
	var seen strings.Builder
	deadline := time.After(20 * time.Second)
readLoop:
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				break readLoop
			}
			seen.WriteString(line.Text)
			if strings.Contains(seen.String(), leaseSecret) {
				break readLoop
			}
		case <-deadline:
			t.Fatalf("workload never read its credential; output so far: %q", seen.String())
		}
	}

	// --- the revocation, with the task still running -----------------------
	res := ex.RevokeLease(context.Background(), remote.RevokePayload{
		LeaseID: lease.ID,
		Reason:  "e2e: operator revoked the grant",
		Action:  remote.RevokeScrub,
	})

	if res.State != remote.RevokeStateRevoked {
		t.Fatalf("revocation state = %q, want revoked (error=%q)", res.State, res.Error)
	}
	if res.Ack == nil {
		t.Fatal("a revoked lease must carry the agent's report")
	}
	if !res.Ack.Known {
		t.Error("the agent was holding this lease and must say so")
	}
	if res.Ack.FilesRemoved != 1 {
		t.Errorf("files_removed = %d, want 1 (the token file); errors=%q",
			res.Ack.FilesRemoved, res.Ack.Error)
	}
	if !containsString(res.Ack.EnvScrubbed, "GITHUB_TOKEN") {
		t.Errorf("env_scrubbed = %v, should include GITHUB_TOKEN", res.Ack.EnvScrubbed)
	}
	if res.Ack.Error != "" {
		t.Errorf("scrub reported errors: %s", res.Ack.Error)
	}

	// The credential is really gone from the filesystem, not merely forgotten.
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Errorf("the token file should be unlinked after a revoke; Stat err = %v", err)
	}

	// And the running task observes it. This is the assertion the whole
	// feature exists to make true.
	tail := drainUntil(t, lines, 30*time.Second, "TOKEN_FILE_GONE", "STILL_THERE")
	switch {
	case strings.Contains(tail, "STILL_THERE"):
		t.Error("the workload still had its credential after the revocation acked")
	case !strings.Contains(tail, "TOKEN_FILE_GONE"):
		t.Errorf("the workload never noticed its credential being revoked; output=%q", tail)
	}

	// The binding is released once the task ends, so a second revocation does
	// not chase a credential that went with the process.
	waitFor(t, 20*time.Second, func() bool { return !ex.HoldsLease(lease.ID) },
		"a finished workload should stop being reported as holding the lease")
}

// TestLoopbackRevokeKillTerminatesHolder covers the case scrubbing cannot
// reach: a credential handed to a process as an environment variable lives in
// that process's own memory, and killing the task is the only thing that
// actually stops its use.
func TestLoopbackRevokeKillTerminatesHolder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the loopback test runs POSIX shell commands")
	}
	lb := newLoopback(t)
	ex := lb.executor(t)

	lease, mount := mintLease(t, t.TempDir())
	spec := executor.Spec{
		WorkDir: "revoke-kill",
		Argv:    []string{"/bin/sh", "-c", `echo READY; sleep 120`},
		Env:     append(os.Environ(), mount.Env()...),
		Secrets: leaseBindings(lease, mount),
	}

	handle, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	lines, err := ex.Stream(context.Background(), handle.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if out := drainUntil(t, lines, 20*time.Second, "READY"); !strings.Contains(out, "READY") {
		t.Fatalf("workload never started; output=%q", out)
	}

	res := ex.RevokeLease(context.Background(), remote.RevokePayload{
		LeaseID: lease.ID,
		Reason:  "e2e: credential compromised",
		Action:  remote.RevokeKill,
	})
	if res.State != remote.RevokeStateRevoked {
		t.Fatalf("revocation state = %q, want revoked (error=%q)", res.State, res.Error)
	}
	if res.Ack == nil || len(res.Ack.Killed) != 1 {
		t.Fatalf("a kill revocation must report the handles it terminated; got %+v", res.Ack)
	}
	if res.Ack.Killed[0] != handle.ID {
		t.Errorf("killed = %v, want the handle holding the lease (%s)", res.Ack.Killed, handle.ID)
	}

	// The task really stops, well inside the `sleep 120` it would otherwise
	// have run for.
	waitFor(t, 30*time.Second, func() bool {
		st, err := ex.Status(context.Background(), handle.ID)
		return err == nil && st.State.Terminal()
	}, "the workload holding a killed lease should terminate promptly")
}

// TestLoopbackRevokeRefusesPathsOutsideALeaseDirectory is the confinement
// check. The control plane is a party this system's threat model treats as
// potentially compromised, and the revoke frame names paths — so it must not
// become an arbitrary-unlink primitive on every enrolled device.
func TestLoopbackRevokeRefusesPathsOutsideALeaseDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the loopback test runs POSIX shell commands")
	}
	lb := newLoopback(t)
	ex := lb.executor(t)

	// A file that is emphatically not lease material.
	victimDir := t.TempDir()
	victim := filepath.Join(victimDir, "important.conf")
	if err := os.WriteFile(victim, []byte("do not delete"), 0o600); err != nil {
		t.Fatalf("write victim: %v", err)
	}

	spec := executor.Spec{
		WorkDir: "confinement",
		Argv:    []string{"/bin/sh", "-c", "echo READY; sleep 60"},
		Secrets: []executor.SecretBinding{{
			LeaseID: "lease_evil",
			EnvKeys: []string{"NOTHING"},
			// A hostile hub naming a file it wants gone from the device.
			Files: []string{victim},
			Dir:   victimDir,
		}},
	}
	handle, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = ex.Signal(context.Background(), handle.ID, executor.SignalKill) })

	res := ex.RevokeLease(context.Background(), remote.RevokePayload{LeaseID: "lease_evil"})

	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("the agent unlinked a file outside any lease directory: %v", err)
	}
	if res.Ack == nil {
		t.Fatal("the agent should still ack, reporting the refusal")
	}
	if res.Ack.FilesRemoved != 0 {
		t.Errorf("files_removed = %d, want 0", res.Ack.FilesRemoved)
	}
	// Refusals are reported, not swallowed: "I did not delete your credential
	// file" is something the operator has to be told.
	if !strings.Contains(res.Ack.Error, "refused") {
		t.Errorf("the ack should report the refusal; error=%q", res.Ack.Error)
	}
}

// drainUntil reads lines until one of the sentinels appears or the timeout
// expires, returning everything read.
func drainUntil(t *testing.T, lines <-chan executor.LogLine, timeout time.Duration, sentinels ...string) string {
	t.Helper()
	var sb strings.Builder
	deadline := time.After(timeout)
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				return sb.String()
			}
			sb.WriteString(line.Text)
			for _, s := range sentinels {
				if strings.Contains(sb.String(), s) {
					return sb.String()
				}
			}
		case <-deadline:
			return sb.String()
		}
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
