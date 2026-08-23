package ui

// The hub's half of secret-file delivery (Task 20192): which rendering of a
// lease each executor gets, and what happens when it can take neither.
//
// The decision lives in acquireSecretLease and applyLease, and it is the point
// where the delivery either becomes real or becomes the bug it replaced. Both
// directions are asserted here because both are silent when wrong: a lease
// materialised for a sandbox that cannot open the file leaves plaintext on the
// control plane for nothing, and a lease *not* refused on an executor that
// cannot receive files starts a workload holding paths to nowhere.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// seedPATGrant mints a repository-scoped GitHub PAT and grants it to
// executorID, returning the control-plane directory to lease against.
func seedPATGrant(t *testing.T, executorID, canary string) string {
	t.Helper()
	t.Setenv(secretbroker.EnvPassphraseKey, "secret-delivery-unit-passphrase")

	dir := t.TempDir()
	if _, err := state.Init(dir, "secret delivery", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	defer db.Close()

	store, err := secretstore.New(db)
	if err != nil {
		t.Fatalf("secretstore.New: %v", err)
	}
	broker, err := secretbroker.New(store, secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		t.Fatalf("secretbroker.New: %v", err)
	}
	sec, err := broker.Mint(t.Context(), secretbroker.MintRequest{
		Name: "delivery-pat", Kind: secretbroker.KindGitHubPAT,
		Payload: []byte(canary), Actor: "test",
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := broker.Grant(t.Context(), secretbroker.GrantRequest{
		SecretRef:   sec.ID,
		Subject:     secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: executorID},
		Constraints: secretbroker.Constraints{Repos: []string{"acme/*"}},
		TTL:         time.Hour, Actor: "test",
	}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	return dir
}

// TestIsolatedExecutorGetsTheBytesAndTheHubKeepsNoFile is the delivery split.
func TestIsolatedExecutorGetsTheBytesAndTheHubKeepsNoFile(t *testing.T) {
	const canary = "ghp_uidelivery0123456789abcdefghijkl"
	dir := seedPATGrant(t, "sandbox-1", canary)

	ex := stubExec{id: "sandbox-1", caps: executor.Capabilities{
		SupportsSecretFiles: true, SecretFilesFromHostPath: false,
	}}
	lease := acquireSecretLease(dir, "/srv/proj", ex)
	if lease == nil {
		t.Fatal("no lease was issued, so this test would be vacuous")
	}
	defer lease.Close()

	if lease.mount != nil {
		t.Error("the hub materialised a lease for an executor that cannot read hub paths: " +
			"plaintext on the control plane that nothing will ever open")
	}
	if lease.delivery == nil {
		t.Fatal("no in-memory delivery was prepared")
	}

	spec, err := applyLease(executor.Spec{Argv: []string{"cloop", "run"}}, ex, lease)
	if err != nil {
		t.Fatalf("applyLease refused an executor that supports secret files: %v", err)
	}
	if len(spec.SecretFiles) == 0 {
		t.Fatal("the spec carries no credential files, so the sandbox would get an environment " +
			"naming paths that do not exist there")
	}
	found := false
	for _, f := range spec.SecretFiles {
		if !filepath.IsAbs(f.Dir) {
			t.Errorf("credential file %s has a relative directory %q", f.Name, f.Dir)
		}
		if strings.Contains(string(f.Content), canary) {
			found = true
		}
	}
	if !found {
		t.Error("no delivered file carries the token")
	}

	// The delivery directory is nominal — it names a path inside the sandbox,
	// which is exactly why nothing on this host should exist at it.
	if _, err := os.Stat(spec.SecretFiles[0].Dir); !os.IsNotExist(err) {
		t.Errorf("the hub created %s on its own filesystem: %v", spec.SecretFiles[0].Dir, err)
	}
}

// TestHostPathExecutorStillGetsFilesOnDisk is the other branch: the driver that
// really does read the hub's filesystem must keep getting a materialised lease,
// or the delivery split would have fixed the sandboxes by breaking the host.
func TestHostPathExecutorStillGetsFilesOnDisk(t *testing.T) {
	const canary = "ghp_uihostpath0123456789abcdefghijkl"
	dir := seedPATGrant(t, "host-1", canary)

	ex := stubExec{id: "host-1", caps: executor.Capabilities{
		SupportsSecretFiles: true, SecretFilesFromHostPath: true,
	}}
	lease := acquireSecretLease(dir, "/srv/proj", ex)
	if lease == nil {
		t.Fatal("no lease was issued, so this test would be vacuous")
	}
	defer lease.Close()

	if lease.mount == nil {
		t.Fatal("no lease directory was materialised for a driver that reads hub paths")
	}
	spec, err := applyLease(executor.Spec{Argv: []string{"cloop", "run"}}, ex, lease)
	if err != nil {
		t.Fatalf("applyLease: %v", err)
	}
	// The bytes must *not* also travel on the Spec: the files are already on
	// the filesystem the workload reads, and carrying a second copy would put
	// plaintext into a struct for no delivery it enables.
	if len(spec.SecretFiles) != 0 {
		t.Errorf("a host-path lease also carried %d file(s) in the Spec", len(spec.SecretFiles))
	}
	if !spec.NeedsSecretFiles() {
		t.Error("the spec does not report needing credential files, so placement would not gate on them")
	}
	entries, err := os.ReadDir(lease.mount.Dir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("lease directory %s holds nothing: %v", lease.mount.Dir, err)
	}
}

// TestExecutorThatCannotTakeFilesIsRefused is the guarantee proper.
//
// A remote agent below the protocol floor runs work perfectly well; it simply
// has no field to receive credential bytes in, and it does not reject the
// field, it ignores it. Without this refusal the run starts, the harness
// executes, and the grant is absent — which is exactly the shape of the bug
// this task exists to close.
func TestExecutorThatCannotTakeFilesIsRefused(t *testing.T) {
	const canary = "ghp_uirefusal0123456789abcdefghijklm"
	dir := seedPATGrant(t, "old-edge", canary)

	ex := stubExec{id: "old-edge", caps: executor.Capabilities{
		Isolation: executor.IsolationRemote, SupportsSecretFiles: false,
	}}
	lease := acquireSecretLease(dir, "/srv/proj", ex)
	if lease == nil {
		t.Fatal("no lease was issued, so this test would be vacuous")
	}
	defer lease.Close()

	_, err := applyLease(executor.Spec{Argv: []string{"cloop", "run"}}, ex, lease)
	if err == nil {
		t.Fatal("a workload was allowed to start on an executor that cannot receive its credential files")
	}
	if !errors.Is(err, executor.ErrUnsupported) {
		t.Errorf("refusal does not wrap ErrUnsupported, so a handler cannot map it to a status: %v", err)
	}
	// The message has to name the executor, the credential and a way out; an
	// error an operator cannot act on is a crash with better grammar.
	for _, want := range []string{"old-edge", "github_pat", "delivery-pat", "upgrade"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not mention %q: %v", want, err)
		}
	}
	// And it must not leak the credential it is complaining about.
	if strings.Contains(err.Error(), canary) {
		t.Error("the refusal quotes the token")
	}
}
