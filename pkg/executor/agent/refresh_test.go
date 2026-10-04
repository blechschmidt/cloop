package agent

// The device's confinement for a refresh frame (Task 20375): it may only
// replace a file this device was given for that lease, in place.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/redact"
)

func refreshVault(t *testing.T) (*vault, string) {
	t.Helper()
	dir, err := os.MkdirTemp(t.TempDir(), "cloop-lease-")
	if err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(dir, "github-token")
	if err := os.WriteFile(token, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	v := newVault()
	v.bind("h1", []executor.SecretBinding{{
		LeaseID: "lease_v", GrantID: "grant_v", Dir: dir, Files: []string{token},
	}})
	v.own("h1", []string{token})
	return v, token
}

func refreshFile(name, content string) []executor.SecretFile {
	return []executor.SecretFile{{
		LeaseID: "lease_v", GrantID: "grant_v", Dir: "/run/cloop/cloop-lease-v",
		Name: name, Mode: 0o600, Content: []byte(content),
	}}
}

func TestVaultRefreshRewritesTheDeliveredFile(t *testing.T) {
	v, token := refreshVault(t)
	rep := v.refresh("lease_v", refreshFile("github-token", "second\n"))
	if !rep.Known || rep.rewritten != 1 || len(rep.errors) != 0 {
		t.Fatalf("refresh = %+v", rep)
	}
	got, err := os.ReadFile(token)
	if err != nil || string(got) != "second\n" {
		t.Fatalf("token file = %q, %v; want the refreshed content", got, err)
	}
	if info, _ := os.Stat(token); info.Mode().Perm() != 0o600 {
		t.Errorf("refreshed file mode = %v, want 0600", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(filepath.Dir(token))
	if len(entries) != 1 {
		t.Errorf("the lease directory holds %d entries after the refresh, want just the token", len(entries))
	}
}

func TestVaultRefreshPlantsNothing(t *testing.T) {
	v, token := refreshVault(t)
	rep := v.refresh("lease_v", refreshFile("authorized_keys", "ssh-ed25519 AAAA\n"))
	if rep.rewritten != 0 || len(rep.errors) == 0 {
		t.Fatalf("a file the lease never delivered was written: %+v", rep)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(token), "authorized_keys")); err == nil {
		t.Fatal("the refresh created a new file in the lease directory")
	}
	if rep := v.refresh("lease_other", refreshFile("github-token", "x\n")); rep.Known {
		t.Fatalf("a lease this device does not hold was reported known: %+v", rep)
	}
}

func TestVaultRefreshDoesNotFollowAPlantedLink(t *testing.T) {
	v, token := refreshVault(t)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(token); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, token); err != nil {
		t.Fatal(err)
	}
	rep := v.refresh("lease_v", refreshFile("github-token", "second\n"))
	if rep.rewritten != 0 || len(rep.errors) == 0 || !strings.Contains(strings.Join(rep.errors, ";"), "regular") {
		t.Fatalf("a symlink at the token path was refreshed: %+v", rep)
	}
	if got, _ := os.ReadFile(victim); string(got) != "untouched" {
		t.Fatal("the refresh wrote through a planted symlink")
	}
}

func TestVaultRefreshAfterAScrubPutsNothingBack(t *testing.T) {
	v, token := refreshVault(t)
	v.scrub("lease_v", "", nil)
	rep := v.refresh("lease_v", refreshFile("github-token", "second\n"))
	if rep.rewritten != 0 || len(rep.errors) == 0 {
		t.Fatalf("a scrubbed lease was refreshed: %+v", rep)
	}
	if _, err := os.Stat(token); !os.IsNotExist(err) {
		t.Fatal("a refresh after revocation brought the credential back")
	}
}

// TestVaultRefreshWritesOnlyWhatThisAgentPlaced: a start frame's bindings are
// the hub's word for what a lease covers. A compromised hub that bound another
// workload's lease file must not be able to overwrite it with a refresh.
func TestVaultRefreshWritesOnlyWhatThisAgentPlaced(t *testing.T) {
	v, _ := refreshVault(t)
	other, err := os.MkdirTemp(t.TempDir(), "cloop-lease-")
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(other, "git-credential-cloop")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\necho original\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	// The hub names that file in a second start for the same lease; the agent
	// placed nothing there.
	v.bind("h2", []executor.SecretBinding{{LeaseID: "lease_v", Dir: other, Files: []string{helper}}})
	rep := v.refresh("lease_v", refreshFile("git-credential-cloop", "#!/bin/sh\necho pwned\n"))
	if rep.rewritten != 0 || len(rep.errors) == 0 {
		t.Fatalf("a file this agent never placed was rewritten: %+v", rep)
	}
	if got, _ := os.ReadFile(helper); !strings.Contains(string(got), "original") {
		t.Fatalf("another workload's helper was overwritten: %q", got)
	}
}

// TestRefreshFrameExtendsTheWorkloadsRedaction: the frame extends the
// redaction of every workload holding the lease before it writes the file, so
// a terminal open on one scrubs the new token as well as the first.
func TestRefreshFrameExtendsTheWorkloadsRedaction(t *testing.T) {
	const first, second = "ghs_first_token_value_0001", "ghs_second_token_value_0002"
	v, token := refreshVault(t)
	a := &Agent{cfg: Config{Logf: t.Logf}, workloads: map[string]*workload{}, vault: v}
	wl := &workload{handleID: "h1"}
	wl.recordAttachContext(filepath.Dir(token), redact.New(first))
	a.workloads["h1"] = wl

	frame, err := remote.NewFrame(remote.TypeSecretRefresh, "refresh-1", "", remote.SecretRefreshPayload{
		LeaseID: "lease_v",
		Files:   []remote.SecretFile{remote.NewSecretFile(refreshFile("github-token", second+"\n")[0])},
	})
	if err != nil {
		t.Fatal(err)
	}
	agentSide, cpSide := remote.NewPipe(4)
	sess := &deviceSession{conn: agentSide, closed: make(chan struct{})}
	a.handleSecretRefresh(context.Background(), sess, frame)

	cp := &controlPlane{t: t, conn: cpSide}
	ack, err := remote.DecodeSecretRefreshed(cp.readUntil(remote.TypeSecretRefreshed, 5*time.Second))
	if err != nil || ack.FilesRewritten != 1 || ack.Error != "" {
		t.Fatalf("ack = %+v, %v; want the token file rewritten", ack, err)
	}
	if got, _ := os.ReadFile(token); string(got) != second+"\n" {
		t.Fatalf("token file = %q", got)
	}
	red := wl.redactor()
	if !red.Contains("x "+second+" y") || !red.Contains("x "+first+" y") {
		t.Error("the workload's redaction does not cover both the refreshed token and the first")
	}
}
