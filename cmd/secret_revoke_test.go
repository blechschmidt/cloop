package cmd

// `cloop secret revoke` revokes from a process that holds no lease, so it
// announces the revocation to the running hubs and says — honestly — whether
// any received it (Task 20403). That a running member answers and takes the
// grant back is pkg/ui's TestACLIRevocationReachesARunningHubThroughTheBus;
// these pin what the command prints when none does.

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// revokeWorld is a hub directory holding one granted secret, with the command
// run from inside it as an operator would.
func revokeWorld(t *testing.T) (dir, grantID string) {
	t.Helper()
	dir = hubDir(t)
	t.Setenv(secretbroker.EnvPassphraseKey, "cmd-secret-revoke-test-passphrase")
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := secretbroker.New(store)
	if err != nil {
		t.Fatal(err)
	}
	sec, err := broker.Mint(context.Background(), secretbroker.MintRequest{Name: "deploy-pat",
		Kind: secretbroker.KindGitHubPAT, Payload: []byte("ghp_REVOKEREVOKEREVOKEREVOKEREVOKE0000"), Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	g, err := broker.Grant(context.Background(), secretbroker.GrantRequest{SecretRef: sec.ID,
		Subject:     secretbroker.Subject{Type: secretbroker.SubjectProject, Value: "/srv/app"},
		Constraints: secretbroker.Constraints{Repos: []string{"corp/app"}}, TTL: time.Hour, Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	prev := secretRevokeWait
	secretRevokeWait = 700 * time.Millisecond
	t.Cleanup(func() { secretRevokeWait = prev })
	return dir, g.ID
}

func runSecretRevoke(t *testing.T, grantID string) string {
	t.Helper()
	out, err := captureStdout(t, func() error {
		secretRevokeCmd.SetContext(context.Background())
		return secretRevokeCmd.RunE(secretRevokeCmd, []string{grantID})
	})
	if err != nil {
		t.Fatalf("secret revoke: %v\n%s", err, out)
	}
	return out
}

// TestSecretRevokeSaysNoHubWasRunning: with no hub serving the control plane
// there is no lease anywhere to take back, and the command says so rather than
// leaving the operator to guess.
func TestSecretRevokeSaysNoHubWasRunning(t *testing.T) {
	_, grantID := revokeWorld(t)
	out := runSecretRevoke(t, grantID)
	if !strings.Contains(out, "revoked grant "+grantID) {
		t.Fatalf("output does not confirm the revocation:\n%s", out)
	}
	if !strings.Contains(out, "No hub is serving this control plane") {
		t.Errorf("output does not say that no hub was there to take it back:\n%s", out)
	}

	// And the repeat is a no-op that says when it happened.
	again := runSecretRevoke(t, grantID)
	if !strings.Contains(again, "already revoked") {
		t.Errorf("a repeat revocation did not say it was already revoked:\n%s", again)
	}
}

// TestSecretRevokeNamesAMemberThatDidNotAnswer: a member the control plane
// believes alive that does not answer is named, with what that means — never
// reported as having taken the grant back.
func TestSecretRevokeNamesAMemberThatDidNotAnswer(t *testing.T) {
	dir, grantID := revokeWorld(t)
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	host, _ := os.Hostname()
	if err := db.JoinHubMember(statedb.HubMemberRow{
		InstanceID: "hub-silent", Hostname: host + "-elsewhere", PID: 1, Meta: "{}",
		StartedAt: time.Now(), HeartbeatAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	out := runSecretRevoke(t, grantID)
	if !strings.Contains(out, "hub member hub-silent did not answer") {
		t.Errorf("the silent member is not named:\n%s", out)
	}
	if strings.Contains(out, "taken back from") {
		t.Errorf("the output claims a take-back nobody reported:\n%s", out)
	}

	// The announcement is on the bus for the member to act on when it reads it.
	db, err = statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	evs, err := db.HubEventsAfter(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var announced bool
	for _, ev := range evs {
		if ev.Key == "grant" && strings.Contains(ev.Payload, grantID) {
			announced = true
		}
	}
	if !announced {
		t.Error("no announcement was written to the bus")
	}
}
