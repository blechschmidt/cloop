package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// An executor pool's runner (Task 20482): told it is ephemeral, the agent keeps
// its credential in memory, reconnects with it, and ends Run with success when
// the hub retires it — the exit a Kubernetes Pod reads as "done".
func TestEphemeralRunnerKeepsItsCredentialInMemoryAndExitsCleanlyWhenRetired(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "agent.json")
	a, conns := newScriptedAgent(t, credPath, filepath.Join(dir, "work"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	cp := <-conns
	f := cp.readUntil(remote.TypeHello, 5*time.Second)
	welcome, err := remote.NewFrame(remote.TypeWelcome, f.ID, "", remote.WelcomePayload{
		ProtocolVersion: remote.ProtocolVersion, ExecutorID: "runner-1",
		Credential: "clac1.runner-1.secret.mac", HeartbeatSeconds: int(remote.HeartbeatInterval / time.Second),
		Ephemeral: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	cp.write(welcome)
	waitFor(t, 5*time.Second, a.isEphemeral, "the agent should know it is an ephemeral runner")
	if _, err := os.Stat(credPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an ephemeral runner wrote its credential to %s (%v)", credPath, err)
	}

	// A dropped link: it reconnects with the credential it holds in memory.
	_ = cp.conn.Close("link dropped")
	cp = <-conns
	hello := cp.handshake(t, "runner-1", nil, "")
	if hello.AgentID != "runner-1" {
		t.Fatalf("the reconnecting runner claims %q, want runner-1", hello.AgentID)
	}
	if tok, enrolling := a.authToken(); enrolling || tok != "clac1.runner-1.secret.mac" {
		t.Fatalf("the runner reconnects with %q (enrolling %v)", tok, enrolling)
	}

	bye, err := remote.NewFrame(remote.TypeBye, "", "", remote.ByePayload{Reason: "its run settled", Retired: true})
	if err != nil {
		t.Fatal(err)
	}
	cp.write(bye)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a retired runner's Run returned %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the retired runner did not stop")
	}
}

// A device that is not a runner reads the same bye as a refusal: the retired
// flag means nothing to an agent that never heard it was ephemeral.
func TestRetiredByeRefusesAnAgentThatIsNoRunner(t *testing.T) {
	dir := t.TempDir()
	a, conns := newScriptedAgent(t, filepath.Join(dir, "agent.json"), filepath.Join(dir, "work"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	cp := <-conns
	cp.handshake(t, "edge-1", nil, "clac1.edge-1.secret.mac")
	bye, _ := remote.NewFrame(remote.TypeBye, "", "", remote.ByePayload{Reason: "retired", Retired: true})
	cp.write(bye)
	select {
	case err := <-done:
		if !errors.Is(err, errDoNotReconnect) {
			t.Fatalf("Run returned %v, want a permanent refusal", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the agent did not stop")
	}
}
