package remote

import (
	"context"
	"testing"
	"time"
)

// TestARunnerRetiredBeforeItsSessionAttachesIsToldSo: the hub writes a
// runner's welcome and only then attaches its session to the executor, so a
// Retire landing in between finds no session to tell — it marks the executor
// retired and returns, and the runner, already holding its welcome, was left
// connected and never sent its bye. CI hit that window under load
// (TestRunnerTokenEnrollsAnEphemeralExecutorAndRetireEndsIt timing out on
// "read bye"). The attach now finds the mark and retires the session itself.
func TestARunnerRetiredBeforeItsSessionAttachesIsToldSo(t *testing.T) {
	ex, err := NewExecutor(Options{ID: "runner-1", Name: "pool-runner", Ephemeral: true})
	if err != nil {
		t.Fatal(err)
	}
	// What Hub.Retire leaves behind when no session is attached yet.
	ex.retired.Store(true)

	cp, agent := NewPipe(16)
	accepted := make(chan *Session, 1)
	go func() {
		sess, err := Accept(context.Background(), cp, AcceptOptions{Agent: AgentRecord{AgentID: "runner-1"}, Executor: ex})
		if err != nil {
			t.Errorf("Accept: %v", err)
		}
		accepted <- sess
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hello, err := NewFrame(TypeHello, "hello", "", HelloPayload{AgentID: "runner-1", ProtocolVersion: ProtocolVersion})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.WriteFrame(ctx, hello); err != nil {
		t.Fatal(err)
	}
	welcomed := false
	for {
		f, err := agent.ReadFrame(ctx)
		if err != nil {
			t.Fatalf("read: %v (welcome received: %v) — the retired runner was never told", err, welcomed)
		}
		if f.Type == TypeWelcome {
			welcomed = true
			continue
		}
		if f.Type != TypeBye {
			continue
		}
		bye, err := DecodeBye(f)
		if err != nil {
			t.Fatal(err)
		}
		if !welcomed || !bye.Retired || bye.Reconnect {
			t.Fatalf("bye %+v after a welcome %v: want the welcome, then retired and no reconnect", bye, welcomed)
		}
		break
	}
	sess := <-accepted
	if sess == nil {
		t.Fatal("Accept returned no session")
	}
	select {
	case <-sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the retired runner's session is still open")
	}
	ex.mu.RLock()
	status := ex.status
	ex.mu.RUnlock()
	if status == StatusOnline {
		t.Error("a runner retired before its session attached was reported online")
	}
}
