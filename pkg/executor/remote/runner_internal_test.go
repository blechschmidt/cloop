package remote

import (
	"errors"
	"testing"
)

// An executor pool's runner takes one workload, ever (Task 20482): the slot is
// claimed once, given back only by a start refused before a handle existed,
// and an ordinary device is never limited.
func TestEphemeralExecutorTakesOneWorkload(t *testing.T) {
	ex, err := NewExecutor(Options{ID: "runner-1", Name: "pool-runner", Ephemeral: true})
	if err != nil {
		t.Fatal(err)
	}
	release, err := ex.claimRunner()
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if !ex.Spent() {
		t.Fatal("a claimed runner does not report spent")
	}
	if _, err := ex.claimRunner(); !errors.Is(err, ErrRunnerSpent) {
		t.Fatalf("second claim = %v, want ErrRunnerSpent", err)
	}
	// A start refused before it created a handle gives the slot back.
	release()
	if ex.Spent() {
		t.Fatal("a released runner still reports spent")
	}
	if _, err := ex.claimRunner(); err != nil {
		t.Fatalf("claim after release: %v", err)
	}
	// Once a handle exists the runner stays spent, released or not.
	ex.mu.Lock()
	ex.handles["h-1"] = &handleState{id: "h-1"}
	ex.mu.Unlock()
	if !ex.Spent() {
		t.Fatal("a runner with a handle does not report spent")
	}

	device, _ := NewExecutor(Options{ID: "edge-1", Name: "edge"})
	for i := 0; i < 3; i++ {
		if _, err := device.claimRunner(); err != nil {
			t.Fatalf("an ordinary device was limited: %v", err)
		}
	}
	if device.Ephemeral() || device.Spent() {
		t.Fatal("an ordinary device reports itself ephemeral or spent")
	}
}
