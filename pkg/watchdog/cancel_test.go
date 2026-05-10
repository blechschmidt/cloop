// Tests for the public Cancel method (Task 20140). Cancel is the seam the
// orchestrator's kill-request poller uses to abort a running task on manual
// status changes from the UI.
package watchdog

import (
	"context"
	"testing"
)

func TestCancel_FiresRegisteredCancel(t *testing.T) {
	w := &Watchdog{}
	var called int
	cancel := func() { called++ }
	w.Register(42, cancel)

	if fired := w.Cancel(42); !fired {
		t.Error("Cancel(42) = false, want true (cancel was registered)")
	}
	if called != 1 {
		t.Errorf("registered cancel called %d times, want 1", called)
	}
	// Cancel removes the entry so a second call is a no-op.
	if fired := w.Cancel(42); fired {
		t.Error("Cancel(42) second call = true; want false (entry should have been cleared)")
	}
	if called != 1 {
		t.Errorf("registered cancel called %d times after second Cancel, want 1", called)
	}
}

func TestCancel_UnknownTaskID(t *testing.T) {
	w := &Watchdog{}
	if fired := w.Cancel(99); fired {
		t.Error("Cancel on unknown id = true, want false")
	}
}

func TestCancel_NilWatchdog(t *testing.T) {
	var w *Watchdog
	if fired := w.Cancel(1); fired {
		t.Error("Cancel on nil watchdog returned true; want false (must not panic)")
	}
}

func TestCancel_PropagatesToContext(t *testing.T) {
	// End-to-end check: the orchestrator wraps a context.CancelFunc, so the
	// cancel registered here actually cancels a context — verify that.
	w := &Watchdog{}
	ctx, cancel := context.WithCancel(context.Background())
	w.Register(7, cancel)

	if fired := w.Cancel(7); !fired {
		t.Fatal("Cancel(7) = false; want true")
	}
	select {
	case <-ctx.Done():
		// expected
	default:
		t.Error("ctx.Done() not closed after Cancel; cancel func did not propagate")
	}
}
