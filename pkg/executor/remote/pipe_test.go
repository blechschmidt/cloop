package remote_test

// The in-memory pipe keeps a real connection's order: what was written before
// a close is read before the close is reported, and nothing is written after
// it. Before, a reader that had not caught up got the close half the time and
// lost the frames in front of it — an ephemeral runner's farewell, in
// pkg/executor/agent's TestEphemeralStoppedDuringItsRunStopsTheRun on CI.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

func TestPipeDeliversWhatWasWrittenBeforeItsClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Many rounds: the old select chose the close at random.
	for round := 0; round < 200; round++ {
		writer, reader := remote.NewPipe(8)
		for _, id := range []string{"one", "two", "three"} {
			f, err := remote.NewFrame(remote.TypeBye, id, "", remote.ByePayload{Reason: id})
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.WriteFrame(ctx, f); err != nil {
				t.Fatalf("round %d: write %s: %v", round, id, err)
			}
		}
		if err := writer.Close("the writer is done"); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"one", "two", "three"} {
			f, err := reader.ReadFrame(ctx)
			if err != nil {
				t.Fatalf("round %d: frame %s was lost to the close: %v", round, want, err)
			}
			if f.ID != want {
				t.Fatalf("round %d: read %q, want %q", round, f.ID, want)
			}
		}
		if _, err := reader.ReadFrame(ctx); !errors.Is(err, remote.ErrSessionClosed) {
			t.Fatalf("round %d: after the queued frames, read = %v, want the close", round, err)
		}
		f, _ := remote.NewFrame(remote.TypeBye, "late", "", remote.ByePayload{Reason: "late"})
		if err := writer.WriteFrame(ctx, f); !errors.Is(err, remote.ErrSessionClosed) {
			t.Fatalf("round %d: a write after the close = %v, want it refused", round, err)
		}
		if err := reader.WriteFrame(ctx, f); !errors.Is(err, remote.ErrSessionClosed) {
			t.Fatalf("round %d: a write from the other end after the close = %v, want it refused", round, err)
		}
	}
}
