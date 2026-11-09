package localprocess

// A workload started for Run is collected whole (Task 20481). Stream drops
// what a consumer falls behind on, which Run used to inherit: a helper
// subcommand's 2.8 MB reply, read by a goroutine the scheduler left waiting
// for a millisecond on a loaded host, came back with its middle missing, and
// the hub recorded the shorter document as the spec file it had read.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// blastLines is how many lines modeBlast writes: about 3.4 MB, some eight
// hundred of the pump's 4 KiB chunks against a subscriber's 512.
const blastLines = 260_000

// blastOutput is exactly what modeBlast writes.
func blastOutput() string {
	var b strings.Builder
	b.Grow(blastLines * 13)
	for i := 0; i < blastLines; i++ {
		fmt.Fprintf(&b, "blast-%06d\n", i)
	}
	return b.String()
}

// TestACollectedStreamLosesNothingToAStalledConsumer: the consumer
// StartCollected attaches is handed every chunk from the first, in order,
// however long it leaves them unread — the workload's output waits for it.
func TestACollectedStreamLosesNothingToAStalledConsumer(t *testing.T) {
	ex := New("test")
	consumer, stop := context.WithCancel(context.Background())
	defer stop()
	h, lines, err := ex.StartCollected(context.Background(), fixtureSpec(t, modeBlast, t.TempDir()), consumer)
	if err != nil {
		t.Fatalf("StartCollected: %v", err)
	}
	t.Cleanup(func() { _ = ex.Signal(context.Background(), h.ID, executor.SignalKill) })

	// Long enough for the workload to fill a dropping subscriber's buffer
	// several times over.
	time.Sleep(500 * time.Millisecond)

	var (
		got  strings.Builder
		want uint64 = 1
	)
	deadline := time.After(60 * time.Second)
	for done := false; !done; {
		select {
		case line, ok := <-lines:
			if !ok {
				done = true
				break
			}
			if line.Seq != want {
				t.Fatalf("chunk %d arrived where %d was due: the collected stream dropped output", line.Seq, want)
			}
			want++
			got.WriteString(line.Text)
		case <-deadline:
			t.Fatalf("the collected stream did not close; %d bytes so far", got.Len())
		}
	}
	if exp := blastOutput(); got.String() != exp {
		t.Fatalf("collected %d bytes, want the workload's %d exactly", got.Len(), len(exp))
	}
	st, err := ex.Status(context.Background(), h.ID)
	if err != nil || st.State != executor.StateExited || st.ExitCode != 0 {
		t.Fatalf("Status = %+v, %v; want a clean exit", st, err)
	}

	// And Run, which starts through it, hands back the same.
	res, err := executor.Run(context.Background(), ex, fixtureSpec(t, modeBlast, t.TempDir()))
	if err != nil || res.Dropped || string(res.Output) != blastOutput() {
		t.Fatalf("Run = %d bytes (dropped %v), %v; want the whole output", len(res.Output), res.Dropped, err)
	}
}

// TestACollectedStreamsConsumerLeavingReleasesTheWorkload: a consumer that
// stops reading and goes — its context cancelled, as Run's is when it returns
// — no longer holds the workload's output back: the workload finishes.
func TestACollectedStreamsConsumerLeavingReleasesTheWorkload(t *testing.T) {
	ex := New("test")
	consumer, leave := context.WithCancel(context.Background())
	h, lines, err := ex.StartCollected(context.Background(), fixtureSpec(t, modeBlast, t.TempDir()), consumer)
	if err != nil {
		t.Fatalf("StartCollected: %v", err)
	}
	t.Cleanup(func() { _ = ex.Signal(context.Background(), h.ID, executor.SignalKill) })
	select {
	case <-lines:
	case <-time.After(30 * time.Second):
		t.Fatal("the workload wrote nothing")
	}
	// Held back now: the consumer read one chunk and stopped.
	time.Sleep(200 * time.Millisecond)
	if st, err := ex.Status(context.Background(), h.ID); err != nil || st.State != executor.StateRunning {
		t.Fatalf("Status = %+v, %v; want the workload held back while its consumer is still there", st, err)
	}
	leave()
	deadline := time.Now().Add(30 * time.Second)
	for {
		st, err := ex.Status(context.Background(), h.ID)
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		if st.State.Terminal() {
			if st.State != executor.StateExited || st.ExitCode != 0 {
				t.Fatalf("Status = %+v; want the workload to have finished on its own", st)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the workload was still %s 30s after its consumer left", st.State)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The channel the consumer abandoned is closed, not left open.
	for range lines { //nolint:revive // drain to the close
	}
}
