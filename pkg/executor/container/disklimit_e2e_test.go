package container

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/internal/diskwatch"
)

// TestIntegration_DiskLimitStopsAWorkloadThatWritesPastIt runs a real sandbox
// that writes past a 64 MB disk limit, and holds the driver to everything Task
// 20405 promises of it: the workload is stopped, its status says disk_limit
// with both sizes, the overshoot is bounded by the write rate times the
// sampling interval, and starting again over the full workspace is refused.
//
// Opt-in, because it writes over a hundred megabytes through a container and
// waits for the sampler: a podman-backed test of that weight starves its
// package siblings' deadlines when it runs by default. Run it with
//
//	CLOOP_CONTAINER_DISK_E2E=1 go test ./pkg/executor/container -run DiskLimitStops -v
func TestIntegration_DiskLimitStopsAWorkloadThatWritesPastIt(t *testing.T) {
	if os.Getenv("CLOOP_CONTAINER_DISK_E2E") != "1" {
		t.Skip("set CLOOP_CONTAINER_DISK_E2E=1 to run the container disk-limit e2e (it writes >100 MB into a sandbox)")
	}
	executor.ResetResourceCeiling()
	t.Cleanup(executor.ResetResourceCeiling)
	// CLOOP_CONTAINER_DISK_E2E_RUNTIME picks the engine — the default is the
	// one DetectRuntime prefers, podman on a machine with both — and
	// CLOOP_CONTAINER_DISK_E2E_OCI_RUNTIME the low-level runtime, so the same
	// test proves the host-side walk under gVisor or Kata, whose sandboxes
	// write the same bind mount.
	ex := newTestExecutor(t, defaultTestImage, func(o *Options) {
		o.Runtime = strings.TrimSpace(os.Getenv("CLOOP_CONTAINER_DISK_E2E_RUNTIME"))
		o.OCIRuntime = strings.TrimSpace(os.Getenv("CLOOP_CONTAINER_DISK_E2E_OCI_RUNTIME"))
	})
	// A quicker schedule than production's, so the test is about the stop and
	// not about waiting: it still bounds each sample by its cost.
	ex.diskPolicy = diskwatch.Policy{MinInterval: 200 * time.Millisecond, MaxInterval: time.Second,
		CostFactor: 10, Deadline: 30 * time.Second}

	project := t.TempDir()
	// One megabyte at a time, written for real (dd from /dev/zero allocates
	// every block), to 200 MB — far past the limit — then a marker the
	// workload must never reach.
	script := `i=0
while [ $i -lt 200 ]; do
  dd if=/dev/zero of=/workspace/fill.$i bs=1M count=1 2>/dev/null || exit 3
  i=$((i+1))
  sleep 0.02
done
echo WROTE-EVERYTHING
sleep 60`
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	h, err := ex.Start(ctx, executor.Spec{
		WorkDir:        project,
		Argv:           []string{"sh", "-c", script},
		ResourceLimits: executor.ResourceLimits{DiskMB: 64},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Read the stream to its end, which is the workload's terminal status:
	// stopping at a marker would race the reaper.
	lines, err := ex.Stream(ctx, h.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	var out strings.Builder
	for l := range lines {
		out.WriteString(l.Text)
	}
	st, err := ex.Status(ctx, h.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	t.Logf("status: %+v", st)
	t.Logf("output:\n%s", out.String())

	if strings.Contains(out.String(), "WROTE-EVERYTHING") {
		t.Fatal("the workload wrote all 200 MB: nothing held it to its 64 MB limit")
	}
	if st.State != executor.StateKilled || st.Outcome != executor.OutcomeDiskLimit || st.DiskLimit == nil {
		t.Fatalf("status = %+v, want killed with outcome disk_limit", st)
	}
	b := *st.DiskLimit
	if b.LimitMB != 64 || !b.Over() || b.Source != executor.DiskLimitFromSpec {
		t.Fatalf("breach = %+v", b)
	}
	if !strings.Contains(st.Error, "stopped at its disk limit") || !strings.Contains(st.Error, "64 MB") {
		t.Fatalf("Error = %q, want the stop named with the limit", st.Error)
	}
	if !strings.Contains(out.String(), "[cloop] disk limit:") {
		t.Fatal("the workload's own log does not say why it stopped")
	}
	// The overshoot is the write rate times the interval: at most a second's
	// sampling at well under 100 MB/s here. Generous, and still far below the
	// 200 MB the workload would have written.
	if b.UsedMB() > 150 {
		t.Fatalf("stopped at %d MB: the overshoot is not bounded by the sampling interval", b.UsedMB())
	}

	// The workspace is still over the limit, so a second start is refused
	// before anything is created — the loop a paused run must not fall into.
	_, err = ex.Start(ctx, executor.Spec{
		WorkDir:        project,
		Argv:           []string{"true"},
		ResourceLimits: executor.ResourceLimits{DiskMB: 64},
	})
	var refused *executor.DiskLimitError
	if !errors.As(err, &refused) {
		t.Fatalf("restart over a full workspace = %v, want a DiskLimitError", err)
	}
	t.Logf("restart refused: %v", err)
}
