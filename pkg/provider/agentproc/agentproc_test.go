package agentproc

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

func TestResolveFillsDefaults(t *testing.T) {
	got := BackgroundPolicy{}.Resolve()
	if got.Grace != DefaultBackgroundGrace || got.Wait != DefaultBackgroundWait || got.TerminateGrace != DefaultTerminateGrace {
		t.Errorf("zero value must resolve to defaults, got %+v", got)
	}
	if got := (BackgroundPolicy{Wait: -1}).Resolve(); got.Wait != 0 {
		t.Errorf("negative Wait must resolve to no wait, got %v", got.Wait)
	}
	custom := BackgroundPolicy{Grace: time.Second, Wait: time.Hour, TerminateGrace: time.Minute}
	if got := custom.Resolve(); got != custom {
		t.Errorf("explicit values must be preserved, got %+v", got)
	}
}

// startGroup runs script in a process group of its own, as both providers
// start their CLI, and reaps the leader: what remains in the group is what
// the script left behind.
func startGroup(t *testing.T, script string) int {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("process-group detection is procfs-only")
	}
	cmd := exec.Command("bash", "-c", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Run(); err != nil {
		t.Fatalf("leader: %v", err)
	}
	return cmd.Process.Pid
}

func TestSettleWaitsForWorkLeftRunning(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "done")
	pgid := startGroup(t, `nohup bash -c 'sleep 3; touch `+marker+`' >/dev/null 2>&1 &`)

	var told []provider.BackgroundActivity
	got := Settle(context.Background(), pgid, BackgroundPolicy{Grace: 200 * time.Millisecond, Wait: time.Minute},
		func(a provider.BackgroundActivity) { told = append(told, a) })
	if got == nil || got.Detected == 0 || !got.Drained {
		t.Fatalf("work left running must be waited for and reported drained, got %+v", got)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("Settle returned before the work finished: %v", err)
	}
	if len(told) != 1 || told[0].Detected == 0 {
		t.Errorf("the wait must be announced once as it begins, got %+v", told)
	}
}

func TestSettleTerminatesWorkPastItsBudget(t *testing.T) {
	pgid := startGroup(t, `nohup sleep 120 >/dev/null 2>&1 &`)
	got := Settle(context.Background(), pgid, BackgroundPolicy{
		Grace: 200 * time.Millisecond, Wait: 500 * time.Millisecond, TerminateGrace: time.Second}, nil)
	if got == nil || got.Drained || !got.Incomplete() {
		t.Fatalf("work that outlives the budget makes the task incomplete, got %+v", got)
	}
	if got.Terminated == 0 {
		t.Errorf("work past its budget must be terminated, got %+v", got)
	}
}

func TestSettleDisabledReportsNothing(t *testing.T) {
	pgid := startGroup(t, `nohup sleep 2 >/dev/null 2>&1 &`)
	if got := Settle(context.Background(), pgid, BackgroundPolicy{Disabled: true}, nil); got != nil {
		t.Errorf("a disabled policy must report nothing, got %+v", got)
	}
}
