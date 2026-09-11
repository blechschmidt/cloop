//go:build unix

package outlive_test

// The claim under test is about what the Go runtime does to a process, so it
// cannot be tested in-process: the failure being prevented is the test binary
// dying. Each case therefore re-execs this test binary as a child, wires its
// stdout to a pipe exactly as pkg/executor/localprocess wires a run's, kills
// the reader mid-flight, and asks the only question that matters — did the
// child finish its work and record the outcome, or did a log line kill it.
//
// The child reports through a file rather than through stdout, because stdout
// is the thing being broken.

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/outlive"
)

// Environment contract between the test and its re-exec'd child.
const (
	envChildProgress = "CLOOP_OUTLIVE_TEST_PROGRESS" // where the child records durable work
	envChildProtect  = "CLOOP_OUTLIVE_TEST_PROTECT"  // "1" to call outlive.ControlPlane
)

// doneMarker is the child's terminal status: the line a run writes only if it
// survived long enough to finish. Its absence is the bug.
const doneMarker = "TERMINAL STATUS"

// workUnits is how many work-then-log cycles the child performs. It needs to be
// comfortably more than the number that fit before the pipe breaks, so that an
// unprotected child is still mid-loop when its next log line kills it.
const workUnits = 10

// TestMain runs the child role when the environment selects it, and the test
// suite otherwise.
func TestMain(m *testing.M) {
	if path := os.Getenv(envChildProgress); path != "" {
		os.Exit(runChild(path, os.Getenv(envChildProtect) == "1"))
	}
	os.Exit(m.Run())
}

// runChild stands in for `cloop run`: it interleaves durable work with chatter
// on stdout, the way the orchestrator interleaves database writes with progress
// lines. Only the durable half is observable to the parent, which is the point
// — it is what survives in state.db when the noisy half turns lethal.
func runChild(progressPath string, protect bool) int {
	if protect {
		outlive.ControlPlane()
	}
	f, err := os.Create(progressPath)
	if err != nil {
		return 1
	}
	defer f.Close()

	for i := 1; i <= workUnits; i++ {
		fmt.Fprintf(f, "work %d\n", i)
		_ = f.Sync()
		// The lethal write, once the parent has closed the read end.
		fmt.Printf("progress: completed unit %d\n", i)
		time.Sleep(60 * time.Millisecond)
	}
	fmt.Fprintln(f, doneMarker)
	_ = f.Sync()
	return 0
}

// childRun is what a single scenario observed.
type childRun struct {
	units     int  // durable work units the child committed
	completed bool // whether it lived long enough to record its outcome
}

// runWithDyingHub starts the child with its stdout on a pipe, lets it get going,
// then closes the read end — the hub being OOM-killed — and reports how far the
// child got afterwards.
func runWithDyingHub(t *testing.T, protect bool) childRun {
	t.Helper()

	progress := filepath.Join(t.TempDir(), "progress.txt")
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("create output pipe: %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestMain")
	cmd.Stdout = pw
	cmd.Stderr = pw
	cmd.Env = append(os.Environ(),
		envChildProgress+"="+progress,
		envChildProtect+"="+map[bool]string{true: "1", false: "0"}[protect],
	)
	if err := cmd.Start(); err != nil {
		pr.Close()
		pw.Close()
		t.Fatalf("start child: %v", err)
	}
	// Like the hub, the parent holds no write end of its own; only the child
	// does, so closing the reader is what breaks the pipe for the child.
	pw.Close()

	// Drain briefly so the child's early writes succeed and it is genuinely
	// mid-loop — a child blocked on a full pipe would prove nothing.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		buf := make([]byte, 512)
		for {
			if _, err := pr.Read(buf); err != nil {
				return
			}
		}
	}()
	time.Sleep(200 * time.Millisecond)

	// The hub dies.
	pr.Close()
	<-drained

	// Reap the child however it ends: cleanly, or by the signal under test.
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	select {
	case <-waited:
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("child neither finished nor died within 30s")
	}

	return readProgress(t, progress)
}

func readProgress(t *testing.T, path string) childRun {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("read child progress: %v", err)
	}
	defer f.Close()

	var run childRun
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		switch line := strings.TrimSpace(sc.Text()); {
		case line == doneMarker:
			run.completed = true
		case strings.HasPrefix(line, "work "):
			run.units++
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan child progress: %v", err)
	}
	return run
}

// TestControlPlaneSurvivesABrokenStdoutPipe is the regression test proper: a run
// whose hub dies must still finish, because everything after the point it would
// otherwise die is work that silently does not happen.
func TestControlPlaneSurvivesABrokenStdoutPipe(t *testing.T) {
	got := runWithDyingHub(t, true)

	if !got.completed {
		t.Errorf("child did not record its terminal status after the hub died: "+
			"it committed %d/%d work units then stopped — this is the stall "+
			"that leaves a task in_progress and a project status of \"running\" "+
			"with nothing behind it", got.units, workUnits)
	}
	if got.units != workUnits {
		t.Errorf("child committed %d work units after the hub died, want all %d",
			got.units, workUnits)
	}
}

// TestBrokenStdoutPipeIsFatalWithoutControlPlane pins the behaviour being
// defended against. If Go ever stops making SIGPIPE fatal on descriptors 1 and
// 2, this test fails and ControlPlane becomes dead weight that can be deleted —
// which is worth being told about, and is the only way to know the test above
// is still testing something.
func TestBrokenStdoutPipeIsFatalWithoutControlPlane(t *testing.T) {
	got := runWithDyingHub(t, false)

	if got.completed {
		t.Skip("writing to a broken stdout pipe is no longer fatal in this Go " +
			"runtime; outlive.ControlPlane may no longer be necessary")
	}
	if got.units == 0 {
		t.Fatal("child committed no work at all, so the pipe broke before the " +
			"scenario started — the test is not exercising what it claims")
	}
	if got.units >= workUnits {
		t.Errorf("child committed all %d work units but recorded no terminal "+
			"status; expected it to die partway", workUnits)
	}
}
