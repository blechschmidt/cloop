package procgroup

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestParseStat(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantComm string
		wantPGID int
		wantErr  bool
	}{
		{
			name:     "ordinary process",
			line:     "1234 (python3) S 1 4321 4321 0 -1 4194304 100 0 0 0 5 2 0 0 20 0 1 0 987654",
			wantComm: "python3",
			wantPGID: 4321,
		},
		{
			// A binary may be named anything. Splitting this line on
			// whitespace from the left reads "0" as the pgid and would
			// silently mis-attribute — or fail to attribute — the process.
			name:     "comm containing spaces and parens",
			line:     "1234 (evil ) 0 R 1 9) S 1 4321 4321 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5",
			wantComm: "evil ) 0 R 1 9",
			wantPGID: 4321,
		},
		{
			name:     "comm that is only parens",
			line:     "7 (()) S 1 42 42 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5",
			wantComm: "()",
			wantPGID: 42,
		},
		{name: "no parens", line: "1234 python3 S 1 4321", wantErr: true},
		{name: "truncated after comm", line: "1234 (x) S", wantErr: true},
		{name: "unparsable pgid", line: "1234 (x) S 1 notanumber 1 0", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			comm, _, pgid, err := parseStat(tc.line)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got comm=%q pgid=%d", comm, pgid)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseStat: %v", err)
			}
			if comm != tc.wantComm {
				t.Errorf("comm = %q, want %q", comm, tc.wantComm)
			}
			if pgid != tc.wantPGID {
				t.Errorf("pgid = %d, want %d", pgid, tc.wantPGID)
			}
		})
	}
}

// writeFakeProc builds a procfs fixture so Members can be tested against a
// known process table instead of whatever happens to be running.
func writeFakeProc(t *testing.T, entries map[int]string) string {
	t.Helper()
	root := t.TempDir()
	for pid, line := range entries {
		dir := filepath.Join(root, strconv.Itoa(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(line), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Non-pid entries exist in a real procfs and must be skipped.
	for _, name := range []string{"self", "meminfo", "sys"} {
		_ = os.MkdirAll(filepath.Join(root, name), 0o755)
	}
	return root
}

func TestMembersFiltersGroup(t *testing.T) {
	root := writeFakeProc(t, map[int]string{
		100: "100 (train.py) S 1 500 500 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5",
		101: "101 (helper) S 1 500 500 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5",
		200: "200 (unrelated) S 1 700 700 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5",
		// A zombie has finished its work and is only awaiting reaping.
		// Counting it would make a drain loop wait forever.
		102: "102 (finished) Z 1 500 500 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5",
	})
	old := procRoot
	procRoot = root
	defer func() { procRoot = old }()

	members, err := Members(500)
	if err != nil {
		t.Fatalf("Members: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("got %d members %+v, want 2 (zombie excluded)", len(members), members)
	}
	if members[0].PID != 100 || members[0].Command != "train.py" {
		t.Errorf("unexpected first member %+v", members[0])
	}
	if members[1].PID != 101 {
		t.Errorf("unexpected second member %+v", members[1])
	}

	empty, err := Members(999)
	if err != nil {
		t.Fatalf("Members(999): %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("expected empty group, got %+v", empty)
	}
}

func TestMembersRejectsInvalidPGID(t *testing.T) {
	if _, err := Members(0); err == nil {
		t.Error("Members(0) should error")
	}
	if _, err := Members(-1); err == nil {
		t.Error("Members(-1) should error")
	}
}

// TestTerminateRefusesOwnGroup guards the property with the worst blast
// radius in this package: cloop's control plane is a long-lived service, and
// signalling its own group by negative pid would kill the service and every
// project it is running.
func TestTerminateRefusesOwnGroup(t *testing.T) {
	if !Supported() {
		t.Skip("not linux")
	}
	own, err := syscall.Getpgid(os.Getpid())
	if err != nil {
		t.Fatalf("Getpgid: %v", err)
	}
	if _, err := Terminate(own, 0); err == nil {
		t.Fatal("Terminate must refuse the caller's own process group")
	}
	for _, bad := range []int{0, 1, -5} {
		if _, err := Terminate(bad, 0); err == nil {
			t.Errorf("Terminate(%d) must be refused", bad)
		}
	}
}

// startGroup runs sh in its own process group, leaving a background sleep
// behind, and returns the group id after the shell itself is reaped. This is
// the exact shape the fix exists to catch.
func startGroup(t *testing.T, script string) int {
	t.Helper()
	cmd := exec.Command("sh", "-c", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Discard output so a background child holding the pipe cannot block Wait;
	// this mirrors nohup's default redirection.
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	pgid := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v", err)
	}
	return pgid
}

func TestDrainDetectsAndWaitsForBackgroundWork(t *testing.T) {
	if !Supported() {
		t.Skip("not linux")
	}
	// The shell exits immediately; the sleep it forked stays in the group.
	pgid := startGroup(t, "sleep 1 & exit 0")
	defer func() { _, _ = Terminate(pgid, 0) }()

	out := Drain(context.Background(), pgid, DrainOptions{
		Grace:  50 * time.Millisecond,
		Budget: 10 * time.Second,
		Poll:   50 * time.Millisecond,
	})
	if out.Detected == 0 {
		t.Fatal("expected to detect the background sleep")
	}
	if !out.Drained {
		t.Fatalf("expected the group to drain within budget, got %+v", out)
	}
	if !out.Clean() {
		t.Error("a drained group is clean")
	}
	if out.Waited < 900*time.Millisecond {
		t.Errorf("Drain returned after %v; it must actually wait for the work", out.Waited)
	}
	if len(out.Commands) == 0 {
		t.Error("Commands must name what was running, for diagnosis")
	}
}

func TestDrainReportsSurvivorsPastBudget(t *testing.T) {
	if !Supported() {
		t.Skip("not linux")
	}
	pgid := startGroup(t, "sleep 30 & exit 0")
	defer func() { _, _ = Terminate(pgid, 0) }()

	out := Drain(context.Background(), pgid, DrainOptions{
		Grace:  50 * time.Millisecond,
		Budget: 300 * time.Millisecond,
		Poll:   50 * time.Millisecond,
	})
	if out.Detected == 0 {
		t.Fatal("expected to detect the background sleep")
	}
	if out.Drained {
		t.Fatal("a 30s sleep cannot drain inside a 300ms budget")
	}
	if out.Clean() {
		t.Error("work that outlived the budget is not clean")
	}
	if len(out.Survivors) == 0 {
		t.Error("survivors must be reported so the failure names its cause")
	}
}

func TestDrainCleanWhenHarnessLeavesNothing(t *testing.T) {
	if !Supported() {
		t.Skip("not linux")
	}
	pgid := startGroup(t, "exit 0")

	start := time.Now()
	out := Drain(context.Background(), pgid, DrainOptions{
		Grace:  2 * time.Second,
		Budget: 5 * time.Second,
		Poll:   50 * time.Millisecond,
	})
	elapsed := time.Since(start)
	if out.Detected != 0 {
		t.Fatalf("well-behaved harness must report nothing, got %+v", out)
	}
	if !out.Clean() {
		t.Error("Clean() must hold when nothing was detected")
	}
	// The common case must not pay the grace window: this runs after every
	// task in every project, and a 2s tax on all of them to catch the few
	// that background work would be a bad trade.
	if elapsed > time.Second {
		t.Errorf("clean path took %v; it must not wait out the grace window", elapsed)
	}
}

// TestDrainGraceIgnoresTeardownRace covers the false-positive that would make
// this feature unusable: harnesses routinely leave children exiting a few
// milliseconds behind them, and treating those as abandoned work would flag
// every task.
func TestDrainGraceIgnoresTeardownRace(t *testing.T) {
	if !Supported() {
		t.Skip("not linux")
	}
	pgid := startGroup(t, "sleep 0.2 & exit 0")

	out := Drain(context.Background(), pgid, DrainOptions{
		Grace:  1500 * time.Millisecond,
		Budget: 5 * time.Second,
		Poll:   50 * time.Millisecond,
	})
	if out.Detected != 0 {
		t.Fatalf("a child that exits inside the grace window is not background work, got %+v", out)
	}
}

func TestDrainRespectsContextCancellation(t *testing.T) {
	if !Supported() {
		t.Skip("not linux")
	}
	pgid := startGroup(t, "sleep 30 & exit 0")
	defer func() { _, _ = Terminate(pgid, 0) }()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	Drain(ctx, pgid, DrainOptions{Grace: 10 * time.Millisecond, Budget: time.Hour, Poll: 50 * time.Millisecond})
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Drain ignored cancellation, blocked %v", elapsed)
	}
}

func TestTerminateKillsGroup(t *testing.T) {
	if !Supported() {
		t.Skip("not linux")
	}
	pgid := startGroup(t, "sleep 30 & exit 0")

	n, err := Terminate(pgid, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("Terminate: %v", err)
	}
	if n == 0 {
		t.Fatal("expected to report the killed processes")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if m, _ := Members(pgid); len(m) == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("group survived Terminate")
}

func TestTerminateEmptyGroupIsNoOp(t *testing.T) {
	if !Supported() {
		t.Skip("not linux")
	}
	pgid := startGroup(t, "exit 0")
	n, err := Terminate(pgid, 0)
	if err != nil {
		t.Fatalf("Terminate on empty group: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 terminated, got %d", n)
	}
}

func TestCommandNamesDedupesAndBounds(t *testing.T) {
	var many []Process
	for i := 0; i < 50; i++ {
		many = append(many, Process{PID: i + 1, Command: "worker"})
	}
	names := commandNames(many)
	if len(names) != 1 || names[0] != "worker" {
		t.Fatalf("expected deduplication to a single name, got %v", names)
	}

	many = nil
	for i := 0; i < 50; i++ {
		many = append(many, Process{PID: i + 1, Command: "w" + strconv.Itoa(i)})
	}
	if names := commandNames(many); len(names) != maxReportedCommands {
		t.Fatalf("expected the list bounded to %d, got %d", maxReportedCommands, len(names))
	}

	unnamed := commandNames([]Process{{PID: 42}})
	if len(unnamed) != 1 || !strings.Contains(unnamed[0], "42") {
		t.Fatalf("a nameless process must still be identifiable, got %v", unnamed)
	}
}
