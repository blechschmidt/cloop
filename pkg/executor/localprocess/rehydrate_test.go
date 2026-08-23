package localprocess

// Tests for surviving a control-plane restart (Task 20191).
//
// Two things are being proved here and they pull in opposite directions:
// that a handle whose process is still running comes back, and that a handle
// whose pid now belongs to somebody else emphatically does not. The second is
// the one with teeth — a driver that adopted on liveness alone would pass every
// reattachment test in this file and, on a busy host, occasionally SIGKILL a
// stranger's process — so the negative tests here run against a real live
// process that the test asserts is *still alive* afterwards.
//
// Everything forks the test binary through the existing fixtureSpec helper, so
// nothing depends on /bin/sh or on a particular PATH. Where a test needs a
// process the driver did not fork (adoption's whole premise), it starts one
// with exec.Command directly and leaves it unreaped, which is as close to
// "inherited by init" as a single test process can get.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// foreignProcess starts a long-lived child that no Executor owns and returns
// its pid plus a channel closed when it exits.
//
// It stands in for the process an adopting hub finds: alive, reachable through
// procfs, and belonging to nobody in this process's bookkeeping. The Wait
// goroutine is what lets a test tell "still running" from "we killed it",
// which is the assertion the recycled-pid test turns on.
func foreignProcess(t *testing.T) (pid int, exited <-chan struct{}) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable: %v", err)
	}
	cmd := exec.Command(self, "-test.run", "TestNothingMatches")
	cmd.Env = append(os.Environ(), fixtureEnv+"="+modeSleep)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start foreign process: %v", err)
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	})
	return cmd.Process.Pid, done
}

// savedRow is the durable row a previous control plane would have written for
// pid, with whatever identity the caller wants stamped on it.
func savedRow(handleID, executorID string, pid int, id procIdentity) executor.HandleRecord {
	return executor.HandleRecord{
		HandleID:    handleID,
		ExecutorID:  executorID,
		Driver:      executor.KindLocalProcess,
		ExternalID:  strconv.Itoa(pid),
		ProjectPath: "/srv/project",
		TaskID:      20191,
		PID:         pid,
		StartedAt:   time.Now().Add(-90 * time.Second),
		Meta:        id.meta(),
	}
}

// waitFor polls cond until it holds or the deadline passes. Rehydration's
// terminal transitions are driven by a watcher goroutine on a timer, so a
// fixed sleep would either be flaky or slow; this is neither.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", timeout, what)
}

// TestRehydrate_ReattachesAfterAControlPlaneRestart is the restart simulation
// and the whole point of the file: a driver forks a workload and is discarded,
// a new driver is built from the same store, and Stream, Status and Signal all
// answer for the still-running child instead of ErrHandleNotFound.
func TestRehydrate_ReattachesAfterAControlPlaneRestart(t *testing.T) {
	ctx := context.Background()
	store := executor.NewMemoryHandleStore()
	dir := t.TempDir()

	// The pre-restart control plane.
	first := New("restart-test")
	first.AttachHandleStore(store)
	h, err := first.Start(ctx, fixtureSpec(t, modeSleep, dir))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = first.Signal(ctx, h.ID, executor.SignalKill) })
	if store.Len() != 1 {
		t.Fatalf("Start persisted %d rows, want 1 — nothing can be reattached to without one", store.Len())
	}

	// The negative control. Without the store a rebuilt driver has exactly the
	// pre-Task-20191 behaviour, and asserting it here is what stops the
	// assertions below from being vacuous: they would pass on any driver that
	// answered for every handle ID it was handed.
	blind := New("restart-test")
	if _, err := blind.Status(ctx, h.ID); !errors.Is(err, executor.ErrHandleNotFound) {
		t.Fatalf("a driver with no handle store must not know %s; Status err = %v", h.ID, err)
	}

	// The restart. `first` is deliberately never touched again.
	second := New("restart-test")
	second.AttachHandleStore(store)

	st, err := second.Status(ctx, h.ID)
	if err != nil {
		t.Fatalf("Status after a restart: %v (ErrHandleNotFound here is the bug this task fixes)", err)
	}
	if st.State != executor.StateRunning {
		t.Fatalf("State = %q after adoption, want running — the child is still alive", st.State)
	}
	if st.PID != h.PID {
		t.Errorf("Status.PID = %d, want %d", st.PID, h.PID)
	}
	if !st.StartedAt.Equal(h.StartedAt.Truncate(0)) && st.StartedAt.IsZero() {
		t.Errorf("adopted handle lost its start time")
	}

	// Stream must not fail, and must be honest about what it can and cannot
	// deliver. The child's real output went with the previous process's pipe.
	lines, err := second.Stream(ctx, h.ID)
	if err != nil {
		t.Fatalf("Stream after a restart: %v", err)
	}
	var notice string
	select {
	case line, ok := <-lines:
		if !ok {
			t.Fatal("the reattached stream closed before saying anything")
		}
		notice = line.Text
	case <-time.After(10 * time.Second):
		t.Fatal("the reattached stream produced nothing within 10s")
	}
	for _, want := range []string{"control plane restarted", "cannot be recovered", strconv.Itoa(h.PID)} {
		if !strings.Contains(notice, want) {
			t.Errorf("the reattach notice must say %q; got %q", want, notice)
		}
	}

	// Signal must reach the adopted child. This is the operator pressing Stop on
	// a run that outlived the hub.
	if err := second.Signal(ctx, h.ID, executor.SignalKill); err != nil {
		t.Fatalf("Signal on an adopted handle: %v", err)
	}

	// The stream closes when the watcher notices the process is gone.
	collect(t, lines, 30*time.Second)

	st, err = second.Status(ctx, h.ID)
	if err != nil {
		t.Fatalf("Status after the adopted workload ended: %v", err)
	}
	if !st.State.Terminal() {
		t.Fatalf("State = %q after the process exited, want terminal", st.State)
	}
	// Failed, not exited(0). The exit status of a process this hub never forked
	// is unrecoverable, and reporting success would mark failed work as done.
	if st.State != executor.StateFailed || st.ExitCode == 0 {
		t.Errorf("adopted workload finished as {%q, %d}; an unknown exit status must not be reported "+
			"as a clean exit", st.State, st.ExitCode)
	}
	if !strings.Contains(st.Error, "exit status") {
		t.Errorf("Status.Error should say the exit status was unavailable; got %q", st.Error)
	}
	waitFor(t, 10*time.Second, "the spent row to be dropped", func() bool { return store.Len() == 0 })
}

// TestRehydrate_RefusesARecycledPid is the safety property. A row whose pid is
// alive but is no longer the process it was written for must be refused, not
// signalled: the pid belongs to something else on the host now, and SIGKILL to
// it is the driver destroying a bystander.
func TestRehydrate_RefusesARecycledPid(t *testing.T) {
	ctx := context.Background()
	pid, exited := foreignProcess(t)

	live, alive, err := probeProcess(pid)
	if err != nil {
		t.Skipf("procfs identity is unavailable on this host: %v", err)
	}
	if !alive {
		t.Fatalf("the fixture process %d is not running, so this test would prove nothing", pid)
	}

	// Exactly what a recycled pid looks like: the number is in the table and
	// running, but it was started at a different moment than the row records.
	stale := live
	stale.startTicks++

	store := executor.NewMemoryHandleStore()
	if err := store.PutHandle(savedRow("h-recycled", "recycle-test", pid, stale)); err != nil {
		t.Fatalf("PutHandle: %v", err)
	}

	ex := New("recycle-test")
	ex.AttachHandleStore(store)

	st, err := ex.Status(ctx, "h-recycled")
	if err != nil {
		t.Fatalf("Status on a refused adoption: %v — the caller is holding this handle ID and "+
			"deserves an answer, not ErrHandleNotFound", err)
	}
	if st.State != executor.StateFailed {
		t.Fatalf("State = %q for a row whose pid was recycled, want failed", st.State)
	}
	if !strings.Contains(st.Error, "recycled") {
		t.Errorf("Status.Error must name the cause; got %q", st.Error)
	}
	if store.Len() != 0 {
		t.Errorf("a row that can never be adopted must be dropped, %d left", store.Len())
	}

	// Signalling it must still be refused. This is the case that kills a
	// bystander if the identity check is only done at adoption time.
	if err := ex.Signal(ctx, "h-recycled", executor.SignalKill); err != nil {
		t.Fatalf("Signal on a refused handle = %v, want nil (the workload is already not running)", err)
	}

	select {
	case <-exited:
		t.Fatal("the driver killed a live process whose pid a stale row happened to name — this is " +
			"the bug pid identity exists to prevent")
	case <-time.After(1500 * time.Millisecond):
		// Still running, which is the assertion.
	}
}

// TestRehydrate_DropsRowForADeadPid: a row whose process is gone must be
// retired and deleted, not re-adopted on every boot for as long as the state
// database survives.
func TestRehydrate_DropsRowForADeadPid(t *testing.T) {
	ctx := context.Background()
	pid, exited := foreignProcess(t)

	id, alive, err := probeProcess(pid)
	if err != nil {
		t.Skipf("procfs identity is unavailable on this host: %v", err)
	}
	if !alive {
		t.Fatalf("the fixture process %d never ran", pid)
	}

	// Kill it and let the Wait goroutine reap it, so the pid is genuinely
	// released rather than held by a zombie.
	proc, err := os.FindProcess(pid)
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	_ = proc.Kill()
	select {
	case <-exited:
	case <-time.After(30 * time.Second):
		t.Fatal("the fixture process would not die")
	}

	store := executor.NewMemoryHandleStore()
	if err := store.PutHandle(savedRow("h-dead", "dead-test", pid, id)); err != nil {
		t.Fatalf("PutHandle: %v", err)
	}

	ex := New("dead-test")
	ex.AttachHandleStore(store)

	st, err := ex.Status(ctx, "h-dead")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.State != executor.StateFailed {
		t.Fatalf("State = %q for a dead pid, want failed", st.State)
	}
	// The pid could in principle have been handed to something else between the
	// reap and the adoption, in which case the refusal is a mismatch rather than
	// an absence. Both are refusals and both drop the row, so the assertion is
	// on the outcome the caller sees.
	if !strings.Contains(st.Error, "could not be reattached") {
		t.Errorf("Status.Error should explain the refusal; got %q", st.Error)
	}
	if store.Len() != 0 {
		t.Errorf("a dead pid's row must be dropped, %d left", store.Len())
	}
}

// TestStart_PersistsHandleRowAndForgetsItOnExit pins the row's shape. The
// fields are a contract with the sweep and with adoption, and getting
// ExternalID or PID wrong produces a row that looks fine in a table and can
// never be reattached to.
func TestStart_PersistsHandleRowAndForgetsItOnExit(t *testing.T) {
	ctx := context.Background()
	store := executor.NewMemoryHandleStore()
	dir := t.TempDir()

	ex := New("row-test")
	ex.AttachHandleStore(store)

	spec := fixtureSpec(t, modeEcho, dir)
	spec.Labels = map[string]string{"task_id": "20191"}
	h, err := ex.Start(ctx, spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	rows, err := store.ListHandles("row-test")
	if err != nil {
		t.Fatalf("ListHandles: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("Start wrote %d rows, want 1", len(rows))
	}
	row := rows[0]
	if row.HandleID != h.ID {
		t.Errorf("row.HandleID = %q, want %q", row.HandleID, h.ID)
	}
	if row.Driver != executor.KindLocalProcess {
		t.Errorf("row.Driver = %q, want %q", row.Driver, executor.KindLocalProcess)
	}
	if row.ExternalID != strconv.Itoa(h.PID) {
		t.Errorf("row.ExternalID = %q, want the pid %d as decimal", row.ExternalID, h.PID)
	}
	if row.PID != h.PID {
		t.Errorf("row.PID = %d, want %d", row.PID, h.PID)
	}
	if row.ProjectPath != dir {
		t.Errorf("row.ProjectPath = %q, want %q", row.ProjectPath, dir)
	}
	if row.TaskID != 20191 {
		t.Errorf("row.TaskID = %d, want 20191", row.TaskID)
	}
	if !row.StartedAt.Equal(h.StartedAt) {
		t.Errorf("row.StartedAt = %s, want the dispatch time %s", row.StartedAt, h.StartedAt)
	}
	if row.Meta[metaBootID] == "" || row.Meta[metaProcStartTicks] == "" {
		t.Errorf("row.Meta must carry the pid identity, got %v — without it adoption declines "+
			"every row rather than risk a recycled pid", row.Meta)
	}

	// The row is identity, not history: once the workload is terminal nothing
	// can reattach to it, so it must not linger.
	lines, err := ex.Stream(ctx, h.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	collect(t, lines, 30*time.Second)
	waitFor(t, 10*time.Second, "the finished handle's row to be dropped", func() bool { return store.Len() == 0 })
}

// TestAttachHandleStore_IsIdempotent: this driver is a process-wide singleton
// reached from several bootstrap paths, so attaching twice is normal. Two
// adoptions of one row would mean two watchers racing to finish the same
// record.
func TestAttachHandleStore_IsIdempotent(t *testing.T) {
	ctx := context.Background()
	pid, _ := foreignProcess(t)

	id, alive, err := probeProcess(pid)
	if err != nil {
		t.Skipf("procfs identity is unavailable on this host: %v", err)
	}
	if !alive {
		t.Fatalf("the fixture process %d never ran", pid)
	}

	store := executor.NewMemoryHandleStore()
	if err := store.PutHandle(savedRow("h-twice", "idem-test", pid, id)); err != nil {
		t.Fatalf("PutHandle: %v", err)
	}

	ex := New("idem-test")
	ex.AttachHandleStore(store)
	ex.AttachHandleStore(store)
	ex.rehydrate()

	if got := ex.Handles(); len(got) != 1 {
		t.Fatalf("three rehydrations produced %d handles, want 1: %v", len(got), got)
	}
	st, err := ex.Status(ctx, "h-twice")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.State != executor.StateRunning {
		t.Fatalf("State = %q, want running — a duplicate adoption must not retire a live handle", st.State)
	}
	if store.Len() != 1 {
		t.Errorf("the row for a live adopted process must survive, %d rows left", store.Len())
	}
}

// TestAttachHandleStore_IgnoresNil: "forget how to find your processes" is not
// something a caller should be able to ask for by passing a zero value.
func TestAttachHandleStore_IgnoresNil(t *testing.T) {
	store := executor.NewMemoryHandleStore()
	ex := New("nil-test")
	ex.AttachHandleStore(store)
	ex.AttachHandleStore(nil)
	if ex.handleStore() == nil {
		t.Fatal("AttachHandleStore(nil) cleared a store that had already been installed")
	}
}

// TestParseProcStat covers the field arithmetic and the escaping hazard that
// makes it necessary. Field 22 is the number that decides whether a pid may be
// signalled, so a parse that can be pushed off by one is a parse that can
// authorise killing a bystander.
func TestParseProcStat(t *testing.T) {
	// Fields 3..22 with a plain comm: state, ppid, pgrp, session, tty_nr,
	// tpgid, flags, minflt, cminflt, majflt, cmajflt, utime, stime, cutime,
	// cstime, priority, nice, num_threads, itrealvalue, starttime.
	const tail = " S 1 2 3 0 -1 4194304 100 0 0 0 5 6 0 0 20 0 1 0 987654 " +
		"1234567 89 18446744073709551615 1 2 3 4 5 6 7"

	tests := []struct {
		name      string
		line      string
		wantState string
		wantTicks uint64
		wantErr   bool
	}{
		{
			name:      "ordinary comm",
			line:      "4242 (cloop)" + tail,
			wantState: "S",
			wantTicks: 987654,
		},
		{
			// The reason the parse scans to the last ')' rather than splitting
			// on whitespace: a process can name itself anything, and a naive
			// parse reads a field the process chose.
			name:      "comm containing spaces and parentheses",
			line:      "4242 (evil ) 0 R 999999)" + tail,
			wantState: "S",
			wantTicks: 987654,
		},
		{
			name:      "zombie state survives the parse",
			line:      "4242 (cloop) Z 1 2 3 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 4242 0 0",
			wantState: "Z",
			wantTicks: 4242,
		},
		{name: "no comm field", line: "4242 cloop S 1 2", wantErr: true},
		{name: "truncated", line: "4242 (cloop) S 1 2 3", wantErr: true},
		{name: "empty", line: "", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state, ticks, err := parseProcStat(tc.line)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseProcStat(%q) = (%q, %d, nil), want an error", tc.line, state, ticks)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseProcStat(%q): %v", tc.line, err)
			}
			if state != tc.wantState || ticks != tc.wantTicks {
				t.Fatalf("parseProcStat = (%q, %d), want (%q, %d)", state, ticks, tc.wantState, tc.wantTicks)
			}
		})
	}
}

// TestProcIdentityVerify covers the three refusals directly, including the one
// that cannot be produced with a real process: a row carrying no identity at
// all, which is what a row written by a host with an unreadable procfs looks
// like.
func TestProcIdentityVerify(t *testing.T) {
	pid, _ := foreignProcess(t)
	live, alive, err := probeProcess(pid)
	if err != nil {
		t.Skipf("procfs identity is unavailable on this host: %v", err)
	}
	if !alive {
		t.Fatalf("the fixture process %d never ran", pid)
	}

	if err := live.verify(pid); err != nil {
		t.Fatalf("verify on the very process the identity was read from: %v", err)
	}

	wrongTicks := live
	wrongTicks.startTicks += 7
	if err := wrongTicks.verify(pid); !errors.Is(err, errIdentityMismatch) {
		t.Fatalf("verify(wrong start time) = %v, want errIdentityMismatch", err)
	}

	wrongBoot := live
	wrongBoot.bootID = "00000000-0000-0000-0000-000000000000"
	if err := wrongBoot.verify(pid); !errors.Is(err, errProcessGone) {
		t.Fatalf("verify(other boot) = %v, want errProcessGone — a reboot kills every inherited child", err)
	}

	if _, err := identityFromMeta(nil); !errors.Is(err, errUnverifiable) {
		t.Fatalf("identityFromMeta(nil) = %v, want errUnverifiable", err)
	}
	if _, err := identityFromMeta(map[string]string{metaBootID: live.bootID}); !errors.Is(err, errUnverifiable) {
		t.Fatalf("identityFromMeta(half a token) = %v, want errUnverifiable", err)
	}
	if _, err := identityFromMeta(map[string]string{
		metaBootID: live.bootID, metaProcStartTicks: "not-a-number",
	}); !errors.Is(err, errUnverifiable) {
		t.Fatalf("identityFromMeta(junk ticks) = %v, want errUnverifiable", err)
	}
	if got, err := identityFromMeta(live.meta()); err != nil || got != live {
		t.Fatalf("identityFromMeta(meta()) = (%v, %v), want a round trip of %v", got, err, live)
	}
}

// TestAdopt_RefusesAnUnverifiableRow: a row with no identity token is the
// hardest case to get right, because the pid in it may well be alive and
// adopting it would look like a success.
func TestAdopt_RefusesAnUnverifiableRow(t *testing.T) {
	ctx := context.Background()
	pid, exited := foreignProcess(t)

	store := executor.NewMemoryHandleStore()
	row := savedRow("h-blind", "blind-test", pid, procIdentity{}) // no Meta at all
	if err := store.PutHandle(row); err != nil {
		t.Fatalf("PutHandle: %v", err)
	}

	ex := New("blind-test")
	ex.AttachHandleStore(store)

	st, err := ex.Status(ctx, "h-blind")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.State != executor.StateFailed {
		t.Fatalf("State = %q for a row with no identity, want failed", st.State)
	}
	if store.Len() != 0 {
		t.Errorf("an unverifiable row must be dropped, %d left", store.Len())
	}
	if err := ex.Signal(ctx, "h-blind", executor.SignalKill); err != nil {
		t.Fatalf("Signal: %v", err)
	}
	select {
	case <-exited:
		t.Fatal("a row with no identity token got its pid signalled anyway")
	case <-time.After(750 * time.Millisecond):
	}
}

// TestAdopt_IgnoresAnotherDriversRow: rows are scoped by executor ID, so this
// should be unreachable — but the way to reach it (an operator renaming a
// container executor onto this one's old ID) would have this driver read a
// container name as a pid.
func TestAdopt_IgnoresAnotherDriversRow(t *testing.T) {
	store := executor.NewMemoryHandleStore()
	if err := store.PutHandle(executor.HandleRecord{
		HandleID:   "h-foreign",
		ExecutorID: "mixed",
		Driver:     executor.KindContainer,
		ExternalID: "cloop-project-abcdef",
		StartedAt:  time.Now(),
	}); err != nil {
		t.Fatalf("PutHandle: %v", err)
	}

	ex := New("mixed")
	ex.AttachHandleStore(store)

	if _, err := ex.Status(context.Background(), "h-foreign"); !errors.Is(err, executor.ErrHandleNotFound) {
		t.Fatalf("Status on another driver's row = %v, want ErrHandleNotFound", err)
	}
	if store.Len() != 1 {
		t.Error("another driver's row must be left alone, not deleted")
	}
}
