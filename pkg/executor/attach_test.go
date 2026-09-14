package executor

// Tests for the attach policy gate, the concurrency ceiling, and the
// redaction wrapper (Task 20265).
//
// The gate is the part worth testing hardest. Three drivers implement Attacher
// and a fourth deliberately does not; what keeps that fourth one out is not the
// missing method — a future edit could add one — but AttachTarget refusing a
// non-isolating executor before it ever asks about the interface.

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/pkg/redact"
)

// attachableExec is policy_test.go's fakeExec plus the optional Attacher
// interface, so a test can hold the isolation level and the capability
// independently — which is exactly the combination the gate has to get right.
type attachableExec struct{ fakeExec }

func (a attachableExec) Attach(context.Context, AttachRequest) (AttachConn, error) {
	return NewAttachConn(strings.NewReader(""), nil, nil, nil), nil
}

// TestAttachTarget_RefusesNonIsolatingExecutor is the guarantee the whole
// feature rests on: attach must never produce a shell on the control-plane
// host. A localprocess workload has no sandbox, so there is nothing to enter.
func TestAttachTarget_RefusesNonIsolatingExecutor(t *testing.T) {
	// Even one that *does* implement Attacher must be refused: the interface
	// is not what makes a workload safe to enter.
	ex := attachableExec{fakeExec{id: "local", kind: KindLocalProcess, isolation: IsolationNone}}

	_, err := AttachTarget(ex)
	if !errors.Is(err, ErrAttachNoSandbox) {
		t.Fatalf("AttachTarget(localprocess) = %v, want ErrAttachNoSandbox", err)
	}
	if AttachSupported(ex) {
		t.Error("AttachSupported(localprocess) must be false")
	}
}

// TestAttachTarget_NamesThePolicyInStrictMode: the two ways to arrive at a
// non-isolating executor need different remediation, and the message is the
// only place an operator gets it.
func TestAttachTarget_NamesThePolicyInStrictMode(t *testing.T) {
	ex := fakeExec{id: "local", kind: KindLocalProcess, isolation: IsolationNone}

	prev := SetAllowHostExecution(false)
	t.Cleanup(func() { SetAllowHostExecution(prev) })

	_, err := AttachTarget(ex)
	if !errors.Is(err, ErrAttachNoSandbox) {
		t.Fatalf("AttachTarget = %v, want ErrAttachNoSandbox", err)
	}
	if !strings.Contains(err.Error(), "allow_host_process") {
		t.Errorf("strict-mode refusal must name the policy that caused it, got %q", err)
	}

	SetAllowHostExecution(true)
	_, err = AttachTarget(ex)
	if !errors.Is(err, ErrAttachNoSandbox) {
		t.Fatalf("AttachTarget = %v, want ErrAttachNoSandbox", err)
	}
	if strings.Contains(err.Error(), "allow_host_process is false") {
		t.Errorf("permissive-mode refusal must not blame the policy, got %q", err)
	}
}

// TestAttachTarget_RefusesIsolatingDriverWithoutTheInterface keeps a future
// isolating driver from silently reading as attachable.
func TestAttachTarget_RefusesIsolatingDriverWithoutTheInterface(t *testing.T) {
	ex := fakeExec{id: "ctr", kind: KindContainer, isolation: IsolationContainer}
	_, err := AttachTarget(ex)
	if !errors.Is(err, ErrAttachUnsupported) {
		t.Fatalf("AttachTarget = %v, want ErrAttachUnsupported", err)
	}
}

// TestAttachTarget_AcceptsEveryIsolatingLevel: container, VM and remote are all
// sandboxes, and the gate must not accidentally allow only the one it was
// written against.
func TestAttachTarget_AcceptsEveryIsolatingLevel(t *testing.T) {
	for _, iso := range []Isolation{IsolationContainer, IsolationVM, IsolationRemote} {
		ex := attachableExec{fakeExec{id: "x", kind: "x", isolation: iso}}
		if _, err := AttachTarget(ex); err != nil {
			t.Errorf("AttachTarget(isolation=%s) = %v, want nil", iso, err)
		}
	}
}

func TestAttachTarget_NilExecutor(t *testing.T) {
	if _, err := AttachTarget(nil); !errors.Is(err, ErrAttachHandleUnknown) {
		t.Errorf("AttachTarget(nil) = %v, want ErrAttachHandleUnknown", err)
	}
}

// ── Concurrency ceiling ───────────────────────────────────────────────────

func TestAttachLimiter_BoundsSessionsPerExecutor(t *testing.T) {
	l := NewAttachLimiter(2)
	info := AttachSessionInfo{ExecutorID: "ctr-1", HandleID: "h1", Actor: "alice"}

	_, rel1, err := l.Acquire(info)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if _, _, err = l.Acquire(info); err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if _, _, err = l.Acquire(info); !errors.Is(err, ErrAttachBusy) {
		t.Fatalf("third acquire = %v, want ErrAttachBusy", err)
	}

	// A different executor has its own budget: the ceiling protects one
	// machine, not the fleet.
	if _, _, err = l.Acquire(AttachSessionInfo{ExecutorID: "ctr-2"}); err != nil {
		t.Errorf("acquire on a second executor: %v", err)
	}

	rel1()
	if _, _, err = l.Acquire(info); err != nil {
		t.Errorf("acquire after release: %v", err)
	}
}

// TestAttachLimiter_ReleaseIsIdempotent: handlers defer the release and also
// call it on early error paths, so a double release must not free a slot twice
// and let the ceiling drift upward.
func TestAttachLimiter_ReleaseIsIdempotent(t *testing.T) {
	l := NewAttachLimiter(1)
	info := AttachSessionInfo{ExecutorID: "e"}
	_, release, err := l.Acquire(info)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	release()
	release()
	release()
	if got := l.Count("e"); got != 0 {
		t.Fatalf("Count after releases = %d, want 0", got)
	}
	if _, _, err := l.Acquire(info); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, _, err := l.Acquire(info); !errors.Is(err, ErrAttachBusy) {
		t.Errorf("a repeated release must not raise the ceiling: got %v, want ErrAttachBusy", err)
	}
}

func TestAttachLimiter_ConcurrentAcquireRespectsTheCeiling(t *testing.T) {
	const max = 4
	l := NewAttachLimiter(max)

	var wg sync.WaitGroup
	var mu sync.Mutex
	granted := 0
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := l.Acquire(AttachSessionInfo{ExecutorID: "e"}); err == nil {
				mu.Lock()
				granted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if granted != max {
		t.Errorf("granted %d concurrent sessions, want exactly %d", granted, max)
	}
}

// TestAttachLimiter_LiveIsTheInventory: the limiter doubles as the answer to
// "who is inside which sandbox right now".
func TestAttachLimiter_LiveIsTheInventory(t *testing.T) {
	l := NewAttachLimiter(4)
	if _, _, err := l.Acquire(AttachSessionInfo{
		ExecutorID: "k8s-1", HandleID: "h9", Actor: "alice@example.com",
		Command: "/bin/sh", Writable: true,
	}); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	live := l.Live()
	if len(live) != 1 {
		t.Fatalf("Live() has %d entries, want 1", len(live))
	}
	got := live[0]
	if got.Actor != "alice@example.com" || got.HandleID != "h9" || !got.Writable {
		t.Errorf("Live()[0] = %+v, want the acquiring identity, handle and write flag", got)
	}
	if got.SessionID == "" {
		t.Error("a live session must carry the ID Acquire minted, for the audit correlation")
	}
}

// TestAttachLimiter_NilAdmitsEverything: a driver test or an embedded use with
// no limiter configured must not be silently capped at zero.
func TestAttachLimiter_NilAdmitsEverything(t *testing.T) {
	var l *AttachLimiter
	for i := 0; i < 3; i++ {
		if _, _, err := l.Acquire(AttachSessionInfo{ExecutorID: "e"}); err != nil {
			t.Fatalf("nil limiter must admit: %v", err)
		}
	}
	if got := l.Count("e"); got != 0 {
		t.Errorf("nil limiter Count = %d, want 0", got)
	}
}

// ── Read-only enforcement ─────────────────────────────────────────────────

// TestAttachConn_ReadOnlyRefusesWrite: the shared adapter is what stops each
// driver having to remember the rule.
func TestAttachConn_ReadOnlyRefusesWrite(t *testing.T) {
	conn := NewAttachConn(strings.NewReader("hello"), nil, nil, nil)
	if _, err := conn.Write([]byte("rm -rf /")); !errors.Is(err, ErrAttachReadOnly) {
		t.Fatalf("Write on a read-only conn = %v, want ErrAttachReadOnly", err)
	}
	// Reading still works: read-only means read-only, not useless.
	buf := make([]byte, 5)
	if n, err := conn.Read(buf); err != nil || string(buf[:n]) != "hello" {
		t.Errorf("Read = %q, %v; want \"hello\", nil", buf[:n], err)
	}
}

// TestAttachConn_ResizeWithoutATTYIsNotAnError: a caller that always reports
// geometry should not have to know which kind of session it opened.
func TestAttachConn_ResizeWithoutATTYIsNotAnError(t *testing.T) {
	conn := NewAttachConn(strings.NewReader(""), nil, nil, nil)
	if err := conn.Resize(40, 120); err != nil {
		t.Errorf("Resize on a pipe session = %v, want nil", err)
	}
}

// TestAttachConn_CloseIsIdempotent: handlers defer Close and drivers call it
// on teardown, so it runs more than once by design.
func TestAttachConn_CloseIsIdempotent(t *testing.T) {
	closes := 0
	conn := NewAttachConn(strings.NewReader(""), nil, nil, func() error {
		closes++
		return nil
	})
	_ = conn.Close()
	_ = conn.Close()
	if closes != 1 {
		t.Errorf("close function ran %d times, want 1", closes)
	}
}

// ── Redaction ─────────────────────────────────────────────────────────────

// TestRedactAttachOutput_ScrubsSecrets is the baseline.
func TestRedactAttachOutput_ScrubsSecrets(t *testing.T) {
	const secret = "ghp_thisIsALeasedTokenValue12345678"
	set := redact.New(secret)
	src := strings.NewReader("before " + secret + " after\n")

	out, err := io.ReadAll(RedactAttachOutput(src, set))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(out), secret) {
		t.Fatalf("attach output leaked the secret: %q", out)
	}
	if !strings.Contains(string(out), "before ") || !strings.Contains(string(out), " after") {
		t.Errorf("redaction ate the surrounding text: %q", out)
	}
}

// TestRedactAttachOutput_ScrubsAcrossReadBoundaries is the case a per-chunk
// scrub gets wrong, and the reason this wraps redact.Writer rather than calling
// Set.String on each read: a token split across two reads matches neither half,
// and a terminal reassembles it perfectly on screen.
func TestRedactAttachOutput_ScrubsAcrossReadBoundaries(t *testing.T) {
	const secret = "ghp_splitAcrossTwoReadsEntirely123"
	set := redact.New(secret)

	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write([]byte("start " + secret[:10]))
		_, _ = pw.Write([]byte(secret[10:] + " end\n"))
		_ = pw.Close()
	}()

	out, err := io.ReadAll(RedactAttachOutput(pr, set))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(out), secret) {
		t.Fatalf("a secret split across two writes survived redaction: %q", out)
	}
}

// TestRedactAttachOutput_PassesThroughWithoutASet keeps the common case free:
// a workload holding no credential must not pay for a pipe and a goroutine.
func TestRedactAttachOutput_PassesThroughWithoutASet(t *testing.T) {
	src := strings.NewReader("plain")
	if got := RedactAttachOutput(src, nil); got != io.Reader(src) {
		t.Error("a nil redaction set must return the reader unchanged")
	}
	if got := RedactAttachOutput(src, redact.New()); got != io.Reader(src) {
		t.Error("an empty redaction set must return the reader unchanged")
	}
}

// TestRedactAttachOutput_FlushesTheTail: a transcript that ends mid-token
// leaves bytes in the holdback buffer, and dropping them would eat the last
// line of every session that ends without a trailing newline.
func TestRedactAttachOutput_FlushesTheTail(t *testing.T) {
	set := redact.New("NEVER_APPEARS_IN_THIS_STREAM")
	src := strings.NewReader("final line with no newline")

	out, err := io.ReadAll(RedactAttachOutput(src, set))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(out) != "final line with no newline" {
		t.Errorf("tail was not flushed: got %q", out)
	}
}

// ── Request shaping ───────────────────────────────────────────────────────

func TestAttachRequest_ArgvDefaultsToAShell(t *testing.T) {
	var r AttachRequest
	if got := r.Argv(); len(got) == 0 || !strings.Contains(got[0], "sh") {
		t.Errorf("Argv() with no command = %v, want a default shell", got)
	}
	r.Command = []string{"ps", "aux"}
	if got := r.CommandLine(); got != "ps aux" {
		t.Errorf("CommandLine() = %q, want %q", got, "ps aux")
	}
}

// TestAttachRequest_ArgvCopies: the audit record and the driver both read
// Argv, and a shared backing array would let one mutate the other's view of
// what was run.
func TestAttachRequest_ArgvCopies(t *testing.T) {
	r := AttachRequest{Command: []string{"sh", "-c", "echo hi"}}
	got := r.Argv()
	got[2] = "rm -rf /"
	if r.Command[2] != "echo hi" {
		t.Error("Argv() must copy: mutating the result changed the request")
	}
}
