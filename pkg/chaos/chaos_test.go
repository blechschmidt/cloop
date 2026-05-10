package chaos

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseFaultType(t *testing.T) {
	for _, ft := range AllFaultTypes {
		got, err := ParseFaultType(string(ft))
		if err != nil {
			t.Errorf("ParseFaultType(%q) error: %v", ft, err)
		}
		if got != ft {
			t.Errorf("ParseFaultType(%q) = %q, want %q", ft, got, ft)
		}
	}
	// Mixed case + whitespace should normalise.
	if got, err := ParseFaultType("  Provider-429  "); err != nil || got != FaultProvider429 {
		t.Errorf("ParseFaultType normalisation failed: got=%q err=%v", got, err)
	}
	// Unknown values are rejected with the catalogue listed.
	_, err := ParseFaultType("typo")
	if err == nil || !strings.Contains(err.Error(), "valid:") {
		t.Errorf("ParseFaultType(typo) = %v, want error listing valid types", err)
	}
}

func TestFaultActiveWindow(t *testing.T) {
	now := time.Now()
	f := Fault{
		Type:      FaultProvider429,
		StartedAt: now.Add(-time.Second),
		Until:     now.Add(time.Second),
	}
	if !f.Active(now) {
		t.Error("Active(now) = false, want true inside window")
	}
	if f.Active(now.Add(2 * time.Second)) {
		t.Error("Active(after Until) = true, want false")
	}
	if f.Active(now.Add(-2 * time.Second)) {
		t.Error("Active(before StartedAt) = true, want false")
	}
	// Empty type is never active.
	if (Fault{StartedAt: now, Until: now.Add(time.Hour)}).Active(now) {
		t.Error("Active() on empty-type fault = true, want false")
	}
	// Open-ended fault is bounded to a 1-minute window so a forgotten injection
	// cannot poison a long-running daemon.
	open := Fault{Type: FaultProvider429, StartedAt: now}
	if !open.Active(now.Add(30 * time.Second)) {
		t.Error("open-ended fault inactive at +30s, want active")
	}
	if open.Active(now.Add(2 * time.Minute)) {
		t.Error("open-ended fault still active at +2m, want inactive")
	}
}

// TestControllerRoundTrip exercises the full disk → memory → ShouldInject path
// so the Inject/Refresh/Clear contract is verified end-to-end.
func TestControllerRoundTrip(t *testing.T) {
	dir := t.TempDir()
	c := NewController(dir)

	// Empty state: never injects.
	if c.ShouldInject(FaultProvider429) {
		t.Error("empty controller injected anyway")
	}

	now := time.Now()
	if err := c.Inject(Fault{
		Type:        FaultProvider500,
		Probability: 1.0,
		StartedAt:   now,
		Until:       now.Add(2 * time.Second),
	}); err != nil {
		t.Fatalf("Inject: %v", err)
	}
	if !c.ShouldInject(FaultProvider500) {
		t.Error("ShouldInject(500) = false after Inject, want true")
	}
	if c.ShouldInject(FaultProvider429) {
		t.Error("ShouldInject(429) = true after Inject(500), want false")
	}

	// A fresh controller pointed at the same directory must see the fault via
	// the file mirror — this is what `cloop ui` relies on for cross-process
	// pickup.
	c2 := NewController(dir)
	if err := c2.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if !c2.ShouldInject(FaultProvider500) {
		t.Error("sibling controller did not pick up persisted fault")
	}

	if err := c.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if c.ShouldInject(FaultProvider500) {
		t.Error("ShouldInject after Clear = true, want false")
	}
}

// TestControllerInjectValidation surfaces the parameter checks that prevent
// the on-disk mirror from being polluted with malformed faults.
func TestControllerInjectValidation(t *testing.T) {
	c := NewController(t.TempDir())
	now := time.Now()

	cases := []struct {
		name string
		f    Fault
		want string
	}{
		{"empty type", Fault{StartedAt: now, Until: now.Add(time.Second)}, "empty fault type"},
		{"unknown type", Fault{Type: "nope", StartedAt: now, Until: now.Add(time.Second)}, "unknown fault type"},
		{"until before start", Fault{Type: FaultProvider429, StartedAt: now, Until: now.Add(-time.Second)}, "not after"},
		{"prob <0", Fault{Type: FaultProvider429, StartedAt: now, Until: now.Add(time.Second), Probability: -0.1}, "out of [0,1]"},
		{"prob >1", Fault{Type: FaultProvider429, StartedAt: now, Until: now.Add(time.Second), Probability: 1.5}, "out of [0,1]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := c.Inject(tc.f)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Inject error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

// TestTransportInjectsFaults exercises the actual middleware: every supported
// HTTP-side fault should produce its documented effect against a stub upstream.
func TestTransportInjectsFaults(t *testing.T) {
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "real-upstream-ok")
	}))
	defer upstream.Close()
	upstreamURL := upstream.URL

	dir := t.TempDir()
	c := NewController(dir)
	prev := SetGlobal(c)
	t.Cleanup(func() { SetGlobal(prev) })

	client := &http.Client{Transport: &Transport{Base: upstream.Client().Transport}}

	// Happy path: no fault → upstream hit.
	resp, err := client.Get(upstreamURL)
	if err != nil {
		t.Fatalf("happy path Get: %v", err)
	}
	resp.Body.Close()
	if upstreamHits != 1 || resp.StatusCode != 200 {
		t.Fatalf("happy path: hits=%d status=%d", upstreamHits, resp.StatusCode)
	}

	now := time.Now()
	mustInject := func(f Fault) {
		t.Helper()
		_ = c.Clear()
		if err := c.Inject(f); err != nil {
			t.Fatalf("Inject(%s): %v", f.Type, err)
		}
	}

	// 429 fault.
	mustInject(Fault{Type: FaultProvider429, Probability: 1.0, StartedAt: now, Until: now.Add(2 * time.Second)})
	resp, err = client.Get(upstreamURL)
	if err != nil {
		t.Fatalf("429 fault Get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("429 fault: got status %d, want 429", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Chaos-Injected"); got != "true" {
		t.Errorf("X-Chaos-Injected = %q, want true", got)
	}
	if got := resp.Header.Get("Retry-After"); got == "" {
		t.Error("Retry-After header missing on synthetic 429")
	}

	// 500 fault.
	mustInject(Fault{Type: FaultProvider500, Probability: 1.0, StartedAt: now, Until: now.Add(2 * time.Second)})
	resp, err = client.Get(upstreamURL)
	if err != nil {
		t.Fatalf("500 fault Get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("500 fault: got status %d, want 500", resp.StatusCode)
	}

	// network-flap fault.
	mustInject(Fault{Type: FaultNetworkFlap, Probability: 1.0, StartedAt: now, Until: now.Add(2 * time.Second)})
	_, err = client.Get(upstreamURL)
	if err == nil {
		t.Error("network-flap: expected dial error, got nil")
	} else if !strings.Contains(err.Error(), "chaos: network-flap injected") {
		t.Errorf("network-flap: error = %v, want chaos message", err)
	}

	// provider-timeout fault — bounded by caller's context so the test stays fast.
	mustInject(Fault{Type: FaultProviderTimeout, Probability: 1.0, StartedAt: now, Until: now.Add(2 * time.Second)})
	timeoutCtx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(timeoutCtx, http.MethodGet, upstreamURL, nil)
	start := time.Now()
	_, err = client.Do(req)
	elapsed := time.Since(start)
	if err == nil {
		t.Error("provider-timeout: expected error, got nil")
	}
	if elapsed > time.Second {
		t.Errorf("provider-timeout: blocked for %s, expected to honour caller deadline", elapsed)
	}

	// Make sure no faulted response ever reached the upstream.
	if upstreamHits != 1 {
		t.Errorf("upstream hits = %d, want 1 — faults should short-circuit before dispatch", upstreamHits)
	}
}

// TestTransportFastPathNoController verifies the documented invariant that the
// chaos middleware is fully transparent (≈ zero cost) when no controller is
// installed. Production builds where chaos is never invoked must not pay for it.
func TestTransportFastPathNoController(t *testing.T) {
	prev := SetGlobal(nil)
	t.Cleanup(func() { SetGlobal(prev) })

	hits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	client := &http.Client{Transport: &Transport{Base: upstream.Client().Transport}}
	for i := 0; i < 5; i++ {
		resp, err := client.Get(upstream.URL)
		if err != nil {
			t.Fatalf("Get %d: %v", i, err)
		}
		resp.Body.Close()
	}
	if hits != 5 {
		t.Errorf("upstream hits = %d, want 5 (transport must be transparent without controller)", hits)
	}
}

// TestStoreInsertUpdateList walks a chaos_runs row through its lifecycle and
// confirms the resulting summary aggregates correctly. Uses a fresh sqlite
// file so the test does not depend on any project state.
func TestStoreInsertUpdateList(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "chaos.db")
	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.Close()

	now := time.Now()
	id, err := store.Insert(Run{
		FaultType:   FaultProvider429,
		Probability: 1.0,
		StartedAt:   now,
		Outcome:     OutcomeUnknown,
		Note:        "test",
	})
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if id == 0 {
		t.Fatal("Insert returned zero id")
	}

	if err := store.Update(Run{
		ID:            id,
		StoppedAt:     now.Add(time.Second),
		DurationMS:    1000,
		Outcome:       OutcomeRecovered,
		OutcomeDetail: "client got 429",
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	// Update with a zero ID must error (defensive guard).
	if err := store.Update(Run{Outcome: OutcomeRecovered}); err == nil {
		t.Error("Update(id=0) = nil, want error")
	}

	runs, err := store.List(0, 10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("List len = %d, want 1", len(runs))
	}
	r := runs[0]
	if r.FaultType != FaultProvider429 || r.Outcome != OutcomeRecovered || r.DurationMS != 1000 {
		t.Errorf("List row mismatch: %+v", r)
	}
	if r.StartedAt.IsZero() {
		t.Error("StartedAt did not round-trip through SQLite")
	}

	rows := SummaryRows(runs)
	if len(rows) != 1 {
		t.Fatalf("SummaryRows len = %d, want 1", len(rows))
	}
	if rows[0].Recovered != 1 || rows[0].Total != 1 {
		t.Errorf("SummaryRows row mismatch: %+v", rows[0])
	}
	formatted := FormatSummary(rows)
	if !strings.Contains(formatted, "provider-429") || !strings.Contains(formatted, "TOTAL") {
		t.Errorf("FormatSummary missing expected content:\n%s", formatted)
	}
	// Empty input prints a friendly message rather than an empty table.
	if got := FormatSummary(nil); !strings.Contains(got, "no chaos runs") {
		t.Errorf("FormatSummary(nil) = %q, want hint message", got)
	}
}

// TestSlowDiskDelay parses Note values into durations and falls back gracefully.
func TestSlowDiskDelay(t *testing.T) {
	c := NewController(t.TempDir())
	now := time.Now()
	until := now.Add(time.Second)

	if got := SlowDiskDelay(c); got != 0 {
		t.Errorf("SlowDiskDelay with no fault = %s, want 0", got)
	}
	if err := c.Inject(Fault{Type: FaultSlowDisk, StartedAt: now, Until: until, Note: "200ms"}); err != nil {
		t.Fatalf("Inject: %v", err)
	}
	if got := SlowDiskDelay(c); got != 200*time.Millisecond {
		t.Errorf("SlowDiskDelay = %s, want 200ms", got)
	}
	// An unparseable note falls back to the documented 50ms default.
	_ = c.Clear()
	_ = c.Inject(Fault{Type: FaultSlowDisk, StartedAt: now, Until: until})
	if got := SlowDiskDelay(c); got != 50*time.Millisecond {
		t.Errorf("SlowDiskDelay (no note) = %s, want 50ms", got)
	}
}

// TestSuiteRunsAllFaults executes the default suite end-to-end and confirms
// every fault type produces a recovered outcome — i.e. the chaos framework
// itself is healthy. This is the spec-mandated "chaos test suite that runs
// faults against a real running cloop instance" minus the network round-trips
// (fully in-process, deterministic, fast).
func TestSuiteRunsAllFaults(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping suite in -short mode")
	}
	dir := t.TempDir()
	if err := mkdirAll(filepath.Join(dir, ".cloop")); err != nil {
		t.Fatalf("mkdir .cloop: %v", err)
	}
	dbPath := filepath.Join(dir, ".cloop", "state.db")
	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.Close()

	c := NewController(dir)
	prev := SetGlobal(c)
	t.Cleanup(func() { SetGlobal(prev) })

	s := &Suite{
		WorkDir:    dir,
		StatePath:  dbPath,
		Controller: c,
		Store:      store,
		Cases:      DefaultCases(dir),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	runs, err := s.Run(ctx)
	if err != nil {
		t.Fatalf("Suite.Run: %v", err)
	}
	if len(runs) != len(AllFaultTypes) {
		t.Fatalf("runs len = %d, want %d (one per fault)", len(runs), len(AllFaultTypes))
	}
	seen := make(map[FaultType]bool)
	for _, r := range runs {
		seen[r.FaultType] = true
		if r.Outcome != OutcomeRecovered {
			t.Errorf("%s: outcome = %s, detail = %s, want recovered", r.FaultType, r.Outcome, r.OutcomeDetail)
		}
	}
	for _, ft := range AllFaultTypes {
		if !seen[ft] {
			t.Errorf("default suite did not cover fault type %s", ft)
		}
	}
}

// TestBusyHolderHoldsWriteLock proves the SQLite chaos primitive actually
// blocks contending writers — the realistic SQLITE_BUSY scenario the rest of
// cloop's WAL+busy_timeout work is designed to survive.
func TestBusyHolderHoldsWriteLock(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "busy.db")
	bootstrap, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore bootstrap: %v", err)
	}
	bootstrap.Close()

	holder := NewBusyHolder(dbPath)
	if err := holder.Start(context.Background()); err != nil {
		t.Fatalf("BusyHolder.Start: %v", err)
	}
	t.Cleanup(func() { holder.Stop() })

	// A second writer with a short busy_timeout should fail. We use a 200ms
	// timeout so the test is fast even on slow CI.
	c2, err := openShortBusyTimeout(dbPath, 200)
	if err != nil {
		t.Fatalf("open short-timeout connection: %v", err)
	}
	defer c2.Close()
	if _, err := c2.Insert(Run{FaultType: FaultProvider429, StartedAt: time.Now()}); err == nil {
		t.Error("expected sqlite-busy error from contending writer, got nil")
	} else if !strings.Contains(err.Error(), "busy") && !strings.Contains(err.Error(), "locked") {
		// Some sqlite drivers surface the error as "database is locked"; both
		// are acceptable.
		t.Logf("contending writer error (accepted): %v", err)
	}

	held := holder.Stop()
	if held <= 0 {
		t.Errorf("Stop returned non-positive duration %s", held)
	}
	// Subsequent Stop is idempotent.
	_ = holder.Stop()

	// After release, the contending writer succeeds.
	c3, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore post-release: %v", err)
	}
	defer c3.Close()
	if _, err := c3.Insert(Run{FaultType: FaultProvider429, StartedAt: time.Now()}); err != nil {
		t.Errorf("post-release insert failed: %v", err)
	}
}

// openShortBusyTimeout returns a Store with an aggressive busy_timeout so the
// contending-writer test does not block for the default several seconds.
// PRAGMA does not accept SQL parameters in modernc.org/sqlite, so the value
// must be inlined — busyMS is bounded so this is not an injection risk.
func openShortBusyTimeout(dbPath string, busyMS int) (*Store, error) {
	if busyMS <= 0 || busyMS > 60000 {
		busyMS = 100
	}
	store, err := OpenStore(dbPath)
	if err != nil {
		return nil, err
	}
	if _, err := store.db.Exec(fmt.Sprintf("PRAGMA busy_timeout = %d", busyMS)); err != nil {
		store.Close()
		return nil, err
	}
	return store, nil
}

// mkdirAll is a tiny wrapper over os.MkdirAll used by the suite test to
// pre-create the .cloop directory the suite would otherwise miss in a freshly
// minted t.TempDir().
func mkdirAll(path string) error {
	return os.MkdirAll(path, 0o755)
}

// TestTransportContextCancelled verifies that provider-timeout respects an
// already-cancelled context — important because it is the only fault that
// blocks rather than failing fast.
func TestTransportContextCancelled(t *testing.T) {
	dir := t.TempDir()
	c := NewController(dir)
	prev := SetGlobal(c)
	t.Cleanup(func() { SetGlobal(prev) })

	now := time.Now()
	if err := c.Inject(Fault{Type: FaultProviderTimeout, Probability: 1.0, StartedAt: now, Until: now.Add(time.Second)}); err != nil {
		t.Fatalf("Inject: %v", err)
	}
	client := &http.Client{Transport: &Transport{}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel — the round trip must return immediately
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://chaos.local/", nil)

	start := time.Now()
	_, err := client.Do(req)
	if err == nil {
		t.Fatal("expected error from pre-cancelled context, got nil")
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("blocked %s after Cancel, want immediate return", elapsed)
	}
	if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context") {
		t.Logf("error: %v (acceptable as long as it is not a real timeout)", err)
	}
}
