package executor

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeExecutor is a minimal Executor used to exercise registry policy
// without starting real processes.
type fakeExecutor struct {
	id   string
	kind string
}

func (f *fakeExecutor) ID() string   { return f.id }
func (f *fakeExecutor) Kind() string { return f.kind }
func (f *fakeExecutor) Capabilities() Capabilities {
	return Capabilities{Isolation: IsolationNone}
}
func (f *fakeExecutor) Start(context.Context, Spec) (Handle, error) {
	return Handle{ID: "h", ExecutorID: f.id, StartedAt: time.Now()}, nil
}
func (f *fakeExecutor) Signal(context.Context, string, Signal) error { return nil }
func (f *fakeExecutor) Status(context.Context, string) (Status, error) {
	return Status{State: StateExited}, nil
}
func (f *fakeExecutor) Stream(context.Context, string) (<-chan LogLine, error) {
	ch := make(chan LogLine)
	close(ch)
	return ch, nil
}
func (f *fakeExecutor) HealthCheck(context.Context) error { return nil }

func newFake(id string) *fakeExecutor { return &fakeExecutor{id: id, kind: KindLocalProcess} }

func TestRegisterAndGet(t *testing.T) {
	reg := NewRegistry()
	local := newFake("local")

	if err := reg.Register(local); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, err := reg.Get("local")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID() != "local" {
		t.Fatalf("Get returned %q, want local", got.ID())
	}

	// The first registration also becomes the default so a zero-config
	// install needs no extra wiring.
	if reg.DefaultID() != "local" {
		t.Fatalf("DefaultID = %q, want local (first registration)", reg.DefaultID())
	}

	if err := reg.Register(newFake("local")); !errors.Is(err, ErrAlreadyRegistered) {
		t.Fatalf("duplicate Register error = %v, want ErrAlreadyRegistered", err)
	}
	// Ensure is the idempotent variant.
	if err := reg.Ensure(newFake("local")); err != nil {
		t.Fatalf("Ensure on existing ID = %v, want nil", err)
	}

	if _, err := reg.Get("nope"); !errors.Is(err, ErrExecutorNotFound) {
		t.Fatalf("Get(unknown) error = %v, want ErrExecutorNotFound", err)
	}
}

func TestRegistryEmptyAndInvalidRegistration(t *testing.T) {
	reg := NewRegistry()

	if _, err := reg.Default(); !errors.Is(err, ErrNoDefault) {
		t.Fatalf("Default on empty registry = %v, want ErrNoDefault", err)
	}
	if _, err := reg.Resolve("/some/project"); !errors.Is(err, ErrNoDefault) {
		t.Fatalf("Resolve on empty registry = %v, want ErrNoDefault", err)
	}
	if err := reg.Register(nil); err == nil {
		t.Fatal("Register(nil) succeeded, want error")
	}
	if err := reg.Register(newFake("   ")); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("Register with blank ID = %v, want ErrInvalidSpec", err)
	}
}

func TestResolveFallsBackToDefault(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(newFake("local")); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := reg.Register(newFake("sandbox")); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// No binding for this project → the default.
	ex, err := reg.Resolve("/projects/unbound")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ex.ID() != "local" {
		t.Fatalf("Resolve(unbound) = %q, want local (the default)", ex.ID())
	}

	// Changing the default changes where unbound projects run.
	if err := reg.SetDefault("sandbox"); err != nil {
		t.Fatalf("SetDefault: %v", err)
	}
	ex, err = reg.Resolve("/projects/unbound")
	if err != nil {
		t.Fatalf("Resolve after SetDefault: %v", err)
	}
	if ex.ID() != "sandbox" {
		t.Fatalf("Resolve(unbound) = %q, want sandbox", ex.ID())
	}

	if err := reg.SetDefault("ghost"); !errors.Is(err, ErrExecutorNotFound) {
		t.Fatalf("SetDefault(unknown) = %v, want ErrExecutorNotFound", err)
	}
}

func TestResolveHonoursBinding(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(newFake("local"))
	_ = reg.Register(newFake("sandbox"))

	if err := reg.Bind("/projects/secure", "sandbox"); err != nil {
		t.Fatalf("Bind: %v", err)
	}

	ex, err := reg.Resolve("/projects/secure")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ex.ID() != "sandbox" {
		t.Fatalf("Resolve(bound) = %q, want sandbox", ex.ID())
	}

	// Other projects are unaffected.
	if ex, err := reg.Resolve("/projects/other"); err != nil || ex.ID() != "local" {
		t.Fatalf("Resolve(other) = (%v, %v), want local", ex, err)
	}

	// Unbinding restores the default.
	reg.Unbind("/projects/secure")
	if ex, err := reg.Resolve("/projects/secure"); err != nil || ex.ID() != "local" {
		t.Fatalf("Resolve after Unbind = (%v, %v), want local", ex, err)
	}

	// Binding with an empty executor ID clears rather than storing a blank.
	_ = reg.Bind("/projects/secure", "sandbox")
	if err := reg.Bind("/projects/secure", ""); err != nil {
		t.Fatalf("Bind(clear): %v", err)
	}
	if id, ok := reg.Binding("/projects/secure"); ok {
		t.Fatalf("binding survived clear: %q", id)
	}
	if err := reg.Bind("", "sandbox"); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("Bind with blank path = %v, want ErrInvalidSpec", err)
	}
}

// TestResolveFailsClosedOnMissingBoundExecutor is the security-critical case:
// a project pinned to an isolated executor must NOT silently fall back to the
// (unisolated) default when that executor is unavailable.
func TestResolveFailsClosedOnMissingBoundExecutor(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(newFake("local"))
	if err := reg.Bind("/projects/secure", "remote-edge-01"); err != nil {
		t.Fatalf("Bind: %v", err)
	}

	ex, err := reg.Resolve("/projects/secure")
	if err == nil {
		t.Fatalf("Resolve returned executor %q, want failure — a project bound to an "+
			"unavailable isolated executor must never fall back to the host", ex.ID())
	}
	if !errors.Is(err, ErrExecutorNotFound) {
		t.Fatalf("Resolve error = %v, want ErrExecutorNotFound", err)
	}

	// Once the executor shows up (e.g. the remote agent enrolls), the same
	// binding resolves.
	_ = reg.Register(newFake("remote-edge-01"))
	if ex, err := reg.Resolve("/projects/secure"); err != nil || ex.ID() != "remote-edge-01" {
		t.Fatalf("Resolve after enrollment = (%v, %v), want remote-edge-01", ex, err)
	}
}

func TestBindingPathCanonicalization(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(newFake("local"))
	_ = reg.Register(newFake("sandbox"))

	abs, err := filepath.Abs("/projects/app")
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}
	if err := reg.Bind(abs, "sandbox"); err != nil {
		t.Fatalf("Bind: %v", err)
	}

	// Trailing slashes and "." segments must resolve to the same binding —
	// otherwise a project reached via a cosmetically different path would
	// silently run on the default executor.
	for _, variant := range []string{abs + "/", abs + "/.", filepath.Join(abs, "sub", "..")} {
		ex, err := reg.Resolve(variant)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", variant, err)
		}
		if ex.ID() != "sandbox" {
			t.Errorf("Resolve(%q) = %q, want sandbox", variant, ex.ID())
		}
	}
}

func TestPersistentBindingLookup(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(newFake("local"))
	_ = reg.Register(newFake("sandbox"))

	calls := 0
	reg.SetBindingLookup(func(projectPath string) (string, bool) {
		calls++
		if projectPath == filepath.Clean("/projects/persisted") {
			return "sandbox", true
		}
		return "", false
	})

	ex, err := reg.Resolve("/projects/persisted")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ex.ID() != "sandbox" {
		t.Fatalf("Resolve via persistent lookup = %q, want sandbox", ex.ID())
	}
	if calls == 0 {
		t.Fatal("persistent lookup was never consulted")
	}

	// Unknown project → lookup says no → default.
	if ex, err := reg.Resolve("/projects/other"); err != nil || ex.ID() != "local" {
		t.Fatalf("Resolve(other) = (%v, %v), want local", ex, err)
	}

	// The in-memory binding takes precedence over storage.
	if err := reg.Bind("/projects/persisted", "local"); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	before := calls
	if ex, err := reg.Resolve("/projects/persisted"); err != nil || ex.ID() != "local" {
		t.Fatalf("Resolve with in-memory override = (%v, %v), want local", ex, err)
	}
	if calls != before {
		t.Error("persistent lookup consulted despite an in-memory binding")
	}

	// Removing the lookup returns to pure default behavior.
	reg.SetBindingLookup(nil)
	reg.Unbind("/projects/persisted")
	if ex, err := reg.Resolve("/projects/persisted"); err != nil || ex.ID() != "local" {
		t.Fatalf("Resolve after clearing lookup = (%v, %v), want local", ex, err)
	}
}

func TestUnregisterReassignsDefault(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(newFake("aaa"))
	_ = reg.Register(newFake("bbb"))
	if reg.DefaultID() != "aaa" {
		t.Fatalf("DefaultID = %q, want aaa", reg.DefaultID())
	}

	reg.Unregister("aaa")
	if reg.DefaultID() != "bbb" {
		t.Fatalf("DefaultID after Unregister = %q, want bbb", reg.DefaultID())
	}

	reg.Unregister("bbb")
	if reg.DefaultID() != "" {
		t.Fatalf("DefaultID on empty registry = %q, want empty", reg.DefaultID())
	}
	if _, err := reg.Default(); !errors.Is(err, ErrNoDefault) {
		t.Fatalf("Default = %v, want ErrNoDefault", err)
	}
}

func TestListIsSortedAndStable(t *testing.T) {
	reg := NewRegistry()
	for _, id := range []string{"zeta", "alpha", "mid"} {
		_ = reg.Register(newFake(id))
	}
	got := reg.List()
	want := []string{"alpha", "mid", "zeta"}
	if len(got) != len(want) {
		t.Fatalf("List returned %d executors, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].ID() != want[i] {
			t.Errorf("List()[%d] = %q, want %q", i, got[i].ID(), want[i])
		}
	}
}

// TestRegistryConcurrentAccess exercises the mutex under -race: the registry
// is read on every run request and written whenever an executor enrolls or
// drops out.
func TestRegistryConcurrentAccess(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(newFake("local"))
	reg.SetBindingLookup(func(string) (string, bool) { return "", false })

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_, _ = reg.Resolve("/projects/app")
				_ = reg.List()
				_ = reg.DefaultID()
				id := "dyn-" + string(rune('a'+i%26))
				_ = reg.Ensure(newFake(id))
				_ = reg.Bind("/projects/app", "local")
				reg.Unbind("/projects/other")
			}
		}(i)
	}
	wg.Wait()
}

func TestSpecValidate(t *testing.T) {
	cases := []struct {
		name    string
		spec    Spec
		wantErr bool
	}{
		{name: "minimal valid", spec: Spec{Argv: []string{"cloop", "run"}}},
		{name: "valid with env", spec: Spec{Argv: []string{"cloop"}, Env: []string{"A=1", "B="}}},
		{name: "empty argv", spec: Spec{}, wantErr: true},
		{name: "blank argv0", spec: Spec{Argv: []string{"  "}}, wantErr: true},
		{name: "negative timeout", spec: Spec{Argv: []string{"cloop"}, TimeoutMinutes: -1}, wantErr: true},
		{name: "malformed env", spec: Spec{Argv: []string{"cloop"}, Env: []string{"NOEQUALS"}}, wantErr: true},
		{
			name:    "negative memory limit",
			spec:    Spec{Argv: []string{"cloop"}, ResourceLimits: ResourceLimits{MemoryMB: -5}},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.spec.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("Validate() = nil, want error")
			}
			if tc.wantErr && !errors.Is(err, ErrInvalidSpec) {
				t.Fatalf("Validate() = %v, want ErrInvalidSpec", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestSpecTimeout(t *testing.T) {
	if d := (Spec{}).Timeout(); d != 0 {
		t.Fatalf("zero TimeoutMinutes → %v, want 0 (unbounded)", d)
	}
	if d := (Spec{TimeoutMinutes: 3}).Timeout(); d != 3*time.Minute {
		t.Fatalf("Timeout() = %v, want 3m", d)
	}
}

func TestStateTerminalAndSignalValid(t *testing.T) {
	terminal := map[State]bool{
		StatePending: false, StateRunning: false, StateUnknown: false,
		StateExited: true, StateFailed: true, StateKilled: true,
	}
	for st, want := range terminal {
		if st.Terminal() != want {
			t.Errorf("State(%q).Terminal() = %v, want %v", st, st.Terminal(), want)
		}
	}
	for _, sig := range []Signal{SignalInterrupt, SignalTerminate, SignalKill} {
		if !sig.Valid() {
			t.Errorf("Signal(%q).Valid() = false, want true", sig)
		}
	}
	if Signal("sigsegv").Valid() {
		t.Error("unknown signal reported valid")
	}
}
