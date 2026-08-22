package security

// Guarantee 2: under strict no-host-execution mode, an executor that offers
// no isolation is refused at registration and at Start, with a typed error.
//
// "Typed error" is the part that is easy to get wrong and expensive to get
// wrong. A refusal that is only a log line cannot be handled: the UI cannot
// turn it into a 409 with remediation, the CLI cannot distinguish it from a
// crash, and a caller that ignores errors proceeds to run the workload
// anyway. So these tests assert both that the refusal happens and that it
// arrives as something a caller can branch on — errors.Is against the
// sentinel and errors.As into the rich form that names the alternatives.
//
// The policy is process-global by design (see pkg/executor/policy.go), so
// nothing here may call t.Parallel().

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/localprocess"
	"github.com/blechschmidt/cloop/pkg/ui"
)

// strictMode turns on no-host-execution for the duration of a test and
// restores the previous setting afterwards.
func strictMode(t *testing.T) {
	t.Helper()
	prev := executor.SetAllowHostExecution(false)
	t.Cleanup(func() { executor.SetAllowHostExecution(prev) })
}

// permissiveMode is the explicit opposite, for tests that assert the default
// path still works.
func permissiveMode(t *testing.T) {
	t.Helper()
	prev := executor.SetAllowHostExecution(true)
	t.Cleanup(func() { executor.SetAllowHostExecution(prev) })
}

// fakeExecutor is a driver that reports whatever isolation it is told to,
// so the policy can be tested against every isolation level rather than only
// against the one driver that happens to be un-isolated today.
type fakeExecutor struct {
	id        string
	kind      string
	isolation executor.Isolation
}

func (f fakeExecutor) ID() string   { return f.id }
func (f fakeExecutor) Kind() string { return f.kind }
func (f fakeExecutor) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: f.isolation}
}
func (f fakeExecutor) Start(context.Context, executor.Spec) (executor.Handle, error) {
	return executor.Handle{ID: "h1", ExecutorID: f.id}, nil
}
func (f fakeExecutor) Signal(context.Context, string, executor.Signal) error { return nil }
func (f fakeExecutor) Status(context.Context, string) (executor.Status, error) {
	return executor.Status{}, nil
}
func (f fakeExecutor) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	ch := make(chan executor.LogLine)
	close(ch)
	return ch, nil
}
func (f fakeExecutor) HealthCheck(context.Context) error { return nil }

// TestStrictModeRefusesHostExecutorAtRegistration is the first of the two
// enforcement points. Refusing here matters more than it looks: an executor
// that is never registered can never become the registry's default, so a
// project with no explicit binding fails closed instead of quietly landing on
// the host.
func TestStrictModeRefusesHostExecutorAtRegistration(t *testing.T) {
	strictMode(t)

	for _, tc := range []struct {
		name       string
		isolation  executor.Isolation
		wantRefuse bool
	}{
		{"no isolation is refused", executor.IsolationNone, true},
		{"container isolation is allowed", executor.IsolationContainer, false},
		{"vm isolation is allowed", executor.IsolationVM, false},
		{"remote isolation is allowed", executor.IsolationRemote, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := executor.NewRegistry()
			err := reg.Register(fakeExecutor{
				id: "ex-" + tc.name, kind: "fake", isolation: tc.isolation,
			})

			if !tc.wantRefuse {
				if err != nil {
					t.Fatalf("Register(%s) = %v, want nil — isolating drivers "+
						"must still register under strict mode", tc.isolation, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Register(%s) succeeded under strict mode; an "+
					"un-isolated executor must be refused", tc.isolation)
			}
			assertTypedHostDenial(t, err)
			if _, getErr := reg.Get("ex-" + tc.name); getErr == nil {
				t.Error("the refused executor is still in the registry")
			}
			if reg.DefaultID() != "" {
				t.Errorf("a refused executor became the default (%q)", reg.DefaultID())
			}
		})
	}
}

// TestStrictModeRefusesHostExecutorAtStart is the backstop: a caller holding a
// direct driver reference, which never goes through Resolve, must still be
// refused by the driver itself.
func TestStrictModeRefusesHostExecutorAtStart(t *testing.T) {
	strictMode(t)

	ex := localprocess.New("direct-ref")
	_, err := ex.Start(context.Background(), executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"/bin/true"},
	})
	if err == nil {
		t.Fatal("localprocess.Start succeeded under strict mode — the driver " +
			"must refuse even when the caller bypassed Resolve")
	}
	assertTypedHostDenial(t, err)
}

// TestStrictModeRefusesAtResolve covers the path every UI handler actually
// takes.
func TestStrictModeRefusesAtResolve(t *testing.T) {
	strictMode(t)

	reg := executor.NewRegistry()
	// Registration is refused under strict mode, so seed the registry the way
	// a real process does: permissively, before the policy is read. This is
	// exactly the bootstrap-ordering case the eviction sweep exists for, and
	// Resolve must refuse regardless of how the executor got in.
	executor.SetAllowHostExecution(true)
	if err := reg.Register(fakeExecutor{id: "host", kind: executor.KindLocalProcess}); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	if err := reg.Register(fakeExecutor{
		id: "sandbox", kind: executor.KindContainer, isolation: executor.IsolationContainer,
	}); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	executor.SetAllowHostExecution(false)

	_, err := reg.Resolve(t.TempDir())
	if err == nil {
		t.Fatal("Resolve returned the host executor under strict mode")
	}
	assertTypedHostDenial(t, err)

	// The refusal must name the isolated alternative, or the operator who
	// hits it in a browser has no way to know what to do next.
	var denied *executor.HostExecutionDeniedError
	if errors.As(err, &denied) {
		if len(denied.Alternatives) == 0 || denied.Alternatives[0] != "sandbox" {
			t.Errorf("Alternatives = %v, want it to name the registered "+
				"isolated executor", denied.Alternatives)
		}
		if !strings.Contains(denied.Remediation(), "sandbox") {
			t.Errorf("Remediation() = %q, want it to name the alternative",
				denied.Remediation())
		}
	}
}

// TestApplyHostExecutionPolicyEvictsHostDrivers proves the sweep that makes
// bootstrap order irrelevant. `cloop ui` registers the host driver from
// several entry points; if any of them runs before the config is read, the
// registration-time refusal never fires and a host driver stays registered —
// and therefore eligible to be the default — in a deployment that forbids it.
func TestApplyHostExecutionPolicyEvictsHostDrivers(t *testing.T) {
	permissiveMode(t)

	if err := executor.DefaultRegistry.Ensure(fakeExecutor{
		id: "sweep-host", kind: executor.KindLocalProcess,
	}); err != nil {
		t.Fatalf("seed host executor: %v", err)
	}
	if err := executor.DefaultRegistry.Ensure(fakeExecutor{
		id: "sweep-sandbox", kind: executor.KindContainer, isolation: executor.IsolationContainer,
	}); err != nil {
		t.Fatalf("seed sandbox executor: %v", err)
	}
	t.Cleanup(func() {
		executor.DefaultRegistry.Unregister("sweep-host")
		executor.DefaultRegistry.Unregister("sweep-sandbox")
	})

	executor.ApplyHostExecutionPolicy(false)
	t.Cleanup(func() { executor.SetAllowHostExecution(true) })

	if _, err := executor.DefaultRegistry.Get("sweep-host"); err == nil {
		t.Error("the un-isolated executor survived ApplyHostExecutionPolicy(false)")
	}
	if _, err := executor.DefaultRegistry.Get("sweep-sandbox"); err != nil {
		t.Errorf("the isolated executor was evicted too: %v", err)
	}
}

// TestPolicyOnlyTightens pins the ratchet. ApplyHostExecutionPolicy is called
// once per Server and once per project config; if a permissive config could
// re-open host execution, any tenant able to write a config.yaml could
// escalate the whole control plane.
func TestPolicyOnlyTightens(t *testing.T) {
	permissiveMode(t)

	executor.ApplyHostExecutionPolicy(false)
	if executor.HostExecutionAllowed() {
		t.Fatal("ApplyHostExecutionPolicy(false) did not disable host execution")
	}
	executor.ApplyHostExecutionPolicy(true)
	if executor.HostExecutionAllowed() {
		t.Error("ApplyHostExecutionPolicy(true) re-enabled host execution; " +
			"the policy must only ever tighten, or a tenant-controlled " +
			"config.yaml becomes a privilege escalation")
	}
	executor.SetAllowHostExecution(true)
}

// gatedEndpoints are the HTTP endpoints enumerated in gatedHostExecution
// (see callgraph_test.go), which cause a program to run on the control-plane
// host and therefore must refuse under strict mode.
//
// The two lists are checked against each other by
// TestGatedListsAgree, so an endpoint cannot be exempted from the static
// check without also being proved to refuse here.
var gatedEndpoints = []struct {
	name    string
	method  string
	path    string
	body    string
	handler string // matching key in gatedHostExecution
}{
	{
		name:    "claude auth status",
		method:  http.MethodGet,
		path:    "/api/claudecode/auth/status",
		handler: "(*github.com/blechschmidt/cloop/pkg/ui.Server).handleClaudeCodeAuthStatus",
	},
	{
		name:    "claude auth login start",
		method:  http.MethodPost,
		path:    "/api/claudecode/auth/login",
		body:    `{}`,
		handler: "(*github.com/blechschmidt/cloop/pkg/ui.Server).handleClaudeCodeAuthLoginStart",
	},
	{
		name:    "claude auth login code",
		method:  http.MethodPost,
		path:    "/api/claudecode/auth/login/code",
		body:    `{"code":"x"}`,
		handler: "(*github.com/blechschmidt/cloop/pkg/ui.Server).handleClaudeCodeAuthLoginCode",
	},
	{
		name:    "claude auth logout",
		method:  http.MethodPost,
		path:    "/api/claudecode/auth/logout",
		body:    `{}`,
		handler: "(*github.com/blechschmidt/cloop/pkg/ui.Server).handleClaudeCodeAuthLogout",
	},
	{
		name:    "inline task replay",
		method:  http.MethodPost,
		path:    "/api/replay-runs",
		body:    `{"task_id":1}`,
		handler: "(*github.com/blechschmidt/cloop/pkg/ui.Server).handleReplayRunCreate",
	},
}

// TestGatedHandlersRefuseUnderStrictMode is what turns the static exemption
// list into a guarantee rather than a suppression. Every handler exempted
// from the call-graph check is exempted *because* it is gated, and this
// proves each gate is really there and really closed.
func TestGatedHandlersRefuseUnderStrictMode(t *testing.T) {
	strictMode(t)

	// ui.New rather than a struct literal: the constructor allocates the maps
	// the middleware chain writes to, and a bare literal panics in the rate
	// limiter before any handler runs — which would make this test pass or
	// fail for reasons unrelated to the policy.
	srv := ui.New(t.TempDir(), 0, "")
	handler := srv.Handler()

	for _, tc := range gatedEndpoints {
		t.Run(tc.name, func(t *testing.T) {
			var body *strings.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			} else {
				body = strings.NewReader("")
			}
			req := httptest.NewRequest(tc.method, tc.path, body)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusConflict {
				t.Fatalf("%s %s under strict mode = HTTP %d, want %d.\n"+
					"This endpoint runs a program on the control-plane host, so "+
					"strict no-host-execution must refuse it. Body: %s",
					tc.method, tc.path, rec.Code, http.StatusConflict,
					truncate(rec.Body.String(), 300))
			}
			// The response must explain itself. A bare 409 sends the operator
			// looking for a bug instead of at their own config.
			if got := rec.Body.String(); !strings.Contains(got, "allow_host_process") {
				t.Errorf("refusal does not name the setting that caused it: %s",
					truncate(got, 300))
			}
		})
	}
}

// TestGatedListsAgree keeps the static exemption list and the behavioral
// proof in lockstep. Exempting a handler from the call-graph check without
// adding it here would be a suppression wearing the costume of a guarantee.
func TestGatedListsAgree(t *testing.T) {
	proved := map[string]bool{}
	for _, e := range gatedEndpoints {
		proved[e.handler] = true
	}
	for key := range gatedHostExecution {
		if !proved[key] {
			t.Errorf("%s is exempt from the call-graph check but no endpoint in "+
				"gatedEndpoints proves it refuses under strict mode. Add one, or "+
				"route the handler through the executor boundary.", key)
		}
	}
	for key := range proved {
		if _, ok := gatedHostExecution[key]; !ok {
			t.Errorf("gatedEndpoints proves %s refuses, but it is not in "+
				"gatedHostExecution — remove the stale entry.", key)
		}
	}
}

// assertTypedHostDenial checks a refusal is machine-readable both ways: as a
// sentinel for callers that only need to branch, and as the rich type for
// callers that need to render remediation.
func assertTypedHostDenial(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, executor.ErrHostExecutionDenied) {
		t.Errorf("error does not wrap ErrHostExecutionDenied, so callers "+
			"cannot distinguish a policy refusal from a failure: %v", err)
	}
	var denied *executor.HostExecutionDeniedError
	if !errors.As(err, &denied) {
		t.Errorf("error is not a *HostExecutionDeniedError, so the UI cannot "+
			"render remediation: %v (%T)", err, err)
		return
	}
	if denied.Remediation() == "" {
		t.Error("Remediation() is empty — the refusal tells the operator nothing")
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
