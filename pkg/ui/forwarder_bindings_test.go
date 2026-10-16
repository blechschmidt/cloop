package ui

// Tests for device forwarder bindings and their dispatch (Task 20430): who may
// bind, that a project gets exactly what is bound to it, that a dispatch with
// an offline forwarder is refused naming it, and that revoking a binding — by
// route, from the CLI, or by its TTL running out — detaches the device from a
// run already holding it.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/deviceforward"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// fakeReach stands in for forwarders: the ones named online answer an open
// with one end of a pipe, whose other end the test holds.
type fakeReach struct {
	mu      sync.Mutex
	up      map[string]bool
	devices map[string][]net.Conn
}

func newFakeReach(t *testing.T, online ...string) *fakeReach {
	t.Helper()
	f := &fakeReach{up: map[string]bool{}, devices: map[string][]net.Conn{}}
	for _, id := range online {
		f.up[id] = true
	}
	prev := forwarderReach
	forwarderReach = f
	t.Cleanup(func() {
		forwarderReach = prev
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, cs := range f.devices {
			for _, c := range cs {
				_ = c.Close()
			}
		}
	})
	return f
}

func (f *fakeReach) online(id string) (bool, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.up[id], "test-member"
}

func (f *fakeReach) open(ctx context.Context, id, purpose, binding string) (io.ReadWriteCloser, deviceforward.ExportedDevice, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.up[id] {
		return nil, deviceforward.ExportedDevice{}, deviceforward.ErrForwarderOffline
	}
	hub, device := net.Pipe()
	f.devices[id] = append(f.devices[id], device)
	return hub, deviceforward.ExportedDevice{Kind: deviceforward.KindUSB, BusID: "1-1"}, nil
}

// device returns the forwarder's end of the n-th stream opened to id.
func (f *fakeReach) device(t *testing.T, id string, n int) net.Conn {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.devices[id]) <= n {
		t.Fatalf("no stream %d was opened to forwarder %s", n, id)
	}
	return f.devices[id][n]
}

// takerExecutor is an executor whose sandboxes take forwarded devices, as an
// agent's do; refuse, when set, is its refusal.
type takerExecutor struct {
	id, kind string
	refuse   error
}

func (e *takerExecutor) ID() string   { return e.id }
func (e *takerExecutor) Kind() string { return e.kind }
func (e *takerExecutor) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: executor.IsolationRemote}
}
func (e *takerExecutor) Start(context.Context, executor.Spec) (executor.Handle, error) {
	return executor.Handle{}, errors.New("not used")
}
func (e *takerExecutor) Signal(context.Context, string, executor.Signal) error { return nil }
func (e *takerExecutor) Status(context.Context, string) (executor.Status, error) {
	return executor.Status{}, executor.ErrHandleNotFound
}
func (e *takerExecutor) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	return nil, executor.ErrHandleNotFound
}
func (e *takerExecutor) HealthCheck(context.Context) error            { return nil }
func (e *takerExecutor) CanTakeForwardedDevices(kinds []string) error { return e.refuse }

// plainHost is an executor that is not a ForwardedDeviceTaker at all.
type plainHost struct{ id string }

func (e *plainHost) ID() string   { return e.id }
func (e *plainHost) Kind() string { return executor.KindLocalProcess }
func (e *plainHost) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: executor.IsolationNone}
}
func (e *plainHost) Start(context.Context, executor.Spec) (executor.Handle, error) {
	return executor.Handle{}, errors.New("not used")
}
func (e *plainHost) Signal(context.Context, string, executor.Signal) error { return nil }
func (e *plainHost) Status(context.Context, string) (executor.Status, error) {
	return executor.Status{}, executor.ErrHandleNotFound
}
func (e *plainHost) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	return nil, executor.ErrHandleNotFound
}
func (e *plainHost) HealthCheck(context.Context) error { return nil }

// forwarderFixture is a hub directory with forwarders enrolled in its control
// plane, and the control plane pointed at it.
type forwarderFixture struct {
	dir     string
	project string
	srv     *Server
}

func newForwarderFixture(t *testing.T, forwarders ...string) forwarderFixture {
	t.Helper()
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, id := range forwarders {
		dev, _ := json.Marshal(deviceforward.ForwardedDevice{Kind: deviceforward.KindUSB,
			USB: &executor.USBMatch{VendorID: "0627", ProductID: "0001"}})
		if err := db.PutForwarder(statedb.ForwarderRow{ForwarderID: id, Name: "bench " + id, SecretHash: "00",
			DeviceJSON: string(dev), CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	return forwarderFixture{dir: dir, project: policyProjectPath(dir), srv: srv}
}

func (f forwarderFixture) db(t *testing.T) *statedb.DB {
	t.Helper()
	db, err := statedb.Open(state.DBPath(f.dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func (f forwarderFixture) bind(t *testing.T, forwarderID, project, vx string, ttl time.Duration) statedb.ForwarderBindingRow {
	t.Helper()
	row, err := CreateForwarderBinding(f.db(t), ForwarderBindingInput{
		ForwarderID: forwarderID, Project: project, VirtualExecutor: vx, TTL: ttl, Actor: "admin@example.com",
	}, time.Now())
	if err != nil {
		t.Fatalf("CreateForwarderBinding: %v", err)
	}
	return row
}

// auditCount counts the control plane's audit rows of one action.
func (f forwarderFixture) auditCount(t *testing.T, action auditaction.Action) int {
	t.Helper()
	db := f.db(t)
	evs, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: string(action), Limit: 1000})
	if err != nil {
		t.Fatalf("ListAuditEvents: %v", err)
	}
	return len(evs)
}

// eofWithin reports whether reading c ends within d — the relay closed it.
func eofWithin(c net.Conn, d time.Duration) bool {
	_ = c.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 64)
	for {
		if _, err := c.Read(buf); err != nil {
			var ne net.Error
			return !(errors.As(err, &ne) && ne.Timeout())
		}
	}
}

// TestUnboundProjectGetsNoForwardedDevices: a project with no binding — or
// whose bindings name another project, or a virtual executor its run is not
// on — dispatches exactly as before, with nothing opened.
func TestUnboundProjectGetsNoForwardedDevices(t *testing.T) {
	f := newForwarderFixture(t, "fwdA")
	reach := newFakeReach(t, "fwdA")
	ex := &takerExecutor{id: "edge-1", kind: executor.KindRemoteAgent}
	spec := executor.Spec{WorkDir: f.dir, Argv: []string{"cloop", "run"}}

	out, rf, err := applyForwardedDevices(spec, ex, f.dir, "run-1")
	if err != nil || rf != nil || len(out.ForwardedDevices) != 0 {
		t.Fatalf("an unbound project got %d devices (set %v, err %v); want none", len(out.ForwardedDevices), rf, err)
	}

	other := t.TempDir()
	f.bind(t, "fwdA", other, "", time.Hour)
	// Narrowed to a virtual executor this run is not on — written directly,
	// since that executor is not on this test hub.
	if err := f.db(t).PutForwarderBinding(statedb.ForwarderBindingRow{ID: "fbd_vx", ForwarderID: "fwdA",
		Project: f.project, VirtualExecutor: "vx-not-this-one", CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	out, rf, err = applyForwardedDevices(spec, ex, f.dir, "run-2")
	if err != nil || rf != nil || len(out.ForwardedDevices) != 0 {
		t.Fatalf("a project bound only through another project or virtual executor got %d devices (err %v)",
			len(out.ForwardedDevices), err)
	}
	if n := len(reach.devices["fwdA"]); n != 0 {
		t.Fatalf("%d streams were opened for a project with nothing bound to it", n)
	}
}

// TestBoundForwarderOfflineRefusesTheDispatch: a run whose bound forwarder has
// no live session is refused, and the refusal names the forwarder.
func TestBoundForwarderOfflineRefusesTheDispatch(t *testing.T) {
	f := newForwarderFixture(t, "fwdB")
	newFakeReach(t) // nothing online
	f.bind(t, "fwdB", f.project, "", time.Hour)
	ex := &takerExecutor{id: "edge-1", kind: executor.KindRemoteAgent}
	_, _, err := applyForwardedDevices(executor.Spec{WorkDir: f.dir, Argv: []string{"x"}}, ex, f.dir, "run-1")
	var off *forwarderOfflineError
	if !errors.As(err, &off) {
		t.Fatalf("dispatch with an offline forwarder = %v, want a forwarderOfflineError", err)
	}
	if !strings.Contains(err.Error(), "bench fwdB") || !strings.Contains(err.Error(), "fwdB") {
		t.Fatalf("the refusal %q does not name the forwarder", err)
	}
}

// TestForwardedDeviceOnlyReachesASandbox: an executor with no sandbox — a host
// process — is refused the device, and an agent that says it cannot take it
// is refused in its own words.
func TestForwardedDeviceOnlyReachesASandbox(t *testing.T) {
	f := newForwarderFixture(t, "fwdC")
	newFakeReach(t, "fwdC")
	f.bind(t, "fwdC", f.project, "", time.Hour)
	spec := executor.Spec{WorkDir: f.dir, Argv: []string{"x"}}

	_, _, err := applyForwardedDevices(spec, &plainHost{id: "local"}, f.dir, "run-1")
	var refused *forwardedDevicesRefusedError
	if !errors.As(err, &refused) || !strings.Contains(err.Error(), "no sandbox") {
		t.Fatalf("a host-process run of a bound project = %v, want a refusal saying it has no sandbox", err)
	}

	agentRefusal := errors.New("the device's agent speaks protocol v21, and the hub needs v22")
	_, _, err = applyForwardedDevices(spec, &takerExecutor{id: "old", kind: executor.KindRemoteAgent, refuse: agentRefusal}, f.dir, "run-2")
	if !errors.Is(err, agentRefusal) {
		t.Fatalf("an agent that cannot take the device = %v, want its own refusal", err)
	}
}

// openForRun dispatches a bound project's run on a taker executor the way the
// remote driver would: opening each device, then binding the run's handle.
func openForRun(t *testing.T, f forwarderFixture, handle string) (*runForwards, executor.ForwardedDevice) {
	t.Helper()
	ex := &takerExecutor{id: "edge-1", kind: executor.KindRemoteAgent}
	out, rf, err := applyForwardedDevices(executor.Spec{WorkDir: f.dir, Argv: []string{"x"}}, ex, f.dir, "run-"+handle)
	if err != nil || rf == nil || len(out.ForwardedDevices) != 1 {
		t.Fatalf("applyForwardedDevices = %d devices, set %v, err %v; want one", len(out.ForwardedDevices), rf, err)
	}
	fd := out.ForwardedDevices[0]
	if fd.Kind != executor.ForwardedUSB || fd.Name == "" || fd.Open == nil {
		t.Fatalf("forwarded device = %+v", fd)
	}
	st, err := fd.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if st.BusID != "1-1" {
		t.Fatalf("the stream names bus id %q, want the forwarder's 1-1", st.BusID)
	}
	rf.bindHandle(ex, handle)
	return rf, fd
}

// TestRevokedBindingDetachesTheDeviceMidRun: unbinding through the dashboard
// route closes the stream a running workload holds — the forwarder's end sees
// it end — and the trail records the attach, the unbind and the detach.
func TestRevokedBindingDetachesTheDeviceMidRun(t *testing.T) {
	f := newForwarderFixture(t, "fwdD")
	reach := newFakeReach(t, "fwdD")
	b := f.bind(t, "fwdD", f.project, "", time.Hour)
	openForRun(t, f, "h-revoke")
	device := reach.device(t, "fwdD", 0)
	if n := len(forwardsInUse(b.ID)); n != 1 {
		t.Fatalf("the binding shows %d runs using it, want 1", n)
	}

	ts := newTestHTTPServer(t, f.srv)
	status, body := do(t, http.DefaultClient, http.MethodDelete, ts+"/api/forwarders/bindings/"+b.ID, "")
	if status != http.StatusOK {
		t.Fatalf("DELETE binding = %d %s", status, body)
	}
	if !eofWithin(device, 3*time.Second) {
		t.Fatal("the run kept the device after its binding was revoked")
	}
	if n := len(forwardsInUse(b.ID)); n != 0 {
		t.Fatalf("%d runs still hold the revoked binding's device", n)
	}
	for _, a := range []auditaction.Action{auditaction.ActionForwarderBind, auditaction.ActionForwarderAttach,
		auditaction.ActionForwarderUnbind, auditaction.ActionForwarderDetach} {
		if f.auditCount(t, a) != 1 {
			t.Errorf("audit rows for %s = %d, want 1", a, f.auditCount(t, a))
		}
	}
}

// TestBindingRevokedElsewhereDetachesAtTheRecheck: a revocation recorded by
// something that is not this hub member — the CLI — detaches the device at the
// member's next re-check of the store.
func TestBindingRevokedElsewhereDetachesAtTheRecheck(t *testing.T) {
	f := newForwarderFixture(t, "fwdE")
	reach := newFakeReach(t, "fwdE")
	b := f.bind(t, "fwdE", f.project, "", time.Hour)
	openForRun(t, f, "h-cli")
	device := reach.device(t, "fwdE", 0)

	if _, changed, err := RevokeForwarderBindingRecord(f.db(t), b.ID, "cli:root", "", time.Now()); err != nil || !changed {
		t.Fatalf("RevokeForwarderBindingRecord = %v, %v", changed, err)
	}
	recheckForwards(time.Now())
	if !eofWithin(device, 3*time.Second) {
		t.Fatal("a binding revoked from the CLI left the device attached past the re-check")
	}
}

// TestLapsedBindingDetachesOnceAudited: a binding whose TTL runs out mid-run
// detaches the device, and its lapse is recorded once however many members
// notice.
func TestLapsedBindingDetachesOnceAudited(t *testing.T) {
	f := newForwarderFixture(t, "fwdF")
	reach := newFakeReach(t, "fwdF")
	b := f.bind(t, "fwdF", f.project, "", time.Hour)
	openForRun(t, f, "h-ttl")
	device := reach.device(t, "fwdF", 0)

	later := time.Now().Add(2 * time.Hour)
	recheckForwards(later)
	if !eofWithin(device, 3*time.Second) {
		t.Fatal("a lapsed binding left the device attached")
	}
	recheckForwards(later)
	sweepLapsedForwarderBindings(later)
	if n := f.auditCount(t, auditaction.ActionForwarderUnbind); n != 1 {
		t.Fatalf("a lapse was audited %d times, want once", n)
	}
	got, err := f.db(t).GetForwarderBinding(b.ID)
	if err != nil || !got.Revoked() {
		t.Fatalf("the lapsed binding is not stamped revoked: %+v %v", got, err)
	}
}

// TestRunEndDetachesTheDevice: the run's end, however it is reached, closes
// what it held.
func TestRunEndDetachesTheDevice(t *testing.T) {
	f := newForwarderFixture(t, "fwdG")
	reach := newFakeReach(t, "fwdG")
	f.bind(t, "fwdG", f.project, "", time.Hour)
	openForRun(t, f, "h-end")
	device := reach.device(t, "fwdG", 0)
	closeRunForwards("h-end", "the run ended")
	if !eofWithin(device, 3*time.Second) {
		t.Fatal("the run's end left the device attached")
	}
}

// TestForwarderRevocationCascadesToBindings: revoking a forwarder revokes its
// bindings, each audited, and detaches its device from running work.
func TestForwarderRevocationCascadesToBindings(t *testing.T) {
	f := newForwarderFixture(t, "fwdH")
	reach := newFakeReach(t, "fwdH")
	b := f.bind(t, "fwdH", f.project, "", time.Hour)
	openForRun(t, f, "h-fwd")
	device := reach.device(t, "fwdH", 0)

	ts := newTestHTTPServer(t, f.srv)
	if status, body := do(t, http.DefaultClient, http.MethodDelete, ts+"/api/forwarders/fwdH", ""); status != http.StatusOK {
		t.Fatalf("DELETE forwarder = %d %s", status, body)
	}
	if !eofWithin(device, 3*time.Second) {
		t.Fatal("revoking the forwarder left its device attached to a run")
	}
	got, err := f.db(t).GetForwarderBinding(b.ID)
	if err != nil || !got.Revoked() {
		t.Fatalf("the revoked forwarder's binding is still in force: %+v %v", got, err)
	}
}

// TestForwarderBindingValidation: a binding names a live forwarder and a real
// project, lasts at most the ceiling, and is not made twice.
func TestForwarderBindingValidation(t *testing.T) {
	f := newForwarderFixture(t, "fwdI")
	db := f.db(t)
	now := time.Now()
	cases := map[string]ForwarderBindingInput{
		"unknown forwarder": {ForwarderID: "nope", Project: f.project},
		"relative project":  {ForwarderID: "fwdI", Project: "relative/dir"},
		"too long":          {ForwarderID: "fwdI", Project: f.project, TTL: ForwarderBindingTTLMax + time.Hour},
		"interface on usb":  {ForwarderID: "fwdI", Project: f.project, Interface: forwardedInterface{Target: "eth1"}},
		"no such virtual":   {ForwarderID: "fwdI", Project: f.project, VirtualExecutor: "vx-missing"},
	}
	for name, in := range cases {
		if _, err := CreateForwarderBinding(db, in, now); err == nil {
			t.Errorf("%s: binding accepted", name)
		}
	}
	f.bind(t, "fwdI", f.project, "", time.Hour)
	if _, err := CreateForwarderBinding(db, ForwarderBindingInput{ForwarderID: "fwdI", Project: f.project}, now); !errors.Is(err, errBindingConflict) {
		t.Fatalf("a second binding of the same forwarder to the same project = %v, want a conflict", err)
	}
}

// TestForwarderBindingRoutesDeclareTheirPermissions pins the gates: binding,
// unbinding and probing take executor.manage at the global scope — enrolling a
// forwarder's own permission — reading takes executor.read, and asking takes
// secret.request.
func TestForwarderBindingRoutesDeclareTheirPermissions(t *testing.T) {
	want := map[string]authz.Permission{
		"GET /api/forwarders/bindings":          authz.PermExecutorRead,
		"POST /api/forwarders/{id}/bindings":    authz.PermExecutorManage,
		"DELETE /api/forwarders/bindings/{bid}": authz.PermExecutorManage,
		"POST /api/forwarders/{id}/expose":      authz.PermExecutorManage,
		"GET /api/forwarders/requests":          authz.PermSecretRequest,
		"GET /api/projects/{idx}/forwarders":    authz.PermExecutorRead,
	}
	srv := New(t.TempDir(), 0, "")
	for _, r := range srv.forwarderRoutes() {
		perm, ok := want[r.Pattern]
		if !ok {
			continue
		}
		if r.Perm != perm {
			t.Errorf("%s takes %s, want %s", r.Pattern, r.Perm, perm)
		}
		if strings.Contains(r.Pattern, "/bindings") && r.Perm == authz.PermExecutorManage && r.Scope != scopeGlobal {
			t.Errorf("%s is decided at %v, want the global scope: a project role must not bind hardware", r.Pattern, r.Scope)
		}
		delete(want, r.Pattern)
	}
	for p := range want {
		t.Errorf("route %s is missing", p)
	}
}

// TestForwarderBindingRequestFlow: a maintainer cannot bind but may ask, the
// ask lands in an administrator's inbox and not in the maintainer's, the
// maintainer cannot decide it, and an administrator's approval mints the
// binding — never the requester's own.
func TestForwarderBindingRequestFlow(t *testing.T) {
	af := newApprovalsFixture(t)
	dir := af.srv.WorkDir
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	dev, _ := json.Marshal(deviceforward.ForwardedDevice{Kind: deviceforward.KindUSB,
		USB: &executor.USBMatch{VendorID: "0627", ProductID: "0001"}})
	if err := db.PutForwarder(statedb.ForwarderRow{ForwarderID: "fwdR", Name: "bench", SecretHash: "00",
		DeviceJSON: string(dev), CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	db.Close()
	project := policyProjectPath(dir)

	maint := af.as(t, "maint@example.com")
	status, body := do(t, maint, http.MethodPost, af.ts+"/api/forwarders/fwdR/bindings",
		`{"project":`+jsonString(project)+`}`)
	if status != http.StatusForbidden {
		t.Fatalf("a maintainer binding a forwarder = %d %s, want 403", status, body)
	}
	status, body = do(t, maint, http.MethodPost, af.ts+"/api/grant-requests",
		`{"source":"forwarder","forwarder_id":"fwdR","project":`+jsonString(project)+`,"ttl_minutes":120,"justification":"bring-up of the bench tablet"}`)
	if status != http.StatusOK {
		t.Fatalf("a maintainer asking for a binding = %d %s", status, body)
	}
	var req requestView
	_ = json.Unmarshal([]byte(body), &req)
	if !strings.HasPrefix(req.ID, forwarderRequestPrefix) || req.State != "pending" {
		t.Fatalf("filed request = %+v", req)
	}

	// The maintainer cannot decide it, and it is not in their inbox.
	if status, _ := do(t, maint, http.MethodPost, af.ts+"/api/grant-requests/"+req.ID+"/approve", ""); status != http.StatusForbidden {
		t.Fatalf("the maintainer approving their own binding request = %d, want 403", status)
	}
	var inbox approvalsView
	getJSONAs(t, maint, af.ts+"/api/approvals", &inbox)
	for _, it := range inbox.Items {
		if it.ID == req.ID {
			t.Fatal("the requester's inbox offers their own binding request to decide")
		}
	}

	admin := af.as(t, "admin@example.com")
	inbox = approvalsView{}
	getJSONAs(t, admin, af.ts+"/api/approvals", &inbox)
	found := false
	for _, it := range inbox.Items {
		found = found || it.ID == req.ID
	}
	if !found {
		t.Fatalf("an administrator's inbox does not list the binding request: %v", inboxIDs(inbox))
	}
	status, body = do(t, admin, http.MethodPost, af.ts+"/api/grant-requests/"+req.ID+"/approve", `{"ttl_minutes":60}`)
	if status != http.StatusOK || !strings.Contains(body, forwarderBindingPrefix) {
		t.Fatalf("an administrator approving = %d %s", status, body)
	}
	db, _ = statedb.Open(state.DBPath(dir))
	defer db.Close()
	rows, _ := db.ListForwarderBindings(statedb.ForwarderBindingFilter{Project: project, ActiveAt: time.Now()})
	if len(rows) != 1 || rows[0].RequestID != req.ID {
		t.Fatalf("approval minted %+v, want one binding naming the request", rows)
	}
	if left := time.Until(rows[0].ExpiresAt); left > 61*time.Minute || left < 59*time.Minute {
		t.Fatalf("the approver narrowed the binding to an hour, but it lasts %s", left)
	}

	// An administrator's own request is not theirs to approve.
	status, body = do(t, admin, http.MethodPost, af.ts+"/api/grant-requests",
		`{"source":"forwarder","forwarder_id":"fwdR","project":`+jsonString(project)+`,"virtual_executor":"","justification":"second"}`)
	if status != http.StatusOK {
		t.Fatalf("an administrator asking = %d %s", status, body)
	}
	_ = json.Unmarshal([]byte(body), &req)
	if status, _ := do(t, admin, http.MethodPost, af.ts+"/api/grant-requests/"+req.ID+"/approve", ""); status != http.StatusForbidden {
		t.Fatalf("approving one's own binding request = %d, want 403", status)
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// newTestHTTPServer serves srv's handler for one test.
func newTestHTTPServer(t *testing.T, srv *Server) string {
	t.Helper()
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts.URL
}

// TestForwardedDeviceRefusalsAreConflicts: a dispatch refused for a forwarded
// device answers 409 with a code and a remedy, never a 500 — the request was
// well formed, and what conflicts is the binding with the forwarder or the
// executor.
func TestForwardedDeviceRefusalsAreConflicts(t *testing.T) {
	for code, err := range map[string]error{
		"forwarder_offline":            &forwarderOfflineError{ForwarderID: "fwd1", Name: "bench"},
		"forwarded_device_unsupported": &forwardedDevicesRefusedError{ExecutorID: "local", Reason: "no sandbox"},
	} {
		rec := httptest.NewRecorder()
		jsonWorkloadErr(rec, err)
		var body struct {
			Code        string `json:"code"`
			Remediation string `json:"remediation"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != http.StatusConflict || body.Code != code || body.Remediation == "" {
			t.Errorf("%T answered %d %+v; want 409 %s with a remedy", err, rec.Code, body, code)
		}
	}
}
