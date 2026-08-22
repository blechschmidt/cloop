// Handler tests for the Executors panel API (Task 20160).
//
// The behaviour worth pinning here is not "does the handler return JSON" but
// the two properties the feature exists for:
//
//   - the panel's view is the *join* of the live registry, the executors
//     table, and the project bindings, so an operator sees what can actually
//     run work rather than what a single source happens to remember; and
//   - strict no-host-execution mode is enforced at every UI entry point,
//     with a 409 and a remediation rather than a 500 and a shrug.
//
// The policy is a process-global switch (see pkg/executor/policy.go), so every
// test that flips it restores it through t.Cleanup. These tests therefore must
// not run in parallel with each other — none of them call t.Parallel.

package ui

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/localprocess"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// denyHostExecution flips the process-wide policy for the duration of a test.
func denyHostExecution(t *testing.T) {
	t.Helper()
	prev := executor.SetAllowHostExecution(false)
	t.Cleanup(func() { executor.SetAllowHostExecution(prev) })
}

// executorsGET fetches /api/executors and decodes it into the response shape
// the frontend consumes.
func executorsGET(t *testing.T, ts *httptest.Server, query string) executorsResponse {
	t.Helper()
	resp, err := http.Get(ts.URL + "/api/executors" + query)
	if err != nil {
		t.Fatalf("GET /api/executors: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/executors = HTTP %d, want 200", resp.StatusCode)
	}
	var out executorsResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode /api/executors: %v", err)
	}
	return out
}

func TestExecutorsList_IncludesHostDriver(t *testing.T) {
	dir := setupProjectDir(t, "executors list", nil)
	ts := newTestServer(t, dir, nil)

	got := executorsGET(t, ts, "")

	var host *executorView
	for i := range got.Executors {
		if got.Executors[i].Kind == executor.KindLocalProcess {
			host = &got.Executors[i]
		}
	}
	if host == nil {
		t.Fatalf("no localprocess executor in the panel: %+v", got.Executors)
	}
	if !host.Registered {
		t.Error("the built-in host driver must be reported as registered")
	}
	if host.Enrolled {
		t.Error("the built-in host driver must not report as enrolled — the panel would " +
			"offer a Revoke button that the delete handler refuses")
	}
	if len(host.AgentCapabilities) != 0 {
		t.Error("a local driver has no device advertisement; echoing its own capabilities " +
			"back under agent_capabilities makes the panel render the same chips twice")
	}
	if host.Isolation != string(executor.IsolationNone) {
		t.Errorf("host isolation = %q, want %q — the panel must not imply the host driver "+
			"confines anything", host.Isolation, executor.IsolationNone)
	}
	// Load has to be a real number for a driver that can enumerate: rendering
	// "unknown" for the one backend we fully control would be a lie.
	if !host.RunningKnown {
		t.Error("localprocess implements executor.Lister; running_known must be true")
	}
	if got.Project == nil {
		t.Fatal("response carries no project view — the Overview card has nothing to render")
	}
	if got.Project.EffectiveID == "" {
		t.Error("project view has no effective executor, but the host driver is the default")
	}
}

// TestExecutorsList_ReportsBinding checks the registry/storage/binding join:
// a persisted binding must surface in the project view even though nothing in
// the live registry knows about it until Resolve consults the lookup.
func TestExecutorsList_ReportsBinding(t *testing.T) {
	dir := setupProjectDir(t, "executors binding", nil)
	ts := newTestServer(t, dir, nil)

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("open state db: %v", err)
	}
	defer db.Close()
	if err := db.BindProjectExecutor(dir, localprocess.DefaultID, "tester"); err != nil {
		t.Fatalf("bind project: %v", err)
	}

	got := executorsGET(t, ts, "")
	if got.Project == nil || !got.Project.Bound {
		t.Fatalf("project view does not report the binding: %+v", got.Project)
	}
	if got.Project.ExecutorID != localprocess.DefaultID {
		t.Errorf("bound executor = %q, want %q", got.Project.ExecutorID, localprocess.DefaultID)
	}

	var host *executorView
	for i := range got.Executors {
		if got.Executors[i].ID == localprocess.DefaultID {
			host = &got.Executors[i]
		}
	}
	if host == nil {
		t.Fatal("host executor missing from list")
	}
	if len(host.Projects) == 0 {
		t.Error("executor card does not list the project bound to it — the operator " +
			"cannot tell which backend is carrying which work")
	}
}

// TestExecutorsList_StrictModeBanner is the panel half of the enforcement
// story: the mode must be visible, not merely enforced.
func TestExecutorsList_StrictModeBanner(t *testing.T) {
	dir := setupProjectDir(t, "strict banner", nil)
	ts := newTestServer(t, dir, nil)
	denyHostExecution(t)

	got := executorsGET(t, ts, "")
	if !got.Policy.StrictMode || got.Policy.AllowHostProcess {
		t.Fatalf("policy view does not report strict mode: %+v", got.Policy)
	}
	if got.Policy.Banner == "" {
		t.Error("strict mode with no banner — the Executors tab would show nothing")
	}
	if !strings.Contains(strings.ToLower(got.Policy.Banner), "strict") {
		t.Errorf("banner %q does not name the mode it describes", got.Policy.Banner)
	}

	// With no isolated executor configured, the banner must warn rather than
	// congratulate: nothing can run at all in that state. If some other test
	// in this process registered an isolated backend, the honest answer flips
	// to "ok" — assert the mapping, not one branch of it.
	wantSeverity := "warn"
	if len(got.Policy.Alternatives) > 0 {
		wantSeverity = "ok"
	}
	if got.Policy.Severity != wantSeverity {
		t.Errorf("severity = %q, want %q (alternatives: %v)",
			got.Policy.Severity, wantSeverity, got.Policy.Alternatives)
	}

	for _, ex := range got.Executors {
		if ex.Kind == executor.KindLocalProcess {
			if !ex.Blocked {
				t.Error("host executor is not marked blocked under strict mode")
			}
			if ex.BlockedReason == "" {
				t.Error("blocked host executor carries no remediation text")
			}
		}
	}
	if got.Project == nil || !got.Project.Blocked {
		t.Errorf("project view does not report that its target is blocked: %+v", got.Project)
	}
}

func TestExecutorsList_RejectsNonGET(t *testing.T) {
	dir := setupProjectDir(t, "method check", nil)
	ts := newTestServer(t, dir, nil)

	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/executors", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT /api/executors: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("PUT /api/executors = HTTP %d, want 405", resp.StatusCode)
	}
}

func TestExecutorEnroll_ReturnsPasteableCommand(t *testing.T) {
	dir := setupProjectDir(t, "enroll", nil)
	ts := newTestServer(t, dir, nil)

	body := strings.NewReader(`{"name":"edge-1","ttl_minutes":30}`)
	resp, err := http.Post(ts.URL+"/api/executors/enroll", "application/json", body)
	if err != nil {
		t.Fatalf("POST enroll: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST enroll = HTTP %d, want 200", resp.StatusCode)
	}
	var got enrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode enroll response: %v", err)
	}

	if got.ID == "" || got.Token == "" {
		t.Fatalf("enroll response missing id or token: %+v", got)
	}
	// The whole point of the endpoint is that the operator can paste the
	// result on the device without assembling anything by hand.
	if !strings.HasPrefix(got.Command, "cloop executor agent ") {
		t.Errorf("command %q is not the agent invocation", got.Command)
	}
	if !strings.Contains(got.Command, got.Token) {
		t.Error("command does not embed the token — it would not authenticate")
	}
	if !strings.Contains(got.Command, executorConnectPath) {
		t.Errorf("command %q does not point at the agent connect endpoint", got.Command)
	}
	if got.Notice == "" {
		t.Error("no shown-once notice — an operator would assume the token is recoverable")
	}
	if !got.ExpiresAt.After(time.Now()) {
		t.Errorf("token expires at %s, which is not in the future", got.ExpiresAt)
	}

	// The token is stored only as a hash: a second read must not reveal it.
	got2 := executorsGET(t, ts, "")
	raw, _ := json.Marshal(got2)
	if strings.Contains(string(raw), got.Token) {
		t.Error("the enrollment token leaked into GET /api/executors — it must be shown exactly once")
	}
}

func TestExecutorEnroll_RejectsOutOfRangeTTL(t *testing.T) {
	dir := setupProjectDir(t, "enroll ttl", nil)
	ts := newTestServer(t, dir, nil)

	for _, body := range []string{`{"ttl_minutes":-5}`, `{"ttl_minutes":100000}`} {
		resp, err := http.Post(ts.URL+"/api/executors/enroll", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("POST enroll %s: %v", body, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("POST enroll %s = HTTP %d, want 400", body, resp.StatusCode)
		}
	}
}

func TestExecutorEnroll_RejectsRelativeWorkdirRoot(t *testing.T) {
	dir := setupProjectDir(t, "enroll root", nil)
	ts := newTestServer(t, dir, nil)

	resp, err := http.Post(ts.URL+"/api/executors/enroll", "application/json",
		strings.NewReader(`{"workdir_root":"relative/path"}`))
	if err != nil {
		t.Fatalf("POST enroll: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("relative workdir_root accepted (HTTP %d) — it would resolve against "+
			"whatever directory the agent happened to start in", resp.StatusCode)
	}
}

func TestExecutorDelete_RefusesConfiguredBackend(t *testing.T) {
	dir := setupProjectDir(t, "delete builtin", nil)
	ts := newTestServer(t, dir, nil)

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/executors/"+localprocess.DefaultID, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE host executor: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("DELETE host executor = HTTP %d, want 400 — deleting a configured backend "+
			"would appear to work and silently reappear on restart", resp.StatusCode)
	}
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	// The remedy has to be the right one for the *host* driver: there is no
	// executors.localprocess section, so pointing at one would send the
	// operator looking for a key that does not exist.
	if !strings.Contains(body["error"], "allow_host_process") {
		t.Errorf("error %q does not name the setting that actually disables host execution",
			body["error"])
	}
	if strings.Contains(body["error"], "executors.localprocess") {
		t.Errorf("error %q points at a config section that does not exist", body["error"])
	}

	// And it must still be there.
	if _, err := executor.Get(localprocess.DefaultID); err != nil {
		t.Errorf("host executor was unregistered by a refused delete: %v", err)
	}
}

func TestExecutorDelete_UnknownIsNotFound(t *testing.T) {
	dir := setupProjectDir(t, "delete unknown", nil)
	ts := newTestServer(t, dir, nil)

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/executors/no-such-device", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE unknown executor: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DELETE unknown executor = HTTP %d, want 404", resp.StatusCode)
	}
}

// TestExecutorDelete_RevokesEnrolledAgent covers the path that matters for
// security: a revoked device loses its credential, its registry entry, and
// every project binding that pointed at it.
func TestExecutorDelete_RevokesEnrolledAgent(t *testing.T) {
	dir := setupProjectDir(t, "delete agent", nil)
	ts := newTestServer(t, dir, nil)

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("open state db: %v", err)
	}
	defer db.Close()

	const agentID = "edge-test-1"
	if err := db.UpsertExecutor(statedb.ExecutorRow{
		ID:        agentID,
		Name:      "edge-test-1",
		Kind:      executor.KindRemoteAgent,
		Status:    statedb.ExecutorStatusOffline,
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("seed executor row: %v", err)
	}
	if err := db.BindProjectExecutor(dir, agentID, "tester"); err != nil {
		t.Fatalf("bind project to agent: %v", err)
	}

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/executors/"+agentID, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE agent: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE enrolled agent = HTTP %d, want 200", resp.StatusCode)
	}

	if _, err := db.GetExecutor(agentID); err == nil {
		t.Error("revoked agent still has an executors row")
	}
	if id, ok, err := db.ProjectExecutor(dir); err == nil && ok {
		t.Errorf("project is still bound to %q after its executor was revoked — "+
			"it must fail closed, not fall back to the host", id)
	}
}

func TestProjectExecutorBind_RoundTrips(t *testing.T) {
	dir := setupProjectDir(t, "bind roundtrip", nil)
	ts := newTestServer(t, dir, nil)
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })

	body := `{"executor_id":"` + localprocess.DefaultID + `"}`
	resp, err := http.Post(ts.URL+"/api/projects/0/executor", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST bind: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST bind = HTTP %d, want 200", resp.StatusCode)
	}

	got := executorsGET(t, ts, "")
	if got.Project == nil || got.Project.ExecutorID != localprocess.DefaultID {
		t.Fatalf("binding did not round-trip through the panel: %+v", got.Project)
	}

	// Unbind with an empty ID.
	resp2, err := http.Post(ts.URL+"/api/projects/0/executor", "application/json",
		strings.NewReader(`{"executor_id":""}`))
	if err != nil {
		t.Fatalf("POST unbind: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("POST unbind = HTTP %d, want 200", resp2.StatusCode)
	}
	got2 := executorsGET(t, ts, "")
	if got2.Project != nil && got2.Project.Bound {
		t.Error("project is still pinned after an empty-ID bind, which means unbind")
	}
}

func TestProjectExecutorBind_RejectsUnknownExecutor(t *testing.T) {
	dir := setupProjectDir(t, "bind unknown", nil)
	ts := newTestServer(t, dir, nil)

	resp, err := http.Post(ts.URL+"/api/projects/0/executor", "application/json",
		strings.NewReader(`{"executor_id":"ghost"}`))
	if err != nil {
		t.Fatalf("POST bind: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("binding to an unregistered executor = HTTP %d, want 400 — accepting it "+
			"would defer the failure to the next run with a worse message", resp.StatusCode)
	}
}

func TestProjectExecutorBind_RejectsBadIndex(t *testing.T) {
	dir := setupProjectDir(t, "bind index", nil)
	ts := newTestServer(t, dir, nil)

	for _, path := range []string{"/api/projects/notanumber/executor", "/api/projects/99/executor"} {
		resp, err := http.Post(ts.URL+path, "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("POST %s = HTTP %d, want 400", path, resp.StatusCode)
		}
	}
}

// TestProjectExecutorBind_StrictModeReturns409 is the enforcement path for the
// binding endpoint: pinning a project to the host while host execution is
// forbidden must be refused, not accepted-and-then-failed-at-run-time.
func TestProjectExecutorBind_StrictModeReturns409(t *testing.T) {
	dir := setupProjectDir(t, "bind strict", nil)
	ts := newTestServer(t, dir, nil)
	denyHostExecution(t)

	body := `{"executor_id":"` + localprocess.DefaultID + `"}`
	resp, err := http.Post(ts.URL+"/api/projects/0/executor", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST bind: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("bind to host under strict mode = HTTP %d, want 409", resp.StatusCode)
	}
	assertHostDeniedBody(t, resp)
}

// TestRun_StrictModeReturns409 is the property the whole task exists for: the
// Web UI cannot spawn a harness on the host when policy forbids it, and it
// says so in a way an operator can act on.
func TestRun_StrictModeReturns409(t *testing.T) {
	dir := setupProjectDir(t, "run strict", nil)
	ts := newTestServer(t, dir, nil)
	denyHostExecution(t)

	resp, err := http.Post(ts.URL+"/api/run", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST /api/run: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("POST /api/run under strict mode = HTTP %d, want 409 — a 500 would read "+
			"as a server fault rather than as policy", resp.StatusCode)
	}
	assertHostDeniedBody(t, resp)
}

func TestProjectRun_StrictModeReturns409(t *testing.T) {
	dir := setupProjectDir(t, "project run strict", nil)
	ts := newTestServer(t, dir, nil)
	denyHostExecution(t)

	resp, err := http.Post(ts.URL+"/api/projects/0/run", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST /api/projects/0/run: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("POST /api/projects/0/run under strict mode = HTTP %d, want 409", resp.StatusCode)
	}
	assertHostDeniedBody(t, resp)
}

// TestStartWorkload_StrictModeDeniesEveryProject covers the helper both the
// handlers and the background paths funnel through, so a future handler that
// forgets its own check still cannot fork on the host.
func TestStartWorkload_StrictModeDeniesEveryProject(t *testing.T) {
	dir := setupProjectDir(t, "helper strict", nil)
	_ = newTestServer(t, dir, nil) // bootstraps the registry
	denyHostExecution(t)

	if _, _, err := startWorkload(dir, fixtureArgv(t), nil); err == nil {
		t.Fatal("startWorkload forked on the host while host execution was denied")
	} else if !isHostDenied(err) {
		t.Fatalf("startWorkload error = %v, want a host-execution denial", err)
	}

	if _, err := runWorkload(t.Context(), dir, fixtureArgv(t), nil); err == nil {
		t.Fatal("runWorkload forked on the host while host execution was denied")
	} else if !isHostDenied(err) {
		t.Fatalf("runWorkload error = %v, want a host-execution denial", err)
	}
}

// isHostDenied reports whether err is the policy refusal, matched through the
// sentinel rather than by string comparison.
func isHostDenied(err error) bool {
	return errors.Is(err, executor.ErrHostExecutionDenied)
}

// ------------------------------------------- scheduling state (Task 20162)
//
// The property under test is the one that distinguishes cordoning from
// revoking: an operator can take a node out of rotation, see that decision in
// the panel, and put it back — without the node's in-flight work being
// disturbed and without a probe silently undoing it.
//
// The supervisor is process-wide (see pkg/ui/executor_supervisor.go), so every
// test here restores the state it changed through t.Cleanup, exactly as the
// policy tests above restore the host-execution switch.

// findExecutorView returns the card for id, failing the test when the panel
// does not carry one.
func findExecutorView(t *testing.T, resp executorsResponse, id string) executorView {
	t.Helper()
	for _, ex := range resp.Executors {
		if ex.ID == id {
			return ex
		}
	}
	t.Fatalf("executor %q is missing from the panel: %+v", id, resp.Executors)
	return executorView{}
}

// restoreSchedState returns an executor to rotation when the test finishes.
// Without it a cordon set here would leak into every later test in the package,
// because the supervisor and its health rows outlive one Server.
func restoreSchedState(t *testing.T, id string) {
	t.Helper()
	t.Cleanup(func() {
		if sv := executorSupervisor(); sv != nil {
			_, _ = sv.Uncordon(id)
		}
	})
}

// withoutExecutorSupervision detaches the process-wide supervisor for one test,
// reproducing a control plane whose supervision never started — the state every
// Server built as a struct literal is in.
//
// It swaps the pointer rather than calling stopExecutorSupervisor so the probe
// loop the rest of the package shares is not torn down and its database handle
// stays open.
func withoutExecutorSupervision(t *testing.T) {
	t.Helper()
	supervisorMu.Lock()
	prev := fleetSupervisor
	fleetSupervisor = nil
	supervisorMu.Unlock()
	t.Cleanup(func() {
		supervisorMu.Lock()
		fleetSupervisor = prev
		supervisorMu.Unlock()
	})
}

// execSchedPost calls one of the scheduling endpoints and returns the status
// code with the raw body, so a test can assert on either.
func execSchedPost(t *testing.T, ts *httptest.Server, id, action, body string) (int, []byte) {
	t.Helper()
	resp, err := http.Post(ts.URL+"/api/executors/"+id+"/"+action,
		"application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/executors/%s/%s: %v", id, action, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s response: %v", action, err)
	}
	return resp.StatusCode, raw
}

// decodeSched decodes a cordon/uncordon response, failing on a non-200.
func decodeSched(t *testing.T, status int, raw []byte, action string) executorSchedResponse {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("%s = HTTP %d, want 200: %s", action, status, raw)
	}
	var out executorSchedResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode %s response: %v (%s)", action, err, raw)
	}
	if !out.OK {
		t.Errorf("%s response does not carry ok:true: %s", action, raw)
	}
	return out
}

// TestExecutorsList_PopulatesSchedulingFields pins that the panel's payload
// carries the scheduler's view at all, and that the derived booleans agree with
// the state they are derived from. A card whose sched_state says "cordoned"
// while schedulable says true would render a green node nobody can place work
// on.
func TestExecutorsList_PopulatesSchedulingFields(t *testing.T) {
	dir := setupProjectDir(t, "sched fields", nil)
	ts := newTestServer(t, dir, nil)

	host := findExecutorView(t, executorsGET(t, ts, ""), localprocess.DefaultID)

	if host.SchedState == "" {
		t.Fatal("executor card carries no sched_state — the panel cannot tell a cordoned " +
			"node from a ready one")
	}
	state := executor.NodeState(host.SchedState)
	if !state.Valid() {
		t.Fatalf("sched_state = %q, which is not a NodeState", host.SchedState)
	}
	if host.Schedulable != state.Schedulable() {
		t.Errorf("schedulable = %v for state %q, want %v", host.Schedulable, state, state.Schedulable())
	}
	if host.AdminHeld != state.AdminHeld() {
		t.Errorf("admin_held = %v for state %q, want %v", host.AdminHeld, state, state.AdminHeld())
	}
	// The control-plane database is open, so the count is knowable. Reporting
	// it as unknown would make the panel render an em dash forever on the one
	// backend whose sessions we definitely track.
	if !host.InFlightKnown {
		t.Error("in_flight_known is false with an open control-plane database")
	}
	if host.InFlight != 0 {
		t.Errorf("in_flight = %d on a control plane that dispatched nothing", host.InFlight)
	}
}

// TestExecutorsList_ReflectsCordon is the round trip that matters: a cordon set
// through the supervisor must be visible on the card, or the operator has no
// way to see the decision they just made.
func TestExecutorsList_ReflectsCordon(t *testing.T) {
	dir := setupProjectDir(t, "sched cordon view", nil)
	ts := newTestServer(t, dir, nil)
	sv := executorSupervisor()
	if sv == nil {
		t.Fatal("bootstrap produced no executor supervisor")
	}
	restoreSchedState(t, localprocess.DefaultID)

	if _, err := sv.Cordon(localprocess.DefaultID, "under investigation"); err != nil {
		t.Fatalf("cordon: %v", err)
	}

	host := findExecutorView(t, executorsGET(t, ts, ""), localprocess.DefaultID)
	if host.SchedState != string(executor.NodeCordoned) {
		t.Errorf("sched_state = %q, want %q", host.SchedState, executor.NodeCordoned)
	}
	if host.Schedulable {
		t.Error("a cordoned executor reports schedulable — placement would keep using it")
	}
	if !host.AdminHeld {
		t.Error("a cordoned executor does not report admin_held — the card would offer " +
			"Cordon again instead of Uncordon")
	}
	if host.SchedReason == "" {
		t.Error("the operator's reason did not reach the card")
	}
}

func TestExecutorCordon_TakesNodeOutOfRotation(t *testing.T) {
	dir := setupProjectDir(t, "cordon endpoint", nil)
	ts := newTestServer(t, dir, nil)
	restoreSchedState(t, localprocess.DefaultID)

	status, raw := execSchedPost(t, ts, localprocess.DefaultID, "cordon", `{"reason":"disk full"}`)
	got := decodeSched(t, status, raw, "cordon")

	if got.State != string(executor.NodeCordoned) {
		t.Fatalf("state = %q, want %q", got.State, executor.NodeCordoned)
	}
	if got.Schedulable {
		t.Error("cordon response reports the node as still schedulable")
	}
	if !got.AdminHeld {
		t.Error("cordon response does not report admin_held — no probe may lift a cordon")
	}
	if !strings.Contains(got.Reason, "disk full") {
		t.Errorf("reason = %q, does not carry the operator's note", got.Reason)
	}
	// The full Health rides along so the client never has to re-fetch the list
	// to learn what its own action produced.
	if got.Health.ExecutorID != localprocess.DefaultID {
		t.Errorf("health.executor_id = %q, want %q", got.Health.ExecutorID, localprocess.DefaultID)
	}
	if got.Health.StateChangedAt.IsZero() {
		t.Error("health.state_changed_at is zero — the panel cannot render \"cordoned 20m ago\"")
	}
}

func TestExecutorUncordon_ReturnsNodeToRotation(t *testing.T) {
	dir := setupProjectDir(t, "uncordon endpoint", nil)
	ts := newTestServer(t, dir, nil)
	restoreSchedState(t, localprocess.DefaultID)

	status, raw := execSchedPost(t, ts, localprocess.DefaultID, "cordon", `{"reason":"maintenance"}`)
	decodeSched(t, status, raw, "cordon")

	// No body at all: uncordon takes no parameters, and requiring an empty
	// JSON object would be a trap for every client that sends nothing.
	status, raw = execSchedPost(t, ts, localprocess.DefaultID, "uncordon", "")
	got := decodeSched(t, status, raw, "uncordon")

	if got.AdminHeld {
		t.Fatalf("still admin-held after uncordon: %s", raw)
	}
	// The host driver's health check allocates a pipe and succeeds, so its
	// probe history justifies ready. Uncordon deliberately does not force it.
	if got.State != string(executor.NodeReady) {
		t.Errorf("state = %q, want %q — the host driver's probes succeed, so uncordon "+
			"should restore it fully", got.State, executor.NodeReady)
	}
	if !got.Schedulable {
		t.Error("an uncordoned, healthy node must be schedulable again")
	}
}

// TestExecutorDrain_SetsStateAndReportsInFlight covers the default (non-
// blocking) drain: the state change is what the operator asked for, and the
// in-flight count is what they need to know next.
func TestExecutorDrain_SetsStateAndReportsInFlight(t *testing.T) {
	dir := setupProjectDir(t, "drain endpoint", nil)
	ts := newTestServer(t, dir, nil)
	restoreSchedState(t, localprocess.DefaultID)

	status, raw := execSchedPost(t, ts, localprocess.DefaultID, "drain", `{"reason":"reimaging"}`)
	if status != http.StatusOK {
		t.Fatalf("drain = HTTP %d, want 200: %s", status, raw)
	}
	var got executorDrainResponse
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode drain response: %v (%s)", err, raw)
	}

	if !got.OK {
		t.Errorf("drain response does not carry ok:true: %s", raw)
	}
	if got.State != string(executor.NodeDraining) {
		t.Fatalf("state = %q, want %q", got.State, executor.NodeDraining)
	}
	if got.Schedulable {
		t.Error("a draining node reports schedulable — new work would keep landing on it")
	}
	if !got.AdminHeld {
		t.Error("a draining node must be admin-held; a probe may not lift a drain")
	}
	if !got.InFlightKnown {
		t.Error("in_flight_known is false with an open control-plane database")
	}
	if got.InFlight != 0 {
		t.Errorf("in_flight = %d with nothing dispatched", got.InFlight)
	}
	if !got.Drained {
		t.Error("an idle node did not report drained:true")
	}
}

// TestExecutorDrain_WaitsWhenAsked exercises the bounded-wait branch. With no
// sessions in flight the wait returns immediately, which is the point: the
// timeout governs how long the *request* blocks, never whether the drain took.
func TestExecutorDrain_WaitsWhenAsked(t *testing.T) {
	dir := setupProjectDir(t, "drain wait", nil)
	ts := newTestServer(t, dir, nil)
	restoreSchedState(t, localprocess.DefaultID)

	status, raw := execSchedPost(t, ts, localprocess.DefaultID, "drain", `{"timeout_seconds":5}`)
	if status != http.StatusOK {
		t.Fatalf("drain with timeout = HTTP %d, want 200: %s", status, raw)
	}
	var got executorDrainResponse
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode drain response: %v (%s)", err, raw)
	}
	if !got.Drained {
		t.Errorf("waiting drain on an idle node reported drained:false (%d in flight)", got.InFlight)
	}
	if got.State != string(executor.NodeDraining) {
		t.Errorf("state = %q, want %q — a completed drain still leaves the node out of "+
			"rotation until it is uncordoned", got.State, executor.NodeDraining)
	}
}

// TestExecutorDrain_RejectsOutOfRangeTimeout guards the one bound on this
// endpoint: a request may not pin a handler open indefinitely.
func TestExecutorDrain_RejectsOutOfRangeTimeout(t *testing.T) {
	dir := setupProjectDir(t, "drain timeout range", nil)
	ts := newTestServer(t, dir, nil)
	restoreSchedState(t, localprocess.DefaultID)

	for _, body := range []string{`{"timeout_seconds":-1}`, `{"timeout_seconds":86400}`} {
		status, raw := execSchedPost(t, ts, localprocess.DefaultID, "drain", body)
		if status != http.StatusBadRequest {
			t.Errorf("drain %s = HTTP %d, want 400: %s", body, status, raw)
		}
	}
}

// TestExecutorSched_UnknownExecutorIsNotFound checks the sentinel-based mapping.
// A typo'd device ID must not read as a server fault.
func TestExecutorSched_UnknownExecutorIsNotFound(t *testing.T) {
	dir := setupProjectDir(t, "sched unknown", nil)
	ts := newTestServer(t, dir, nil)

	for _, action := range []string{"cordon", "uncordon", "drain"} {
		status, raw := execSchedPost(t, ts, "no-such-device", action, `{}`)
		if status != http.StatusNotFound {
			t.Errorf("%s of an unknown executor = HTTP %d, want 404: %s", action, status, raw)
		}
		var body map[string]string
		_ = json.Unmarshal(raw, &body)
		if !strings.Contains(body["error"], "no-such-device") {
			t.Errorf("%s 404 body %q does not name the executor that was not found",
				action, body["error"])
		}
	}
}

// TestExecutorSched_WithoutSupervisionIs503 is the nil-supervisor path. Every
// caller of executorSupervisor() must handle nil; a handler that dereferenced
// it would turn a missing capability into a panic and a 500.
func TestExecutorSched_WithoutSupervisionIs503(t *testing.T) {
	dir := setupProjectDir(t, "sched unsupervised", nil)
	ts := newTestServer(t, dir, nil)
	withoutExecutorSupervision(t)

	for _, action := range []string{"cordon", "uncordon", "drain"} {
		status, raw := execSchedPost(t, ts, localprocess.DefaultID, action, `{}`)
		if status != http.StatusServiceUnavailable {
			t.Errorf("%s without supervision = HTTP %d, want 503: %s", action, status, raw)
		}
		var body map[string]string
		_ = json.Unmarshal(raw, &body)
		// The message has to say the request was not applied. "Something went
		// wrong" would leave an operator believing a cordon is in force.
		if !strings.Contains(body["error"], "nothing was applied") {
			t.Errorf("%s 503 body %q does not say the request had no effect", action, body["error"])
		}
	}
}

// TestExecutorsList_SurvivesMissingSupervision is the read-side half of the
// same invariant: the panel must still render when supervision is not running,
// falling back to the normalized zero health rather than nil-panicking.
func TestExecutorsList_SurvivesMissingSupervision(t *testing.T) {
	dir := setupProjectDir(t, "list unsupervised", nil)
	ts := newTestServer(t, dir, nil)
	withoutExecutorSupervision(t)

	host := findExecutorView(t, executorsGET(t, ts, ""), localprocess.DefaultID)
	if host.SchedState != string(executor.NodeReady) {
		t.Errorf("sched_state = %q without a supervisor, want %q — refusing to schedule "+
			"merely because supervision is down would make the control plane unusable",
			host.SchedState, executor.NodeReady)
	}
	if !host.Schedulable {
		t.Error("an unsupervised control plane reports its own host driver as unschedulable")
	}
}

// assertHostDeniedBody checks that a 409 carries the machine-readable code and
// the human-readable remediation the frontend renders.
func assertHostDeniedBody(t *testing.T, resp *http.Response) {
	t.Helper()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode 409 body: %v", err)
	}
	if body["code"] != "host_execution_denied" {
		t.Errorf("409 body code = %v, want \"host_execution_denied\"", body["code"])
	}
	msg, _ := body["error"].(string)
	if !strings.Contains(msg, "allow_host_process") {
		t.Errorf("409 error %q does not name the setting that caused it", msg)
	}
	rem, _ := body["remediation"].(string)
	if rem == "" {
		t.Error("409 body carries no remediation — the operator is told what broke but not what to do")
	}
}
