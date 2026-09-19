package ui

// executor_policy_api_test.go drives the admin flow Task 20310 describes, end
// to end through the real HTTP handlers:
//
//	an admin configures an executor's resource ceiling through the UI, and
//	makes that executor available to specific users or groups; a user outside
//	those groups cannot bind a project to it or start a run on it, and a user
//	inside them can.
//
// # Why the run case asserts a refusal rather than a success
//
// A POST to /api/run that is *accepted* reaches a real executor and poisons
// process-global executor state for the whole package — see workspace_test.go
// and run_reentrancy_test.go, which both say so and both stay on the refusal
// side of the line for it.
//
// That is not a compromise here. The gate's whole job is the refusal, and a
// test proving a denied user gets 403 with the audience code is testing exactly
// the property. The positive direction is covered where it can be covered
// safely: the bind route, which is a real mutation with a real 200, and which
// is the other place a user chooses an executor.

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/localprocess"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// doJSON runs a request with a body through c and returns status and decoded body.
func doJSON(t *testing.T, c *http.Client, method, url, body string) (int, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// hubWithControlPlane makes dir the control plane and returns an open handle.
func hubWithControlPlane(t *testing.T, dir string) *statedb.DB {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	withControlPlaneDir(t, dir)
	return db
}

// ─── resource ceiling ────────────────────────────────────────────────────────

// TestExecutorLimitsRoundTripThroughTheAPI is the admin's half: type a ceiling
// into the panel, read it back, and see the hub-wide one alongside it.
func TestExecutorLimitsRoundTripThroughTheAPI(t *testing.T) {
	withFleetCeiling(t, executor.ResourceCeiling{MemoryMB: 8192})
	dir := setupProjectDir(t, "executor limits", nil)
	hubWithControlPlane(t, dir)
	ts := newTestServer(t, dir, nil)
	c := ts.Client()

	url := ts.URL + "/api/executors/" + localprocess.DefaultID + "/limits"

	// Unset to begin with: an executor nobody has capped, which is every
	// executor before an admin opens this dialog.
	status, got := doJSON(t, c, http.MethodGet, url, "")
	if status != http.StatusOK {
		t.Fatalf("GET limits = HTTP %d, want 200 (%v)", status, got)
	}
	if got["configured"] != false {
		t.Errorf("a never-configured executor reported configured=%v", got["configured"])
	}

	// Sizes are typed the way an admin types them, not in megabytes.
	status, got = doJSON(t, c, http.MethodPut, url,
		`{"max_cpu":1.5,"max_memory":"2g","max_disk":"10g","max_pids":512}`)
	if status != http.StatusOK {
		t.Fatalf("PUT limits = HTTP %d, want 200 (%v)", status, got)
	}

	ceiling, _ := got["ceiling"].(map[string]any)
	if ceiling == nil {
		t.Fatalf("no ceiling in the response: %v", got)
	}
	if ceiling["cpu_millis"] != float64(1500) {
		t.Errorf("cpu_millis = %v, want 1500 (1.5 cores)", ceiling["cpu_millis"])
	}
	if ceiling["memory_mb"] != float64(2048) {
		t.Errorf("memory_mb = %v, want 2048 (\"2g\")", ceiling["memory_mb"])
	}
	if ceiling["pids"] != float64(512) {
		t.Errorf("pids = %v, want 512", ceiling["pids"])
	}

	// The fleet ceiling rides along, because the tighter of the two wins and an
	// admin who cannot see it would set a number they never receive.
	fleet, _ := got["fleet"].(map[string]any)
	if fleet == nil || fleet["memory_mb"] != float64(8192) {
		t.Errorf("fleet ceiling not surfaced: %v", got["fleet"])
	}
	// 2g is tighter than the fleet's 8g, so the effective cap is this one's.
	eff, _ := got["effective"].(map[string]any)
	if eff == nil || eff["memory_mb"] != float64(2048) {
		t.Errorf("effective memory = %v, want the tighter 2048", got["effective"])
	}

	// And it survives a read.
	status, got = doJSON(t, c, http.MethodGet, url, "")
	if status != http.StatusOK || got["configured"] != true {
		t.Fatalf("GET after PUT = HTTP %d configured=%v", status, got["configured"])
	}

	// Clearing leaves the executor bounded only by the fleet.
	status, got = doJSON(t, c, http.MethodPut, url, `{"clear":true}`)
	if status != http.StatusOK {
		t.Fatalf("PUT clear = HTTP %d, want 200 (%v)", status, got)
	}
	if got["configured"] != false {
		t.Errorf("after clear, configured=%v, want false", got["configured"])
	}
}

func TestExecutorLimitsRejectsAMalformedSize(t *testing.T) {
	dir := setupProjectDir(t, "executor limits bad size", nil)
	hubWithControlPlane(t, dir)
	ts := newTestServer(t, dir, nil)

	url := ts.URL + "/api/executors/" + localprocess.DefaultID + "/limits"
	status, got := doJSON(t, ts.Client(), http.MethodPut, url, `{"max_memory":"eight gigs"}`)
	if status != http.StatusBadRequest {
		t.Fatalf("PUT a malformed size = HTTP %d, want 400 (%v)", status, got)
	}
	// A ceiling that silently became a different number is a policy the admin
	// believes they have and does not, so nothing may have been written.
	status, got = doJSON(t, ts.Client(), http.MethodGet, url, "")
	if status != http.StatusOK || got["configured"] != false {
		t.Errorf("a refused write left state behind: configured=%v", got["configured"])
	}
}

func TestExecutorLimitsRejectsANegativeCeiling(t *testing.T) {
	dir := setupProjectDir(t, "executor limits negative", nil)
	hubWithControlPlane(t, dir)
	ts := newTestServer(t, dir, nil)

	url := ts.URL + "/api/executors/" + localprocess.DefaultID + "/limits"
	// Negative is the runtimes' "unlimited" sentinel. A ceiling meaning
	// unlimited is the one thing a ceiling may never mean.
	status, _ := doJSON(t, ts.Client(), http.MethodPut, url, `{"max_cpu":-4}`)
	if status != http.StatusBadRequest {
		t.Fatalf("PUT a negative ceiling = HTTP %d, want 400", status)
	}
}

// TestExecutorCeilingSetInTheUIBindsTheDispatchedSpec is the one that matters:
// the number an admin typed into the panel actually lowers what a workload is
// given, through the same function every dispatch site calls.
func TestExecutorCeilingSetInTheUIBindsTheDispatchedSpec(t *testing.T) {
	dir := setupProjectDir(t, "executor ceiling binds", nil)
	hubWithControlPlane(t, dir)
	ts := newTestServer(t, dir, nil)

	url := ts.URL + "/api/executors/" + localprocess.DefaultID + "/limits"
	if status, got := doJSON(t, ts.Client(), http.MethodPut, url,
		`{"max_memory":"1g","max_cpu":2}`); status != http.StatusOK {
		t.Fatalf("PUT limits = HTTP %d (%v)", status, got)
	}

	registerBuiltinExecutors()
	ex, err := executor.Get(localprocess.DefaultID)
	if err != nil {
		t.Fatalf("executor.Get: %v", err)
	}

	project := t.TempDir()
	spec := executor.Spec{
		WorkDir:        project,
		ResourceLimits: executor.ResourceLimits{MemoryMB: 65536, CPUMillis: 32000},
	}
	got, clamps := applyResourceCeiling(spec, project, ex)

	if got.ResourceLimits.MemoryMB != 1024 {
		t.Errorf("memory: got %d MB, want the executor ceiling's 1024",
			got.ResourceLimits.MemoryMB)
	}
	if got.ResourceLimits.CPUMillis != 2000 {
		t.Errorf("cpu: got %d, want the executor ceiling's 2000", got.ResourceLimits.CPUMillis)
	}
	// Attribution: the developer whose run was capped has to be able to find
	// out that it was this executor's policy rather than their project's.
	var sawExecutor bool
	for _, c := range clamps {
		if c.Source == executor.CeilingSourceExecutor {
			sawExecutor = true
		}
	}
	if !sawExecutor {
		t.Errorf("want the executor ceiling named in the clamps, got %+v", clamps)
	}

	// And it is scoped: the same project on a different executor is untouched.
	other := executor.Spec{
		WorkDir:        project,
		ResourceLimits: executor.ResourceLimits{MemoryMB: 65536},
	}
	otherGot, _ := applyResourceCeiling(other, project, stubExec{id: "some-other-box"})
	if otherGot.ResourceLimits.MemoryMB != 65536 {
		t.Errorf("another executor's workload was capped at %d MB by this executor's ceiling",
			otherGot.ResourceLimits.MemoryMB)
	}
}

// TestExecutorCeilingDoesNotFillInAnUnstatedRequest guards the subtle failure
// BoundSpec's comment warns about: writing a ceiling into a limit the project
// left unset converts "stated nothing" into "explicitly requested the ceiling",
// which the drivers treat as more specific than their own default — so the
// ceiling could *raise* the allowance.
func TestExecutorCeilingDoesNotFillInAnUnstatedRequest(t *testing.T) {
	dir := setupProjectDir(t, "executor ceiling unstated", nil)
	hubWithControlPlane(t, dir)
	ts := newTestServer(t, dir, nil)

	url := ts.URL + "/api/executors/" + localprocess.DefaultID + "/limits"
	if status, _ := doJSON(t, ts.Client(), http.MethodPut, url,
		`{"max_memory":"4g"}`); status != http.StatusOK {
		t.Fatalf("PUT limits = HTTP %d", status)
	}

	registerBuiltinExecutors()
	ex, _ := executor.Get(localprocess.DefaultID)
	project := t.TempDir()

	spec := executor.Spec{WorkDir: project} // states nothing
	got, _ := applyResourceCeiling(spec, project, ex)
	if got.ResourceLimits.MemoryMB != 0 {
		t.Errorf("an unstated request became %d MB; it must stay unstated and be bounded "+
			"by the driver through BoundLimit", got.ResourceLimits.MemoryMB)
	}
}

// ─── access list ─────────────────────────────────────────────────────────────

// TestExecutorAudienceGatesBindAndRun is the flow the task names: an admin
// makes an executor available to one group, and a user outside it cannot reach
// that executor by either route.
func TestExecutorAudienceGatesBindAndRun(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	dir := srv.WorkDir
	hubWithControlPlane(t, dir)
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })

	resolver, err := authz.New(authz.Config{
		Bindings: []authz.Binding{
			// Both groups are admins, so the *role* ladder admits either of
			// them to every route below. What separates them is the access
			// list alone — which is the point: an audience restricts a
			// permission the caller already holds fleet-wide, and no
			// arrangement of role bindings can express that.
			{Claim: authz.ClaimGroup, Value: "platform", Role: authz.RoleAdmin},
			{Claim: authz.ClaimGroup, Value: "contractors", Role: authz.RoleAdmin},
		},
	})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver

	loginAs := func(groups ...string) *http.Client {
		idp.groups = groups
		c := jarClient(t)
		login(t, c, ts)
		return c
	}
	insider := loginAs("platform")
	outsider := loginAs("contractors")

	audience := ts.URL + "/api/executors/" + localprocess.DefaultID + "/audience"
	bind := ts.URL + "/api/projects/0/executor"

	// Before any restriction, the outsider can bind. This is the baseline that
	// makes the rest of the test mean something: the refusal below is caused by
	// the access list and not by a role the outsider never had.
	if status, got := doJSON(t, outsider, http.MethodPost, bind,
		`{"executor_id":"`+localprocess.DefaultID+`"}`); status != http.StatusOK {
		t.Fatalf("bind before any restriction = HTTP %d, want 200 (%v)", status, got)
	}
	if status, _ := doJSON(t, outsider, http.MethodPost, bind, `{"executor_id":""}`); status != http.StatusOK {
		t.Fatalf("unbind = HTTP %d, want 200", status)
	}

	// The admin restricts the executor to their own group.
	status, got := doJSON(t, insider, http.MethodPost, audience, `{"kind":"group","value":"platform"}`)
	if status != http.StatusOK {
		t.Fatalf("admit platform = HTTP %d, want 200 (%v)", status, got)
	}
	if got["restricted"] != true {
		t.Errorf("after the first entry, restricted=%v, want true", got["restricted"])
	}
	if got["caller_admitted"] != true {
		t.Errorf("the admin who admitted their own group reads caller_admitted=%v",
			got["caller_admitted"])
	}

	// The outsider is now refused at the bind route...
	status, got = doJSON(t, outsider, http.MethodPost, bind,
		`{"executor_id":"`+localprocess.DefaultID+`"}`)
	if status != http.StatusForbidden {
		t.Fatalf("bind by an unlisted user = HTTP %d, want 403 (%v)", status, got)
	}
	if got["code"] != "executor_audience_denied" {
		t.Errorf("refusal code = %v, want executor_audience_denied", got["code"])
	}

	// ...and at the run route, which is the gate that actually holds: an admin
	// may narrow an audience after a project was bound, and a binding made
	// yesterday must not outlive the access it was made under.
	//
	// Bound out of band, exactly as that scenario would leave it.
	if err := executor.Bind(dir, localprocess.DefaultID); err != nil {
		t.Fatalf("bind out of band: %v", err)
	}
	status, got = doJSON(t, outsider, http.MethodPost, ts.URL+"/api/run", `{}`)
	if status != http.StatusForbidden {
		t.Fatalf("run by an unlisted user = HTTP %d, want 403 (%v)", status, got)
	}
	if got["code"] != "executor_audience_denied" {
		t.Errorf("run refusal code = %v, want executor_audience_denied", got["code"])
	}

	// The insider is admitted at the bind route. (The run route is deliberately
	// not driven to success here: an accepted POST /api/run starts a real
	// harness and poisons process-global executor state for the package.)
	executor.DefaultRegistry.Unbind(dir)
	if status, got := doJSON(t, insider, http.MethodPost, bind,
		`{"executor_id":"`+localprocess.DefaultID+`"}`); status != http.StatusOK {
		t.Fatalf("bind by a listed user = HTTP %d, want 200 (%v)", status, got)
	}
}

// TestExecutorAudienceWithdrawalReopensTheExecutor covers the edit that reads
// like a narrowing and is the opposite: removing the last entry makes the
// executor available to everyone again.
func TestExecutorAudienceWithdrawalReopensTheExecutor(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	dir := srv.WorkDir
	hubWithControlPlane(t, dir)
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })

	resolver, err := authz.New(authz.Config{
		Bindings: []authz.Binding{
			{Claim: authz.ClaimGroup, Value: "platform", Role: authz.RoleAdmin},
			{Claim: authz.ClaimGroup, Value: "contractors", Role: authz.RoleAdmin},
		},
	})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver

	loginAs := func(groups ...string) *http.Client {
		idp.groups = groups
		c := jarClient(t)
		login(t, c, ts)
		return c
	}
	insider := loginAs("platform")
	outsider := loginAs("contractors")

	audience := ts.URL + "/api/executors/" + localprocess.DefaultID + "/audience"
	bind := ts.URL + "/api/projects/0/executor"

	if status, _ := doJSON(t, insider, http.MethodPost, audience,
		`{"kind":"group","value":"platform"}`); status != http.StatusOK {
		t.Fatalf("admit = HTTP %d", status)
	}
	if status, _ := doJSON(t, outsider, http.MethodPost, bind,
		`{"executor_id":"`+localprocess.DefaultID+`"}`); status != http.StatusForbidden {
		t.Fatalf("bind while restricted = HTTP %d, want 403", status)
	}

	status, got := doJSON(t, insider, http.MethodDelete, audience, `{"kind":"group","value":"platform"}`)
	if status != http.StatusOK {
		t.Fatalf("withdraw = HTTP %d, want 200 (%v)", status, got)
	}
	if got["restricted"] != false {
		t.Errorf("after withdrawing the last entry, restricted=%v, want false", got["restricted"])
	}

	if status, got := doJSON(t, outsider, http.MethodPost, bind,
		`{"executor_id":"`+localprocess.DefaultID+`"}`); status != http.StatusOK {
		t.Fatalf("bind after the executor reopened = HTTP %d, want 200 (%v)", status, got)
	}
}

// TestExecutorAudienceRefusesASelfLockout covers the guard on the first entry.
// An admin who restricts an executor to a group they are not in has removed
// their own access to it — silently, and possibly on a hub where the people who
// could undo it are now locked out too.
func TestExecutorAudienceRefusesASelfLockout(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	hubWithControlPlane(t, srv.WorkDir)

	resolver, err := authz.New(authz.Config{
		Bindings: []authz.Binding{{Claim: authz.ClaimGroup, Value: "platform", Role: authz.RoleAdmin}},
	})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver

	idp.groups = []string{"platform"}
	c := jarClient(t)
	login(t, c, ts)

	audience := ts.URL + "/api/executors/" + localprocess.DefaultID + "/audience"

	status, got := doJSON(t, c, http.MethodPost, audience, `{"kind":"group","value":"some-other-team"}`)
	if status != http.StatusConflict {
		t.Fatalf("restricting to a group the admin is not in = HTTP %d, want 409 (%v)", status, got)
	}
	if got["code"] != "executor_audience_self_lockout" {
		t.Errorf("refusal code = %v, want executor_audience_self_lockout", got["code"])
	}

	// Nothing was written: the executor is still unrestricted, so the admin can
	// try again rather than being half-locked out.
	status, got = doJSON(t, c, http.MethodGet, audience, "")
	if status != http.StatusOK || got["restricted"] != false {
		t.Fatalf("a refused lockout left the executor restricted: %v", got)
	}

	// Admitting themselves first works, and then the other group may be added:
	// the guard is on the first entry only, or a restricted executor could
	// never be edited by anyone outside its own list.
	if status, _ := doJSON(t, c, http.MethodPost, audience,
		`{"kind":"group","value":"platform"}`); status != http.StatusOK {
		t.Fatalf("admitting own group = HTTP %d, want 200", status)
	}
	status, got = doJSON(t, c, http.MethodPost, audience, `{"kind":"group","value":"some-other-team"}`)
	if status != http.StatusOK {
		t.Fatalf("adding a second group = HTTP %d, want 200 (%v)", status, got)
	}
	members, _ := got["members"].([]any)
	if len(members) != 2 {
		t.Errorf("members = %v, want both groups listed", got["members"])
	}
}

func TestExecutorAudienceRejectsAnUnusablePrincipal(t *testing.T) {
	dir := setupProjectDir(t, "audience validation", nil)
	hubWithControlPlane(t, dir)
	ts := newTestServer(t, dir, nil)

	audience := ts.URL + "/api/executors/" + localprocess.DefaultID + "/audience"
	for _, tc := range []struct{ name, body string }{
		{"unknown kind", `{"kind":"wardrobe","value":"narnia"}`},
		{"blank value", `{"kind":"group","value":"   "}`},
		{"missing value", `{"kind":"group"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, _ := doJSON(t, ts.Client(), http.MethodPost, audience, tc.body)
			if status != http.StatusBadRequest {
				t.Errorf("POST %s = HTTP %d, want 400", tc.body, status)
			}
		})
	}
	// A blank value is the dangerous one: stored, it would match an identity
	// whose provider emits an empty group, turning "restricted" into "open".
	status, got := doJSON(t, ts.Client(), http.MethodGet, audience, "")
	if status != http.StatusOK || got["restricted"] != false {
		t.Errorf("a rejected principal was stored anyway: %v", got)
	}
}

// TestExecutorAudienceWithdrawalAcceptsAnUnrecognisedKind covers the asymmetry
// between admitting and withdrawing.
//
// A row naming a kind this binary does not understand is reachable — a newer
// binary sharing this control plane could have written one — and it renders on
// the list with a Remove button beside it. Refusing that removal would leave an
// admin looking at an entry they are told is invalid and cannot delete.
func TestExecutorAudienceWithdrawalAcceptsAnUnrecognisedKind(t *testing.T) {
	dir := setupProjectDir(t, "audience withdraw unknown", nil)
	hubWithControlPlane(t, dir)
	ts := newTestServer(t, dir, nil)
	audience := ts.URL + "/api/executors/" + localprocess.DefaultID + "/audience"

	// Admitting an unrecognised kind is refused: that direction can create a
	// silent lockout, where an entry the admin can see admits nobody.
	if status, _ := doJSON(t, ts.Client(), http.MethodPost, audience,
		`{"kind":"wardrobe","value":"narnia"}`); status != http.StatusBadRequest {
		t.Errorf("admitting an unrecognised kind = HTTP %d, want 400", status)
	}

	// Withdrawing the same principal is accepted. Removal only ever widens
	// access, so there is nothing to protect by being strict — and a row a
	// newer binary wrote must stay removable by the admin looking at it.
	status, got := doJSON(t, ts.Client(), http.MethodDelete, audience,
		`{"kind":"wardrobe","value":"narnia"}`)
	if status != http.StatusOK {
		t.Fatalf("withdrawing an unrecognised kind = HTTP %d, want 200 (%v)", status, got)
	}
	if got["restricted"] != false {
		t.Errorf("restricted=%v after withdrawing from an empty list, want false", got["restricted"])
	}
}

// TestExecutorListReportsAudienceState covers the card annotation: an admin
// scanning the fleet for somewhere to put a project should see which executors
// are off limits before choosing one and being refused.
func TestExecutorListReportsAudienceState(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	hubWithControlPlane(t, srv.WorkDir)

	resolver, err := authz.New(authz.Config{
		Bindings: []authz.Binding{
			{Claim: authz.ClaimGroup, Value: "platform", Role: authz.RoleAdmin},
			{Claim: authz.ClaimGroup, Value: "contractors", Role: authz.RoleAdmin},
		},
	})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver

	loginAs := func(groups ...string) *http.Client {
		idp.groups = groups
		c := jarClient(t)
		login(t, c, ts)
		return c
	}
	insider := loginAs("platform")
	outsider := loginAs("contractors")

	// Find the host driver's card and report its two access fields.
	cardFor := func(c *http.Client) map[string]any {
		t.Helper()
		status, got := doJSON(t, c, http.MethodGet, ts.URL+"/api/executors", "")
		if status != http.StatusOK {
			t.Fatalf("GET /api/executors = HTTP %d", status)
		}
		list, _ := got["executors"].([]any)
		for _, e := range list {
			m, _ := e.(map[string]any)
			if m != nil && m["id"] == localprocess.DefaultID {
				return m
			}
		}
		t.Fatalf("no card for %s in %v", localprocess.DefaultID, got["executors"])
		return nil
	}

	// Unrestricted: everyone is admitted, and nothing is flagged.
	if card := cardFor(outsider); card["restricted"] == true || card["admitted"] != true {
		t.Errorf("unrestricted card: restricted=%v admitted=%v, want false/true",
			card["restricted"], card["admitted"])
	}

	if status, _ := doJSON(t, insider, http.MethodPost,
		ts.URL+"/api/executors/"+localprocess.DefaultID+"/audience",
		`{"kind":"group","value":"platform"}`); status != http.StatusOK {
		t.Fatalf("admit = HTTP %d", status)
	}

	if card := cardFor(insider); card["restricted"] != true || card["admitted"] != true {
		t.Errorf("insider card: restricted=%v admitted=%v, want true/true",
			card["restricted"], card["admitted"])
	}
	if card := cardFor(outsider); card["restricted"] != true || card["admitted"] != false {
		t.Errorf("outsider card: restricted=%v admitted=%v, want true/false",
			card["restricted"], card["admitted"])
	}
}

// TestExecutorAudienceUnrestrictedByDefault is the no-op property the whole
// feature rests on. Every existing deployment upgrades into this code path, and
// it must change nothing for them.
func TestExecutorAudienceUnrestrictedByDefault(t *testing.T) {
	dir := setupProjectDir(t, "audience default", nil)
	hubWithControlPlane(t, dir)
	ts := newTestServer(t, dir, nil)
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })

	status, got := doJSON(t, ts.Client(), http.MethodGet,
		ts.URL+"/api/executors/"+localprocess.DefaultID+"/audience", "")
	if status != http.StatusOK {
		t.Fatalf("GET audience = HTTP %d, want 200", status)
	}
	if got["restricted"] != false {
		t.Errorf("a fresh executor reported restricted=%v", got["restricted"])
	}
	// And the gate is genuinely out of the way, on a hub with no OIDC at all —
	// where there is no subject for an access list to match.
	if status, got := doJSON(t, ts.Client(), http.MethodPost, ts.URL+"/api/projects/0/executor",
		`{"executor_id":"`+localprocess.DefaultID+`"}`); status != http.StatusOK {
		t.Fatalf("bind on an unrestricted executor = HTTP %d, want 200 (%v)", status, got)
	}
}
