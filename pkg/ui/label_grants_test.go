package ui

// label_grants_test.go: a grant to a label selector reaches the executors the
// hub records with those labels — a device by its agent credential, a virtual
// executor by its device's, a configured executor by the configuration — and
// nothing an agent says about itself counts. When the record changes under a
// running task, what no longer matches is taken back (Task 20432).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// labelFixture is a control plane with a hub serving it, a broker and a
// database handle over it.
type labelFixture struct {
	dir    string
	srv    *Server
	broker *secretbroker.Broker
	db     *statedb.DB
}

func newLabelFixture(t *testing.T) *labelFixture {
	t.Helper()
	t.Setenv(secretbroker.EnvPassphraseKey, "label-grants-unit-passphrase")
	f := &labelFixture{dir: setupProjectDir(t, "label grants", nil)}
	f.srv = New(f.dir, 0, "")
	broker, closeBroker, err := openUIBroker(f.dir)
	if err != nil {
		t.Fatalf("openUIBroker: %v", err)
	}
	t.Cleanup(closeBroker)
	f.broker = broker
	db, err := statedb.Open(state.DBPath(f.dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	f.db = db
	return f
}

// withConfiguredLabels stands in for the configuration a hub starts from,
// enabling a container executor id carrying labels.
func withConfiguredLabels(t *testing.T, id string, labels map[string]string) {
	t.Helper()
	cfg := &config.Config{}
	cfg.Executors.Container = config.ContainerExecutorConfig{Enabled: true, ID: id, Labels: labels}
	setConfiguredExecutorLabels(cfg)
	t.Cleanup(func() { setConfiguredExecutorLabels(nil) })
}

// enroll records a device as enrollment does: its agent credential, carrying
// the labels the operator gave it, and its registry row.
func enrollLabelled(t *testing.T, db *statedb.DB, id string, labels map[string]string) {
	t.Helper()
	if err := db.PutAgentCredential(statedb.AgentCredentialRow{
		AgentID: id, Name: id, SecretHash: "sha256-of-" + id, Labels: labels,
	}); err != nil {
		t.Fatalf("PutAgentCredential: %v", err)
	}
	if err := db.UpsertExecutor(statedb.ExecutorRow{
		ID: id, Name: id, Kind: executor.KindRemoteAgent, Status: statedb.ExecutorStatusOnline, Labels: labels,
	}); err != nil {
		t.Fatalf("UpsertExecutor: %v", err)
	}
}

// addVirtual records a virtual executor on device.
func addVirtual(t *testing.T, db *statedb.DB, id, device string) {
	t.Helper()
	if err := db.CreateVirtualExecutor(statedb.VirtualExecutor{
		ID: id, ParentID: device, Name: id,
		Spec: executor.VirtualSpec{Sandbox: executor.SandboxSettings{Mode: executor.SandboxModeContainer, Engine: "docker"}},
	}); err != nil {
		t.Fatalf("CreateVirtualExecutor: %v", err)
	}
}

// grantEnv mints an env secret named name and grants it to subject.
func (f *labelFixture) grantEnv(t *testing.T, name, subject string) secretbroker.Grant {
	t.Helper()
	ctx := context.Background()
	key := strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
	sec, err := f.broker.Mint(ctx, secretbroker.MintRequest{
		Name: name, Kind: secretbroker.KindEnv, Actor: "test",
		Payload: []byte(`{"` + key + `":"` + name + `-value-0123456789"}`),
	})
	if err != nil {
		t.Fatalf("Mint %s: %v", name, err)
	}
	sub, err := secretbroker.ParseSubject(subject)
	if err != nil {
		t.Fatal(err)
	}
	g, err := f.broker.Grant(ctx, secretbroker.GrantRequest{
		SecretRef: sec.ID, Subject: sub, Constraints: secretbroker.Constraints{EnvKeys: []string{key}},
		TTL: time.Hour, Actor: "test",
	})
	if err != nil {
		t.Fatalf("Grant %s to %s: %v", name, subject, err)
	}
	return g
}

// leaseFor leases for ex as a dispatch does, and returns the grants the lease
// carries: none when it was issued nothing.
func (f *labelFixture) leaseFor(t *testing.T, ex executor.Executor) (*secretLease, []string) {
	t.Helper()
	sl := acquireSecretLease(f.dir, f.dir, ex, "run_"+ex.ID(), nil)
	if sl == nil {
		return nil, nil
	}
	stopKeepaliveForTest(sl)
	t.Cleanup(sl.Close)
	return sl, sl.broker.HeldGrantIDs(sl.lease.ID)
}

// putLabels sets a device's labels through the dashboard's route.
func putLabels(t *testing.T, srv *Server, id string, labels map[string]string) (int, executorLabelsView, string) {
	t.Helper()
	body, err := json.Marshal(executorLabelsRequest{Labels: labels})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPut, "/api/executors/"+url.PathEscape(id)+"/labels", strings.NewReader(string(body)))
	req.Host = "127.0.0.1" // a hub with no sign-in answers to loopback only
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	var view executorLabelsView
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
			t.Fatalf("decode: %v: %s", err, rec.Body.String())
		}
	}
	return rec.Code, view, rec.Body.String()
}

// labelGetJSON serves a GET through the hub and decodes the answer.
func labelGetJSON(t *testing.T, srv *Server, path string, out any) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "127.0.0.1"
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code == http.StatusOK && out != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("decode %s: %v: %s", path, err, rec.Body.String())
		}
	}
	return rec.Code
}

func deliveringStub(id string) stubExec {
	return stubExec{id: id, caps: executor.Capabilities{SupportsSecretFiles: true}}
}

// TestALabelGrantReachesTheExecutorsTheHubRecordsWithItsLabels: a device
// carrying the labels on its agent credential, a virtual executor on it, and a
// configured container executor carrying them in the configuration all receive
// the grant; a device labelled otherwise, and an executor the hub records no
// labels for, do not.
func TestALabelGrantReachesTheExecutorsTheHubRecordsWithItsLabels(t *testing.T) {
	f := newLabelFixture(t)
	eu := map[string]string{"region": "eu", "gpu": "true"}
	enrollLabelled(t, f.db, "edge-eu", eu)
	enrollLabelled(t, f.db, "edge-us", map[string]string{"region": "us", "gpu": "true"})
	addVirtual(t, f.db, "vx-eu", "edge-eu")
	withConfiguredLabels(t, "container-eu", eu)

	labelled := f.grantEnv(t, "eu-gpu-token", "label:region=eu,gpu=true")
	f.grantEnv(t, "baseline", "any")

	for _, tc := range []struct {
		executor string
		want     bool
	}{
		{"edge-eu", true},
		{"vx-eu", true},
		{"container-eu", true},
		{"edge-us", false},
		{"local-host", false},
	} {
		t.Run(tc.executor, func(t *testing.T) {
			sl, held := f.leaseFor(t, deliveringStub(tc.executor))
			if sl == nil {
				t.Fatal("no lease was issued, though a grant to any requester exists")
			}
			if got := slices.Contains(held, labelled.ID); got != tc.want {
				t.Fatalf("the lease for %s carries %v; label grant delivered = %v, want %v",
					tc.executor, held, got, tc.want)
			}
			r, _ := sl.broker.HeldRequester(sl.lease.ID)
			if tc.want && !secretbroker.SameLabels(r.Labels, eu) {
				t.Errorf("the lease is judged as labels %v, want the recorded %v", r.Labels, eu)
			}
		})
	}
}

// TestALabelAnAgentReportsAboutItselfNeverCounts: a device enrolled with no
// labels that says region=eu in its hello — what `cloop executor agent
// --label` does — receives nothing a grant to label:region=eu carries. Only
// the hub's record decides, and once an admin sets the label there the grant
// reaches it.
func TestALabelAnAgentReportsAboutItselfNeverCounts(t *testing.T) {
	f := newLabelFixture(t)
	const id = "edge-claims"
	enrollLabelled(t, f.db, id, nil)
	labelled := f.grantEnv(t, "eu-token", "label:region=eu")
	f.grantEnv(t, "baseline", "executor:"+id)

	claim := map[string]string{"region": "eu"}
	ex, err := remote.NewExecutor(remote.Options{ID: id, Name: id})
	if err != nil {
		t.Fatal(err)
	}
	end := connectAnsweringCaps(t, ex, remote.ProtocolVersion, "dev", remote.AgentCapabilities{Labels: claim}, nil)
	defer end()
	// And the hub records the connect as it records every device's.
	makeExecutorConnectRecorder(f.db)(remote.AgentRecord{AgentID: id, Name: id},
		remote.AgentCapabilities{Labels: claim}, "dev")
	row, err := f.db.GetExecutor(id)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(row.Capabilities), `"region":"eu"`) {
		t.Fatalf("precondition: the device's claim did not reach the hub: %s", row.Capabilities)
	}
	if len(row.Labels) != 0 {
		t.Errorf("the registry row took the device's own claim as its labels: %v", row.Labels)
	}

	_, held := f.leaseFor(t, ex)
	if slices.Contains(held, labelled.ID) {
		t.Fatalf("a label the device reported about itself delivered grant %s: %v", labelled.ID, held)
	}
	rec, err := secretbroker.LookupExecutor(hubExecutorRecords(f.db), id)
	if err != nil || rec.HasLabels() {
		t.Fatalf("the hub's record of the device = %+v, %v; want no labels", rec, err)
	}

	if code, _, body := putLabels(t, f.srv, id, claim); code != http.StatusOK {
		t.Fatalf("PUT labels = %d: %s", code, body)
	}
	if _, held = f.leaseFor(t, ex); !slices.Contains(held, labelled.ID) {
		t.Fatalf("with the label on the device's credential, the lease carries %v; want grant %s", held, labelled.ID)
	}
}

// TestChangingADevicesLabelsTakesBackWhatNoLongerMatches: an admin relabels a
// device while tasks on it and on its virtual executor hold a credential from
// a label grant. The edit is audited, both leases give that grant back — on
// the hub and from every holder — and keep the grant that still matches, and
// their records carry the new labels for any process that adopts the runs.
func TestChangingADevicesLabelsTakesBackWhatNoLongerMatches(t *testing.T) {
	// A hub member, so the leases are recorded for one to adopt.
	prevHolder := leaseHolderID
	leaseHolderID = func() string { return "member-relabel" }
	t.Cleanup(func() { leaseHolderID = prevHolder })
	f := newLabelFixture(t)
	const device, virtual = "edge-relabel", "vx-relabel"
	enrollLabelled(t, f.db, device, map[string]string{"region": "eu"})
	addVirtual(t, f.db, virtual, device)
	labelled := f.grantEnv(t, "eu-token", "label:region=eu")
	keep := f.grantEnv(t, "baseline", "any")

	type held struct {
		ex *revokeRecordingExec
		sl *secretLease
	}
	var runs []held
	for _, id := range []string{device, virtual} {
		ex := &revokeRecordingExec{stubExec: deliveringStub(id)}
		if err := executor.Register(ex); err != nil {
			t.Fatalf("register %s: %v", id, err)
		}
		t.Cleanup(func() { executor.DefaultRegistry.Unregister(id) })
		sl, grants := f.leaseFor(t, ex)
		if sl == nil || !slices.Contains(grants, labelled.ID) {
			t.Fatalf("precondition: the lease for %s carries %v, want the label grant", id, grants)
		}
		ex.mu.Lock()
		ex.held = sl.lease.ID
		ex.mu.Unlock()
		runs = append(runs, held{ex, sl})
	}

	code, view, body := putLabels(t, f.srv, device, map[string]string{"region": "us"})
	if code != http.StatusOK {
		t.Fatalf("PUT labels = %d: %s", code, body)
	}
	if view.Recheck == nil || view.Recheck.Leases != 2 || len(view.Recheck.TakenBack) != 2 {
		t.Fatalf("recheck = %+v; want both leases relabeled and the grant taken back from each", view.Recheck)
	}
	if !secretbroker.SameLabels(view.Labels, map[string]string{"region": "us"}) || view.Source != "agent credential" {
		t.Errorf("view = %+v; want the new labels, from the agent credential", view)
	}

	store, err := secretstore.New(f.db)
	if err != nil {
		t.Fatal(err)
	}
	for _, run := range runs {
		lease := run.sl.lease.ID
		if got := run.sl.broker.HeldGrantIDs(lease); !slices.Equal(got, []string{keep.ID}) {
			t.Errorf("lease %s on %s carries %v after the edit, want only %s", lease, run.ex.ID(), got, keep.ID)
		}
		if !run.sl.isWithdrawn(labelled.ID) {
			t.Errorf("the hub's copy of grant %s in lease %s was not withdrawn", labelled.ID, lease)
		}
		asked := run.ex.asked()
		if len(asked) != 1 || asked[0].LeaseID != lease || asked[0].GrantID != labelled.ID ||
			!strings.Contains(asked[0].Reason, "region=eu to region=us") {
			t.Errorf("%s was asked %+v; want grant %s of lease %s taken back, saying the labels changed",
				run.ex.ID(), asked, labelled.ID, lease)
		}
		rec, err := store.GetLease(lease)
		if err != nil {
			t.Fatalf("GetLease: %v", err)
		}
		if !secretbroker.SameLabels(rec.Requester.Labels, map[string]string{"region": "us"}) {
			t.Errorf("lease %s is recorded as labels %v; a process adopting the run would judge it by those",
				lease, rec.Requester.Labels)
		}
	}
	for _, tb := range view.Recheck.TakenBack {
		if tb.GrantID != labelled.ID || tb.Subject != "label:region=eu" || tb.State != remote.RevokeStateRevoked {
			t.Errorf("taken back: %+v", tb)
		}
	}

	rows := controlAudit(t, f.dir, secretbroker.Action("executor.labels"))
	if len(rows) != 1 {
		t.Fatalf("executor.labels rows = %d, want 1", len(rows))
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(rows[0].Payload), &payload); err != nil {
		t.Fatal(err)
	}
	from, _ := payload["from"].(map[string]any)
	to, _ := payload["to"].(map[string]any)
	if rows[0].EntityID != device || from["region"] != "eu" || to["region"] != "us" || payload["taken_back"] != float64(2) {
		t.Errorf("audit row = %s %s; want the device, its labels before and after, and the two take-backs",
			rows[0].EntityID, rows[0].Payload)
	}

	// The next run on the device is not handed the grant either.
	if _, grants := f.leaseFor(t, deliveringStub(device)); slices.Contains(grants, labelled.ID) {
		t.Errorf("a lease issued after the edit carries the grant: %v", grants)
	}
}

// TestAConfiguredExecutorsNewLabelsAreTakenUpByTheJanitor: a hub that starts
// with a configured executor labelled otherwise judges the leases it holds on
// that executor by the new labels at the janitor's next pass, and takes back
// what they no longer match. A second pass changes nothing.
func TestAConfiguredExecutorsNewLabelsAreTakenUpByTheJanitor(t *testing.T) {
	f := newLabelFixture(t)
	const id = "container-tiered"
	withConfiguredLabels(t, id, map[string]string{"tier": "prod"})
	labelled := f.grantEnv(t, "prod-token", "label:tier=prod")
	keep := f.grantEnv(t, "baseline", "any")

	ex := &revokeRecordingExec{stubExec: deliveringStub(id)}
	if err := executor.Register(ex); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(id) })
	sl, grants := f.leaseFor(t, ex)
	if sl == nil || !slices.Contains(grants, labelled.ID) {
		t.Fatalf("precondition: the lease carries %v, want the label grant", grants)
	}
	ex.mu.Lock()
	ex.held = sl.lease.ID
	ex.mu.Unlock()

	withConfiguredLabels(t, id, map[string]string{"tier": "dev"})
	rc := f.srv.reconcileExecutorLabels(context.Background(), nil, "janitor")
	if rc.Leases != 1 || len(rc.TakenBack) != 1 || rc.TakenBack[0].GrantID != labelled.ID || len(rc.Errors) != 0 {
		t.Fatalf("janitor pass = %+v; want the lease relabeled and the label grant taken back", rc)
	}
	if got := sl.broker.HeldGrantIDs(sl.lease.ID); !slices.Equal(got, []string{keep.ID}) {
		t.Errorf("the lease carries %v, want only %s", got, keep.ID)
	}
	if asked := ex.asked(); len(asked) != 1 || asked[0].GrantID != labelled.ID {
		t.Errorf("the executor was asked %+v; want the label grant taken back", asked)
	}

	again := f.srv.reconcileExecutorLabels(context.Background(), nil, "janitor")
	if again.Leases != 0 || len(again.TakenBack) != 0 {
		t.Errorf("a second pass = %+v; want nothing to do", again)
	}
}

// TestALabelEgressGrantFollowsTheDevicesLabels: an egress grant issued to a
// label selector gives a run on a device carrying the labels a proxy session
// and one on a device that does not none; relabeling the device closes the
// session.
func TestALabelEgressGrantFollowsTheDevicesLabels(t *testing.T) {
	dir, svc := hostEgress(t, func(e *config.EgressConfig) { e.AdvertiseAddr = "hub.example.org:41000" })
	srv := New(dir, 0, "")
	enrollLabelled(t, svc.db, "edge-lab", map[string]string{"site": "lab"})
	enrollLabelled(t, svc.db, "edge-home", map[string]string{"site": "home"})
	g := grantEgress(t, svc, "label:site=lab", nil)
	project := statedbtest.Dir(t)

	_, none, err := applyEgressSession(executor.Spec{}, postured{newEgressStub("edge-home", executor.KindRemoteAgent)},
		project, nil, egressRun{runID: "run-home"})
	if err != nil || none != nil {
		t.Fatalf("a device without the label = %v, %v; want no session", none, err)
	}
	_, egr, err := applyEgressSession(executor.Spec{}, postured{newEgressStub("edge-lab", executor.KindRemoteAgent)},
		project, nil, egressRun{runID: "run-lab"})
	if err != nil || egr == nil {
		t.Fatalf("a device carrying the label = %v, %v; want a session", egr, err)
	}
	t.Cleanup(func() { egr.close("test over") })
	if egr.sess.GrantID != g.ID {
		t.Fatalf("session stands on grant %s, want %s", egr.sess.GrantID, g.ID)
	}

	code, view, body := putLabels(t, srv, "edge-lab", map[string]string{"site": "home"})
	if code != http.StatusOK {
		t.Fatalf("PUT labels = %d: %s", code, body)
	}
	if view.Recheck == nil || view.Recheck.Sessions != 1 || len(view.Recheck.TakenBack) != 1 ||
		view.Recheck.TakenBack[0].SessionID != egr.sess.ID {
		t.Fatalf("recheck = %+v; want the session relabeled and closed", view.Recheck)
	}
	if !egr.sess.Closed() {
		t.Fatal("the session stayed open after the device stopped carrying the label")
	}
	if reason := egr.sess.CloseReason(); !strings.Contains(reason, "site=lab") {
		t.Errorf("close reason = %q; want it to name the selector the device no longer carries", reason)
	}
}

// TestGrantListAndDialogSayWhichExecutorsALabelReaches: the grant list shows,
// for a grant to a label selector, the executors carrying its labels now —
// none, for a selector nobody carries — and the dialog's preview answers the
// same for a subject being typed, or why it is not one.
func TestGrantListAndDialogSayWhichExecutorsALabelReaches(t *testing.T) {
	f := newLabelFixture(t)
	enrollLabelled(t, f.db, "edge-eu", map[string]string{"region": "eu"})
	enrollLabelled(t, f.db, "edge-us", map[string]string{"region": "us"})
	addVirtual(t, f.db, "vx-eu", "edge-eu")
	reaching := f.grantEnv(t, "eu-token", "label:region=eu")
	nobody := f.grantEnv(t, "mars-token", "label:region=mars")
	project := f.grantEnv(t, "project-token", "project:"+f.dir)

	var list grantsListResponse
	if code := labelGetJSON(t, f.srv, "/api/grants", &list); code != http.StatusOK {
		t.Fatalf("GET /api/grants = %d", code)
	}
	byID := map[string]grantView{}
	for _, g := range list.Grants {
		byID[g.ID] = g
	}
	ids := func(m *labelMatchView) []string {
		if m == nil {
			return nil
		}
		out := []string{}
		for _, e := range m.Executors {
			out = append(out, e.ID+"@"+e.Device)
		}
		return out
	}
	if got := ids(byID[reaching.ID].LabelMatches); !slices.Equal(got, []string{"edge-eu@", "vx-eu@edge-eu"}) {
		t.Errorf("label:region=eu matches %v, want the device and its virtual executor", got)
	}
	if m := byID[nobody.ID].LabelMatches; m == nil || len(m.Executors) != 0 || m.Unknown != "" {
		t.Errorf("label:region=mars matches %+v, want none, said as none", m)
	}
	if m := byID[project.ID].LabelMatches; m != nil {
		t.Errorf("a project grant carries label matches: %+v", m)
	}

	var preview grantSubjectMatchesView
	if code := labelGetJSON(t, f.srv, "/api/grants/matches?subject="+url.QueryEscape("label:region=us"), &preview); code != http.StatusOK {
		t.Fatalf("preview = %d", code)
	}
	if preview.Subject != "label:region=us" || !slices.Equal(ids(preview.Matches), []string{"edge-us@"}) {
		t.Errorf("preview = %+v; want edge-us alone", preview)
	}
	if code := labelGetJSON(t, f.srv, "/api/grants/matches?subject="+url.QueryEscape("project:"+f.dir), &preview); code != http.StatusOK {
		t.Fatalf("project preview = %d", code)
	}
	if code := labelGetJSON(t, f.srv, "/api/grants/matches?subject="+url.QueryEscape("label:"), nil); code != http.StatusBadRequest {
		t.Errorf("an empty selector previews as %d, want 400", code)
	}
}

// TestLabelEditRefusesWhatItDoesNotSet: the route sets an enrolled device's
// labels and nothing else — a virtual executor carries its device's, a
// configured executor's are the configuration — and refuses labels no
// selector could match.
func TestLabelEditRefusesWhatItDoesNotSet(t *testing.T) {
	f := newLabelFixture(t)
	enrollLabelled(t, f.db, "edge-1", nil)
	addVirtual(t, f.db, "vx-1", "edge-1")
	withConfiguredLabels(t, "container-1", map[string]string{"tier": "prod"})

	for _, tc := range []struct {
		id     string
		labels map[string]string
		want   int
		has    string
	}{
		{"vx-1", map[string]string{"a": "b"}, http.StatusConflict, "device, edge-1"},
		{"container-1", map[string]string{"a": "b"}, http.StatusConflict, "configuration"},
		{"no-such-executor", map[string]string{"a": "b"}, http.StatusNotFound, ""},
		{"edge-1", map[string]string{"region": "eu,us"}, http.StatusBadRequest, "selector cannot express"},
		{"edge-1", map[string]string{"bad key": "x"}, http.StatusBadRequest, "space"},
	} {
		code, _, body := putLabels(t, f.srv, tc.id, tc.labels)
		if code != tc.want || !strings.Contains(body, tc.has) {
			t.Errorf("PUT %s %v = %d %s; want %d mentioning %q", tc.id, tc.labels, code, body, tc.want, tc.has)
		}
	}
	if rows := controlAudit(t, f.dir, secretbroker.Action("executor.labels")); len(rows) != 0 {
		t.Errorf("a refused edit was audited as made: %d rows", len(rows))
	}

	var view executorLabelsView
	if code := labelGetJSON(t, f.srv, "/api/executors/vx-1/labels", &view); code != http.StatusOK || view.Editable {
		t.Errorf("GET a virtual executor's labels = %d %+v; want readable and not editable", code, view)
	}
}

// TestTheWorkspaceGrantChosenBeforeDispatchCanBeALabelGrant: the hub picks the
// GitHub grant a private fetch will lease as the lease will ask (Task 20432),
// so a grant to a label selector is chosen for a device — or a virtual
// executor on it — carrying the labels, and refused for one that does not.
func TestTheWorkspaceGrantChosenBeforeDispatchCanBeALabelGrant(t *testing.T) {
	f := newLabelFixture(t)
	enrollLabelled(t, f.db, "edge-eu", map[string]string{"region": "eu"})
	enrollLabelled(t, f.db, "edge-us", map[string]string{"region": "us"})
	addVirtual(t, f.db, "vx-eu", "edge-eu")
	ctx := context.Background()
	sec, err := f.broker.Mint(ctx, secretbroker.MintRequest{
		Name: "eu-pat", Kind: secretbroker.KindGitHubPAT, Actor: "test",
		Payload: []byte("ghp_labelworkspacehub0123456789abcdefg"),
	})
	if err != nil {
		t.Fatal(err)
	}
	sub, _ := secretbroker.ParseSubject("label:region=eu")
	if _, err := f.broker.Grant(ctx, secretbroker.GrantRequest{SecretRef: sec.ID, Subject: sub,
		Constraints: secretbroker.Constraints{Repos: []string{"acme/*"}}, TTL: time.Hour, Actor: "test"}); err != nil {
		t.Fatal(err)
	}
	ws := executor.Workspace{Kind: executor.WorkspaceGit, Repo: "https://github.com/acme/tool.git", Ref: "main"}
	for _, id := range []string{"edge-eu", "vx-eu"} {
		if name, err := workspaceGrantFor(ws, deliveringStub(id), f.dir); err != nil || name != "eu-pat" {
			t.Errorf("%s: workspaceGrantFor = %q, %v; want the label grant's secret", id, name, err)
		}
	}
	if name, err := workspaceGrantFor(ws, deliveringStub("edge-us"), f.dir); err == nil {
		t.Errorf("a device without the label was given grant %q for a private fetch", name)
	}
}

// TestAnAdoptedRunIsJudgedByTheLabelsTheHubRecordsNow: a device relabeled
// while no hub process held its run's lease — on another member, or by a
// command — has the label grant its new labels no longer match taken back by
// the process that adopts the run, before anything is restored on the lease's
// behalf; the grant still standing is kept.
func TestAnAdoptedRunIsJudgedByTheLabelsTheHubRecordsNow(t *testing.T) {
	ex := newTakeoverExecutor("edge-adopt")
	h := newTakeoverHub(t, ex.ID())
	db, err := statedb.Open(state.DBPath(h.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	enrollLabelled(t, db, ex.ID(), map[string]string{"region": "eu"})
	broker, closeBroker, err := openUIBroker(h.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeBroker()
	f := &labelFixture{dir: h.dir, broker: broker, db: db}
	labelled := f.grantEnv(t, "eu-token", "label:region=eu")

	old := h.dispatch(t, ex, "h-1")
	leaseID := old.lease.ID
	if held := old.broker.HeldGrantIDs(leaseID); len(held) != 2 || !slices.Contains(held, labelled.ID) {
		t.Fatalf("precondition: the lease carries %v", held)
	}
	ids := liveLeases.forHandle(ex.ID(), "h-1")
	liveLeases.removeIf(old)

	if err := db.SetAgentCredentialLabels(ex.ID(), map[string]string{"region": "us"}); err != nil {
		t.Fatal(err)
	}
	h.holder = "hub_adopter"
	(&Server{WorkDir: h.dir}).takeOverRunLeases(h.dir, ex, "h-1", ids)
	// The workload ends with the test, and the adopter releases its lease: a
	// lease left in the process's registry would be found lapsed by a later
	// test's janitor.
	t.Cleanup(func() {
		ex.finish()
		deadline := time.Now().Add(5 * time.Second)
		for registeredLease(leaseID) != nil && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if sl := registeredLease(leaseID); sl != nil {
			t.Errorf("the adopted lease outlived its run")
			liveLeases.removeIf(sl)
		}
	})
	taken := registeredLease(leaseID)
	if taken == nil {
		t.Fatal("the adopting process does not hold the run's lease")
	}
	stopKeepaliveForTest(taken)
	held := taken.broker.HeldGrantIDs(leaseID)
	if len(held) != 1 || slices.Contains(held, labelled.ID) {
		t.Errorf("the adopted lease carries %v; want only the grant still standing", held)
	}
	if r, _ := taken.broker.HeldRequester(leaseID); r.Labels["region"] != "us" {
		t.Errorf("the adopted lease is judged as %v, want region=us", r.Labels)
	}
	if !taken.isWithdrawn(labelled.ID) {
		t.Error("the hub's copy of the label grant was not taken back on adoption")
	}
}
