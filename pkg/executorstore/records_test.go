package executorstore

// records_test.go: which labels the hub records for each kind of executor
// (Task 20432) — and that nothing a device reports about itself is among them.

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func openRecordsDB(t *testing.T) *statedb.DB {
	t.Helper()
	db, err := statedb.Open(statedbtest.Path(t))
	if err != nil {
		t.Fatalf("open statedb: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// enrollDevice records a device as enrollment does, with labels on its
// credential, and the capabilities its agent advertised on its row.
func enrollDevice(t *testing.T, db *statedb.DB, id string, labels, advertised map[string]string) {
	t.Helper()
	if err := db.PutAgentCredential(statedb.AgentCredentialRow{
		AgentID: id, Name: id, SecretHash: "sha256-" + id, Labels: labels,
	}); err != nil {
		t.Fatal(err)
	}
	caps, _ := json.Marshal(map[string]any{"os": "linux", "labels": advertised})
	if err := db.UpsertExecutor(statedb.ExecutorRow{
		ID: id, Name: id, Kind: executor.KindRemoteAgent, Capabilities: caps,
		// A row whose labels disagree with the credential — written by an
		// older hub, or by hand — must not be what grants are judged by.
		Labels: advertised,
	}); err != nil {
		t.Fatal(err)
	}
}

func configured(m map[string]map[string]string) func() (map[string]map[string]string, error) {
	return func() (map[string]map[string]string, error) { return m, nil }
}

func TestRecordsPerKindOfExecutor(t *testing.T) {
	db := openRecordsDB(t)
	eu := map[string]string{"region": "eu", "gpu": "true"}
	claim := map[string]string{"region": "us", "tier": "gold"}
	enrollDevice(t, db, "edge-eu", eu, claim)
	enrollDevice(t, db, "edge-plain", nil, claim)
	enrollDevice(t, db, "edge-gone", eu, nil)
	if err := db.RevokeAgentCredential("edge-gone", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateVirtualExecutor(statedb.VirtualExecutor{
		ID: "vx-eu", ParentID: "edge-eu", Name: "hsm",
		Spec: executor.VirtualSpec{Sandbox: executor.SandboxSettings{Mode: executor.SandboxModeContainer, Engine: "docker"}},
	}); err != nil {
		t.Fatal(err)
	}
	records := Records{DB: db, Configured: configured(map[string]map[string]string{
		"container": {"tier": "prod"},
		// A configured entry sharing a device's ID does not label the device.
		"edge-plain": {"tier": "prod"},
	})}

	for _, tc := range []struct {
		id     string
		labels map[string]string
		source string
	}{
		{"edge-eu", eu, SourceAgentCredential},
		{"vx-eu", eu, "the agent credential of device edge-eu"},
		{"container", map[string]string{"tier": "prod"}, SourceConfiguration},
		// What its agent advertises — on its row and in its capabilities —
		// is not its labels.
		{"edge-plain", nil, ""},
		{"edge-gone", nil, ""},
		{"local", nil, ""},
		{"", nil, ""},
	} {
		rec, err := records.RecordedExecutor(tc.id)
		if err != nil {
			t.Fatalf("%q: %v", tc.id, err)
		}
		if rec.ID != tc.id || !secretbroker.SameLabels(rec.Labels, tc.labels) || rec.Source != tc.source {
			t.Errorf("%q = %+v; want labels %v from %q", tc.id, rec, tc.labels, tc.source)
		}
	}

	// A virtual executor's own row carries the hub's bookkeeping parent label,
	// which no selector reaches it by.
	row, err := db.GetExecutor("vx-eu")
	if err != nil || row.Labels["parent"] != "edge-eu" {
		t.Fatalf("precondition: the virtual executor's row = %+v, %v", row, err)
	}
	r, _ := secretbroker.RequesterFor(records, "vx-eu", secretbroker.RequestScope{})
	if sub, _ := secretbroker.ParseSubject("label:parent=edge-eu"); sub.Matches(r) {
		t.Error("label:parent=… reached a virtual executor through the hub's bookkeeping label")
	}
}

func TestRecordsThatCannotBeReadAreAnError(t *testing.T) {
	boom := errors.New("configuration did not parse")
	db := openRecordsDB(t)
	records := Records{DB: db, Configured: func() (map[string]map[string]string, error) { return nil, boom }}
	if _, err := records.RecordedExecutor("container"); !errors.Is(err, boom) {
		t.Errorf("an unreadable configuration = %v, want it reported", err)
	}
	if _, err := (Records{}).RecordedExecutor("edge-1"); err == nil {
		t.Error("records with no database answered without one")
	}
	if rec, err := (Records{}).RecordedExecutor(""); err != nil || rec.ID != "" {
		t.Errorf("no executor = %+v, %v", rec, err)
	}
}

func TestSetAgentCredentialLabelsMirrorsTheRow(t *testing.T) {
	db := openRecordsDB(t)
	enrollDevice(t, db, "edge-1", map[string]string{"region": "eu"}, nil)
	want := map[string]string{"region": "us", "site": "lab"}
	if err := db.SetAgentCredentialLabels("edge-1", want); err != nil {
		t.Fatal(err)
	}
	cred, err := db.GetAgentCredential("edge-1")
	if err != nil || !secretbroker.SameLabels(cred.Labels, want) {
		t.Errorf("credential labels = %v, %v; want %v", cred.Labels, err, want)
	}
	row, err := db.GetExecutor("edge-1")
	if err != nil || !secretbroker.SameLabels(row.Labels, want) {
		t.Errorf("row labels = %v, %v; want %v", row.Labels, err, want)
	}
	if err := db.SetAgentCredentialLabels("edge-1", nil); err != nil {
		t.Fatal(err)
	}
	if rec, _ := (Records{DB: db}).RecordedExecutor("edge-1"); rec.HasLabels() {
		t.Errorf("cleared labels still recorded: %v", rec.Labels)
	}
	if err := db.SetAgentCredentialLabels("edge-none", want); !errors.Is(err, statedb.ErrAgentCredentialNotFound) {
		t.Errorf("an unknown device = %v, want ErrAgentCredentialNotFound", err)
	}
}
