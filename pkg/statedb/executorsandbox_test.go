package statedb

// Tests for the per-executor sandbox configuration table (Task 20307).

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
)

func TestExecutorSandbox_RoundTrip(t *testing.T) {
	db := openTestDB(t)

	// Absent means unset, and is not an error: an executor nobody has configured
	// keeps running work the way its driver always did.
	if s, ok, err := db.ExecutorSandboxSettings("edge-1"); err != nil || ok || !s.IsZero() {
		t.Fatalf("unconfigured executor: settings=%+v ok=%v err=%v; want zero,false,nil", s, ok, err)
	}

	want := executor.SandboxSettings{
		Mode: executor.SandboxModeContainer, Engine: "podman", Runtime: "kata", Image: "ghcr.io/x/y:v1",
	}
	if err := db.SetExecutorSandbox("edge-1", want, "admin@example.com"); err != nil {
		t.Fatalf("SetExecutorSandbox: %v", err)
	}

	got, ok, err := db.ExecutorSandboxSettings("edge-1")
	if err != nil || !ok {
		t.Fatalf("read back: ok=%v err=%v", ok, err)
	}
	if got != want {
		t.Errorf("round trip = %+v, want %+v", got, want)
	}

	// Provenance is recorded beside the settings, not inside them — see
	// executor.SandboxSettings for why it must not travel to the device.
	rec, ok, err := db.ExecutorSandboxRecord("edge-1")
	if err != nil || !ok {
		t.Fatalf("ExecutorSandboxRecord: ok=%v err=%v", ok, err)
	}
	if rec.SetBy != "admin@example.com" {
		t.Errorf("set_by = %q, want the identity that wrote it", rec.SetBy)
	}
	if rec.SetAt.IsZero() {
		t.Error("set_at is zero; the panel cannot say when containment last changed")
	}

	// Replacing is an upsert, not a second row.
	if err := db.SetExecutorSandbox("edge-1", executor.SandboxSettings{Mode: executor.SandboxModeHost}, "b"); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	got, _, err = db.ExecutorSandboxSettings("edge-1")
	if err != nil {
		t.Fatalf("read after overwrite: %v", err)
	}
	if got.Mode != executor.SandboxModeHost {
		t.Errorf("mode after overwrite = %q, want host", got.Mode)
	}
	// And the container fields are gone rather than lingering under host mode:
	// Normalize runs on the way in, so the durable row cannot hold a runtime the
	// mode makes meaningless.
	if got.Engine != "" || got.Runtime != "" || got.Image != "" {
		t.Errorf("host-mode row retained container fields: %+v", got)
	}
	if rows, err := db.ListExecutorSandboxes(); err != nil || len(rows) != 1 {
		t.Fatalf("ListExecutorSandboxes = %d rows, err=%v; want exactly 1", len(rows), err)
	}
}

// TestExecutorSandbox_ExplicitDefaultIsDistinctFromAbsent pins the difference the
// panel renders: an admin who looked at this executor and chose its default is
// not the same as an executor nobody has considered.
func TestExecutorSandbox_ExplicitDefaultIsDistinctFromAbsent(t *testing.T) {
	db := openTestDB(t)

	if err := db.SetExecutorSandbox("edge-2", executor.SandboxSettings{}, "admin"); err != nil {
		t.Fatalf("store an all-empty record: %v", err)
	}
	s, ok, err := db.ExecutorSandboxSettings("edge-2")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !ok {
		t.Error("an explicitly stored default must read back as configured")
	}
	if !s.IsZero() {
		t.Errorf("settings = %+v, want the zero value", s)
	}
}

func TestExecutorSandbox_Clear(t *testing.T) {
	db := openTestDB(t)

	if err := db.SetExecutorSandbox("edge-3", executor.SandboxSettings{
		Mode: executor.SandboxModeContainer, Engine: "docker",
	}, "admin"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := db.ClearExecutorSandbox("edge-3"); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if _, ok, err := db.ExecutorSandboxSettings("edge-3"); err != nil || ok {
		t.Fatalf("after clear: ok=%v err=%v; want false,nil", ok, err)
	}
	// Clearing an executor that was never configured is a no-op, not an error:
	// the caller's intent is "no policy here", which is already true.
	if err := db.ClearExecutorSandbox("never-configured"); err != nil {
		t.Errorf("clearing an unconfigured executor: %v", err)
	}
}

// TestSetExecutorSandbox_ValidatesBeforeStoring is the last line of defence. The
// engine becomes the program an executor runs, so a value that reached this table
// unchecked would be chosen by whoever last wrote the row.
func TestSetExecutorSandbox_ValidatesBeforeStoring(t *testing.T) {
	db := openTestDB(t)

	cases := []executor.SandboxSettings{
		{Mode: executor.SandboxMode("vm")},
		{Mode: executor.SandboxModeContainer, Engine: "/usr/bin/evil"},
		{Mode: executor.SandboxModeContainer, Runtime: "../../bin/sh"},
		{Mode: executor.SandboxModeContainer, Image: "-v/:/host"},
	}
	for _, in := range cases {
		if err := db.SetExecutorSandbox("edge-4", in, "admin"); err == nil {
			t.Errorf("SetExecutorSandbox(%+v) stored a value it must refuse", in)
		}
	}
	// And nothing was written on the way past.
	if _, ok, err := db.ExecutorSandboxSettings("edge-4"); err != nil || ok {
		t.Errorf("a refused write left a row behind: ok=%v err=%v", ok, err)
	}

	if err := db.SetExecutorSandbox("", executor.SandboxSettings{}, "admin"); err == nil {
		t.Error("an empty executor id must be refused")
	} else if !strings.Contains(err.Error(), "executor id") {
		t.Errorf("error = %q, want it to name the missing id", err)
	}
}

// TestSandboxSettingsFor_NilDBIsUnsetNotAnError covers the single-user,
// no-control-plane install: there is no policy, so failing to read one is not a
// fault.
func TestSandboxSettingsFor_NilDBIsUnsetNotAnError(t *testing.T) {
	s, err := SandboxSettingsFor(nil, "edge-5")
	if err != nil {
		t.Fatalf("SandboxSettingsFor(nil) = %v, want no error", err)
	}
	if !s.IsZero() {
		t.Errorf("settings = %+v, want the zero value", s)
	}
}

func TestSandboxSettingsFor_ReadsTheStoredRow(t *testing.T) {
	db := openTestDB(t)
	want := executor.SandboxSettings{Mode: executor.SandboxModeContainer, Engine: "podman"}
	if err := db.SetExecutorSandbox("edge-6", want, "admin"); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := SandboxSettingsFor(db, "edge-6")
	if err != nil {
		t.Fatalf("SandboxSettingsFor: %v", err)
	}
	if got != want {
		t.Errorf("SandboxSettingsFor = %+v, want %+v", got, want)
	}
}

// TestExecutorSandboxMigrationIsAdditive keeps a shared control plane readable by
// an older binary. A breaking migration blanks the other hub's dashboard until
// the nightly rebuild; the table is one CREATE TABLE plus one index precisely so
// that cannot happen.
func TestExecutorSandboxMigrationIsAdditive(t *testing.T) {
	migs, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	var found bool
	for _, m := range migs {
		if !strings.Contains(m.Name, "executor_sandbox") {
			continue
		}
		found = true
		if got := classifyMigration(m.SQL); got != CompatAdditive {
			t.Errorf("%s classified %q, want %q — an older hub sharing this control plane "+
				"would stop reading it", m.Name, got, CompatAdditive)
		}
	}
	if !found {
		t.Fatal("no executor_sandbox migration found; this test names the wrong file")
	}
}

// TestExecutorSandboxNetworkRoundTrips covers the column added by 0048. A
// setting that does not survive the write is the same failure as no setting at
// all: the agent is told nothing, builds a network-less driver, and the sandbox
// cannot reach the git proxy it was granted a credential for.
func TestExecutorSandboxNetworkRoundTrips(t *testing.T) {
	db := openTestDB(t)

	want := executor.SandboxSettings{
		Mode:    executor.SandboxModeContainer,
		Engine:  "docker",
		Runtime: "runsc",
		Image:   "example/harness:1",
		Network: "bridge",
	}
	if err := db.SetExecutorSandbox("edge-1", want, "admin@example.com"); err != nil {
		t.Fatalf("SetExecutorSandbox: %v", err)
	}

	got, ok, err := db.ExecutorSandboxSettings("edge-1")
	if err != nil || !ok {
		t.Fatalf("ExecutorSandboxSettings: %v (ok=%v)", err, ok)
	}
	if got.Network != "bridge" {
		t.Errorf("settings network = %q, want %q", got.Network, "bridge")
	}

	rec, ok, err := db.ExecutorSandboxRecord("edge-1")
	if err != nil || !ok {
		t.Fatalf("ExecutorSandboxRecord: %v (ok=%v)", err, ok)
	}
	if rec.Settings.Network != "bridge" {
		t.Errorf("record network = %q, want %q", rec.Settings.Network, "bridge")
	}

	list, err := db.ListExecutorSandboxes()
	if err != nil {
		t.Fatalf("ListExecutorSandboxes: %v", err)
	}
	if len(list) != 1 || list[0].Settings.Network != "bridge" {
		t.Fatalf("ListExecutorSandboxes = %+v, want one row on the bridge network", list)
	}

	// Narrowing is the direction that matters: an admin taking the network away
	// must not leave the old value behind for the next dispatch to read.
	want.Network = ""
	if err := db.SetExecutorSandbox("edge-1", want, "admin@example.com"); err != nil {
		t.Fatalf("SetExecutorSandbox (narrow): %v", err)
	}
	got, _, err = db.ExecutorSandboxSettings("edge-1")
	if err != nil {
		t.Fatalf("ExecutorSandboxSettings after narrowing: %v", err)
	}
	if got.Network != "" {
		t.Errorf("network = %q after being cleared, want empty", got.Network)
	}
}
