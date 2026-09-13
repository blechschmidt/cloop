package statedb

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// openInventoryDB opens a migrated database in a temp directory.
func openInventoryDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func fullInventory() ExecutorInventory {
	return ExecutorInventory{
		AgentVersion:      "v0.0.1",
		OS:                "linux",
		Arch:              "arm64",
		CPUs:              4,
		MemoryMB:          7861,
		Harnesses:         []string{"claude", "codex"},
		ContainerRuntimes: []string{"podman"},
		WorkDirRoot:       "/var/lib/cloop-executor/work",
	}
}

// TestExecutorInventoryRoundTrips is the gate on the failure this project has
// hit before: a new field with a struct tag but no column silently vanishes at
// the first Save. Every field is asserted, through both read paths.
func TestExecutorInventoryRoundTrips(t *testing.T) {
	db := openInventoryDB(t)
	want := fullInventory()

	if err := db.UpsertExecutor(ExecutorRow{
		ID:        "edge-1",
		Name:      "edge-1",
		Kind:      "remote-agent",
		Status:    ExecutorStatusOnline,
		Inventory: want,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := db.GetExecutor("edge-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !reflect.DeepEqual(got.Inventory, want) {
		t.Errorf("GetExecutor inventory:\n got %+v\nwant %+v", got.Inventory, want)
	}

	// ListExecutors is a separate SELECT with its own column list; a drift
	// between the two is exactly what executorColumns exists to prevent, and
	// this asserts it rather than trusting it.
	list, err := db.ListExecutors()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("ListExecutors returned %d rows, want 1", len(list))
	}
	if !reflect.DeepEqual(list[0].Inventory, want) {
		t.Errorf("ListExecutors inventory:\n got %+v\nwant %+v", list[0].Inventory, want)
	}
}

// TestExecutorInventoryRefreshOnReconnect is the regression test for the bug
// behind this whole change: inventory was recorded once, at enrollment, so an
// upgraded device kept being reported as the build it ran the day it joined.
//
// It also pins the other half of the contract — that refreshing inventory must
// not disturb the enrollment facts, since the upsert now writes far more
// columns than it used to.
func TestExecutorInventoryRefreshOnReconnect(t *testing.T) {
	db := openInventoryDB(t)

	first := fullInventory()
	first.AgentVersion = "1" // the old hardcoded placeholder
	if err := db.UpsertExecutor(ExecutorRow{
		ID: "edge-1", Name: "edge-1", Kind: "remote-agent",
		Status: ExecutorStatusOnline, EnrolledBy: "tok-abc", Inventory: first,
	}); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	enrolled, err := db.GetExecutor("edge-1")
	if err != nil {
		t.Fatalf("get after enroll: %v", err)
	}

	// The device is upgraded and reconnects reporting a real version, more
	// memory, and a harness it did not have before.
	second := fullInventory()
	second.AgentVersion = "v0.1.0"
	second.MemoryMB = 16000
	second.Harnesses = []string{"claude", "codex", "cloop"}
	if err := db.UpsertExecutor(ExecutorRow{
		ID: "edge-1", Name: "edge-1", Kind: "remote-agent",
		Status: ExecutorStatusOnline, EnrolledBy: "tok-abc", Inventory: second,
	}); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	got, err := db.GetExecutor("edge-1")
	if err != nil {
		t.Fatalf("get after reconnect: %v", err)
	}
	if !reflect.DeepEqual(got.Inventory, second) {
		t.Errorf("inventory not refreshed on reconnect:\n got %+v\nwant %+v",
			got.Inventory, second)
	}
	if got.Inventory.AgentVersion == "1" {
		t.Error("agent version still the pre-upgrade placeholder after reconnect")
	}
	// CreatedAt is documented as preserved across upserts; an inventory
	// refresh must not be the thing that rewrites an enrollment date.
	if !got.CreatedAt.Equal(enrolled.CreatedAt) {
		t.Errorf("CreatedAt changed on reconnect: %v -> %v", enrolled.CreatedAt, got.CreatedAt)
	}
	if got.EnrolledBy != "tok-abc" {
		t.Errorf("EnrolledBy = %q after reconnect, want %q", got.EnrolledBy, "tok-abc")
	}
}

// TestExecutorInventoryAbsentIsEmptyNotError covers the pre-migration rows and
// the configured (non-enrolled) backends: both must read back as a zero
// inventory that reports itself unknown, rather than as an error or as a device
// claiming zero CPUs.
func TestExecutorInventoryAbsentIsEmptyNotError(t *testing.T) {
	db := openInventoryDB(t)
	if err := db.UpsertExecutor(ExecutorRow{
		ID: "container", Name: "container", Kind: "container", Status: ExecutorStatusOnline,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := db.GetExecutor("container")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Inventory.Known() {
		t.Errorf("empty inventory reported Known(): %+v", got.Inventory)
	}
	if got.Inventory.Harnesses != nil || got.Inventory.ContainerRuntimes != nil {
		t.Errorf("empty lists decoded as non-nil: %+v", got.Inventory)
	}
	// omitzero keeps an absent inventory out of the wire entirely, so a
	// configured backend does not render an empty inventory block.
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got := string(encoded); strings.Contains(got, `"inventory"`) {
		t.Errorf("zero inventory serialised into the wire payload: %s", got)
	}
}

// TestExecutorInventoryMalformedListsDoNotFailTheListing pins the deliberate
// choice that advisory inventory cannot take the fleet view down: a device
// whose harness list got corrupted is still a device an operator must see.
func TestExecutorInventoryMalformedListsDoNotFailTheListing(t *testing.T) {
	db := openInventoryDB(t)
	if err := db.UpsertExecutor(ExecutorRow{
		ID: "edge-1", Name: "edge-1", Kind: "remote-agent", Status: ExecutorStatusOnline,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	// Corrupt the stored blobs behind the API's back, which is the only way
	// this state can arise.
	if _, err := db.conn.Exec(
		`UPDATE executors SET agent_harnesses = ?, agent_runtimes = ? WHERE id = ?`,
		`{"not":"a list"}`, `[[[`, "edge-1"); err != nil {
		t.Fatalf("corrupt: %v", err)
	}

	list, err := db.ListExecutors()
	if err != nil {
		t.Fatalf("ListExecutors failed on a malformed inventory blob: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("executor dropped from the listing: got %d rows", len(list))
	}
	if list[0].Inventory.Harnesses != nil || list[0].Inventory.ContainerRuntimes != nil {
		t.Errorf("malformed lists were not discarded: %+v", list[0].Inventory)
	}
}
