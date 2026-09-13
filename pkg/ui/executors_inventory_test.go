package ui

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/version"
)

// withHubVersion stages the control-plane build for a test.
//
// hubVersion is a package var precisely so this is possible: skew is a
// comparison against the hub, and a test that could not fix both sides could
// only assert the case that happens to hold for whatever build ran it — which
// under `go test` is always the unstamped "dev", the one case where no ordering
// exists at all.
func withHubVersion(t *testing.T, v string) {
	t.Helper()
	prev := hubVersion
	hubVersion = func() string { return v }
	t.Cleanup(func() { hubVersion = prev })
}

func remoteRow(inv statedb.ExecutorInventory) statedb.ExecutorRow {
	return statedb.ExecutorRow{
		ID:        "edge-1",
		Name:      "edge-1",
		Kind:      executor.KindRemoteAgent,
		Status:    remote.StatusOnline,
		Inventory: inv,
	}
}

func fullInventory() statedb.ExecutorInventory {
	return statedb.ExecutorInventory{
		AgentVersion:      "v0.1.0",
		OS:                "linux",
		Arch:              "arm64",
		CPUs:              4,
		MemoryMB:          7861,
		Harnesses:         []string{"claude", "codex"},
		ContainerRuntimes: []string{"podman"},
		WorkDirRoot:       "/var/lib/cloop-executor/work",
	}
}

// TestAnnotateInventorySurfacesEveryAdvertisedField is the regression test for
// the second defect: the device's advertisement was stored as an opaque
// json.RawMessage and rendered as undifferentiated chips, so none of these
// fields was usable for filtering, placement diagnosis, or inventory.
//
// Each field is asserted individually rather than with DeepEqual so a failure
// names the field that stopped being surfaced.
func TestAnnotateInventorySurfacesEveryAdvertisedField(t *testing.T) {
	withHubVersion(t, "v0.1.0")
	inv := fullInventory()

	var view executorView
	annotateInventory(&view, remoteRow(inv), nil)

	if view.Inventory == nil {
		t.Fatal("Inventory is nil; the device's advertisement was not surfaced at all")
	}
	got := view.Inventory
	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"agent_version", got.AgentVersion, "v0.1.0"},
		{"os", got.OS, "linux"},
		{"arch", got.Arch, "arm64"},
		{"cpus", got.CPUs, 4},
		{"memory_mb", got.MemoryMB, 7861},
		{"workdir_root", got.WorkDirRoot, "/var/lib/cloop-executor/work"},
		{"memory_label", got.MemoryLabel, "7.7 GB"},
		{"agent_version_label", got.AgentVersionLabel, "v0.1.0"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.field, c.got, c.want)
		}
	}
	if strings.Join(got.Harnesses, ",") != "claude,codex" {
		t.Errorf("harnesses = %v, want [claude codex]", got.Harnesses)
	}
	if strings.Join(got.ContainerRuntimes, ",") != "podman" {
		t.Errorf("container_runtimes = %v, want [podman]", got.ContainerRuntimes)
	}
	// Sourced from the stored row, not a session, so it must not claim to be
	// current.
	if got.Live {
		t.Error("Live = true for inventory read from the stored row")
	}
}

// TestAnnotateInventorySkewedBuild is the case the task names directly: an agent
// reporting a build that materially trails the hub must be flagged, and the
// note must point at a procedure that exists.
func TestAnnotateInventorySkewedBuild(t *testing.T) {
	withHubVersion(t, "v0.3.0")
	inv := fullInventory()
	inv.AgentVersion = "v0.1.0" // two minor releases behind

	var view executorView
	annotateInventory(&view, remoteRow(inv), nil)

	if view.VersionSkew == nil {
		t.Fatal("VersionSkew is nil for a device on an older build")
	}
	skew := view.VersionSkew
	if skew.Skew != string(version.SkewBehind) {
		t.Errorf("skew = %q, want %q", skew.Skew, version.SkewBehind)
	}
	if !skew.Material {
		t.Error("a two-minor-release gap was not reported as material")
	}
	if skew.HubVersion != "v0.3.0" {
		t.Errorf("hub_version = %q, want v0.3.0", skew.HubVersion)
	}
	// Both versions in the note, so an operator can check the comparison
	// instead of trusting it.
	for _, want := range []string{"v0.1.0", "v0.3.0"} {
		if !strings.Contains(skew.Note, want) {
			t.Errorf("note does not name %q: %q", want, skew.Note)
		}
	}
	if !strings.Contains(skew.Note, AgentUpgradeCommand) {
		t.Errorf("note does not name the upgrade command %q: %q", AgentUpgradeCommand, skew.Note)
	}
}

// TestAnnotateInventoryPatchDriftIsNotMaterial pins the deliberate quietness.
// Flagging every patch release across a fleet would train operators to ignore
// the warning, costing them the one that matters.
func TestAnnotateInventoryPatchDriftIsNotMaterial(t *testing.T) {
	withHubVersion(t, "v0.1.3")
	inv := fullInventory()
	inv.AgentVersion = "v0.1.1"

	var view executorView
	annotateInventory(&view, remoteRow(inv), nil)

	if view.VersionSkew == nil {
		t.Fatal("VersionSkew is nil")
	}
	if view.VersionSkew.Skew != string(version.SkewPatch) {
		t.Errorf("skew = %q, want %q", view.VersionSkew.Skew, version.SkewPatch)
	}
	if view.VersionSkew.Material {
		t.Error("patch drift reported as material; the panel would warn on every card")
	}
}

// TestAnnotateInventoryLegacyPlaceholder covers the fleet's oldest agents, which
// report the hardcoded "1". Before this work that was the *only* value any agent
// ever sent, so it must be recognised rather than compared: read as a version it
// is major 1, which would rank a year-old device above the hub.
func TestAnnotateInventoryLegacyPlaceholder(t *testing.T) {
	withHubVersion(t, "v0.0.1")
	inv := fullInventory()
	inv.AgentVersion = version.LegacyAgentVersion

	var view executorView
	annotateInventory(&view, remoteRow(inv), nil)

	if view.VersionSkew == nil {
		t.Fatal("VersionSkew is nil")
	}
	if view.VersionSkew.Skew == string(version.SkewAhead) {
		t.Fatal("the legacy placeholder was read as a build NEWER than the hub")
	}
	if view.VersionSkew.Skew != string(version.SkewLegacy) {
		t.Errorf("skew = %q, want %q", view.VersionSkew.Skew, version.SkewLegacy)
	}
	if !view.VersionSkew.Material {
		t.Error("a legacy build was not reported as material")
	}
	if view.Inventory == nil || !strings.Contains(view.Inventory.AgentVersionLabel, "legacy") {
		t.Errorf("legacy build not labelled as such: %+v", view.Inventory)
	}
}

// TestAnnotateInventoryUnreportedVersion covers a connected device that sends no
// version at all — distinct from the placeholder, and distinct from "we never
// asked".
func TestAnnotateInventoryUnreportedVersion(t *testing.T) {
	withHubVersion(t, "v0.1.0")
	inv := fullInventory()
	inv.AgentVersion = ""

	var view executorView
	annotateInventory(&view, remoteRow(inv), nil)

	if view.VersionSkew == nil || view.VersionSkew.Skew != string(version.SkewUnknown) {
		t.Fatalf("skew = %+v, want %q", view.VersionSkew, version.SkewUnknown)
	}
	if view.Inventory == nil || view.Inventory.AgentVersionLabel != "unreported" {
		t.Errorf("unreported build not labelled: %+v", view.Inventory)
	}
	// The rest of the advertisement is still present: a device that cannot name
	// its build can still be placed on.
	if view.Inventory.CPUs != 4 {
		t.Errorf("hardware inventory lost when the version was absent: %+v", view.Inventory)
	}
}

// TestAnnotateInventoryUniformFleetIsSilent: a matching build must produce no
// note, so the panel says nothing when there is nothing to say — but must still
// report that a comparison happened, which is different from never comparing.
func TestAnnotateInventoryUniformFleetIsSilent(t *testing.T) {
	withHubVersion(t, "v0.1.0")

	var view executorView
	annotateInventory(&view, remoteRow(fullInventory()), nil)

	if view.VersionSkew == nil {
		t.Fatal("VersionSkew is nil for a device on the hub's own build")
	}
	if view.VersionSkew.Skew != string(version.SkewNone) {
		t.Errorf("skew = %q, want %q", view.VersionSkew.Skew, version.SkewNone)
	}
	if view.VersionSkew.Material {
		t.Error("a matching build reported as material skew")
	}
	if view.VersionSkew.Note != "" {
		t.Errorf("a matching build carried a note: %q", view.VersionSkew.Note)
	}
}

// TestAnnotateInventorySkipsNonDeviceBackends: a container or Kubernetes
// executor runs this very binary, so comparing its "build" against the hub's
// would be comparing the hub with itself and would warn about nothing.
func TestAnnotateInventorySkipsNonDeviceBackends(t *testing.T) {
	withHubVersion(t, "v0.3.0")

	for _, kind := range []string{executor.KindContainer, executor.KindKubernetes, executor.KindLocalProcess} {
		row := remoteRow(fullInventory())
		row.Kind = kind

		var view executorView
		annotateInventory(&view, row, nil)

		if view.Inventory != nil {
			t.Errorf("%s: rendered a device inventory for a non-device backend", kind)
		}
		if view.VersionSkew != nil {
			t.Errorf("%s: compared a local driver's build against the hub's", kind)
		}
	}
}

// TestExecutorViewInventoryWireShape asserts the JSON the panel consumes, since
// the frontend reads these exact keys. A rename here is invisible to the Go
// compiler and shows up as a silently empty chip row.
func TestExecutorViewInventoryWireShape(t *testing.T) {
	withHubVersion(t, "v0.3.0")
	inv := fullInventory()
	inv.AgentVersion = "v0.1.0"

	var view executorView
	annotateInventory(&view, remoteRow(inv), nil)

	encoded, err := json.Marshal(view)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	invWire, ok := wire["inventory"].(map[string]any)
	if !ok {
		t.Fatalf("no inventory object on the wire: %s", encoded)
	}
	// Exactly the keys 23-executors.js reads.
	for _, key := range []string{
		"agent_version", "agent_version_label", "os", "arch", "cpus",
		"memory_mb", "memory_label", "harnesses", "container_runtimes",
		"workdir_root", "live",
	} {
		if _, present := invWire[key]; !present {
			t.Errorf("inventory.%s missing from the wire payload; "+
				"23-executors.js reads it", key)
		}
	}

	skewWire, ok := wire["version_skew"].(map[string]any)
	if !ok {
		t.Fatalf("no version_skew object on the wire: %s", encoded)
	}
	for _, key := range []string{"skew", "material", "hub_version", "note"} {
		if _, present := skewWire[key]; !present {
			t.Errorf("version_skew.%s missing from the wire payload", key)
		}
	}
}

// TestInventoryFromCapsProjectsEveryField guards the projection against a field
// being added to AgentCapabilities and quietly not reaching storage — the shape
// of the original bug, where the data arrived and was dropped.
func TestInventoryFromCapsProjectsEveryField(t *testing.T) {
	caps := remote.AgentCapabilities{
		OS:                "linux",
		Arch:              "amd64",
		CPUs:              8,
		MemoryMB:          32000,
		ContainerRuntimes: []string{"docker", "podman"},
		Harnesses:         []string{"claude"},
		WorkDirRoot:       "/srv/work",
	}
	got := inventoryFromCaps(caps, "v1.2.3")

	want := statedb.ExecutorInventory{
		AgentVersion:      "v1.2.3",
		OS:                "linux",
		Arch:              "amd64",
		CPUs:              8,
		MemoryMB:          32000,
		Harnesses:         []string{"claude"},
		ContainerRuntimes: []string{"docker", "podman"},
		WorkDirRoot:       "/srv/work",
	}
	if got.AgentVersion != want.AgentVersion || got.OS != want.OS || got.Arch != want.Arch ||
		got.CPUs != want.CPUs || got.MemoryMB != want.MemoryMB ||
		got.WorkDirRoot != want.WorkDirRoot ||
		strings.Join(got.Harnesses, ",") != strings.Join(want.Harnesses, ",") ||
		strings.Join(got.ContainerRuntimes, ",") != strings.Join(want.ContainerRuntimes, ",") {
		t.Errorf("inventoryFromCaps:\n got %+v\nwant %+v", got, want)
	}
}

func TestMemoryLabel(t *testing.T) {
	tests := []struct {
		mb   int
		want string
	}{
		// Undetectable memory renders as nothing, not "0 MB": a device whose
		// agent could not read its RAM is not a device with no RAM.
		{0, ""},
		{-1, ""},
		{512, "512 MB"},
		{1023, "1023 MB"},
		{1024, "1.0 GB"},
		{7861, "7.7 GB"},
		{32000, "31.2 GB"},
	}
	for _, tc := range tests {
		if got := memoryLabel(tc.mb); got != tc.want {
			t.Errorf("memoryLabel(%d) = %q, want %q", tc.mb, got, tc.want)
		}
	}
}

// TestUpgradeHintNamesAnImplementedFlag is the direct regression test for the
// third defect: the panel told operators to run
// `cloop executor agent install --upgrade` when no such flag existed, so the
// documented remediation for its most security-relevant warning was a dead end.
//
// The flag's existence is asserted in cmd (see TestExecutorInstallHasUpgradeFlag);
// this side asserts the message still points at it and at nothing else.
func TestUpgradeHintNamesAnImplementedFlag(t *testing.T) {
	if !strings.Contains(upgradeHint, AgentUpgradeCommand) {
		t.Errorf("upgradeHint does not name AgentUpgradeCommand: %q", upgradeHint)
	}
	if !strings.Contains(AgentUpgradeCommand, "--upgrade") {
		t.Errorf("AgentUpgradeCommand = %q, expected it to name --upgrade", AgentUpgradeCommand)
	}
	// The hint must tell the operator to get the new binary onto the device
	// first; --upgrade alone on an unchanged binary is a no-op, and an operator
	// following an incomplete instruction would conclude the flag is broken.
	if !strings.Contains(strings.ToLower(upgradeHint), "binary") {
		t.Errorf("upgradeHint does not mention getting the new binary onto the device: %q", upgradeHint)
	}
}
