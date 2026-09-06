package multiui

// Tests for per-viewer project hiding (Task 20206).
//
// The property under test throughout is tenancy: the registry is one file
// shared by every user of a hub, so "alice hid it" must never read back as
// "it is hidden".

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadEntry returns the registry entry for path, failing if absent.
func loadEntry(t *testing.T, path string) ProjectEntry {
	t.Helper()
	entries, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, e := range entries {
		if e.Path == path {
			return e
		}
	}
	t.Fatalf("no registry entry for %s (have %+v)", path, entries)
	return ProjectEntry{}
}

func TestSetHiddenIsPerViewer(t *testing.T) {
	t.Setenv(EnvRoot, t.TempDir())

	const alpha, beta = "/srv/alpha", "/srv/beta"
	if err := AddPaths([]string{alpha, beta}); err != nil {
		t.Fatalf("AddPaths: %v", err)
	}

	if err := SetHidden(alpha, "alice@example.com", true); err != nil {
		t.Fatalf("SetHidden: %v", err)
	}

	e := loadEntry(t, alpha)
	if !e.HiddenForViewer("alice@example.com") {
		t.Error("alice hid alpha but it does not read back as hidden for her")
	}
	// The whole point: bob's dashboard is untouched.
	if e.HiddenForViewer("bob@example.com") {
		t.Error("alice hiding alpha also hid it from bob — the registry is shared, the preference must not be")
	}
	if got := loadEntry(t, beta); got.HiddenForViewer("alice@example.com") {
		t.Error("hiding alpha also hid beta")
	}
}

func TestSetHiddenUnhideRemovesOnlyThatViewer(t *testing.T) {
	t.Setenv(EnvRoot, t.TempDir())

	const alpha = "/srv/alpha"
	if err := AddPaths([]string{alpha}); err != nil {
		t.Fatalf("AddPaths: %v", err)
	}
	for _, who := range []string{"alice@example.com", "bob@example.com"} {
		if err := SetHidden(alpha, who, true); err != nil {
			t.Fatalf("SetHidden(%s): %v", who, err)
		}
	}
	if err := SetHidden(alpha, "alice@example.com", false); err != nil {
		t.Fatalf("unhide: %v", err)
	}

	e := loadEntry(t, alpha)
	if e.HiddenForViewer("alice@example.com") {
		t.Error("alice unhid alpha but it is still hidden for her")
	}
	if !e.HiddenForViewer("bob@example.com") {
		t.Error("alice unhiding alpha also unhid it for bob")
	}
}

// TestSetHiddenIsIdempotent guards against the set degenerating into a
// multiset — hiding twice then unhiding once would otherwise leave the
// project stuck hidden with no way back through the UI.
func TestSetHiddenIsIdempotent(t *testing.T) {
	t.Setenv(EnvRoot, t.TempDir())

	const alpha = "/srv/alpha"
	if err := AddPaths([]string{alpha}); err != nil {
		t.Fatalf("AddPaths: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := SetHidden(alpha, "alice@example.com", true); err != nil {
			t.Fatalf("SetHidden #%d: %v", i, err)
		}
	}
	if got := len(loadEntry(t, alpha).HiddenFor); got != 1 {
		t.Errorf("hiding three times recorded %d entries, want 1", got)
	}
	if err := SetHidden(alpha, "alice@example.com", false); err != nil {
		t.Fatalf("unhide: %v", err)
	}
	if loadEntry(t, alpha).HiddenForViewer("alice@example.com") {
		t.Error("one unhide did not undo three hides")
	}
}

// TestSetHiddenClearsFieldWhenEmpty keeps the serialized registry free of
// "hidden_for": [] residue, so an entry that nobody hides is byte-identical
// to one from before the feature existed.
func TestSetHiddenClearsFieldWhenEmpty(t *testing.T) {
	root := t.TempDir()
	t.Setenv(EnvRoot, root)

	const alpha = "/srv/alpha"
	if err := AddPaths([]string{alpha}); err != nil {
		t.Fatalf("AddPaths: %v", err)
	}
	if err := SetHidden(alpha, "alice@example.com", true); err != nil {
		t.Fatalf("hide: %v", err)
	}
	if err := SetHidden(alpha, "alice@example.com", false); err != nil {
		t.Fatalf("unhide: %v", err)
	}

	if got := loadEntry(t, alpha).HiddenFor; got != nil {
		t.Errorf("HiddenFor = %v, want nil after the last viewer unhid", got)
	}
	raw, err := os.ReadFile(filepath.Join(root, "projects.json"))
	if err != nil {
		t.Fatalf("read registry: %v", err)
	}
	if strings.Contains(string(raw), "hidden_for") {
		t.Errorf("registry still mentions hidden_for after the set emptied:\n%s", raw)
	}
}

// TestSetHiddenCaseInsensitive matches the Owner comparison rule: an IdP is
// free to hand back Alice@Example.com one day and alice@example.com the next,
// and a user must not lose track of what they hid because of it.
func TestSetHiddenCaseInsensitive(t *testing.T) {
	t.Setenv(EnvRoot, t.TempDir())

	const alpha = "/srv/alpha"
	if err := AddPaths([]string{alpha}); err != nil {
		t.Fatalf("AddPaths: %v", err)
	}
	if err := SetHidden(alpha, "Alice@Example.com", true); err != nil {
		t.Fatalf("hide: %v", err)
	}
	if !loadEntry(t, alpha).HiddenForViewer("alice@example.com") {
		t.Error("case difference in the viewer key lost the hidden state")
	}
	if err := SetHidden(alpha, "alice@example.com", false); err != nil {
		t.Fatalf("unhide: %v", err)
	}
	if loadEntry(t, alpha).HiddenForViewer("Alice@Example.com") {
		t.Error("unhide did not match the differently-cased key it was stored under")
	}
}

// TestSetHiddenRegistersUnknownPath covers the project a single-project
// deployment cares about: the directory `cloop ui` was launched in reaches
// the dashboard without ever being registered, and hiding it must still
// stick across a restart.
func TestSetHiddenRegistersUnknownPath(t *testing.T) {
	t.Setenv(EnvRoot, t.TempDir())

	const solo = "/srv/solo"
	if err := SetHidden(solo, "local", true); err != nil {
		t.Fatalf("SetHidden: %v", err)
	}
	e := loadEntry(t, solo)
	if !e.HiddenForViewer("local") {
		t.Error("hiding an unregistered project did not persist")
	}
	if e.Name != "solo" {
		t.Errorf("Name = %q, want the path basename", e.Name)
	}
}

// TestSetHiddenUnhideUnknownPathIsNoop is the mirror: there is nothing to
// clear, so the call must not conjure a registry entry as a side effect.
func TestSetHiddenUnhideUnknownPathIsNoop(t *testing.T) {
	t.Setenv(EnvRoot, t.TempDir())

	if err := SetHidden("/srv/never-seen", "local", false); err != nil {
		t.Fatalf("SetHidden: %v", err)
	}
	entries, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("unhiding an unknown path registered it: %+v", entries)
	}
}

func TestSetHiddenRejectsEmptyViewer(t *testing.T) {
	t.Setenv(EnvRoot, t.TempDir())

	if err := SetHidden("/srv/alpha", "  ", true); err == nil {
		t.Fatal("SetHidden with a blank viewer key must fail — an empty key " +
			"is the sentinel HiddenForViewer treats as 'nobody', so accepting " +
			"it would write a preference that can never be read back or undone")
	}
}

// TestHiddenForRoundTripsThroughJSON pins the wire field, which lives in a
// file that survives upgrades.
func TestHiddenForRoundTripsThroughJSON(t *testing.T) {
	t.Parallel()

	in := ProjectEntry{Name: "alpha", Path: "/srv/alpha", HiddenFor: []string{"alice@example.com"}}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"hidden_for":["alice@example.com"]`) {
		t.Errorf("serialized as %s, want a hidden_for array", raw)
	}
	var out ProjectEntry
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !out.HiddenForViewer("alice@example.com") {
		t.Error("hidden_for did not survive the round trip")
	}

	// An entry written before this feature must decode as hidden-by-nobody
	// rather than tripping over the missing field.
	var legacy ProjectEntry
	if err := json.Unmarshal([]byte(`{"name":"a","path":"/srv/a"}`), &legacy); err != nil {
		t.Fatalf("unmarshal legacy: %v", err)
	}
	if legacy.HiddenForViewer("alice@example.com") || legacy.HiddenFor != nil {
		t.Error("a pre-feature registry entry did not decode as unhidden")
	}
}

// TestAggregateDiscountsHidden keeps the headline counters consistent with
// the cards actually rendered.
func TestAggregateDiscountsHidden(t *testing.T) {
	t.Parallel()

	stats := Aggregate([]ProjectStatus{
		{Path: "/a", TotalTasks: 3, DoneTasks: 1, TotalSteps: 5, Health: HealthRunning},
		{Path: "/b", TotalTasks: 7, DoneTasks: 4, TotalSteps: 9, Health: HealthRunning, Hidden: true},
	})
	if stats.TotalProjects != 1 {
		t.Errorf("TotalProjects = %d, want 1 — the hidden project must not be counted", stats.TotalProjects)
	}
	if stats.TotalTasks != 3 || stats.DoneTasks != 1 || stats.TotalSteps != 5 {
		t.Errorf("stats = %+v — the hidden project's figures leaked into the totals", stats)
	}
	if stats.ActiveRuns != 1 {
		t.Errorf("ActiveRuns = %d, want 1", stats.ActiveRuns)
	}
}
