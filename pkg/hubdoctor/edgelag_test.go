package hubdoctor

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// seedDevice stores a device row the way the hub's connect recorder does: the
// inventory columns plus the full advertisement it sent.
func seedDevice(t *testing.T, dir, id, name, agentVersion string, caps map[string]any) {
	t.Helper()
	db, err := statedb.Open(filepath.Join(dir, ".cloop", "state.db"))
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	raw, err := json.Marshal(caps)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertExecutor(statedb.ExecutorRow{ID: id, Name: name, Kind: executor.KindRemoteAgent,
		Status: statedb.ExecutorStatusOnline, Capabilities: raw, CreatedAt: time.Now(),
		Inventory: statedb.ExecutorInventory{AgentVersion: agentVersion}}); err != nil {
		t.Fatalf("UpsertExecutor: %v", err)
	}
}

func withHubSequence(t *testing.T, seq int, ok bool) {
	t.Helper()
	prev := hubSequence
	hubSequence = func() (int, bool) { return seq, ok }
	t.Cleanup(func() { hubSequence = prev })
}

// TestEdgeLagWarnsPastTwentyBehind (Task 20380): a device on the edge channel
// more than twenty commits behind this hub's build is a warning with the way
// forward; one within twenty, or ahead, passes; one whose build carries no
// sequence is a warning, because rollback protection does not cover it yet; a
// device on the stable channel is not compared at all.
func TestEdgeLagWarnsPastTwentyBehind(t *testing.T) {
	dir := t.TempDir()
	mustInitStateDB(t, dir)
	withHubSequence(t, 4200, true)
	seedDevice(t, dir, "a1", "close", "dev+g1111111", map[string]any{"update_channel": "edge", "build_sequence": 4180})
	seedDevice(t, dir, "a2", "far", "dev+g2222222", map[string]any{"update_channel": "edge", "build_sequence": 4179})
	seedDevice(t, dir, "a3", "ahead", "dev+g3333333", map[string]any{"update_channel": "edge", "build_sequence": 4210})
	seedDevice(t, dir, "a4", "unsequenced", "dev+g4a67976", map[string]any{"update_channel": "edge"})
	seedDevice(t, dir, "a5", "stable", "v0.0.4", map[string]any{"update_channel": "stable"})

	var got []Finding
	checkEdgeLag(dir, func(f Finding) { got = append(got, f) })
	byTitle := map[string]Finding{}
	for _, f := range got {
		if f.Check != "executors.edge_lag" {
			t.Errorf("finding under check %q", f.Check)
		}
		byTitle[f.Title] = f
	}
	if len(got) != 4 {
		t.Fatalf("findings = %+v, want one per edge device", got)
	}
	for title, want := range map[string]struct {
		sev  Severity
		says string
	}{
		"Edge build of close":       {SeverityPass, "within 20 commits of this hub's build at sequence 4200"},
		"Edge build of far":         {SeverityWarn, "21 commits behind this hub's build at sequence 4200 (more than 20)"},
		"Edge build of ahead":       {SeverityPass, "10 commits ahead of this hub's build"},
		"Edge build of unsequenced": {SeverityWarn, "rollback protection does not cover it"},
	} {
		f, ok := byTitle[title]
		if !ok {
			t.Errorf("no finding %q", title)
			continue
		}
		if f.Severity != want.sev || !strings.Contains(f.Message, want.says) {
			t.Errorf("%s: %s %q, want %s saying %q", title, f.Severity, f.Message, want.sev, want.says)
		}
		if f.Severity != SeverityPass && f.Remediation == "" {
			t.Errorf("%s: a warning without a remediation", title)
		}
	}
	if _, ok := byTitle["Edge build of stable"]; ok {
		t.Error("a device on the stable channel was compared with the hub's edge build")
	}
}

// TestEdgeLagNeedsAStampedHub: with edge devices enrolled and a doctor binary
// that carries no sequence, the check says it could not compare rather than
// passing; with no edge device there is nothing to say.
func TestEdgeLagNeedsAStampedHub(t *testing.T) {
	dir := t.TempDir()
	mustInitStateDB(t, dir)
	withHubSequence(t, 0, false)

	var got []Finding
	checkEdgeLag(dir, func(f Finding) { got = append(got, f) })
	if len(got) != 0 {
		t.Fatalf("no edge device, yet: %+v", got)
	}

	seedDevice(t, dir, "a1", "sgx", "dev+g4a67976", map[string]any{"update_channel": "edge", "build_sequence": 4180})
	checkEdgeLag(dir, func(f Finding) { got = append(got, f) })
	if len(got) != 1 || got[0].Severity != SeverityWarn || !strings.Contains(got[0].Message, "carries no sequence") ||
		got[0].Remediation == "" {
		t.Fatalf("findings = %+v", got)
	}
}
