package hubdoctor

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/hubcluster"
)

// TestAnAdoptedRunsUndecidedTakeoverIsReported (Task 20451): a run whose hub
// process could not take a credential over is reported from its owner row —
// with what it waits on, since when, why and until when — and with who tries
// next once that process has stopped.
func TestAnAdoptedRunsUndecidedTakeoverIsReported(t *testing.T) {
	dir := t.TempDir()
	path := mustInitStateDB(t, dir)
	node, err := hubcluster.Join(hubcluster.Options{
		DBPath: path, AdvertiseURL: "http://127.0.0.1:1",
		Heartbeat: 40 * time.Millisecond, MemberTTL: 500 * time.Millisecond, BusPoll: 15 * time.Millisecond,
		BusFlush: 5 * time.Millisecond, Campaign: 30 * time.Millisecond, LeaderTTL: 600 * time.Millisecond,
		LeaderInterval: 60 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	node.Start(ctx)
	t.Cleanup(func() {
		cancel()
		_ = node.Close()
	})
	run := func(opts Options) []Finding {
		var out []Finding
		checkRunTakeovers(dir, opts, func(f Finding) { out = append(out, f) })
		return out
	}

	// A run that took everything over is nothing to report.
	if _, ok, err := node.Claim(hubcluster.OwnerKindRun, "/srv/fine", map[string]any{
		"executor": "edge-1", "handle": "h-0", "leases": []string{"lea_0"},
	}); err != nil || !ok {
		t.Fatalf("claim = %v, %v", ok, err)
	}
	if got := run(Options{}); len(got) != 1 || got[0].Severity != SeverityPass || got[0].Check != runTakeoversCheck {
		t.Fatalf("with no undecided takeover: %+v", got)
	}

	since := time.Now().Add(-90 * time.Second).UTC().Truncate(time.Second)
	until := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second)
	if _, ok, err := node.Claim(hubcluster.OwnerKindRun, "/srv/proj", map[string]any{
		"executor": "edge-1", "handle": "h-1", "leases": []string{"lea_1"},
		"takeovers": []hubcluster.RunTakeover{{Kind: "run", ID: "lea_1", Since: since, Attempts: 7,
			Reason: "statedb: database is locked", Until: until}},
	}); err != nil || !ok {
		t.Fatalf("claim = %v, %v", ok, err)
	}
	got := run(Options{})
	if len(got) != 1 || got[0].Severity != SeverityWarn {
		t.Fatalf("an undecided takeover = %+v, want one warning", got)
	}
	f := got[0]
	for _, want := range []string{"/srv/proj", node.ID(), "which serves", "secret lease lea_1",
		since.Format(time.RFC3339), "7 attempt", "database is locked", until.Format(time.RFC3339),
		"git pushes and kubectl calls"} {
		if !strings.Contains(f.Message, want) {
			t.Errorf("the finding does not say %q: %s", want, f.Message)
		}
	}
	if !strings.Contains(f.Remediation, "retries on its own") || !strings.Contains(f.Remediation, "secrets.kms.reachable") {
		t.Errorf("the remediation = %q", f.Remediation)
	}
	if f.Details["id"] != "lea_1" || f.Details["member_serving"] != true {
		t.Errorf("details = %+v", f.Details)
	}

	// An hour on, the member that owned it has stopped: whoever adopts the
	// run next tries again, and the lease has lapsed.
	later := run(Options{Now: func() time.Time { return time.Now().Add(time.Hour) }})
	if len(later) != 1 || !strings.Contains(later[0].Message, "which has stopped") ||
		!strings.Contains(later[0].Message, "lapsed at") || !strings.Contains(later[0].Remediation, "adopts the run next") {
		t.Fatalf("an undecided takeover of a stopped member = %+v", later)
	}
}

// TestRunTakeoversWithoutAControlPlaneIsSilent: nothing has been adopted on a
// hub with no database yet.
func TestRunTakeoversWithoutAControlPlaneIsSilent(t *testing.T) {
	var got []Finding
	checkRunTakeovers(t.TempDir(), Options{}, func(f Finding) { got = append(got, f) })
	if len(got) != 0 {
		t.Fatalf("findings without a database: %+v", got)
	}
}
