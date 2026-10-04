package ui

// executors_edge_test.go holds the Executors panel's Upgrade dialog and REST
// route to the edge channel (Task 20376): a device on the edge channel is
// offered this hub's own build once CI has published it, never one that would
// lower its protocol, and is told plainly why when it is not offered; a device
// on the stable channel is never sent a build of main.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/upgrade"
)

const hubCommit = "a0f387020b4df29e9f39ebe0369ec0de0ca8c674"

// withEdgeResolution stubs GitHub: every resolution returns what build says,
// for the version asked about. It installs a fresh cache, and counts the
// lookups.
func withEdgeResolution(t *testing.T, build func(version, commit string) upgrade.EdgeBuild) *int {
	t.Helper()
	var mu sync.Mutex
	calls := 0
	prevResolve, prevCache := resolveEdgeBuild, hubEdgeCache
	resolveEdgeBuild = func(_ context.Context, version, commit string) upgrade.EdgeBuild {
		mu.Lock()
		calls++
		mu.Unlock()
		return build(version, commit)
	}
	hubEdgeCache = newEdgeBuildCache()
	t.Cleanup(func() { resolveEdgeBuild, hubEdgeCache = prevResolve, prevCache })
	return &calls
}

func published(protocol int) func(string, string) upgrade.EdgeBuild {
	return func(version, _ string) upgrade.EdgeBuild {
		return upgrade.EdgeBuild{Version: version, Short: "a0f3870", Commit: hubCommit, Status: upgrade.EdgePublished,
			Manifest: upgrade.EdgeManifest{Commit: hubCommit, Version: "dev+ga0f3870", Protocol: protocol}}
	}
}

func unpublished(status upgrade.EdgeStatus) func(string, string) upgrade.EdgeBuild {
	return func(version, _ string) upgrade.EdgeBuild {
		b := upgrade.EdgeBuild{Version: version, Short: "a0f3870", Status: status, RunURL: "https://github.com/x/run"}
		if status != upgrade.EdgeUnpushed {
			b.Commit = hubCommit
		}
		return b
	}
}

// edgeDevice registers a connected device advertising protocol and caps, and
// answering upgrade frames by accepting them; it returns what it was asked.
func edgeDevice(t *testing.T, id string, protocol int, caps remote.AgentCapabilities) (*remote.Executor, func() []string) {
	t.Helper()
	ex, err := remote.NewExecutor(remote.Options{ID: id, Name: "sgx"})
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.DefaultRegistry.Register(ex); err != nil {
		t.Fatalf("Register: %v", err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(id) })
	var mu sync.Mutex
	var asked []string
	end := connectAnsweringCaps(t, ex, protocol, "dev+g06e06ed", caps, func(conn remote.Conn, f remote.Frame) {
		if f.Type != remote.TypeUpgrade {
			return
		}
		p, err := remote.DecodeUpgrade(f)
		if err != nil {
			return
		}
		mu.Lock()
		asked = append(asked, p.TargetVersion)
		mu.Unlock()
		reply, err := remote.NewFrame(remote.TypeUpgrading, f.ID, "", remote.UpgradingPayload{
			Accepted: true, FromVersion: "dev+g06e06ed", TargetVersion: p.TargetVersion,
		})
		if err == nil {
			_ = conn.WriteFrame(context.Background(), reply)
		}
	})
	t.Cleanup(end)
	return ex, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), asked...)
	}
}

var edgeCaps = remote.AgentCapabilities{UpdateChannel: "edge", RemoteUpgrade: true}

func dialog(t *testing.T, ex *remote.Executor) executorView {
	t.Helper()
	view := executorView{}
	annotateInventory(context.Background(), &view, statedb.ExecutorRow{Kind: executor.KindRemoteAgent}, ex)
	return view
}

// TestUpgradeDialog_OffersTheHubsBuildToAnEdgeDevice: published, and speaking
// at least what the device does — so it is offered, by name.
func TestUpgradeDialog_OffersTheHubsBuildToAnEdgeDevice(t *testing.T) {
	withHubVersion(t, "dev+ga0f3870")
	withEdgeResolution(t, published(17))
	ex, _ := edgeDevice(t, "edge-offer-1", 16, edgeCaps)

	v := dialog(t, ex)
	if v.UpgradeTarget != "edge:"+hubCommit || v.UpgradeLabel != "this hub's build (a0f3870)" {
		t.Fatalf("offer = %q (%q), want this hub's edge build", v.UpgradeTarget, v.UpgradeLabel)
	}
	if v.UpdateChannel != "edge" || !strings.Contains(v.UpgradeNote, "signed commit a0f3870") ||
		!strings.Contains(v.UpgradeNote, "v17") {
		t.Errorf("channel %q, note %q", v.UpdateChannel, v.UpgradeNote)
	}
}

// TestUpgradeDialog_SaysWhyTheHubsBuildIsNotOffered walks the three reasons
// the task names — an unpushed local commit, CI not having published it yet,
// CI having failed — and a protocol the build would lower.
func TestUpgradeDialog_SaysWhyTheHubsBuildIsNotOffered(t *testing.T) {
	withHubVersion(t, "dev+ga0f3870")
	for _, c := range []struct {
		name  string
		build func(string, string) upgrade.EdgeBuild
		says  string
	}{
		{"unpushed", unpublished(upgrade.EdgeUnpushed), "never pushed"},
		{"CI running", unpublished(upgrade.EdgeCIRunning), "CI has not published commit a0f3870 yet"},
		{"publishing", unpublished(upgrade.EdgePublishing), "has not published it yet"},
		{"CI failed", unpublished(upgrade.EdgeCIFailed), "CI failed on commit a0f3870"},
		{"lower protocol", published(16), "it speaks v16"},
	} {
		t.Run(c.name, func(t *testing.T) {
			withEdgeResolution(t, c.build)
			ex, _ := edgeDevice(t, "edge-why-"+strings.ReplaceAll(c.name, " ", "-"), 17, edgeCaps)
			v := dialog(t, ex)
			if strings.HasPrefix(v.UpgradeTarget, "edge:") {
				t.Fatalf("an unofferable build was offered: %q", v.UpgradeTarget)
			}
			if !strings.Contains(v.UpgradeNote, "This hub's build (a0f3870) is not offered") ||
				!strings.Contains(v.UpgradeNote, c.says) {
				t.Errorf("note %q does not say %q", v.UpgradeNote, c.says)
			}
		})
	}
}

// TestUpgradeDialog_NeverOffersMainToAStableDevice: a device on the stable
// channel is offered what it was before, and told where the switch is.
func TestUpgradeDialog_NeverOffersMainToAStableDevice(t *testing.T) {
	withHubVersion(t, "dev+ga0f3870")
	calls := withEdgeResolution(t, published(17))
	ex, _ := edgeDevice(t, "stable-offer-1", 16, remote.AgentCapabilities{UpdateChannel: "stable", RemoteUpgrade: true})
	v := dialog(t, ex)
	if strings.HasPrefix(v.UpgradeTarget, "edge:") || v.UpgradeLabel != "" {
		t.Fatalf("a stable device was offered %q", v.UpgradeTarget)
	}
	if !strings.Contains(v.UpgradeNote, executor.EdgeOptIn) {
		t.Errorf("the note does not say how the device could follow the hub: %q", v.UpgradeNote)
	}
	if *calls != 0 {
		t.Errorf("GitHub was asked %d times about a device that cannot use the answer", *calls)
	}
}

// TestUpgradeDialog_ADeviceThatCannotUpgradeIsOfferedNothing.
func TestUpgradeDialog_ADeviceThatCannotUpgradeIsOfferedNothing(t *testing.T) {
	withHubVersion(t, "dev+ga0f3870")
	withEdgeResolution(t, published(17))
	const issue = "cosign is not installed on this device"
	ex, _ := edgeDevice(t, "edge-cannot-1", 16, remote.AgentCapabilities{UpdateChannel: "edge", RemoteUpgradeIssue: issue})
	v := dialog(t, ex)
	if v.UpgradeTarget != "" || !strings.Contains(v.UpgradeNote, issue) {
		t.Errorf("offer %q, note %q", v.UpgradeTarget, v.UpgradeNote)
	}
}

// TestExecutorUpgrade_EdgeTargets drives the REST route.
func TestExecutorUpgrade_EdgeTargets(t *testing.T) {
	withHubVersion(t, "dev+ga0f3870")
	withLatestRelease(t, "v0.0.4", nil)
	dir := setupProjectDir(t, "edge upgrades", nil)

	t.Run("the hub's own version means its edge build", func(t *testing.T) {
		withEdgeResolution(t, published(17))
		_, asked := edgeDevice(t, "edge-api-1", 16, edgeCaps)
		code, body := postUpgrade(t, dir, "edge-api-1", map[string]any{"target_version": "dev+ga0f3870"})
		if code != http.StatusOK || body["accepted"] != true {
			t.Fatalf("status %d, %v", code, body)
		}
		if got := asked(); len(got) != 1 || got[0] != "edge:"+hubCommit {
			t.Errorf("the device was asked for %v", got)
		}
	})
	t.Run("not published is a 409 with the reason", func(t *testing.T) {
		withEdgeResolution(t, unpublished(upgrade.EdgeCIFailed))
		_, asked := edgeDevice(t, "edge-api-2", 16, edgeCaps)
		code, body := postUpgrade(t, dir, "edge-api-2", map[string]any{"target_version": "edge:a0f3870"})
		if code != http.StatusConflict || !strings.Contains(errorText(body), "CI failed") {
			t.Fatalf("status %d, %q", code, errorText(body))
		}
		if len(asked()) != 0 {
			t.Error("the device was asked anyway")
		}
	})
	t.Run("a stable device is never sent main", func(t *testing.T) {
		withEdgeResolution(t, published(17))
		_, asked := edgeDevice(t, "edge-api-3", 16, remote.AgentCapabilities{UpdateChannel: "stable", RemoteUpgrade: true})
		code, body := postUpgrade(t, dir, "edge-api-3", map[string]any{"target_version": "edge:" + hubCommit, "force": true})
		if code != http.StatusConflict || !strings.Contains(errorText(body), "the hub cannot") {
			t.Fatalf("status %d, %q", code, errorText(body))
		}
		code, _ = postUpgrade(t, dir, "edge-api-3", map[string]any{"target_version": "dev+ga0f3870"})
		if code != http.StatusBadRequest {
			t.Errorf("the hub's version for a stable device: %d, want 400", code)
		}
		if len(asked()) != 0 {
			t.Error("the device was asked anyway")
		}
	})
	t.Run("never lowers the protocol", func(t *testing.T) {
		withEdgeResolution(t, published(16))
		_, asked := edgeDevice(t, "edge-api-4", 17, edgeCaps)
		code, body := postUpgrade(t, dir, "edge-api-4", map[string]any{"target_version": "edge:" + hubCommit})
		if code != http.StatusConflict || !strings.Contains(errorText(body), "speaks v16") {
			t.Fatalf("status %d, %q", code, errorText(body))
		}
		if len(asked()) != 0 {
			t.Error("the device was asked anyway")
		}
	})
}

// TestEdgeBuildCacheSpendsFewLookups: GitHub's unauthenticated API allows
// sixty requests an hour, so a published answer is reused for ten minutes, a
// pending one for five, and a failure to ask not at all.
func TestEdgeBuildCacheSpendsFewLookups(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	status := upgrade.EdgeCIRunning
	var commits []string
	calls := withEdgeResolution(t, func(version, commit string) upgrade.EdgeBuild {
		commits = append(commits, commit)
		b := unpublished(status)(version, commit)
		if status == upgrade.EdgePublished {
			b = published(17)(version, commit)
		}
		if status == upgrade.EdgeUnknown {
			b.Err = errors.New("network")
		}
		return b
	})
	c := hubEdgeCache
	c.now = func() time.Time { return now }
	ctx := context.Background()

	c.get(ctx, "dev+ga0f3870")
	c.get(ctx, "dev+ga0f3870")
	if *calls != 1 {
		t.Fatalf("a pending answer was not reused: %d lookups", *calls)
	}
	now = now.Add(edgePendingTTL)
	status = upgrade.EdgePublished
	if b := c.get(ctx, "dev+ga0f3870"); !b.Published() || *calls != 2 {
		t.Fatalf("a stale pending answer was not refreshed: %+v after %d lookups", b, *calls)
	}
	if commits[1] != hubCommit {
		t.Errorf("the full commit was looked up again: second lookup was given %q", commits[1])
	}
	now = now.Add(latestReleaseTTL - time.Second)
	c.get(ctx, "dev+ga0f3870")
	if *calls != 2 {
		t.Errorf("a published answer was not reused for %s", latestReleaseTTL)
	}
	now = now.Add(time.Second)
	status = upgrade.EdgeUnknown
	c.get(ctx, "dev+ga0f3870")
	c.get(ctx, "dev+ga0f3870")
	if *calls != 4 {
		t.Errorf("a failure to ask was cached: %d lookups, want 4", *calls)
	}
}
