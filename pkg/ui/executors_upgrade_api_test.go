package ui

// executors_upgrade_api_test.go holds the Upgrade button's REST route to what
// Task 20371 changed: "latest" is resolved to a concrete tag before the device
// is asked, a target that would lower the device's protocol — or is not a
// release at all — is refused with a 4xx and the reason, and what is sound is
// still sent.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// upgradeDevice registers a connected device whose agent advertises protocol
// and answers upgrade frames by accepting them, and returns the targets it was
// asked for.
func upgradeDevice(t *testing.T, id string, protocol int) func() []string {
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
	end := connectAnswering(t, ex, protocol, "dev+g47e68a9", func(conn remote.Conn, f remote.Frame) {
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
			Accepted: true, FromVersion: "dev+g47e68a9", TargetVersion: p.TargetVersion,
		})
		if err == nil {
			_ = conn.WriteFrame(context.Background(), reply)
		}
	})
	t.Cleanup(end)
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), asked...)
	}
}

// withLatestRelease stubs the lookup of "latest", which must never reach
// GitHub from a test.
func withLatestRelease(t *testing.T, tag string, err error) {
	t.Helper()
	prev := latestRelease
	latestRelease = func(context.Context) (string, error) { return tag, err }
	t.Cleanup(func() { latestRelease = prev })
}

func postUpgrade(t *testing.T, dir, id string, body map[string]any) (int, map[string]any) {
	t.Helper()
	ts := newTestServer(t, dir, nil)
	code, raw := virtualDo(t, ts, http.MethodPost, "/api/executors/"+id+"/upgrade", body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return code, out
}

func errorText(body map[string]any) string {
	s, _ := body["error"].(string)
	return s
}

// TestExecutorUpgrade_RefusesALowerProtocol is the reference deployment's
// button press: an unreleased hub, a device speaking v14, and "latest" — which
// GitHub says is v0.0.4, speaking v13. 409, the helper's explanation, and no
// frame sent.
func TestExecutorUpgrade_RefusesALowerProtocol(t *testing.T) {
	withHubVersion(t, "dev+g8b418e2")
	withLatestRelease(t, "v0.0.4", nil)
	dir := setupProjectDir(t, "upgrade refusals", nil)
	asked := upgradeDevice(t, "sgx-upgrade-1", 14)

	for _, target := range []string{"", "latest", "v0.0.4"} {
		code, body := postUpgrade(t, dir, "sgx-upgrade-1", map[string]any{"target_version": target})
		if code != http.StatusConflict {
			t.Fatalf("target %q: status %d (%v), want 409", target, code, body)
		}
		want := executor.ProtocolDrop("agent sgx-upgrade-1 (sgx)", 14, "v0.0.4", 13)
		if !strings.Contains(errorText(body), want) {
			t.Errorf("target %q: error = %q\nwant it to carry %q", target, errorText(body), want)
		}
	}
	if got := asked(); len(got) != 0 {
		t.Errorf("the device was asked to install %v", got)
	}
}

// TestExecutorUpgrade_RefusesANonRelease: the old dialog's prefill on an
// unreleased hub, sent as-is. 400: there is no release by that name.
func TestExecutorUpgrade_RefusesANonRelease(t *testing.T) {
	withHubVersion(t, "dev+g8b418e2")
	withLatestRelease(t, "", errors.New("no network in a test"))
	dir := setupProjectDir(t, "upgrade refusals", nil)
	asked := upgradeDevice(t, "sgx-upgrade-2", 14)

	code, body := postUpgrade(t, dir, "sgx-upgrade-2", map[string]any{"target_version": "dev+g8b418e2"})
	if code != http.StatusBadRequest {
		t.Fatalf("status %d (%v), want 400", code, body)
	}
	if want := executor.UnpublishedTarget("agent sgx-upgrade-2 (sgx)", "dev+g8b418e2", 14); !strings.Contains(errorText(body), want) {
		t.Errorf("error = %q\nwant it to carry %q", errorText(body), want)
	}
	if got := asked(); len(got) != 0 {
		t.Errorf("the device was asked to install %v", got)
	}
}

// TestExecutorUpgrade_SendsTheResolvedTag: "latest" reaches the device as the
// tag it was checked as, so what is installed is what was judged.
func TestExecutorUpgrade_SendsTheResolvedTag(t *testing.T) {
	withHubVersion(t, "dev+g8b418e2")
	withLatestRelease(t, "v0.0.4", nil)
	dir := setupProjectDir(t, "upgrade resolution", nil)
	asked := upgradeDevice(t, "edge-upgrade-3", 12)

	code, body := postUpgrade(t, dir, "edge-upgrade-3", map[string]any{"target_version": ""})
	if code != http.StatusOK || body["accepted"] != true {
		t.Fatalf("status %d (%v), want an accepted upgrade", code, body)
	}
	if got := asked(); len(got) != 1 || got[0] != "v0.0.4" {
		t.Errorf("the device was asked for %v, want [v0.0.4] — the resolved tag, not \"latest\"", got)
	}
}

// TestExecutorUpgrade_UnresolvedLatestIsJudgedFromTheTable: with no answer
// from GitHub the hub keeps "latest" on the wire and judges it as the newest
// release it knows of — refusing for a device that would drop, sending for one
// that would not.
func TestExecutorUpgrade_UnresolvedLatestIsJudgedFromTheTable(t *testing.T) {
	withHubVersion(t, "dev+g8b418e2")
	withLatestRelease(t, "", errors.New("GitHub API returned HTTP 403"))
	dir := setupProjectDir(t, "upgrade fallback", nil)

	high := upgradeDevice(t, "sgx-upgrade-4", 14)
	code, body := postUpgrade(t, dir, "sgx-upgrade-4", map[string]any{"target_version": "latest"})
	if code != http.StatusConflict || !strings.Contains(errorText(body), "the newest published release this hub knows of") {
		t.Fatalf("status %d, error %q; want 409 saying how latest was judged", code, errorText(body))
	}
	if got := high(); len(got) != 0 {
		t.Errorf("the v14 device was asked for %v", got)
	}

	low := upgradeDevice(t, "edge-upgrade-5", 12)
	code, body = postUpgrade(t, dir, "edge-upgrade-5", map[string]any{"target_version": "latest"})
	if code != http.StatusOK {
		t.Fatalf("status %d (%v), want 200", code, body)
	}
	if got := low(); len(got) != 1 || got[0] != remote.LatestVersion {
		t.Errorf("the v12 device was asked for %v, want [latest]", got)
	}
}

// TestLatestReleaseCacheReusesAnswersNotFailures: one lookup serves a fleet's
// worth of button presses for ten minutes, and a failed one is retried by the
// next request rather than remembered.
func TestLatestReleaseCacheReusesAnswersNotFailures(t *testing.T) {
	calls := 0
	fail := true
	c := &latestReleaseCache{ttl: time.Hour, fetch: func(context.Context) (string, error) {
		calls++
		if fail {
			return "", errors.New("down")
		}
		return "v0.0.4", nil
	}}
	if _, err := c.get(context.Background()); err == nil {
		t.Fatal("a failed lookup reported success")
	}
	fail = false
	for i := 0; i < 3; i++ {
		if tag, err := c.get(context.Background()); err != nil || tag != "v0.0.4" {
			t.Fatalf("get = %q, %v", tag, err)
		}
	}
	if calls != 2 {
		t.Errorf("fetched %d times, want 2: the failure retried once, the answer reused", calls)
	}
}
