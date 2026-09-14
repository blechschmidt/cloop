package ui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/version"
)

// TestVersionEndpointReportsTheRunningBuild is the round trip: the route is
// registered, it answers, and it carries the fields the dashboard renders.
func TestVersionEndpointReportsTheRunningBuild(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	body := apiGET(t, ts, "/api/version")

	// Fields with no sensible zero value: a dashboard rendering "undefined"
	// for any of these is worse than no panel at all.
	for _, key := range []string{"version", "go", "os", "arch", "started_at", "build_id"} {
		if v, ok := body[key]; !ok || v == "" {
			t.Errorf("/api/version is missing %q (got %v)", key, v)
		}
	}
	if _, ok := body["identified"].(bool); !ok {
		t.Errorf("identified = %v, want a bool — the frontend branches on it", body["identified"])
	}
	// The test binary speaks some protocol; zero would mean the constant was
	// not wired through.
	if p, _ := body["protocol"].(float64); p <= 0 {
		t.Errorf("protocol = %v, want the real executor protocol version", body["protocol"])
	}
}

// TestVersionEndpointMatchesTheVersionCommand pins the two surfaces together.
// `cloop version` and the dashboard answering differently about the same
// process is the kind of discrepancy that costs an hour during an incident.
func TestVersionEndpointMatchesTheVersionCommand(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")

	got := srv.buildInfo(time.Now())
	if got.Version != version.String() {
		t.Errorf("/api/version reports %q but version.String() is %q",
			got.Version, version.String())
	}
	if got.Identified != (version.String() != version.DevVersion) {
		t.Errorf("identified=%v disagrees with version %q", got.Identified, got.Version)
	}
}

// TestVersionAgesAreServerComputed: the browser must not have to subtract
// timestamps. A client clock that is wrong — and on a kiosk or a wearable it
// often is — would otherwise render a fresh deploy as days old and destroy the
// credibility of the one panel whose job is to be believed.
func TestVersionAgesAreServerComputed(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")

	got := srv.buildInfo(processStart.Add(90 * time.Second))
	if got.UptimeSeconds != 90 {
		t.Errorf("uptime_seconds = %d, want 90", got.UptimeSeconds)
	}

	// Ages are derived, not echoed: an mtime in the future must clamp to zero
	// rather than render as a negative age.
	past := srv.buildInfo(processStart.Add(-time.Hour))
	if past.UptimeSeconds < 0 {
		t.Errorf("uptime_seconds = %d, want no negative age", past.UptimeSeconds)
	}
	if past.BuildAgeSeconds != nil && *past.BuildAgeSeconds < 0 {
		t.Errorf("build_age_seconds = %d, want no negative age", *past.BuildAgeSeconds)
	}
}

// TestBuildFingerprintDistinguishesDeploys is the core of the stale-tab check.
//
// The fingerprint has to move for every way a deploy can differ — including
// the case the version string cannot express, where an unstamped build's
// frontend changed but it still calls itself "dev". And it must *not* move for
// a restart of the same build, or the dashboard would nag users to reload for
// a byte-identical page and teach them to ignore the prompt that matters.
func TestBuildFingerprintDistinguishesDeploys(t *testing.T) {
	base := version.BuildInfo{
		Version:  "dev",
		Revision: "1a2b3c4d",
		BuiltAt:  time.Date(2026, 9, 14, 4, 43, 0, 0, time.UTC),
	}
	const assets = `"abc123"`
	ref := buildFingerprint(base, assets)

	for _, tc := range []struct {
		name   string
		mutate func(*version.BuildInfo)
		assets string
	}{
		{"a new release", func(b *version.BuildInfo) { b.Version = "v1.2.3" }, assets},
		{"a new revision", func(b *version.BuildInfo) { b.Revision = "9f8e7d6c" }, assets},
		{"a dirty tree", func(b *version.BuildInfo) { b.Modified = true }, assets},
		{"a rebuild of the same source", func(b *version.BuildInfo) {
			b.BuiltAt = b.BuiltAt.Add(24 * time.Hour)
		}, assets},
		// The case the version fields miss entirely.
		{"unstamped build, changed frontend", func(*version.BuildInfo) {}, `"def456"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := base
			tc.mutate(&mutated)
			if got := buildFingerprint(mutated, tc.assets); got == ref {
				t.Errorf("fingerprint did not change for %s — a stale page would "+
					"never be told to reload", tc.name)
			}
		})
	}

	t.Run("same build is stable", func(t *testing.T) {
		if got := buildFingerprint(base, assets); got != ref {
			t.Errorf("fingerprint = %q then %q for an unchanged build — every "+
				"reconnect would prompt a pointless reload", ref, got)
		}
	})
}

// TestVersionEndpointLeaksNoProjectData: the route is public (authenticated but
// ungated), so its payload must stay a property of the binary. A field that
// named a project or a user here would be readable by a caller whose role
// grants nothing.
func TestVersionEndpointLeaksNoProjectData(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/api/version")
	if err != nil {
		t.Fatalf("GET /api/version: %v", err)
	}
	defer resp.Body.Close()

	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// An allowlist, not a denylist: a field added later is caught here and has
	// to be justified rather than shipped by accident.
	allowed := map[string]bool{
		"version": true, "identified": true, "revision": true, "modified": true,
		"built_at": true, "built_at_source": true, "build_age_seconds": true,
		"started_at": true, "uptime_seconds": true, "go": true, "os": true,
		"arch": true, "protocol": true, "min_protocol": true, "build_id": true,
	}
	for key := range raw {
		if !allowed[key] {
			t.Errorf("/api/version returned unexpected field %q — this route is "+
				"reachable by any authenticated caller regardless of role, so every "+
				"field must be a property of the binary, not of a project or user", key)
		}
	}
}
