package upgrade_test

// The parts of the rehearsal that need neither the network nor a release:
// which release it starts from, that a release is verified before anything of
// it runs and is cached by tag, and that the runbook's refusal is the guard's
// own sentence. These run wherever the test suite runs.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/cosigntest"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/provenance"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/version"
)

func TestPlanFromPicksTheReleaseToRehearseFrom(t *testing.T) {
	table := []version.Release{{Tag: "v0.0.4"}, {Tag: "v0.0.5"}, {Tag: "v0.0.6"}, {Tag: "v0.0.7"}}
	latest := func(tag string, err error) func() (string, error) {
		return func() (string, error) { return tag, err }
	}
	unreachable := fmt.Errorf("%w: https://github.com/blechschmidt/cloop/releases/latest: dial tcp: no route", errNoNetwork)
	for _, tc := range []struct {
		name, pinned, own string
		latest            func() (string, error)
		want, wantErr     string
	}{
		{name: "a build of main starts from the latest release", latest: latest("v0.0.7", nil), want: "v0.0.7"},
		{name: "a pin wins", pinned: "v0.0.5", own: "v0.0.7", latest: latest("v0.0.7", nil), want: "v0.0.5"},
		{name: "a pin must be a release", pinned: "dev+gabc", wantErr: "names no release tag"},
		{name: "a release starts from the one before it, not from itself",
			own: "v0.0.7", latest: latest("v0.0.7", nil), want: "v0.0.6"},
		{name: "a release not yet in the table starts from the newest before it",
			own: "v0.0.8", latest: latest("v0.0.7", nil), want: "v0.0.7"},
		{name: "a re-run of an older tag's workflow ignores a later latest",
			own: "v0.0.6", latest: latest("v0.0.7", nil), want: "v0.0.5"},
		{name: "the first release has nothing to rehearse from", own: "v0.0.4", wantErr: "lists no release before it"},
		{name: "an unreachable GitHub is reported as such", latest: latest("", unreachable), wantErr: "no network"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.latest == nil {
				tc.latest = func() (string, error) { t.Fatal("latest was resolved"); return "", nil }
			}
			got, err := planFrom(tc.pinned, tc.own, table, tc.latest)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("planFrom = %+v, %v; want an error saying %q", got, err, tc.wantErr)
				}
				return
			}
			if err != nil || got.tag != tc.want {
				t.Fatalf("planFrom = %+v, %v; want %s", got, err, tc.want)
			}
		})
	}
	if !isNoNetwork(fmt.Errorf("obtain: %w", unreachable)) {
		t.Error("a wrapped errNoNetwork is not recognised, so an offline run would fail rather than skip")
	}
}

// mirror serves releases the way GitHub does: releases/latest redirects to a
// tag, and each asset downloads from releases/download/<tag>/<name>.
type mirror struct {
	srv      *httptest.Server
	latest   string
	assets   map[string][]byte // "<tag>/<name>"
	requests atomic.Int64
}

func newMirror(t *testing.T) *mirror {
	m := &mirror{assets: map[string][]byte{}}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.requests.Add(1)
		if r.URL.Path == "/releases/latest" {
			http.Redirect(w, r, "/releases/tag/"+m.latest, http.StatusFound)
			return
		}
		if data, ok := m.assets[strings.TrimPrefix(r.URL.Path, "/releases/download/")]; ok {
			_, _ = w.Write(data)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mirror) source() releaseSource {
	return releaseSource{base: m.srv.URL, client: &http.Client{Timeout: 10 * time.Second}}
}

// publish puts a release on the mirror: an archive holding a stand-in cloop
// that reports reports as its version, signed as signer, with its checksum.
func (m *mirror) publish(t *testing.T, tag, reports, signer string) {
	t.Helper()
	script := fmt.Sprintf("#!/bin/sh\necho '{\"version\":%q,\"protocol\":26,\"min_protocol\":1,\"commit\":\"c0ffee\",\"sequence\":1170,\"schema\":82}'\n", reports)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct {
		name string
		body string
		mode int64
	}{{"./README.md", "a release\n", 0o644}, {"./cloop", script, 0o755}} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: f.mode, Size: int64(len(f.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	archive := buf.Bytes()
	sum := sha256.Sum256(archive)
	m.assets[tag+"/"+releaseAsset] = archive
	m.assets[tag+"/"+provenance.BundleNameFor(releaseAsset)] = cosigntest.Bundle(signer, archive)
	m.assets[tag+"/"+checksumsAsset] = []byte(hex.EncodeToString(sum[:]) + "  " + releaseAsset + "\n")
}

func TestAReleaseIsVerifiedBeforeItRunsAndCachedByTag(t *testing.T) {
	m := newMirror(t)
	m.latest = "v9.9.9"
	m.publish(t, "v9.9.9", "v9.9.9", cosigntest.Release)
	verifier := &provenance.Verifier{Binary: cosigntest.Install(t)}
	cache := t.TempDir()
	ctx := context.Background()
	var logged []string
	logf := func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }

	tag, err := m.source().latestTag(ctx)
	if err != nil || tag != "v9.9.9" {
		t.Fatalf("latestTag = %q, %v; want v9.9.9", tag, err)
	}

	first, err := obtainRelease(ctx, m.source(), cache, "v9.9.9", t.TempDir(), verifier, logf)
	if err != nil {
		t.Fatalf("first obtain: %v", err)
	}
	if first.cached || first.info.Version != "v9.9.9" || first.info.Schema != 82 {
		t.Fatalf("first obtain = %+v; want a download reporting v9.9.9 at schema 82", first)
	}
	if fi, err := os.Stat(first.bin); err != nil || fi.Mode().Perm()&0o100 == 0 {
		t.Fatalf("the extracted binary %s is not executable: %v", first.bin, err)
	}

	served := m.requests.Load()
	second, err := obtainRelease(ctx, m.source(), cache, "v9.9.9", t.TempDir(), verifier, logf)
	if err != nil || !second.cached {
		t.Fatalf("second obtain = %+v, %v; want it from the cache", second, err)
	}
	if n := m.requests.Load() - served; n != 0 {
		t.Fatalf("a cached release was downloaded again (%d requests)", n)
	}

	// A cached archive that no longer verifies is dropped and fetched again,
	// and says so.
	archive := filepath.Join(cache, "v9.9.9", releaseAsset)
	f, err := os.OpenFile(archive, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte("tampered"))
	_ = f.Close()
	third, err := obtainRelease(ctx, m.source(), cache, "v9.9.9", t.TempDir(), verifier, logf)
	if err != nil || third.cached {
		t.Fatalf("obtain after tampering = %+v, %v; want a fresh, verified download", third, err)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "failed verification") {
		t.Fatalf("a cache entry that failed verification was replaced without a word: %q", logged)
	}

	// Signed by the edge workflow, not the release one: refused, and nothing
	// is extracted to run.
	m.publish(t, "v9.9.8", "v9.9.8", cosigntest.Edge)
	dest := t.TempDir()
	if _, err := obtainRelease(ctx, m.source(), cache, "v9.9.8", dest, verifier, logf); err == nil ||
		!strings.Contains(err.Error(), "not signed by cloop's release workflow") || isNoNetwork(err) {
		t.Fatalf("an edge-signed archive = %v; want refused as unsigned by the release workflow", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "cloop")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a binary from an archive that failed verification was extracted: %v", err)
	}

	// A signed archive whose binary is another release.
	m.publish(t, "v9.9.7", "v9.9.6", cosigntest.Release)
	if _, err := obtainRelease(ctx, m.source(), cache, "v9.9.7", t.TempDir(), verifier, logf); err == nil ||
		!strings.Contains(err.Error(), `reports version "v9.9.6"`) {
		t.Fatalf("an archive whose binary reports another version = %v; want refused", err)
	}

	// A tag that is not one is never a path.
	if _, err := obtainRelease(ctx, m.source(), cache, "../v9.9.9", t.TempDir(), verifier, logf); err == nil {
		t.Fatal("a tag naming a path outside the cache was accepted")
	}

	// cosign missing fails closed, naming the remedy.
	if _, err := obtainRelease(ctx, m.source(), cache, "v9.9.9", t.TempDir(),
		&provenance.Verifier{Binary: filepath.Join(t.TempDir(), "no-cosign")}, logf); err == nil ||
		!strings.Contains(err.Error(), cosignEnv) {
		t.Fatalf("obtain without cosign = %v; want a refusal naming %s", err, cosignEnv)
	}

	// Offline: a host that cannot be reached skips, it does not fail.
	m.srv.Close()
	if _, err := obtainRelease(ctx, m.source(), t.TempDir(), "v9.9.9", t.TempDir(), verifier, logf); !isNoNetwork(err) {
		t.Fatalf("obtain from an unreachable host = %v; want errNoNetwork", err)
	}
	if _, err := m.source().latestTag(ctx); !isNoNetwork(err) {
		t.Fatalf("latestTag from an unreachable host = %v; want errNoNetwork", err)
	}
}

// The refusals the runbook shows are the guard's own sentences, as `cloop ui`
// and every other command print them: the rehearsal holds the release to the
// runbook, and this holds the runbook to the build it ships in, without a
// release or the network.
func TestTheRunbookShowsTheSchemaGuardsRefusals(t *testing.T) {
	tmpl := readRunbookRefusals(t)
	for _, verdict := range []statedb.MigrationCompat{statedb.CompatBreaking, statedb.CompatUnknown, "from-the-future"} {
		name := string(verdict)
		if name == "" {
			name = "unclassified"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ".cloop", "state.db")
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			db, err := statedb.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			_ = db.Close()
			conn, err := statedb.OpenConn(path, statedb.ReadWrite)
			if err != nil {
				t.Fatal(err)
			}
			at := time.Date(2026, 10, 27, 9, 14, 22, 0, time.UTC)
			var v int
			if err := conn.QueryRow(`SELECT MAX(version) + 1 FROM schema_migrations`).Scan(&v); err != nil {
				t.Fatal(err)
			}
			mig := fmt.Sprintf("%04d_widget_policy.sql", v)
			if _, err := conn.Exec(`INSERT INTO schema_migrations (version, applied_at, name, applied_by, compat)
				VALUES (?, ?, ?, 'v9.9.9', ?)`, v, at.Format(time.RFC3339), mig, string(verdict)); err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()

			_, statusErr := statedb.Open(path)
			node, uiErr := hubcluster.Join(hubcluster.Options{DBPath: path})
			if node != nil {
				node.Close()
			}
			for _, got := range []struct {
				command string
				err     error
			}{{"status", statusErr}, {"ui", uiErr}} {
				if got.err == nil {
					t.Fatalf("`cloop %s` would open a database migrated past it", got.command)
				}
				ex := tmpl[got.command]
				want, err := ex.pattern(path, fmt.Sprint(v), fmt.Sprint(v-1), "v9.9.9", mig, at.Format(time.RFC3339), []string{mig})
				if err != nil {
					t.Fatal(err)
				}
				if line := "Error: " + got.err.Error(); !want.MatchString(normalizeSpace(line)) {
					t.Errorf("`cloop %s` refuses with a sentence the runbook does not show.\nrunbook: %s\nbuild:   %s",
						got.command, ex.text, line)
				}
			}
		})
	}
}
