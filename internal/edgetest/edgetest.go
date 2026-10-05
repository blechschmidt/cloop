// Package edgetest stages what an edge-channel upgrade touches, for tests
// (Task 20376): a device installed as `cloop executor agent install` would
// install it — unit, drop-ins, remote-upgrade helper, binary — under a temp
// directory, and an edge release served over HTTP whose assets a stand-in
// cosign (internal/cosigntest) will accept or refuse by signer.
//
// The binaries are shell scripts that answer `cloop version` the way a real
// build does, so the installer's identify-before-replace check runs for real.
package edgetest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/internal/cosigntest"
	"github.com/blechschmidt/cloop/pkg/executor/install"
	"github.com/blechschmidt/cloop/pkg/provenance"
	"github.com/blechschmidt/cloop/pkg/upgrade"
)

// FakeCloop is a stand-in cloop binary reporting version and protocol, with a
// marker a test can read back to tell which one is installed. It reports no
// commit and no sequence: a build from before builds were stamped with their
// place on main (Task 20380).
func FakeCloop(version string, protocol int, marker string) string {
	return FakeCloopAt(version, protocol, "", 0, marker)
}

// FakeCloopAt is FakeCloop stamped with a commit and its place on main, as
// scripts/build-release.sh stamps every build since Task 20380. A zero
// sequence and an empty commit are left out of the report, as a real build
// leaves them out.
func FakeCloopAt(version string, protocol int, commit string, sequence int, marker string) string {
	stamp := ""
	if commit != "" {
		stamp += ",\"commit\":\"" + commit + "\""
	}
	if sequence > 0 {
		stamp += ",\"sequence\":" + strconv.Itoa(sequence)
	}
	return "#!/bin/sh\n" +
		"# edgetest-marker: " + marker + "\n" +
		"if [ \"$1\" = \"version\" ] && [ \"$2\" = \"--json\" ]; then\n" +
		"  printf '{\"version\":\"" + version + "\",\"protocol\":" + strconv.Itoa(protocol) + ",\"min_protocol\":1," +
		"\"os\":\"" + runtime.GOOS + "\",\"arch\":\"" + runtime.GOARCH + "\"" + stamp + "}\\n'\n" +
		"  exit 0\n" +
		"fi\n" +
		"if [ \"$1\" = \"version\" ]; then echo \"cloop " + version + "\"; exit 0; fi\n" +
		"exit 0\n"
}

// Marker reads back what FakeCloop embedded.
func Marker(body string) string {
	for _, line := range strings.Split(body, "\n") {
		if rest, ok := strings.CutPrefix(line, "# edgetest-marker: "); ok {
			return rest
		}
	}
	return ""
}

// Device is a staged install.
type Device struct {
	Spec install.Spec
}

// NewDevice stages an install running installedVersion at protocol, on
// channel, with the packet-filter grant and the remote-upgrade helper. Its
// binary carries no sequence; InstallBuild replaces it with one that does.
func NewDevice(t testing.TB, installedVersion string, protocol int, channel provenance.Channel) *Device {
	t.Helper()
	root := t.TempDir()
	spec, err := install.Spec{
		ServiceName:   "cloop-executor",
		BinaryPath:    filepath.Join(root, "usr", "local", "bin", "cloop"),
		StateDir:      filepath.Join(root, "var", "lib", "cloop-executor"),
		UnitDir:       filepath.Join(root, "etc", "systemd", "system"),
		InitDir:       filepath.Join(root, "etc", "init.d"),
		Server:        "wss://hub.example:8888/api/executors/connect",
		PacketFilter:  true,
		RemoteUpgrade: true,
		Channel:       channel,
	}.Normalize()
	if err != nil {
		t.Fatalf("edgetest: %v", err)
	}
	write := func(path, body string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(spec.BinaryPath, FakeCloop(installedVersion, protocol, "INSTALLED"), 0o755)
	write(spec.UnitPath(), install.SystemdUnit(spec), 0o644)
	write(spec.PacketFilterDropInPath(), install.PacketFilterDropIn(spec), 0o644)
	if channel == provenance.ChannelEdge {
		write(spec.ChannelDropInPath(), install.ChannelDropIn(spec, channel), 0o644)
	}
	write(spec.UpgradeHelperServicePath(), install.UpgradeHelperService(spec), 0o644)
	write(spec.UpgradeHelperPathUnitPath(), install.UpgradeHelperPathUnit(spec), 0o644)
	if err := os.MkdirAll(spec.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return &Device{Spec: spec}
}

// InstallBuild puts a binary in place as if the device ran body — for a
// device whose installed build is stamped (FakeCloopAt).
func (d *Device) InstallBuild(t testing.TB, body string) {
	t.Helper()
	if err := os.WriteFile(d.Spec.BinaryPath, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// Target answers agent.Config.InstallTarget.
func (d *Device) Target() (install.Spec, install.Output, error) {
	return d.Spec, install.OutputSystemd, nil
}

// Installed reads the marker of the binary in place, and of the one kept for
// rollback ("" when there is none).
func (d *Device) Installed(t testing.TB) (current, previous string) {
	t.Helper()
	b, err := os.ReadFile(d.Spec.BinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	prev, _ := os.ReadFile(d.Spec.BinaryPath + ".prev")
	return Marker(string(b)), Marker(string(prev))
}

// Recorder is an Installer that records the commands it would run and
// reports the service active, so an upgrade restarts and settles.
func Recorder() (*install.Installer, func() []string) {
	var mu sync.Mutex
	var cmds []string
	in := &install.Installer{
		Run: func(name string, args ...string) error {
			mu.Lock()
			defer mu.Unlock()
			cmds = append(cmds, strings.TrimSpace(name+" "+strings.Join(args, " ")))
			return nil
		},
		Logf: func(string, ...any) {},
	}
	return in, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), cmds...)
	}
}

// Release is a stand-in for the edge release's download endpoint.
type Release struct {
	URL   string
	mu    sync.Mutex
	files map[string][]byte
}

// NewRelease serves an empty edge release.
func NewRelease(t testing.TB) *Release {
	t.Helper()
	r := &Release{files: map[string][]byte{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		body, ok := r.files[strings.TrimPrefix(req.URL.Path, "/")]
		r.mu.Unlock()
		if !ok {
			http.NotFound(w, req)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	r.URL = srv.URL + "/"
	return r
}

// DefaultSequence is the place on main Publish gives a build.
const DefaultSequence = 4000

// Publish puts commit's build up, every asset signed by san, its binary a
// FakeCloopAt reporting the edge version at protocol, stamped with commit and
// DefaultSequence, with the given marker.
func (r *Release) Publish(t testing.TB, commit, san string, protocol int, marker string) upgrade.EdgeManifest {
	t.Helper()
	return r.PublishBuild(t, Build{Commit: commit, SAN: san, Protocol: protocol, Sequence: DefaultSequence,
		Marker: marker})
}

// Build is one edge build to publish.
type Build struct {
	Commit   string
	SAN      string
	Protocol int
	// Sequence is the commit's place on main. Zero publishes a build from
	// before Task 20380: a schema-1 manifest, and a binary carrying none.
	Sequence int
	Marker   string
	// Binary, when set, is the archived binary instead of the stand-in the
	// manifest describes — a validly signed manifest paired with the bytes
	// of another build.
	Binary string
}

// PublishBuild puts b up, every asset signed by b.SAN.
func (r *Release) PublishBuild(t testing.TB, b Build) upgrade.EdgeManifest {
	t.Helper()
	binary := b.Binary
	if binary == "" {
		stamped := b.Commit
		if b.Sequence <= 0 {
			stamped = ""
		}
		binary = FakeCloopAt(upgrade.EdgeVersion(b.Commit), b.Protocol, stamped, b.Sequence, b.Marker)
	}
	archive := TarGz(t, binary)
	name := upgrade.EdgeArchiveName(b.Commit, runtime.GOOS, runtime.GOARCH)
	sum := sha256.Sum256(archive)
	m := upgrade.EdgeManifest{
		Schema: upgrade.EdgeManifestSchema, Commit: b.Commit, Version: upgrade.EdgeVersion(b.Commit),
		Protocol: b.Protocol, Sequence: b.Sequence, Archives: map[string]string{name: hex.EncodeToString(sum[:])},
	}
	r.put(name, archive, b.SAN)
	// A sequenced build carries both manifests, as scripts/build-edge.sh
	// writes them: schema 2 with the sequence, and the schema-1 copy without
	// it that a device whose cloop predates sequences reads.
	legacy := m
	legacy.Schema, legacy.Sequence = 1, 0
	if b.Sequence > 0 {
		r.put(upgrade.EdgeManifestV2Name(b.Commit), mustJSON(t, m), b.SAN)
	} else {
		m = legacy
	}
	r.put(upgrade.EdgeManifestName(b.Commit), mustJSON(t, legacy), b.SAN)
	return m
}

func mustJSON(t testing.TB, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func (r *Release) put(name string, data []byte, san string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.files[name] = data
	r.files[provenance.BundleNameFor(name)] = cosigntest.Bundle(san, data)
}

// Options are the staging options that fetch from this release and verify
// with the stand-in cosign.
func (r *Release) Options(t testing.TB) upgrade.Options {
	return upgrade.Options{Verifier: &provenance.Verifier{Binary: cosigntest.Install(t)}, EdgeBaseURL: r.URL}
}

// TarGz packs a "cloop" file the way scripts/build-release.sh does.
func TarGz(t testing.TB, binary string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "./cloop", Mode: 0o755, Size: int64(len(binary))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(binary)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
