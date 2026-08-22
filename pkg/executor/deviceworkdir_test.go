package executor

// Tests for DeviceWorkDir — the translation that makes a hub path mean
// something on a machine that is not the hub.
//
// The bug these pin down was found by the docker-compose end-to-end stack and
// by nothing else: every dispatch from a hub to a remote agent enrolled with a
// --workdir-root failed with "workdir escapes agent root", because the hub sent
// its own absolute project path and the agent — correctly — refused it.

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDeviceWorkDir_AbsolutePathBecomesOneRelativeComponent(t *testing.T) {
	got := DeviceWorkDir("/var/lib/cloop/projects/api")

	if filepath.IsAbs(got) {
		t.Fatalf("DeviceWorkDir returned an absolute path %q; an agent rejects those", got)
	}
	if strings.ContainsRune(got, filepath.Separator) {
		t.Errorf("DeviceWorkDir returned %q, which is more than one path component", got)
	}
	if !strings.HasPrefix(got, "api-") {
		t.Errorf("DeviceWorkDir returned %q; the base name should survive so an operator "+
			"can recognise the directory on the device", got)
	}
}

func TestDeviceWorkDir_IsStableAcrossCalls(t *testing.T) {
	// Not cosmetic: a device handed a fresh directory each run re-clones the
	// repository every run.
	const path = "/var/lib/cloop/projects/api"
	if a, b := DeviceWorkDir(path), DeviceWorkDir(path); a != b {
		t.Errorf("DeviceWorkDir is not stable: %q then %q", a, b)
	}
}

func TestDeviceWorkDir_DistinctPathsDoNotCollide(t *testing.T) {
	// Two projects can share a base name. If they collided on the device they
	// would pull each other's history into one working tree.
	a := DeviceWorkDir("/srv/team-one/api")
	b := DeviceWorkDir("/srv/team-two/api")
	if a == b {
		t.Errorf("two different projects both mapped to %q", a)
	}
}

func TestDeviceWorkDir_TrailingSlashesAndDotsNormalize(t *testing.T) {
	want := DeviceWorkDir("/srv/api")
	for _, variant := range []string{"/srv/api/", "/srv/./api", "/srv/x/../api"} {
		if got := DeviceWorkDir(variant); got != want {
			t.Errorf("DeviceWorkDir(%q) = %q, want %q — the same directory must map "+
				"to the same device path however it is spelled", variant, got, want)
		}
	}
}

func TestDeviceWorkDir_RelativeAndEmptyPassThrough(t *testing.T) {
	// A relative path is already device-relative: it is what the protocol's own
	// tests send and what a caller that knows the device's layout would send.
	for _, in := range []string{"", "myproject", "nested/project"} {
		if got := DeviceWorkDir(in); got != in {
			t.Errorf("DeviceWorkDir(%q) = %q, want it unchanged", in, got)
		}
	}
}

// TestDeviceWorkDir_CannotProduceATraversal: the derived name is fed to an
// agent that joins it onto its root, so it must never be able to climb out —
// even from a path made of nothing but dots.
func TestDeviceWorkDir_CannotProduceATraversal(t *testing.T) {
	hostile := []string{
		"/../../etc",
		"/srv/..",
		"/srv/../../root/.ssh",
		"/srv/" + strings.Repeat("a", 300),
		"/srv/pro ject;rm -rf /",
	}
	for _, in := range hostile {
		got := DeviceWorkDir(in)
		if got == "" {
			t.Errorf("DeviceWorkDir(%q) returned empty, which would land on the agent root", in)
			continue
		}
		if strings.ContainsRune(got, filepath.Separator) || got == "." || got == ".." {
			t.Errorf("DeviceWorkDir(%q) = %q, which is not a single safe component", in, got)
		}
		if joined := filepath.Join("/root", got); !strings.HasPrefix(joined, "/root/") {
			t.Errorf("DeviceWorkDir(%q) = %q escapes when joined: %q", in, got, joined)
		}
	}
}
