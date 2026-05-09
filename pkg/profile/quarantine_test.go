package profile_test

// Regression tests for the corrupt-file quarantine path in
// profile.LoadProfiles.
//
// Before the fix a malformed ~/.cloop/profiles.yaml (zero-byte from a torn
// pre-atomicfile write, schema drift, or a manual edit gone wrong) caused
// every Load to return the yaml.Unmarshal error. That bricked every
// profile-aware command (`cloop run --profile`, `cloop profile list`,
// `cloop profile use`) host-wide because the registry is global. Worse,
// since profiles store API keys, "delete and start over" cost the user
// their credentials. Now Load quarantines the bad bytes aside and returns
// an empty slice, surfacing "no profiles configured" — the user can
// re-create profiles, and the bad bytes survive in the quarantine sibling
// for forensic recovery of credentials.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/profile"
)

func TestLoadProfiles_CorruptFileQuarantined(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, ".cloop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, "profiles.yaml")
	// Mid-document garbage — exactly the shape a torn pre-atomicfile write
	// would produce (yaml.Marshal cut off mid-stream).
	if err := os.WriteFile(path, []byte("profiles:\n  - name: dev\n    provider: \x00\x00\x00not-yaml"), 0o600); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}

	got, err := profile.LoadProfiles()
	if err != nil {
		t.Fatalf("LoadProfiles on corrupt file should not return an error, got: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("LoadProfiles on corrupt file should return empty slice, got: %+v", got)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected corrupt %s to be moved aside, stat err = %v", path, err)
	}
	entries, _ := os.ReadDir(dir)
	found := false
	for _, e := range entries {
		if strings.Contains(e.Name(), ".corrupt-") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a .corrupt-* sibling preserving the bad bytes, dir contents: %v", entries)
	}
}

func TestLoadProfiles_RecoversAfterQuarantine(t *testing.T) {
	// Confirms the user-visible recovery flow: corrupt → Load returns empty
	// → SaveProfiles succeeds → next Load returns the freshly-saved data.
	// Without quarantine, SaveProfiles would still succeed but Load would
	// keep failing on the leftover file (Save replaces, but only if the
	// caller got past Load first — many callers do read-modify-write).
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, ".cloop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, "profiles.yaml")
	if err := os.WriteFile(path, []byte("\x00\x00not-yaml"), 0o600); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}

	// First load: quarantine + empty.
	if _, err := profile.LoadProfiles(); err != nil {
		t.Fatalf("first Load: %v", err)
	}

	// Upsert is the typical recovery path.
	if err := profile.Upsert(profile.Profile{Name: "dev", Provider: "anthropic"}); err != nil {
		t.Fatalf("Upsert after quarantine: %v", err)
	}

	got, err := profile.LoadProfiles()
	if err != nil {
		t.Fatalf("Load after Upsert: %v", err)
	}
	if len(got) != 1 || got[0].Name != "dev" {
		t.Errorf("expected single 'dev' profile after recovery, got: %+v", got)
	}
}
