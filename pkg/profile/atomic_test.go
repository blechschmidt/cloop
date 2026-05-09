package profile_test

// Regression tests for the atomic-write + serialised-Upsert fix in profile.go.
//
// profiles.yaml is a global file (~/.cloop/profiles.yaml) shared by every
// cloop invocation, and entries can carry API keys. A torn write or a
// concurrent Upsert that drops a sibling's edit silently destroys
// credentials, so these tests pin the invariants explicitly:
//
//  1. Save → no leftover .tmp files (rename succeeded, defer cleaned up).
//  2. A reader running in parallel with a writer never sees a 0-byte or
//     malformed YAML file.
//  3. N concurrent Upserts produce N profiles — none are clobbered by the
//     load → modify → save race the mutex guards against.
//  4. The persisted file ends up at 0600 (it may contain API keys).

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/cloop/pkg/profile"
	"gopkg.in/yaml.v3"
)

func setHomeForAtomic(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	return dir
}

// TestSaveProfiles_NoLeftoverTmpFiles asserts the atomic write path renames
// (and never leaks) its .tmp staging files. A leftover .tmp file means the
// rename failed silently or the cleanup defer regressed.
func TestSaveProfiles_NoLeftoverTmpFiles(t *testing.T) {
	home := setHomeForAtomic(t)

	for i := 0; i < 8; i++ {
		err := profile.SaveProfiles([]profile.Profile{
			{Name: "p", Provider: "anthropic", APIKey: "sk-test"},
		})
		if err != nil {
			t.Fatalf("save iter %d: %v", i, err)
		}
	}

	cloopDir := filepath.Join(home, ".cloop")
	entries, err := os.ReadDir(cloopDir)
	if err != nil {
		t.Fatalf("read .cloop: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("leftover tmp file after SaveProfiles: %s", e.Name())
		}
	}
	if _, err := os.Stat(filepath.Join(cloopDir, "profiles.yaml")); err != nil {
		t.Errorf("expected profiles.yaml to exist: %v", err)
	}
}

// TestSaveProfiles_ConcurrentReaderNeverSeesPartial pits a hot writer against
// a hot reader. Without the atomic rename, the reader would observe a
// truncated YAML doc mid-write (the API-key-loss scenario this fix exists to
// prevent).
func TestSaveProfiles_ConcurrentReaderNeverSeesPartial(t *testing.T) {
	home := setHomeForAtomic(t)
	path := filepath.Join(home, ".cloop", "profiles.yaml")

	// Seed.
	seed := []profile.Profile{
		{Name: "alpha", Provider: "anthropic", APIKey: strings.Repeat("k", 256)},
		{Name: "beta", Provider: "openai", APIKey: strings.Repeat("k", 256)},
	}
	if err := profile.SaveProfiles(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const iterations = 200
	var stop atomic.Bool
	var wg sync.WaitGroup

	// Writer: keeps re-saving with growing payloads to widen the torn-write window.
	wg.Add(1)
	go func() {
		defer wg.Done()
		profs := append([]profile.Profile(nil), seed...)
		for i := 0; !stop.Load(); i++ {
			profs = append(profs, profile.Profile{
				Name:     "extra-" + strings.Repeat("x", 8),
				Provider: "anthropic",
				APIKey:   strings.Repeat("v", 256),
			})
			if err := profile.SaveProfiles(profs); err != nil {
				t.Errorf("save: %v", err)
				return
			}
		}
	}()

	// Reader: must always see a parsable YAML document.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stop.Store(true)
		for i := 0; i < iterations; i++ {
			data, err := os.ReadFile(path)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					t.Errorf("reader saw missing profiles.yaml mid-write")
					return
				}
				continue
			}
			if len(data) == 0 {
				t.Errorf("reader saw 0-byte profiles.yaml")
				return
			}
			var pf struct {
				Profiles []profile.Profile `yaml:"profiles"`
			}
			if err := yaml.Unmarshal(data, &pf); err != nil {
				t.Errorf("reader saw partial/invalid YAML: %v (len=%d)", err, len(data))
				return
			}
		}
	}()

	wg.Wait()
}

// TestUpsert_ConcurrentDoesNotLoseProfiles verifies that N goroutines each
// Upserting a uniquely-named profile end up with all N profiles persisted.
// Without the in-process mutex, two Upserts could load the same baseline,
// each append "their" profile, and the second save would overwrite the first
// — a silent data loss bug.
func TestUpsert_ConcurrentDoesNotLoseProfiles(t *testing.T) {
	setHomeForAtomic(t)

	const n = 25
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := profile.Profile{
				Name:     "p-" + strings.Repeat("x", i+1),
				Provider: "anthropic",
				APIKey:   "sk-test",
			}
			if err := profile.Upsert(p); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("upsert: %v", err)
	}

	got, err := profile.LoadProfiles()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != n {
		t.Fatalf("expected %d profiles after concurrent Upsert, got %d — load/modify/save race lost writes", n, len(got))
	}
}

// TestSaveProfiles_PermissionsAre0600 asserts the on-disk file is owner-only
// readable. profiles.yaml may contain API keys; world-readable would regress
// the security posture documented in the file header.
func TestSaveProfiles_PermissionsAre0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission semantics not enforced on Windows")
	}
	home := setHomeForAtomic(t)

	if err := profile.SaveProfiles([]profile.Profile{{Name: "p", APIKey: "sk-test"}}); err != nil {
		t.Fatalf("save: %v", err)
	}
	info, err := os.Stat(filepath.Join(home, ".cloop", "profiles.yaml"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("expected mode 0600 (owner-only — file may contain API keys), got %o", got)
	}
}
