package session_test

// Regression tests for the atomic-write + serialised-write fix in session.go.
//
// .cloop/active_session is the single small file that routes every
// downstream command (state.Load, statedb.Open, …) to the right session
// directory. A torn write would leave a 0-byte file and ActiveName would
// silently fall back to the default session, hiding the user's real working
// state. session.json is the per-session metadata file — a torn write makes
// the session "disappear" from `cloop session list`.
//
// These tests pin:
//  1. Switch / writeMeta produce no leftover .tmp files.
//  2. A reader running in parallel with a writer never sees a 0-byte file.
//  3. N concurrent New("name-i") calls each succeed and produce N distinct
//     session directories — verifying the in-process mutex prevents the
//     stat-then-mkdir race.

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/cloop/pkg/session"
)

// TestSwitch_NoLeftoverTmpFiles asserts the atomic write path renames its
// .tmp staging files instead of leaking them next to active_session.
func TestSwitch_NoLeftoverTmpFiles(t *testing.T) {
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Need an existing session for Switch(name) to validate against.
	if _, err := session.New(work, "primary", ""); err != nil {
		t.Fatalf("new: %v", err)
	}

	for i := 0; i < 8; i++ {
		if err := session.Switch(work, "primary"); err != nil {
			t.Fatalf("switch iter %d: %v", i, err)
		}
	}

	entries, err := os.ReadDir(filepath.Join(work, ".cloop"))
	if err != nil {
		t.Fatalf("read .cloop: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("leftover tmp file after Switch: %s", e.Name())
		}
	}
}

// TestSwitch_ConcurrentReaderNeverSeesZeroByte runs an ActiveName reader in a
// hot loop against a Switch writer. Without the atomic rename the reader
// would observe a freshly truncated file in the os.WriteFile→write window
// and resolve the active session to the empty string.
func TestSwitch_ConcurrentReaderNeverSeesZeroByte(t *testing.T) {
	work := t.TempDir()
	if _, err := session.New(work, "alpha", ""); err != nil {
		t.Fatalf("new alpha: %v", err)
	}
	if _, err := session.New(work, "beta", ""); err != nil {
		t.Fatalf("new beta: %v", err)
	}

	const iterations = 300
	var stop atomic.Bool
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		toggle := false
		for i := 0; !stop.Load(); i++ {
			name := "alpha"
			if toggle {
				name = "beta"
			}
			toggle = !toggle
			if err := session.Switch(work, name); err != nil {
				t.Errorf("switch: %v", err)
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stop.Store(true)
		path := filepath.Join(work, ".cloop", "active_session")
		for i := 0; i < iterations; i++ {
			data, err := os.ReadFile(path)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					// Acceptable: writer may not have run yet on first ticks.
					continue
				}
				t.Errorf("read active_session: %v", err)
				return
			}
			s := strings.TrimSpace(string(data))
			if s != "alpha" && s != "beta" {
				t.Errorf("reader saw torn active_session contents: %q (len=%d)", string(data), len(data))
				return
			}
		}
	}()

	wg.Wait()
}

// TestNew_ConcurrentDistinctNamesAllSucceed verifies that N goroutines each
// creating a uniquely-named session all succeed and produce N distinct
// directories. The pre-fix code did stat() then MkdirAll() with no mutex, so
// two New("foo") calls could both pass the stat check; even with distinct
// names there was no need for serialisation, but the mutex now also guards
// the writeMeta atomic write underneath.
func TestNew_ConcurrentDistinctNamesAllSucceed(t *testing.T) {
	work := t.TempDir()

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := "s-" + strings.Repeat("x", i+1)
			if _, err := session.New(work, name, ""); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("new: %v", err)
	}

	got, err := session.List(work)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != n {
		t.Fatalf("expected %d sessions after concurrent New, got %d", n, len(got))
	}
}

// TestList_QuarantinesCorruptSessionMeta verifies that a torn or hand-edited
// session.json no longer makes the session permanently un-loadable. The bad
// bytes are renamed aside as a .corrupt-* sibling and List skips that session
// in its return value (load() returns an error which List treats as "skip
// this entry"). The state.db that lives next to session.json is left alone —
// only the metadata file is quarantined, so the user's actual session data
// remains recoverable.
func TestList_QuarantinesCorruptSessionMeta(t *testing.T) {
	work := t.TempDir()

	if _, err := session.New(work, "good", ""); err != nil {
		t.Fatalf("new good: %v", err)
	}
	if _, err := session.New(work, "broken", ""); err != nil {
		t.Fatalf("new broken: %v", err)
	}

	brokenMeta := filepath.Join(work, ".cloop", "sessions", "broken", "session.json")
	if err := os.WriteFile(brokenMeta, []byte("{not json"), 0o644); err != nil {
		t.Fatalf("corrupt meta: %v", err)
	}

	got, err := session.List(work)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].Name != "good" {
		t.Fatalf("expected only 'good' session in list, got %+v", got)
	}

	if _, err := os.Stat(brokenMeta); !os.IsNotExist(err) {
		t.Fatalf("corrupt session.json should have been renamed away (stat err: %v)", err)
	}
	entries, err := os.ReadDir(filepath.Dir(brokenMeta))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	foundCorrupt := false
	for _, e := range entries {
		if strings.Contains(e.Name(), ".corrupt-") {
			foundCorrupt = true
			break
		}
	}
	if !foundCorrupt {
		t.Fatalf("expected a .corrupt-* sibling preserving the bad bytes; entries=%v", entries)
	}
}

// TestNew_ConcurrentSameNameOneWinsExclusively verifies the stat-then-mkdir
// invariant: when N goroutines all try to create the same session name, only
// one succeeds and the rest get "already exists" — no two ever return ok.
// Without the mutex two stat calls could both miss the directory and both
// create it; MkdirAll won't error on an existing dir, so both Goroutines
// would proceed to writeMeta and one would silently overwrite the other.
func TestNew_ConcurrentSameNameOneWinsExclusively(t *testing.T) {
	work := t.TempDir()

	const n = 16
	var wg sync.WaitGroup
	successes := atomic.Int32{}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := session.New(work, "shared", ""); err == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := successes.Load(); got != 1 {
		t.Fatalf("expected exactly 1 successful New, got %d — stat→mkdir race regressed", got)
	}
}
