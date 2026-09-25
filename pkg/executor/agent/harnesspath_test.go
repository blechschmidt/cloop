package agent

// Tests for making a per-user harness install reachable (Task 20336).
//
// These cover the half of the feature that has no visible symptom of its own.
// Installing Claude Code works; it lands in ~/.local/bin because that is where
// its official installer puts things that need no root. A systemd unit's PATH
// does not include that directory, so without the fixes here the device
// installs a harness, fails to detect it, refuses the dispatch it was trying to
// unblock, and installs it again next time.
//
// The two halves are tested separately because they fail separately, and the
// second one fails for only *some* projects: a Spec with a nil environment
// inherits the agent's PATH and works, while a Spec carrying an explicit
// environment — which is exactly what a leased credential produces — does not.
// That is a difference nobody would think to test by hand.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor/localprocess"
)

func TestNativeHarnessDirsSkipsWhatDoesNotExist(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if got := NativeHarnessDirs(); len(got) != 0 {
		t.Fatalf("NativeHarnessDirs on an empty home = %v, want none; entries that resolve to "+
			"nothing cost every exec on the device a failed stat", got)
	}

	local := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(local, 0o755); err != nil {
		t.Fatal(err)
	}
	got := NativeHarnessDirs()
	if len(got) != 1 || got[0] != local {
		t.Fatalf("NativeHarnessDirs = %v, want exactly [%s]", got, local)
	}
}

// TestEnsureHarnessPathIsIdempotent matters because this runs on every
// capability report and after every install, for the life of a process that is
// meant to stay up for months. A version that appended unconditionally would
// grow PATH without bound.
func TestEnsureHarnessPathIsIdempotent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", "/usr/bin:/bin")

	local := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(local, 0o755); err != nil {
		t.Fatal(err)
	}

	if added := EnsureHarnessPath(); len(added) != 1 || added[0] != local {
		t.Fatalf("first call added %v, want [%s]", added, local)
	}
	first := os.Getenv("PATH")
	if !strings.HasPrefix(first, local+string(os.PathListSeparator)) {
		t.Errorf("PATH = %q, want %s first so a user's own install wins over a stale system "+
			"copy", first, local)
	}

	if added := EnsureHarnessPath(); len(added) != 0 {
		t.Errorf("second call added %v, want nothing", added)
	}
	if got := os.Getenv("PATH"); got != first {
		t.Errorf("PATH changed on the second call: %q -> %q", first, got)
	}
}

func TestWithHarnessPath(t *testing.T) {
	dirs := []string{"/home/edge/.local/bin"}

	t.Run("a nil environment is left alone", func(t *testing.T) {
		// nil means "inherit", and the agent's own PATH has already been
		// fixed. Materialising the full environment here to edit one variable
		// would convert an inheriting Spec into an explicit one and hand the
		// payload everything the agent holds — its enrollment credential
		// included.
		if got := withHarnessPath(nil, dirs, "/usr/bin:/bin"); got != nil {
			t.Fatalf("withHarnessPath(nil) = %v, want nil", got)
		}
	})

	t.Run("an explicit PATH gains the directory", func(t *testing.T) {
		in := []string{"HOME=/work", "PATH=/usr/bin:/bin", "TOKEN=x"}
		got := withHarnessPath(in, dirs, "/agent/bin")

		want := "PATH=/home/edge/.local/bin:/usr/bin:/bin"
		if !containsEnv(got, want) {
			t.Fatalf("withHarnessPath = %v, want it to contain %q", got, want)
		}
		// Everything else has to survive untouched; this environment is a
		// credential lease.
		for _, kv := range []string{"HOME=/work", "TOKEN=x"} {
			if !containsEnv(got, kv) {
				t.Errorf("withHarnessPath dropped %q", kv)
			}
		}
		// The caller still holds the input, and executorstore persists it.
		if in[1] != "PATH=/usr/bin:/bin" {
			t.Errorf("the caller's slice was mutated: %q", in[1])
		}
	})

	t.Run("a directory already present is not duplicated", func(t *testing.T) {
		in := []string{"PATH=/home/edge/.local/bin:/usr/bin"}
		got := withHarnessPath(in, dirs, "/agent/bin")
		if got[0] != in[0] {
			t.Fatalf("withHarnessPath = %q, want it unchanged", got[0])
		}
	})

	// The case a leased credential produces, and the one Task 20336 got wrong:
	// it left this environment to localprocess's fixed floor, which has /bin
	// but not ~/.local/bin. A project holding a grant then failed with
	// `exec: "claude": executable file not found` on the device the harness
	// had just been installed on (Task 20337).
	t.Run("an explicit environment with no PATH gets the inherited one", func(t *testing.T) {
		in := []string{"HOME=/work", "CLOOP_LEASE_DIR=/dev/shm/lease"}
		got := withHarnessPath(in, dirs, "/usr/local/bin:/usr/bin:/bin")

		// The same PATH the payload would have inherited without the grant:
		// this process's own, with the harness directory in front.
		want := "PATH=/home/edge/.local/bin:/usr/local/bin:/usr/bin:/bin"
		if !containsEnv(got, want) {
			t.Fatalf("withHarnessPath = %v, want it to contain %q", got, want)
		}
		for _, kv := range in {
			if !containsEnv(got, kv) {
				t.Errorf("withHarnessPath dropped %q", kv)
			}
		}
		if len(in) != 2 {
			t.Errorf("the caller's slice was mutated: %v", in)
		}
	})

	t.Run("only PATH is inherited", func(t *testing.T) {
		// The reason nil is not materialised applies here too: the agent's
		// environment holds its enrollment credential, and a payload that
		// declared an explicit environment asked for nothing else of it.
		t.Setenv("CLOOP_AGENT_SECRET", "enrollment-token")
		got := withHarnessPath([]string{"HOME=/work"}, dirs, "/usr/bin")
		if len(got) != 2 {
			t.Fatalf("withHarnessPath = %v, want HOME plus a PATH and nothing else", got)
		}
		for _, kv := range got {
			if strings.Contains(kv, "enrollment-token") {
				t.Errorf("the payload environment carries the agent's own variable: %q", kv)
			}
		}
	})

	t.Run("an inherited PATH that already has the directory is not doubled", func(t *testing.T) {
		got := withHarnessPath([]string{"HOME=/work"}, dirs, "/home/edge/.local/bin:/usr/bin")
		if !containsEnv(got, "PATH=/home/edge/.local/bin:/usr/bin") {
			t.Fatalf("withHarnessPath = %v, want the inherited PATH unchanged", got)
		}
	})

	t.Run("an agent with no PATH falls back to the system floor", func(t *testing.T) {
		// Not the harness directory alone: a PATH with no /bin in it gives
		// the harness no shell to call.
		got := withHarnessPath([]string{"HOME=/work"}, dirs, "")
		want := "PATH=/home/edge/.local/bin:" + localprocess.DefaultPath
		if !containsEnv(got, want) {
			t.Fatalf("withHarnessPath = %v, want it to contain %q", got, want)
		}
	})

	t.Run("no harness directories still inherits the PATH", func(t *testing.T) {
		// A device whose operator put the harness somewhere of their own and
		// on the agent's PATH: the grant must not take that away either.
		got := withHarnessPath([]string{"HOME=/work"}, nil, "/opt/harness/bin:/usr/bin")
		if !containsEnv(got, "PATH=/opt/harness/bin:/usr/bin") {
			t.Fatalf("withHarnessPath = %v, want the inherited PATH", got)
		}
	})

	t.Run("no directories leaves an explicit PATH alone", func(t *testing.T) {
		in := []string{"PATH=/usr/bin"}
		if got := withHarnessPath(in, nil, "/agent/bin"); got[0] != in[0] {
			t.Fatalf("withHarnessPath = %q, want it unchanged", got[0])
		}
	})
}

// TestCapabilitiesSeesAPerUserInstall is the join between the two halves: a
// harness reachable only through a per-user directory still has to show up in
// what the device advertises, because a device that cannot see its own harness
// refuses every dispatch that needs it.
func TestCapabilitiesSeesAPerUserInstall(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", t.TempDir()) // deliberately empty: no ambient claude

	local := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(local, 0o755); err != nil {
		t.Fatal(err)
	}
	writeStubBinary(t, filepath.Join(local, "claude"), "9.9.9 (Claude Code)")

	a := &Agent{}
	caps := a.Capabilities()
	if !HasHarness(caps, "claude") {
		t.Fatalf("advertised harnesses = %v, want claude; it is installed at %s, which is "+
			"where the official installer puts it", caps.Harnesses, local)
	}
}

func containsEnv(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
