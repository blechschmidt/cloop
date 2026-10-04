package agent

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

func envValue(env []string, key string) (string, bool) {
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, key+"="); ok {
			return v, true
		}
	}
	return "", false
}

func TestWithPayloadHome(t *testing.T) {
	root := t.TempDir()
	tree := filepath.Join(root, "proj-1234abcd")
	if err := os.MkdirAll(tree, 0o700); err != nil {
		t.Fatal(err)
	}
	wantHome := filepath.Join(root, ".proj-1234abcd.home")

	t.Run("nil environment inherits", func(t *testing.T) {
		got, err := withPayloadHome(nil, root, tree)
		if err != nil || got != nil {
			t.Fatalf("withPayloadHome(nil) = %v, %v; a nil environment inherits the agent's HOME", got, err)
		}
		if _, err := os.Stat(wantHome); err == nil {
			t.Fatal("a home was created for a payload that inherits one")
		}
	})

	t.Run("explicit environment gets a home beside the tree", func(t *testing.T) {
		in := []string{"PATH=/usr/bin:/bin", "CLAUDE_CODE_OAUTH_TOKEN=x"}
		got, err := withPayloadHome(in, root, tree)
		if err != nil {
			t.Fatalf("withPayloadHome: %v", err)
		}
		home, ok := envValue(got, "HOME")
		if !ok || home != wantHome {
			t.Fatalf("HOME = %q (set %v), want %q", home, ok, wantHome)
		}
		if strings.HasPrefix(home, tree+string(os.PathSeparator)) || home == tree {
			t.Fatalf("HOME %q is inside the working tree %q", home, tree)
		}
		if len(in) != 2 || slices.Contains(in, "HOME="+wantHome) {
			t.Fatalf("the caller's environment was modified: %v", in)
		}
		info, err := os.Stat(home)
		if err != nil {
			t.Fatalf("the home directory was not created: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o700 {
			t.Fatalf("home mode = %04o, want 0700", perm)
		}
	})

	t.Run("a reused home is restricted again", func(t *testing.T) {
		if err := os.Chmod(wantHome, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := withPayloadHome([]string{"PATH=/bin"}, root, tree); err != nil {
			t.Fatalf("withPayloadHome: %v", err)
		}
		info, err := os.Stat(wantHome)
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("reused home mode = %v (%v), want 0700", info.Mode().Perm(), err)
		}
	})

	t.Run("a link where the home goes is replaced, never followed", func(t *testing.T) {
		outside := t.TempDir()
		if err := os.Chmod(outside, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(wantHome); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, wantHome); err != nil {
			t.Fatal(err)
		}
		if _, err := withPayloadHome([]string{"PATH=/bin"}, root, tree); err != nil {
			t.Fatalf("withPayloadHome: %v", err)
		}
		info, err := os.Lstat(wantHome)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("the home is not a real directory after a link was planted there: %v (%v)", info, err)
		}
		if st, err := os.Stat(outside); err != nil || st.Mode().Perm() != 0o755 {
			t.Fatalf("the link's target was touched: %v (%v)", st.Mode().Perm(), err)
		}
	})

	t.Run("an explicit HOME is kept", func(t *testing.T) {
		in := []string{"PATH=/bin", "HOME=/somewhere"}
		got, err := withPayloadHome(in, root, tree)
		if err != nil {
			t.Fatalf("withPayloadHome: %v", err)
		}
		if home, _ := envValue(got, "HOME"); home != "/somewhere" || len(got) != 2 {
			t.Fatalf("an explicit HOME was replaced: %v", got)
		}
	})

	t.Run("a payload in the root itself is left to the floor", func(t *testing.T) {
		got, err := withPayloadHome([]string{"PATH=/bin"}, root, root)
		if err != nil {
			t.Fatalf("withPayloadHome: %v", err)
		}
		if _, ok := envValue(got, "HOME"); ok {
			t.Fatalf("a home outside the root was invented for a payload running in it: %v", got)
		}
	})
}

// TestHostPayloadWritesItsHomeOutsideItsTree drives a real host-mode payload
// through the agent: one that writes into $HOME what Claude Code writes there.
// Before Task 20371 HOME was the tree, and a feature's write-back committed the
// harness's state onto the feature's branch.
func TestHostPayloadWritesItsHomeOutsideItsTree(t *testing.T) {
	root := t.TempDir()
	a, conns := newScriptedAgent(t, filepath.Join(t.TempDir(), "agent.json"), root)
	go func() { _ = a.Run(t.Context()) }()
	cp := <-conns
	cp.handshakeAt(t, "exec-home", remote.ProtocolVersion)

	const dir = "app-0123abcd"
	start, err := remote.NewFrameAt(remote.ProtocolVersion, remote.TypeStart, "start-home", "handle-home", remote.StartPayload{
		HandleID: "handle-home",
		Spec: executor.Spec{
			WorkDir: dir,
			// An explicit environment, as a project holding any grant has.
			Env: []string{"PATH=/usr/bin:/bin", "CLOOP_TEST_GRANT=1"},
			Argv: []string{"/bin/sh", "-c",
				`printf %s "$HOME" > home.txt && mkdir -p "$HOME/.claude" && echo '{}' > "$HOME/.claude.json"`},
		},
	})
	if err != nil {
		t.Fatalf("build start: %v", err)
	}
	cp.write(start)
	deadline := time.Now().Add(20 * time.Second)
	for {
		f, err := cp.read(time.Until(deadline))
		if err != nil {
			t.Fatalf("reading agent frames: %v", err)
		}
		if f.Type == remote.TypeStarted {
			if sp, _ := remote.DecodeStarted(f); sp.Error != "" {
				t.Fatalf("agent refused the workload: %s", sp.Error)
			}
		}
		if f.Type == remote.TypeStatus {
			if st, err := remote.DecodeStatus(f); err == nil && st.Status.State.Terminal() {
				break
			}
		}
	}

	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	tree := filepath.Join(resolvedRoot, dir)
	got, err := os.ReadFile(filepath.Join(tree, "home.txt"))
	if err != nil {
		t.Fatalf("the payload did not run: %v", err)
	}
	if want := filepath.Join(resolvedRoot, "."+dir+".home"); string(got) != want {
		t.Fatalf("the payload's HOME was %q, want %q beside its tree", got, want)
	}
	for _, leaked := range []string{".claude.json", ".claude"} {
		if _, err := os.Stat(filepath.Join(tree, leaked)); err == nil {
			t.Errorf("%s was written into the working tree, where a write-back commits it", leaked)
		}
	}
}
