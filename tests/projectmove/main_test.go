// Package projectmove_test proves that moving a project between executors
// keeps everything the project held, end to end, with the real cloop binary
// (Task 20497).
//
// Every move starts from a project holding the work a move exists to carry:
// a dirty tree (a modified, a deleted, a renamed, an untracked and a binary
// file), a commit on main that no remote has, a feature whose worktree branch
// holds a commit no remote has, a task with an attachment, and a task whose
// run was in progress when the move began. The moves are the ones an operator
// makes:
//
//   - hub-local → container executor (TestMoveRoundTrip)
//   - container → a remote agent, a second process speaking the real agent
//     protocol over a WebSocket (TestMoveRoundTrip)
//   - remote agent → hub-local (TestMoveRoundTrip)
//   - hub-local → remote agent with the hub killed while the device is being
//     seeded; the restarted hub resumes the move and verifies it
//     (TestMoveResumesAfterTheHubDiesMidSeed)
//
// After each move the suite checks, against snapshots it takes itself rather
// than the hub's own verdict: the working tree byte for byte, the index, HEAD,
// every branch and tag tip, the .cloop files a move delivers, that the
// interrupted task went back to pending and runs to done on the target, that
// the attachment is still there, and that the source keeps its copy until the
// move is cleaned up, and only then lets it go.
//
// The harness is a stand-in claude (stubClaude), and every process gets its
// own HOME and CLOOP_HOME under the test's temporary directory, with every
// inherited CLOOP_* variable dropped. The project's origin is a git server on
// loopback, served over TLS from a certificate the device is told to trust,
// because a device run fetches its project's origin before it starts.
//
// The suite needs git, a static cloop and, for the round trip, Docker, so it
// is opt-in:
//
//	CLOOP_PROJECTMOVE_E2E=1 go test ./tests/projectmove/ -v -count=1 -timeout 20m
//
// CLOOP_PROJECTMOVE_BIN (or CLOOP_FLAGSHIP_BIN, as CI's flagship job builds
// it) names a static cloop to use; otherwise the suite builds one.
// CLOOP_PROJECTMOVE_KEEP=1 keeps the test's directory for a look afterwards.
package projectmove_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
)

// optIn skips a test unless the suite was asked for.
func optIn(t *testing.T) {
	t.Helper()
	if os.Getenv("CLOOP_PROJECTMOVE_E2E") != "1" {
		t.Skip("set CLOOP_PROJECTMOVE_E2E=1 to run the project move suite (needs git, and Docker for the round trip)")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
}

// requireDocker skips a test that needs a container runtime when there is
// none.
func requireDocker(t *testing.T) {
	t.Helper()
	if out, err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
		t.Skipf("docker is not usable: %v %s", err, out)
	}
}

var (
	builtOnce sync.Once
	builtBin  string
	builtErr  error
)

// cloopBinary is the static cloop under test: the one the environment names,
// or one built once for the whole test binary. Static, because the container
// round trip copies it into an Alpine image.
func cloopBinary(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"CLOOP_PROJECTMOVE_BIN", "CLOOP_FLAGSHIP_BIN"} {
		if bin := os.Getenv(name); bin != "" {
			if _, err := os.Stat(bin); err != nil {
				t.Fatalf("%s names %s: %v", name, bin, err)
			}
			return bin
		}
	}
	builtOnce.Do(func() {
		_, thisFile, _, _ := runtime.Caller(0)
		repo := filepath.Join(filepath.Dir(thisFile), "..", "..")
		dir, err := os.MkdirTemp("", "cloop-projectmove-bin-*")
		if err != nil {
			builtErr = err
			return
		}
		builtBin = filepath.Join(dir, "cloop")
		build := exec.Command("go", "build", "-o", builtBin, ".")
		build.Dir = repo
		build.Env = append(append(os.Environ(), goCaches...), "CGO_ENABLED=0")
		if out, err := build.CombinedOutput(); err != nil {
			builtErr = fmt.Errorf("build a static cloop: %v\n%s", err, out)
		}
	})
	if builtErr != nil {
		t.Fatal(builtErr)
	}
	return builtBin
}

// goCaches are Go's cache locations as they were before TestMain moved HOME:
// the build the suite makes would otherwise start cold in the isolated home,
// and fill it with a gigabyte of objects.
var goCaches []string

func TestMain(m *testing.M) {
	if os.Getenv("CLOOP_PROJECTMOVE_E2E") == "1" && os.Getenv("CLOOP_PROJECTMOVE_BIN") == "" && os.Getenv("CLOOP_FLAGSHIP_BIN") == "" {
		for _, k := range []string{"GOCACHE", "GOMODCACHE", "GOPATH"} {
			if out, err := exec.Command("go", "env", k).Output(); err == nil {
				if v := strings.TrimSpace(string(out)); v != "" {
					goCaches = append(goCaches, k+"="+v)
				}
			}
		}
	}
	code := hometest.Isolate(m)
	if builtBin != "" {
		_ = os.RemoveAll(filepath.Dir(builtBin))
	}
	os.Exit(code)
}
