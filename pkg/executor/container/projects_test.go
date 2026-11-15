package container

// Two projects on one container executor (Task 20500): what each sandbox is
// given is its own tree and nothing of the other's — no parent directory, no
// sibling project, no other project's .cloop, no control plane, no shared /tmp
// and no shared cache — whether runc, Kata or gVisor runs it, since the
// command line is the same for each.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// twoProjects makes two project trees side by side beneath one parent, each
// with a file and a .cloop, and returns them.
func twoProjects(t *testing.T) (parent, web, api string) {
	t.Helper()
	parent = t.TempDir()
	web, api = filepath.Join(parent, "web"), filepath.Join(parent, "api")
	for _, d := range []string{web, api} {
		if err := os.MkdirAll(filepath.Join(d, ".cloop"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "secret-of-"+filepath.Base(d)), []byte(filepath.Base(d)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return parent, web, api
}

func TestTwoProjectsOnOneContainerExecutorShareNothing(t *testing.T) {
	parent, web, api := twoProjects(t)
	for _, runtime := range []string{"", "kata-runtime", "runsc"} {
		t.Run("runtime="+runtime, func(t *testing.T) {
			ex := fakeExecutor(t, Options{OCIRuntime: runtime, ControlPlaneDir: t.TempDir(), AllowRootUser: true})
			for _, tc := range []struct{ own, other string }{{web, api}, {api, web}} {
				req, err := ex.buildRequest(executor.Spec{WorkDir: tc.own, Argv: []string{"cloop", "run"}}, tc.own, nil)
				if err != nil {
					t.Fatalf("buildRequest(%s): %v", tc.own, err)
				}
				built, err := buildRunArgs(req)
				if err != nil {
					t.Fatalf("buildRunArgs(%s): %v", tc.own, err)
				}
				var volumes []string
				for i, a := range built.Args {
					if (a == "--volume" || a == "-v" || a == "--mount") && i+1 < len(built.Args) {
						volumes = append(volumes, built.Args[i+1])
					}
					if strings.Contains(a, tc.other) {
						t.Errorf("%s's sandbox names %s's tree: %q", tc.own, tc.other, a)
					}
				}
				if len(volumes) != 1 || !strings.HasPrefix(volumes[0], tc.own+":"+ContainerWorkspace) {
					t.Errorf("%s's sandbox binds %v, want its own tree alone at %s", tc.own, volumes, ContainerWorkspace)
				}
				for _, v := range volumes {
					if host, _, _ := strings.Cut(v, ":"); host == parent || host == filepath.Dir(parent) {
						t.Errorf("%s's sandbox binds the parent directory %s", tc.own, host)
					}
				}
				joined := strings.Join(built.Args, " ")
				if !strings.Contains(joined, "--tmpfs /tmp:") || !strings.Contains(joined, "--read-only") {
					t.Errorf("%s's sandbox has no private /tmp of its own over a read-only root: %s", tc.own, joined)
				}
			}
		})
	}
	// Derived images are per project too: see TestDerivedKey_IsEachProjectsOwn.
}

// TestTheHubsOwnDirectoryIsNeverBoundIntoASandbox: the hub's own directory
// holds the control plane in its .cloop, so no sandbox is given it — before
// the runtime is asked for anything — while a project beside it is.
func TestTheHubsOwnDirectoryIsNeverBoundIntoASandbox(t *testing.T) {
	_, web, _ := twoProjects(t)
	hub := t.TempDir()
	if err := os.MkdirAll(filepath.Join(hub, ".cloop"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "hub-link")
	if err := os.Symlink(hub, link); err != nil {
		t.Fatal(err)
	}
	for _, tree := range []string{hub, hub + "/", link} {
		err := refuseControlPlaneTree(hub, tree, "box")
		if !errors.Is(err, executor.ErrUnsupported) || !strings.Contains(err.Error(), "control plane") ||
			!strings.Contains(err.Error(), "executors.host_sandbox.opt_out") {
			t.Errorf("binding %s, the hub's own directory: %v", tree, err)
		}
	}
	if err := refuseControlPlaneTree(hub, web, "box"); err != nil {
		t.Errorf("a project beside the hub was refused: %v", err)
	}
	if err := refuseControlPlaneTree("", hub, "box"); err != nil {
		t.Errorf("an executor told of no control plane refused: %v", err)
	}

	// Through Start, before any runtime call: the fake runtime would fail
	// differently if one were made.
	ex := fakeExecutor(t, Options{ControlPlaneDir: hub, AllowRootUser: true})
	ex.rt.Path = filepath.Join(t.TempDir(), "no-such-docker")
	_, err := ex.Start(context.Background(), executor.Spec{WorkDir: hub, Argv: []string{"cloop", "run"}})
	if !errors.Is(err, executor.ErrUnsupported) || !strings.Contains(err.Error(), "control plane") {
		t.Errorf("Start in the hub's own directory: %v", err)
	}
}

// TestASandboxOfOneProjectCannotReachAnothers runs both projects' workloads in
// real sandboxes on one executor: neither can open, list or write the other's
// tree, nor find it anywhere in its filesystem, and a file one leaves in its
// /tmp is not in the other's.
func TestASandboxOfOneProjectCannotReachAnothers(t *testing.T) {
	if testing.Short() {
		t.Skip("starts containers; skipped under -short")
	}
	_, web, api := twoProjects(t)
	ex := newTestExecutor(t, defaultTestImage, nil)
	probe := func(name, cmd string) string {
		return "if ( " + cmd + " ) >/dev/null 2>&1; then echo " + name + ":ok; else echo " + name + ":denied; fi\n"
	}
	script := func(own, other string) string {
		return probe("own-read", "cat "+ContainerWorkspace+"/secret-of-"+filepath.Base(own)) +
			probe("own-write", "echo built > "+ContainerWorkspace+"/out.txt") +
			probe("other-open", "cat "+filepath.Join(other, "secret-of-"+filepath.Base(other))) +
			probe("other-list", "ls "+other) +
			probe("other-write", "mkdir -p "+other+" && touch "+filepath.Join(other, "planted")) +
			probe("other-found", "find / -xdev -name 'secret-of-"+filepath.Base(other)+"' 2>/dev/null | grep -q .") +
			probe("parent-listed", "ls "+ContainerWorkspace+"/.. | grep -q '^"+filepath.Base(other)+"$'") +
			probe("tmp-left", "cat /tmp/left-by-the-other") +
			"echo x > /tmp/left-by-the-other\n"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	for _, tc := range []struct{ own, other string }{{web, api}, {api, web}} {
		res, err := executor.Run(ctx, ex, executor.Spec{WorkDir: tc.own,
			Argv: []string{"/bin/sh", "-c", script(tc.own, tc.other)}})
		if err != nil {
			t.Fatalf("%s's run: %v (%q)", tc.own, err, res.Output)
		}
		out := string(res.Output)
		for _, want := range []string{"own-read:ok", "own-write:ok", "other-open:denied", "other-list:denied",
			"other-found:denied", "parent-listed:denied", "tmp-left:denied"} {
			if !strings.Contains(out, want) {
				t.Errorf("want %s from %s's sandbox:\n%s", want, filepath.Base(tc.own), out)
			}
		}
		if _, err := os.Stat(filepath.Join(tc.other, "planted")); err == nil {
			t.Errorf("%s's sandbox wrote into %s's tree", tc.own, tc.other)
		}
	}
}
