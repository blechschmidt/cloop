package remote_test

// Projects kept apart on one device (Task 20500): a real agent behind a real
// WebSocket runs two projects' payloads as host processes, and the one the hub
// asked to keep to its project cannot open, list or write the other's tree.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/hostsandbox"
)

// probeScript tries each of the things a payload of one project must not do to
// another's tree, and the things it must still be able to do to its own, and
// prints name:ok or name:denied for each.
func probeScript(other string) string {
	probes := []struct{ name, cmd string }{
		{"own-write", "echo built > own.txt"},
		{"own-read", "cat own.txt"},
		{"other-read", "cat " + other + "/secret.txt"},
		{"other-list", "ls " + other},
		{"other-write", "touch " + other + "/planted"},
		// The root holding every project's tree: listing it must not name the
		// other project. (Under namespaces it lists a skeleton holding only
		// the payload's own directory; under Landlock alone it is refused.)
		{"other-named", "ls .. | grep -q '^" + filepath.Base(other) + "$'"},
	}
	var b strings.Builder
	for _, p := range probes {
		b.WriteString("if ( " + p.cmd + " ) >/dev/null 2>&1; then printf '" + p.name + ":ok '; else printf '" +
			p.name + ":denied '; fi\n")
	}
	b.WriteString("echo\n")
	return b.String()
}

func TestLoopbackHostRunsOfTwoProjectsCannotReachEachOther(t *testing.T) {
	if err := hostsandbox.Available(); err != nil {
		t.Skipf("no host sandbox on this host: %v", err)
	}
	lb := newLoopback(t)
	ex := lb.executor(t)
	ctx := context.Background()

	// Project B's run leaves a file in its tree.
	if res, err := executor.Run(ctx, ex, executor.Spec{WorkDir: "proj-b-1a2b3c4d",
		Argv: []string{"/bin/sh", "-c", "echo bob > secret.txt"}}); err != nil {
		t.Fatalf("project B's run: %v (%q)", err, res.Output)
	}
	other := filepath.Join(lb.root, "proj-b-1a2b3c4d")
	if _, err := os.Stat(filepath.Join(other, "secret.txt")); err != nil {
		t.Fatalf("project B's file is not where the test looks: %v", err)
	}

	run := func(t *testing.T, confine bool, env []string) string {
		t.Helper()
		res, err := executor.Run(ctx, ex, executor.Spec{WorkDir: "proj-a-5e6f7a8b", ConfineToProject: confine,
			Env: env, Argv: []string{"/bin/sh", "-c", probeScript(other)}})
		if err != nil {
			t.Fatalf("project A's run (confine=%v): %v (%q)", confine, err, res.Output)
		}
		return string(res.Output)
	}

	// The control: unconfined, project A's run reaches B's tree, so the
	// probes below can tell.
	if got := run(t, false, nil); !strings.Contains(got, "other-read:ok") || !strings.Contains(got, "other-list:ok") ||
		!strings.Contains(got, "other-named:ok") || !strings.Contains(got, "other-write:ok") {
		t.Fatalf("the unconfined run could not reach B's tree, so the probes prove nothing: %s", got)
	}
	_ = os.Remove(filepath.Join(other, "planted"))

	for name, env := range map[string][]string{"inheriting the agent's environment": nil,
		"with an environment of its own": {"PATH=/usr/bin:/bin", "LANG=C"}} {
		t.Run(name, func(t *testing.T) {
			got := run(t, true, env)
			for _, want := range []string{"own-write:ok", "own-read:ok", "other-read:denied", "other-list:denied",
				"other-write:denied", "other-named:denied"} {
				if !strings.Contains(got, want) {
					t.Errorf("want %s from project A's confined run: %s", want, got)
				}
			}
			if _, err := os.Stat(filepath.Join(other, "planted")); err == nil {
				t.Error("project A's confined run wrote into project B's tree")
			}
		})
	}
}

// TestLoopbackProjectDirectoriesArePrivateAndOneLevelDeep: each project's
// directory beneath the agent's root is its own — mode 0700, never a link,
// never inside another project's — and a workload that names none runs in a
// private directory of its own that goes with it, never in the root.
func TestLoopbackProjectDirectoriesArePrivateAndOneLevelDeep(t *testing.T) {
	lb := newLoopback(t)
	ex := lb.executor(t)
	ctx := context.Background()

	// An existing directory an older agent left open is closed again.
	loose := filepath.Join(lb.root, "loose-1a2b3c4d")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"fresh-5e6f7a8b", "loose-1a2b3c4d"} {
		if _, err := executor.Run(ctx, ex, executor.Spec{WorkDir: dir, Argv: []string{"/bin/true"}}); err != nil {
			t.Fatalf("run in %s: %v", dir, err)
		}
		fi, err := os.Lstat(filepath.Join(lb.root, dir))
		if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
			t.Errorf("project directory %s: %v %v, want a directory of mode 0700", dir, fi.Mode(), err)
		}
	}

	// A directory inside another project's tree, the root itself, or a link
	// where a project's directory goes: each is refused.
	victim := filepath.Join(lb.root, "victim-0a0b0c0d")
	if err := os.Mkdir(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(lb.root, "alias-0a0b0c0d")); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"fresh-5e6f7a8b/nested", lb.root, ".", "alias-0a0b0c0d"} {
		_, err := ex.Start(ctx, executor.Spec{WorkDir: dir, Argv: []string{"/bin/true"}})
		if err == nil || !strings.Contains(err.Error(), "root") {
			t.Errorf("WorkDir %q: %v, want a refusal naming the root", dir, err)
		}
	}

	// No directory named: a private one, not the root, gone afterwards.
	res, err := executor.Run(ctx, ex, executor.Spec{Argv: []string{"/bin/sh", "-c", "pwd; ls .."}})
	if err != nil {
		t.Fatalf("a run naming no directory: %v (%q)", err, res.Output)
	}
	pwd := strings.TrimSpace(strings.SplitN(string(res.Output), "\n", 2)[0])
	if pwd == lb.root || !strings.HasPrefix(pwd, lb.root+string(os.PathSeparator)) ||
		strings.Contains(string(res.Output), "victim-0a0b0c0d") {
		t.Errorf("a run naming no directory ran in %q and saw %q, want a private directory of its own", pwd, res.Output)
	}
	waitFor(t, loopbackWorkloadDeathBound, func() bool {
		_, err := os.Stat(pwd)
		return errors.Is(err, os.ErrNotExist)
	}, "the private directory of a run naming no directory should be removed once it ends")
}

// TestConfinementNeedsProtocol30: an agent below v30 ignores
// Spec.ConfineToProject and would run the payload with every other project in
// reach, so a host-mode dispatch asked to confine is refused, naming the
// upgrade and the opt-out; a container-mode one, already kept to its bind
// mount, is not.
func TestConfinementNeedsProtocol30(t *testing.T) {
	spec := plainSpec(t.TempDir())
	spec.ConfineToProject = true

	host := sandboxExecutor(t, executor.SandboxSettings{Mode: executor.SandboxModeHost}, nil)
	_, sess := connect(t, host, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloAt(remote.MinProjectConfinementVersion-1), nil)
	_, err := host.Start(context.Background(), spec)
	sess.Close()
	if !errors.Is(err, remote.ErrProjectConfinementUnsupported) {
		t.Fatalf("Start = %v, want ErrProjectConfinementUnsupported", err)
	}
	for _, want := range []string{"edge-1", "v29", "v30", "executors.host_sandbox.opt_out"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal should mention %q: %v", want, err)
		}
	}

	box := sandboxExecutor(t, executor.SandboxSettings{Mode: executor.SandboxModeContainer}, nil)
	_, sess = connect(t, box, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloAt(remote.MinProjectConfinementVersion-1), nil)
	defer sess.Close()
	if _, err := box.Start(briefly(t), spec); errors.Is(err, remote.ErrProjectConfinementUnsupported) {
		t.Errorf("a container-mode dispatch was refused for confinement: %v", err)
	}

	if remote.SupportsProjectConfinement(remote.MinProjectConfinementVersion-1) ||
		!remote.SupportsProjectConfinement(remote.ProtocolVersion) {
		t.Error("SupportsProjectConfinement disagrees with MinProjectConfinementVersion")
	}
}

// TestLoopbackAWorkloadNamingNoProjectOnASharedDeviceIsConfined: a workload
// that names no directory, on a device the hub said other projects share,
// runs in its private directory alone and cannot reach a project's tree.
func TestLoopbackAWorkloadNamingNoProjectOnASharedDeviceIsConfined(t *testing.T) {
	if err := hostsandbox.Available(); err != nil {
		t.Skipf("no host sandbox on this host: %v", err)
	}
	lb := newLoopback(t)
	ex := lb.executor(t)
	ctx := context.Background()
	if _, err := executor.Run(ctx, ex, executor.Spec{WorkDir: "proj-b-1a2b3c4d",
		Argv: []string{"/bin/sh", "-c", "echo bob > secret.txt"}}); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(lb.root, "proj-b-1a2b3c4d")
	res, err := executor.Run(ctx, ex, executor.Spec{ConfineToProject: true,
		Argv: []string{"/bin/sh", "-c", "echo mine > own.txt && cat own.txt; " +
			"cat " + filepath.Join(other, "secret.txt") + " 2>/dev/null || echo other-denied"}})
	if err != nil {
		t.Fatalf("a run naming no project: %v (%q)", err, res.Output)
	}
	out := string(res.Output)
	if !strings.Contains(out, "mine") || !strings.Contains(out, "other-denied") || strings.Contains(out, "bob") {
		t.Errorf("a confined run naming no project: %q", out)
	}
}

// TestLoopbackAnAttachTerminalBesideAConfinedWorkloadIsConfined: a terminal
// an operator opens beside a workload kept to its project reaches what the
// workload reaches, and no other project's tree.
func TestLoopbackAnAttachTerminalBesideAConfinedWorkloadIsConfined(t *testing.T) {
	if err := hostsandbox.Available(); err != nil {
		t.Skipf("no host sandbox on this host: %v", err)
	}
	lb := newLoopback(t)
	if _, err := executor.Run(context.Background(), lb.executor(t), executor.Spec{WorkDir: "proj-b-1a2b3c4d",
		Argv: []string{"/bin/sh", "-c", "echo bob > secret.txt"}}); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(lb.root, "proj-b-1a2b3c4d", "secret.txt")
	h, ex := startLongRunning(t, lb, executor.Spec{WorkDir: "proj-a-5e6f7a8b", ConfineToProject: true})
	conn := ex.attach(t, executor.AttachRequest{
		HandleID: h.ID,
		Command: []string{"/bin/sh", "-c", "pwd; echo own > own.txt && echo own-written; " +
			"cat " + other + " 2>/dev/null || echo other-denied; echo DONE"},
	})
	out, ok := readUntilE2E(t, conn, "DONE", 30*time.Second)
	if !ok {
		t.Fatalf("the terminal did not finish; transcript: %q", out)
	}
	if !strings.Contains(out, "own-written") || !strings.Contains(out, "other-denied") || strings.Contains(out, "bob") {
		t.Errorf("a terminal beside a confined workload: %q", out)
	}
}

// TestLoopbackADirectoryNamedForTwoProjectsServesTheFirstOnly: the hub names
// a project's directory on a device by its base name and 32 bits of a hash,
// so two project paths can be given one name; the device records whose the
// directory is on the first run and refuses the other project's.
func TestLoopbackADirectoryNamedForTwoProjectsServesTheFirstOnly(t *testing.T) {
	lb := newLoopback(t)
	ex := lb.executor(t)
	ctx := context.Background()
	run := func(project string) error {
		_, err := executor.Run(ctx, ex, executor.Spec{WorkDir: "api-1a2b3c4d", Argv: []string{"/bin/true"},
			Labels: map[string]string{"project": project}})
		return err
	}
	if err := run("/srv/team-one/api"); err != nil {
		t.Fatalf("the first project's run: %v", err)
	}
	if err := run("/srv/team-one/api/"); err != nil {
		t.Fatalf("the same project, spelled with a slash: %v", err)
	}
	err := run("/srv/team-two/api")
	if err == nil || !strings.Contains(err.Error(), "another project's tree") {
		t.Fatalf("another project named into the same directory: %v", err)
	}
	// A hub that names no project checks nothing, as before.
	if _, err := executor.Run(ctx, ex, executor.Spec{WorkDir: "api-1a2b3c4d", Argv: []string{"/bin/true"}}); err != nil {
		t.Fatalf("a run with no project label: %v", err)
	}
	if fi, err := os.Lstat(filepath.Join(lb.root, ".cloop-projects", "api-1a2b3c4d.project")); err != nil ||
		fi.Mode().Perm() != 0o600 {
		t.Errorf("the record of whose the directory is: %v %v", fi, err)
	}
}
