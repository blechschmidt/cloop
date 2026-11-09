//go:build linux

package hostsandbox

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// sandboxFixture is a host with a project, a home of its own, a read-only tree
// and a second person's files, and a workload to run among them.
type sandboxFixture struct {
	root, project, home, readOnly, other, tmp string
}

func newSandboxFixture(t *testing.T) sandboxFixture {
	t.Helper()
	if err := Available(); err != nil {
		t.Skipf("no host sandbox here: %v", err)
	}
	root := t.TempDir()
	f := sandboxFixture{
		root:     root,
		project:  filepath.Join(root, "projects", "alice-app"),
		home:     filepath.Join(root, "homes", "alice"),
		readOnly: filepath.Join(root, "toolchain"),
		other:    filepath.Join(root, "projects", "bob-app"),
		tmp:      filepath.Join(root, "sandbox", "tmp"),
	}
	for _, d := range []string{f.project, f.home, f.readOnly, f.other, f.tmp} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for path, body := range map[string]string{
		filepath.Join(f.project, "main.go"):     "alice's code\n",
		filepath.Join(f.readOnly, "tool.txt"):   "a toolchain\n",
		filepath.Join(f.other, "secret.txt"):    "bob's code\n",
		filepath.Join(f.home, ".gitconfig"):     "[user]\n",
		filepath.Join(root, "hub-key-file.txt"): "the hub's root key\n",
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f sandboxFixture) policy(namespaces bool, script string) Policy {
	return Policy{
		Argv:       []string{"/bin/sh", "-c", script},
		Dir:        f.project,
		ReadWrite:  []string{f.project, f.home},
		ReadOnly:   append(append(append([]string{}, SystemReadOnly...), EtcReadOnly...), f.readOnly),
		Devices:    DefaultDevices,
		Namespaces: namespaces,
		Tmp:        f.tmp,
	}
}

// run starts the policy's workload in the sandbox the way the driver does and
// returns its output and exit status.
func (f sandboxFixture) run(t *testing.T, p Policy) (string, int) {
	t.Helper()
	helper, err := HelperPath()
	if err != nil {
		t.Fatal(err)
	}
	tmp := f.tmp
	if p.Namespaces {
		tmp = "/tmp"
	}
	cmd := exec.Command(p.Argv[0], p.Argv[1:]...)
	cmd.Dir = p.Dir
	cmd.Env = Environment(append(os.Environ(), "SANDBOX_TEST_MARKER=outside"), f.home, tmp, f.root, p.ReadWrite)
	if err := Wrap(cmd, helper, p); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err = cmd.Run()
	code := 0
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatalf("run the sandbox: %v\n%s", err, out.String())
	}
	return out.String(), code
}

// modes are the sandbox modes this host can run: Landlock alone always, and
// with namespaces when the test runs as root.
func modes() []bool {
	if UsesNamespaces() {
		return []bool{false, true}
	}
	return []bool{false}
}

func modeName(namespaces bool) string {
	if namespaces {
		return "namespaces"
	}
	return "landlock"
}

// probe runs one shell test and prints whether it succeeded, so one workload
// answers many questions.
func probe(name, cmd string) string {
	return fmt.Sprintf("if %s >/dev/null 2>&1; then echo 'ok:%s'; else echo 'denied:%s'; fi\n", cmd, name, name)
}

func TestTheSandboxGrantsItsPolicyAndNothingElse(t *testing.T) {
	f := newSandboxFixture(t)
	shm := filepath.Join("/dev/shm", "cloop-hostsandbox-test-"+strconv.Itoa(os.Getpid()))
	if err := os.WriteFile(shm, []byte("another run's lease\n"), 0o600); err != nil {
		t.Skipf("no /dev/shm here: %v", err)
	}
	t.Cleanup(func() { os.Remove(shm) })

	script := probe("read-project", "cat "+filepath.Join(f.project, "main.go")) +
		probe("write-project", "echo more >> "+filepath.Join(f.project, "main.go")) +
		probe("create-in-project", "mkdir "+filepath.Join(f.project, "build")+" && mv "+
			filepath.Join(f.project, "main.go")+" "+filepath.Join(f.project, "build", "main.go")) +
		probe("write-home", "echo x > $HOME/.cache-test") +
		probe("read-toolchain", "cat "+filepath.Join(f.readOnly, "tool.txt")) +
		probe("write-toolchain", "echo x > "+filepath.Join(f.readOnly, "tool.txt")) +
		probe("read-other-person", "cat "+filepath.Join(f.other, "secret.txt")) +
		probe("list-other-person", "ls "+f.other) +
		probe("read-hub-key", "cat "+filepath.Join(f.root, "hub-key-file.txt")) +
		probe("write-tmp", "echo x > $TMPDIR/scratch") +
		probe("read-another-runs-shm", "cat "+shm) +
		probe("read-shadow", "cat /etc/shadow") +
		probe("read-hub-environment", "cat /proc/"+strconv.Itoa(os.Getpid())+"/environ") +
		probe("run-a-system-program", "/usr/bin/env true") +
		probe("dev-null", "echo x > /dev/null") +
		probe("mknod", "mknod "+filepath.Join(f.project, "disk")+" b 8 0")

	for _, ns := range modes() {
		t.Run(modeName(ns), func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(f.project, "main.go"), []byte("alice's code\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			os.RemoveAll(filepath.Join(f.project, "build"))
			out, code := f.run(t, f.policy(ns, script))
			if code != 0 {
				t.Fatalf("the workload exited %d:\n%s", code, out)
			}
			want := map[string]string{
				"read-project":          "ok",
				"write-project":         "ok",
				"create-in-project":     "ok",
				"write-home":            "ok",
				"read-toolchain":        "ok",
				"write-toolchain":       "denied",
				"read-other-person":     "denied",
				"list-other-person":     "denied",
				"read-hub-key":          "denied",
				"write-tmp":             "ok",
				"read-another-runs-shm": "denied",
				"read-shadow":           "denied",
				"read-hub-environment":  "denied",
				"run-a-system-program":  "ok",
				"dev-null":              "ok",
				"mknod":                 "denied",
			}
			for name, verdict := range want {
				if !strings.Contains(out, verdict+":"+name+"\n") {
					t.Errorf("%s: want %s, got:\n%s", name, verdict, out)
				}
			}
		})
	}
}

func TestTheWorkloadsExitStatusIsTheSandboxes(t *testing.T) {
	f := newSandboxFixture(t)
	for _, ns := range modes() {
		t.Run(modeName(ns), func(t *testing.T) {
			if _, code := f.run(t, f.policy(ns, "exit 7")); code != 7 {
				t.Fatalf("exit status %d, want 7", code)
			}
			if _, code := f.run(t, f.policy(ns, "kill -TERM $$")); code != 128+15 && code != -1 {
				t.Fatalf("a workload that died of SIGTERM reported %d", code)
			}
		})
	}
}

func TestAPolicyTheHelperCannotHonourIsRefusedBeforeTheWorkloadRuns(t *testing.T) {
	f := newSandboxFixture(t)
	for _, ns := range modes() {
		t.Run(modeName(ns), func(t *testing.T) {
			p := f.policy(ns, "echo the workload ran")
			p.ReadWrite = append(p.ReadWrite, filepath.Join(f.root, "does-not-exist"))
			out, code := f.run(t, p)
			if code != ExitHelperFailed || strings.Contains(out, "the workload ran") {
				t.Fatalf("exit %d, output:\n%s", code, out)
			}
			if !strings.Contains(out, "cloop: host sandbox:") || !strings.Contains(out, "does-not-exist") {
				t.Fatalf("the refusal does not say why:\n%s", out)
			}
		})
	}
}

func TestNamespaceModeHidesTheHostsProcessesSocketsAndCapabilities(t *testing.T) {
	if !UsesNamespaces() {
		t.Skip("namespace mode is for a hub running as root")
	}
	f := newSandboxFixture(t)
	marker := filepath.Join("/run", "cloop-hostsandbox-test-"+strconv.Itoa(os.Getpid()))
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(marker) })
	script := probe("see-host-run", "test -e "+marker) +
		probe("see-hub-process", "test -e /proc/"+strconv.Itoa(os.Getpid())) +
		"echo pid:$$\n" +
		"grep -E '^(CapBnd|CapEff|NoNewPrivs):' /proc/self/status\n"
	out, code := f.run(t, f.policy(true, script))
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, want := range []string{
		"denied:see-host-run\n", "denied:see-hub-process\n",
		"CapBnd:\t000000000000041b\n", "CapEff:\t000000000000041b\n", "NoNewPrivs:\t1\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("want %q in:\n%s", want, out)
		}
	}
	var pid int
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(line, "pid:"); ok {
			pid, _ = strconv.Atoi(v)
		}
	}
	if pid <= 0 || pid > 10 {
		t.Errorf("the workload is pid %d; in its own namespace it is one of the first", pid)
	}
}

func TestATestBinaryWithoutTheHelperRefusesToStartIt(t *testing.T) {
	testHelperInstalled.Store(false)
	t.Cleanup(func() { testHelperInstalled.Store(true) })
	if _, err := HelperPath(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("HelperPath in a test binary without the helper: %v", err)
	}
}

func TestALinkLeftInAWritableGrantIsNeverFollowedOutOfIt(t *testing.T) {
	f := newSandboxFixture(t)
	// What an earlier run could have done to the home it may write: turn the
	// directory the hub grants next time into a link to the root.
	planted := filepath.Join(f.home, "sandbox-home")
	if err := os.Symlink("/", planted); err != nil {
		t.Fatal(err)
	}
	for _, ns := range modes() {
		t.Run(modeName(ns), func(t *testing.T) {
			p := f.policy(ns, "cat "+filepath.Join(f.other, "secret.txt")+" && echo read-through-the-link")
			p.ReadWrite = append(p.ReadWrite, planted)
			out, code := f.run(t, p)
			if code != ExitHelperFailed || strings.Contains(out, "read-through-the-link") || strings.Contains(out, "bob's code") {
				t.Fatalf("a planted link was followed: exit %d\n%s", code, out)
			}
			if !strings.Contains(out, "leads out of") {
				t.Errorf("the refusal does not say why:\n%s", out)
			}
		})
	}
}

func TestTheHostsTerminalsAreOutOfReach(t *testing.T) {
	f := newSandboxFixture(t)
	// A terminal of the host's — an administrator's SSH session, say.
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no terminals here: %v", err)
	}
	defer ptmx.Close()
	if err := unix.IoctlSetPointerInt(int(ptmx.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(int(ptmx.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	pts := "/dev/pts/" + strconv.Itoa(n)
	for _, ns := range modes() {
		t.Run(modeName(ns), func(t *testing.T) {
			out, code := f.run(t, f.policy(ns, probe("open-host-terminal", "( exec 3<>"+pts+" )")))
			if code != 0 {
				t.Fatalf("exit %d:\n%s", code, out)
			}
			if !strings.Contains(out, "denied:open-host-terminal\n") {
				t.Errorf("the sandbox opened the host's terminal %s:\n%s", pts, out)
			}
		})
	}
}

// In namespace mode the whole tree is read-only but for the writable grants,
// which stops what Landlock does not: chmod, chown and utimes on a file the
// workload may not open. Needs a project outside the directories namespace
// mode makes private, so it lives under HOME.
func TestNamespaceModeLeavesOnlyTheWritableGrantsWritable(t *testing.T) {
	if !UsesNamespaces() {
		t.Skip("namespace mode is for a hub running as root")
	}
	if err := Available(); err != nil {
		t.Skipf("no host sandbox here: %v", err)
	}
	home, err := os.UserHomeDir()
	if err != nil || underAny(home, privateDirs) || home == "/" {
		t.Skipf("no home outside the private directories: %q %v", home, err)
	}
	root, err := os.MkdirTemp(home, ".hostsandbox-test-")
	if err != nil {
		t.Skipf("cannot write under %s: %v", home, err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	project, outside := filepath.Join(root, "project"), filepath.Join(root, "outside")
	for _, d := range []string{project, outside} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{filepath.Join(project, "f"), filepath.Join(outside, "f")} {
		if err := os.WriteFile(path, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	script := probe("chmod-project", "chmod 640 "+filepath.Join(project, "f")) +
		probe("write-project", "echo y >> "+filepath.Join(project, "f")) +
		probe("chmod-outside", "chmod 644 "+filepath.Join(outside, "f")) +
		probe("touch-outside", "touch -d 2001-01-01 "+filepath.Join(outside, "f")) +
		probe("chown-outside", "chown 65534 "+filepath.Join(outside, "f"))
	f := sandboxFixture{root: root, project: project, home: project, other: outside,
		readOnly: filepath.Join(root, "toolchain"), tmp: filepath.Join(root, "tmp")}
	for _, d := range []string{f.tmp, f.readOnly} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	p := f.policy(true, script)
	p.ReadWrite = []string{project}
	out, code := f.run(t, p)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for name, verdict := range map[string]string{
		"chmod-project": "ok", "write-project": "ok",
		"chmod-outside": "denied", "touch-outside": "denied", "chown-outside": "denied",
	} {
		if !strings.Contains(out, verdict+":"+name+"\n") {
			t.Errorf("%s: want %s in:\n%s", name, verdict, out)
		}
	}
	if fi, err := os.Stat(filepath.Join(outside, "f")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("the file outside every grant changed: %v %v", fi.Mode(), err)
	}
}

// A run's lease directory and the files in it are granted together, as the
// driver grants them; namespace mode binds the directory back read-only once,
// with its files in it.
func TestTheRunsOwnLeaseFilesAreReadable(t *testing.T) {
	f := newSandboxFixture(t)
	lease := filepath.Join("/dev/shm", "cloop-lease-hostsandbox-test-"+strconv.Itoa(os.Getpid()))
	if err := os.Mkdir(lease, 0o700); err != nil {
		t.Skipf("no /dev/shm here: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(lease) })
	token := filepath.Join(lease, "token")
	if err := os.WriteFile(token, []byte("the run's own credential\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, ns := range modes() {
		t.Run(modeName(ns), func(t *testing.T) {
			p := f.policy(ns, probe("read-lease", "cat "+token)+probe("write-lease", "echo x > "+token))
			p.ReadOnly = append(p.ReadOnly, lease, token)
			out, code := f.run(t, p)
			if code != 0 {
				t.Fatalf("exit %d:\n%s", code, out)
			}
			if !strings.Contains(out, "ok:read-lease\n") || !strings.Contains(out, "denied:write-lease\n") {
				t.Errorf("the run's lease files:\n%s", out)
			}
		})
	}
}
