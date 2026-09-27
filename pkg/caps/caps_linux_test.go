//go:build linux

package caps

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// childEnv switches the test binary into the role of an agent that was started
// holding CAP_NET_ADMIN the way systemd hands it over: ambient, as an ordinary
// user, with a bounding set of that one capability and no_new_privs set.
const childEnv = "CLOOP_CAPS_TEST_CHILD"

func TestMain(m *testing.M) {
	if os.Getenv(childEnv) != "" {
		os.Exit(runChild())
	}
	os.Exit(m.Run())
}

// childReport is what the stand-in agent saw.
type childReport struct {
	ConfineErr string `json:"confine_err"`
	Self       Sets   `json:"self"`
	Holds      bool   `json:"holds"`
	Plain      Sets   `json:"plain"`
	Granted    Sets   `json:"granted"`
	GrantAsked bool   `json:"grant_asked"`
	Threads    int    `json:"threads"`
	Err        string `json:"err"`
}

func runChild() int {
	rep := childReport{}
	if err := Confine(); err != nil {
		rep.ConfineErr = err.Error()
	}
	rep.Self, _ = readSets("/proc/self/status")
	rep.Holds = Holds(NetAdmin)
	tasks, _ := filepath.Glob("/proc/self/task/*")
	rep.Threads = len(tasks)

	status := func(grantIt bool) (Sets, bool, error) {
		cmd := exec.Command("cat", "/proc/self/status")
		asked := false
		if grantIt {
			asked = Grant(cmd, NetAdmin)
		}
		out, err := cmd.Output()
		if err != nil {
			return Sets{}, asked, err
		}
		s, err := ParseStatus(string(out))
		return s, asked, err
	}
	var err error
	if rep.Plain, _, err = status(false); err != nil {
		rep.Err = "plain child: " + err.Error()
	}
	if rep.Granted, rep.GrantAsked, err = status(true); err != nil {
		rep.Err = "granted child: " + err.Error()
	}
	_ = json.NewEncoder(os.Stdout).Encode(rep)
	return 0
}

// TestConfinedAgentKeepsItsCapabilityFromChildren is the property Task 20352
// rests on. The agent's unit hands it CAP_NET_ADMIN so it can install sandbox
// firewalls; without Confine every program it started — the harness, its shell,
// a workload's git hooks — would hold it too. After Confine the agent still
// holds it, a child it starts holds nothing, and a child it Grants holds exactly
// that one capability.
//
// It needs root, to start a process with a chosen ambient set as another user,
// and setpriv(1) to do it. Run it under both build modes — plain and
// CGO_ENABLED=0 — because they clear the sets by different mechanisms.
func TestConfinedAgentKeepsItsCapabilityFromChildren(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to start a process with an ambient capability set")
	}
	setpriv, err := exec.LookPath("setpriv")
	if err != nil {
		t.Skip("setpriv(1) is not installed")
	}
	if help, _ := exec.Command(setpriv, "--help").CombinedOutput(); !strings.Contains(string(help), "--ambient-caps") {
		t.Skip("this setpriv cannot set ambient capabilities")
	}

	// The test binary sits in a root-only build directory; the stand-in agent
	// runs as nobody, so it gets a copy it can execute.
	dir, err := os.MkdirTemp("", "cloop-caps-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "caps.test")
	if err := copyExecutable(os.Args[0], bin); err != nil {
		t.Fatalf("copy the test binary: %v", err)
	}

	cmd := exec.Command(setpriv,
		"--reuid=65534", "--regid=65534", "--clear-groups",
		"--inh-caps=+net_admin", "--ambient-caps=+net_admin",
		"--bounding-set=-all,+net_admin", "--no-new-privs",
		bin, "-test.run=^$")
	cmd.Env = append(os.Environ(), childEnv+"=1")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		var stderr string
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("stand-in agent: %v\n%s%s", err, out, stderr)
	}
	var rep childReport
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatalf("stand-in agent printed %q: %v", out, err)
	}
	if rep.Err != "" {
		t.Fatalf("stand-in agent: %s", rep.Err)
	}
	t.Logf("stand-in agent: %d threads; self %+v", rep.Threads, rep.Self)

	if rep.ConfineErr != "" {
		t.Errorf("Confine: %s", rep.ConfineErr)
	}
	if rep.Self.Ambient != 0 || rep.Self.Inheritable != 0 {
		t.Errorf("the agent can still pass capabilities on: ambient %#x, inheritable %#x",
			rep.Self.Ambient, rep.Self.Inheritable)
	}
	if !Has(rep.Self.Permitted, NetAdmin) || !Has(rep.Self.Effective, NetAdmin) || !rep.Holds {
		t.Errorf("Confine took CAP_NET_ADMIN from the agent itself: %+v (Holds %t)", rep.Self, rep.Holds)
	}
	if p := rep.Plain; p.Permitted|p.Effective|p.Ambient|p.Inheritable != 0 {
		t.Errorf("a child the agent started holds capabilities: %+v", p)
	}
	if !rep.GrantAsked {
		t.Error("Grant did not ask for CAP_NET_ADMIN although the agent holds it")
	}
	if g := rep.Granted; g.Effective != 1<<NetAdmin || g.Permitted != 1<<NetAdmin || g.Ambient != 1<<NetAdmin {
		t.Errorf("the granted child does not hold exactly CAP_NET_ADMIN: %+v", g)
	}
}

func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, 0o755)
}

// TestVerifyConfinedNamesTheLeakingThread: the verification is what turns a
// constructor that silently failed to run into a warning an operator reads, so
// its report has to say what it found.
func TestVerifyConfinedNamesTheLeakingThread(t *testing.T) {
	if err := verifyConfined(); err != nil {
		s, _ := readSets("/proc/self/status")
		if s.Ambient == 0 && s.Inheritable == 0 {
			t.Fatalf("verifyConfined reported a leak in a process holding nothing inheritable: %v", err)
		}
		if !strings.Contains(err.Error(), "thread") {
			t.Errorf("the report does not name the thread: %v", err)
		}
	}
}
