package e2e_test

// An open hub is not reachable from the network (Task 20393), with the built
// binary: a scratch HOME, CLOOP_HOME and working directory, free ports, and
// this machine's own non-loopback address standing in for "the network".
//
// A hub with no sign-in is only ever started on loopback here. The positive
// control — proof that the reachability check can see a hub that IS on the
// network — is a token-protected hub, so no test ever serves an open hub
// beyond loopback, even for a second, on a machine that may have a public
// address.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// exposureScene is one scratch control plane.
type exposureScene struct {
	t   *testing.T
	bin string
	dir string // the hub's working directory
	env []string
}

func newExposureScene(t *testing.T) *exposureScene {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	s := &exposureScene{t: t, bin: binaryPath(t), dir: filepath.Join(root, "hub")}
	for _, d := range []string{home, s.dir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Every CLOOP_* variable dropped: an inherited CLOOP_UI_TOKEN would give
	// the "open" hub a credential, and the agent running this test carries
	// its own hub's environment.
	s.env = append(withoutCloopEnv(os.Environ()),
		"HOME="+home,
		"CLOOP_HOME="+filepath.Join(home, ".cloop"),
		"NO_COLOR=1",
	)
	s.run(nil, "init", "--provider", "mock", "--skip-clarify", "exposure")
	return s
}

// run executes the binary in the hub's directory and returns its combined
// output, failing the test on a non-zero exit.
func (s *exposureScene) run(extraEnv []string, args ...string) string {
	s.t.Helper()
	out, err := s.runErr(extraEnv, args...)
	if err != nil {
		s.t.Fatalf("cloop %v: %v\n%s", args, err, out)
	}
	return out
}

func (s *exposureScene) runErr(extraEnv []string, args ...string) (string, error) {
	cmd := exec.Command(s.bin, args...)
	cmd.Dir = s.dir
	cmd.Env = append(append([]string(nil), s.env...), extraEnv...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// runningHub is a `cloop ui` the scene started.
type runningHub struct {
	port int
	log  *strings.Builder
	w    *syncWriter
	done chan struct{}
	err  error
}

// output is what the hub has printed so far, read under the lock its writes
// take.
func (h *runningHub) output() string {
	h.w.mu.Lock()
	defer h.w.mu.Unlock()
	return h.log.String()
}

// startHub starts `cloop ui` on port and returns once it answers /healthz on
// loopback, or fails the test with its output if it exits first.
func (s *exposureScene) startHub(port int, extraEnv []string, args ...string) *runningHub {
	s.t.Helper()
	argv := append([]string{"ui", "--port", strconv.Itoa(port), "--no-browser"}, args...)
	cmd := exec.Command(s.bin, argv...)
	cmd.Dir = s.dir
	cmd.Env = append(append([]string(nil), s.env...), extraEnv...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	h := &runningHub{port: port, log: &strings.Builder{}, done: make(chan struct{})}
	h.w = &syncWriter{w: h.log}
	cmd.Stdout, cmd.Stderr = h.w, h.w
	if err := cmd.Start(); err != nil {
		s.t.Fatal(err)
	}
	go func() {
		h.err = cmd.Wait()
		close(h.done)
	}()
	s.t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-h.done
	})
	deadline := time.Now().Add(60 * time.Second)
	for {
		select {
		case <-h.done:
			s.t.Fatalf("cloop %v exited before answering (%v):\n%s", argv, h.err, h.output())
		default:
		}
		if resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", port)); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return h
			}
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("cloop %v did not answer /healthz within 60s:\n%s", argv, h.output())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// exposureFinding runs `cloop hub doctor --port port --json` and returns its
// ui.exposure finding's severity and message.
func (s *exposureScene) exposureFinding(port int, extraEnv []string) (severity, message string) {
	s.t.Helper()
	// Exits 1 on any failing check, which a scratch hub has plenty of; the
	// JSON is what is read.
	out, _ := s.runErrStdout(extraEnv, "hub", "doctor", "--port", strconv.Itoa(port), "--json")
	var rep struct {
		Findings []struct{ Check, Severity, Message string } `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		s.t.Fatalf("hub doctor --json: %v\n%s", err, out)
	}
	for _, f := range rep.Findings {
		if f.Check == "ui.exposure" {
			return f.Severity, f.Message
		}
	}
	s.t.Fatalf("hub doctor reported no ui.exposure finding:\n%s", out)
	return "", ""
}

func (s *exposureScene) runErrStdout(extraEnv []string, args ...string) (string, error) {
	cmd := exec.Command(s.bin, args...)
	cmd.Dir = s.dir
	cmd.Env = append(append([]string(nil), s.env...), extraEnv...)
	out, err := cmd.Output()
	return string(out), err
}

// networkAddr is an address of this machine that is not loopback: what
// another host would dial. Tests that need one skip on a machine without.
func networkAddr(t *testing.T) net.IP {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("cannot list this machine's addresses: %v", err)
	}
	var v6 net.IP
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || !ipn.IP.IsGlobalUnicast() {
			continue // loopback, link-local, multicast
		}
		if ipn.IP.To4() != nil {
			return ipn.IP
		}
		if v6 == nil {
			v6 = ipn.IP
		}
	}
	if v6 == nil {
		t.Skip("this machine has no non-loopback address to dial")
	}
	return v6
}

// dialable reports whether a TCP connection to ip:port opens.
func dialable(ip net.IP, port int) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)), 2*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// TestE2EOpenHubIsNotReachableBeyondLoopback: started with no sign-in and no
// --listen, `cloop ui` serves this machine and nothing else — it answers on
// 127.0.0.1, open, and refuses a connection on the machine's network address.
func TestE2EOpenHubIsNotReachableBeyondLoopback(t *testing.T) {
	ip := networkAddr(t)
	s := newExposureScene(t)
	port := freePort(t)
	h := s.startHub(port, nil)

	if !strings.Contains(h.output(), fmt.Sprintf("listens on 127.0.0.1:%d only", port)) {
		t.Errorf("the hub did not say it is loopback-only:\n%s", h.output())
	}
	// It is open — which is why the bind is all that protects it.
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/projects", port))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/projects on loopback = %d, want 200 from an open hub", resp.StatusCode)
	}
	if dialable(ip, port) {
		t.Fatalf("an open hub accepts connections on %s:%d — it is reachable from the network", ip, port)
	}

	sev, msg := s.exposureFinding(port, nil)
	if sev != "pass" || !strings.Contains(msg, fmt.Sprintf("127.0.0.1:%d only", port)) {
		t.Errorf("hub doctor: %s: %s", sev, msg)
	}
}

// TestE2EOpenHubRefusesANetworkAddress: named a network address, a hub with no
// sign-in exits with the reason and binds nothing — by flag and by the
// instance overlay alike — and the doctor predicts the refusal.
func TestE2EOpenHubRefusesANetworkAddress(t *testing.T) {
	s := newExposureScene(t)

	port := freePort(t)
	out, err := s.runErr(nil, "ui", "--port", strconv.Itoa(port), "--no-browser", "--listen", "0.0.0.0")
	if err == nil {
		t.Fatalf("an open hub started on every interface:\n%s", out)
	}
	for _, want := range []string{
		fmt.Sprintf("refusing to listen on *:%d (--listen)", port),
		"Remote executor agents need to reach the hub",
		"ui.allow_unauthenticated_network: true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the refusal does not say %q:\n%s", want, out)
		}
	}
	if dialable(net.IPv4(127, 0, 0, 1), port) {
		t.Errorf("something listens on :%d after the refusal", port)
	}

	// The same address from the hub's instance overlay.
	port = freePort(t)
	writeTestFile(t, filepath.Join(s.dir, ".cloop", fmt.Sprintf("config.ui-%d.yaml", port)),
		"ui:\n  listen: 0.0.0.0\n")
	sev, msg := s.exposureFinding(port, nil)
	if sev != "fail" || !strings.Contains(msg, "would refuse to start") {
		t.Errorf("hub doctor before the start: %s: %s", sev, msg)
	}
	out, err = s.runErr(nil, "ui", "--port", strconv.Itoa(port), "--no-browser")
	if err == nil || !strings.Contains(out, fmt.Sprintf("refusing to listen on *:%d (ui.listen)", port)) {
		t.Fatalf("ui.listen 0.0.0.0 on an open hub: err=%v\n%s", err, out)
	}
}

// TestE2ESignedInHubIsReachableOnTheNetwork is the control the two tests above
// lean on: a hub with a token keeps its default of every interface, and the
// same dial that a loopback-only hub refuses opens — to a 401.
func TestE2ESignedInHubIsReachableOnTheNetwork(t *testing.T) {
	ip := networkAddr(t)
	s := newExposureScene(t)
	tok := make([]byte, 24)
	if _, err := rand.Read(tok); err != nil {
		t.Fatal(err)
	}
	token := []string{"CLOOP_UI_TOKEN=" + hex.EncodeToString(tok)}
	port := freePort(t)
	h := s.startHub(port, token)

	if !strings.Contains(h.output(), fmt.Sprintf("listening on *:%d", port)) {
		t.Errorf("the hub did not say it listens on every interface:\n%s", h.output())
	}
	if !dialable(ip, port) {
		t.Fatalf("a token-protected hub is not reachable on %s:%d — so the loopback check proves nothing", ip, port)
	}
	resp, err := http.Get("http://" + net.JoinHostPort(ip.String(), strconv.Itoa(port)) + "/api/projects")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /api/projects from the network = %d, want 401", resp.StatusCode)
	}

	sev, msg := s.exposureFinding(port, token)
	if sev != "pass" || !strings.Contains(msg, fmt.Sprintf("requires sign-in on *:%d", port)) ||
		!strings.Contains(msg, "answered 401") {
		t.Errorf("hub doctor: %s: %s", sev, msg)
	}
}
