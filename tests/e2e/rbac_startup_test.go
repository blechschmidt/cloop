package e2e_test

// `cloop ui` with single sign-on and no role policy (Task 20395), with the
// built binary: the warning lands on stderr — so it survives a redirected
// stdout — and ui.oidc.require_rbac turns the same start into a refusal before
// anything listens. The identity provider is a loopback port nothing listens
// on, so no test here leaves the machine, and every hub is held to loopback.

import (
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ssoOverlay is a per-port overlay turning single sign-on on against an issuer
// on idpPort, with admin_emails and nothing else unless extra adds it.
func ssoOverlay(idpPort, port int, extra string) string {
	return fmt.Sprintf("ui:\n  oidc:\n    enabled: true\n"+
		"    issuer: http://127.0.0.1:%d/realms/main\n"+
		"    client_id: cloop\n"+
		"    redirect_url: http://127.0.0.1:%d/auth/callback\n"+
		"    admin_emails: [ops@example.com]\n%s", idpPort, port, extra)
}

// startSplit starts `cloop ui` on loopback with stdout and stderr kept apart,
// returning once /healthz answers; it fails the test if the hub exits first.
func (s *exposureScene) startSplit(port int) (stdout, stderr func() string) {
	s.t.Helper()
	cmd := exec.Command(s.bin, "ui", "--port", strconv.Itoa(port), "--no-browser", "--listen", "127.0.0.1")
	cmd.Dir = s.dir
	cmd.Env = append([]string(nil), s.env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var outLog, errLog strings.Builder
	out, errw := &syncWriter{w: &outLog}, &syncWriter{w: &errLog}
	cmd.Stdout, cmd.Stderr = out, errw
	read := func(w *syncWriter, b *strings.Builder) func() string {
		return func() string { w.mu.Lock(); defer w.mu.Unlock(); return b.String() }
	}
	stdout, stderr = read(out, &outLog), read(errw, &errLog)
	if err := cmd.Start(); err != nil {
		s.t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	s.t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
	})
	deadline := time.Now().Add(60 * time.Second)
	for {
		select {
		case err := <-done:
			s.t.Fatalf("cloop ui exited before answering (%v):\nstdout:\n%s\nstderr:\n%s", err, stdout(), stderr())
		default:
		}
		if resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", port)); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return stdout, stderr
			}
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("cloop ui did not answer /healthz within 60s:\nstdout:\n%s\nstderr:\n%s", stdout(), stderr())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestE2ESSOHubWithoutAPolicyWarnsOnStderr: started with SSO and admin_emails
// — the Task 20317 hub's shape — `cloop ui` serves, says RBAC is off on its
// banner, and warns on stderr naming the issuer; with default_role: none it
// starts quietly with the deny-by-default banner.
func TestE2ESSOHubWithoutAPolicyWarnsOnStderr(t *testing.T) {
	s := newExposureScene(t)
	idp, port := freePort(t), freePort(t)
	writeTestFile(t, filepath.Join(s.dir, ".cloop", fmt.Sprintf("config.ui-%d.yaml", port)), ssoOverlay(idp, port, ""))

	stdout, stderr := s.startSplit(port)
	want := fmt.Sprintf("warning: RBAC is off: everyone who can sign in through http://127.0.0.1:%d/realms/main has full access.", idp)
	if !strings.Contains(stderr(), want) {
		t.Errorf("stderr does not carry %q:\n%s", want, stderr())
	}
	if !strings.Contains(stdout(), "RBAC: off") || strings.Contains(stdout(), `default role "none"`) {
		t.Errorf("the banner does not say RBAC is off:\n%s", stdout())
	}
	if strings.Contains(stdout(), "RBAC is off: everyone") {
		t.Errorf("the warning went to stdout, where a redirect loses it:\n%s", stdout())
	}

	// The doctor agrees, from the same overlay.
	out, _ := s.runErrStdout(nil, "hub", "doctor", "--port", strconv.Itoa(port), "--offline", "--json")
	if !strings.Contains(out, `"check": "rbac.enforced"`) || !strings.Contains(out, "RBAC is off: everyone who can sign in through") {
		t.Errorf("hub doctor does not fail rbac.enforced:\n%s", out)
	}

	// Deny-by-default: the banner it always had, and no warning.
	port = freePort(t)
	writeTestFile(t, filepath.Join(s.dir, ".cloop", fmt.Sprintf("config.ui-%d.yaml", port)),
		ssoOverlay(idp, port, "    default_role: none\n"))
	stdout, stderr = s.startSplit(port)
	if !strings.Contains(stdout(), `RBAC: 0 role mapping(s), default role "none"`) {
		t.Errorf("deny-by-default banner missing:\n%s", stdout())
	}
	if strings.Contains(stderr(), "RBAC is off") {
		t.Errorf("a hub with a policy warned:\n%s", stderr())
	}
}

// TestE2ERequireRBACRefusesToStart: the opt-in refusal stops the start before
// the hub binds, and says why and what to do.
func TestE2ERequireRBACRefusesToStart(t *testing.T) {
	s := newExposureScene(t)
	idp, port := freePort(t), freePort(t)
	writeTestFile(t, filepath.Join(s.dir, ".cloop", fmt.Sprintf("config.ui-%d.yaml", port)),
		ssoOverlay(idp, port, "    require_rbac: true\n"))

	out, err := s.runErr(nil, "ui", "--port", strconv.Itoa(port), "--no-browser", "--listen", "127.0.0.1")
	if err == nil {
		t.Fatalf("require_rbac let an SSO hub without a policy start:\n%s", out)
	}
	for _, want := range []string{
		"ui.oidc.require_rbac is set",
		fmt.Sprintf("RBAC is off: everyone who can sign in through http://127.0.0.1:%d/realms/main has full access", idp),
		"default_role: none",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the refusal does not say %q:\n%s", want, out)
		}
	}
	if dialable(net.IPv4(127, 0, 0, 1), port) {
		t.Errorf("something listens on :%d after the refusal", port)
	}
}
