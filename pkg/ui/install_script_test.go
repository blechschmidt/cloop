// Handler tests for GET /install.sh and the enrollment response that points at
// it (Task 20172).
//
// Two properties carry the security weight, and neither is visible by reading
// the handler in isolation:
//
//   - the endpoint refuses plaintext, because its body is piped into a root
//     shell on a device that has not yet decided whom to trust; and
//   - RBAC is evaluated before that refusal, so an unauthorized caller cannot
//     use the difference between the two errors to learn whether the hub has
//     TLS configured.

package ui

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// installScriptRequest builds a request for /install.sh as a reverse proxy
// would forward it: the hop to this process is plaintext, and the client's leg
// is described by X-Forwarded-Proto. That is the shape of every hosted
// deployment, so it is the default the tests exercise.
//
// The http:// target is deliberate — httptest.NewRequest populates r.TLS from
// an https:// target, which would make every case here take the direct-TLS
// branch and leave the forwarded-header logic untested.
func installScriptRequest(method string, secure bool) *http.Request {
	r := httptest.NewRequest(method, "http://hub.example.com/install.sh", nil)
	if secure {
		r.Header.Set("X-Forwarded-Proto", "https")
	}
	return r
}

func TestInstallScript_RefusesPlaintextHTTP(t *testing.T) {
	s := &Server{WorkDir: t.TempDir()}
	rr := httptest.NewRecorder()
	s.handleInstallScript(rr, installScriptRequest(http.MethodGet, false))

	if rr.Code != http.StatusForbidden {
		t.Fatalf("GET /install.sh over plaintext = %d, want 403", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "plaintext") {
		t.Errorf("the refusal does not say why:\n%s", body)
	}
	// A shell reading this must not find something it would execute.
	if strings.Contains(body, "#!/bin/sh") {
		t.Error("the plaintext refusal still returned a script body")
	}
	// A redirect would be followed silently by `curl -L`, and the operator
	// would never learn the first request went in the clear.
	if loc := rr.Header().Get("Location"); loc != "" {
		t.Errorf("the refusal redirects to %q instead of refusing", loc)
	}
}

// TestInstallScript_HonoursForwardedProto: every hosted deployment terminates
// TLS at a proxy, so r.TLS is nil on a request the browser made over HTTPS.
// Refusing those would make the endpoint useless in exactly the topology it
// exists for.
func TestInstallScript_HonoursForwardedProto(t *testing.T) {
	s := &Server{WorkDir: t.TempDir()}
	for _, proto := range []string{"https", "https, http", "HTTPS"} {
		r := installScriptRequest(http.MethodGet, false)
		r.Header.Set("X-Forwarded-Proto", proto)
		rr := httptest.NewRecorder()
		s.handleInstallScript(rr, r)
		if rr.Code != http.StatusOK {
			t.Errorf("X-Forwarded-Proto: %q = %d, want 200", proto, rr.Code)
		}
	}
	for _, proto := range []string{"http", "http, https", ""} {
		r := installScriptRequest(http.MethodGet, false)
		r.Header.Set("X-Forwarded-Proto", proto)
		rr := httptest.NewRecorder()
		s.handleInstallScript(rr, r)
		if rr.Code != http.StatusForbidden {
			t.Errorf("X-Forwarded-Proto: %q = %d, want 403 — the client's leg was plaintext",
				proto, rr.Code)
		}
	}

	// And a direct TLS connection needs no header at all.
	direct := httptest.NewRequest(http.MethodGet, "https://hub.example.com/install.sh", nil)
	if direct.TLS == nil {
		t.Fatal("httptest.NewRequest no longer populates TLS for an https target; this case is vacuous")
	}
	rr := httptest.NewRecorder()
	s.handleInstallScript(rr, direct)
	if rr.Code != http.StatusOK {
		t.Errorf("a direct TLS request = %d, want 200", rr.Code)
	}
}

// TestInstallScript_RendersTheDeploymentFromTheRequest: the hub's own config
// frequently names a URL the operator never reaches, so the address a device
// is told to dial has to come from the request that asked.
func TestInstallScript_RendersTheDeploymentFromTheRequest(t *testing.T) {
	s := &Server{WorkDir: t.TempDir()}
	r := installScriptRequest(http.MethodGet, true)
	r.Host = "internal-pod-7:8080"
	r.Header.Set("X-Forwarded-Host", "cloop.example.com")

	rr := httptest.NewRecorder()
	s.handleInstallScript(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /install.sh = %d, want 200", rr.Code)
	}
	body := rr.Body.String()

	want := "wss://cloop.example.com" + executorConnectPath
	if !strings.Contains(body, want) {
		t.Errorf("the script does not tell the device to dial %s", want)
	}
	if strings.Contains(body, "internal-pod-7") {
		t.Error("the script leaked the hub's internal hostname; no device can reach it")
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain so a browser shows it rather than downloading it", ct)
	}
	if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing X-Content-Type-Options: nosniff")
	}
	if cc := rr.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q — a cached installer pins a rotated key", cc)
	}
	// Nothing may run until the whole body has arrived.
	if !strings.Contains(body, `main "$@"`) {
		t.Error("the script does not defer execution to a final call; a truncated download would run half of it")
	}
}

// TestInstallScript_CarriesTheCertificatePin is the reason enrollment is not
// simply "trust whatever answers at this hostname".
func TestInstallScript_CarriesTheCertificatePin(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "hub.crt")
	keyPath := filepath.Join(dir, "hub.key")
	pin, err := tlsconf.GenerateSelfSigned(certPath, keyPath, tlsconf.SelfSignedOptions{
		Hosts: []string{"cloop.example.com"},
	})
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}

	s := &Server{WorkDir: dir, TLSCertFile: certPath, TLSKeyFile: keyPath}
	rr := httptest.NewRecorder()
	s.handleInstallScript(rr, installScriptRequest(http.MethodGet, true))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /install.sh = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), pin) {
		t.Errorf("the script does not carry the hub's SPKI pin %q", pin)
	}
}

// TestInstallScript_SaysSoWhenThereIsNoPin: silence would read as "pinned".
func TestInstallScript_SaysSoWhenThereIsNoPin(t *testing.T) {
	s := &Server{WorkDir: t.TempDir()}
	rr := httptest.NewRecorder()
	s.handleInstallScript(rr, installScriptRequest(http.MethodGet, true))
	body := rr.Body.String()
	if !strings.Contains(body, `CLOOP_PIN=''`) {
		t.Error("an unpinned deployment did not render an explicitly empty pin")
	}
	if !strings.Contains(body, "no certificate pin") {
		t.Error("the script does not warn the operator that the deployment is unpinned")
	}
}

// TestInstallScript_CarriesNoCredential: the endpoint is RBAC-gated but not
// per-enrollment, so a body that contained a token would hand every reader a
// working one.
func TestInstallScript_CarriesNoCredential(t *testing.T) {
	s := &Server{WorkDir: t.TempDir()}
	rr := httptest.NewRecorder()
	s.handleInstallScript(rr, installScriptRequest(http.MethodGet, true))
	body := rr.Body.String()
	// The usage text mentions the bundle prefix by way of an example, so
	// match only a prefix followed by a real base64url payload.
	if loc := realBundleRE.FindString(body); loc != "" {
		t.Errorf("the served script embeds an enrollment bundle: %s", loc)
	}
	if strings.Contains(body, "--token ") {
		t.Error("the served script passes a token on a command line")
	}
}

// realBundleRE matches an actual encoded bundle rather than the "cloopenroll1.…"
// placeholder in the script's own usage text.
var realBundleRE = regexp.MustCompile(`cloopenroll1\.[A-Za-z0-9_-]{8,}`)

func TestInstallScript_RejectsNonGET(t *testing.T) {
	s := &Server{WorkDir: t.TempDir()}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rr := httptest.NewRecorder()
		s.handleInstallScript(rr, installScriptRequest(method, true))
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /install.sh = %d, want 405", method, rr.Code)
		}
		if allow := rr.Header().Get("Allow"); !strings.Contains(allow, http.MethodGet) {
			t.Errorf("%s /install.sh: Allow = %q", method, allow)
		}
	}
}

// TestInstallScript_HeadReturnsNoBody keeps a probe from being served the
// whole script.
func TestInstallScript_HeadReturnsNoBody(t *testing.T) {
	s := &Server{WorkDir: t.TempDir()}
	rr := httptest.NewRecorder()
	s.handleInstallScript(rr, installScriptRequest(http.MethodHead, true))
	if rr.Code != http.StatusOK {
		t.Fatalf("HEAD /install.sh = %d, want 200", rr.Code)
	}
	if rr.Body.Len() != 0 {
		t.Errorf("HEAD returned %d bytes of body", rr.Body.Len())
	}
}

// TestInstallScriptRouteMatchesTheConstant guards the one duplication in this
// feature: routes.go spells the path as a literal (the authz drift tests parse
// the table as source), while the handler and the copy-paste snippet use the
// constant.
func TestInstallScriptRouteMatchesTheConstant(t *testing.T) {
	srv := &Server{WorkDir: t.TempDir()}
	for _, rs := range srv.routeTable() {
		if rs.Pattern == installScriptPath {
			return
		}
	}
	t.Fatalf("no route registered for installScriptPath (%q) — the literal in routes.go has drifted",
		installScriptPath)
}

// TestInstallScript_RBACIsEvaluatedBeforeTheTLSRefusal.
//
// Ordering matters: if the TLS check ran first, a caller with no executor
// authority could probe whether the hub has TLS configured by comparing the
// two 403 bodies. Gating first means every unauthorized caller sees the same
// thing regardless of the deployment's transport.
func TestInstallScript_RBACIsEvaluatedBeforeTheTLSRefusal(t *testing.T) {
	f := newRBACFixture(t)

	get := func(c *http.Client, secure bool) (int, string) {
		req, err := http.NewRequest(http.MethodGet, f.ts.URL+installScriptPath, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		if secure {
			req.Header.Set("X-Forwarded-Proto", "https")
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", installScriptPath, err)
		}
		defer resp.Body.Close()
		blob, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(blob)
	}

	// Only executor.manage may fetch it. A viewer and an operator are
	// refused by the gate, over TLS or not, and with the same body.
	for name, c := range map[string]*http.Client{
		"viewer": f.viewer, "operator": f.operator, "unmapped": f.unmapped,
	} {
		for _, secure := range []bool{true, false} {
			code, body := get(c, secure)
			if code != http.StatusForbidden {
				t.Errorf("%s (tls=%v): GET /install.sh = %d, want 403", name, secure, code)
			}
			if strings.Contains(body, "plaintext") {
				t.Errorf("%s (tls=%v): the RBAC refusal disclosed the deployment's transport:\n%s",
					name, secure, body)
			}
		}
	}

	// An admin reaches the handler, and then the transport check applies.
	if code, body := get(f.admin, true); code != http.StatusOK {
		t.Errorf("admin over TLS: GET /install.sh = %d, want 200\n%s", code, body)
	}
	code, body := get(f.admin, false)
	if code != http.StatusForbidden {
		t.Errorf("admin over plaintext: GET /install.sh = %d, want 403", code)
	}
	if !strings.Contains(body, "plaintext") {
		t.Errorf("admin over plaintext got a refusal that does not explain itself:\n%s", body)
	}
}

// ── The enrollment response that points at it ───────────────────────────────

// TestExecutorEnroll_OffersTheOneCommandInstaller: the panel's snippet must
// carry the bundle out-of-band and point at this hub's own /install.sh.
func TestExecutorEnroll_OffersTheOneCommandInstaller(t *testing.T) {
	dir := setupProjectDir(t, "enroll installer", nil)
	ts := newTestServer(t, dir, nil)

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/executors/enroll",
		strings.NewReader(`{"name":"edge-1"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "cloop.example.com")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST enroll: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST enroll = %d, want 200", resp.StatusCode)
	}
	var got enrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if got.Bundle == "" {
		t.Fatal("the enroll response carries no bundle; the installer has nothing to redeem")
	}
	bundle, err := remote.DecodeBundle(got.Bundle)
	if err != nil {
		t.Fatalf("the bundle does not decode: %v", err)
	}
	if bundle.Token != got.Token {
		t.Error("the bundle's token differs from the one shown; one of the two would not authenticate")
	}
	if bundle.Server != "wss://cloop.example.com"+executorConnectPath {
		t.Errorf("bundle server = %q, want it derived from the forwarded host", bundle.Server)
	}

	if got.InstallCommand == "" {
		t.Fatal("no one-command installer offered over HTTPS")
	}
	for _, want := range []string{"CLOOP_ENROLL_BUNDLE=", got.Bundle, "https://cloop.example.com/install.sh"} {
		if !strings.Contains(got.InstallCommand, want) {
			t.Errorf("the install command does not contain %q:\n  %s", want, got.InstallCommand)
		}
	}
	// argv is world-readable through /proc; the bundle must ride in the
	// environment instead.
	if strings.Contains(got.InstallCommand, "-s -- --bundle") {
		t.Error("the install command passes the bundle as an argument, exposing it to every local user")
	}
}

// TestExecutorEnroll_WithholdsTheInstallerOverPlaintext: offering a command
// that /install.sh will refuse sends the operator to a device to watch curl
// fail.
func TestExecutorEnroll_WithholdsTheInstallerOverPlaintext(t *testing.T) {
	dir := setupProjectDir(t, "enroll plaintext", nil)
	ts := newTestServer(t, dir, nil)

	resp, err := http.Post(ts.URL+"/api/executors/enroll", "application/json",
		strings.NewReader(`{"name":"edge-2"}`))
	if err != nil {
		t.Fatalf("POST enroll: %v", err)
	}
	defer resp.Body.Close()
	var got enrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.InstallCommand != "" {
		t.Errorf("an installer command was offered over plaintext: %s", got.InstallCommand)
	}
	if got.InstallUnavailable == "" {
		t.Error("no explanation for the missing installer — the operator would think it is a bug")
	}
	// The manual path must still work: it is the fallback the note points at.
	if !strings.HasPrefix(got.Command, "cloop executor agent ") {
		t.Errorf("the manual command is missing: %q", got.Command)
	}
}

// TestShellSingleQuote pins the escaping used to embed the bundle in the
// snippet: a value that changed the meaning of the pasted command would be a
// command injection into the operator's own root shell.
func TestShellSingleQuote(t *testing.T) {
	cases := map[string]string{
		"cloopenroll1.abc":  `'cloopenroll1.abc'`,
		"":                  `''`,
		"a'b":               `'a'\''b'`,
		"$(rm -rf /)":       `'$(rm -rf /)'`,
		"`whoami`":          "'`whoami`'",
		"x; touch /tmp/pwn": `'x; touch /tmp/pwn'`,
	}
	for in, want := range cases {
		if got := shellSingleQuote(in); got != want {
			t.Errorf("shellSingleQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestTransportPinToleratesAnUnreadableCertificate: an installer without a pin
// is worse than one with, but an installer that 500s is worse than both.
func TestTransportPinToleratesAnUnreadableCertificate(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "not-a-cert.pem")
	if err := os.WriteFile(bad, []byte("this is not PEM"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	s := &Server{WorkDir: dir, TLSCertFile: bad}
	if pin := s.transportPin(); pin != "" {
		t.Errorf("transportPin = %q for an unreadable certificate, want \"\"", pin)
	}
	rr := httptest.NewRecorder()
	s.handleInstallScript(rr, installScriptRequest(http.MethodGet, true))
	if rr.Code != http.StatusOK {
		t.Errorf("GET /install.sh with an unreadable certificate = %d, want 200", rr.Code)
	}
}
