// Package ciworkflow_test runs the GitHub Actions workflow from the CI/CD
// pipelines guide (docs/guides/ci-pipelines.md, "The workflow") against a real
// cloop hub and a real Claude Code, with GitHub Actions itself played by a
// shell.
//
// # Why this exists
//
// The guide tells an operator to paste a workflow into GitHub Actions, and the
// hub's Settings panel renders the same text with the hub's URL filled in. The
// hub's half of that circuit was tested — pkg/ui/ci_api_test.go drives the
// exchange and the relay with a Go HTTP client — but nothing had ever run the
// workflow: the curl and jq that fetch the job's ID token, the exchange as the
// step spells it, $GITHUB_ENV carrying the session to the next step, and Claude
// Code reading it from there. A GitHub-hosted runner cannot reach a hub on a
// private network, so the only way to run that end to end is to play the
// runner. Doing so found that the workflow as published could not work: Claude
// Code's own default model is outside the allowlist the hub applies by default,
// and a refused exchange left the job green with ANTHROPIC_BASE_URL=null.
//
// # What is real and what is played
//
// Real: the cloop binary, serving HTTPS behind a dashboard token, so what lets
// the pipeline in is the carve-out of the two CI endpoints from hub
// authentication and nothing a test arranged; the workflow text, fetched from
// the hub's Settings API and checked against the guide; bash, curl and jq; and
// Claude Code itself, whenever one is installed.
//
// Played, each as close to the original as the assertions need:
//
//   - GitHub's OIDC issuer and the runner's ID-token endpoint (fakeGitHub): it
//     publishes discovery and a key set at the paths GitHub does, requires the
//     runtime bearer, and signs RS256 tokens carrying GitHub's claims — all of
//     them strings, as GitHub sends them.
//   - The runner (runner_test.go): each `run:` goes through `bash -e`, which is
//     what GitHub uses when a step names no shell, with a fresh $GITHUB_ENV per
//     step and ::add-mask:: applied to the job log.
//   - The Anthropic API (fakeAnthropic): it refuses any credential but the
//     hub's, validates the fields the relay rewrites the way the real API does,
//     and answers in the Messages API's streaming shape.
//
// Every server speaks TLS under a CA minted per run, because production does:
// the verifier's plaintext-loopback exception and the hub's http:// base URL
// are test conveniences that a workflow never meets.
//
// # Claude Code
//
// The agent step runs `npx -y @anthropic-ai/claude-code …`. The runner's npx
// resolves that one package to a locally installed Claude Code rather than the
// registry, so the test needs no network: CLOOP_CIWORKFLOW_CLAUDE names the
// binary, and otherwise `claude` is looked up on PATH. Without one the agent
// step runs testdata/stand-in-claude.sh, which makes the same HTTP call Claude
// Code makes and proves the API path but not the harness; the test says so in
// its log. CLOOP_CIWORKFLOW_REQUIRE_CLAUDE=1 turns that fallback into a
// failure, for a job that installed Claude Code and wants to be sure it ran.
//
// # Against the real API
//
// CLOOP_CIWORKFLOW_ANTHROPIC_API_KEY relays the agent's calls to
// https://api.anthropic.com with that key instead of to the fake, which turns
// "works in principle" into "works". It is opt-in because it spends money.
package ciworkflow_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/hometest"
)

func TestMain(m *testing.M) {
	// Read before Isolate moves HOME: Go's build and module caches default to
	// directories under it, and a build of cloop against empty ones is a cold
	// compile that also needs the network for every module.
	goEnv = captureGoEnv()
	code := hometest.Isolate(m)
	// The build is shared by every test, so no test's cleanup can own it.
	if builtDir != "" {
		_ = os.RemoveAll(builtDir)
	}
	os.Exit(code)
}

// goEnv carries GOCACHE, GOMODCACHE and GOPATH from the invoking environment
// into the build of cloop.
var goEnv []string

func captureGoEnv() []string {
	names := []string{"GOCACHE", "GOMODCACHE", "GOPATH"}
	out, err := exec.Command("go", append([]string{"env"}, names...)...).Output()
	if err != nil {
		return nil
	}
	var env []string
	for i, v := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if i < len(names) && v != "" {
			env = append(env, names[i]+"="+v)
		}
	}
	return env
}

// Environment variables that change what the suite runs against.
const (
	// binEnv supplies a prebuilt cloop. Absent, the suite builds its own.
	binEnv = "CLOOP_CIWORKFLOW_BIN"

	// claudeEnv names the Claude Code binary the agent step runs.
	claudeEnv = "CLOOP_CIWORKFLOW_CLAUDE"

	// requireClaudeEnv fails the suite rather than falling back to the
	// stand-in when no Claude Code is found.
	requireClaudeEnv = "CLOOP_CIWORKFLOW_REQUIRE_CLAUDE"

	// liveKeyEnv relays to the real Anthropic API with this key.
	liveKeyEnv = "CLOOP_CIWORKFLOW_ANTHROPIC_API_KEY"
)

// Per-step deadlines. Each is generous against the step's cost on an unloaded
// machine and still bounded, so a hang fails naming the step rather than
// surfacing as the package timeout.
const (
	buildTimeout = 5 * time.Minute
	readyTimeout = 60 * time.Second
	stepTimeout  = 3 * time.Minute // one workflow step, Claude Code included
	callTimeout  = 30 * time.Second
)

// repoRoot is the module root, two levels above this file.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

var (
	buildOnce sync.Once
	builtDir  string
	builtBin  string
	buildErr  error
	buildOut  []byte
)

// cloopBinary returns the cloop under test, building it once per package run.
func cloopBinary(t *testing.T) string {
	t.Helper()
	if bin := os.Getenv(binEnv); bin != "" {
		if _, err := os.Stat(bin); err != nil {
			t.Fatalf("%s=%s: %v", binEnv, bin, err)
		}
		return bin
	}
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "cloop-ciworkflow-bin-")
		if err != nil {
			buildErr = err
			return
		}
		builtDir = dir
		builtBin = filepath.Join(dir, "cloop")
		ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "build", "-o", builtBin, ".")
		cmd.Dir = repoRoot(t)
		cmd.Env = append(os.Environ(), goEnv...)
		buildOut, buildErr = cmd.CombinedOutput()
	})
	if buildErr != nil {
		t.Fatalf("build cloop: %v\n%s", buildErr, buildOut)
	}
	return builtBin
}

// requireTools skips when the machine cannot play a GitHub-hosted runner. Every
// one of these is preinstalled on ubuntu-latest; a developer machine without
// them is not a failure of the workflow.
func requireTools(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("the workflow runs under bash on a Linux runner; this is %s", runtime.GOOS)
	}
	for _, tool := range runnerTools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed; the played runner needs it", tool)
		}
	}
}

// runnerTools are the commands the workflow's steps and the played checkout
// call, and so the ones the runner's PATH has to reach.
var runnerTools = []string{"bash", "curl", "jq", "git"}

// claudeCode resolves the Claude Code the agent step runs, or "" when there is
// none and the stand-in should run instead.
func claudeCode(t *testing.T) string {
	t.Helper()
	bin := os.Getenv(claudeEnv)
	if bin == "" {
		if p, err := exec.LookPath("claude"); err == nil {
			bin = p
		}
	}
	if bin != "" {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()
		out, err := exec.CommandContext(ctx, bin, "--version").CombinedOutput()
		if err == nil && strings.Contains(string(out), "Claude Code") {
			t.Logf("agent: %s (%s)", bin, strings.TrimSpace(string(out)))
			return bin
		}
		if os.Getenv(claudeEnv) != "" {
			t.Fatalf("%s=%s is not Claude Code: %v\n%s", claudeEnv, bin, err, out)
		}
	}
	if os.Getenv(requireClaudeEnv) != "" {
		t.Fatalf("%s is set and no Claude Code was found (set %s or put claude on PATH)",
			requireClaudeEnv, claudeEnv)
	}
	t.Logf("agent: no Claude Code installed — the agent step runs testdata/stand-in-claude.sh, " +
		"which proves the relay's API path but not the harness")
	return ""
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

// testPKI is a CA minted for one run and a certificate it issued for the
// loopback address every server here listens on.
type testPKI struct {
	caFile   string // the CA alone, PEM
	certFile string // the leaf's chain, PEM
	keyFile  string // the leaf's key, PEM
	leaf     tls.Certificate
	pool     *x509.CertPool

	// bundleFile is what processes that verify TLS are told to trust: the
	// test CA, plus the system roots when the run reaches the real API.
	bundleFile string
}

func newTestPKI(t *testing.T, withSystemRoots bool) *testPKI {
	t.Helper()
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("CA key: %v", err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cloop ci-workflow test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{"localhost"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	p := &testPKI{
		caFile:     filepath.Join(dir, "ca.pem"),
		certFile:   filepath.Join(dir, "cert.pem"),
		keyFile:    filepath.Join(dir, "key.pem"),
		bundleFile: filepath.Join(dir, "bundle.pem"),
		pool:       x509.NewCertPool(),
	}
	p.pool.AddCert(caCert)
	bundle := append([]byte(nil), caPEM...)
	if withSystemRoots {
		sys, err := systemRootsPEM()
		if err != nil {
			t.Fatalf("the real API needs the system's roots as well as the test CA: %v", err)
		}
		bundle = append(bundle, sys...)
	}
	for path, data := range map[string][]byte{
		p.caFile: caPEM, p.certFile: certPEM, p.keyFile: keyPEM, p.bundleFile: bundle,
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	p.leaf, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load leaf: %v", err)
	}
	return p
}

// systemRootsPEM reads the platform's CA bundle. Setting SSL_CERT_FILE
// replaces the roots a Go or OpenSSL process trusts rather than adding to
// them, so a bundle that is to reach a public endpoint has to carry them.
func systemRootsPEM() ([]byte, error) {
	for _, p := range []string{
		"/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu
		"/etc/pki/tls/certs/ca-bundle.crt",   // Fedora, RHEL
		"/etc/ssl/cert.pem",                  // Alpine, macOS
	} {
		if b, err := os.ReadFile(p); err == nil {
			return b, nil
		}
	}
	return nil, os.ErrNotExist
}

// serverTLS is the configuration the fake servers listen with.
func (p *testPKI) serverTLS() *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{p.leaf}, MinVersion: tls.VersionTLS12}
}

// clientTLS trusts the test CA and nothing else.
func (p *testPKI) clientTLS() *tls.Config {
	return &tls.Config{RootCAs: p.pool, MinVersion: tls.VersionTLS12}
}
