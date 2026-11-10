package kubecontroller_test

// helpers_test.go: how the suite drives the cluster, the hub and the tools
// around them. Everything that touches the cluster shells out to the tools an
// operator uses — kubectl, helm, docker, kind — so a failure reads the way it
// would at a terminal.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// tool runs command-line tools with the test's kubeconfig.
type tool struct {
	t          *testing.T
	kubeconfig string
}

// run executes name args with stdin and returns the combined output. It fails
// the test unless allowFail.
func (x tool) run(ctx context.Context, stdin []byte, allowFail bool, name string, args ...string) (string, error) {
	x.t.Helper()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(toolEnv(), "KUBECONFIG="+x.kubeconfig)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if err != nil && !allowFail {
		x.t.Fatalf("%s %s: %v\n%s", name, strings.Join(redactArgs(args), " "), err, tail(out.String(), 60))
	}
	return out.String(), err
}

// out runs kubectl and returns its stdout alone, failing the test with both
// streams when it fails: a value the test parses must not include a warning.
func (x tool) out(ctx context.Context, args ...string) string {
	x.t.Helper()
	stdout, stderr, err := x.capture(ctx, nil, "kubectl", args...)
	if err != nil {
		x.t.Fatalf("kubectl %s: %v\n%s\n%s", strings.Join(redactArgs(args), " "), err, tail(stdout, 30), tail(stderr, 30))
	}
	return strings.TrimSpace(stdout)
}

// may runs kubectl and returns its stdout, or the error and both streams,
// without failing the test: for polling.
func (x tool) may(ctx context.Context, args ...string) (string, error) {
	x.t.Helper()
	stdout, stderr, err := x.capture(ctx, nil, "kubectl", args...)
	if err != nil {
		return stdout + stderr, err
	}
	return strings.TrimSpace(stdout), nil
}

func (x tool) capture(ctx context.Context, stdin []byte, name string, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(toolEnv(), "KUBECONFIG="+x.kubeconfig)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func (x tool) kubectl(ctx context.Context, args ...string) string {
	x.t.Helper()
	out, _ := x.run(ctx, nil, false, "kubectl", args...)
	return out
}

// apply submits objects (each a JSON-able value) with kubectl apply.
func (x tool) apply(ctx context.Context, objects ...any) {
	x.t.Helper()
	b, err := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "List", "items": objects})
	if err != nil {
		x.t.Fatal(err)
	}
	x.run(ctx, b, false, "kubectl", "apply", "-f", "-")
}

// jsonpath reads one jsonpath expression of an object, "" when it is absent
// or the object is gone.
func (x tool) jsonpath(ctx context.Context, ns, kind, name, path string) string {
	x.t.Helper()
	out, err := x.may(ctx, "-n", ns, "get", kind, name, "-o", "jsonpath="+path)
	if err != nil {
		return ""
	}
	return out
}

// realHome is HOME as the test binary found it, before hometest isolated it:
// docker, kind and helm keep their state under it.
var realHome string

// toolEnv is the environment for go, docker, kind, helm and kubectl.
func toolEnv() []string {
	env := os.Environ()
	if realHome != "" {
		env = append(env, "HOME="+realHome)
	}
	return env
}

// processEnv is the environment for the cloop processes the test starts: this
// process's, without anything cloop or a model client would read from it. A
// test run from a hub's own run inherits that hub's CLOOP_SECRET_KEY and task
// id; a test hub must have neither.
func processEnv(extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch {
		case strings.HasPrefix(k, "CLOOP_"), strings.HasPrefix(k, "ANTHROPIC_"), strings.HasPrefix(k, "CLAUDE_"),
			k == "KUBECONFIG", k == "HOME", k == "XDG_CONFIG_HOME", k == "CREDENTIALS_DIRECTORY":
			continue
		}
		env = append(env, kv)
	}
	return append(env, extra...)
}

// redactArgs keeps a credential passed by flag out of a failure message.
func redactArgs(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		if strings.Contains(a, "cloop_pool1_") || strings.Contains(a, "BEGIN CERTIFICATE") {
			a = "<redacted>"
		}
		out[i] = a
	}
	return out
}

func tail(s string, lines int) string {
	parts := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(parts) > lines {
		parts = parts[len(parts)-lines:]
	}
	return strings.Join(parts, "\n")
}

// waitFor polls cond every interval until it reports done, failing the test
// after timeout with what it waited for and the last thing cond said.
func waitFor(t *testing.T, what string, timeout time.Duration, cond func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	last := ""
	for {
		done, note := cond()
		if done {
			return
		}
		if note != "" {
			last = note
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s; last: %s", timeout, what, last)
		}
		time.Sleep(2 * time.Second)
	}
}

// hubClient speaks the test hub's REST API over its TLS, as its administrator
// or as a pool controller.
type hubClient struct {
	t     *testing.T
	base  string
	token string
	http  *http.Client
}

// newHubClient trusts exactly the hub's self-signed certificate.
func newHubClient(t *testing.T, base, token string, certPEM []byte) hubClient {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("the hub's certificate is not PEM")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	return hubClient{t: t, base: base, token: token, http: &http.Client{Timeout: 60 * time.Second, Transport: tr}}
}

// as is the same client presenting another bearer token.
func (h hubClient) as(token string) hubClient {
	h.token = token
	return h
}

// call sends method path with body (JSON-encoded unless nil) and decodes a
// 2xx response into out when it is non-nil.
func (h hubClient) call(method, path string, body, out any) (int, string) {
	h.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			h.t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, h.base+path, rd)
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.http.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if out != nil && resp.StatusCode < 300 {
		if err := json.Unmarshal(raw, out); err != nil {
			h.t.Fatalf("%s %s: decode %q: %v", method, path, tail(string(raw), 5), err)
		}
	}
	return resp.StatusCode, string(raw)
}

// get is a GET that reports a transport error instead of failing the test:
// for polling a hub that may not be listening yet.
func (h hubClient) get(path string) (int, string, error) {
	req, err := http.NewRequest(http.MethodGet, h.base+path, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	resp, err := h.http.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(raw), nil
}

// must is call failing the test on anything but a 2xx.
func (h hubClient) must(method, path string, body, out any) {
	h.t.Helper()
	if code, raw := h.call(method, path, body, out); code >= 300 {
		h.t.Fatalf("%s %s: HTTP %d: %s", method, path, code, tail(raw, 10))
	}
}

// hostAddressFor is the address of this host's interface on the network a
// cluster node is on: the docker bridge a kind or k3s-in-docker node hangs
// off, which the node's Pods reach through its NAT. "" when no interface's
// network holds nodeIP.
func hostAddressFor(nodeIP string) string {
	ip := net.ParseIP(nodeIP)
	if ip == nil {
		return ""
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok || n.IP.To4() == nil || n.IP.Equal(ip) {
				continue
			}
			if n.Contains(ip) {
				return n.IP.String()
			}
		}
	}
	return ""
}

// freePort returns a port nothing listens on now, on addr.
func freePort(t *testing.T, addr string) int {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(addr, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// randomAlnum is n characters of [a-z0-9].
func randomAlnum(t *testing.T, n int) string {
	t.Helper()
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		x, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			t.Fatal(err)
		}
		b[i] = alphabet[x.Int64()]
	}
	return string(b)
}

// repoRoot is the module root, found from this file's own directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test's source file")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o755); err != nil {
		t.Fatal(err)
	}
}

func envOr(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

// goBuild builds a static cloop for the image's alpine.
func goBuild(ctx context.Context, t *testing.T, root, out string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", out, ".")
	cmd.Dir = root
	cmd.Env = append(toolEnv(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
}

// runIn runs a command in dir and returns its combined output, failing the
// test with it when the command fails.
func runIn(ctx context.Context, t *testing.T, dir string, env []string, name string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir, cmd.Env = dir, env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", filepath.Base(name), strings.Join(redactArgs(args), " "), err, tail(string(out), 40))
	}
	return string(out)
}

// resultLine is one probe check's report, wherever the log prefixed it.
var resultLine = regexp.MustCompile(`RESULT ([A-Z][A-Z0-9]*) (PASS|FAIL)(?: (.*))?$`)

type result struct {
	pass   bool
	detail string
}

// parseResults reads the probe's RESULT lines out of text, the last report of
// each id winning.
func parseResults(text string) map[string]result {
	out := map[string]result{}
	for _, l := range strings.Split(text, "\n") {
		if m := resultLine.FindStringSubmatch(strings.TrimRight(l, "\r")); m != nil {
			out[m[1]] = result{pass: m[2] == "PASS", detail: m[3]}
		}
	}
	return out
}

// expectPass fails the test for every id that did not report PASS.
func expectPass(t *testing.T, what string, results map[string]result, ids ...string) {
	t.Helper()
	for _, id := range ids {
		r, ok := results[id]
		switch {
		case !ok:
			t.Errorf("%s: no %s line in the run's output", what, id)
		case !r.pass:
			t.Errorf("%s: %s FAIL %s", what, id, r.detail)
		default:
			t.Logf("%s: %s PASS %s", what, id, r.detail)
		}
	}
}

func fmtDuration(d time.Duration) string { return d.Round(100 * time.Millisecond).String() }
