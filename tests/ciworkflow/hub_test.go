package ciworkflow_test

// hub_test.go runs the cloop binary as a hub: `cloop ui` over HTTPS, behind a
// dashboard token, with CI federation pointed at the fake GitHub and the fake
// (or real) Anthropic API.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
)

// hub is a running `cloop ui`.
type hub struct {
	url   string // https://127.0.0.1:<port>
	dir   string // the hub's working directory
	token string // the dashboard token an operator authenticates with

	client *http.Client
	cmd    *exec.Cmd
	log    *lockedBuffer
	done   chan struct{}

	// argv and env start the process, so restart can start it again in the
	// same directory, on the same port, as a restarted service is.
	argv []string
	env  []string
}

// hubOptions is what differs between the worlds the tests build.
type hubOptions struct {
	issuer   string // the OIDC issuer federation verifies against
	upstream string // Anthropic API origin; "" for the real one
	apiKey   string // the credential the relay attaches
}

// lockedBuffer collects the hub's output, which is written by the process's
// pipe copier and read by failure messages on the test goroutine.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// tail returns the end of the hub's output, for failure messages.
func (h *hub) tail() string {
	s := h.log.String()
	if len(s) > 6000 {
		s = "…" + s[len(s)-6000:]
	}
	return s
}

// startHub writes a hub configuration, starts the binary and waits for it to
// report ready.
//
// Federation is left switched off in the file and turned on through the
// Settings API afterwards, which is the path the guide describes for an
// operator. What the file does carry is what an operator could not set from
// the panel: the Anthropic credential, and the issuer — which on a real hub is
// GitHub's default and here has to be the fake.
func startHub(t *testing.T, pki *testPKI, opts hubOptions) *hub {
	t.Helper()
	bin := cloopBinary(t)
	dir := t.TempDir()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cfg := config.Default()
	cfg.Anthropic.APIKey = opts.apiKey
	cfg.UI.CI = config.CIConfig{
		Issuer:          opts.issuer,
		UpstreamBaseURL: opts.upstream,
	}
	if err := config.Save(dir, cfg); err != nil {
		t.Fatalf("write hub config: %v", err)
	}

	h := &hub{
		dir:   dir,
		token: "hub-operator-" + randHex(t, 16),
		log:   &lockedBuffer{},
		done:  make(chan struct{}),
		client: &http.Client{
			Timeout:   callTimeout,
			Transport: &http.Transport{TLSClientConfig: pki.clientTLS()},
		},
	}
	port := freePort(t)
	h.url = "https://127.0.0.1:" + strconv.Itoa(port)

	h.argv = []string{bin, "ui", "--port", strconv.Itoa(port), "--no-browser",
		"--tls-cert", pki.certFile, "--tls-key", pki.keyFile}
	// A clean environment, not os.Environ(): an ANTHROPIC_API_KEY or a
	// CLAUDE_CONFIG_DIR inherited from whoever runs the suite must not become
	// the hub's credential, and the hub must reach the fakes only through the
	// trust it was given here.
	h.env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"LANG=C.UTF-8",
		"NO_COLOR=1",
		"TERM=dumb",
		"TMPDIR=" + os.TempDir(),
		// The hub dials the issuer for its key set and the upstream for the
		// relay; both present certificates from the test CA.
		"SSL_CERT_FILE=" + pki.bundleFile,
		"CLOOP_UI_TOKEN=" + h.token,
	}
	h.launch(t)
	t.Cleanup(func() { h.stop(t) })
	return h
}

// launch starts the hub process and waits for it to report ready.
func (h *hub) launch(t *testing.T) {
	t.Helper()
	h.cmd = exec.Command(h.argv[0], h.argv[1:]...)
	h.cmd.Dir = h.dir
	h.cmd.Env = h.env
	h.cmd.Stdout, h.cmd.Stderr = h.log, h.log
	h.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := h.cmd.Start(); err != nil {
		t.Fatalf("start hub: %v", err)
	}
	done := make(chan struct{})
	h.done = done
	cmd := h.cmd
	go func() {
		_ = cmd.Wait()
		close(done)
	}()

	deadline := time.Now().Add(readyTimeout)
	for {
		select {
		case <-done:
			t.Fatalf("hub exited during startup:\n%s", h.tail())
		default:
		}
		resp, err := h.client.Get(h.url + "/readyz")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("hub not ready at %s after %s (last error: %v):\n%s",
				h.url, readyTimeout, err, h.tail())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// halt signals the hub's process group and waits for it to exit: SIGTERM as
// systemd stops a service, SIGKILL as a crash or an OOM kill does.
func (h *hub) halt(t *testing.T, sig syscall.Signal) {
	t.Helper()
	_ = syscall.Kill(-h.cmd.Process.Pid, sig)
	select {
	case <-h.done:
	case <-time.After(30 * time.Second):
		t.Fatalf("the hub did not exit within 30s of %v:\n%s", sig, h.tail())
	}
}

// restart stops the hub with sig and starts it again in the same directory,
// on the same port — a nightly deploy, or a rolling update of one replica.
func (h *hub) restart(t *testing.T, sig syscall.Signal) {
	t.Helper()
	h.halt(t, sig)
	h.launch(t)
}

// stop terminates the hub's process group and waits for it.
func (h *hub) stop(t *testing.T) {
	select {
	case <-h.done:
		return
	default:
	}
	_ = syscall.Kill(-h.cmd.Process.Pid, syscall.SIGTERM)
	select {
	case <-h.done:
	case <-time.After(15 * time.Second):
		_ = syscall.Kill(-h.cmd.Process.Pid, syscall.SIGKILL)
		<-h.done
		t.Logf("hub did not stop on SIGTERM and was killed:\n%s", h.tail())
	}
}

// freePort asks the kernel for an unused port. The window between closing the
// probe and the hub binding it is a race nothing else on a test machine is
// likely to win; if something does, the hub fails to start and says so.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe port: %v", err)
	}
	defer l.Close() //nolint:errcheck
	return l.Addr().(*net.TCPAddr).Port
}

// api makes an operator call with the dashboard token and returns the status
// and body.
func (h *hub) api(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, h.url+path, rdr)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v\nhub output:\n%s", method, path, err, h.tail())
	}
	defer resp.Body.Close() //nolint:errcheck
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s %s: read: %v", method, path, err)
	}
	return resp.StatusCode, out
}

// mustAPI is api for calls that have to succeed, decoding the reply into dst.
func (h *hub) mustAPI(t *testing.T, method, path string, body, dst any) {
	t.Helper()
	status, out := h.api(t, method, path, body)
	if status != http.StatusOK {
		t.Fatalf("%s %s: HTTP %d: %s", method, path, status, out)
	}
	if dst != nil {
		if err := json.Unmarshal(out, dst); err != nil {
			t.Fatalf("%s %s: decode %s: %v", method, path, out, err)
		}
	}
}

// ciSettings is the part of GET /api/ci/config the tests read.
type ciSettings struct {
	Enabled       bool     `json:"enabled"`
	Issuer        string   `json:"issuer"`
	Audience      string   `json:"audience"`
	DefaultModels []string `json:"default_models"`
	UpstreamReady bool     `json:"upstream_ready"`
	BaseURL       string   `json:"base_url"`
	Error         string   `json:"error"`
	Snippet       string   `json:"snippet"`
}

// enableFederation turns CI federation on the way the Settings panel does.
func (h *hub) enableFederation(t *testing.T) ciSettings {
	t.Helper()
	var s ciSettings
	h.mustAPI(t, http.MethodPut, "/api/ci/config", map[string]any{"enabled": true}, &s)
	if !s.Enabled || !s.UpstreamReady || s.Error != "" {
		t.Fatalf("federation did not come up: %+v", s)
	}
	return s
}

// addRule allowlists a pipeline and returns the rule's id.
func (h *hub) addRule(t *testing.T, rule map[string]any) string {
	t.Helper()
	var out struct {
		ID string `json:"id"`
	}
	h.mustAPI(t, http.MethodPost, "/api/ci/rules", rule, &out)
	if out.ID == "" {
		t.Fatal("rule was created without an id")
	}
	return out.ID
}

// ciExchange is one row of GET /api/ci/exchanges.
type ciExchange struct {
	Accepted   bool   `json:"accepted"`
	Reason     string `json:"reason"`
	Detail     string `json:"detail"`
	RuleName   string `json:"rule_name"`
	SessionID  string `json:"session_id"`
	Repository string `json:"repository"`
	Ref        string `json:"ref"`
	Subject    string `json:"subject"`
}

func (h *hub) exchanges(t *testing.T) []ciExchange {
	t.Helper()
	var out struct {
		Exchanges []ciExchange `json:"exchanges"`
	}
	h.mustAPI(t, http.MethodGet, "/api/ci/exchanges", nil, &out)
	return out.Exchanges
}

// ciSession is one row of GET /api/ci/sessions.
type ciSession struct {
	ID         string   `json:"id"`
	RuleName   string   `json:"rule_name"`
	Repository string   `json:"repository"`
	Ref        string   `json:"ref"`
	Workflow   string   `json:"workflow"`
	Actor      string   `json:"actor"`
	RunURL     string   `json:"run_url"`
	Models     []string `json:"models"`
	Remaining  int      `json:"remaining_requests"`
	Usage      struct {
		Requests     int64 `json:"requests"`
		Denied       int64 `json:"denied"`
		InputTokens  int64 `json:"input_tokens"`
		OutputTokens int64 `json:"output_tokens"`
	} `json:"usage"`
}

func (h *hub) sessions(t *testing.T) []ciSession {
	t.Helper()
	var out struct {
		Sessions []ciSession `json:"sessions"`
	}
	h.mustAPI(t, http.MethodGet, "/api/ci/sessions", nil, &out)
	return out.Sessions
}

// auditEvents returns the hub's audit events of one type.
func (h *hub) auditEvents(t *testing.T, eventType string) []map[string]any {
	t.Helper()
	var out struct {
		Events []map[string]any `json:"events"`
	}
	h.mustAPI(t, http.MethodGet, "/api/audit?limit=200&event_type="+eventType, nil, &out)
	return out.Events
}

// exchangeRaw presents a token at /api/ci/token the way the workflow does,
// with no hub credential, and returns the status.
func (h *hub) exchangeRaw(t *testing.T, idToken string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"token": idToken})
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url+"/api/ci/token", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// errNotFound marks a heading or code block the guide does not have.
var errNotFound = errors.New("not found")

// docsWorkflow extracts the YAML block under "## The workflow" in the guide.
func docsWorkflow(t *testing.T) string {
	t.Helper()
	path := filepath.Join(repoRoot(t), "docs", "guides", "ci-pipelines.md")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the guide: %v", err)
	}
	block, err := yamlBlockUnder(string(raw), "## The workflow")
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return block
}

// yamlBlockUnder returns the first ```yaml fence after heading and before the
// next heading of the same level.
func yamlBlockUnder(doc, heading string) (string, error) {
	lines := strings.Split(doc, "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == heading {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return "", fmt.Errorf("heading %q: %w", heading, errNotFound)
	}
	level := strings.SplitN(heading, " ", 2)[0] + " "
	var block []string
	in := false
	for _, l := range lines[start:] {
		switch {
		case !in && strings.HasPrefix(l, level):
			return "", fmt.Errorf("no ```yaml block under %q: %w", heading, errNotFound)
		case !in && strings.TrimSpace(l) == "```yaml":
			in = true
		case in && strings.TrimSpace(l) == "```":
			return strings.Join(block, "\n"), nil
		case in:
			block = append(block, l)
		}
	}
	return "", fmt.Errorf("unterminated ```yaml block under %q", heading)
}
