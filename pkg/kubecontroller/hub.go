package kubecontroller

// hub.go is the controller's side of the hub's pool-controller endpoints
// (Task 20482): the demand feed, runner configurations, and retirement.
//
// The connection is the one an agent makes: TLS verified against the system
// store or the pool's hubCABundle, then pinned to hubCAPin when it is set, and
// never plaintext — the controller credential travels in its Authorization
// header and nowhere else. The credential is read from its Secret when the
// feed starts, again whenever the hub refuses it (it may have been rotated),
// and on a timer, so a rotated credential takes effect without a restart.
//
// The feed is the long-poll form: each request returns at once when the pool
// changed since the revision the controller holds, and otherwise when it
// changes or the wait runs out; the controller asks again immediately. On a
// network failure it backs off exponentially, with jitter, to 30 seconds, and
// the pool reports Degraded with what failed until the hub answers again.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// The hub's pool-controller endpoints.
const (
	hubFeedPath    = "/api/pool-controller/feed"
	hubRunnersPath = "/api/pool-controller/runners"
	hubRetirePath  = "/api/pool-controller/runners/retire"
)

// Feed timing.
var (
	// feedWait is the long-poll's wait, under the hub's 60-second ceiling and
	// the idle timeouts of the proxies in front of most hubs.
	feedWait = 50 * time.Second
	// feedBackoffBase and feedBackoffMax bound the retry delay after a failure.
	feedBackoffBase = time.Second
	feedBackoffMax  = 30 * time.Second
	// credentialRefresh re-reads the credential Secret this often while the
	// feed is healthy.
	credentialRefresh = 5 * time.Minute
	// maxHubResponse bounds what the controller reads of one hub response.
	maxHubResponse int64 = 8 << 20
	// hubCallTimeout bounds a mint or a retirement, and the slack a feed
	// request gets beyond its wait: a hub that holds a connection without
	// answering must not hold a reconcile worker with it.
	hubCallTimeout = 30 * time.Second
)

// hubConfig is what a pool's hub connection is made from. Two configs that
// are equal share a connection; any change restarts the feed.
type hubConfig struct {
	URL      string
	Pin      string
	CABundle string
	// Namespace, Secret and Key locate the credential.
	Namespace string
	Secret    string
	Key       string
}

// FeedMessage is one message of the demand feed.
type FeedMessage struct {
	Type     string                `json:"type"`
	Snapshot executorpool.Snapshot `json:"snapshot"`
	Pool     executorpool.Spec     `json:"pool"`
	Server   string                `json:"server"`
	Pin      string                `json:"pin,omitempty"`
}

// HubError is a refusal from the hub.
type HubError struct {
	Status  int
	Code    string
	Message string
}

func (e *HubError) Error() string {
	msg := strings.TrimSpace(e.Message)
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	if e.Code != "" {
		return fmt.Sprintf("the hub answered %d (%s): %s", e.Status, e.Code, msg)
	}
	return fmt.Sprintf("the hub answered %d: %s", e.Status, msg)
}

// Unauthorized reports whether the hub refused the credential: it is
// malformed, unknown, revoked, or its pool was revoked.
func (e *HubError) Unauthorized() bool { return e.Status == http.StatusUnauthorized }

// AtCapacity reports whether the hub refused runners past max_runners.
func (e *HubError) AtCapacity() bool { return e.Status == http.StatusConflict }

// hubClient talks to one hub for one pool.
type hubClient struct {
	base *url.URL
	http *http.Client
	// credential returns the controller credential; refused is told when
	// the hub refuses it, so the next request reads the Secret again.
	credential func(ctx context.Context) (string, error)
	refused    func()
	userAgent  string
}

// newHubClient builds the client for cfg over transport (nil builds the
// pinned TLS one); creds supplies the credential.
func newHubClient(cfg hubConfig, creds *credentialSource, transport http.RoundTripper) (*hubClient, error) {
	base, err := url.Parse(strings.TrimRight(strings.TrimSpace(cfg.URL), "/"))
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return nil, fmt.Errorf("kubecontroller: hubURL %q is not an https URL", cfg.URL)
	}
	if transport == nil {
		tlsCfg, err := hubTLSConfig(cfg)
		if err != nil {
			return nil, err
		}
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.TLSClientConfig = tlsCfg
		t.ResponseHeaderTimeout = 0
		transport = t
	}
	return &hubClient{base: base, http: &http.Client{Transport: transport}, credential: creds.get,
		refused: creds.refuse, userAgent: "cloop-executor-controller"}, nil
}

// hubTLSConfig is the TLS the controller speaks to its hub: the CA bundle as
// the only roots when one is given, then the pin.
func hubTLSConfig(cfg hubConfig) (*tls.Config, error) {
	pins, err := tlsconf.ParsePinSet(cfg.Pin)
	if err != nil {
		return nil, fmt.Errorf("kubecontroller: hubCAPin: %w", err)
	}
	tc, err := tlsconf.ClientConfig(tlsconf.ClientOptions{Pins: pins})
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.CABundle) != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.CABundle)) {
			return nil, fmt.Errorf("kubecontroller: hubCABundle holds no certificate")
		}
		tc.RootCAs = pool
	}
	return tc, nil
}

// close drops pooled connections.
func (h *hubClient) close() {
	if t, ok := h.http.Transport.(interface{ CloseIdleConnections() }); ok {
		t.CloseIdleConnections()
	}
}

// do sends one request to the hub with the credential, decoding a 2xx into
// out and anything else into a *HubError.
func (h *hubClient) do(ctx context.Context, method, path string, query url.Values, in, out any) error {
	cred, err := h.credential(ctx)
	if err != nil {
		return err
	}
	u := *h.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawQuery = query.Encode()
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cred)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", h.userAgent)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.http.Do(req)
	if err != nil {
		// The URL in a transport error is the hub's, never the credential.
		return fmt.Errorf("reach the hub at %s: %w", h.base.Host, scrubErr(err, cred))
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
	}()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxHubResponse))
	if err != nil {
		return fmt.Errorf("read the hub's answer: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		he := &HubError{Status: resp.StatusCode}
		var e struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		if json.Unmarshal(raw, &e) == nil {
			he.Code, he.Message = e.Code, e.Error
		} else {
			he.Message = firstLine(string(raw))
		}
		he.Message = redact.Scrub(strings.ReplaceAll(he.Message, cred, "[REDACTED]"))
		if he.Unauthorized() && h.refused != nil {
			h.refused()
		}
		return he
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode the hub's answer: %w", err)
	}
	return nil
}

// scrubErr removes the credential from an error's text, should a transport
// ever echo a header.
func scrubErr(err error, cred string) error {
	if err == nil || cred == "" || !strings.Contains(err.Error(), cred) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), cred, "[REDACTED]"))
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// Feed long-polls the demand feed once.
func (h *hubClient) Feed(ctx context.Context, after string, wait time.Duration) (FeedMessage, error) {
	q := url.Values{}
	if after != "" {
		q.Set("after", after)
	}
	q.Set("wait", strconv.Itoa(int(wait/time.Second)))
	// The hub answers by the end of the wait; past that and some slack the
	// connection is hung, and the feed is better off asking again.
	ctx, cancel := context.WithTimeout(ctx, wait+hubCallTimeout)
	defer cancel()
	var msg FeedMessage
	err := h.do(ctx, http.MethodGet, hubFeedPath, q, nil, &msg)
	return msg, err
}

// RunnerConfig is one runner the hub minted.
type RunnerConfig = executorpool.RunnerConfig

// MintRunners asks for n runner configurations.
func (h *hubClient) MintRunners(ctx context.Context, n int) ([]RunnerConfig, error) {
	ctx, cancel := context.WithTimeout(ctx, hubCallTimeout)
	defer cancel()
	var out struct {
		Runners []RunnerConfig `json:"runners"`
	}
	if err := h.do(ctx, http.MethodPost, hubRunnersPath, nil, map[string]any{"count": n}, &out); err != nil {
		return nil, err
	}
	if len(out.Runners) != n {
		return out.Runners, fmt.Errorf("the hub minted %d runners, not the %d asked for", len(out.Runners), n)
	}
	return out.Runners, nil
}

// RetireResult is what became of one runner the controller asked to retire.
type RetireResult struct {
	EnrollmentID string `json:"enrollment_id"`
	Outcome      string `json:"outcome"`
	State        string `json:"state,omitempty"`
}

// Retire asks the hub to retire runners that hold no run.
func (h *hubClient) Retire(ctx context.Context, enrollmentIDs []string) ([]RetireResult, error) {
	ctx, cancel := context.WithTimeout(ctx, hubCallTimeout)
	defer cancel()
	var out struct {
		Results []RetireResult `json:"results"`
	}
	err := h.do(ctx, http.MethodPost, hubRetirePath, nil, map[string]any{"runners": enrollmentIDs}, &out)
	return out.Results, err
}

// ── the feed ───────────────────────────────────────────────────────────────

// feedState is what a pool's feed has learned.
type feedState struct {
	// Msg is the last message, Revision its snapshot's revision.
	Msg FeedMessage
	// Have says a message arrived at all.
	Have bool
	// At is when the hub last answered; a feed whose At is older than
	// feedFresh is stale and the controller decides nothing on it.
	At time.Time
	// Err is the last failure, cleared by the next answer.
	Err error
}

// feed is one pool's long-poll loop.
type feed struct {
	cfg    hubConfig
	client *hubClient
	creds  *credentialSource
	cancel context.CancelFunc
	done   chan struct{}

	mu    sync.Mutex
	state feedState
}

// snapshot returns what the feed holds.
func (f *feed) snapshot() feedState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state
}

// run long-polls until ctx ends, calling changed whenever there is something
// new to act on: a new revision, a failure, or a recovery.
func (f *feed) run(ctx context.Context, changed func(), logf func(string, ...any)) {
	defer close(f.done)
	defer f.client.close()
	after := ""
	failures := 0
	for ctx.Err() == nil {
		msg, err := f.client.Feed(ctx, after, feedWait)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			failures++
			f.mu.Lock()
			first := f.state.Err == nil
			f.state.Err = err
			f.mu.Unlock()
			if first {
				logf("hub feed for %s: %v", f.cfg.URL, err)
			}
			changed()
			delay := backoff(failures, feedBackoffBase, feedBackoffMax)
			var he *HubError
			if errors.As(err, &he) && he.Unauthorized() {
				// A refused credential is not fixed by asking again soon: it
				// waits for the Secret to change, which the next attempt reads.
				delay = max(delay, 15*time.Second)
			}
			if !sleep(ctx, delay) {
				return
			}
			continue
		}
		recovered := failures > 0
		failures = 0
		f.mu.Lock()
		prev := f.state
		f.state = feedState{Msg: msg, Have: true, At: time.Now()}
		f.mu.Unlock()
		if recovered {
			logf("hub feed for %s: answering again", f.cfg.URL)
		}
		if !prev.Have || prev.Err != nil || msg.Snapshot.Revision != prev.Msg.Snapshot.Revision {
			changed()
		}
		after = msg.Snapshot.Revision
	}
}

// credentialSource reads a pool's controller credential from its Secret,
// caching it for credentialRefresh and dropping the cache when the hub
// refuses it.
type credentialSource struct {
	api *kubeAPI
	cfg hubConfig

	mu      sync.Mutex
	value   string
	readAt  time.Time
	refused bool
}

// get returns the credential, reading the Secret when the cache is cold.
func (c *credentialSource) get(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.value != "" && !c.refused && time.Since(c.readAt) < credentialRefresh {
		return c.value, nil
	}
	raw, _, err := c.api.getSecretKey(ctx, c.cfg.Namespace, c.cfg.Secret, c.cfg.Key)
	if err != nil {
		return "", &credentialError{err: fmt.Errorf("read the pool credential from Secret %s/%s: %w",
			c.cfg.Namespace, c.cfg.Secret, err)}
	}
	v := strings.TrimSpace(string(raw))
	zeroBytes(raw)
	if !strings.HasPrefix(v, executorpool.CredentialPrefix) {
		return "", &credentialError{err: fmt.Errorf("secret %s/%s key %q does not hold a pool controller "+
			"credential (%s…)", c.cfg.Namespace, c.cfg.Secret, c.cfg.Key, executorpool.CredentialPrefix)}
	}
	c.value, c.readAt, c.refused = v, time.Now(), false
	return v, nil
}

// id is the public ID of the credential last read, "" before one was.
func (c *credentialSource) id() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	id, _, err := executorpool.ParseCredential(c.value)
	if err != nil {
		return ""
	}
	return id
}

// refuse marks the cached credential refused, so the next request re-reads
// the Secret.
func (c *credentialSource) refuse() {
	c.mu.Lock()
	c.refused = true
	c.mu.Unlock()
}

// forget drops the credential.
func (c *credentialSource) forget() {
	c.mu.Lock()
	c.value = ""
	c.mu.Unlock()
}
