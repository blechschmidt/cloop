// Package embed reaches the embedding endpoint the hub's knowledge index makes
// its vectors with (Task 20471): an OpenAI-compatible API — OpenAI, Azure
// OpenAI, Ollama, vLLM — or Voyage AI's. A *Client is a knowledge.Embedder.
//
// The endpoint is the one an administrator named in knowledge.embeddings, and
// what is sent to it is the text of the hub's knowledge chunks and its
// searches' queries, so the client is careful about where a request goes and
// what comes back:
//
//   - Every connection is checked at the address it is about to dial, after
//     DNS: never a cloud metadata service. Loopback and private addresses are
//     allowed — a local Ollama, an in-cluster vLLM — since the operator, not
//     a tenant, chose the endpoint. A proxy the hub's environment names is
//     used, as the hub's other clients use it; Go never proxies loopback.
//   - No redirect is followed: the key goes to the endpoint named, or
//     nowhere.
//   - An answer is read up to a bound derived from what was asked, and must
//     hold exactly one vector of exactly the configured length per text.
//   - The key is opened from the secret store when first needed and again
//     every few minutes, and after the endpoint refuses it; no error the
//     client returns carries it.
//
// A query is not sent while the endpoint is known to be failing: a search
// must not wait out a timeout per query when it would rank by words in the
// end anyway. A batch of documents is always tried, once per sync.
package embed

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/cloudmeta"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/redact"
)

// Client bounds.
const (
	// credentialTTL is how long an opened key is used before it is opened
	// again, so a rotated or deleted secret takes effect within it.
	credentialTTL = 5 * time.Minute
	// coolDown is how long after a failure the client sends no query.
	coolDown = 30 * time.Second
	// maxErrorBytes bounds the error body read from a refusal.
	maxErrorBytes = 8 << 10
	// maxErrorMessageBytes bounds the message quoted from one.
	maxErrorMessageBytes = 300
	// bytesPerValue bounds what one vector value may take in an answer's
	// JSON, generously: "-0.012345678901234567," is 22.
	bytesPerValue = 40
	// maxAnswerBytes bounds any answer.
	maxAnswerBytes = 256 << 20
	// documentAttempts bounds the tries of a batch of documents that is
	// refused for load (429, 5xx); a query is tried once.
	documentAttempts = 3
	// maxRetryWait bounds the wait a Retry-After may ask for.
	maxRetryWait = 30 * time.Second
	// MaxTexts bounds the texts one request embeds.
	MaxTexts = config.EmbeddingsBatchSizeUpper
)

// ErrCoolingDown reports a query not sent because the endpoint failed within
// the last coolDown.
var ErrCoolingDown = errors.New("embed: the embedding endpoint failed moments ago; not asking it again yet")

// ErrRejected marks an answer the client refuses: the wrong number of vectors,
// or a vector of the wrong length.
var ErrRejected = errors.New("embed: the embedding endpoint's answer was refused")

// ErrBlockedAddress reports a connection refused at dial time.
var ErrBlockedAddress = errors.New("embed: refusing to connect")

// Options configures a Client.
type Options struct {
	// Provider is config.EmbeddingsOpenAI or config.EmbeddingsVoyage.
	Provider string
	// Endpoint is the API's base URL; requests go to <Endpoint>/embeddings.
	Endpoint string
	// Model and Dimensions are the model the endpoint is asked for and the
	// length every vector must have.
	Model      string
	Dimensions int
	// RequestDimensions asks the endpoint for vectors of Dimensions.
	RequestDimensions bool
	// Auth is config.EmbeddingsAuthBearer or config.EmbeddingsAuthAPIKey.
	Auth string
	// Credential opens the endpoint's key; nil for an endpoint that takes
	// none. The client zeroes what it returns when it opens the next.
	Credential func() ([]byte, error)
	// Timeout bounds one request (config.EmbeddingsTimeoutDefault).
	Timeout time.Duration
	// Transport replaces the guarded transport, for tests; nil uses it.
	Transport http.RoundTripper
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Sleep waits between tries; nil waits on a timer. Tests record it.
	Sleep func(context.Context, time.Duration) error
}

// FromConfig is a Client for the hub's knowledge.embeddings, which must have
// loaded: ValidateEmbeddings is what Load holds it to. cred opens the key the
// section's secret_ref names; nil for a section that names none.
func FromConfig(c config.EmbeddingsConfig, cred func() ([]byte, error)) (*Client, error) {
	if !c.Enabled {
		return nil, errors.New("embed: knowledge.embeddings is off")
	}
	if err := config.ValidateEmbeddings(c); err != nil {
		return nil, fmt.Errorf("embed: knowledge.embeddings: %w", err)
	}
	if strings.TrimSpace(c.SecretRef) == "" {
		cred = nil
	}
	return New(Options{
		Provider: c.ProviderName(), Endpoint: c.EffectiveEndpoint(), Model: strings.TrimSpace(c.Model),
		Dimensions: c.Dimensions, RequestDimensions: c.RequestDimensions, Auth: c.EffectiveAuth(), Credential: cred,
		Timeout: c.EffectiveTimeout(),
	})
}

// Client is one embedding endpoint. Safe for concurrent use.
type Client struct {
	o       Options
	url     *url.URL
	display string
	model   string
	http    *http.Client

	mu sync.Mutex
	// key is the opened key and when it was opened.
	key   []byte
	keyAt time.Time
	// failedAt is when a request last failed, and failure why, scrubbed.
	failedAt time.Time
	failure  string
}

// New returns a Client.
func New(o Options) (*Client, error) {
	switch o.Provider {
	case config.EmbeddingsOpenAI, config.EmbeddingsVoyage:
	default:
		return nil, fmt.Errorf("embed: provider %q is not %s or %s", o.Provider, config.EmbeddingsOpenAI, config.EmbeddingsVoyage)
	}
	if strings.TrimSpace(o.Model) == "" {
		return nil, errors.New("embed: a model is required")
	}
	if o.Dimensions < 1 || o.Dimensions > config.EmbeddingsMaxDimensions {
		return nil, fmt.Errorf("embed: %d dimensions is outside 1-%d", o.Dimensions, config.EmbeddingsMaxDimensions)
	}
	switch o.Auth {
	case "":
		o.Auth = config.EmbeddingsAuthBearer
	case config.EmbeddingsAuthBearer, config.EmbeddingsAuthAPIKey:
	default:
		return nil, fmt.Errorf("embed: auth %q is not %s or %s", o.Auth, config.EmbeddingsAuthBearer, config.EmbeddingsAuthAPIKey)
	}
	if o.Timeout <= 0 {
		o.Timeout = config.EmbeddingsTimeoutDefault
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = sleep
	}
	base, err := url.Parse(strings.TrimSpace(o.Endpoint))
	if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") || base.User != nil {
		return nil, fmt.Errorf("embed: %q is not an http(s) endpoint without credentials", o.Endpoint)
	}
	target := *base
	target.Fragment = ""
	// An endpoint pasted with its /embeddings is taken as it is meant.
	target.Path = strings.TrimRight(target.Path, "/")
	if !strings.HasSuffix(target.Path, "/embeddings") {
		target.Path += "/embeddings"
	}
	target.RawPath = ""
	c := &Client{
		o: o, url: &target,
		display: strings.ToLower(base.Scheme) + "://" + base.Host + strings.TrimRight(base.EscapedPath(), "/"),
		model:   ModelKey(o.Provider, o.Model, o.Dimensions),
	}
	c.http = httpClient(o)
	return c, nil
}

// Model names the vectors' model: provider, model and dimensions.
func (c *Client) Model() string { return c.model }

// ModelKey is how vectors of a model are stored: provider, model and
// dimensions, "openai/text-embedding-3-small/1536". Two endpoints serving one
// model under one name — OpenAI and an Azure OpenAI deployment of it — share
// it, so moving between them embeds nothing again.
func ModelKey(provider, model string, dims int) string {
	return fmt.Sprintf("%s/%s/%d", strings.ToLower(strings.TrimSpace(provider)), strings.TrimSpace(model), dims)
}

// Dimensions is the length every vector has.
func (c *Client) Dimensions() int { return c.o.Dimensions }

// Endpoint is the endpoint as messages name it: scheme, host and path.
func (c *Client) Endpoint() string { return c.display }

// Close releases the client's idle connections and forgets its key.
func (c *Client) Close() {
	c.http.CloseIdleConnections()
	c.mu.Lock()
	clear(c.key)
	c.key = nil
	c.mu.Unlock()
}

// EmbedDocuments returns one vector per text, in order, for chunks to be
// stored. A batch the endpoint refuses for load is tried again, at most
// documentAttempts times in all, as long as ctx allows.
func (c *Client) EmbedDocuments(ctx context.Context, texts []string) ([][]float32, error) {
	if len(texts) == 0 {
		return nil, nil
	}
	if len(texts) > MaxTexts {
		return nil, fmt.Errorf("embed: %d texts in one request, more than %d", len(texts), MaxTexts)
	}
	var err error
	for attempt := 1; ; attempt++ {
		var vectors [][]float32
		var wait time.Duration
		vectors, wait, err = c.embed(ctx, hubmetrics.KnowledgeEmbedPurposeDocument, "document", texts)
		if err == nil {
			return vectors, nil
		}
		if wait == 0 || attempt == documentAttempts || ctx.Err() != nil {
			return nil, err
		}
		if serr := c.o.Sleep(ctx, wait); serr != nil {
			return nil, err
		}
	}
}

// EmbedQuery returns a search query's vector. While the endpoint is known to
// be failing it is not asked: ErrCoolingDown.
func (c *Client) EmbedQuery(ctx context.Context, text string) ([]float32, error) {
	c.mu.Lock()
	age := c.o.Now().Sub(c.failedAt)
	cooling, failure := !c.failedAt.IsZero() && age < coolDown, c.failure
	c.mu.Unlock()
	if cooling {
		hubmetrics.KnowledgeEmbeddingRequests.Inc(hubmetrics.KnowledgeEmbedPurposeQuery, hubmetrics.KnowledgeEmbedRequestSkipped)
		return nil, fmt.Errorf("%w (it failed %s ago: %s)", ErrCoolingDown, age.Round(time.Second), failure)
	}
	vectors, _, err := c.embed(ctx, hubmetrics.KnowledgeEmbedPurposeQuery, "query", []string{text})
	if err != nil {
		return nil, err
	}
	return vectors[0], nil
}

// embed makes one request. wait, when an error is returned, is how long to
// wait before trying again for a refusal that says the endpoint is busy; zero
// for one that trying again would not fix.
func (c *Client) embed(ctx context.Context, purpose, inputType string, texts []string) (vectors [][]float32, wait time.Duration, err error) {
	started := c.o.Now()
	outcome := hubmetrics.KnowledgeEmbedRequestError
	defer func() {
		hubmetrics.KnowledgeEmbeddingRequests.Inc(purpose, outcome)
		hubmetrics.KnowledgeEmbeddingRequestDuration.Observe(c.o.Now().Sub(started).Seconds(), purpose)
		c.mu.Lock()
		switch {
		case err == nil:
			c.failedAt, c.failure = time.Time{}, ""
		case ctx.Err() == nil:
			// The caller giving up is not the endpoint failing.
			c.failedAt, c.failure = c.o.Now(), err.Error()
		}
		c.mu.Unlock()
	}()
	body, err := c.requestBody(inputType, texts)
	if err != nil {
		return nil, 0, err
	}
	key, err := c.credential()
	if err != nil {
		return nil, 0, fmt.Errorf("embed: open the key knowledge.embeddings.secret_ref names: %w", err)
	}
	defer clear(key)
	rctx, cancel := context.WithTimeout(ctx, c.o.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, c.url.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, c.clean(err, key)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "cloop-knowledge")
	if len(key) > 0 {
		if c.o.Auth == config.EmbeddingsAuthAPIKey {
			req.Header.Set("api-key", string(key))
		} else {
			req.Header.Set("Authorization", "Bearer "+string(key))
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if rctx.Err() != nil && ctx.Err() == nil {
			return nil, 0, fmt.Errorf("embed: no answer within %s", c.o.Timeout)
		}
		return nil, 0, c.clean(err, key)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBytes))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			// Opened again for the next request: the secret may have been
			// rotated since.
			c.forgetKey()
		}
		return nil, retryWait(resp), c.clean(refusal(resp.StatusCode, raw), key)
	}
	limit := int64(len(texts))*int64(c.o.Dimensions)*bytesPerValue + 1<<20
	limit = min(limit, maxAnswerBytes)
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, 0, c.clean(fmt.Errorf("embed: read the answer: %w", err), key)
	}
	if int64(len(raw)) > limit {
		outcome = hubmetrics.KnowledgeEmbedRequestRejected
		return nil, 0, fmt.Errorf("%w: it is larger than %d bytes, more than %d vectors of %d dimensions take",
			ErrRejected, limit, len(texts), c.o.Dimensions)
	}
	vectors, err = c.decode(raw, len(texts))
	if err != nil {
		outcome = hubmetrics.KnowledgeEmbedRequestRejected
		return nil, 0, err
	}
	outcome = hubmetrics.KnowledgeEmbedRequestOK
	return vectors, 0, nil
}

// requestBody is the request for texts, in the provider's shape.
func (c *Client) requestBody(inputType string, texts []string) ([]byte, error) {
	body := map[string]any{"model": c.o.Model, "input": texts}
	switch c.o.Provider {
	case config.EmbeddingsVoyage:
		body["input_type"] = inputType
		if c.o.RequestDimensions {
			body["output_dimension"] = c.o.Dimensions
		}
	default:
		if c.o.RequestDimensions {
			body["dimensions"] = c.o.Dimensions
		}
	}
	return json.Marshal(body)
}

// answer is the shape both providers answer in.
type answer struct {
	Data []struct {
		Index     *int      `json:"index"`
		Embedding []float32 `json:"embedding"`
	} `json:"data"`
}

// decode reads an answer to n texts: exactly n vectors, each named by its
// index once — or, from an endpoint that sends no indexes, in order — and
// each of the configured length.
func (c *Client) decode(raw []byte, n int) ([][]float32, error) {
	var a answer
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("%w: it is not the JSON of an embeddings answer: %v", ErrRejected, err)
	}
	if len(a.Data) != n {
		return nil, fmt.Errorf("%w: %d texts were answered with %d vectors", ErrRejected, n, len(a.Data))
	}
	out := make([][]float32, n)
	for i, d := range a.Data {
		at := i
		if d.Index != nil {
			at = *d.Index
		}
		if at < 0 || at >= n || out[at] != nil {
			return nil, fmt.Errorf("%w: it names vector %d twice or out of range", ErrRejected, at)
		}
		if len(d.Embedding) != c.o.Dimensions {
			return nil, fmt.Errorf("%w: a vector has %d dimensions, and knowledge.embeddings.dimensions is %d",
				ErrRejected, len(d.Embedding), c.o.Dimensions)
		}
		out[at] = d.Embedding
	}
	return out, nil
}

// credential returns a copy of the endpoint's key, for the caller to clear
// once it is in a request, opening it when the one held is older than
// credentialTTL. Nil for an endpoint that takes none.
func (c *Client) credential() ([]byte, error) {
	if c.o.Credential == nil {
		return nil, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.key != nil && c.o.Now().Sub(c.keyAt) < credentialTTL {
		return bytes.Clone(c.key), nil
	}
	b, err := c.o.Credential()
	if err != nil {
		return nil, err
	}
	key := []byte(strings.TrimSpace(string(b)))
	clear(b)
	if len(key) == 0 {
		return nil, errors.New("the secret is empty")
	}
	if strings.ContainsAny(string(key), "\r\n") {
		clear(key)
		return nil, errors.New("the secret holds a line break, which no header may carry")
	}
	clear(c.key)
	c.key, c.keyAt = key, c.o.Now()
	return bytes.Clone(key), nil
}

// forgetKey drops the key held, so the next request opens it again.
func (c *Client) forgetKey() {
	c.mu.Lock()
	clear(c.key)
	c.key = nil
	c.mu.Unlock()
}

// clean returns err's text with the key, and anything else shaped like a
// credential, removed.
func (c *Client) clean(err error, key []byte) error {
	if err == nil {
		return nil
	}
	text := err.Error()
	if len(key) > 0 {
		text = strings.ReplaceAll(text, string(key), redact.Marker)
	}
	out := &cleanError{text: redact.Scrub(text), cause: err}
	return out
}

// cleanError is an error whose text was scrubbed. It matches what its cause
// matches without unwrapping to the text it replaced.
type cleanError struct {
	text  string
	cause error
}

func (e *cleanError) Error() string        { return e.text }
func (e *cleanError) Is(target error) bool { return errors.Is(e.cause, target) }

// refusal describes a non-2xx answer: its status, what it means for the
// endpoint's configuration, and the message the endpoint gave, bounded.
func refusal(status int, raw []byte) error {
	text := fmt.Sprintf("embed: HTTP %d %s", status, http.StatusText(status))
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		text += " — the endpoint refused the key: check the secret knowledge.embeddings.secret_ref names, and auth"
	case http.StatusNotFound:
		text += " — check knowledge.embeddings.endpoint and model"
	case http.StatusTooManyRequests:
		text += " — the endpoint is rate-limiting the hub"
	}
	if msg := errorMessage(raw); msg != "" {
		text += ": " + msg
	}
	return errors.New(text)
}

// errorMessage is the message of an error body, as OpenAI ({"error":
// {"message"}}), Ollama ({"error": "..."}) and Voyage ({"detail": "..."})
// put it, one line and bounded. Text that is not JSON is not quoted: it may be
// an HTML page, or echo what was sent.
func errorMessage(raw []byte) string {
	var body struct {
		Error  json.RawMessage `json:"error"`
		Detail json.RawMessage `json:"detail"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return ""
	}
	pick := func(m json.RawMessage) string {
		var s string
		if json.Unmarshal(m, &s) == nil {
			return s
		}
		var o struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(m, &o) == nil {
			return o.Message
		}
		return ""
	}
	msg := pick(body.Error)
	if msg == "" {
		msg = pick(body.Detail)
	}
	msg = strings.Join(strings.Fields(msg), " ")
	if len(msg) > maxErrorMessageBytes {
		cut := maxErrorMessageBytes
		for cut > 0 && msg[cut]&0xC0 == 0x80 {
			cut--
		}
		msg = msg[:cut] + "…"
	}
	return msg
}

// retryWait is how long to wait before trying a refused request again: what
// Retry-After asks, within maxRetryWait, for a refusal that says the endpoint
// is busy; zero for any other.
func retryWait(resp *http.Response) time.Duration {
	switch {
	case resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode >= 500:
	default:
		return 0
	}
	if s, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && s > 0 {
		return min(time.Duration(s)*time.Second, maxRetryWait)
	}
	return 2 * time.Second
}

// httpClient is the HTTP client for o: the guarded transport, or o.Transport
// in a test.
func httpClient(o Options) *http.Client {
	noRedirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if o.Transport != nil {
		return &http.Client{Transport: o.Transport, CheckRedirect: noRedirect}
	}
	dialer := &net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			return CheckDialAddress(address)
		},
	}
	return &http.Client{
		CheckRedirect: noRedirect,
		Transport: &http.Transport{
			Proxy:                  http.ProxyFromEnvironment,
			DialContext:            dialer.DialContext,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:    15 * time.Second,
			ResponseHeaderTimeout:  o.Timeout,
			MaxResponseHeaderBytes: 64 << 10,
			MaxIdleConnsPerHost:    4,
			IdleConnTimeout:        90 * time.Second,
			ForceAttemptHTTP2:      true,
		},
	}
}

// CheckDialAddress refuses a connection to a cloud metadata service: the check
// every connection the client makes passes, at the address it dials.
func CheckDialAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %q is not an address", ErrBlockedAddress, address)
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%w: %q is not an IP address", ErrBlockedAddress, host)
	}
	if svc, ok := cloudmeta.LookupDialed(a); ok {
		return fmt.Errorf("%w: %s is the cloud metadata service %s", ErrBlockedAddress, a, svc.Describe())
	}
	return nil
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
