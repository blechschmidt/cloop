package embed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
)

// fakeAPI is an embeddings endpoint: it records what it was sent and answers
// each text with a vector of dims values, or what fail says.
type fakeAPI struct {
	mu       sync.Mutex
	requests []recorded
	dims     int
	// fail, when set, is the status and body every request is answered with.
	fail     int
	failBody string
	// answer, when set, replaces the answer.
	answer func(texts []string) any
	// failFirst fails that many requests with 429 first.
	failFirst int
}

type recorded struct {
	path, query, auth, apiKey string
	body                      map[string]any
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	f.mu.Lock()
	f.requests = append(f.requests, recorded{path: r.URL.Path, query: r.URL.RawQuery,
		auth: r.Header.Get("Authorization"), apiKey: r.Header.Get("api-key"), body: body})
	fail, failBody := f.fail, f.failBody
	if f.failFirst > 0 {
		f.failFirst--
		fail, failBody = http.StatusTooManyRequests, `{"error":{"message":"slow down"}}`
		w.Header().Set("Retry-After", "1")
	}
	answer, dims := f.answer, f.dims
	f.mu.Unlock()
	if fail != 0 {
		w.WriteHeader(fail)
		_, _ = io.WriteString(w, failBody)
		return
	}
	var texts []string
	if in, ok := body["input"].([]any); ok {
		for _, t := range in {
			s, _ := t.(string)
			texts = append(texts, s)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if answer != nil {
		_ = json.NewEncoder(w).Encode(answer(texts))
		return
	}
	type item struct {
		Index     int       `json:"index"`
		Embedding []float32 `json:"embedding"`
	}
	// Answered last first, as an endpoint is free to: the index orders them.
	var data []item
	for i := len(texts) - 1; i >= 0; i-- {
		v := make([]float32, dims)
		v[i%dims] = float32(len(texts[i]))
		data = append(data, item{Index: i, Embedding: v})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

func (f *fakeAPI) seen() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.requests...)
}

func newClient(t *testing.T, o Options) *Client {
	t.Helper()
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

// TestOpenAICompatibleRequests: the request an OpenAI-compatible endpoint is
// sent — its path below the endpoint, the model and texts, dimensions only when
// asked for, the key as a bearer token — and an answer in any order read back
// in the texts' order.
func TestOpenAICompatibleRequests(t *testing.T) {
	api := &fakeAPI{dims: 4}
	srv := httptest.NewServer(api)
	defer srv.Close()
	c := newClient(t, Options{Provider: config.EmbeddingsOpenAI, Endpoint: srv.URL + "/v1", Model: "text-embedding-3-small",
		Dimensions: 4, RequestDimensions: true, Credential: func() ([]byte, error) { return []byte("sk-test-123\n"), nil }})
	if c.Model() != "openai/text-embedding-3-small/4" || c.Endpoint() != srv.URL+"/v1" || c.Dimensions() != 4 {
		t.Fatalf("client = %s %s %d", c.Model(), c.Endpoint(), c.Dimensions())
	}
	vs, err := c.EmbedDocuments(context.Background(), []string{"a", "bbb"})
	if err != nil {
		t.Fatal(err)
	}
	if vs[0][0] != 1 || vs[1][1] != 3 {
		t.Fatalf("vectors = %v; the answer's indexes were not followed", vs)
	}
	req := api.seen()[0]
	if req.path != "/v1/embeddings" || req.auth != "Bearer sk-test-123" || req.apiKey != "" {
		t.Fatalf("request = %+v", req)
	}
	if req.body["model"] != "text-embedding-3-small" || req.body["dimensions"] != float64(4) || req.body["input_type"] != nil {
		t.Fatalf("body = %v", req.body)
	}
	// Without request_dimensions, none is asked for; an endpoint pasted with
	// /embeddings is not given a second one; no key, no header.
	plain := newClient(t, Options{Provider: config.EmbeddingsOpenAI, Endpoint: srv.URL + "/v1/embeddings/",
		Model: "nomic-embed-text", Dimensions: 4})
	if _, err := plain.EmbedQuery(context.Background(), "q"); err != nil {
		t.Fatal(err)
	}
	req = api.seen()[1]
	if req.path != "/v1/embeddings" || req.auth != "" || req.body["dimensions"] != nil {
		t.Fatalf("plain request = %+v", req)
	}
}

// TestAzureDeployments: an Azure OpenAI deployment URL keeps its api-version,
// gets /embeddings on its path, and is sent the key as api-key — the default
// for an Azure host when the configuration says nothing.
func TestAzureDeployments(t *testing.T) {
	api := &fakeAPI{dims: 3}
	srv := httptest.NewServer(api)
	defer srv.Close()
	c := newClient(t, Options{Provider: config.EmbeddingsOpenAI, Auth: config.EmbeddingsAuthAPIKey,
		Endpoint: srv.URL + "/openai/deployments/emb?api-version=2024-10-21", Model: "text-embedding-3-large",
		Dimensions: 3, Credential: func() ([]byte, error) { return []byte("azure-key"), nil }})
	if _, err := c.EmbedDocuments(context.Background(), []string{"x"}); err != nil {
		t.Fatal(err)
	}
	req := api.seen()[0]
	if req.path != "/openai/deployments/emb/embeddings" || req.query != "api-version=2024-10-21" ||
		req.apiKey != "azure-key" || req.auth != "" {
		t.Fatalf("request = %+v", req)
	}
	if c.Endpoint() != srv.URL+"/openai/deployments/emb" {
		t.Fatalf("endpoint shown as %q; the query is not part of it", c.Endpoint())
	}
	cfg := config.EmbeddingsConfig{Enabled: true, Provider: "openai", Endpoint: "https://corp.openai.azure.com/openai/deployments/e?api-version=2024-10-21"}
	if cfg.EffectiveAuth() != config.EmbeddingsAuthAPIKey {
		t.Fatalf("an Azure host's default auth = %q", cfg.EffectiveAuth())
	}
}

// TestVoyageRequests: Voyage is told whether it embeds documents or a query,
// and asked for output_dimension only when the configuration says to.
func TestVoyageRequests(t *testing.T) {
	api := &fakeAPI{dims: 2}
	srv := httptest.NewServer(api)
	defer srv.Close()
	c := newClient(t, Options{Provider: config.EmbeddingsVoyage, Endpoint: srv.URL + "/v1", Model: "voyage-3.5",
		Dimensions: 2, RequestDimensions: true, Credential: func() ([]byte, error) { return []byte("pa-key"), nil }})
	if _, err := c.EmbedDocuments(context.Background(), []string{"doc"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.EmbedQuery(context.Background(), "query"); err != nil {
		t.Fatal(err)
	}
	reqs := api.seen()
	if reqs[0].body["input_type"] != "document" || reqs[1].body["input_type"] != "query" ||
		reqs[0].body["output_dimension"] != float64(2) || reqs[0].body["dimensions"] != nil || reqs[0].auth != "Bearer pa-key" {
		t.Fatalf("requests = %+v", reqs)
	}
}

// TestAnswersOfTheWrongShapeAreRejected: a vector of the wrong length, too
// few or too many vectors, an index named twice, or an answer larger than the
// vectors asked for could take is refused as a whole.
func TestAnswersOfTheWrongShapeAreRejected(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer func([]string) any
	}{
		{"wrong length", func(texts []string) any {
			return map[string]any{"data": []any{map[string]any{"index": 0, "embedding": []float32{1, 2, 3}}}}
		}},
		{"too few", func([]string) any { return map[string]any{"data": []any{}} }},
		{"too many", func([]string) any {
			v := []float32{1, 0, 0, 0}
			return map[string]any{"data": []any{map[string]any{"index": 0, "embedding": v}, map[string]any{"index": 1, "embedding": v}}}
		}},
		{"index twice", func([]string) any {
			v := []float32{1, 0, 0, 0}
			return map[string]any{"data": []any{map[string]any{"index": 0, "embedding": v}, map[string]any{"index": 0, "embedding": v}}}
		}},
		{"too large", func([]string) any { return map[string]any{"data": []any{}, "pad": strings.Repeat("x", 2<<20)} }},
		{"not JSON numbers", func([]string) any {
			return map[string]any{"data": []any{map[string]any{"index": 0, "embedding": []string{"a", "b", "c", "d"}}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &fakeAPI{dims: 4, answer: tc.answer}
			srv := httptest.NewServer(api)
			defer srv.Close()
			c := newClient(t, Options{Provider: config.EmbeddingsOpenAI, Endpoint: srv.URL, Model: "m", Dimensions: 4})
			texts := []string{"one"}
			if tc.name == "too many" || tc.name == "index twice" {
				texts = []string{"one", "two"}
				if tc.name == "too many" {
					texts = texts[:1]
				}
			}
			_, err := c.EmbedDocuments(context.Background(), texts)
			if !errors.Is(err, ErrRejected) {
				t.Fatalf("EmbedDocuments = %v, want ErrRejected", err)
			}
		})
	}
}

// TestRefusalsNameTheProblemAndNeverTheKey: an endpoint's refusal is reported
// with its status and its own message, bounded — and with the key removed even
// when the endpoint echoes it. A refused key is opened again for the next
// request.
func TestRefusalsNameTheProblemAndNeverTheKey(t *testing.T) {
	const key = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD"
	api := &fakeAPI{dims: 4, fail: http.StatusUnauthorized,
		failBody: fmt.Sprintf(`{"error":{"message":"Incorrect API key provided: %s. %s"}}`, key, strings.Repeat("pad ", 200))}
	srv := httptest.NewServer(api)
	defer srv.Close()
	opened := 0
	c := newClient(t, Options{Provider: config.EmbeddingsOpenAI, Endpoint: srv.URL, Model: "m", Dimensions: 4,
		Credential: func() ([]byte, error) { opened++; return []byte(key), nil }})
	_, err := c.EmbedDocuments(context.Background(), []string{"x"})
	if err == nil || strings.Contains(err.Error(), key) || strings.Contains(err.Error(), "abcdefghijklmnop") {
		t.Fatalf("error = %v; it must not carry the key", err)
	}
	for _, want := range []string{"401", "refused the key", "Incorrect API key"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not say %q", err, want)
		}
	}
	if len(err.Error()) > 800 {
		t.Fatalf("error is %d bytes; the endpoint's message is not bounded", len(err.Error()))
	}
	api.mu.Lock()
	api.fail = 0
	api.mu.Unlock()
	if _, err := c.EmbedDocuments(context.Background(), []string{"x"}); err != nil {
		t.Fatal(err)
	}
	if opened != 2 {
		t.Fatalf("the key was opened %d times; a refused key is opened again", opened)
	}
	// A body that is not JSON is not quoted.
	html := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "<html>echo: chunk text here</html>")
	}))
	defer html.Close()
	c2 := newClient(t, Options{Provider: config.EmbeddingsOpenAI, Endpoint: html.URL, Model: "m", Dimensions: 4,
		Sleep: func(context.Context, time.Duration) error { return nil }})
	if _, err := c2.EmbedDocuments(context.Background(), []string{"x"}); err == nil || strings.Contains(err.Error(), "chunk text") {
		t.Fatalf("an HTML refusal = %v", err)
	}
}

// TestRedirectsAreNotFollowed: the key goes to the endpoint named or nowhere.
func TestRedirectsAreNotFollowed(t *testing.T) {
	elsewhere := &fakeAPI{dims: 4}
	other := httptest.NewServer(elsewhere)
	defer other.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/v1/embeddings", http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	c := newClient(t, Options{Provider: config.EmbeddingsOpenAI, Endpoint: redirect.URL, Model: "m", Dimensions: 4,
		Credential: func() ([]byte, error) { return []byte("k"), nil }})
	if _, err := c.EmbedDocuments(context.Background(), []string{"x"}); err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("a redirect = %v, want its refusal", err)
	}
	if n := len(elsewhere.seen()); n != 0 {
		t.Fatalf("the redirect's target was sent %d requests", n)
	}
}

// TestTheDialerRefusesMetadataServices: a cloud metadata service is never
// dialled, in any spelling; loopback and private addresses are, since an
// operator's own Ollama or vLLM lives there.
func TestTheDialerRefusesMetadataServices(t *testing.T) {
	for _, addr := range []string{"169.254.169.254:80", "[fd00:ec2::254]:80", "[::ffff:169.254.169.254]:443", "100.100.100.200:80"} {
		if err := CheckDialAddress(addr); !errors.Is(err, ErrBlockedAddress) {
			t.Errorf("CheckDialAddress(%s) = %v, want a refusal", addr, err)
		}
	}
	for _, addr := range []string{"127.0.0.1:11434", "[::1]:8000", "10.0.0.7:8000", "192.168.1.5:443", "140.82.112.3:443"} {
		if err := CheckDialAddress(addr); err != nil {
			t.Errorf("CheckDialAddress(%s) = %v", addr, err)
		}
	}
	// And the guarded transport applies it.
	c := newClient(t, Options{Provider: config.EmbeddingsOpenAI, Endpoint: "http://169.254.169.254/v1", Model: "m",
		Dimensions: 4, Timeout: 2 * time.Second})
	if _, err := c.EmbedQuery(context.Background(), "q"); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("a query to the metadata service = %v", err)
	}
}

// TestQueriesWaitOutAFailingEndpoint: after a failure no query is sent for the
// cool-down — a search ranks by words at once rather than after a timeout —
// while a sync's batch is still tried, and a success ends it.
func TestQueriesWaitOutAFailingEndpoint(t *testing.T) {
	api := &fakeAPI{dims: 4, fail: http.StatusServiceUnavailable}
	srv := httptest.NewServer(api)
	defer srv.Close()
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	c := newClient(t, Options{Provider: config.EmbeddingsOpenAI, Endpoint: srv.URL, Model: "m", Dimensions: 4, Now: clock,
		Sleep: func(context.Context, time.Duration) error { return nil }})
	if _, err := c.EmbedQuery(context.Background(), "q"); err == nil {
		t.Fatal("a failing endpoint answered")
	}
	sent := len(api.seen())
	if _, err := c.EmbedQuery(context.Background(), "q"); !errors.Is(err, ErrCoolingDown) {
		t.Fatalf("a query during the cool-down = %v", err)
	}
	if len(api.seen()) != sent {
		t.Fatal("a query was sent during the cool-down")
	}
	if _, err := c.EmbedDocuments(context.Background(), []string{"d"}); err == nil || errors.Is(err, ErrCoolingDown) {
		t.Fatalf("a batch during the cool-down = %v; it is tried", err)
	}
	api.mu.Lock()
	api.fail = 0
	api.mu.Unlock()
	now = now.Add(coolDown + time.Second)
	if _, err := c.EmbedQuery(context.Background(), "q"); err != nil {
		t.Fatalf("a query after the cool-down = %v", err)
	}
}

// TestBusyEndpointsAreRetriedForDocuments: a batch refused with 429 is tried
// again after the Retry-After it was given; a refusal a retry cannot fix is
// not; a query is tried once.
func TestBusyEndpointsAreRetriedForDocuments(t *testing.T) {
	api := &fakeAPI{dims: 4, failFirst: 1}
	srv := httptest.NewServer(api)
	defer srv.Close()
	var waits []time.Duration
	c := newClient(t, Options{Provider: config.EmbeddingsOpenAI, Endpoint: srv.URL, Model: "m", Dimensions: 4,
		Sleep: func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }})
	if _, err := c.EmbedDocuments(context.Background(), []string{"d"}); err != nil {
		t.Fatalf("a batch refused once with 429 = %v", err)
	}
	if len(waits) != 1 || waits[0] != time.Second || len(api.seen()) != 2 {
		t.Fatalf("waited %v over %d requests", waits, len(api.seen()))
	}
	api.mu.Lock()
	api.fail, api.failBody = http.StatusBadRequest, `{"error":"model not found"}`
	api.mu.Unlock()
	waits = nil
	if _, err := c.EmbedDocuments(context.Background(), []string{"d"}); err == nil || len(waits) != 0 ||
		!strings.Contains(err.Error(), "model not found") {
		t.Fatalf("a 400 = %v after %v waits; it is not retried", err, waits)
	}
}

// TestFromConfig: a client is made only for an enabled section that
// validates, and takes the section's knobs.
func TestFromConfig(t *testing.T) {
	if _, err := FromConfig(config.EmbeddingsConfig{}, nil); err == nil {
		t.Fatal("a client was made for a disabled section")
	}
	if _, err := FromConfig(config.EmbeddingsConfig{Enabled: true, Provider: "openai", Model: "m", Dimensions: 4}, nil); err == nil {
		t.Fatal("a client was made for an openai section without an endpoint")
	}
	c, err := FromConfig(config.EmbeddingsConfig{Enabled: true, Provider: "Voyage", Model: "voyage-3.5", Dimensions: 1024,
		Timeout: "10s"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.Endpoint() != config.EmbeddingsVoyageEndpoint || c.Model() != "voyage/voyage-3.5/1024" || c.o.Timeout != 10*time.Second {
		t.Fatalf("client = %s %s %s", c.Endpoint(), c.Model(), c.o.Timeout)
	}
}

// TestTheKeyIsOpenedAgainAfterItsTTL: a rotated secret takes effect within
// credentialTTL.
func TestTheKeyIsOpenedAgainAfterItsTTL(t *testing.T) {
	api := &fakeAPI{dims: 4}
	srv := httptest.NewServer(api)
	defer srv.Close()
	now := time.Now()
	keys := []string{"first", "second"}
	opened := 0
	c := newClient(t, Options{Provider: config.EmbeddingsOpenAI, Endpoint: srv.URL, Model: "m", Dimensions: 4,
		Now: func() time.Time { return now }, Credential: func() ([]byte, error) { opened++; return []byte(keys[opened-1]), nil }})
	for i := 0; i < 3; i++ {
		if _, err := c.EmbedQuery(context.Background(), "q"); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(credentialTTL + time.Second)
	if _, err := c.EmbedQuery(context.Background(), "q"); err != nil {
		t.Fatal(err)
	}
	reqs := api.seen()
	if opened != 2 || reqs[2].auth != "Bearer first" || reqs[3].auth != "Bearer second" {
		t.Fatalf("opened %d times; auth %q then %q", opened, reqs[2].auth, reqs[3].auth)
	}
}
