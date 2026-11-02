package ui

// Semantic knowledge search on the hub (Task 20471): the hub's own
// knowledge.embeddings reaches syncs, searches and the listing, and an
// endpoint that fails costs a search its ranking by meaning, never its answer.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/knowledge"
)

// uiEmbedServer is a fake OpenAI-compatible embedding endpoint: every text's
// vector says whether it mentions rolling back, or failing is set.
type uiEmbedServer struct {
	srv      *httptest.Server
	mu       sync.Mutex
	fail     bool
	requests int
}

func newUIEmbedServer(t *testing.T) *uiEmbedServer {
	t.Helper()
	es := &uiEmbedServer{}
	es.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			Input []string `json:"input"`
		}
		_ = json.Unmarshal(raw, &req)
		es.mu.Lock()
		es.requests++
		fail := es.fail
		es.mu.Unlock()
		if fail {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"error":{"message":"down for maintenance"}}`)
			return
		}
		type item struct {
			Index     int       `json:"index"`
			Embedding []float32 `json:"embedding"`
		}
		var data []item
		for i, text := range req.Input {
			v := []float32{0, 0, 0.1}
			if strings.Contains(strings.ToLower(text), "roll") || strings.Contains(strings.ToLower(text), "revert") {
				v[0] = 1
			}
			if strings.Contains(strings.ToLower(text), "broke") {
				v[1] = 1
			}
			data = append(data, item{Index: i, Embedding: v})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	t.Cleanup(es.srv.Close)
	return es
}

func (es *uiEmbedServer) count() int {
	es.mu.Lock()
	defer es.mu.Unlock()
	return es.requests
}

// setHubEmbeddings writes knowledge.embeddings into the hub's configuration.
func setHubEmbeddings(t *testing.T, dir string, e config.EmbeddingsConfig) {
	t.Helper()
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Knowledge.Embeddings = e
	if err := config.Save(dir, cfg); err != nil {
		t.Fatal(err)
	}
}

// TestKnowledgeSearchUsesTheHubsEmbeddings: with knowledge.embeddings on in
// the hub's configuration, a sync embeds the source's chunks at the endpoint it
// names; the listing says embeddings are on, and only an administrator is told
// where the text goes; a search is hybrid and says what found each hit. With
// the endpoint down the search ranks by words and says why, and the next sync
// records a warning. Turned off, nothing is sent.
func TestKnowledgeSearchUsesTheHubsEmbeddings(t *testing.T) {
	registerUIGated.Do(func() { knowledge.MustRegister(uiGated) })
	gate := uniqueGate("embed")
	h := knowledgeHub(t)
	t.Cleanup(func() { h.srv.stopKnowledgeSyncs(10 * time.Second) })
	es := newUIEmbedServer(t)
	setHubEmbeddings(t, h.srv.WorkDir, config.EmbeddingsConfig{Enabled: true, Provider: "openai",
		Endpoint: es.srv.URL + "/v1", Model: "fake-embed", Dimensions: 3})
	admin := h.signIn(t, "ada@example.com", false, "owners")
	engineer := h.signIn(t, "eng@example.com", false, "engineers")
	viewer := h.signIn(t, "vic@example.com", false, "readers")
	expect := func(c *http.Client, method, path string, body any, want int) []byte {
		t.Helper()
		resp, raw := h.call(t, c, method, path, body)
		if resp.StatusCode != want {
			t.Fatalf("%s %s = %d %s, want %d", method, path, resp.StatusCode, raw, want)
		}
		return raw
	}
	type sourceResp struct {
		Source knowledgeSourceView `json:"source"`
	}
	var created sourceResp
	decodeBody(t, expect(admin, "POST", "/api/knowledge/sources", map[string]any{"kind": "uigated", "name": "Ops wiki",
		"scope": "org", "config": map[string]any{"gate": gate}}, http.StatusCreated), &created)
	src := created.Source
	expect(admin, "POST", "/api/projects/0/knowledge/bindings", map[string]any{"source_id": src.ID}, http.StatusCreated)

	sourcePath := fmt.Sprintf("/api/knowledge/sources/%d", src.ID)
	syncAndWait := func() knowledgeSourceView {
		t.Helper()
		var before sourceResp
		decodeBody(t, expect(admin, "GET", sourcePath, nil, http.StatusOK), &before)
		expect(admin, "POST", sourcePath+"/sync", map[string]any{}, http.StatusAccepted)
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			var now sourceResp
			decodeBody(t, expect(admin, "GET", sourcePath, nil, http.StatusOK), &now)
			if now.Source.Sync.Running == nil && now.Source.Sync.At != "" && now.Source.Sync.At != before.Source.Sync.At {
				return now.Source
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("the sync did not end")
		return knowledgeSourceView{}
	}
	synced := syncAndWait()
	e := synced.Sync.Counts
	if synced.Sync.Status != knowledge.StatusOK || e == nil || e.Embeddings == nil || e.Embeddings.Embedded != 2 ||
		synced.Vectors != 2 || synced.Sync.Warning != "" {
		t.Fatalf("the source after its sync = %+v (vectors %d)", synced.Sync, synced.Vectors)
	}

	type listing struct {
		Embeddings knowledgeEmbeddingsView `json:"embeddings"`
	}
	var l listing
	decodeBody(t, expect(admin, "GET", "/api/knowledge/sources", nil, http.StatusOK), &l)
	if !l.Embeddings.Enabled || l.Embeddings.Model != "openai/fake-embed/3" || l.Embeddings.Endpoint != es.srv.URL+"/v1" {
		t.Fatalf("an administrator's listing says %+v", l.Embeddings)
	}
	l = listing{}
	decodeBody(t, expect(engineer, "GET", "/api/knowledge/sources", nil, http.StatusOK), &l)
	if !l.Embeddings.Enabled || l.Embeddings.Endpoint != "" {
		t.Fatalf("an engineer's listing says %+v; the endpoint is an administrator's to know", l.Embeddings)
	}

	type searchResp struct {
		Hits      []knowledgeHitView     `json:"hits"`
		Retrieval knowledgeRetrievalView `json:"retrieval"`
	}
	var found searchResp
	decodeBody(t, expect(viewer, "GET", "/api/projects/0/knowledge/search?q=revert", nil, http.StatusOK), &found)
	if found.Retrieval.Mode != "hybrid" || found.Retrieval.Candidates != 2 || len(found.Hits) == 0 ||
		found.Hits[0].ExternalID != gate+"-1" || strings.Join(found.Hits[0].FoundBy, ",") != "semantic" {
		t.Fatalf("a hybrid search = %+v", found)
	}
	found = searchResp{}
	decodeBody(t, expect(viewer, "GET", "/api/projects/0/knowledge/search?q=deploy", nil, http.StatusOK), &found)
	if len(found.Hits) != 2 || strings.Join(found.Hits[0].FoundBy, ",") != "lexical,semantic" {
		t.Fatalf("a search both rankings find = %+v", found)
	}

	// The endpoint goes down: searches rank by words, the next sync warns.
	es.mu.Lock()
	es.fail = true
	es.mu.Unlock()
	found = searchResp{}
	decodeBody(t, expect(viewer, "GET", "/api/projects/0/knowledge/search?q=deploy", nil, http.StatusOK), &found)
	if found.Retrieval.Mode != "lexical" || !strings.Contains(found.Retrieval.Warning, "503") || len(found.Hits) != 2 ||
		strings.Join(found.Hits[0].FoundBy, ",") != "lexical" {
		t.Fatalf("a search with the endpoint down = %+v", found)
	}
	// What the next sync embeds: a document that changed.
	db, err := h.srv.controlPlaneDB()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := knowledge.New(db).Index(src.ID, knowledge.Document{ExternalID: gate + "-3", Title: "New page",
		Body: "Rolling forward."}); err != nil {
		t.Fatal(err)
	}
	db.Close()
	synced = syncAndWait()
	if synced.Sync.Status != knowledge.StatusOK || !strings.Contains(synced.Sync.Warning, "503") || synced.Vectors != 2 {
		t.Fatalf("a sync with the endpoint down = %+v (vectors %d)", synced.Sync, synced.Vectors)
	}

	// Turned off: nothing is asked, and nothing is said.
	setHubEmbeddings(t, h.srv.WorkDir, config.EmbeddingsConfig{})
	sent := es.count()
	found = searchResp{}
	decodeBody(t, expect(viewer, "GET", "/api/projects/0/knowledge/search?q=deploy", nil, http.StatusOK), &found)
	if found.Retrieval.Mode != "lexical" || found.Retrieval.Warning != "" || es.count() != sent {
		t.Fatalf("a search with embeddings off = %+v after %d requests", found.Retrieval, es.count()-sent)
	}
	l = listing{}
	decodeBody(t, expect(admin, "GET", "/api/knowledge/sources", nil, http.StatusOK), &l)
	if l.Embeddings.Enabled {
		t.Fatalf("the listing with embeddings off says %+v", l.Embeddings)
	}
}
