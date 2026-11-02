package knowledge

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/knowledge/embed"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// embedDims is the fake embedding server's vector length: one axis per
// concept, and one every text has a little of, so no vector is zero.
const embedDims = 8

// concepts are the fake server's axes: a text's vector holds 1 on each axis
// one of whose words it contains. "revert" and "rollback" mean the same to it,
// as they would to a real model, and to the full-text index they do not.
var concepts = [][]string{
	{"rollback", "revert", "undo"},
	{"invoice", "billing"},
	{"latency", "slow"},
	{"database", "postgres"},
	{"holiday", "vacation"},
	{"acquisition", "merger", "acquires", "takeover"},
	{"laptop", "onboarding"},
}

func conceptVector(text string, dims int) []float32 {
	v := make([]float32, dims)
	lower := strings.ToLower(text)
	for i, words := range concepts {
		for _, w := range words {
			if strings.Contains(lower, w) && i < dims-1 {
				v[i] = 1
			}
		}
	}
	v[dims-1] = 0.1
	return v
}

// embedServer is a fake OpenAI-compatible embedding endpoint.
type embedServer struct {
	srv *httptest.Server

	mu sync.Mutex
	// fail, when set, is the status every request is answered with.
	fail int
	// dims is the length of the vectors it answers with.
	dims int
	// hang makes every request wait until the request is cancelled.
	hang     bool
	requests int
	texts    int
	models   []string
	inputs   []string
}

func newEmbedServer(t *testing.T) *embedServer {
	t.Helper()
	es := &embedServer{dims: embedDims}
	es.srv = httptest.NewServer(http.HandlerFunc(es.serve))
	t.Cleanup(es.srv.Close)
	return es
}

func (es *embedServer) serve(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var req struct {
		Model string   `json:"model"`
		Input []string `json:"input"`
	}
	_ = json.Unmarshal(raw, &req)
	es.mu.Lock()
	es.requests++
	es.texts += len(req.Input)
	es.models = append(es.models, req.Model)
	es.inputs = append(es.inputs, req.Input...)
	fail, dims, hang := es.fail, es.dims, es.hang
	es.mu.Unlock()
	if hang {
		<-r.Context().Done()
		return
	}
	if fail != 0 {
		w.WriteHeader(fail)
		_, _ = io.WriteString(w, `{"error":{"message":"the model is overloaded"}}`)
		return
	}
	type item struct {
		Index     int       `json:"index"`
		Embedding []float32 `json:"embedding"`
	}
	var data []item
	for i, text := range req.Input {
		data = append(data, item{Index: i, Embedding: conceptVector(text, dims)})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

func (es *embedServer) set(fn func(*embedServer)) {
	es.mu.Lock()
	defer es.mu.Unlock()
	fn(es)
}

func (es *embedServer) counts() (requests, texts int) {
	es.mu.Lock()
	defer es.mu.Unlock()
	return es.requests, es.texts
}

// client is a real embedding client for the fake server, under model.
func (es *embedServer) client(t *testing.T, model string, now func() time.Time) *embed.Client {
	t.Helper()
	c, err := embed.New(embed.Options{Provider: config.EmbeddingsOpenAI, Endpoint: es.srv.URL + "/v1", Model: model,
		Dimensions: embedDims, Now: now, Timeout: 5 * time.Second,
		Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

// embedded is a Service over f's database with e as its embedder.
func (f *fixture) embedded(e Embedder, opts ...Option) *Service {
	all := append([]Option{WithRegistry(f.svc.registry), WithCredentials(f.svc.credentials), WithChunking(f.svc.chunking),
		WithEmbeddings(Embeddings{Embedder: e})}, opts...)
	return New(f.db, all...)
}

func syncOK(t *testing.T, svc *Service, id int64) SyncReport {
	t.Helper()
	rep, err := svc.Sync(context.Background(), id)
	if err != nil {
		t.Fatalf("sync of source %d: %v", id, err)
	}
	return rep
}

func retrieve(t *testing.T, svc *Service, p Project, query string) SearchResult {
	t.Helper()
	res, err := svc.For(as(t, "root@corp.example", "admins")).Retrieve(context.Background(), p, query, 10)
	if err != nil {
		t.Fatalf("search %s for %q: %v", p.Path, query, err)
	}
	return res
}

func hitIDs(hits []Hit) []string {
	out := []string{}
	for _, h := range hits {
		out = append(out, h.ExternalID)
	}
	return out
}

func vectorsOf(t *testing.T, db *statedb.DB, model string, sourceID int64) int {
	t.Helper()
	n, err := db.CountKnowledgeVectors(model)
	if err != nil {
		t.Fatal(err)
	}
	return n[sourceID]
}

// TestHybridSearchFusesWordsAndMeaning: with an embedder, a search fuses the
// words' ranking with the vectors' by reciprocal rank. "revert" is found by
// its words in A and C, C first (in C's title); by meaning in A first (its
// only concept is rollback), then B, which never says "revert", then C (also
// about invoices and databases), then D. Fused, A — second and first — leads
// C — first and third — and B and D, found by meaning alone, follow; without
// the embedder the same search finds C and A alone.
func TestHybridSearchFusesWordsAndMeaning(t *testing.T) {
	f := newFixture(t)
	es := newEmbedServer(t)
	src := orgSource(t, f, "Wiki", projectA)
	f.conn.docs = []Document{
		{ExternalID: "A", Title: "Rollback runbook", Body: "How to revert a release safely."},
		{ExternalID: "B", Title: "Release notes", Body: "We made rollback faster; latency dropped."},
		{ExternalID: "C", Title: "Revert policy", Body: "Revert an invoice from the billing database within 30 days."},
		{ExternalID: "D", Title: "Holiday calendar", Body: "Offices close for the winter holidays."},
	}
	f.conn.pageSize = 10
	svc := f.embedded(es.client(t, "fake-embed-v1", nil))
	rep := syncOK(t, svc, src.ID)
	if rep.Embeddings == nil || rep.Embeddings.Embedded != 4 || rep.Embeddings.Pending != 0 || rep.Warning != "" {
		t.Fatalf("the sync's embedding pass = %+v, warning %q", rep.Embeddings, rep.Warning)
	}

	lexical := retrieve(t, f.svc, projectA, "revert")
	if got := hitIDs(lexical.Hits); !reflect.DeepEqual(got, []string{"C", "A"}) || lexical.Retrieval.Mode != RetrievalLexical {
		t.Fatalf("by words alone = %v (%s), want [C A]", got, lexical.Retrieval.Mode)
	}
	res := retrieve(t, svc, projectA, "revert")
	if got := hitIDs(res.Hits); !reflect.DeepEqual(got, []string{"A", "C", "B", "D"}) {
		t.Fatalf("fused = %v, want [A C B D]", got)
	}
	r := res.Retrieval
	if r.Mode != RetrievalHybrid || r.Model != "openai/fake-embed-v1/8" || r.Candidates != 4 || r.Capped || r.Warning != "" {
		t.Fatalf("retrieval = %+v", r)
	}
	want := map[string][2]bool{"A": {true, true}, "C": {true, true}, "B": {false, true}, "D": {false, true}}
	for i, h := range res.Hits {
		if h.Rank != i+1 || [2]bool{h.Lexical, h.Semantic} != want[h.ExternalID] {
			t.Fatalf("hit %s: rank %d, lexical %v, semantic %v", h.ExternalID, h.Rank, h.Lexical, h.Semantic)
		}
	}
	// A hit found by meaning alone has a snippet of its own text.
	if b := res.Hits[2]; b.Snippet != "We made rollback faster; latency dropped." || b.Title != "Release notes" || b.Source.ID != src.ID {
		t.Fatalf("B = %+v", b)
	}
	// k bounds the fused answer.
	two, err := svc.For(as(t, "root@corp.example", "admins")).Retrieve(context.Background(), projectA, "revert", 2)
	if err != nil || !reflect.DeepEqual(hitIDs(two.Hits), []string{"A", "C"}) {
		t.Fatalf("k=2 = %v, %v", hitIDs(two.Hits), err)
	}
	// A query no word of which is indexed is still answered by meaning.
	undo := retrieve(t, svc, projectA, "undo")
	if len(undo.Hits) == 0 || undo.Hits[0].ExternalID != "A" || undo.Hits[0].Lexical {
		t.Fatalf("\"undo\" = %v", hitIDs(undo.Hits))
	}
}

// TestFuseBreaksTiesTheSameWayEveryTime: equal fused scores go to the words'
// ranking, then the vectors', then the lower chunk id.
func TestFuseBreaksTiesTheSameWayEveryTime(t *testing.T) {
	got := fuse([]int64{10, 20}, []int64{30, 10})
	var ids []int64
	for _, h := range got {
		ids = append(ids, h.id)
	}
	// 10 is in both; 30, first by meaning, outscores 20, second by words.
	if !reflect.DeepEqual(ids, []int64{10, 30, 20}) {
		t.Fatalf("fused = %v", ids)
	}
	tie := fuse([]int64{7}, []int64{3})
	if tie[0].id != 7 || tie[1].id != 3 || tie[0].score != tie[1].score {
		t.Fatalf("a tie = %+v; the words' first leads", tie)
	}
	top := newTopVectors(2)
	for _, c := range []scoredChunk{{5, 0.5}, {2, 0.9}, {9, 0.9}, {1, 0.1}, {4, 0.95}} {
		top.offer(c.id, c.score)
	}
	if got := top.best(); !reflect.DeepEqual(got, []int64{4, 2}) {
		t.Fatalf("top 2 = %v, want [4 2] (of the two at 0.9, the lower id)", got)
	}
}

// TestEmbeddingBackfillsWhenTheModelChanges: a sync embeds what has no vector
// of the model and nothing else; a document that changes has its changed
// chunks embedded again and keeps the vectors of the ones that did not; a new
// model makes every source due at once, its sync embeds every chunk again, the
// old model's vectors are purged, and searches use the new.
func TestEmbeddingBackfillsWhenTheModelChanges(t *testing.T) {
	f := newFixture(t)
	es := newEmbedServer(t)
	src := orgSource(t, f, "Wiki", projectA)
	long := strings.Repeat("The rollback step restores the previous release. ", 12)
	f.conn.docs = []Document{
		{ExternalID: "runbook", Title: "Runbook", Body: "# Rollback\n\n" + long + "\n\n# Latency\n\nWhen requests are slow, check the database."},
		{ExternalID: "notes", Title: "Notes", Body: "Holiday rota."},
	}
	f.conn.pageSize = 10
	v1 := f.embedded(es.client(t, "fake-embed-v1", nil))
	rep := syncOK(t, v1, src.ID)
	chunks := rep.Embeddings.Embedded
	if chunks < 3 || rep.Embeddings.Pending != 0 || vectorsOf(t, f.db, "openai/fake-embed-v1/8", src.ID) != chunks {
		t.Fatalf("first sync embedded %+v", rep.Embeddings)
	}
	// Nothing changed: nothing is sent.
	reqs, _ := es.counts()
	rep = syncOK(t, v1, src.ID)
	if after, _ := es.counts(); after != reqs || rep.Embeddings.Embedded != 0 {
		t.Fatalf("an unchanged source was embedded again: %d requests, %+v", after-reqs, rep.Embeddings)
	}
	row, err := f.db.GetKnowledgeSource(src.ID)
	if err != nil {
		t.Fatal(err)
	}
	if next := nextSyncFor(row, v1.EmbeddingModel()); !next.Equal(row.SyncedAt.Add(DefaultSyncInterval)) {
		t.Fatalf("with the same model the next sync is at %s, want an interval on", next)
	}

	// The last section changes, the first does not. However the change was
	// indexed, the next sync's pass finds it.
	f.conn.docs[0].Body = "# Rollback\n\n" + long + "\n\n# Latency\n\nWhen requests are slow, check postgres first."
	if out, err := v1.Index(src.ID, f.conn.docs[0]); err != nil || out != statedb.KnowledgeIndexUpdated {
		t.Fatalf("re-index = %s, %v", out, err)
	}
	_, textsBefore := es.counts()
	rep = syncOK(t, v1, src.ID)
	_, textsAfter := es.counts()
	if rep.Embeddings.Embedded != 1 || rep.Embeddings.Reused != chunks-2 || textsAfter-textsBefore != 1 {
		t.Fatalf("after editing one chunk: %+v, %d texts sent", rep.Embeddings, textsAfter-textsBefore)
	}

	// A new model: due at once, and every chunk is embedded under it.
	v2 := f.embedded(es.client(t, "fake-embed-v2", nil))
	row, _ = f.db.GetKnowledgeSource(src.ID)
	if next := nextSyncFor(row, v2.EmbeddingModel()); !next.Equal(row.SyncedAt.Add(resumeAfter)) {
		t.Fatalf("after a model change the next sync is at %s, want a minute after the last", next)
	}
	if next := nextSyncFor(row, ""); !next.Equal(row.SyncedAt.Add(DefaultSyncInterval)) {
		t.Fatalf("with embeddings off the next sync is at %s", next)
	}
	rep = syncOK(t, v2, src.ID)
	if rep.Embeddings.Model != "openai/fake-embed-v2/8" || rep.Embeddings.Embedded != chunks || rep.Embeddings.Pending != 0 {
		t.Fatalf("the backfill under the new model = %+v", rep.Embeddings)
	}
	row, _ = f.db.GetKnowledgeSource(src.ID)
	if next := nextSyncFor(row, v2.EmbeddingModel()); !next.Equal(row.SyncedAt.Add(DefaultSyncInterval)) {
		t.Fatalf("after the backfill the next sync is at %s, want an interval on", next)
	}
	// The schedule's purge removes the old model's vectors.
	r := NewRunner(RunnerOptions{Member: "m"})
	r.purgeVectors(context.Background(), v2, time.Now())
	if n := vectorsOf(t, f.db, "openai/fake-embed-v1/8", src.ID); n != 0 {
		t.Fatalf("%d vectors of the old model survived the purge", n)
	}
	if n := vectorsOf(t, f.db, "openai/fake-embed-v2/8", src.ID); n != chunks {
		t.Fatalf("%d vectors of the new model, want %d", n, chunks)
	}
	res := retrieve(t, v2, projectA, "undo")
	es.mu.Lock()
	last := es.models[len(es.models)-1]
	es.mu.Unlock()
	if res.Retrieval.Mode != RetrievalHybrid || res.Retrieval.Model != "openai/fake-embed-v2/8" || last != "fake-embed-v2" ||
		len(res.Hits) == 0 || res.Hits[0].ExternalID != "runbook" {
		t.Fatalf("search under the new model = %v %+v (last request for %s)", hitIDs(res.Hits), res.Retrieval, last)
	}
}

// TestEmbeddingOutageFallsBackToWords: an endpoint that is down fails neither
// the sync nor the search. The sync ends ok, indexes the documents, and
// records a warning; the search ranks by words and says why; a search during
// the client's cool-down does not ask again; and once the endpoint is back the
// next sync embeds what waited and searches are hybrid again. A configuration
// the hub refused is reported the same way, and a hanging endpoint costs a
// search its bounded wait and no more.
func TestEmbeddingOutageFallsBackToWords(t *testing.T) {
	f := newFixture(t)
	es := newEmbedServer(t)
	es.set(func(es *embedServer) { es.fail = http.StatusServiceUnavailable })
	src := orgSource(t, f, "Wiki", projectA)
	f.conn.docs = []Document{{ExternalID: "A", Title: "Rollback runbook", Body: "How to revert a release safely."}}
	now := time.Now()
	clock := func() time.Time { return now }
	svc := f.embedded(es.client(t, "fake-embed-v1", clock))
	rep, err := svc.Sync(context.Background(), src.ID)
	if err != nil {
		t.Fatalf("a sync with the endpoint down failed: %v", err)
	}
	if rep.Created != 1 || rep.Embeddings == nil || rep.Embeddings.Failed != 1 || rep.Embeddings.Embedded != 0 ||
		rep.Embeddings.Pending != 1 || !strings.Contains(rep.Warning, "503") || !strings.Contains(rep.Warning, "overloaded") {
		t.Fatalf("the sync = created %d, %+v, warning %q", rep.Created, rep.Embeddings, rep.Warning)
	}
	got, _, err := svc.For(as(t, "root@corp.example", "admins")).Source(context.Background(), src.ID)
	if err != nil || got.Sync.Status != StatusOK || got.Sync.Warning != rep.Warning || got.Counts.Vectors != 0 {
		t.Fatalf("the source = %s, warning %q, vectors %d, %v", got.Sync.Status, got.Sync.Warning, got.Counts.Vectors, err)
	}

	reqs, _ := es.counts()
	res := retrieve(t, svc, projectA, "revert")
	if res.Retrieval.Mode != RetrievalLexical || !strings.Contains(res.Retrieval.Warning, "ranked by words alone") ||
		!reflect.DeepEqual(hitIDs(res.Hits), []string{"A"}) || !res.Hits[0].Lexical || res.Hits[0].Semantic {
		t.Fatalf("a search with the endpoint down = %v %+v", hitIDs(res.Hits), res.Retrieval)
	}
	if after, _ := es.counts(); after != reqs {
		t.Fatalf("the search asked the endpoint %d times during its cool-down", after-reqs)
	}

	// Back up: the next sync embeds what waited, and searches are hybrid.
	es.set(func(es *embedServer) { es.fail = 0 })
	now = now.Add(time.Minute)
	rep = syncOK(t, svc, src.ID)
	if rep.Embeddings.Embedded != 1 || rep.Warning != "" {
		t.Fatalf("the sync after the outage = %+v, warning %q", rep.Embeddings, rep.Warning)
	}
	if res := retrieve(t, svc, projectA, "revert"); res.Retrieval.Mode != RetrievalHybrid || res.Retrieval.Warning != "" {
		t.Fatalf("a search after the outage = %+v", res.Retrieval)
	}

	// A refused configuration: warned about in syncs and searches alike.
	broken := New(f.db, WithRegistry(f.svc.registry), WithCredentials(f.svc.credentials),
		WithEmbeddings(Embeddings{Broken: "knowledge.embeddings was refused at load: model is required"}))
	rep = syncOK(t, broken, src.ID)
	if !strings.Contains(rep.Warning, "model is required") {
		t.Fatalf("a broken configuration's sync warning = %q", rep.Warning)
	}
	if res := retrieve(t, broken, projectA, "revert"); res.Retrieval.Mode != RetrievalLexical ||
		!strings.Contains(res.Retrieval.Warning, "model is required") || len(res.Hits) != 1 {
		t.Fatalf("a broken configuration's search = %v %+v", hitIDs(res.Hits), res.Retrieval)
	}

	// A hanging endpoint: the search waits its bound, then ranks by words.
	defer func(d time.Duration) { queryEmbedTimeout = d }(queryEmbedTimeout)
	queryEmbedTimeout = 200 * time.Millisecond
	es.set(func(es *embedServer) { es.hang = true })
	hung := f.embedded(es.client(t, "fake-embed-v1", nil))
	started := time.Now()
	res = retrieve(t, hung, projectA, "revert")
	if res.Retrieval.Mode != RetrievalLexical || len(res.Hits) != 1 || time.Since(started) > 5*time.Second {
		t.Fatalf("a hanging endpoint's search = %v %+v after %s", hitIDs(res.Hits), res.Retrieval, time.Since(started))
	}
	es.set(func(es *embedServer) { es.hang = false })
}

// wrongDims is an embedder that answers with vectors one value short.
type wrongDims struct{}

func (wrongDims) Model() string          { return "test/wrong/8" }
func (wrongDims) Dimensions() int        { return embedDims }
func (wrongDims) Endpoint() string       { return "https://embed.example/v1" }
func (wrongDims) shortVector() []float32 { return make([]float32, embedDims-1) }
func (w wrongDims) EmbedDocuments(_ context.Context, texts []string) ([][]float32, error) {
	out := make([][]float32, len(texts))
	for i := range out {
		v := w.shortVector()
		v[0] = 1
		out[i] = v
	}
	return out, nil
}
func (w wrongDims) EmbedQuery(context.Context, string) ([]float32, error) {
	v := w.shortVector()
	v[0] = 1
	return v, nil
}

// TestEmbeddingDimensionMismatchIsRejected: vectors of another length than
// the configured dimensions are never stored and never compared — whether the
// embedding client refuses the answer or an embedder hands them over — and the
// sync and the search say so and carry on.
func TestEmbeddingDimensionMismatchIsRejected(t *testing.T) {
	f := newFixture(t)
	es := newEmbedServer(t)
	es.set(func(es *embedServer) { es.dims = embedDims - 1 })
	src := orgSource(t, f, "Wiki", projectA)
	f.conn.docs = []Document{{ExternalID: "A", Title: "Rollback runbook", Body: "How to revert a release safely."}}
	for _, tc := range []struct {
		name string
		e    Embedder
	}{
		{"the client", es.client(t, "fake-embed-v1", nil)},
		{"an embedder", wrongDims{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := f.embedded(tc.e)
			rep := syncOK(t, svc, src.ID)
			if !strings.Contains(rep.Warning, "7 dimensions") || !strings.Contains(rep.Warning, "8") ||
				rep.Embeddings.Embedded != 0 || rep.Embeddings.Failed != 1 {
				t.Fatalf("the sync = %+v, warning %q", rep.Embeddings, rep.Warning)
			}
			if n := vectorsOf(t, f.db, tc.e.Model(), src.ID); n != 0 {
				t.Fatalf("%d vectors of the wrong length were stored", n)
			}
			res := retrieve(t, svc, projectA, "revert")
			if res.Retrieval.Mode != RetrievalLexical || !strings.Contains(res.Retrieval.Warning, "7 dimensions") ||
				len(res.Hits) != 1 {
				t.Fatalf("the search = %v %+v", hitIDs(res.Hits), res.Retrieval)
			}
		})
	}
	// Nor a zero vector, nor one that is not finite.
	for _, v := range [][]float32{make([]float32, embedDims), {float32(math.NaN()), 0, 0, 0, 0, 0, 0, 1}} {
		if _, err := encodeVector(v, embedDims); err == nil {
			t.Fatalf("encodeVector(%v) was accepted", v)
		}
	}
}

// TestSemanticSearchNeverCrossesProjects: the vectors a search compares are
// those of the sources bound to the project asking, through each binding's
// narrowing — never another project's, however near its chunks are to the
// query, never a disabled source's, and never one made for what a document
// said before it changed.
func TestSemanticSearchNeverCrossesProjects(t *testing.T) {
	f := newFixture(t)
	es := newEmbedServer(t)
	svc := f.embedded(es.client(t, "fake-embed-v1", nil))
	a := orgSource(t, f, "A wiki", projectA)
	b := orgSource(t, f, "B wiki", projectB)
	f.conn.docs = []Document{{ExternalID: "a1", Title: "Merger", Body: "Project Bluebird acquires Initech in Q3.", Space: "ENG"}}
	syncOK(t, svc, a.ID)
	f.conn.docs = []Document{
		{ExternalID: "b1", Title: "Handbook", Body: "Laptops are ordered through IT.", Space: "ENG"},
		{ExternalID: "b2", Title: "Payroll", Body: "Salaries are paid monthly.", Space: "HR"},
	}
	syncOK(t, svc, b.ID)

	for _, who := range []Principal{as(t, "root@corp.example", "admins"), as(t, "vic@corp.example", "proj-b-viewers")} {
		for _, q := range []string{"acquisition", "takeover of a company", "merger"} {
			res, err := svc.For(who).Retrieve(context.Background(), projectB, q, MaxResults)
			if err != nil {
				t.Fatal(err)
			}
			if res.Retrieval.Mode != RetrievalHybrid {
				t.Fatalf("%q in B = %+v", q, res.Retrieval)
			}
			for _, h := range res.Hits {
				if h.Source.ID != b.ID {
					t.Fatalf("%s searching B for %q found %q of source %d, bound only to A", who.Identity, q, h.Title, h.Source.ID)
				}
			}
			if res.Retrieval.Candidates != 2 {
				t.Fatalf("B's search compared %d vectors, want its own 2", res.Retrieval.Candidates)
			}
		}
	}
	// A's own search finds it by meaning.
	if res := retrieve(t, svc, projectA, "takeover"); len(res.Hits) != 1 || res.Hits[0].ExternalID != "a1" {
		t.Fatalf("A's search for \"takeover\" = %v", hitIDs(res.Hits))
	}
	// A project bound to nothing finds nothing, by words or by meaning.
	if res := retrieve(t, svc, Project{Path: "/srv/projects/c", Name: "c"}, "merger"); len(res.Hits) != 0 || res.Retrieval.Candidates != 0 {
		t.Fatalf("an unbound project found %v (%+v)", hitIDs(res.Hits), res.Retrieval)
	}
	// A binding's spaces narrow the vectors too.
	admin := svc.For(as(t, "root@corp.example", "admins"))
	projectE := Project{Path: "/srv/projects/e", Name: "e"}
	if _, _, err := admin.Bind(context.Background(), projectE, b.ID, Filter{Spaces: []string{"ENG"}}); err != nil {
		t.Fatal(err)
	}
	if res := retrieve(t, svc, projectE, "salaries"); len(res.Hits) != 1 || res.Hits[0].ExternalID != "b1" || res.Retrieval.Candidates != 1 {
		t.Fatalf("an ENG-narrowed search = %v (%+v); the HR page must not be read", hitIDs(res.Hits), res.Retrieval)
	}
	// A document that changed is not found by its old vector.
	f.conn.docs = []Document{{ExternalID: "a1", Title: "Merger", Body: "Called off.", Space: "ENG"}}
	if _, err := svc.Index(a.ID, f.conn.docs[0]); err != nil {
		t.Fatal(err)
	}
	if res := retrieve(t, svc, projectA, "takeover"); len(res.Hits) != 0 || res.Retrieval.Candidates != 0 {
		t.Fatalf("a changed document's stale vector was compared: %v (%+v)", hitIDs(res.Hits), res.Retrieval)
	}
	// A disabled source is not read.
	off := false
	if _, err := admin.UpdateSource(context.Background(), b.ID, SourceUpdate{Enabled: &off}); err != nil {
		t.Fatal(err)
	}
	if res := retrieve(t, svc, projectB, "laptop"); len(res.Hits) != 0 || res.Retrieval.Candidates != 0 {
		t.Fatalf("a disabled source was searched: %v (%+v)", hitIDs(res.Hits), res.Retrieval)
	}
}

// TestASearchComparesAtMostItsCandidates: a project holding more current
// vectors than the Service compares is searched by meaning over that many,
// and the search says it was capped.
func TestASearchComparesAtMostItsCandidates(t *testing.T) {
	f := newFixture(t)
	es := newEmbedServer(t)
	src := orgSource(t, f, "Wiki", projectA)
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		f.conn.docs = append(f.conn.docs, Document{ExternalID: id, Title: "Page " + id, Body: "Rollback notes " + id + "."})
	}
	f.conn.pageSize = 10
	svc := New(f.db, WithRegistry(f.svc.registry), WithCredentials(f.svc.credentials),
		WithEmbeddings(Embeddings{Embedder: es.client(t, "fake-embed-v1", nil), MaxCandidates: 3}))
	syncOK(t, svc, src.ID)
	res := retrieve(t, svc, projectA, "undo")
	if res.Retrieval.Candidates != 3 || !res.Retrieval.Capped || len(res.Hits) != 3 {
		t.Fatalf("a capped search = %v (%+v)", hitIDs(res.Hits), res.Retrieval)
	}
}

// TestAnEmbeddingBacklogResumesAtOnce: a pass that runs out of its budget with
// chunks left marks the sync as stopping short, so the next is due within a
// minute rather than an interval on.
func TestAnEmbeddingBacklogResumesAtOnce(t *testing.T) {
	f := newFixture(t)
	es := newEmbedServer(t)
	src := orgSource(t, f, "Wiki", projectA)
	for i := 0; i < 5; i++ {
		f.conn.docs = append(f.conn.docs, Document{ExternalID: string(rune('a' + i)), Title: "Page", Body: "Rollback."})
	}
	f.conn.pageSize = 10
	// Each reading of the clock moves it a second: one batch fits in the
	// budget, not two.
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	tick := func() time.Time { now = now.Add(time.Second); return now }
	svc := New(f.db, WithRegistry(f.svc.registry), WithCredentials(f.svc.credentials), WithClock(tick),
		WithEmbeddings(Embeddings{Embedder: es.client(t, "fake-embed-v1", nil), BatchSize: 2}))
	rep, err := svc.SyncWith(context.Background(), src.ID, SyncOptions{EmbedBudget: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if e := rep.Embeddings; e == nil || e.Embedded == 0 || e.Pending == 0 || !e.More {
		t.Fatalf("a pass out of budget = %+v", rep.Embeddings)
	}
	row, _ := f.db.GetKnowledgeSource(src.ID)
	if !row.SyncMore || !nextSyncFor(row, svc.EmbeddingModel()).Equal(row.SyncedAt.Add(resumeAfter)) {
		t.Fatalf("the source after a pass out of budget: more %v, next %s", row.SyncMore, nextSyncFor(row, svc.EmbeddingModel()))
	}
}

// TestDotIsTheCosineOfStoredVectors: the dot product of a query and a stored
// vector, both unit length, is their cosine — for any length, the unrolled
// loop's tail included — and a stored vector of another length scores below
// every real one.
func TestDotIsTheCosineOfStoredVectors(t *testing.T) {
	for _, n := range []int{1, 3, 4, 7, 8, 768} {
		a, b := make([]float32, n), make([]float32, n)
		for i := range a {
			a[i], b[i] = float32(i%5)+0.5, float32((i*7)%3)-1
		}
		ua, err := unit(a, n)
		if err != nil {
			t.Fatal(err)
		}
		ub, err := unit(b, n)
		if err != nil {
			t.Fatal(err)
		}
		stored, err := encodeVector(b, n)
		if err != nil {
			t.Fatal(err)
		}
		var want float64
		for i := range ua {
			want += float64(ua[i]) * float64(ub[i])
		}
		if got := dot(ua, stored); math.Abs(float64(got)-want) > 1e-5 {
			t.Fatalf("dot of %d dimensions = %v, want %v", n, got, want)
		}
		if self := dot(ub, stored); math.Abs(float64(self)-1) > 1e-5 {
			t.Fatalf("a %d-dimensional vector's cosine with itself = %v", n, self)
		}
		if got := dot(ua, stored[:len(stored)-4]); got >= -1 {
			t.Fatalf("a shorter stored vector scored %v", got)
		}
	}
}

// TestPlainSnippet: a snippet of a chunk found by meaning starts a little
// before the first query word it holds, marks the query's words, and says
// where text was left out.
func TestPlainSnippet(t *testing.T) {
	body := strings.Repeat("filler ", 40) + "the rollback, as planned. " + strings.Repeat("tail ", 40)
	got := plainSnippet(body, queryTerms(`"Rollback" plan*`))
	if !strings.HasPrefix(got, SnippetEllipsis) || !strings.HasSuffix(got, SnippetEllipsis) ||
		!strings.Contains(got, "the "+SnippetOpen+"rollback"+SnippetClose+", as planned.") {
		t.Fatalf("snippet = %q", got)
	}
	if got := plainSnippet("Short text.", queryTerms("unrelated")); got != "Short text." {
		t.Fatalf("snippet of a short text with no query word = %q", got)
	}
}
