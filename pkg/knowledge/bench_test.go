package knowledge

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// benchEmbedder answers every query with one fixed vector, in process: the
// benchmark measures what the hub does with a vector, not an endpoint.
type benchEmbedder struct {
	dims  int
	query []float32
}

func (b benchEmbedder) Model() string    { return fmt.Sprintf("bench/model/%d", b.dims) }
func (b benchEmbedder) Dimensions() int  { return b.dims }
func (b benchEmbedder) Endpoint() string { return "in-process" }
func (b benchEmbedder) EmbedDocuments(_ context.Context, texts []string) ([][]float32, error) {
	out := make([][]float32, len(texts))
	for i := range out {
		out[i] = b.query
	}
	return out, nil
}
func (b benchEmbedder) EmbedQuery(context.Context, string) ([]float32, error) { return b.query, nil }

// BenchmarkSearch50k is a search of a project whose bound source holds 50,000
// chunks, each with a 768-dimensional vector: by words alone, and hybrid — the
// same full-text search plus a cosine scan of all 50,000 vectors and the
// fusion. The default max_candidates is 50,000, so the hybrid search compares
// every vector, which is the case the cap is there to bound. The vectors
// metric reports what one search read.
func BenchmarkSearch50k(b *testing.B) {
	const (
		docs       = 5000
		perDoc     = 10
		dims       = 768
		vocabulary = 2000
	)
	db := statedbtest.Open(b).AsControlPlane()
	src, err := db.CreateKnowledgeSource(statedb.KnowledgeSourceRow{Kind: "fake", Name: "Bench wiki", Scope: ScopeOrg,
		Config: `{"base_url":"https://wiki.example"}`, Enabled: true}, "bench")
	if err != nil {
		b.Fatal(err)
	}
	if _, _, err := db.PutKnowledgeBinding(statedb.KnowledgeBindingRow{SourceID: src.ID, ProjectPath: projectA.Path}, "bench"); err != nil {
		b.Fatal(err)
	}
	rng := rand.New(rand.NewSource(20471))
	words := make([]string, vocabulary)
	for i := range words {
		words[i] = fmt.Sprintf("w%04d", i)
	}
	sentence := func(n int) string {
		var sb strings.Builder
		for i := 0; i < n; i++ {
			if i > 0 {
				sb.WriteByte(' ')
			}
			sb.WriteString(words[rng.Intn(vocabulary)])
		}
		return sb.String()
	}
	for d := 0; d < docs; d++ {
		chunks := make([]statedb.KnowledgeChunk, perDoc)
		for c := range chunks {
			chunks[c] = statedb.KnowledgeChunk{Heading: "Section", Text: sentence(60), Tokens: 120}
		}
		if _, err := db.IndexKnowledgeDocument(statedb.KnowledgeDocumentRow{SourceID: src.ID,
			ExternalID: fmt.Sprintf("doc-%d", d), Title: sentence(4), ContentHash: fmt.Sprintf("h%d", d)},
			func() ([]statedb.KnowledgeChunk, bool) { return chunks, false }); err != nil {
			b.Fatal(err)
		}
	}
	unitVector := func() []float32 {
		v := make([]float32, dims)
		for i := range v {
			v[i] = float32(rng.NormFloat64())
		}
		u, err := unit(v, dims)
		if err != nil {
			b.Fatal(err)
		}
		return u
	}
	e := benchEmbedder{dims: dims, query: unitVector()}
	for {
		todo, err := db.PendingKnowledgeEmbeddings(context.Background(), src.ID, e.Model(), 0, 1000)
		if err != nil {
			b.Fatal(err)
		}
		if len(todo) == 0 {
			break
		}
		rows := make([]statedb.KnowledgeEmbedding, len(todo))
		for i, t := range todo {
			vec, err := encodeVector(unitVector(), dims)
			if err != nil {
				b.Fatal(err)
			}
			rows[i] = statedb.KnowledgeEmbedding{ChunkID: t.ChunkID, DocHash: t.DocHash, TextHash: "x", Vector: vec, Dims: dims}
		}
		if _, err := db.PutKnowledgeEmbeddings(statedb.KnowledgeSyncFence{}, src.ID, e.Model(), rows); err != nil {
			b.Fatal(err)
		}
	}
	principal := PrincipalFor(false, nil, nil, "", "bench")
	query := words[7] + " " + words[1234] + " " + words[42]

	b.Run("lexical", func(b *testing.B) {
		acc := New(db).For(principal)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := acc.Retrieve(context.Background(), projectA, query, DefaultResults); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("hybrid", func(b *testing.B) {
		acc := New(db, WithEmbeddings(Embeddings{Embedder: e})).For(principal)
		b.ReportAllocs()
		b.ResetTimer()
		var candidates int
		for i := 0; i < b.N; i++ {
			res, err := acc.Retrieve(context.Background(), projectA, query, DefaultResults)
			if err != nil {
				b.Fatal(err)
			}
			if res.Retrieval.Mode != RetrievalHybrid || len(res.Hits) != DefaultResults {
				b.Fatalf("a hybrid search = %d hits, %+v", len(res.Hits), res.Retrieval)
			}
			candidates = res.Retrieval.Candidates
		}
		if candidates != docs*perDoc {
			b.Fatalf("the search compared %d vectors, want %d", candidates, docs*perDoc)
		}
		b.ReportMetric(float64(candidates), "vectors/op")
	})
}
