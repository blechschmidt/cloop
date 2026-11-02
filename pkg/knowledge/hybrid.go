package knowledge

// hybrid.go: semantic retrieval's half of a search (Task 20471).
//
// With an Embedder configured, a search ranks a project's chunks twice: by
// words, through the full-text index's BM25 as before, and by meaning — the
// query's vector compared, by a brute-force cosine scan, with the vector of
// every chunk the project's bound sources hold, through the same bindings and
// narrowing the full-text search applies. The two rankings are fused by
// reciprocal rank: a chunk scores 1/(60+r) for each ranking that places it at
// r, so one both place well beats one either places first, and neither
// ranking's scale — BM25's, the cosine's — has to be made comparable with the
// other's. What a hit carries is still its place, never a score.
//
// The query's vector is asked for while the words are ranked. When it cannot
// be had — the endpoint is down, slow, refuses the key, or answers with a
// vector of the wrong length — the search returns the words' ranking and says
// why; it never fails because of the endpoint.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// How a search ranked, as Retrieval.Mode says and the hub's
// cloop_knowledge_searches_total counts.
const (
	// RetrievalLexical ranks by words alone: semantic retrieval is off, or
	// the query could not be embedded.
	RetrievalLexical = "lexical"
	// RetrievalHybrid fuses the words' ranking with the vectors'.
	RetrievalHybrid = "hybrid"
	// RetrievalFallback is counted, never returned as a mode: a search that
	// would have been hybrid and ranked by words alone instead.
	RetrievalFallback = "fallback"
)

// Hybrid search bounds.
const (
	// rrfK is reciprocal-rank fusion's constant: the rank a hit's score is
	// damped by, the value its authors found robust across collections.
	rrfK = 60
	// minFusionDepth is how many hits each ranking contributes at least to
	// the fusion; a search asking for more contributes twice what it asks for,
	// up to MaxResults.
	minFusionDepth = 20
	// snippetWords is how long a snippet made from a chunk's text is.
	snippetWords = 32
)

// queryEmbedTimeout bounds the wait for the query's vector: past it the search
// ranks by words, which were ranked meanwhile. A variable for tests.
var queryEmbedTimeout = 5 * time.Second

// SearchResult is a search's hits, best first, and how they were ranked.
type SearchResult struct {
	Hits      []Hit
	Retrieval Retrieval
}

// Retrieval says how a search ranked.
type Retrieval struct {
	// Mode is RetrievalHybrid or RetrievalLexical.
	Mode string
	// Model is the embedding model whose vectors a hybrid search compared,
	// or the one a fallen-back search would have.
	Model string
	// Candidates counts the vectors the query was compared with; Capped
	// reports that the project's sources hold more current vectors than one
	// search compares, so only that many were.
	Candidates int
	Capped     bool
	// Warning says why a search that would have been hybrid ranked by words
	// alone. Empty otherwise.
	Warning string
}

// Search is Retrieve without how the hits were ranked.
func (a *Access) Search(ctx context.Context, project Project, query string, k int) ([]Hit, error) {
	res, err := a.Retrieve(ctx, project, query, k)
	return res.Hits, err
}

// Retrieve returns the k chunks of project's knowledge that best match query,
// best first: only sources bound to project, through each binding's
// narrowing. k <= 0 means DefaultResults; more than MaxResults is cut to it.
// With semantic retrieval on, the ranking by words is fused with the ranking
// by meaning (see this file's header); with it off, or when the query cannot
// be embedded, it is the ranking by words, and Retrieval says which.
//
// A hit says where it ranks, never its BM25 score. FTS5 weighs a term by how
// rare it is across the whole index — every project's sources — so a score,
// read against a chunk the caller can see, would tell them how often a word
// occurs in knowledge bound only to other projects.
func (a *Access) Retrieve(ctx context.Context, project Project, query string, k int) (SearchResult, error) {
	if err := a.requireProject(project, authz.PermProjectRead); err != nil {
		return SearchResult{}, err
	}
	match, err := MatchExpression(query)
	if err != nil {
		return SearchResult{}, err
	}
	if k <= 0 {
		k = DefaultResults
	}
	k = min(k, MaxResults)
	ctx, cancel := context.WithTimeout(ctx, searchTimeout)
	defer cancel()
	select {
	case searchSlots <- struct{}{}:
		defer func() { <-searchSlots }()
	case <-ctx.Done():
		return SearchResult{}, fmt.Errorf("%w: the hub is busy with other searches; try again", ErrUnavailable)
	}
	em := a.s.embeddings
	switch {
	case em.Embedder == nil && em.Broken == "":
		rows, err := a.lexical(ctx, project, match, k)
		if err != nil {
			return SearchResult{}, err
		}
		hubmetrics.KnowledgeSearches.Inc(RetrievalLexical)
		return SearchResult{Hits: lexicalHits(rows), Retrieval: Retrieval{Mode: RetrievalLexical}}, nil
	case em.Broken != "":
		rows, err := a.lexical(ctx, project, match, k)
		if err != nil {
			return SearchResult{}, err
		}
		hubmetrics.KnowledgeSearches.Inc(RetrievalFallback)
		return SearchResult{Hits: lexicalHits(rows), Retrieval: Retrieval{Mode: RetrievalLexical,
			Warning: clip(redact.Scrub("embeddings: "+em.Broken+"; ranked by words alone"), maxEmbedWarningBytes)}}, nil
	}
	return a.hybrid(ctx, project, query, match, k)
}

// lexical runs the full-text search: the best limit chunks by BM25.
func (a *Access) lexical(ctx context.Context, project Project, match string, limit int) ([]statedb.KnowledgeHit, error) {
	rows, err := a.s.db.SearchKnowledge(ctx, statedb.KnowledgeSearchQuery{
		ProjectPath: project.Path, Match: match, Limit: limit,
		SnippetOpen: SnippetOpen, SnippetClose: SnippetClose, SnippetEllipsis: SnippetEllipsis, SnippetTokens: 32,
	})
	switch {
	case errors.Is(err, statedb.ErrKnowledgeQuery):
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	case err != nil && ctx.Err() != nil:
		return nil, fmt.Errorf("%w: the search took longer than %s; narrow the query", ErrUnavailable, searchTimeout)
	case err != nil:
		return nil, err
	}
	return rows, nil
}

// lexicalHits makes hits of full-text rows, ranked in their order.
func lexicalHits(rows []statedb.KnowledgeHit) []Hit {
	out := make([]Hit, 0, len(rows))
	for _, r := range rows {
		h := hitOf(r, r.Snippet)
		h.Rank, h.Lexical = len(out)+1, true
		out = append(out, h)
	}
	return out
}

func hitOf(r statedb.KnowledgeHit, snippet string) Hit {
	if strings.TrimSpace(snippet) == "" {
		snippet = r.Title
	}
	return Hit{
		ChunkID: r.ChunkID, DocumentID: r.DocumentID,
		Source: SourceRef{ID: r.SourceID, Name: r.SourceName, Kind: r.SourceKind},
		Title:  r.Title, URL: r.URL, Space: r.SpaceKey, ExternalID: r.ExternalID, Heading: r.Heading,
		Ancestors: r.Ancestors, Snippet: snippet, Ordinal: r.Ordinal,
	}
}

// queryVector is the answer to a query's embedding.
type queryVector struct {
	v   []float32
	err error
}

// hybrid ranks by words and by meaning and fuses the two, falling back to the
// words' ranking whenever the meaning's cannot be had.
func (a *Access) hybrid(ctx context.Context, project Project, query, match string, k int) (SearchResult, error) {
	em := a.s.embeddings
	e := em.Embedder
	model := e.Model()
	depth := min(MaxResults, max(2*k, minFusionDepth))

	// The query's vector is asked for while the words are ranked.
	ectx, ecancel := context.WithTimeout(ctx, queryEmbedTimeout)
	defer ecancel()
	answer := make(chan queryVector, 1)
	go func() {
		v, err := callEmbedder(func() ([]float32, error) { return e.EmbedQuery(ectx, strings.TrimSpace(query)) })
		answer <- queryVector{v: v, err: err}
	}()
	lex, err := a.lexical(ctx, project, match, depth)
	if err != nil {
		return SearchResult{}, err
	}
	fallback := func(why string) (SearchResult, error) {
		hubmetrics.KnowledgeSearches.Inc(RetrievalFallback)
		return SearchResult{Hits: lexicalHits(lex[:min(k, len(lex))]), Retrieval: Retrieval{
			Mode: RetrievalLexical, Model: model,
			Warning: clip(redact.Scrub("embeddings: "+why+"; ranked by words alone"), maxEmbedWarningBytes),
		}}, nil
	}
	var q queryVector
	select {
	case q = <-answer:
	case <-ectx.Done():
		q.err = fmt.Errorf("no answer within %s", queryEmbedTimeout)
	}
	if q.err != nil {
		return fallback(fmt.Sprintf("the query could not be embedded by %s: %v", e.Endpoint(), q.err))
	}
	qv, err := unit(q.v, e.Dimensions())
	if err != nil {
		return fallback(fmt.Sprintf("%s answered the query with a vector the hub refuses: %v", e.Endpoint(), err))
	}

	top := newTopVectors(depth)
	scanStarted := time.Now()
	scan, err := a.s.db.ScanKnowledgeVectors(ctx, statedb.KnowledgeVectorQuery{
		ProjectPath: project.Path, Model: model, Dims: len(qv), Limit: em.maxCandidates(),
	}, func(id int64, vec []byte) error {
		top.offer(id, dot(qv, vec))
		return nil
	})
	hubmetrics.KnowledgeSearchVectorScanDuration.Observe(time.Since(scanStarted).Seconds())
	hubmetrics.KnowledgeSearchVectorsCompared.Add(float64(scan.Candidates))
	if scan.Capped {
		hubmetrics.KnowledgeSearchVectorsCapped.Inc()
	}
	if err != nil {
		if ctx.Err() != nil {
			return fallback(fmt.Sprintf("comparing %d vectors took longer than the search may", scan.Candidates))
		}
		return fallback("the vectors could not be read: " + err.Error())
	}

	lexical := make(map[int64]statedb.KnowledgeHit, len(lex))
	lexIDs := make([]int64, len(lex))
	for i, r := range lex {
		lexIDs[i] = r.ChunkID
		lexical[r.ChunkID] = r
	}
	fused := fuse(lexIDs, top.best())
	// Each chunk only the vectors found is read now, through the project's
	// bindings again: one unbound since the scan is not returned.
	var need []int64
	for _, c := range fused {
		if c.lexRank == 0 {
			need = append(need, c.id)
		}
	}
	extra := map[int64]statedb.KnowledgeChunkHit{}
	if len(need) > 0 {
		rows, err := a.s.db.KnowledgeChunkHits(ctx, project.Path, need)
		if err != nil {
			if ctx.Err() != nil {
				return fallback("the search by meaning took longer than the search may")
			}
			return fallback("the chunks found by meaning could not be read: " + err.Error())
		}
		for _, r := range rows {
			extra[r.ChunkID] = r
		}
	}
	terms := queryTerms(query)
	hits := make([]Hit, 0, k)
	for _, c := range fused {
		if len(hits) == k {
			break
		}
		var h Hit
		if r, ok := lexical[c.id]; ok {
			h = hitOf(r, r.Snippet)
		} else if r, ok := extra[c.id]; ok {
			h = hitOf(r.KnowledgeHit, plainSnippet(r.Body, terms))
		} else {
			continue
		}
		h.Rank, h.Lexical, h.Semantic = len(hits)+1, c.lexRank > 0, c.semRank > 0
		hits = append(hits, h)
	}
	hubmetrics.KnowledgeSearches.Inc(RetrievalHybrid)
	return SearchResult{Hits: hits, Retrieval: Retrieval{Mode: RetrievalHybrid, Model: model,
		Candidates: scan.Candidates, Capped: scan.Capped}}, nil
}

// fusedHit is one chunk's place in the fused ranking.
type fusedHit struct {
	id int64
	// lexRank and semRank are its places in the two rankings, from 1; 0
	// where it is absent.
	lexRank, semRank int
	score            float64
}

// fuse merges two rankings, each best first, by reciprocal rank. A tie —
// equal scores, as a chunk only the words placed first and one only the
// vectors placed first have — goes to the words' ranking, whose matches are
// the query's own terms; then to the vectors'; then to the lower chunk id, so
// the order is the same every time.
func fuse(lexical, semantic []int64) []fusedHit {
	at := make(map[int64]int, len(lexical)+len(semantic))
	var out []fusedHit
	get := func(id int64) *fusedHit {
		if i, ok := at[id]; ok {
			return &out[i]
		}
		at[id] = len(out)
		out = append(out, fusedHit{id: id})
		return &out[len(out)-1]
	}
	for i, id := range lexical {
		if h := get(id); h.lexRank == 0 {
			h.lexRank = i + 1
			h.score += 1 / float64(rrfK+i+1)
		}
	}
	for i, id := range semantic {
		if h := get(id); h.semRank == 0 {
			h.semRank = i + 1
			h.score += 1 / float64(rrfK+i+1)
		}
	}
	placed := func(r int) int {
		if r == 0 {
			return 1 << 30
		}
		return r
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.score != b.score {
			return a.score > b.score
		}
		if placed(a.lexRank) != placed(b.lexRank) {
			return placed(a.lexRank) < placed(b.lexRank)
		}
		if placed(a.semRank) != placed(b.semRank) {
			return placed(a.semRank) < placed(b.semRank)
		}
		return a.id < b.id
	})
	return out
}

// topVectors keeps the n best-scoring chunks a scan offers: a min-heap on the
// score, so each offer costs a comparison with the worst kept.
type topVectors struct {
	n    int
	heap []scoredChunk
}

type scoredChunk struct {
	id    int64
	score float32
}

func newTopVectors(n int) *topVectors { return &topVectors{n: n, heap: make([]scoredChunk, 0, n)} }

// worse orders the heap: a lower score, then — for equal scores — a higher
// id, so of two equals the lower id is kept, as fuse breaks ties.
func worse(a, b scoredChunk) bool {
	if a.score != b.score {
		return a.score < b.score
	}
	return a.id > b.id
}

func (t *topVectors) offer(id int64, score float32) {
	c := scoredChunk{id: id, score: score}
	if len(t.heap) < t.n {
		t.heap = append(t.heap, c)
		for i := len(t.heap) - 1; i > 0; {
			p := (i - 1) / 2
			if !worse(t.heap[i], t.heap[p]) {
				break
			}
			t.heap[i], t.heap[p] = t.heap[p], t.heap[i]
			i = p
		}
		return
	}
	if t.n == 0 || !worse(t.heap[0], c) {
		return
	}
	t.heap[0] = c
	for i := 0; ; {
		l, r, m := 2*i+1, 2*i+2, i
		if l < len(t.heap) && worse(t.heap[l], t.heap[m]) {
			m = l
		}
		if r < len(t.heap) && worse(t.heap[r], t.heap[m]) {
			m = r
		}
		if m == i {
			break
		}
		t.heap[i], t.heap[m] = t.heap[m], t.heap[i]
		i = m
	}
}

// best returns the kept chunk ids, best first.
func (t *topVectors) best() []int64 {
	kept := append([]scoredChunk(nil), t.heap...)
	sort.Slice(kept, func(i, j int) bool { return worse(kept[j], kept[i]) })
	out := make([]int64, len(kept))
	for i, c := range kept {
		out[i] = c.id
	}
	return out
}

// queryTerms are the words of a query a snippet marks: lower-cased, without
// the quotes and prefix stars of the query syntax, and holding a letter or
// digit.
func queryTerms(query string) map[string]bool {
	terms := map[string]bool{}
	for _, f := range strings.Fields(strings.ToLower(query)) {
		if w := strings.TrimFunc(f, notWordRune); w != "" {
			terms[w] = true
		}
	}
	return terms
}

func notWordRune(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }

// plainSnippet is a snippet of a chunk found by meaning, which the full-text
// index cannot make one for: snippetWords words of its text, from a little
// before the first word of the query it holds — from its start when it holds
// none — with the query's words marked as the index marks them.
func plainSnippet(body string, terms map[string]bool) string {
	words := strings.Fields(body)
	if len(words) == 0 {
		return ""
	}
	start := 0
	for i, w := range words {
		if terms[strings.ToLower(strings.TrimFunc(w, notWordRune))] {
			start = max(0, i-snippetWords/4)
			break
		}
	}
	end := min(len(words), start+snippetWords)
	var b strings.Builder
	if start > 0 {
		b.WriteString(SnippetEllipsis)
	}
	for i, w := range words[start:end] {
		if i > 0 {
			b.WriteByte(' ')
		}
		if core := strings.TrimFunc(w, notWordRune); core != "" && terms[strings.ToLower(core)] {
			lead := strings.Index(w, core)
			b.WriteString(w[:lead] + SnippetOpen + core + SnippetClose + w[lead+len(core):])
			continue
		}
		b.WriteString(w)
	}
	if end < len(words) {
		b.WriteString(SnippetEllipsis)
	}
	return b.String()
}
