package knowledge

// embedding.go: semantic retrieval's half of a sync (Task 20471) — the
// Embedder an endpoint is reached through, the vectors it returns, and the
// pass that gives each chunk without a current vector one.
//
// It is optional, and off unless the hub's knowledge.embeddings says
// otherwise: turning it on sends the text of every chunk to the endpoint. Off,
// none of this runs and a search ranks by words alone, as it always has.
//
// Nothing here can fail a sync. An endpoint that is down, refuses the key, or
// answers with vectors of the wrong length stops the pass and leaves a warning
// on the sync's status; the chunks it did not reach wait for the next sync,
// and are found by their words until then.

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Embedder turns text into vectors: one embedding endpoint, as the hub's
// knowledge.embeddings names it (pkg/knowledge/embed reaches OpenAI-compatible
// APIs and Voyage AI's).
type Embedder interface {
	// Model names the vectors' model — provider, model and dimensions — as
	// they are stored ("openai/text-embedding-3-small/1536"). A vector is
	// compared only with one of the same model, so a change of any of the
	// three is a new model, and every chunk is embedded again.
	Model() string
	// Dimensions is the length of every vector the endpoint must return.
	Dimensions() int
	// Endpoint names where the text goes, for messages: scheme, host, path.
	Endpoint() string
	// EmbedDocuments returns one vector per text, in order.
	EmbedDocuments(ctx context.Context, texts []string) ([][]float32, error)
	// EmbedQuery returns a search query's vector.
	EmbedQuery(ctx context.Context, text string) ([]float32, error)
}

// Embeddings configures semantic retrieval.
type Embeddings struct {
	// Embedder is the endpoint; nil leaves semantic retrieval off.
	Embedder Embedder
	// BatchSize bounds the chunks one request embeds; zero means
	// DefaultEmbedBatch.
	BatchSize int
	// MaxCandidates bounds the vectors one search compares its query with;
	// zero means DefaultMaxCandidates.
	MaxCandidates int
	// Broken, when set, says why the hub's knowledge.embeddings could not be
	// used — refused at load, say. Syncs record it as their warning and
	// searches rank by words, saying so, rather than going quiet about a
	// feature an administrator turned on.
	Broken string
}

// WithEmbeddings turns semantic retrieval on, or records why it is broken.
func WithEmbeddings(e Embeddings) Option { return func(s *Service) { s.embeddings = e } }

// Semantic retrieval bounds and defaults.
const (
	// DefaultEmbedBatch is how many chunks one request embeds.
	DefaultEmbedBatch = 64
	// maxEmbedBatch bounds BatchSize.
	maxEmbedBatch = 512
	// DefaultMaxCandidates bounds the vectors one search compares.
	DefaultMaxCandidates = 50_000
	// DefaultEmbedBudget bounds how long one sync embeds. A source with more
	// to embed is synced again at once, so a backfill of a large source goes
	// on in slices rather than holding one sync slot for hours.
	DefaultEmbedBudget = 10 * time.Minute
	// maxEmbedInputBytes bounds the text one chunk's vector is made from:
	// past any chunk the chunker makes, with its title and heading.
	maxEmbedInputBytes = 32 << 10
	// maxEmbedWarningBytes bounds a sync's recorded warning.
	maxEmbedWarningBytes = 512
)

// Model is the configured embedding model, or "" when semantic retrieval is
// off or broken.
func (e Embeddings) Model() string {
	if e.Embedder == nil || e.Broken != "" {
		return ""
	}
	return e.Embedder.Model()
}

func (e Embeddings) batchSize() int {
	if e.BatchSize <= 0 {
		return DefaultEmbedBatch
	}
	return min(e.BatchSize, maxEmbedBatch)
}

func (e Embeddings) maxCandidates() int {
	if e.MaxCandidates <= 0 {
		return DefaultMaxCandidates
	}
	return e.MaxCandidates
}

// EmbeddingModel is the embedding model this Service makes and compares
// vectors of, or "" when semantic retrieval is off or broken.
func (s *Service) EmbeddingModel() string { return s.embeddings.Model() }

// Embeddings is how this Service's semantic retrieval is configured.
func (s *Service) Embeddings() Embeddings { return s.embeddings }

// EmbedCounts is what one sync's embedding pass did, as its source records it.
type EmbedCounts struct {
	// Model is the model the pass embedded with.
	Model string `json:"model"`
	// Embedded counts the chunks given a new vector, Reused those whose text
	// had not changed with their document, which kept theirs.
	Embedded int `json:"embedded"`
	Reused   int `json:"reused,omitempty"`
	// Failed counts chunks the endpoint was asked about and gave no usable
	// vector for: it failed, or answered with vectors the pass refused.
	Failed int `json:"failed,omitempty"`
	// Pending counts the source's chunks still without a current vector
	// when the pass ended; -1 when it could not be counted.
	Pending int `json:"pending"`
	// More reports a pass that stopped at its budget with chunks to go.
	More bool `json:"more,omitempty"`
}

// errEmbedderPanicked marks a recovered panic in the embedder.
var errEmbedderPanicked = errors.New("knowledge: the embedder panicked")

// embed gives each chunk of the source without a current vector one, in
// batches, until none is left, the pass's budget is spent, or the endpoint
// fails — which stops the pass and is recorded as the sync's warning. It never
// fails the sync.
func (r *syncRun) embed() {
	em := r.s.embeddings
	if em.Embedder == nil && em.Broken == "" {
		return
	}
	if em.Broken != "" {
		r.report.Warning = clip(redact.Scrub("embeddings: "+em.Broken), maxEmbedWarningBytes)
		return
	}
	model := em.Embedder.Model()
	counts := &EmbedCounts{Model: model, Pending: -1}
	r.report.Embeddings = counts
	budget := r.opts.EmbedBudget
	if budget <= 0 {
		budget = DefaultEmbedBudget
	}
	started := r.s.now()
	var (
		after   int64
		stopped bool
	)
	for {
		if r.ctx.Err() != nil {
			return
		}
		if r.s.now().Sub(started) >= budget {
			stopped = true
			break
		}
		todo, err := r.s.db.PendingKnowledgeEmbeddings(r.ctx, r.row.ID, model, after, em.batchSize())
		if err != nil {
			if r.ctx.Err() == nil {
				r.embedWarning(fmt.Errorf("read the chunks to embed: %w", err))
			}
			return
		}
		if len(todo) == 0 {
			break
		}
		after = todo[len(todo)-1].ChunkID
		writes, failed, err := r.embedBatch(em.Embedder, todo)
		counts.Failed += failed
		if len(writes) > 0 {
			w, werr := r.s.db.PutKnowledgeEmbeddings(r.fence(), r.row.ID, model, writes)
			if werr != nil {
				if !overtaken(werr) && r.ctx.Err() == nil {
					r.embedWarning(fmt.Errorf("store vectors: %w", werr))
				}
				return
			}
			counts.Embedded += w.Stored
			counts.Reused += w.Refreshed
		}
		if err != nil {
			if r.ctx.Err() == nil {
				r.embedWarning(err)
			}
			break
		}
	}
	pending, err := r.s.db.CountPendingKnowledgeEmbeddings(r.ctx, r.row.ID, model)
	if err == nil {
		counts.Pending = pending
		counts.More = stopped && pending > 0
	}
}

// embedBatch embeds one batch: the chunks whose text is the text of the
// vector they already have keep it, and the rest are sent to the endpoint.
// failed counts the chunks sent that came back with no usable vector; err is
// why, and stops the pass.
func (r *syncRun) embedBatch(e Embedder, todo []statedb.KnowledgeEmbeddingTodo) (writes []statedb.KnowledgeEmbedding, failed int, err error) {
	var (
		inputs []string
		sent   []statedb.KnowledgeEmbedding
	)
	for _, t := range todo {
		input := embedInput(t.Title, t.Heading, t.Body)
		hash := textHash(input)
		if t.TextHash != "" && t.TextHash == hash {
			writes = append(writes, statedb.KnowledgeEmbedding{ChunkID: t.ChunkID, DocHash: t.DocHash, TextHash: hash})
			continue
		}
		inputs = append(inputs, input)
		sent = append(sent, statedb.KnowledgeEmbedding{ChunkID: t.ChunkID, DocHash: t.DocHash, TextHash: hash})
	}
	if len(inputs) == 0 {
		return writes, 0, nil
	}
	vectors, err := callEmbedder(func() ([][]float32, error) { return e.EmbedDocuments(r.ctx, inputs) })
	if err != nil {
		return writes, len(inputs), fmt.Errorf("%s failed: %w", e.Endpoint(), err)
	}
	if len(vectors) != len(inputs) {
		return writes, len(inputs), fmt.Errorf("%s answered %d texts with %d vectors; none was stored",
			e.Endpoint(), len(inputs), len(vectors))
	}
	dims := e.Dimensions()
	encoded := make([][]byte, len(vectors))
	for i, v := range vectors {
		b, err := encodeVector(v, dims)
		if err != nil {
			return writes, len(inputs), fmt.Errorf("%s: %w; none of the batch was stored", e.Endpoint(), err)
		}
		encoded[i] = b
	}
	for i := range sent {
		sent[i].Vector, sent[i].Dims = encoded[i], dims
	}
	return append(writes, sent...), 0, nil
}

// embedWarning records why the pass stopped as the sync's warning, scrubbed of
// the source's credential and anything shaped like one.
func (r *syncRun) embedWarning(err error) {
	r.report.Warning = clip(r.scrub("embeddings: "+err.Error()+"; the chunks without a vector wait for the "+
		"next sync, and are found by their words until then"), maxEmbedWarningBytes)
}

// callEmbedder runs one call into the embedder, a panic in it becoming its
// error.
func callEmbedder[T any](fn func() (T, error)) (out T, err error) {
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("%w: %s", errEmbedderPanicked, redact.Scrub(fmt.Sprint(v)))
		}
	}()
	return fn()
}

// embedInput is the text a chunk's vector is made from: where it sits — its
// document's title and its heading path — and what it says. Ancestors are
// left out: they are metadata that changes without the document's content
// hash, and a vector must stand for what that hash covers.
func embedInput(title, heading, body string) string {
	var b strings.Builder
	b.WriteString(strings.TrimSpace(title))
	if h := strings.TrimSpace(heading); h != "" {
		if b.Len() > 0 {
			b.WriteString(headingSeparator)
		}
		b.WriteString(h)
	}
	if body = strings.TrimSpace(body); body != "" {
		if b.Len() > 0 {
			b.WriteString("\n\n")
		}
		b.WriteString(body)
	}
	return clip(b.String(), maxEmbedInputBytes)
}

// textHash identifies the text a vector was made from.
func textHash(input string) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])
}

// unit returns v scaled to unit length, refusing a vector of another length
// than dims, one holding a value that is not a finite number, and the zero
// vector, which points nowhere.
func unit(v []float32, dims int) ([]float32, error) {
	if len(v) != dims {
		return nil, fmt.Errorf("a vector has %d dimensions, and knowledge.embeddings.dimensions is %d", len(v), dims)
	}
	var sum float64
	for _, x := range v {
		f := float64(x)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, errors.New("a vector holds a value that is not a finite number")
		}
		sum += f * f
	}
	if sum == 0 {
		return nil, errors.New("a vector is all zeros")
	}
	norm := math.Sqrt(sum)
	out := make([]float32, len(v))
	for i, x := range v {
		out[i] = float32(float64(x) / norm)
	}
	return out, nil
}

// encodeVector is v as it is stored: unit length, as dims little-endian
// float32 values.
func encodeVector(v []float32, dims int) ([]byte, error) {
	u, err := unit(v, dims)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 4*len(u))
	for i, x := range u {
		binary.LittleEndian.PutUint32(b[4*i:], math.Float32bits(x))
	}
	return b, nil
}

// dot is the dot product of q and a stored vector of the same length: their
// cosine, both being unit length. A stored vector of another length scores
// lowest of all. Four sums at a time: a search computes one per vector of the
// project, and the loop's dependency on a single sum is what bounds it.
func dot(q []float32, stored []byte) float32 {
	if len(stored) != 4*len(q) {
		return -2
	}
	var s0, s1, s2, s3 float32
	i := 0
	for ; i+4 <= len(q); i += 4 {
		b := stored[4*i : 4*i+16]
		s0 += q[i] * math.Float32frombits(binary.LittleEndian.Uint32(b[0:4]))
		s1 += q[i+1] * math.Float32frombits(binary.LittleEndian.Uint32(b[4:8]))
		s2 += q[i+2] * math.Float32frombits(binary.LittleEndian.Uint32(b[8:12]))
		s3 += q[i+3] * math.Float32frombits(binary.LittleEndian.Uint32(b[12:16]))
	}
	for ; i < len(q); i++ {
		s0 += q[i] * math.Float32frombits(binary.LittleEndian.Uint32(stored[4*i:]))
	}
	return (s0 + s1) + (s2 + s3)
}
