package knowledge

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/boundedread"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// prepared is a document made fit to store: bounded, cleaned, scrubbed and
// hashed.
type prepared struct {
	row  statedb.KnowledgeDocumentRow
	body string
}

// prepare bounds and cleans what a connector delivered. A document with no
// usable external id is refused; everything else is cut to its bound or
// dropped rather than refused, so one odd field does not keep a page out of
// the index.
//
// The body is read through pkg/boundedread — at most MaxBodyBytes, cut back to
// whole characters — and the title and body are scrubbed of anything shaped
// like a credential (pkg/redact's registry): a token pasted into a wiki page
// is not republished to every project bound to the wiki, nor quoted into an
// agent's prompt.
func prepare(sourceID int64, doc Document, opts ChunkOptions) (prepared, error) {
	id := strings.TrimSpace(doc.ExternalID)
	switch {
	case id == "":
		return prepared{}, invalid("a document needs an external id")
	case len(id) > MaxExternalIDBytes:
		return prepared{}, invalid("a document's external id is at most %d bytes", MaxExternalIDBytes)
	case !utf8.ValidString(id) || strings.IndexFunc(id, unicode.IsControl) >= 0:
		return prepared{}, invalid("a document's external id must be printable text")
	}
	b, truncated, err := boundedread.ReadTruncated(strings.NewReader(doc.Body), MaxBodyBytes)
	if err != nil {
		return prepared{}, fmt.Errorf("knowledge: read the body of %q: %w", id, err)
	}
	if truncated {
		b = trimPartialRune(b)
	}
	body := redact.Scrub(strings.ToValidUTF8(string(b), "�"))
	title := redact.Scrub(clip(oneLine(doc.Title), MaxTitleBytes))
	if title == "" {
		title = id
	}
	row := statedb.KnowledgeDocumentRow{
		SourceID:        sourceID,
		ExternalID:      id,
		Title:           title,
		URL:             cleanURL(doc.URL),
		SpaceKey:        clip(oneLine(doc.Space), MaxSpaceKeyBytes),
		RemoteUpdatedAt: doc.UpdatedAt,
		ACL:             cleanACL(doc.ACL),
		Ancestors:       cleanAncestors(doc.Ancestors),
		BodyBytes:       len(body),
		Truncated:       truncated,
	}
	row.ContentHash = contentHash(title, body, opts)
	return prepared{row: row, body: body}, nil
}

// contentHash identifies what chunks are made from: the chunker, how it was
// configured, the title and the body. Equal hashes mean equal chunks.
func contentHash(title, body string, opts ChunkOptions) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%d\x00%d\x00%d\x00", chunkerVersion, opts.MaxTokens, opts.OverlapTokens, len(title))
	h.Write([]byte(title))
	h.Write([]byte{0})
	h.Write([]byte(body))
	return hex.EncodeToString(h.Sum(nil))
}

// oneLine turns every run of control characters and spaces into one space.
func oneLine(s string) string {
	s = strings.ToValidUTF8(s, "")
	return strings.Join(strings.FieldsFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}), " ")
}

// clip cuts s to at most n bytes, on a character boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// cleanURL keeps an absolute http or https URL of at most MaxURLBytes, and
// drops anything else: the URL is what a dashboard links to, and a
// javascript: or data: link from a remote source is not one it should render.
func cleanURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > MaxURLBytes || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return ""
	}
	return u.String()
}

// cleanACL bounds, deduplicates and sorts a document's access hints.
func cleanACL(hints []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range hints {
		h = clip(oneLine(h), MaxACLHintBytes)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	sort.Strings(out)
	if len(out) > MaxACLHints {
		out = out[:MaxACLHints]
	}
	return out
}

// cleanAncestors bounds a document's ancestors: each one line, at most
// MaxTitleBytes and scrubbed like a title, the empty ones dropped, and at most
// MaxAncestors of them — the innermost, which place it best. Order is kept and
// repeats are too: two pages above this one may share a title.
func cleanAncestors(titles []string) []string {
	var out []string
	for _, t := range titles {
		if t = redact.Scrub(clip(oneLine(t), MaxTitleBytes)); t != "" {
			out = append(out, t)
		}
	}
	if len(out) > MaxAncestors {
		out = out[len(out)-MaxAncestors:]
	}
	return out
}

// Index stores one document of source sourceID — chunked and indexed, or, if
// its content hash is the one already stored, with only its metadata updated
// — and says which. It is what a sync does with each document a connector
// lists, exported for connector packages' tests; it authorizes nothing, and is
// not reachable from a request.
func (s *Service) Index(sourceID int64, doc Document) (statedb.KnowledgeIndexOutcome, error) {
	return s.index(sourceID, doc, s.now())
}

// index is Index, stamping the document as listed at listedAt.
func (s *Service) index(sourceID int64, doc Document, listedAt time.Time) (statedb.KnowledgeIndexOutcome, error) {
	p, err := prepare(sourceID, doc, s.chunking)
	if err != nil {
		return "", err
	}
	p.row.ListedAt = listedAt
	return s.db.IndexKnowledgeDocument(p.row, func() ([]statedb.KnowledgeChunk, bool) {
		if s.onChunk != nil {
			s.onChunk()
		}
		chunks, capped := ChunkDocument(p.row.Title, p.body, s.chunking)
		out := make([]statedb.KnowledgeChunk, len(chunks))
		for i, c := range chunks {
			out[i] = statedb.KnowledgeChunk{Heading: c.Heading, Text: c.Text, Tokens: c.Tokens}
		}
		return out, capped
	})
}
