package knowledge

// run.go: what a run reads of its project's knowledge (Task 20472).
//
// A run is not a person: it holds no role anywhere, only the knowledge session
// the hub minted for it, which names one project. RunPrincipal is that session
// as this package's authorization sees it — read access to that project and
// nothing else — so every operation a run reaches goes through the same
// requireProject, bindings and narrowing a person's search does, and a run
// asking about any other project is told it does not exist.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// RunPrincipal is the principal a run's knowledge session acts as: viewer of
// project — the path its session names — and of nothing else. actor names the
// run in the audit trail.
func RunPrincipal(project Project, actor string) Principal {
	path := strings.TrimSpace(project.Path)
	return Principal{
		Actor: actor,
		Decide: func(scope authz.Scope) authz.Decision {
			if path != "" && scope.ProjectPath == path {
				return authz.FromRoles([]authz.Role{authz.RoleViewer}, authz.SourceRunSession, actor, scope)
			}
			return authz.Deny(authz.SourceRunSession, actor, scope)
		},
	}
}

// Passage is one chunk's text, with what places it.
type Passage struct {
	ChunkID    int64
	DocumentID int64
	Source     SourceRef
	Title      string
	URL        string
	Space      string
	Heading    string
	Ancestors  []string
	Text       string
}

// Passages returns the text of the chunks ids names that project may read,
// keyed by chunk id — through the project's bindings again, so a chunk whose
// binding went since a search found it is left out.
func (a *Access) Passages(ctx context.Context, project Project, ids []int64) (map[int64]Passage, error) {
	if err := a.requireProject(project, authz.PermProjectRead); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return map[int64]Passage{}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, searchTimeout)
	defer cancel()
	rows, err := a.s.db.KnowledgeChunkHits(ctx, project.Path, ids)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%w: reading the passages took longer than %s", ErrUnavailable, searchTimeout)
		}
		return nil, err
	}
	out := make(map[int64]Passage, len(rows))
	for _, r := range rows {
		out[r.ChunkID] = Passage{
			ChunkID: r.ChunkID, DocumentID: r.DocumentID,
			Source: SourceRef{ID: r.SourceID, Name: r.SourceName, Kind: r.SourceKind},
			Title:  r.Title, URL: r.URL, Space: r.SpaceKey, Heading: r.Heading, Ancestors: r.Ancestors, Text: r.Body,
		}
	}
	return out, nil
}

// DocumentRef names one document: by the hub's id, the URL a person reads it
// at, or its key at its source — a Jira issue key. Exactly one is set.
type DocumentRef struct {
	ID  int64
	URL string
	Key string
}

// DocumentText is a document as a run reads it whole.
type DocumentText struct {
	ID        int64
	Source    SourceRef
	Title     string
	URL       string
	Space     string
	Ancestors []string
	UpdatedAt time.Time
	// Text is its chunks in order, each section's heading on a line of its
	// own.
	Text string
	// Truncated reports text cut at the bound asked for, or a document the
	// index holds only in part.
	Truncated bool
}

// MaxDocumentRefKeyBytes bounds a key or URL a run looks a document up by.
const MaxDocumentRefKeyBytes = 2048

// Documents returns the documents ref names that project may read, each with
// at most maxBytes of its text — none, and no error, when the project's
// knowledge has nothing by that name. Text is not given for metaOnly.
func (a *Access) Documents(ctx context.Context, project Project, ref DocumentRef, maxBytes int, metaOnly bool) ([]DocumentText, error) {
	if err := a.requireProject(project, authz.PermProjectRead); err != nil {
		return nil, err
	}
	lookup := statedb.KnowledgeDocumentLookup{ID: ref.ID, URL: strings.TrimSpace(ref.URL), Key: strings.TrimSpace(ref.Key)}
	named := 0
	for _, set := range []bool{lookup.ID > 0, lookup.URL != "", lookup.Key != ""} {
		if set {
			named++
		}
	}
	switch {
	case named != 1:
		return nil, invalid("a document is named by exactly one of its id, its URL or its key")
	case len(lookup.URL) > MaxDocumentRefKeyBytes || len(lookup.Key) > MaxDocumentRefKeyBytes:
		return nil, invalid("a document's URL or key is at most %d bytes", MaxDocumentRefKeyBytes)
	case ref.ID < 0:
		return nil, invalid("a document id is a positive number")
	}
	ctx, cancel := context.WithTimeout(ctx, searchTimeout)
	defer cancel()
	select {
	case searchSlots <- struct{}{}:
		defer func() { <-searchSlots }()
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: the hub is busy with other searches; try again", ErrUnavailable)
	}
	docs, err := a.s.db.KnowledgeProjectDocuments(ctx, project.Path, lookup)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%w: the lookup took longer than %s", ErrUnavailable, searchTimeout)
		}
		return nil, err
	}
	out := make([]DocumentText, 0, len(docs))
	for _, d := range docs {
		dt := DocumentText{
			ID: d.ID, Source: SourceRef{ID: d.SourceID, Name: d.SourceName, Kind: d.SourceKind},
			Title: d.Title, URL: d.URL, Space: d.SpaceKey, Ancestors: d.Ancestors, UpdatedAt: d.RemoteUpdatedAt,
			Truncated: d.Truncated,
		}
		if !metaOnly && maxBytes > 0 {
			chunks, cut, err := a.s.db.KnowledgeProjectDocumentChunks(ctx, project.Path, d.ID, maxBytes)
			if err != nil {
				if ctx.Err() != nil {
					return nil, fmt.Errorf("%w: reading the document took longer than %s", ErrUnavailable, searchTimeout)
				}
				return nil, err
			}
			text, clipped := documentText(chunks, maxBytes)
			dt.Text, dt.Truncated = text, dt.Truncated || cut || clipped
		}
		out = append(out, dt)
	}
	return out, nil
}

// documentText joins a document's chunks into its text: each chunk whose
// heading differs from the one before it begins with that heading, marked as
// a Markdown heading. It reports whether maxBytes cut it.
func documentText(chunks []statedb.KnowledgeDocumentChunk, maxBytes int) (string, bool) {
	var (
		b       strings.Builder
		heading string
	)
	for i, c := range chunks {
		if c.Heading != "" && c.Heading != heading {
			if b.Len() > 0 {
				b.WriteString("\n")
			}
			b.WriteString("## " + c.Heading + "\n")
		} else if i > 0 {
			b.WriteString("\n")
		}
		heading = c.Heading
		b.WriteString(strings.TrimSpace(c.Text))
		b.WriteString("\n")
	}
	text := b.String()
	if len(text) <= maxBytes {
		return text, false
	}
	return strings.ToValidUTF8(text[:maxBytes], ""), true
}
