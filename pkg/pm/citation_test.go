package pm

import (
	"strings"
	"testing"
)

// TestCitationsAreCleanedAndBounded: a citation is drawn as a link, so only an
// http or https URL is kept — a javascript: or data: one never is — its text is
// bounded and scrubbed, and one that names nothing, or of an unknown kind, is
// dropped.
func TestCitationsAreCleanedAndBounded(t *testing.T) {
	scrub := func(s string) string { return strings.ReplaceAll(s, "hunter2", "[REDACTED]") }
	for _, bad := range []string{"javascript:alert(1)", "data:text/html,x", "//evil.example/x", "file:///etc/passwd"} {
		c, ok := CleanCitation(Citation{Kind: CitationFetched, Title: "t", URL: bad}, scrub)
		if !ok || c.URL != "" {
			t.Errorf("URL %q kept as %q", bad, c.URL)
		}
	}
	c, ok := CleanCitation(Citation{Kind: CitationInjected, Title: "pw hunter2\n" + strings.Repeat("x", 500),
		URL: "https://wiki.example/p?id=1", Source: "Wiki", DocumentID: 3}, scrub)
	if !ok || strings.Contains(c.Title, "hunter2") || strings.Contains(c.Title, "\n") ||
		len([]rune(c.Title)) > MaxCitationTitleRunes || c.URL != "https://wiki.example/p?id=1" {
		t.Fatalf("cleaned = %+v", c)
	}
	for _, drop := range []Citation{{Kind: "read", Title: "t"}, {Kind: CitationFetched}} {
		if _, ok := CleanCitation(drop, nil); ok {
			t.Errorf("%+v was kept", drop)
		}
	}
}

// TestMergeCitations: one citation per document, an injected one replacing a
// fetched one of the same document, at most MaxTaskCitations, and a later
// run's attempt keeping only what its own run cited.
func TestMergeCitations(t *testing.T) {
	have := []Citation{{Kind: CitationFetched, Title: "a", DocumentID: 1, RunID: "r1"}}
	got := MergeCitations(have, []Citation{
		{Kind: CitationInjected, Title: "a again", DocumentID: 1, RunID: "r1"},
		{Kind: CitationFetched, Title: "b", URL: "https://x/b", RunID: "r1"},
		{Kind: CitationFetched, Title: "b dup", URL: "https://x/b", RunID: "r1"},
	}, nil)
	if len(got) != 2 || got[0].Kind != CitationInjected || got[0].Title != "a again" || got[1].Title != "b" {
		t.Fatalf("merged = %+v", got)
	}
	var many []Citation
	for i := range 100 {
		many = append(many, Citation{Kind: CitationFetched, Title: "d", DocumentID: int64(i + 1)})
	}
	if n := len(MergeCitations(nil, many, nil)); n != MaxTaskCitations {
		t.Fatalf("kept %d citations", n)
	}
	mixed := []Citation{{Kind: CitationFetched, Title: "old", RunID: "r0"}, {Kind: CitationFetched, Title: "new", RunID: "r1"}}
	if kept := CitationsOfRun(mixed, "r1"); len(kept) != 1 || kept[0].Title != "new" {
		t.Fatalf("CitationsOfRun = %+v", kept)
	}
}

func TestKnowledgeRetrievalDefaultsAndBounds(t *testing.T) {
	var none *KnowledgeRetrieval
	if !none.Enabled() || none.Passages() != DefaultRetrievalK || none.Tokens() != DefaultRetrievalTokens {
		t.Fatalf("defaults: %v %d %d", none.Enabled(), none.Passages(), none.Tokens())
	}
	off := &KnowledgeRetrieval{Disabled: true, K: 50, TokenBudget: 99999}
	if off.Enabled() || off.Passages() != MaxRetrievalK || off.Tokens() != MaxRetrievalTokens {
		t.Fatalf("clamped: %v %d %d", off.Enabled(), off.Passages(), off.Tokens())
	}
	for _, bad := range []KnowledgeRetrieval{{K: -1}, {K: MaxRetrievalK + 1}, {TokenBudget: 10}, {TokenBudget: MaxRetrievalTokens + 1}} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%+v validated", bad)
		}
	}
	if err := (&KnowledgeRetrieval{K: 3, TokenBudget: 800}).Validate(); err != nil {
		t.Errorf("a valid setting: %v", err)
	}
}
