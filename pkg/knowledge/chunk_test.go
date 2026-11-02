package knowledge

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/boundedread"
)

func headings(chunks []Chunk) []string {
	var out []string
	for _, c := range chunks {
		out = append(out, c.Heading)
	}
	return out
}

// TestChunkDocumentSplitsOnHeadingsFirst: no chunk spans two sections, each
// chunk carries its heading path, and nested headings build an outline that
// a shallower heading closes.
func TestChunkDocumentSplitsOnHeadingsFirst(t *testing.T) {
	body := strings.Join([]string{
		"Intro text before any heading.",
		"",
		"# Install",
		"Install the package.",
		"",
		"## Linux",
		"Use apt.",
		"",
		"### Debian",
		"Debian specifics.",
		"",
		"## macOS",
		"Use brew.",
		"",
		"Usage",
		"=====",
		"Run it.",
		"",
		"Options",
		"-------",
		"Flags here.",
	}, "\n")
	chunks, capped := ChunkDocument("Guide", body, ChunkOptions{})
	if capped {
		t.Fatal("a short document was capped")
	}
	want := []string{"", "Install", "Install › Linux", "Install › Linux › Debian", "Install › macOS", "Usage", "Usage › Options"}
	if got := headings(chunks); !reflect.DeepEqual(got, want) {
		t.Fatalf("headings = %q\nwant      %q", got, want)
	}
	texts := map[string]string{}
	for _, c := range chunks {
		texts[c.Heading] = c.Text
	}
	if texts["Install › Linux"] != "Use apt." || texts["Usage › Options"] != "Flags here." {
		t.Fatalf("a section's chunk holds text of another: %q", texts)
	}
}

// TestChunkDocumentPacksParagraphsWithinTheBound: paragraphs are kept whole
// and packed until the next would cross MaxTokens; consecutive chunks of a
// section overlap; no chunk exceeds the bound.
func TestChunkDocumentPacksParagraphsWithinTheBound(t *testing.T) {
	var paras []string
	for i := 0; i < 40; i++ {
		paras = append(paras, strings.Repeat("word"+string(rune('a'+i%26))+" ", 20)+"end.")
	}
	body := "# Section\n" + strings.Join(paras, "\n\n")
	opts := ChunkOptions{MaxTokens: 100, OverlapTokens: 20}
	chunks, _ := ChunkDocument("T", body, opts)
	if len(chunks) < 10 {
		t.Fatalf("40 paragraphs of ~30 tokens in 100-token chunks made only %d chunks", len(chunks))
	}
	for i, c := range chunks {
		if c.Tokens > opts.MaxTokens || EstimateTokens(c.Text) != c.Tokens {
			t.Fatalf("chunk %d has %d tokens (text %d), bound %d", i, c.Tokens, EstimateTokens(c.Text), opts.MaxTokens)
		}
		if c.Heading != "Section" {
			t.Fatalf("chunk %d heading %q", i, c.Heading)
		}
	}
	// Every paragraph appears whole in some chunk.
	all := ""
	for _, c := range chunks {
		all += "\n\n" + c.Text
	}
	for i, p := range paras {
		if !strings.Contains(all, strings.TrimSpace(p)) {
			t.Fatalf("paragraph %d is not whole in any chunk", i)
		}
	}
	// Overlap: each chunk after the first starts with words the previous one
	// ended with.
	for i := 1; i < len(chunks); i++ {
		prev := strings.Fields(chunks[i-1].Text)
		first := strings.Fields(chunks[i].Text)[0]
		if first != prev[len(prev)-1] && !strings.Contains(chunks[i-1].Text, first) {
			t.Fatalf("chunk %d does not overlap chunk %d: starts %q", i, i-1, first)
		}
	}
	// Without overlap, no text repeats.
	plain, _ := ChunkDocument("T", body, ChunkOptions{MaxTokens: 100, OverlapTokens: -1})
	words := 0
	for _, c := range plain {
		words += len(strings.Fields(c.Text))
	}
	if words != 40*21 {
		t.Fatalf("without overlap the chunks hold %d words, want %d", words, 40*21)
	}
}

// TestChunkDocumentCutsALongParagraph: a paragraph over the bound is cut at
// sentences, a sentence over it between words, and a word over it inside the
// word, every piece within the bound.
func TestChunkDocumentCutsALongParagraph(t *testing.T) {
	sentence := strings.Repeat("alpha beta gamma ", 10) + "end."
	long := strings.Repeat(sentence+" ", 20)
	blob := strings.Repeat("x", 3000) // no spaces at all
	chunks, _ := ChunkDocument("T", long+"\n\n"+blob, ChunkOptions{MaxTokens: 64, OverlapTokens: -1})
	for i, c := range chunks {
		if c.Tokens > 64 {
			t.Fatalf("chunk %d has %d tokens, over the bound", i, c.Tokens)
		}
	}
	joined := ""
	for _, c := range chunks {
		joined += c.Text
	}
	if strings.Count(joined, "x") != 3000 {
		t.Fatalf("the spaceless run lost characters: %d x's", strings.Count(joined, "x"))
	}
	if strings.Count(joined, "end.") != 20 {
		t.Fatalf("sentences were lost: %d", strings.Count(joined, "end."))
	}
}

// TestChunkDocumentEdgeCases: fenced code is text, a thematic break only
// separates, an empty body with a title is one empty chunk, nothing at all is
// no chunk, and the output is deterministic.
func TestChunkDocumentEdgeCases(t *testing.T) {
	body := "# Setup\n```bash\n# not a heading\necho hi\n```\n\n---\n\nAfter the break."
	chunks, _ := ChunkDocument("T", body, ChunkOptions{})
	if len(chunks) != 1 || chunks[0].Heading != "Setup" {
		t.Fatalf("chunks = %+v; the comment in the fence became a heading", chunks)
	}
	if strings.Contains(chunks[0].Text, "---") || !strings.Contains(chunks[0].Text, "# not a heading") {
		t.Fatalf("chunk text %q", chunks[0].Text)
	}
	if c, _ := ChunkDocument("Only a title", "  \n\n ", ChunkOptions{}); len(c) != 1 || c[0].Text != "" {
		t.Fatalf("a title with no body = %+v, want one empty chunk", c)
	}
	if c, _ := ChunkDocument("", "", ChunkOptions{}); len(c) != 0 {
		t.Fatalf("nothing at all = %+v", c)
	}
	a, _ := ChunkDocument("T", strings.Repeat("Some text. ", 500), ChunkOptions{MaxTokens: 50})
	b, _ := ChunkDocument("T", strings.Repeat("Some text. ", 500), ChunkOptions{MaxTokens: 50})
	if !reflect.DeepEqual(a, b) {
		t.Fatal("chunking is not deterministic")
	}
	// Control characters and CRLF are normalised.
	c, _ := ChunkDocument("T", "line\r\none\x00two\tthree", ChunkOptions{})
	if len(c) != 1 || c[0].Text != "line\none two three" {
		t.Fatalf("normalised text = %q", c[0].Text)
	}
}

// TestChunkDocumentCaps: a document of more sections than
// MaxChunksPerDocument is cut there and reported.
func TestChunkDocumentCaps(t *testing.T) {
	var b strings.Builder
	for i := 0; i < MaxChunksPerDocument+10; i++ {
		b.WriteString("# H\nx\n")
	}
	chunks, capped := ChunkDocument("T", b.String(), ChunkOptions{})
	if !capped || len(chunks) != MaxChunksPerDocument {
		t.Fatalf("%d chunks, capped=%v; want %d and capped", len(chunks), capped, MaxChunksPerDocument)
	}
}

// TestReadBodyIsBounded: a connector's body reader stops at MaxBodyBytes,
// ends on a whole character, and says it did.
func TestReadBodyIsBounded(t *testing.T) {
	// "é" is two bytes; put one across the cut.
	body := strings.Repeat("a", MaxBodyBytes-1) + "é" + strings.Repeat("b", 10)
	got, truncated, err := ReadBody(strings.NewReader(body))
	if err != nil || !truncated {
		t.Fatalf("ReadBody = %v, truncated=%v", err, truncated)
	}
	if len(got) != MaxBodyBytes-1 || strings.ContainsRune(got, '�') {
		t.Fatalf("ReadBody kept %d bytes ending %q; want the half character dropped", len(got), got[len(got)-3:])
	}
	short, truncated, err := ReadBody(strings.NewReader("whole"))
	if err != nil || truncated || short != "whole" {
		t.Fatalf("a short body = %q, %v, %v", short, truncated, err)
	}
	if _, _, err := ReadBody(failingReader{}); err == nil {
		t.Fatal("a failing reader's error was swallowed")
	}
	_ = boundedread.ErrTooLarge // the package the bound comes from
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("reset") }
