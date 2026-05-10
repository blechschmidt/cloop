package mergeresolve

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/mergequeue"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// scriptedProvider returns canned responses keyed by file path. Used to drive
// the resolver under predictable conditions without an actual AI call.
type scriptedProvider struct {
	responses map[string]string
	err       error
	calls     int
}

func (s *scriptedProvider) Name() string         { return "scripted" }
func (s *scriptedProvider) DefaultModel() string { return "test" }
func (s *scriptedProvider) Complete(ctx context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	for path, body := range s.responses {
		if strings.Contains(prompt, "File: "+path) {
			return &provider.Result{Output: body}, nil
		}
	}
	return &provider.Result{Output: ""}, nil
}

func TestResolver_ResolvesCleanFile(t *testing.T) {
	resolved := "```\npackage main\n\nfunc Hello() string { return \"merged\" }\n```"
	sp := &scriptedProvider{responses: map[string]string{
		"main.go": resolved,
	}}
	r := New(sp, "test", 0)

	in := []mergequeue.ConflictFile{
		{Path: "main.go", Content: "<<<<<<< HEAD\nfunc Hello() string { return \"a\" }\n=======\nfunc Hello() string { return \"b\" }\n>>>>>>> branch\n"},
	}
	out, err := r.Resolve(context.Background(), mergequeue.ResolveInfo{BaseBranch: "main", SourceBranch: "branch", TaskID: 1, TaskTitle: "demo"}, in)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 resolution, got %d", len(out))
	}
	if out[0].Path != "main.go" {
		t.Fatalf("wrong path: %q", out[0].Path)
	}
	if !strings.Contains(out[0].Content, "merged") {
		t.Fatalf("content not extracted from fenced block: %q", out[0].Content)
	}
	if strings.HasPrefix(out[0].Content, "```") {
		t.Fatalf("code fences not stripped: %q", out[0].Content)
	}
	if !strings.HasSuffix(out[0].Content, "\n") {
		t.Fatalf("missing trailing newline: %q", out[0].Content)
	}
}

func TestResolver_RejectsOutputWithMarkers(t *testing.T) {
	// The AI gave up and left markers in. The resolver must NOT return this
	// as a "resolution" — that would commit broken code.
	bad := "```\n<<<<<<< HEAD\nfoo\n=======\nbar\n>>>>>>> branch\n```"
	sp := &scriptedProvider{responses: map[string]string{"main.go": bad}}
	r := New(sp, "", 0)

	in := []mergequeue.ConflictFile{{Path: "main.go", Content: "<<<<<<< HEAD\nfoo\n=======\nbar\n>>>>>>> branch\n"}}
	out, err := r.Resolve(context.Background(), mergequeue.ResolveInfo{}, in)
	if err == nil && len(out) > 0 {
		t.Fatalf("expected resolver to reject markered output, got %d resolutions", len(out))
	}
}

func TestResolver_OversizedFileSkipped(t *testing.T) {
	huge := strings.Repeat("x", MaxFileBytes+1)
	sp := &scriptedProvider{responses: map[string]string{"big.txt": "```\nresolved\n```"}}
	r := New(sp, "", 0)
	in := []mergequeue.ConflictFile{{Path: "big.txt", Content: huge}}
	out, err := r.Resolve(context.Background(), mergequeue.ResolveInfo{}, in)
	if err == nil {
		t.Fatalf("expected error for oversized file, got %d resolutions", len(out))
	}
	if sp.calls != 0 {
		t.Fatalf("provider should not have been called for oversized file (calls=%d)", sp.calls)
	}
}

func TestResolver_NilProviderErrors(t *testing.T) {
	r := &Resolver{}
	_, err := r.Resolve(context.Background(), mergequeue.ResolveInfo{}, []mergequeue.ConflictFile{{Path: "x"}})
	if err == nil {
		t.Fatal("expected error with nil provider")
	}
}

func TestResolver_EmptyInputNoCall(t *testing.T) {
	sp := &scriptedProvider{}
	r := New(sp, "", 0)
	out, err := r.Resolve(context.Background(), mergequeue.ResolveInfo{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected 0 resolutions, got %d", len(out))
	}
	if sp.calls != 0 {
		t.Fatalf("provider should not have been called: calls=%d", sp.calls)
	}
}

func TestResolver_PropagatesProviderError(t *testing.T) {
	sp := &scriptedProvider{err: errors.New("boom")}
	r := New(sp, "", 0)
	in := []mergequeue.ConflictFile{{Path: "x.go", Content: "hello"}}
	_, err := r.Resolve(context.Background(), mergequeue.ResolveInfo{}, in)
	if err == nil {
		t.Fatal("expected provider error to surface when all files fail")
	}
}

func TestExtractCodeBlock(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"```\nhello\n```", "hello\n"},
		{"```go\npackage x\n```", "package x\n"},
		{"```\n\n```", ""},                              // empty fence = give up
		{"no fence here", "no fence here"},              // tolerate no fence
		{"```\nunterminated\nlines\n", "unterminated\nlines\n"},
	}
	for _, c := range cases {
		got := extractCodeBlock(c.in)
		if got != c.want {
			t.Errorf("extractCodeBlock(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestHasConflictMarkers(t *testing.T) {
	if !hasConflictMarkers("foo\n<<<<<<< HEAD\nbar\n") {
		t.Error("expected true for <<<<<<<")
	}
	if !hasConflictMarkers("a\n=======\nb\n") {
		t.Error("expected true for =======")
	}
	if !hasConflictMarkers("ok\n>>>>>>> branch\n") {
		t.Error("expected true for >>>>>>>")
	}
	if hasConflictMarkers("the merge markers <<<<<<< inline don't count without a leading line break") {
		t.Error("expected false: markers only count at line start")
	}
}
