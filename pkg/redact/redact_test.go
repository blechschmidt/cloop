package redact

// redact_test.go holds this package to two promises that pull against each
// other: a known credential must never survive, and text that merely resembles
// one must come through untouched. The second is not a nicety — a redactor that
// mangles ordinary output gets switched off, and then the first promise is
// worth nothing either.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const token = "ghp_FAKE1234567890abcdefTOKENvalue"

// --- Set ---------------------------------------------------------------

func TestNew_SkipsValuesTooShortToBeCredentials(t *testing.T) {
	// "prod" is the kind of value a constraint echo carries. Matching it
	// would replace the word everywhere it legitimately appears.
	if s := New("prod", "dev", "x"); s != nil {
		t.Fatalf("New kept a short value: %d entries", s.Len())
	}
	s := New("prod", token)
	if s.Len() != 1 {
		t.Fatalf("Len = %d, want only the long value", s.Len())
	}
	if got := s.String("deploying to prod"); got != "deploying to prod" {
		t.Errorf("short value was matched anyway: %q", got)
	}
}

// TestNew_SkipsItsOwnPlaceholders guards the rehydrate path. A Spec is stored
// with its leased variables replaced by "<redacted:leased>", so a hub restart
// reloads a spec whose "credentials" are placeholders — which must not become a
// Set that replaces a marker with a marker.
func TestNew_SkipsItsOwnPlaceholders(t *testing.T) {
	if s := New("<redacted:leased>", Marker); s != nil {
		t.Fatalf("placeholders were treated as credentials: %d entries", s.Len())
	}
	// A real value alongside them still survives.
	s := New("<redacted:leased>", token)
	if s.Len() != 1 {
		t.Fatalf("Len = %d, want only the real credential", s.Len())
	}
	if got := s.String("env shows <redacted:leased> for that key"); !strings.Contains(got, "<redacted:leased>") {
		t.Errorf("the stored placeholder was rewritten: %q", got)
	}
}

func TestSet_NilRedactsNothing(t *testing.T) {
	var s *Set
	if got := s.String("anything"); got != "anything" {
		t.Errorf("nil Set changed %q", got)
	}
	if s.Len() != 0 || s.Contains("anything") || s.Holdback("anything") != 0 {
		t.Error("nil Set is not inert")
	}
}

func TestSet_ReplacesEveryOccurrence(t *testing.T) {
	s := New(token)
	in := "export GITHUB_TOKEN=" + token + "\ncurl -H 'auth: " + token + "'\n"
	got := s.String(in)
	if strings.Contains(got, token) {
		t.Fatalf("token survived: %q", got)
	}
	if n := strings.Count(got, Marker); n != 2 {
		t.Errorf("got %d markers, want 2: %q", n, got)
	}
}

// TestSet_LongestMatchWins is the containment case, and it is why New sorts.
// A lease delivers the token *and* the token file's content, which is the token
// plus a newline. Replacing the short one first would leave the newline behind
// and — worse — leave a marker adjacent to the remainder of a longer secret
// that shares its prefix.
func TestSet_LongestMatchWins(t *testing.T) {
	fileContent := token + "\n"
	s := New(token, fileContent)
	got := s.String("cat token: " + fileContent + "done")
	if strings.Contains(got, token) {
		t.Fatalf("token survived: %q", got)
	}
	if got != "cat token: "+Marker+"done" {
		t.Errorf("got %q; the longer value should have been consumed whole", got)
	}
}

func TestSet_BytesLeavesNonMatchingInputAlone(t *testing.T) {
	s := New(token)
	in := []byte("nothing secret here")
	got := s.Bytes(in)
	if !bytes.Equal(got, in) {
		t.Errorf("Bytes rewrote clean input: %q", got)
	}
}

// TestSet_BinaryContentIsMatchedByBytes: a kubeconfig or a gitconfig may be
// invalid UTF-8, and a redactor that round-trips through a Go string would
// mangle it into replacement characters and then fail to match.
func TestSet_BinaryContentIsMatchedByBytes(t *testing.T) {
	secret := "cred-\xff\xfe-blob-value"
	s := New(secret)
	got := s.Bytes([]byte("before " + secret + " after"))
	if bytes.Contains(got, []byte(secret)) {
		t.Fatalf("binary secret survived: %q", got)
	}
	if string(got) != "before "+Marker+" after" {
		t.Errorf("got %q", got)
	}
}

// --- Holdback / Writer -------------------------------------------------

func TestHoldback_ZeroForOrdinaryOutput(t *testing.T) {
	s := New(token)
	// The common case, and the one that must not cost latency: nothing in
	// this text could begin the secret, so nothing is withheld.
	if n := s.Holdback("compiling package foo/bar\n"); n != 0 {
		t.Errorf("Holdback = %d, want 0 — ordinary output must not be delayed", n)
	}
}

func TestHoldback_WithholdsAPartialSecretAtTheBoundary(t *testing.T) {
	s := New(token)
	buf := "token is " + token[:10]
	if n := s.Holdback(buf); n != 10 {
		t.Errorf("Holdback = %d, want 10 (the partial prefix)", n)
	}
}

// TestWriter_CatchesASecretSplitAcrossWrites is the whole reason the Writer
// carries state. A pipe read, a token boundary, or a TCP segment can land
// mid-credential, and a per-chunk redactor would pass both halves through.
func TestWriter_CatchesASecretSplitAcrossWrites(t *testing.T) {
	var sink bytes.Buffer
	w := NewWriter(&sink, New(token))

	for _, chunk := range []string{"auth=" + token[:8], token[8:20], token[20:] + "\ndone\n"} {
		if _, err := w.Write([]byte(chunk)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	got := sink.String()
	if strings.Contains(got, token) {
		t.Fatalf("split secret survived: %q", got)
	}
	// Every fragment long enough to be recognisable must be gone too, or the
	// value is merely obfuscated rather than removed.
	if strings.Contains(got, token[:16]) {
		t.Fatalf("a recognisable fragment survived: %q", got)
	}
	if got != "auth="+Marker+"\ndone\n" {
		t.Errorf("got %q, want the surrounding text intact around one marker", got)
	}
}

func TestWriter_ReportsFullLengthConsumedWhileWithholding(t *testing.T) {
	w := NewWriter(&bytes.Buffer{}, New(token))
	// This write ends mid-secret, so nothing may be forwarded yet — but the
	// io.Writer contract is about what the caller may consider handed over.
	p := []byte("x" + token[:6])
	n, err := w.Write(p)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(p) {
		t.Errorf("Write reported %d of %d consumed; a short write is an error to its caller", n, len(p))
	}
}

func TestWriter_FlushReleasesATrailingPartial(t *testing.T) {
	var sink bytes.Buffer
	w := NewWriter(&sink, New(token))
	// A tail that looks like the start of the secret but never becomes one.
	// It must not be swallowed: the end of the output is where errors are.
	if _, err := w.Write([]byte("result: " + token[:9])); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if sink.Len() != len("result: ") {
		t.Fatalf("withheld more than the partial: %q", sink.String())
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := sink.String(); got != "result: "+token[:9] {
		t.Errorf("got %q, want the partial released verbatim", got)
	}
}

func TestWriter_NilSetForwardsVerbatim(t *testing.T) {
	var sink bytes.Buffer
	w := NewWriter(&sink, nil)
	if _, err := w.Write([]byte("unchanged")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := sink.String(); got != "unchanged" {
		t.Errorf("got %q", got)
	}
}

// --- discovery ---------------------------------------------------------

// TestFromEnviron_TakesDeclaredValuesAndLeaseFiles covers the mechanism a
// workload uses to scrub its own output: the broker names the credential-
// bearing variables, and the lease directory supplies the file contents.
func TestFromEnviron_TakesDeclaredValuesAndLeaseFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "github-token"), []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	environ := []string{
		EnvKey + "=GITHUB_TOKEN,HTTPS_PROXY",
		"GITHUB_TOKEN=" + token,
		"HTTPS_PROXY=http://user:hunter2password@proxy.internal:3128",
		"CLOOP_GITHUB_REPO_ALLOWLIST=blechschmidt/cloop",
		LeaseDirKey + "=" + dir,
	}
	s := FromEnviron(environ)

	for _, want := range []string{token, "http://user:hunter2password@proxy.internal:3128", token + "\n"} {
		if !s.Contains(want) {
			t.Errorf("set does not carry %q", want)
		}
	}
	// The constraint echo beside them must not be matched, or every mention
	// of the repository in a transcript becomes a marker.
	if s.Contains("blechschmidt/cloop") {
		t.Error("the repository allowlist was treated as a credential")
	}

	out := s.String("cloning blechschmidt/cloop with " + token)
	if strings.Contains(out, token) {
		t.Fatalf("token survived: %q", out)
	}
	if !strings.Contains(out, "blechschmidt/cloop") {
		t.Errorf("the repository name was mangled: %q", out)
	}
}

func TestFromEnviron_NoLeaseYieldsNilSet(t *testing.T) {
	if s := FromEnviron([]string{"PATH=/usr/bin", "HOME=/root"}); s != nil {
		t.Errorf("a workload with no grants got a non-nil set of %d values", s.Len())
	}
}

// TestFromEnviron_SurvivesAnUnreadableLeaseDir: failing to redact is not a
// reason to fail a run, and a project with no grants names no directory.
func TestFromEnviron_SurvivesAnUnreadableLeaseDir(t *testing.T) {
	s := FromEnviron([]string{LeaseDirKey + "=/nonexistent/cloop-lease-000000000000"})
	if s != nil {
		t.Errorf("got %d values from a directory that does not exist", s.Len())
	}
}

func TestValues_ReturnsRawAndTrimmed(t *testing.T) {
	got := Values([]byte(token + "\n"))
	if len(got) != 2 || got[0] != token+"\n" || got[1] != token {
		t.Errorf("Values = %q, want the raw bytes and the trimmed form", got)
	}
	// Nothing to trim — one entry, no duplicate.
	if got := Values([]byte(token)); len(got) != 1 {
		t.Errorf("Values = %q, want one entry", got)
	}
}
