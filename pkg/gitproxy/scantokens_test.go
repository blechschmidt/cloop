package gitproxy

// Tests for the tokens a push is scanned for by their recorded hash alone: the
// ones a hub process adopting a run never held (Task 20454).

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/redact"
)

// mintedLike returns a fresh token shaped like the ones the hub mints with
// prefix.
func mintedLike(t testing.TB, prefix string) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	switch prefix {
	case redact.GitProxyTokenPrefix:
		return prefix + base64.RawURLEncoding.EncodeToString(b)
	case redact.KubeGuardTokenPrefix:
		return prefix + base64.RawURLEncoding.EncodeToString(b[:12]) + "." + base64.RawURLEncoding.EncodeToString(b)
	case redact.EgressTokenPrefix:
		return prefix + hex.EncodeToString(b)
	case redact.RelayTokenPrefix:
		return prefix + hex.EncodeToString(b[:12]) + "." + hex.EncodeToString(b)
	default:
		return prefix + hex.EncodeToString(b)[:36]
	}
}

var mintedPrefixesForTest = []string{redact.GitProxyTokenPrefix, redact.KubeGuardTokenPrefix,
	redact.EgressTokenPrefix, redact.RelayTokenPrefix, redact.GitHubAppTokenPrefix}

func scanTokenFor(token string) ScanToken {
	return ScanToken{Hash: redact.HashToken(token), Grant: "gr_tok", Secret: "acme-app", Field: "the run's session token"}
}

// assertNoToken fails if anything the scan would show or record carries token.
func assertNoToken(t testing.TB, run scanRun, token string) {
	t.Helper()
	for _, f := range run.findings {
		for _, s := range []string{f.summary(), f.Path, f.Tag, f.Ref, f.Field, findingsDetail(run.findings)} {
			if strings.Contains(s, token) {
				t.Fatalf("the report carries the token: %q", s)
			}
		}
	}
}

// TestScanRefusesATokenKnownOnlyByItsHash: for every prefix the hub mints with,
// a push whose blob, commit message or delta insert carries a token the proxy
// holds only the hash of is refused, named by its grant, secret and field and
// never by its value; the forge does not get the whole pack.
func TestScanRefusesATokenKnownOnlyByItsHash(t *testing.T) {
	for _, prefix := range mintedPrefixesForTest {
		t.Run(prefix, func(t *testing.T) {
			tok := mintedLike(t, prefix)
			r := newGitRepo(t)
			base := r.commit("base", map[string]string{"README.md": "hello\n"})
			head := r.commit("add", map[string]string{"deploy/token.txt": "TOKEN=" + tok + "\n"})
			pack := r.pack(false, head, "^"+base)
			run := scanPack(t, pack, nil, nil, ScanValues, ScanLimits{}, scanTokenFor(tok))
			f := run.only(t)
			if f.Type != "blob" || f.Path != "deploy/token.txt" || f.Grant != "gr_tok" || f.Secret != "acme-app" ||
				f.Field != "the run's session token" {
				t.Errorf("finding = %+v", f)
			}
			if !run.refused || bytes.Equal(run.forwarded, pack) {
				t.Error("a push carrying the run's token was forwarded whole")
			}
			assertNoToken(t, run, tok)

			// In a commit message, and as a delta's inserted bytes.
			msg := r.commit("ship it "+tok, map[string]string{"b.txt": "b\n"})
			if f := scanPack(t, r.pack(false, msg, "^"+head), nil, nil, ScanValues, ScanLimits{},
				scanTokenFor(tok)).only(t); f.Where != whereMessage {
				t.Errorf("token in a message: %+v", f)
			}
			var body strings.Builder
			for i := 0; i < 400; i++ {
				fmt.Fprintf(&body, "line %d of a configuration file the forge already has\n", i)
			}
			old := r.commit("long", map[string]string{"settings.conf": body.String()})
			tweak := r.commit("tweak", map[string]string{"settings.conf": body.String() + "token = " + tok + "\n"})
			run = scanPack(t, r.pack(true, tweak, "^"+old), nil, nil, ScanValues, ScanLimits{}, scanTokenFor(tok))
			if run.sc.typeCounts[objRefDelta] == 0 {
				t.Fatalf("git wrote no REF_DELTA (types %v)", run.sc.typeCounts)
			}
			if f := run.only(t); f.Type != "delta" || f.Where != whereInsert {
				t.Errorf("token in a delta insert: %+v", f)
			}
		})
	}
}

// TestScanLeavesATokenOfTheSameShapeAlone: a token that looks exactly like the
// run's but does not hash to one of its recorded hashes — a fixture, another
// run's — is not refused, and the push is forwarded byte for byte.
func TestScanLeavesATokenOfTheSameShapeAlone(t *testing.T) {
	for _, prefix := range mintedPrefixesForTest {
		own, stranger := mintedLike(t, prefix), mintedLike(t, prefix)
		r := newGitRepo(t)
		head := r.commit("fixture", map[string]string{"testdata/token.txt": stranger + "\n"})
		pack := r.pack(false, head)
		run := scanPack(t, pack, nil, nil, ScanValues, ScanLimits{}, scanTokenFor(own))
		if run.err != nil || len(run.findings) != 0 || run.refused {
			t.Fatalf("%s: a token of the same shape that is not the run's was refused: %+v (err %v)", prefix, run.findings, run.err)
		}
		if !bytes.Equal(run.forwarded, pack) {
			t.Fatalf("%s: the clean pack was not forwarded byte for byte", prefix)
		}
	}
}

// TestScanFindsATokenInARefNameAndNeverNamesIt: a ref named after the run's
// token is refused without the refusal quoting it.
func TestScanFindsATokenInARefNameAndNeverNamesIt(t *testing.T) {
	tok := mintedLike(t, redact.KubeGuardTokenPrefix)
	r := newGitRepo(t)
	head := r.commit("a", map[string]string{"a.txt": "a\n"})
	cmd := &ReceivePack{Commands: []RefUpdate{{Old: zeroSHA, New: head, Ref: "refs/heads/leak-" + tok}}}
	run := scanPack(t, r.pack(false, head), cmd, nil, ScanValues, ScanLimits{}, scanTokenFor(tok))
	if len(run.findings) == 0 || run.findings[0].Where != whereRef {
		t.Fatalf("findings = %+v", run.findings)
	}
	assertNoToken(t, run, tok)
}

// TestMatcherFindsATokenAcrossEveryChunkBoundary: a token split anywhere across
// two writes of a stream is found exactly once, as a value is.
func TestMatcherFindsATokenAcrossEveryChunkBoundary(t *testing.T) {
	for _, prefix := range mintedPrefixesForTest {
		tok := mintedLike(t, prefix)
		m := newMatcher(nil, scanTokenFor(tok))
		if m == nil {
			t.Fatal("a matcher of tokens alone is nil")
		}
		text := []byte("prefix bytes " + tok + " suffix")
		for cut := 0; cut <= len(text); cut++ {
			st := matchStream{m: m}
			found := 0
			hit := func(pi int, end int64) bool {
				found++
				if want := int64(strings.Index(string(text), tok) + len(tok)); end != want {
					t.Fatalf("%s split at %d: reported ending at %d, want %d", prefix, cut, end, want)
				}
				return true
			}
			st.write(text[:cut], hit)
			st.write(text[cut:], hit)
			if found != 1 {
				t.Fatalf("%s split at %d: found %d times, want once", prefix, cut, found)
			}
		}
		if got := m.redact("ref " + tok); got != "ref "+redact.Marker {
			t.Fatalf("redact = %q", got)
		}
	}
}

// TestMatcherCostsWhatAWriteAddsForTokens: a stream of one-byte writes — what a
// delta of many tiny inserts feeds the scan — full of token prefixes costs what
// it adds, not a re-read of the window per write, and a token at its end is
// still found exactly once, at its end.
func TestMatcherCostsWhatAWriteAddsForTokens(t *testing.T) {
	own := mintedLike(t, redact.GitHubAppTokenPrefix)
	long := ScanToken{Hash: redact.TokenHash{Prefix: redact.GitHubAppTokenPrefix, Len: 390,
		Sum: redact.HashToken("unused").Sum}, Field: "another installation token"}
	m := newMatcher(nil, scanTokenFor(own), long, scanTokenFor(mintedLike(t, redact.GitProxyTokenPrefix)))
	text := []byte(strings.Repeat("ghs_cloop_git1_", (256<<10)/15) + "\n" + own + "\n")
	st := matchStream{m: m}
	found := 0
	start := time.Now()
	for i := range text {
		st.write(text[i:i+1], func(pi int, end int64) bool {
			found++
			if want := int64(len(text) - 1); end != want {
				t.Fatalf("reported ending at %d, want %d", end, want)
			}
			return true
		})
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Fatalf("one-byte writes of 256 KiB of prefixes took %s", d)
	}
	if found != 1 {
		t.Fatalf("the token was found %d times, want once", found)
	}
}
