package redact

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

// mintLike returns a token shaped like the ones the hub mints with prefix, from
// fresh entropy, so no two calls share a value.
func mintLike(t *testing.T, prefix string) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	switch prefix {
	case GitProxyTokenPrefix:
		return prefix + base64.RawURLEncoding.EncodeToString(b)
	case KubeGuardTokenPrefix:
		return prefix + base64.RawURLEncoding.EncodeToString(b[:12]) + "." + base64.RawURLEncoding.EncodeToString(b)
	case EgressTokenPrefix:
		return prefix + hex.EncodeToString(b)
	case RelayTokenPrefix:
		return prefix + hex.EncodeToString(b[:12]) + "." + hex.EncodeToString(b)
	default:
		// An installation token's classic form: ghs_ and 36 letters and
		// digits.
		return prefix + strings.NewReplacer("-", "A", "_", "B").Replace(base64.RawURLEncoding.EncodeToString(b))[:36]
	}
}

// TestTokensReplaceOnlyWhatTheirHashConfirms: of two tokens of one shape, the
// one whose hash the hub recorded is replaced and the other is left alone,
// for every prefix the hub mints with — the precision Task 20454 requires.
func TestTokensReplaceOnlyWhatTheirHashConfirms(t *testing.T) {
	for _, prefix := range mintedPrefixes {
		t.Run(prefix, func(t *testing.T) {
			own, stranger := mintLike(t, prefix), mintLike(t, prefix)
			set := (*Set)(nil).WithTokens(HashToken(own))
			if set.Len() != 1 {
				t.Fatalf("a set of one recorded hash reports Len %d", set.Len())
			}
			text := "token=" + own + " other=" + stranger + "\n"
			got := set.String(text)
			if strings.Contains(got, own) {
				t.Errorf("the run's own token survived: %q", got)
			}
			if !strings.Contains(got, "token="+Marker+" ") {
				t.Errorf("the run's own token was not replaced by the marker: %q", got)
			}
			if !strings.Contains(got, stranger) {
				t.Errorf("a token of the same shape that is not the run's was redacted: %q", got)
			}
			if b := set.Bytes([]byte(text)); string(b) != got {
				t.Errorf("Bytes and String disagree: %q vs %q", b, got)
			}
			if !set.Contains(text) || set.Contains("other="+stranger) {
				t.Error("Contains does not answer what String replaces")
			}
			// Glued to more text of the token's own alphabet, it is still the
			// token: the candidate is cut to the recorded length.
			if got := set.String("x" + own + "abc"); got != "x"+Marker+"abc" {
				t.Errorf("a token run into other text: %q", got)
			}
		})
	}
}

// TestTokensFindNothingWithoutAPrefix: a hash recorded for a token minted
// before its kind had a prefix confirms nothing, because nothing finds it —
// and it does not make the set redact anything else.
func TestTokensFindNothingWithoutAPrefix(t *testing.T) {
	legacy := strings.TrimPrefix(mintLike(t, GitProxyTokenPrefix), GitProxyTokenPrefix)
	h := HashToken(legacy)
	if h.Prefix != "" {
		t.Fatalf("an unprefixed token was given prefix %q", h.Prefix)
	}
	if set := (*Set)(nil).WithTokens(h); set != nil {
		t.Errorf("a hash nothing can find made a set: %v", set.Len())
	}
	if NewTokens(h) != nil {
		t.Error("a hash nothing can find made a Tokens")
	}
}

// TestASplitTokenIsHeldBackUntilItCompletes: a recorded token written through
// a Writer in two pieces, split at every byte, reaches the destination only as
// the marker — the holdback is what keeps a token printed across two reads of
// a pipe from passing through in halves.
func TestASplitTokenIsHeldBackUntilItCompletes(t *testing.T) {
	for _, prefix := range mintedPrefixes {
		own := mintLike(t, prefix)
		set := (*Set)(nil).WithTokens(HashToken(own))
		line := "export TOKEN=" + own + "\nnext line\n"
		for cut := 1; cut < len(line); cut++ {
			var dst bytes.Buffer
			w := NewWriter(&dst, set)
			if _, err := w.Write([]byte(line[:cut])); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(dst.String(), own[:min(len(own), 12)]) && cut < strings.Index(line, own)+len(own) {
				// A piece long enough to identify the token reached the
				// destination before the token completed.
				t.Fatalf("%s cut at %d: %q reached the destination", prefix, cut, dst.String())
			}
			if _, err := w.Write([]byte(line[cut:])); err != nil {
				t.Fatal(err)
			}
			if err := w.Flush(); err != nil {
				t.Fatal(err)
			}
			want := "export TOKEN=" + Marker + "\nnext line\n"
			if dst.String() != want {
				t.Fatalf("%s cut at %d: got %q, want %q", prefix, cut, dst.String(), want)
			}
		}
	}
}

// TestHoldbackLeavesOrdinaryOutputAlone: text that ends in nothing a token can
// begin with is published whole, and a prefix's start is held only while it
// can still become one.
func TestHoldbackLeavesOrdinaryOutputAlone(t *testing.T) {
	set := (*Set)(nil).WithTokens(HashToken(mintLike(t, GitProxyTokenPrefix)))
	for text, want := range map[string]int{
		"step 3 of 7 done\n":           0,
		"compiling":                    0,
		"see cloop":                    len("cloop"),
		"password=cloop_git1_":         len("cloop_git1_"),
		"password=cloop_git1_abc":      len("cloop_git1_abc"),
		"cloop_kube1_xyz":              0, // no hash recorded for that prefix
		"x " + strings.Repeat("a", 60): 0,
	} {
		if got := set.Holdback(text); got != want {
			t.Errorf("Holdback(%q) = %d, want %d", text, got, want)
		}
	}
}

// TestTokenHashesRoundTripThroughTheirRecord: what a record stores parses back
// to the same hashes, and a malformed record is refused whole.
func TestTokenHashesRoundTripThroughTheirRecord(t *testing.T) {
	var hs []TokenHash
	for _, p := range mintedPrefixes {
		hs = append(hs, HashToken(mintLike(t, p)))
	}
	rec := FormatTokenHashes(hs)
	back, err := ParseTokenHashes(rec)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != len(hs) {
		t.Fatalf("%d hashes came back of %d", len(back), len(hs))
	}
	for i := range hs {
		if back[i] != hs[i] {
			t.Errorf("hash %d came back as %v, want %v", i, back[i], hs[i])
		}
	}
	for _, bad := range []string{
		"ghs_:40",
		"ghs_:forty:" + strings.Repeat("ab", 32),
		"ghs_:40:" + strings.Repeat("ab", 31),
		"nope_:40:" + strings.Repeat("ab", 32),
		"ghs_:3:" + strings.Repeat("ab", 32),
	} {
		if got, err := ParseTokenHashes(bad); err == nil || len(got) != 0 {
			t.Errorf("ParseTokenHashes(%q) = %v, %v; want it refused", bad, got, err)
		}
	}
	// One entry it cannot read — a newer build's, say — costs that entry, not
	// the others.
	got, err := ParseTokenHashes(rec + " cloop_git9_:54:" + strings.Repeat("ab", 32))
	if err == nil || len(got) != len(hs) {
		t.Errorf("a record with one unreadable entry gave %d hashes (%v), want the %d readable ones and an error",
			len(got), err, len(hs))
	}
	if _, ok := TokenHashOf(GitProxyTokenPrefix, 54, "not hex"); ok {
		t.Error("TokenHashOf accepted a sum that is not hex")
	}
}

// TestWithAndWithTokensKeepEachOther: adding values keeps the recorded hashes
// and adding hashes keeps the values — a token refreshed mid-run must not cost
// a stream what it already scrubbed.
func TestWithAndWithTokensKeepEachOther(t *testing.T) {
	tok := mintLike(t, EgressTokenPrefix)
	set := New("a-delivered-value").WithTokens(HashToken(tok)).With("another-value-1234")
	text := "a-delivered-value " + tok + " another-value-1234"
	if got := set.String(text); got != Marker+" "+Marker+" "+Marker {
		t.Errorf("got %q", got)
	}
	if set.WithTokens(HashToken(tok)) != set {
		t.Error("adding a hash the set already holds made a new set")
	}
	if set.With("a-delivered-value") != set {
		t.Error("adding a value the set already holds made a new set")
	}
}

// TestTokenScanIsLinearInCandidates: text that is nothing but prefixes, the
// worst a workload can print, costs at most the scan's hashing budget — a few
// dozen times a linear pass, not one installation-token-length hash per
// prefix — and a token after the ordinary decoys a real log holds is still
// found.
func TestTokenScanIsLinearInCandidates(t *testing.T) {
	var hs []TokenHash
	for _, p := range mintedPrefixes {
		hs = append(hs, HashToken(mintLike(t, p)))
	}
	// Installation tokens of both lengths GitHub issues, so every ghs_
	// candidate is cut twice, once at 390 bytes.
	hs = append(hs, TokenHash{Prefix: GitHubAppTokenPrefix, Len: 390, Sum: HashToken("unused").Sum})
	set := (*Set)(nil).WithTokens(hs...)
	for name, unit := range map[string]string{
		"ghs_ only":     "ghs_",
		"every prefix":  "ghs_cloop_git1_cloop_kube1_cloop_egress1_cloop_relay_",
		"ghs_ and body": "ghs_x",
	} {
		text := strings.Repeat(unit, (1<<20)/len(unit))
		start := time.Now()
		if got := set.String(text); got != text {
			t.Fatalf("%s: a text of prefixes alone was changed", name)
		}
		_ = set.Holdback(text)
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("%s: searching 1 MiB of prefixes took %s", name, d)
		}
		if spent := scanHashBudget(len(text)); spent > 40*len(text) {
			t.Fatalf("%s: the budget allows %d bytes of hashing for %d of text", name, spent, len(text))
		}
	}

	own := mintLike(t, GitHubAppTokenPrefix)
	set = set.WithTokens(HashToken(own))
	var log strings.Builder
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&log, "step %d: set GITHUB_TOKEN to a ghs_ token from the App, not a ghs_ placeholder\n", i)
	}
	log.WriteString("token=" + own + "\n")
	if got := set.String(log.String()); strings.Contains(got, own) {
		t.Fatal("a token after the decoys a real log holds was not found")
	}
}
