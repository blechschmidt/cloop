package redact

// tokens.go finds the hub's own minted tokens by their prefix and confirms
// each one against the SHA-256 the hub recorded when it minted it (Task 20454).
//
// # Why a Set is not enough here
//
// A Set matches the values it was given. A hub process that adopts a run
// another one dispatched was given none of the tokens that one minted for it:
// the bearer tokens of the run's git proxy, Kubernetes monitor, egress and
// model relay sessions, and the GitHub App installation tokens behind its
// GitHub grants. Their plaintext is never stored. What the hub keeps of each
// is a SHA-256, which is enough to authenticate the token and not enough to
// recover it. So until such a run ended, its workload could print one of
// those tokens, or commit and push it, and nothing on the hub caught it.
//
// # What Tokens does instead
//
// Every token the hub mints starts with a prefix that says what it is:
// cloop_git1_, cloop_kube1_, cloop_egress1_, cloop_relay_, and GitHub's ghs_
// for installation tokens. That makes searching a stream for candidates as
// cheap as a substring search. Each candidate is cut to a length the hub
// recorded for its kind and hashed, and it is replaced only when that SHA-256
// is one the hub recorded for this run.
//
// A token of the same shape that does not hash to one of the run's own (a
// random string, another run's token, a fixture in a test) is left alone.
// That is the difference from the shape registry in patterns.go. Those
// detectors exist for text that nobody can confirm, so they replace on sight.
// Tokens replaces only what it can prove.
//
// # Who pays for it
//
// Only an adopted run whose values could not all be re-derived. The process
// that dispatched a run knows every value it handed out, and its Set matches
// them exactly, so live streams keep their exact-value-only cost. A nil
// *Tokens, which is what every other Set holds, costs one pointer comparison.
//
// # What it cannot see
//
// A token minted before its kind carried a prefix has no shape to search for,
// so its recorded hash confirms nothing. Neither does a token the workload
// re-encoded (base64, percent-escapes, split across lines), since what is
// hashed is the token exactly as minted.
//
// Nor does one past a scan's hashing budget. A candidate costs a hash of its
// recorded length, up to an installation token's 390 bytes, so output that is
// nothing but prefixes would cost hundreds of times what scanning it for
// values does, under the lock a log bus holds while it scrubs. A scan
// therefore hashes at most scanHashBudget bytes, far more than ordinary output
// ever spends, and leaves whatever comes after that alone. Only a workload
// flooding its own output with token prefixes reaches the budget, and such a
// workload could as easily re-encode its token.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// The prefixes the hub mints its tokens with. A token that starts with one of
// them can be found in a stream and confirmed against its recorded hash. The
// first three are versioned: a future format gets a new number, and the
// recorded hashes of the old one keep confirming the old one.
const (
	// GitProxyTokenPrefix starts the password of a git proxy session, which
	// a sandbox's git presents to the hub in place of a GitHub credential.
	GitProxyTokenPrefix = "cloop_git1_"
	// KubeGuardTokenPrefix starts the bearer token of a Kubernetes monitor
	// session: cloop_kube1_<id>.<secret>.
	KubeGuardTokenPrefix = "cloop_kube1_"
	// EgressTokenPrefix starts the password of an egress proxy session, the
	// userinfo of the HTTPS_PROXY a sandbox is given.
	EgressTokenPrefix = "cloop_egress1_"
	// RelayTokenPrefix starts a model relay session's token.
	RelayTokenPrefix = "cloop_relay_"
	// GitHubAppTokenPrefix starts a GitHub App installation token, the one
	// kind of token the hub mints whose format it does not choose.
	GitHubAppTokenPrefix = "ghs_"
)

// mintedPrefixes are the prefixes a recorded hash can be found by. None is a
// prefix of another, so a token has at most one.
var mintedPrefixes = []string{
	GitProxyTokenPrefix, KubeGuardTokenPrefix, EgressTokenPrefix, RelayTokenPrefix, GitHubAppTokenPrefix,
}

// MintedPrefix returns the minted prefix token starts with, or "".
func MintedPrefix(token string) string {
	for _, p := range mintedPrefixes {
		if strings.HasPrefix(token, p) {
			return p
		}
	}
	return ""
}

// maxTokenLen bounds the length of a token a hash may be recorded for. An
// installation token is 390 characters today; anything far longer is not a
// token the hub minted, and a recorded length is what bounds both the hashing
// per candidate and what a stream holds back.
const maxTokenLen = 1024

// TokenHash is what the hub records of a token it minted and does not store:
// the prefix it is found by, its length, and its SHA-256. None of the three
// can be used to open anything; together they confirm that a string is the
// token.
type TokenHash struct {
	Prefix string
	Len    int
	Sum    [sha256.Size]byte
}

// HashToken returns what the hub records of token. Prefix is empty for a token
// that starts with no minted prefix, and such a hash confirms nothing, because
// nothing can find the token it stands for.
func HashToken(token string) TokenHash {
	return TokenHash{Prefix: MintedPrefix(token), Len: len(token), Sum: sha256.Sum256([]byte(token))}
}

// TokenHashOf rebuilds a TokenHash from a hex SHA-256 recorded without its
// shape, such as proxy_sessions.token_sha256, for a token minted with prefix
// and n bytes long. It reports false for a sum that is not 32 hex-encoded
// bytes, or a shape no token can have.
func TokenHashOf(prefix string, n int, sumHex string) (TokenHash, bool) {
	raw, err := hex.DecodeString(strings.TrimSpace(sumHex))
	if err != nil || len(raw) != sha256.Size {
		return TokenHash{}, false
	}
	h := TokenHash{Prefix: prefix, Len: n}
	copy(h.Sum[:], raw)
	if !h.findable() {
		return TokenHash{}, false
	}
	return h, true
}

// findable reports whether a stream can be searched for the token: it has a
// minted prefix and a length that leaves room for a body.
func (h TokenHash) findable() bool {
	if h.Len <= len(h.Prefix) || h.Len > maxTokenLen {
		return false
	}
	for _, p := range mintedPrefixes {
		if p == h.Prefix {
			return true
		}
	}
	return false
}

// String renders the hash as a record stores it: "<prefix>:<len>:<hex>". No
// minted prefix holds a colon, so the form parses back unambiguously.
func (h TokenHash) String() string {
	return h.Prefix + ":" + strconv.Itoa(h.Len) + ":" + hex.EncodeToString(h.Sum[:])
}

// ParseTokenHash reads what String wrote.
func ParseTokenHash(s string) (TokenHash, error) {
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) != 3 {
		return TokenHash{}, fmt.Errorf("redact: token hash %q is not <prefix>:<len>:<sha256>", s)
	}
	n, err := strconv.Atoi(parts[1])
	if err != nil {
		return TokenHash{}, fmt.Errorf("redact: token hash length %q: %w", parts[1], err)
	}
	h, ok := TokenHashOf(parts[0], n, parts[2])
	if !ok {
		return TokenHash{}, fmt.Errorf("redact: token hash %q has no shape a minted token can have", s)
	}
	return h, nil
}

// FormatTokenHashes renders hashes for a record, space-separated.
func FormatTokenHashes(hs []TokenHash) string {
	parts := make([]string, 0, len(hs))
	for _, h := range hs {
		parts = append(parts, h.String())
	}
	return strings.Join(parts, " ")
}

// ParseTokenHashes reads what FormatTokenHashes wrote. It returns every entry
// it can read, and an error naming how many it could not: a caller keeps what
// the others confirm rather than losing a run's whole history to one entry —
// one a newer build wrote in a shape this one does not know, say.
func ParseTokenHashes(s string) ([]TokenHash, error) {
	var (
		out []TokenHash
		bad int
		err error
	)
	for _, f := range strings.Fields(s) {
		h, perr := ParseTokenHash(f)
		if perr != nil {
			if bad == 0 {
				err = perr
			}
			bad++
			continue
		}
		out = append(out, h)
	}
	if bad > 0 {
		return out, fmt.Errorf("%d unreadable token hash(es), the first: %w", bad, err)
	}
	return out, nil
}

// Findable reports whether a stream can be searched for the token h stands
// for: it starts with a minted prefix and has a length a recorded token can
// have. A hash that is not confirms nothing, and is not worth recording.
func (h TokenHash) Findable() bool { return h.findable() }

// Tokens is an immutable set of recorded token hashes that a text is searched
// for. A nil *Tokens finds nothing, and is what every Set built from values
// alone holds.
//
// Safe for concurrent use, since nothing changes it after it is built.
type Tokens struct {
	entries []TokenHash
	sums    map[[sha256.Size]byte]int
	// shapes lists, for each prefix that has entries, the distinct lengths
	// recorded under it, longest first.
	shapes []tokenShape
	maxLen int
}

type tokenShape struct {
	prefix string
	lens   []int
}

// TokenMatch is one confirmed token in a text.
type TokenMatch struct {
	// Start and End delimit the token.
	Start, End int
	// Index is the entry that confirmed it: Hash(Index) is its hash, which is
	// how a caller finds what it recorded beside the hash.
	Index int
}

// NewTokens returns a Tokens over hs, ignoring hashes nothing could find and
// duplicates. It returns nil when nothing is left.
func NewTokens(hs ...TokenHash) *Tokens {
	return (*Tokens)(nil).With(hs...)
}

// With returns a Tokens over t's hashes and hs, or t itself when hs adds
// nothing. An entry keeps its index: those added later are numbered after t's.
func (t *Tokens) With(hs ...TokenHash) *Tokens {
	var entries []TokenHash
	if t != nil {
		entries = append(entries, t.entries...)
	}
	before := len(entries)
	seen := make(map[[sha256.Size]byte]bool, len(entries)+len(hs))
	for _, e := range entries {
		seen[e.Sum] = true
	}
	for _, h := range hs {
		if !h.findable() || seen[h.Sum] {
			continue
		}
		seen[h.Sum] = true
		entries = append(entries, h)
	}
	if len(entries) == before {
		return t
	}
	out := &Tokens{entries: entries, sums: make(map[[sha256.Size]byte]int, len(entries))}
	lens := map[string]map[int]bool{}
	for i, e := range entries {
		out.sums[e.Sum] = i
		if lens[e.Prefix] == nil {
			lens[e.Prefix] = map[int]bool{}
		}
		lens[e.Prefix][e.Len] = true
		if e.Len > out.maxLen {
			out.maxLen = e.Len
		}
	}
	for _, p := range mintedPrefixes {
		if len(lens[p]) == 0 {
			continue
		}
		sh := tokenShape{prefix: p}
		for n := range lens[p] {
			sh.lens = append(sh.lens, n)
		}
		sort.Sort(sort.Reverse(sort.IntSlice(sh.lens)))
		out.shapes = append(out.shapes, sh)
	}
	return out
}

// Len reports how many hashes t confirms candidates against.
func (t *Tokens) Len() int {
	if t == nil {
		return 0
	}
	return len(t.entries)
}

// TokenShape is a prefix a Tokens searches for and the lengths recorded under
// it, longest first.
type TokenShape struct {
	Prefix string
	Lens   []int
}

// Shapes returns what t searches for, for a caller that finds candidates in a
// stream itself and asks Confirm about each.
func (t *Tokens) Shapes() []TokenShape {
	if t == nil {
		return nil
	}
	out := make([]TokenShape, 0, len(t.shapes))
	for _, sh := range t.shapes {
		out = append(out, TokenShape{Prefix: sh.prefix, Lens: append([]int(nil), sh.lens...)})
	}
	return out
}

// Confirm reports the entry whose hash candidate has, if one does.
func (t *Tokens) Confirm(candidate []byte) (int, bool) {
	if t == nil {
		return -1, false
	}
	i, ok := t.sums[sha256.Sum256(candidate)]
	return i, ok
}

// Hash returns entry i: the hash a TokenMatch's Index names.
func (t *Tokens) Hash(i int) TokenHash {
	if t == nil || i < 0 || i >= len(t.entries) {
		return TokenHash{}
	}
	return t.entries[i]
}

// MaxLen is the longest recorded token: what a caller scanning a stream in
// chunks must keep of the previous chunk so that a token split across two is
// still found whole.
func (t *Tokens) MaxLen() int {
	if t == nil {
		return 0
	}
	return t.maxLen
}

// Find returns every confirmed token in text, in order and without overlap.
func (t *Tokens) Find(text string) []TokenMatch {
	var out []TokenMatch
	t.scan(text, 0, func(m TokenMatch) bool {
		out = append(out, m)
		return true
	})
	return out
}

// Replace returns text with every confirmed token replaced by Marker.
func (t *Tokens) Replace(text string) string {
	if t == nil || text == "" {
		return text
	}
	var b strings.Builder
	last := 0
	t.scan(text, 0, func(m TokenMatch) bool {
		if last == 0 {
			b.Grow(len(text))
		}
		b.WriteString(text[last:m.Start])
		b.WriteString(Marker)
		last = m.End
		return true
	})
	if last == 0 {
		return text
	}
	b.WriteString(text[last:])
	return b.String()
}

// scanHashBudget is how many bytes one scan of text may hash: a fixed
// allowance and 16 for every byte of text — a candidate every few lines of
// ordinary output stays far inside it, and a text of nothing but prefixes
// costs at most a few dozen times a linear pass.
func scanHashBudget(n int) int { return 64<<10 + 16*n }

// scan calls fn for each confirmed token starting at or after from, until fn
// returns false.
//
// Each prefix is searched for with strings.Index, and the next occurrence of
// every prefix is remembered rather than searched for again from each
// candidate, so a text is read once per prefix whatever it holds. A candidate
// is hashed once per length recorded under its prefix, and those are few: one
// for each kind of session token, and the lengths of the installation tokens
// GitHub actually issued to this run.
func (t *Tokens) scan(text string, from int, fn func(TokenMatch) bool) {
	if t == nil || from >= len(text) {
		return
	}
	if from < 0 {
		from = 0
	}
	var nextBuf [8]int
	next := nextBuf[:0]
	for range t.shapes {
		next = append(next, -2)
	}
	budget := scanHashBudget(len(text) - from)
	pos := from
	for pos < len(text) {
		best, bi := -1, -1
		for i, sh := range t.shapes {
			if next[i] == -1 {
				continue
			}
			if next[i] < pos {
				k := strings.Index(text[pos:], sh.prefix)
				if k < 0 {
					next[i] = -1
					continue
				}
				next[i] = pos + k
			}
			if best < 0 || next[i] < best {
				best, bi = next[i], i
			}
		}
		if best < 0 {
			return
		}
		end, idx := -1, -1
		for _, n := range t.shapes[bi].lens {
			if best+n > len(text) {
				continue
			}
			if budget < n {
				return
			}
			budget -= n
			if j, ok := t.sums[sha256.Sum256([]byte(text[best:best+n]))]; ok {
				end, idx = best+n, j
				break
			}
		}
		if end < 0 {
			pos = best + 1
			continue
		}
		if !fn(TokenMatch{Start: best, End: end, Index: idx}) {
			return
		}
		pos = end
	}
}

// Holdback returns how many trailing bytes of text a stream must withhold
// because they could still turn out to be the start of a recorded token: a
// piece of a prefix, or a prefix and less of a body than any length recorded
// under it. Zero when nothing at the end of text could begin one.
//
// Only the trailing run of bytes a token can hold is looked at, so ordinary
// output, which ends in whitespace or punctuation, costs one byte's test.
func (t *Tokens) Holdback(text string) int {
	if t == nil || text == "" {
		return 0
	}
	w := t.maxLen - 1
	if w > maxHoldback {
		w = maxHoldback
	}
	if w > len(text) {
		w = len(text)
	}
	r := len(text)
	for r > len(text)-w && isTokenByte(text[r-1]) {
		r--
	}
	for p := r; p < len(text); p++ {
		tail := text[p:]
		for _, sh := range t.shapes {
			if len(tail) < len(sh.prefix) {
				if strings.HasPrefix(sh.prefix, tail) {
					return len(tail)
				}
				continue
			}
			if strings.HasPrefix(tail, sh.prefix) && len(tail) < sh.lens[0] {
				return len(tail)
			}
		}
	}
	return 0
}

// isTokenByte reports whether c can occur in a minted token: the letters,
// digits and '_' of every prefix, base64url's '-' and '_', and the '.' that
// separates the parts of a Kubernetes monitor, relay or installation token.
func isTokenByte(c byte) bool {
	return isAlnum(c) || c == '_' || c == '-' || c == '.'
}
