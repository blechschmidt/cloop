package gitproxy

// scanmatch.go finds the run's credentials in a stream of bytes.
//
// # Exact values, in the forms a commit carries them
//
// Every value is matched as delivered, and in the encodings a person or a tool
// is likely to write it in: base64 in both alphabets — at all three alignments,
// so a value embedded in a larger encoded blob, such as a .dockerconfigjson or
// a Kubernetes Secret manifest, is found as well as one encoded on its own —
// and percent-encoded, as it appears in a URL's userinfo or a query string. A
// PEM block also contributes each of its base64 lines, so a private key is
// found whatever line endings or indentation the file it was pasted into uses.
//
// # The search
//
// One pass, whatever the number of values. Each pattern is anchored on its
// last eight bytes, which are a 64-bit word: the stream keeps the last eight
// bytes it saw as one, tests a bit in a filter for each position, and only on
// a hit looks the word up and compares the patterns ending in it against the
// bytes before. The window it keeps is as long as the longest pattern, so a
// value split across two chunks of a stream is still found; a value split
// across two *segments* — the inserts on either side of a delta's copy — is
// not, by design (see pushscan.go).

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/redact"
)

// The encodings a match is reported in.
const (
	formRaw     = "as delivered"
	formBase64  = "base64-encoded"
	formPercent = "percent-encoded"
	formPEMLine = "a line of its PEM block"
)

// anchorLen is the width of the word each pattern is anchored on. It is
// redact.MinLen, so every value long enough to be matched at all has one.
const anchorLen = 8

// filterBits sizes the anchor filter: 2^18 bits is 32 KiB, which stays in a
// core's cache, and keeps the false-positive rate for a few hundred patterns
// near a tenth of a percent per byte.
const filterBits = 18

// pemLineMin is the shortest line of a PEM block matched on its own. A body
// line is 64 characters; the last is shorter and can be four, which is too
// short to say anything.
const pemLineMin = 16

type scanPattern struct {
	b      []byte
	secret int
	form   string
}

// matcher is an immutable set of patterns.
type matcher struct {
	secrets []ScanSecret
	pats    []scanPattern
	tails   map[uint64][]int32
	filter  []uint64
	maxLen  int
	// tokens confirm the run's tokens this process knows only by hash
	// (Task 20454), and tokenPat names the pattern standing for each: one
	// with no bytes, which only carries the token's provenance and form.
	// shapes are the prefixes they are found by, with the lengths recorded
	// under each; maxPrefix is the longest prefix.
	tokens    *redact.Tokens
	tokenPat  map[[sha256.Size]byte]int32
	shapes    []redact.TokenShape
	prefixes  [][]byte
	maxPrefix int
}

// newMatcher builds the patterns for secrets, and the confirmations for
// tokens. It returns nil when no value is long enough to match and no token
// can be found.
func newMatcher(secrets []ScanSecret, tokens ...ScanToken) *matcher {
	m := &matcher{tails: map[uint64][]int32{}, filter: make([]uint64, 1<<filterBits/64)}
	seen := map[string]bool{}
	for _, s := range secrets {
		forms := valueForms(s.Value)
		if len(forms) == 0 {
			continue
		}
		idx := -1
		for _, f := range forms {
			if seen[f.text] {
				continue
			}
			seen[f.text] = true
			if idx < 0 {
				// The value is stored with its provenance only once it
				// contributes a pattern, so two grants delivering one value
				// are reported as the first of them.
				m.secrets = append(m.secrets, ScanSecret{Grant: s.Grant, Secret: s.Secret, Field: s.Field})
				idx = len(m.secrets) - 1
			}
			b := []byte(f.text)
			m.pats = append(m.pats, scanPattern{b: b, secret: idx, form: f.form})
			k := tailKey(b)
			m.tails[k] = append(m.tails[k], int32(len(m.pats)-1))
			h := filterIndex(k)
			m.filter[h>>6] |= 1 << (h & 63)
			if len(b) > m.maxLen {
				m.maxLen = len(b)
			}
		}
	}
	m.addTokens(tokens)
	if len(m.pats) == 0 {
		return nil
	}
	return m
}

// addTokens adds a bodiless pattern for each token a hash can confirm, so a
// confirmed token is reported through the same path as a matched value.
func (m *matcher) addTokens(tokens []ScanToken) {
	var hs []redact.TokenHash
	for _, tok := range tokens {
		hs = append(hs, tok.Hash)
	}
	m.tokens = redact.NewTokens(hs...)
	if m.tokens == nil {
		return
	}
	m.tokenPat = map[[sha256.Size]byte]int32{}
	for _, tok := range tokens {
		if _, dup := m.tokenPat[tok.Hash.Sum]; dup {
			continue
		}
		m.secrets = append(m.secrets, ScanSecret{Grant: tok.Grant, Secret: tok.Secret, Field: tok.Field})
		m.pats = append(m.pats, scanPattern{secret: len(m.secrets) - 1, form: formRaw})
		m.tokenPat[tok.Hash.Sum] = int32(len(m.pats) - 1)
	}
	if n := m.tokens.MaxLen(); n > m.maxLen {
		m.maxLen = n
	}
	m.shapes = m.tokens.Shapes()
	for _, sh := range m.shapes {
		m.prefixes = append(m.prefixes, []byte(sh.Prefix))
		m.maxPrefix = max(m.maxPrefix, len(sh.Prefix))
	}
}

func tailKey(b []byte) uint64 {
	var k uint64
	for _, c := range b[len(b)-anchorLen:] {
		k = k<<8 | uint64(c)
	}
	return k
}

func filterIndex(k uint64) uint64 { return (k * 0x9E3779B97F4A7C15) >> (64 - filterBits) }

// redact replaces every pattern in s, for a string about to be shown or
// recorded: a path, a tag or ref name the proxy names in a refusal could
// itself carry the value.
func (m *matcher) redact(s string) string {
	if m == nil || s == "" {
		return s
	}
	for _, p := range m.pats {
		if len(p.b) > 0 && strings.Contains(s, string(p.b)) {
			s = strings.ReplaceAll(s, string(p.b), redact.Marker)
		}
	}
	return m.tokens.Replace(s)
}

// contains reports whether b holds any pattern, for a short buffer read whole.
func (m *matcher) contains(b []byte) (int, bool) {
	if m == nil {
		return -1, false
	}
	st := matchStream{m: m}
	found := -1
	st.write(b, func(pi int, _ int64) bool {
		found = pi
		return false
	})
	return found, found >= 0
}

// matchStream scans one segment of a stream: an object's content, or a run of
// a delta's inserts. reset starts the next one.
type matchStream struct {
	m   *matcher
	buf []byte
	w   uint64
	n   int64
	// prefixedTo is how far into buf token prefixes have been looked for, and
	// pending the prefixes found whose token could still end in a later write:
	// each write reads only what it added for prefixes, and hashes a
	// candidate once, in the write its recorded length ends in.
	prefixedTo int
	pending    []tokenCandidate
}

// tokenCandidate is a token prefix found in a stream: where in buf it starts,
// and which of the matcher's shapes it is.
type tokenCandidate struct {
	pos   int
	shape int
}

func (s *matchStream) reset() {
	s.buf = s.buf[:0]
	s.w = 0
	s.n = 0
	s.prefixedTo = 0
	s.pending = s.pending[:0]
}

// write scans p as the continuation of the segment and calls hit for every
// pattern that ends in it, with the segment offset just past the match. hit
// returns false to stop scanning this write.
func (s *matchStream) write(p []byte, hit func(pattern int, end int64) bool) {
	m := s.m
	if m == nil || len(p) == 0 {
		return
	}
	keep := len(s.buf)
	s.buf = append(s.buf, p...)
	buf := s.buf
	w, n := s.w, s.n
	filter := m.filter
	for i := keep; i < len(buf); i++ {
		w = w<<8 | uint64(buf[i])
		n++
		if n < anchorLen {
			continue
		}
		h := filterIndex(w)
		if filter[h>>6]&(1<<(h&63)) == 0 {
			continue
		}
		for _, pi := range m.tails[w] {
			pat := m.pats[pi].b
			if i+1 >= len(pat) && bytes.Equal(buf[i+1-len(pat):i+1], pat) {
				if !hit(int(pi), n) {
					s.w, s.n = w, n
					s.trim()
					return
				}
			}
		}
	}
	s.w, s.n = w, n
	if m.tokens != nil && !s.writeTokens(keep, hit) {
		s.trim()
		return
	}
	s.trim()
}

// writeTokens finds the run's hashed tokens that end in what the write just
// added — buf[keep:] — and reports each through hit. It reports false when hit
// asked to stop.
//
// The prefixes a write adds are looked for in it alone (and the few bytes
// before it a prefix can straddle). A token is no longer than the window
// keeps, so one ending in this write either started in it or is a prefix
// found by an earlier write, still pending. Each candidate is hashed once per
// recorded length, in the write that length ends in: a stream of many small
// writes — a delta's inserts — costs what it adds, not the window per write.
func (s *matchStream) writeTokens(keep int, hit func(pattern int, end int64) bool) bool {
	m, buf := s.m, s.buf
	from := max(s.prefixedTo-(m.maxPrefix-1), 0)
	for i, prefix := range m.prefixes {
		for at := from; at < len(buf); {
			k := bytes.Index(buf[at:], prefix)
			if k < 0 {
				break
			}
			pos := at + k
			// One that ended before prefixedTo was found by an earlier write.
			if pos+len(prefix) > s.prefixedTo {
				s.pending = append(s.pending, tokenCandidate{pos: pos, shape: i})
			}
			at = pos + 1
		}
	}
	s.prefixedTo = len(buf)
	kept := s.pending[:0]
	ok := true
	for _, c := range s.pending {
		lens := m.shapes[c.shape].Lens
		if ok {
			for _, l := range lens {
				end := c.pos + l
				if end <= keep || end > len(buf) {
					continue
				}
				idx, found := m.tokens.Confirm(buf[c.pos:end])
				if !found {
					continue
				}
				pi := m.tokenPat[m.tokens.Hash(idx).Sum]
				if !hit(int(pi), s.n-int64(len(buf)-end)) {
					ok = false
				}
				break
			}
		}
		// Kept while its longest recorded length can still end later.
		if c.pos+lens[0] > len(buf) {
			kept = append(kept, c)
		}
	}
	s.pending = kept
	return ok
}

// trim keeps the bytes a pattern ending in the next write could start in. It
// lets the window run long before moving it, so a delta's many short inserts
// do not each pay for copying the whole window.
func (s *matchStream) trim() {
	keep := s.m.maxLen - 1
	if keep < 0 {
		keep = 0
	}
	if len(s.buf) > keep+trimSlack {
		shift := len(s.buf) - keep
		copy(s.buf, s.buf[shift:])
		s.buf = s.buf[:keep]
		// Token candidates move with the bytes they name. A pending one is
		// within the longest token of the end, which the window keeps.
		s.prefixedTo = max(s.prefixedTo-shift, 0)
		kept := s.pending[:0]
		for _, c := range s.pending {
			if c.pos -= shift; c.pos >= 0 {
				kept = append(kept, c)
			}
		}
		s.pending = kept
	}
}

// trimSlack is how far the window may run past the longest pattern before
// trim moves it.
const trimSlack = 64 << 10

// --- forms --------------------------------------------------------------------

type valueForm struct {
	text string
	form string
}

// valueForms returns the encodings of v worth matching, longest-guarded: none
// shorter than redact.MinLen, and none for a value that is a placeholder a
// redactor left behind rather than a credential.
func valueForms(v string) []valueForm {
	v = strings.TrimSpace(v)
	if len(v) < redact.MinLen || redact.IsPlaceholder(v) {
		return nil
	}
	var out []valueForm
	add := func(text, form string) {
		if len(text) < redact.MinLen {
			return
		}
		for _, f := range out {
			if f.text == text {
				return
			}
		}
		out = append(out, valueForm{text: text, form: form})
	}
	add(v, formRaw)
	for _, line := range pemBodyLines(v) {
		add(line, formPEMLine)
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		for _, core := range base64Cores(enc, []byte(v)) {
			add(core, formBase64)
		}
	}
	for _, esc := range percentForms(v) {
		add(esc, formPercent)
	}
	return out
}

// base64Cores returns, for each of the three alignments v can start at inside
// a larger encoded input, the characters of its encoding that depend on v
// alone. A value encoded on its own contains the first; one encoded at byte
// offset 1 or 2 of something longer contains the second or third.
func base64Cores(enc *base64.Encoding, v []byte) []string {
	out := make([]string, 0, 3)
	for shift := 0; shift < 3; shift++ {
		buf := make([]byte, shift+len(v))
		copy(buf[shift:], v)
		s := enc.EncodeToString(buf)
		// Characters before the value's first full sextet depend on the bytes
		// in front of it.
		lead := [3]int{0, 2, 3}[shift]
		// And those after its last full sextet on the bytes behind it — which
		// for a value encoded on its own is the padding.
		end := len(s)
		switch len(buf) % 3 {
		case 1:
			end -= 3
		case 2:
			end -= 2
		}
		if end-lead >= redact.MinLen {
			out = append(out, s[lead:end])
		}
	}
	return out
}

// percentForms returns v percent-encoded as a query value, as a path segment,
// as URL userinfo, and with every reserved byte escaped in either case of hex.
func percentForms(v string) []string {
	var out []string
	out = append(out, url.QueryEscape(v), url.PathEscape(v))
	if u := url.UserPassword("x", v).String(); strings.HasPrefix(u, "x:") {
		out = append(out, u[2:])
	}
	upper, lower := strictEscape(v)
	out = append(out, upper, lower)
	keep := out[:0]
	for _, s := range out {
		if s != v {
			keep = append(keep, s)
		}
	}
	return keep
}

// strictEscape escapes every byte outside RFC 3986's unreserved set.
func strictEscape(v string) (upper, lower string) {
	const hexU, hexL = "0123456789ABCDEF", "0123456789abcdef"
	var u, l strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			u.WriteByte(c)
			l.WriteByte(c)
			continue
		}
		u.WriteByte('%')
		u.WriteByte(hexU[c>>4])
		u.WriteByte(hexU[c&15])
		l.WriteByte('%')
		l.WriteByte(hexL[c>>4])
		l.WriteByte(hexL[c&15])
	}
	return u.String(), l.String()
}

// pemBodyLines returns the base64 lines of every private key PEM block in v,
// whether its lines are broken by real newlines or by the escaped "\n" of a
// JSON string — a service account key file carries its private key the second
// way. Only private keys: a certificate or a public key in a credential is
// published by design, and its lines turn up in every repository that pins it.
func pemBodyLines(v string) []string {
	if !strings.Contains(v, "PRIVATE KEY-----") {
		return nil
	}
	norm := strings.ReplaceAll(v, `\r\n`, "\n")
	norm = strings.ReplaceAll(norm, `\n`, "\n")
	norm = strings.ReplaceAll(norm, "\r\n", "\n")
	var out []string
	in := false
	for _, line := range strings.Split(norm, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "-----BEGIN"):
			in = strings.Contains(line, "PRIVATE KEY")
			continue
		case strings.HasPrefix(line, "-----END"):
			in = false
			continue
		}
		// Armor headers (Proc-Type, DEK-Info) say how a key is encrypted,
		// which is the same for every key encrypted that way.
		if !in || len(line) < pemLineMin || strings.Contains(line, ":") {
			continue
		}
		out = append(out, line)
	}
	sort.Strings(out)
	return out
}
