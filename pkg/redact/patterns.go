package redact

// Credential shapes: the one registry every pattern scanner in cloop uses.
//
// # Why there is a registry
//
// Four scanners look for credentials they were never told about: cloop audit's
// scan of .cloop/ history and task artifacts, the provider-call audit's
// error-message redaction, the secret broker's audit-reason redaction, and the
// browser-telemetry scrubber. Each used to carry its own list, and each list
// covered a different subset. The audit regexes had never heard of gho_, ghu_
// or ghr_, and their ghs_ pattern matched nothing GitHub has issued since
// September 2026: an installation token is now 390 characters shaped
// ghs_<7 digits>_<36>.<254>.<86>, and `ghs_[A-Za-z0-9]{30,}` stops at the first
// underscore, seven characters in. The check reported clean over a real leak.
// The telemetry scrubber knew only cloop's own two prefixes, so a browser error
// carrying a GitHub token was stored verbatim; the broker's list knew none of
// cloop's prefixes at all.
//
// A credential shape is a fact about the credential, not about the scanner, so
// it is defined once, here, and every scanner asks this registry. What stays
// per scanner is what it does with a match — the replacement style.
//
// # What this is not
//
// It is not the primary defence. A Set matches the exact values a lease
// delivered, and it is the only thing on the streaming path; nothing here runs
// there, for the reasons the package doc gives. These detectors exist for text
// that never passed through a Set because whoever is scrubbing it cannot know
// the values: an error string from three packages down, a browser's stack
// trace, a commit made last year.
//
// # Precision
//
// A detector that fires on ordinary output is worse than useless: it mangles a
// diagnostic, and an operator who sees a marker over a commit hash learns to
// ignore markers. So each shape is anchored on something a credential has and
// prose does not — a distinctive literal prefix, a fixed length, a header
// keyword — and the looser ones also have to look generated: carry a digit or
// an interior capital, or be long. The negative corpus in pkg/redact/redacttest
// (base64 blobs in diffs, commit SHAs, UUIDs, metric and nftables names) holds
// every scanner to that.

import (
	"regexp"
	"sort"
	"strings"
)

// Detector is one named credential shape.
//
// Name is stable: it is what cloop audit reports and what the fixture corpus
// keys on, so a detector is never renamed — retire it and add another.
type Detector struct {
	// Name is the kebab-case identifier, e.g. "github-token-long".
	Name string
	// Label is a short human description for a report line.
	Label string
	// Recognises says, for the reference page, what the detector matches.
	Recognises string

	re *regexp.Regexp
	// keywords are literals at least one of which must appear in a text for
	// the expression to be worth running. Lowercase when fold is set.
	keywords []string
	// fold makes keywords match ASCII-case-insensitively, for (?i) patterns.
	fold bool
	// before and after reject a match whose neighbouring byte satisfies them:
	// a shape that is also the tail of a longer word is not a credential
	// ("task-…" is not an OpenAI key) and a fixed-length shape that runs on
	// is not that shape. The byte before is read through an escape; see
	// precedingByte.
	before, after func(byte) bool
	// followedBy rejects a match the rest of the text after it satisfies.
	followedBy func(rest string) bool
	// valid is a last check on the matched credential.
	valid func(kind, secret string) bool
	// skipRejected resumes the search at the end of a rejected candidate
	// instead of one byte into it; see appendMatches.
	skipRejected bool
	// secret and kind are the subexpression indices named "secret" and
	// "kind". Without a secret group the whole match is the credential. A
	// group named "bare" is a secret with nothing in front of it to say so —
	// an Authorization value with no scheme — so it must also look generated.
	secret, kind, bare []int
	// toDelimiter carries an accepted value on to the next delimiter; see
	// valueEnd.
	toDelimiter bool
	rank        int
}

// Match is one credential found in a text.
type Match struct {
	// Detector is the Name of the detector that matched; Label is its Label.
	Detector, Label string
	// Start and End delimit the credential: the bytes a scanner removes.
	// Context a detector needed in order to recognise it — "Bearer ", a URL's
	// scheme and host, a "token:" key — lies outside and is kept.
	Start, End int
	// Kind is the credential's public lead when its format has one — "ghs_",
	// "sk-ant-api03-", "cloop_pat_" — and empty otherwise. It sits at Start.
	// A replacement may keep it: it says which kind of credential was removed
	// and nothing about the value.
	Kind string

	rank int
}

// Detectors returns the registry in precedence order. The copies are safe to
// keep; matching does not depend on anything a caller can change.
func Detectors() []Detector {
	out := make([]Detector, len(registry))
	for i, d := range registry {
		out[i] = *d
	}
	return out
}

// Find returns every credential in text, ordered by position.
//
// Detectors are independent, so the same bytes can be reported twice — a
// GitHub token inside an Authorization header is both. A scanner that only
// needs to know what is there (cloop audit) wants exactly that; one that
// rewrites the text wants ScrubFunc, which merges overlaps first.
func Find(text string) []Match {
	if text == "" {
		return nil
	}
	var lower string
	lowered := false
	folded := func() string {
		if !lowered {
			lower, lowered = asciiLower(text), true
		}
		return lower
	}
	var out []Match
	for _, d := range registry {
		if d.mayMatch(text, folded) {
			out = d.appendMatches(out, text)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Start != out[j].Start {
			return out[i].Start < out[j].Start
		}
		if out[i].End != out[j].End {
			return out[i].End > out[j].End
		}
		return out[i].rank < out[j].rank
	})
	return out
}

// ScrubFunc returns text with every credential replaced by what repl returns
// for it. Overlapping matches are merged into one span first, so a token
// inside a URL inside a header is replaced once, and the merged Match carries
// the detector that starts earliest — the most specific on a tie.
//
// It repeats until nothing more changes, at most maxPasses times. One pass is
// not always enough: a credential glued to another one — a key straight after
// a PEM block's last dash — fails its boundary check against bytes that the
// same pass replaces, and only the next pass sees it follow the replacement.
// Text with nothing in it costs one pass, as before.
func ScrubFunc(text string, repl func(Match) string) string {
	for pass := 0; pass < maxPasses; pass++ {
		out := scrubOnce(text, repl)
		if out == text {
			break
		}
		text = out
	}
	return text
}

// maxPasses bounds ScrubFunc. Each pass after the first only finds what a
// replacement uncovered, and a replacement uncovers at most the credential
// glued to it.
const maxPasses = 3

func scrubOnce(text string, repl func(Match) string) string {
	ms := merge(Find(text))
	if len(ms) == 0 {
		return text
	}
	var b strings.Builder
	b.Grow(len(text))
	last := 0
	for _, m := range ms {
		b.WriteString(text[last:m.Start])
		b.WriteString(repl(m))
		last = m.End
	}
	b.WriteString(text[last:])
	return b.String()
}

// Scrub replaces every credential in text with Marker.
func Scrub(text string) string {
	return ScrubFunc(text, func(Match) string { return Marker })
}

// merge collapses overlapping matches, which Find returns sorted by start.
func merge(ms []Match) []Match {
	var out []Match
	for _, m := range ms {
		if n := len(out); n > 0 && m.Start < out[n-1].End {
			if m.End > out[n-1].End {
				out[n-1].End = m.End
			}
			continue
		}
		out = append(out, m)
	}
	return out
}

func (d *Detector) mayMatch(text string, folded func() string) bool {
	if len(d.keywords) == 0 {
		return true
	}
	hay := text
	if d.fold {
		hay = folded()
	}
	for _, k := range d.keywords {
		if strings.Contains(hay, k) {
			return true
		}
	}
	return false
}

// appendMatches adds d's matches in text to out.
//
// The expressions carry no ^ or \b, so searching a suffix of text finds what
// searching the whole would; the boundary rules live in before, after and
// followedBy, which look at the real neighbouring text. When a candidate fails
// them the search resumes just past it, not past its end, so a rejected
// candidate cannot hide a real credential that starts inside it.
//
// That costs a rescan of the rest of the candidate, and for a shape whose body
// can hold its own prefix — "ghs_a.ghs_a.ghs_a." is one long-form candidate
// and, a byte later, another — each rescan runs to the same end: quadratic
// time, which a 2 MiB telemetry field turned into hours of CPU. A detector
// whose rejection provably carries over to every candidate inside the
// rejected one sets skipRejected and resumes at its end instead; the proof for
// each is at its spec.
func (d *Detector) appendMatches(out []Match, text string) []Match {
	// delimFrom and delimAt cache valueEnd's last answer: no delimiter lies in
	// [delimFrom, delimAt), so a value ending anywhere in that range runs on
	// to delimAt, and a run of fields glued together is read once rather
	// than once per field.
	delimFrom, delimAt := -1, -1
	for pos := 0; pos < len(text); {
		loc := d.re.FindStringSubmatchIndex(text[pos:])
		if loc == nil {
			break
		}
		for i := range loc {
			if loc[i] >= 0 {
				loc[i] += pos
			}
		}
		start, end := loc[0], loc[1]
		ss, se := span(loc, d.secret, start, end)
		bare := false
		if bs, be := span(loc, d.bare, -1, -1); bs >= 0 {
			ss, se, bare = bs, be, true
		}
		kind := ""
		if ks, ke := span(loc, d.kind, -1, -1); ks >= 0 {
			kind = text[ks:ke]
		}
		ok := se > ss
		// boundary records a rejection for the byte before the candidate,
		// which a candidate starting later inside it does not share.
		boundary := false
		if ok && d.before != nil && start > 0 && d.before(precedingByte(text, start)) {
			ok, boundary = false, true
		}
		if ok && d.after != nil && end < len(text) && d.after(text[end]) {
			ok = false
		}
		if ok && d.followedBy != nil && d.followedBy(text[end:]) {
			ok = false
		}
		if ok && kind != "" && repeatedTail(text[ss+len(kind):se]) {
			ok = false
		}
		if ok && bare && !credentialLike(text[ss:se]) {
			ok = false
		}
		if ok && d.valid != nil && !d.valid(kind, text[ss:se]) {
			ok = false
		}
		if ok {
			if d.toDelimiter {
				if se < delimFrom || se > delimAt {
					delimFrom, delimAt = se, valueEnd(text, se)
				}
				se = delimAt
			}
			out = append(out, Match{
				Detector: d.Name, Label: d.Label,
				Start: ss, End: se, Kind: kind, rank: d.rank,
			})
			pos = end
			if end == start {
				pos++
			}
			continue
		}
		if d.skipRejected && end > start {
			pos = end
			continue
		}
		pos = start + 1
		if !boundary && ss > pos {
			// Rejected for what it matched, not for where it starts: a
			// candidate starting before ss — the "token" of "auth_token", the
			// "b" of "ab://" — matches the same value and fails the same way,
			// and rescanning it once per such start would read a long value
			// thirty times over. After a boundary rejection those candidates
			// follow a different byte, so they are tried: "oauth_token=…"
			// starts at "auth" glued to an "o", and its "token" is a field.
			pos = ss
		}
	}
	return out
}

// precedingByte returns the byte before i, reading through an escape that ends
// there. Two kinds of text put one in front of a credential:
//
//   - A quoted string — JSON, a Go %q, a log line that quotes another — where
//     the byte before a credential that starts a line is the n of `\n`, and
//     before one after an escaped bracket the c of `\u003c`.
//   - A percent-encoded URL — a redirect parameter carrying a whole address, a
//     telemetry event's page URL — where the byte before a credential that
//     follows "=" is the D of `%3D`.
//
// A boundary check that took that letter for the end of a word would miss
// every such credential, so an escape is read as the byte it encodes, and an
// escaped word byte still joins a word.
func precedingByte(text string, i int) byte {
	if i >= 2 && text[i-2] == '\\' {
		switch text[i-1] {
		case 'n':
			return '\n'
		case 'r':
			return '\r'
		case 't':
			return '\t'
		case 'b':
			return '\b'
		case 'f':
			return '\f'
		}
	}
	if i >= 3 && text[i-3] == '%' {
		if c, ok := unhex(text[i-2], text[i-1]); ok {
			return c
		}
	}
	if i >= 6 && text[i-6] == '\\' && text[i-5] == 'u' && text[i-4] == '0' && text[i-3] == '0' {
		if c, ok := unhex(text[i-2], text[i-1]); ok {
			return c
		}
	}
	return text[i-1]
}

// unhex decodes two hexadecimal digits into the byte they spell.
func unhex(hi, lo byte) (byte, bool) {
	h, okh := hexDigit(hi)
	l, okl := hexDigit(lo)
	return h<<4 | l, okh && okl
}

func hexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// valueEnd returns where a field value whose expression stopped at i really
// ends. A value can hold a byte the expression does not list — "p4ss!word", a
// "|" in a Sanctum-style token, a percent-encoded "+" in a base64 one — and
// cutting it there would leave the rest in place, where the scrubbers this
// registry replaced removed it whole. So the value runs on over those bytes,
// and over percent escapes that stand for one, and stops at anything else: an
// "@" before a URL's host, an "=" or "&" between parameters, whitespace, a
// quote, a bracket.
func valueEnd(text string, i int) int {
	for i < len(text) {
		c := text[i]
		switch {
		case isValueByte(c):
			i++
		case c == '%' && i+2 < len(text):
			d, ok := unhex(text[i+1], text[i+2])
			if !ok || !isValueByte(d) {
				return i
			}
			i += 3
		default:
			return i
		}
	}
	return i
}

// isValueByte is a byte a credential's value may hold: the field detectors'
// own characters and the punctuation generated passwords and tokens use.
func isValueByte(c byte) bool {
	if isAlnum(c) {
		return true
	}
	switch c {
	case '.', '_', '~', '+', '/', '-', '!', '$', '*', '^', '|', '?':
		return true
	}
	return false
}

// span returns the first participating subexpression among idx, or the
// defaults when none took part.
func span(loc, idx []int, defStart, defEnd int) (int, int) {
	for _, i := range idx {
		if 2*i+1 < len(loc) && loc[2*i] >= 0 {
			return loc[2*i], loc[2*i+1]
		}
	}
	return defStart, defEnd
}

// asciiLower lowercases A–Z only. strings.ToLower would also fold some
// multi-byte runes into sequences of a different length, and the offsets a
// folded keyword search relies on would no longer line up.
func asciiLower(s string) string {
	i := 0
	for i < len(s) && (s[i] < 'A' || s[i] > 'Z') {
		i++
	}
	if i == len(s) {
		return s
	}
	b := []byte(s)
	for ; i < len(b); i++ {
		if c := b[i]; c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// --- the registry ---------------------------------------------------------

// spec is a detector before compilation.
type spec struct {
	name, label, recognises string
	pattern                 string
	keywords                []string
	fold                    bool
	before, after           func(byte) bool
	followedBy              func(rest string) bool
	valid                   func(kind, secret string) bool
	skipRejected            bool
	toDelimiter             bool
}

// specs is the registry, in precedence order: when two detectors claim the
// same span, the earlier one names the merged match. A shape that spans more
// (a PEM block) or says more (a cloop token) comes before one that is generic
// (a bearer value, a URL's userinfo).
var specs = []spec{
	{
		name:  "pem-private-key",
		label: "PEM private key",
		recognises: "A `-----BEGIN … PRIVATE KEY-----` block (RSA, EC, DSA, OPENSSH, " +
			"ENCRYPTED, PKCS#8, PGP `PRIVATE KEY BLOCK`) through its END line, or through the " +
			"lines of key after it when the block was cut off. A header with no key after it, " +
			"certificates and public keys are not matched.",
		// The cut-off form reads base64 lines, each at least 16 characters and
		// each led by at most a diff's + or -, across real or escaped line
		// breaks. A header that is only mentioned — "no -----BEGIN RSA PRIVATE
		// KEY----- block found" — has none, and the sentence after it is not
		// a key.
		pattern:  `-----BEGIN[ A-Z0-9]*PRIVATE KEY(?: BLOCK)?-----(?:(?s:.*?)-----END[ A-Z0-9]*PRIVATE KEY(?: BLOCK)?-----|(?:(?:\s|\\[nrt])+[+\-]?[0-9A-Za-z+/=]{16,})+)`,
		keywords: []string{"PRIVATE KEY"},
	},
	{
		name:       "cloop-api-token",
		label:      "cloop API token",
		recognises: "`cloop_pat_<id>_<secret>` — operator PATs, service-account tokens and display-glasses links.",
		pattern:    `(?P<kind>cloop_pat_)[0-9A-Za-z]{4,}_[0-9A-Za-z]{8,}`,
		keywords:   []string{"cloop_pat_"},
	},
	{
		name:  "cloop-glasses-link",
		label: "cloop display-glasses link token",
		recognises: "`cloop_glasses_…`. No build has minted this prefix — glasses links are " +
			"`cloop_pat_` tokens — but the telemetry scrubber matched it from the start, and " +
			"keeping it costs nothing.",
		pattern:  `(?P<kind>cloop_glasses_)[0-9A-Za-z_\-]{8,}`,
		keywords: []string{"cloop_glasses_"},
	},
	{
		name:       "cloop-ci-token",
		label:      "cloop CI relay session token",
		recognises: "`cloop_ci_<id>.<secret>`, the session token a CI job presents to the Claude relay.",
		pattern:    `(?P<kind>cloop_ci_)[0-9A-Za-z\-]{4,}\.[0-9A-Za-z_\-]{8,}`,
		keywords:   []string{"cloop_ci_"},
	},
	{
		name:       "cloop-enrollment-token",
		label:      "cloop executor enrollment token",
		recognises: "`clet1.<id>.<secret>.<mac>`, the single-use token an edge device enrolls with.",
		pattern:    `(?P<kind>clet1\.)[0-9A-Za-z_\-]{4,}\.[0-9A-Za-z_\-]{8,}(?:\.[0-9A-Za-z_\-]+)?`,
		keywords:   []string{"clet1."},
		before:     isWordByte,
	},
	{
		name:       "cloop-enrollment-bundle",
		label:      "cloop executor enrollment bundle",
		recognises: "`cloopenroll1.<base64url>`, the copy-paste bundle that carries an enrollment token.",
		pattern:    `(?P<kind>cloopenroll1\.)[0-9A-Za-z_\-]{16,}`,
		keywords:   []string{"cloopenroll1."},
	},
	{
		name:       "cloop-agent-credential",
		label:      "cloop executor agent credential",
		recognises: "`clac1.<agent>.<secret>.<mac>`, the long-lived credential an enrolled agent reconnects with.",
		pattern:    `(?P<kind>clac1\.)[0-9A-Za-z_\-]{4,}\.[0-9A-Za-z_\-]{8,}(?:\.[0-9A-Za-z_\-]+)?`,
		keywords:   []string{"clac1."},
		before:     isWordByte,
	},
	{
		name:  "github-token-long",
		label: "GitHub token (long form)",
		recognises: "`ghp_`, `gho_`, `ghu_`, `ghs_` or `ghr_` followed by 31 or more characters " +
			"including `_` or `.` — the dotted form GitHub has issued installation tokens in " +
			"since September 2026 (`ghs_<7 digits>_<36>.<254>.<86>`, 390 characters) — or by " +
			"that form's lead alone, the digits and the underscore after them, which is what a " +
			"line break or a truncating log leaves of one on its first line. The body must " +
			"carry a digit or a capital, which a snake_case identifier does not.",
		pattern:  `(?P<kind>gh[pousr]_)(?:[0-9A-Za-z][0-9A-Za-z_.\-]{29,}[0-9A-Za-z_\-]|[0-9]{6,}_[0-9A-Za-z]*)`,
		keywords: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"},
		valid:    githubLongForm,
		// Only the first form is ever rejected: for a body with no digit and no
		// capital past its first byte, or one ending in a long run of one
		// character. A candidate starting inside it ends where it does and has
		// a later suffix of that body for its own: no digit and no capital at
		// all, or the same run under a shorter head — rejected either way. It
		// cannot start inside the run, which holds no "gh?_".
		skipRejected: true,
	},
	{
		name:       "github-token",
		label:      "GitHub token",
		recognises: "`ghp_`, `gho_`, `ghu_`, `ghs_` or `ghr_` followed by 16 or more letters and digits — the classic form (36).",
		pattern:    `(?P<kind>gh[pousr]_)[0-9A-Za-z]{16,}`,
		keywords:   []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"},
	},
	{
		name:       "github-fine-grained-pat",
		label:      "GitHub fine-grained personal access token",
		recognises: "`github_pat_` followed by 16 or more letters, digits and underscores (82 in practice), with a digit or a capital among them.",
		pattern:    `(?P<kind>github_pat_)[0-9A-Za-z_]{16,}`,
		keywords:   []string{"github_pat_"},
		valid:      bodyLooksGenerated,
		// As for the long form: a candidate inside a rejected one ends where
		// it does, and its body is a later suffix of a body with no digit and
		// no capital past its first byte, or the same repeated run under a
		// shorter head.
		skipRejected: true,
	},
	{
		name:       "anthropic-api-key",
		label:      "Anthropic API key",
		recognises: "`sk-ant-api03-…` (any two-digit version).",
		pattern:    `(?P<kind>sk-ant-api[0-9]{2}-)[0-9A-Za-z_\-]{8,}`,
		keywords:   []string{"sk-ant-api"},
	},
	{
		name:       "anthropic-oauth-token",
		label:      "Anthropic OAuth token",
		recognises: "`sk-ant-oat01-…` access tokens and `sk-ant-ort01-…` refresh tokens — what a Claude subscription login holds.",
		pattern:    `(?P<kind>sk-ant-o(?:at|rt)[0-9]{2}-)[0-9A-Za-z_\-]{8,}`,
		keywords:   []string{"sk-ant-oat", "sk-ant-ort"},
	},
	{
		name:       "anthropic-key",
		label:      "Anthropic credential (other form)",
		recognises: "Any other `sk-ant-…` credential with a body of 12 or more characters: admin keys, session keys, forms not yet issued.",
		pattern:    `(?P<kind>sk-ant-)[0-9A-Za-z_\-]{12,}`,
		keywords:   []string{"sk-ant-"},
	},
	{
		name:  "openai-api-key",
		label: "OpenAI API key",
		recognises: "`sk-proj-…`, `sk-svcacct-…`, `sk-admin-…` and `sk-None-…` keys, and legacy `sk-` " +
			"followed by 20 or more letters and digits. Not when `sk-` ends a longer word: `task-…`, `risk-…`.",
		pattern:  `(?P<kind>sk-(?:proj|svcacct|admin|None)-)[0-9A-Za-z_\-]{16,}|(?P<kind>sk-)[0-9A-Za-z]{20,}`,
		keywords: []string{"sk-"},
		before:   isWordByte,
		// Rejected by its boundary or for a placeholder body. Every byte of a
		// match is a word byte, so a candidate starting inside a rejected one
		// follows a word byte — never an escape, which needs a byte the match
		// cannot hold — and is rejected too, before its body is looked at.
		skipRejected: true,
	},
	{
		name:       "slack-token",
		label:      "Slack token",
		recognises: "`xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-`, `xoxo-`, `xoxe-` (and rotating `xoxe.xox?-`) and app-level `xapp-` tokens.",
		pattern:    `(?P<kind>(?:xoxe\.)?xox[abeoprs]-|xapp-)[0-9A-Za-z\-]{10,}`,
		keywords:   []string{"xox", "xapp-"},
	},
	{
		name:  "aws-access-key-id",
		label: "AWS access key ID",
		recognises: "`AKIA`, `ASIA`, `ABIA` or `ACCA` followed by exactly 16 capitals and digits, " +
			"standing alone. AWS's documentation keys, which end in `EXAMPLE`, are not matched.",
		pattern:  `(?P<kind>AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}`,
		keywords: []string{"AKIA", "ASIA", "ABIA", "ACCA"},
		before:   isUpperOrDigit,
		after:    isUpperOrDigit,
		valid:    func(_, v string) bool { return !strings.HasSuffix(v, "EXAMPLE") },
	},
	{
		name:       "google-api-key",
		label:      "Google API key",
		recognises: "`AIza` followed by 30 or more letters, digits, `_` and `-` (35 in practice).",
		pattern:    `(?P<kind>AIza)[0-9A-Za-z_\-]{30,}`,
		keywords:   []string{"AIza"},
	},
	{
		name:  "jwt",
		label: "JSON Web Token",
		recognises: "`eyJ…` header, payload and signature segments joined by dots (and the two further " +
			"segments of a JWE). A lone base64 JSON blob, with no dots, is not matched.",
		pattern:  `eyJ[0-9A-Za-z_\-]{6,}\.[0-9A-Za-z_\-]{2,}\.[0-9A-Za-z_\-]*(?:\.[0-9A-Za-z_\-]+){0,2}`,
		keywords: []string{"eyJ"},
	},
	{
		name:       "kubeconfig-client-key",
		label:      "kubeconfig client key",
		recognises: "The base64 value of a kubeconfig `client-key-data` field. `client-certificate-data` and `certificate-authority-data` are public and are left alone.",
		pattern:    `client-key-data\\?["']?[ \t]*:[ \t]*\\?["']?(?P<secret>[0-9A-Za-z+/]{16,}={0,2})`,
		keywords:   []string{"client-key-data"},
	},
	{
		name:  "aws-secret-access-key",
		label: "AWS secret access key",
		recognises: "The 40-character value of an `aws_secret_access_key` / `SecretAccessKey` field " +
			"— the half of an AWS key pair that is actually secret, and has no prefix of its own. " +
			"AWS's documentation key, which holds `EXAMPLE`, is not matched.",
		pattern:  `(?i)(?:aws_?)?secret_?access_?key\\?["']?[ \t]*[:=][ \t]*\\?["']?(?P<secret>[0-9A-Za-z+/]{40})`,
		keywords: []string{"secret_access_key", "secretaccesskey"},
		fold:     true,
		after:    isBase64Byte,
		valid:    func(_, v string) bool { return !strings.Contains(v, "EXAMPLE") },
	},
	{
		name:  "token-field",
		label: "credential field",
		recognises: "The value of a `token`, `id-token`, `refresh-token`, `access-token`, `auth-token`, " +
			"`session-token`, `api-token` or `client-secret` field (any case, `-` or `_` or " +
			"neither, and after a prefix such as `GITHUB_` or `X-Auth-`) in YAML, JSON — escaped " +
			"or not — `key=value` or Go header form, the `=` percent-encoded or not: a kubeconfig " +
			"user's `token:`, an OAuth token response, a token parameter in a URL carried inside " +
			"another. The value runs to the next delimiter and must look generated — a digit, an " +
			"interior capital, or 32 characters — and be neither a placeholder such as `$TOKEN` " +
			"or `YOUR_TOKEN` nor a name in code such as `cfg.APIToken`.",
		pattern:     `(?i)(?:(?:id|refresh|access|auth|bearer|session|api)[-_]?)?token(?:\\?["']?[ \t]*[:=][ \t]*\[?\\?["']?|%3[ad])(?P<secret>[0-9A-Za-z._~+/|\-]{8,}={0,2})|(?i)client[-_]?secret(?:\\?["']?[ \t]*[:=][ \t]*\[?\\?["']?|%3[ad])(?P<secret>[0-9A-Za-z._~+/|\-]{8,}={0,2})`,
		keywords:    []string{"token", "secret"},
		fold:        true,
		before:      isAlnum,
		followedBy:  intoMarkerOrCall,
		valid:       func(_, v string) bool { return credentialLike(v) },
		toDelimiter: true,
	},
	{
		name:  "authorization-header",
		label: "Authorization header",
		recognises: "The credential in an `Authorization:` or `Proxy-Authorization:` header — after " +
			"`Bearer`, `Basic`, `token`, `Bot` or `Negotiate`, or with no scheme when it looks " +
			"generated — as curl, an HTTP dump or a JSON headers object, escaped or not, would " +
			"print it, to the next delimiter. Placeholders are left alone, and so is a word " +
			"such as `forbidden` where a credential would be.",
		pattern:     `(?i)(?:proxy-)?authorization\\?["']?[ \t]*[:=][ \t]*\[?\\?["']?[ \t]*(?:(?:bearer|basic|token|bot|negotiate)[ \t]+(?P<secret>[0-9A-Za-z._~+/|\-]{8,}=*)|(?P<bare>[0-9A-Za-z._~+/|\-]{8,}=*))`,
		keywords:    []string{"authorization"},
		fold:        true,
		followedBy:  intoMarkerOrCall,
		valid:       func(_, v string) bool { return !placeholder(v) && !isSchemeWord(v) },
		toDelimiter: true,
	},
	{
		name:  "bearer-token",
		label: "bearer token",
		recognises: "A value following the word `Bearer` anywhere, to the next delimiter, when it " +
			"looks generated (a digit, an interior capital, or 32 characters) and is not a name " +
			"in code — so a sentence about \"bearer authentication\" or a `TokenSource` is not a " +
			"finding.",
		pattern:     `(?i)bearer[ \t]+(?P<secret>[0-9A-Za-z._~+/|\-]{8,}=*)`,
		keywords:    []string{"bearer"},
		fold:        true,
		followedBy:  intoMarkerOrCall,
		valid:       func(_, v string) bool { return credentialLike(v) },
		toDelimiter: true,
	},
	{
		name:  "url-userinfo",
		label: "credentials in a URL",
		recognises: "The userinfo of `scheme://user:password@host` — a git remote, a proxy URL, a " +
			"database DSN — when it has a password, or a username long and generated enough to " +
			"be a token. `ssh://git@github.com/…` is not a credential and is left alone.",
		pattern:  `[A-Za-z][0-9A-Za-z+.\-]{0,30}://(?P<secret>[^\s/?#@"'<>\x60\\]+(?:@[^\s/?#@"'<>\x60\\]+)*)@`,
		keywords: []string{"://"},
		valid:    func(_, v string) bool { return userinfoLike(v) },
	},
}

var registry = compile(specs)

func compile(in []spec) []*Detector {
	out := make([]*Detector, 0, len(in))
	seen := make(map[string]bool, len(in))
	for i, s := range in {
		if seen[s.name] {
			panic("redact: duplicate detector " + s.name)
		}
		seen[s.name] = true
		d := &Detector{
			Name: s.name, Label: s.label, Recognises: s.recognises,
			re:           regexp.MustCompile(s.pattern),
			keywords:     s.keywords,
			fold:         s.fold,
			before:       s.before,
			after:        s.after,
			followedBy:   s.followedBy,
			valid:        s.valid,
			skipRejected: s.skipRejected,
			toDelimiter:  s.toDelimiter,
			rank:         i,
		}
		for j, n := range d.re.SubexpNames() {
			switch n {
			case "secret":
				d.secret = append(d.secret, j)
			case "kind":
				d.kind = append(d.kind, j)
			case "bare":
				d.bare = append(d.bare, j)
			}
		}
		out = append(out, d)
	}
	return out
}

// --- byte classes and validators ------------------------------------------

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// isWordByte is a byte that would make a shape the tail of a longer word.
func isWordByte(c byte) bool { return isAlnum(c) || c == '_' || c == '-' }

func isUpperOrDigit(c byte) bool { return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' }

func isBase64Byte(c byte) bool { return isAlnum(c) || c == '+' || c == '/' }

// runsIntoMarker rejects a field value that runs straight into a redaction
// marker: what a scanner leaves when it keeps a credential's public lead and
// replaces the rest — "token: sk-ant-oat01-[REDACTED]". The lead on its own
// looks enough like a value to match a field detector a second time, and the
// broker's store scrubs every reason twice.
//
// The marker, in either case, and not any bracket: a credential runs into one
// often enough — a logger's "[truncated]", an index, a Go slice, a terminal's
// colour reset — and is still the credential.
func runsIntoMarker(rest string) bool {
	return len(rest) >= len(Marker) && strings.EqualFold(rest[:len(Marker)], Marker)
}

// intoMarkerOrCall is runsIntoMarker for the field detectors, which also
// reject a value that runs into "(": what stood after the key was a call in
// code — `token = os.Getenv(`, `Authorization: r.Header.Get(` — not a value.
func intoMarkerOrCall(rest string) bool {
	return strings.HasPrefix(rest, "(") || runsIntoMarker(rest)
}

// sameChar reports whether v is one character repeated, separators aside:
// "***", "xxxxxxxx".
func sameChar(body string) bool {
	var first byte
	n := 0
	for i := 0; i < len(body); i++ {
		switch c := body[i]; {
		case c == '_' || c == '-' || c == '.':
		case n == 0:
			first, n = c, 1
		case c != first:
			return false
		default:
			n++
		}
	}
	return n > 0
}

// looksGenerated reports whether v has what a generated credential always has
// and a word or a snake_case identifier does not: a digit, or a capital after
// the first character.
func looksGenerated(v string) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c >= '0' && c <= '9' || i > 0 && c >= 'A' && c <= 'Z' {
			return true
		}
	}
	return false
}

func bodyLooksGenerated(kind, secret string) bool {
	return looksGenerated(strings.TrimPrefix(secret, kind))
}

// githubLongForm admits the dotted long form and nothing the classic detector
// already describes: the body must contain the separators that make it long
// form, and look generated.
func githubLongForm(kind, secret string) bool {
	body := strings.TrimPrefix(secret, kind)
	return strings.ContainsAny(body, "_.") && looksGenerated(body)
}

// credentialLike is the bar a value must clear when the only evidence that it
// is a credential is the word in front of it.
func credentialLike(v string) bool {
	if len(v) < MinLen || placeholder(v) || identifierLike(v) {
		return false
	}
	if looksGenerated(v) {
		return true
	}
	// A long run of one case and no digits is still a credential once it is
	// longer than any word: 32 characters of [a-z] is not prose.
	return len(v) >= 32
}

// placeholder reports whether v stands in for a credential rather than being
// one: a template, a format verb, a redaction marker, a credential's prefix
// followed by one repeated character, or an environment variable's name.
func placeholder(v string) bool {
	return template(v) || isEnvName(v) || repeatedTail(v)
}

// template reports whether v is a placeholder in a form that templates, format
// strings and redactors write — "${DB_PASSWORD}", "{{.Token}}", "<token>",
// "$PASSWORD", "%s", "***", "[redacted]" — and nothing broader. It is all a
// URL's password is checked against: a generated password may begin with any
// character, "%21…" is a percent-encoded "!", and one that looks like an
// environment variable's name is still what the URL sends.
func template(v string) bool {
	if v == "" || strings.Contains(strings.ToLower(v), "redacted") || sameChar(v) {
		return true
	}
	switch {
	case strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}"),
		strings.HasPrefix(v, "{{") && strings.HasSuffix(v, "}}"),
		strings.HasPrefix(v, "<") && strings.HasSuffix(v, ">"),
		len(v) == 2 && v[0] == '%' && isLetter(v[1]):
		return true
	case v[0] == '$':
		return isShellName(v[1:])
	}
	return false
}

// repeatedTail reports a value that ends in eight or more of one character
// making up at least half of it, separators aside — documentation's stand-in
// for a credential nobody should print: "ghp_xxxx…", "sk-ant-api03-XXXX…". A
// prefix detector checks the body after its prefix, and a field detector the
// whole value, which is how "GITHUB_TOKEN=ghp_xxxx…" stays a placeholder.
func repeatedTail(v string) bool {
	var last byte
	run, total := 0, 0
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '_' || c == '-' || c == '.' {
			continue
		}
		total++
		if c == last {
			run++
		} else {
			last, run = c, 1
		}
	}
	return run >= 8 && 2*run >= total
}

// isShellName reports a shell variable's name — what is left of "$PASSWORD"
// or "$password" when it reached a log unexpanded: a letter or underscore,
// then letters, digits and underscores, all in one case. A mixed-case run
// after a "$" — "$ecretP4ssw0rd" — is a password that happens to start with
// one.
func isShellName(v string) bool {
	if v == "" || v[0] >= '0' && v[0] <= '9' {
		return false
	}
	upper, lower := false, false
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= '0' && c <= '9' || c == '_':
		default:
			return false
		}
	}
	return !(upper && lower)
}

func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// identifierLike reports whether v reads as a name in code rather than a
// value: a dotted path of words with no digit ("cfg.APIToken",
// "r.Header.Get"), or a camelCase or PascalCase identifier ("TokenSource",
// "ExpiredTokenError", "accessToken"). A generated credential that has no
// digit is also unlikely to fall into words.
func identifierLike(v string) bool {
	dots := 0
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c == '.':
			if i == 0 || i == len(v)-1 || v[i-1] == '.' {
				return false
			}
			dots++
		case !isLetter(c):
			return false
		}
	}
	return dots > 0 || camelCase(v)
}

// camelCase reports letters that fall into words: a lower-case second letter,
// and every capital after the first letter followed by a lower-case one.
func camelCase(v string) bool {
	if len(v) < 2 || v[1] < 'a' || v[1] > 'z' {
		return false
	}
	humps := 0
	for i := 1; i < len(v); i++ {
		if c := v[i]; c >= 'A' && c <= 'Z' {
			if i+1 == len(v) || v[i+1] < 'a' || v[i+1] > 'z' {
				return false
			}
			humps++
		}
	}
	return humps > 0
}

// isEnvName reports a value shaped like YOUR_TOKEN or GITHUB_TOKEN: a name
// being referred to, not a value being disclosed.
func isEnvName(v string) bool {
	underscore, letter := false, false
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c == '_':
			underscore = true
		case c >= 'A' && c <= 'Z':
			letter = true
		case c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return underscore && letter
}

// isSchemeWord is an Authorization scheme standing where its credential
// should be, as in a bare "Authorization: Negotiate".
func isSchemeWord(v string) bool {
	switch strings.ToLower(v) {
	case "bearer", "basic", "token", "negotiate", "digest":
		return true
	}
	return false
}

// userinfoLike reports whether a URL's userinfo carries a credential: any real
// password, or a username long and generated enough to be a token presented
// as one (https://<token>@github.com).
func userinfoLike(u string) bool {
	user, pass, hasPass := strings.Cut(u, ":")
	if hasPass {
		return !template(pass)
	}
	return len(user) >= 20 && credentialLike(user)
}
