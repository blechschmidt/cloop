package knowledge

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/redact"
)

// cleanName checks a source's name: 1 to MaxNameRunes characters, no control
// characters, trimmed.
func cleanName(name string) (string, error) {
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return "", invalid("a source needs a name")
	case !utf8.ValidString(name):
		return "", invalid("a source's name must be UTF-8 text")
	case utf8.RuneCountInString(name) > MaxNameRunes:
		return "", invalid("a source's name is at most %d characters", MaxNameRunes)
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", invalid("a source's name may not hold control characters")
		}
	}
	return name, nil
}

// credentialKeyFragments and credentialKeyWords identify a configuration key
// that names a credential. Fragments match anywhere in the key with its case
// folded and its separators dropped — "api-key", "API_KEY" and "apiKey" are
// all "apikey" — and words only as a whole word of it, split at separators and
// at case changes, since "token" is a credential and "tokens" a count. A bare
// "key" is neither — "space_key" and "project_key" are what a connector is
// configured with — so only the credential kinds of key are named; a value
// shaped like a credential is caught by redact.Find whatever its key.
var (
	credentialKeyFragments = []string{
		"secret", "password", "passwd", "passphrase", "credential", "authorization",
		"apikey", "privatekey", "accesskey", "signingkey", "clientkey", "cookie",
	}
	credentialKeyWords = []string{"token", "pat", "bearer", "pass", "pwd"}
)

// isCredentialKey reports whether a configuration key names a credential.
func isCredentialKey(key string) bool {
	var compact strings.Builder
	for _, r := range strings.ToLower(key) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			compact.WriteRune(r)
		}
	}
	for _, f := range credentialKeyFragments {
		if strings.Contains(compact.String(), f) {
			return true
		}
	}
	for _, w := range keyWords(key) {
		for _, want := range credentialKeyWords {
			if w == want {
				return true
			}
		}
	}
	return false
}

// keyWords splits a key into lower-case words at every character that is not
// a letter or digit, and where a lower-case letter or digit is followed by an
// upper-case one ("apiToken" is "api", "token").
func keyWords(key string) []string {
	var (
		words []string
		cur   []rune
		prev  rune
	)
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	for _, r := range key {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
		case unicode.IsUpper(r) && (unicode.IsLower(prev) || unicode.IsDigit(prev)):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
		prev = r
	}
	flush()
	return words
}

// cleanConfig checks a source's configuration before its connector sees it: a
// JSON object of at most MaxConfigBytes that names no credential and holds
// nothing shaped like one. It returns the object compacted.
//
// A source's configuration is stored in the clear, shown to the people who
// manage the source, written into the audit trail and copied into every
// backup — so it must never be where a token ends up. The refusal points at
// the place that is: the secret store, named by the source's secret
// reference.
func cleanConfig(raw json.RawMessage) (json.RawMessage, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = json.RawMessage("{}")
	}
	if len(raw) > MaxConfigBytes {
		return nil, invalid("a source's configuration is at most %d bytes", MaxConfigBytes)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return nil, invalid("a source's configuration must be a JSON object")
	}
	if key, ok := credentialKeyIn(obj); ok {
		return nil, invalid("the configuration key %q names a credential; store the credential as a secret "+
			"and name it in the source's secret reference instead", key)
	}
	// The decoded values, not the raw text: JSON can spell a credential with
	// escapes ("ghp\u005f…") that no pattern over the raw bytes would see.
	for _, text := range append(stringsIn(obj), string(raw)) {
		if found := redact.Find(text); len(found) > 0 {
			what := strings.TrimSpace(found[0].Label)
			if what == "" {
				what = "a credential"
			}
			return nil, invalid("the configuration holds something shaped like %s; store it as a secret and "+
				"name it in the source's secret reference instead", what)
		}
	}
	var out bytes.Buffer
	if err := json.Compact(&out, raw); err != nil {
		return nil, invalid("a source's configuration must be a JSON object")
	}
	return out.Bytes(), nil
}

// stringsIn returns every string in v, keys included.
func stringsIn(v any) []string {
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			out = append(out, t)
		case map[string]any:
			for k, e := range t {
				out = append(out, k)
				walk(e)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	return out
}

// credentialKeyIn finds a credential-naming key anywhere in v.
func credentialKeyIn(v any) (string, bool) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if isCredentialKey(k) {
				return k, true
			}
			if key, ok := credentialKeyIn(t[k]); ok {
				return key, true
			}
		}
	case []any:
		for _, e := range t {
			if key, ok := credentialKeyIn(e); ok {
				return key, true
			}
		}
	}
	return "", false
}

// cleanSecretRef checks a secret reference's shape: empty, "name", or
// "name#KEY", with no spaces or control characters.
func cleanSecretRef(ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", nil
	}
	if len(ref) > MaxSecretRefBytes {
		return "", invalid("a secret reference is at most %d bytes", MaxSecretRefBytes)
	}
	for _, r := range ref {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", invalid("a secret reference is a secret's name, or name#KEY, without spaces")
		}
	}
	name, key, keyed := strings.Cut(ref, "#")
	if name == "" || (keyed && (key == "" || strings.Contains(key, "#"))) {
		return "", invalid("a secret reference is a secret's name, or name#KEY")
	}
	return ref, nil
}

// cleanFilter checks a binding's narrowing: at most MaxBindingSpaces space
// keys, each a short printable token, sorted and without duplicates; and a
// query of at most MaxBindingQueryBytes.
func cleanFilter(f Filter) (Filter, error) {
	var out Filter
	seen := map[string]bool{}
	for _, s := range f.Spaces {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		if len(s) > MaxSpaceKeyBytes {
			return out, invalid("a space key is at most %d bytes", MaxSpaceKeyBytes)
		}
		for _, r := range s {
			if unicode.IsSpace(r) || unicode.IsControl(r) {
				return out, invalid("a space key may not hold spaces or control characters: %q", s)
			}
		}
		seen[s] = true
		out.Spaces = append(out.Spaces, s)
	}
	if len(out.Spaces) > MaxBindingSpaces {
		return out, invalid("a binding narrows to at most %d spaces", MaxBindingSpaces)
	}
	sort.Strings(out.Spaces)
	out.Query = strings.TrimSpace(f.Query)
	if len(out.Query) > MaxBindingQueryBytes {
		return out, invalid("a binding's query is at most %d bytes", MaxBindingQueryBytes)
	}
	if !utf8.ValidString(out.Query) {
		return out, invalid("a binding's query must be UTF-8 text")
	}
	for _, r := range out.Query {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return out, invalid("a binding's query may not hold control characters")
		}
	}
	return out, nil
}
