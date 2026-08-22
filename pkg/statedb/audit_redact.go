// Redaction for audit payloads (Task 20167).
//
// The audit trail is the one table an operator is expected to export to a
// SIEM, hand to an auditor, and keep long after the credentials it mentions
// have been rotated. Secret material must therefore never enter it, and
// "never" has to be a property of the writer rather than a convention every
// call site is trusted to remember: a single emitter that forgets, once,
// writes a credential into an append-only hash-chained table that cannot be
// edited afterwards without breaking the chain.
//
// So redaction runs centrally, in MarshalAuditPayload, over every payload
// regardless of which emitter produced it. Two shapes are handled:
//
//   - Structured payloads (maps, structs, slices): any value whose *key*
//     names a credential is replaced with redactedMarker. The key survives,
//     so the trail still records that a token was involved and what it was
//     called — which is the forensically useful half — without recording
//     what it was.
//   - The config blob: pkg/config serialises the whole of .cloop/config.yaml
//     into a single string, api keys included, and SetConfigBlob passes it
//     here. A YAML-aware line pass redacts the values of sensitive keys.
//
// This deliberately makes `cloop events replay` unable to reconstruct API
// keys from the journal. That is the correct trade for a compliance record:
// a log that can rebuild your secrets is a second copy of your secrets.
//
// The scrub is skipped entirely when a payload contains no sensitive-looking
// key, so the hot paths (task upserts, step appends) pay one substring scan
// rather than a JSON round trip.

package statedb

import (
	"encoding/json"
	"strings"
)

// redactedMarker replaces any value that a key identifies as a credential.
// Distinctive on purpose: an auditor grepping an export can tell the
// difference between "this field was empty" and "this field was withheld".
const redactedMarker = "[redacted]"

// sensitiveSubstrings are matched anywhere inside a lowercased key. They are
// long enough to be unambiguous: no ordinary field name contains "passphrase"
// or "kubeconfig" without being one.
//
// "key" is deliberately absent. As a substring it swallows the structural
// fields this codebase is full of — cache_key, owner_key, visibility_key,
// sort_key — and redacting those turns the trail into a wall of markers. The
// narrower apikey/api_key/private_key forms cover the real cases.
var sensitiveSubstrings = []string{
	"apikey",
	"api_key",
	"secret",
	"password",
	"passphrase",
	"credential",
	"authorization",
	"private_key",
	"privatekey",
	"session_key",
	"kubeconfig",
	"ciphertext",
	"sealed",
}

// sensitiveWords must match a whole word within the key rather than a
// substring, because they are short enough to occur inside unrelated names.
//
// The important case is "token". As a substring it also matches
// total_input_tokens and total_output_tokens — the per-run cost counters,
// which are not credentials and which an auditor reconciling spend needs to
// be able to read. The distinction that resolves it is grammatical and holds
// across the codebase: the singular names a credential ("the enrollment
// token"), the plural names a quantity ("1 200 tokens used"). So "token"
// matches and "tokens" does not.
//
// The same reasoning applies to "pat": a credential when it stands alone
// (github_pat), noise when it does not (path, pattern, separator).
var sensitiveWords = []string{
	"token",
	"pat",
	"bearer",
}

// isSensitiveKey reports whether a field name identifies credential material.
func isSensitiveKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	if k == "" {
		return false
	}
	for _, frag := range sensitiveSubstrings {
		if strings.Contains(k, frag) {
			return true
		}
	}
	words := splitKeyWords(key)
	for _, w := range words {
		for _, want := range sensitiveWords {
			if w == want {
				return true
			}
		}
	}
	return false
}

// splitKeyWords breaks a field name into lowercase words on the separators
// field names actually use, and on camelCase humps so that a Go-syntax
// rendering (`%+v`, which prints exported field names) is analysed the same
// way its JSON tag would be: BearerToken and bearer_token must both match.
func splitKeyWords(key string) []string {
	var b strings.Builder
	runes := []rune(key)
	for i, r := range runes {
		if i > 0 && r >= 'A' && r <= 'Z' {
			prev := runes[i-1]
			// Insert a break at a lower→upper hump (bearerToken) and at the
			// tail of an acronym run (APIKey → API|Key).
			if (prev >= 'a' && prev <= 'z') || (prev >= '0' && prev <= '9') ||
				(i+1 < len(runes) && runes[i+1] >= 'a' && runes[i+1] <= 'z') {
				b.WriteByte('_')
			}
		}
		b.WriteRune(r)
	}
	return strings.FieldsFunc(strings.ToLower(b.String()), func(r rune) bool {
		return r == '_' || r == '-' || r == '.' || r == ' ' || r == '/' || r == ':'
	})
}

// mightContainSecrets is the cheap pre-filter that keeps the common case off
// the JSON round trip. It scans the already-marshalled payload rather than
// the original value, so it costs one lowercase pass over a string we had to
// produce anyway.
//
// It errs towards true: a false positive costs one wasted round trip, while a
// false negative would write a credential into an append-only table. The
// short words are therefore pre-filtered as bare substrings and left to
// isSensitiveKey to adjudicate properly.
func mightContainSecrets(blob string) bool {
	lower := strings.ToLower(blob)
	for _, frag := range sensitiveSubstrings {
		if strings.Contains(lower, frag) {
			return true
		}
	}
	for _, w := range sensitiveWords {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

// redactValue walks a decoded JSON value, replacing every value reached
// through a sensitive key. Returns the scrubbed value.
func redactValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if isSensitiveKey(k) {
				// Preserve the shape of absent values: redacting a null into
				// "[redacted]" would claim a credential was present when the
				// field was simply unset.
				if val == nil {
					out[k] = nil
					continue
				}
				if s, ok := val.(string); ok && s == "" {
					out[k] = ""
					continue
				}
				out[k] = redactedMarker
				continue
			}
			out[k] = redactValue(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = redactValue(val)
		}
		return out
	default:
		return v
	}
}

// redactJSONBlob scrubs an already-marshalled JSON payload. On any decode or
// re-encode failure it returns the redactedMarker rather than the original:
// failing closed is the only safe direction when the reason we are here is
// that the payload looked like it held a credential.
func redactJSONBlob(blob string) string {
	if blob == "" {
		return blob
	}
	if !mightContainSecrets(blob) {
		return blob
	}
	var decoded any
	if err := json.Unmarshal([]byte(blob), &decoded); err != nil {
		return `"` + redactedMarker + `"`
	}
	out, err := json.Marshal(redactValue(decoded))
	if err != nil {
		return `"` + redactedMarker + `"`
	}
	return string(out)
}

// redactYAMLSecrets redacts the values of sensitive keys in a YAML document,
// line by line.
//
// A line pass rather than a real YAML round trip is deliberate: the blob is
// stored so an operator can see what the config looked like at a point in
// time, and re-serialising would reorder keys and drop comments, making two
// consecutive audit rows differ for reasons that have nothing to do with the
// change being recorded. Indentation and ordering are preserved exactly;
// only the scalar to the right of a sensitive key is replaced.
//
// Block scalars (`api_key: |`) are handled by redacting the introducer and
// every more-indented line beneath it, so a multi-line credential cannot slip
// through by virtue of not being on the key's own line.
func redactYAMLSecrets(blob string) string {
	if blob == "" {
		return blob
	}
	lines := strings.Split(blob, "\n")
	out := make([]string, 0, len(lines))

	// When >= 0, we are inside a redacted block scalar and are dropping every
	// line indented deeper than this.
	blockIndent := -1

	for _, line := range lines {
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		trimmed := strings.TrimSpace(line)

		if blockIndent >= 0 {
			if trimmed != "" && indent > blockIndent {
				continue // swallowed: part of the redacted block
			}
			blockIndent = -1
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			out = append(out, line)
			continue
		}

		// Split on the first colon; anything without one is not a mapping
		// entry and cannot be carrying a keyed secret.
		colon := strings.Index(trimmed, ":")
		if colon < 0 {
			out = append(out, line)
			continue
		}
		key := strings.TrimSpace(strings.TrimPrefix(trimmed[:colon], "- "))
		if !isSensitiveKey(key) {
			out = append(out, line)
			continue
		}

		value := strings.TrimSpace(trimmed[colon+1:])
		prefix := line[:len(line)-len(strings.TrimLeft(line, " \t"))] +
			strings.TrimSuffix(trimmed[:colon+1], "")

		switch {
		case value == "":
			// `secret:` with the value on following lines, or an empty
			// mapping. Nothing to redact on this line; keep it as-is so an
			// empty setting still reads as empty.
			out = append(out, line)
		case strings.HasPrefix(value, "|") || strings.HasPrefix(value, ">"):
			out = append(out, prefix+" "+redactedMarker)
			blockIndent = indent
		default:
			out = append(out, prefix+" "+redactedMarker)
		}
	}
	return strings.Join(out, "\n")
}
