package knowledge

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// minPrefixRunes is the shortest word a search may match as a prefix.
const minPrefixRunes = 3

// MatchExpression turns what a person typed into an FTS5 query.
//
// FTS5's query language has operators, column filters and a syntax a stray
// quote breaks, and none of that should be reachable from a search box: text
// is not a program. So the query is read as words — and "quoted phrases",
// kept together — each of which becomes a quoted FTS5 string, joined with OR.
// BM25 then ranks a chunk holding more of the words, and rarer ones, first. A
// word of at least minPrefixRunes characters may end in '*' to match as a
// prefix ("deploy*"); a shorter one matches as itself, since "a*" would walk
// a large part of the index. Characters FTS5 would read as syntax never leave
// a quoted string, and a word with no letter or digit is dropped, since the
// tokenizer would find nothing in it.
//
// ErrInvalid reports a query over MaxQueryBytes or with nothing to search for.
func MatchExpression(query string) (string, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return "", invalid("a search needs a query")
	}
	if len(query) > MaxQueryBytes {
		return "", invalid("a search query is at most %d bytes", MaxQueryBytes)
	}
	if !utf8.ValidString(query) {
		return "", invalid("a search query must be UTF-8 text")
	}
	var (
		terms []string
		seen  = map[string]bool{}
	)
	add := func(text string, prefix bool) {
		if len(terms) == MaxQueryTerms || !hasWordRune(text) {
			return
		}
		term := `"` + strings.ReplaceAll(text, `"`, `""`) + `"`
		if prefix {
			term += "*"
		}
		key := strings.ToLower(term)
		if seen[key] {
			return
		}
		seen[key] = true
		terms = append(terms, term)
	}
	rest := query
	for rest != "" {
		rest = strings.TrimLeftFunc(rest, unicode.IsSpace)
		if rest == "" {
			break
		}
		if rest[0] == '"' {
			end := strings.IndexByte(rest[1:], '"')
			if end < 0 {
				// An unclosed quote: the rest is the phrase.
				add(strings.TrimSpace(rest[1:]), false)
				break
			}
			add(strings.TrimSpace(rest[1:1+end]), false)
			rest = rest[end+2:]
			continue
		}
		end := strings.IndexFunc(rest, unicode.IsSpace)
		word := rest
		if end >= 0 {
			word, rest = rest[:end], rest[end:]
		} else {
			rest = ""
		}
		word = strings.ReplaceAll(word, `"`, "")
		stem := strings.TrimRight(word, "*")
		add(stem, stem != word && utf8.RuneCountInString(stem) >= minPrefixRunes)
	}
	if len(terms) == 0 {
		return "", invalid("the query has no words to search for")
	}
	return strings.Join(terms, " OR "), nil
}

// hasWordRune reports whether s holds a letter or digit — something the
// unicode61 tokenizer indexes.
func hasWordRune(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return true
		}
	}
	return false
}
