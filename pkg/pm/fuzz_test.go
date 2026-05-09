package pm

import "testing"

// FuzzParseDeadline feeds arbitrary strings into ParseDeadline. The parser
// accepts three families of input (RFC3339, date-only, relative <n><unit>);
// any other input must produce an error rather than a panic. Historically
// the relative-unit branch sliced the last byte of the string without a
// rune-boundary check — we want to surface that and any future regressions.
func FuzzParseDeadline(f *testing.F) {
	// Real-world fixtures derived from cloop's docs and tests.
	seeds := []string{
		"",
		" ",
		"2h",
		"30m",
		"3d",
		"1w",
		"2025-12-31",
		"2025-12-31T23:59:00Z",
		"2025-12-31T23:59:00+01:00",
		// Pathological inputs.
		"0h",
		"-5d",
		"99999999999999999999d",
		"abc",
		"123",
		"d",
		"m",
		"123x",
		// Multibyte trailing rune — the byte-slice approach in ParseDeadline
		// will produce an invalid UTF-8 unit if not handled, but must not
		// panic.
		"5ä",
		"日",
		// Embedded NULs and control bytes.
		"\x00",
		"2h\x00",
		"\x00\x01\x02",
		// Whitespace edge cases.
		"   2h   ",
		"\t3d\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		// ParseDeadline may legitimately return an error; we only assert that
		// it never panics and never returns a zero time with a nil error.
		ts, err := ParseDeadline(s)
		if err == nil && ts.IsZero() {
			t.Fatalf("ParseDeadline(%q) returned zero time with nil error", s)
		}
	})
}
