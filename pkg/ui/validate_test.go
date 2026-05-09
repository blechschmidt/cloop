package ui

// Regression tests for the query-parameter validation helpers.
//
// The UI is a long-lived daemon, so any handler that splits, lowercases, or
// stores a user-supplied query value without bounds gives an authenticated
// client a memory amplification primitive. These helpers cap inputs at the
// edge; the tests below pin the exact rejection behaviour so future changes
// can't quietly raise (or remove) a cap.

import (
	"strings"
	"testing"
)

func TestBoundedQueryString(t *testing.T) {
	cases := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{"empty stays empty", "", 10, ""},
		{"trims whitespace", "  hello  ", 10, "hello"},
		{"under cap kept", "abc", 10, "abc"},
		{"at cap kept", "abcdefghij", 10, "abcdefghij"},
		{"over cap dropped to empty", "abcdefghijk", 10, ""},
		{"whitespace counts before trim", "    a    ", 4, "a"}, // trim then check len
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := boundedQueryString(c.in, c.max)
			if got != c.want {
				t.Errorf("boundedQueryString(%q, %d) = %q, want %q", c.in, c.max, got, c.want)
			}
		})
	}
}

// TestBoundedQueryString_RejectsHugeInput confirms that a megabyte-scale input
// (the kind a malicious client would send to trigger a full-string ToLower or
// Contains scan in every iteration) is rejected at the boundary instead of
// flowing into handler logic.
func TestBoundedQueryString_RejectsHugeInput(t *testing.T) {
	huge := strings.Repeat("a", 1<<20) // 1 MiB
	if got := boundedQueryString(huge, maxQueryStringLen); got != "" {
		t.Fatalf("expected oversize input to clamp to empty, got %d-byte string", len(got))
	}
}

func TestParseCSVList(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		maxItems int
		maxLen   int
		want     []string
	}{
		{"empty returns nil", "", 5, 10, nil},
		{"single item", "a", 5, 10, []string{"a"}},
		{"three items", "a,b,c", 5, 10, []string{"a", "b", "c"}},
		{"trims spaces", " a , b ,c", 5, 10, []string{"a", "b", "c"}},
		{"empty entries skipped", "a,,b,,", 5, 10, []string{"a", "b"}},
		{"oversized entry dropped", "ok,toolongtoolong,also", 5, 6, []string{"ok", "also"}},
		{"all oversized returns nil", "longlonglong,evenlonger", 5, 4, nil},
		{"truncates at maxItems", "a,b,c,d,e,f,g,h", 3, 10, []string{"a", "b", "c"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseCSVList(c.in, c.maxItems, c.maxLen)
			if len(got) != len(c.want) {
				t.Fatalf("parseCSVList(%q,%d,%d) len=%d want=%d (%v vs %v)",
					c.in, c.maxItems, c.maxLen, len(got), len(c.want), got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("item %d = %q, want %q", i, got[i], c.want[i])
				}
			}
		})
	}
}

// TestParseCSVList_BoundsAllocation pins the contract that even an attacker
// blasting a million-comma payload into ?tags= cannot force the handler to
// allocate a million-element slice — the cap is applied before any per-item
// work runs.
func TestParseCSVList_BoundsAllocation(t *testing.T) {
	huge := strings.Repeat("a,", 1_000_000) // 1M comma-separated entries
	got := parseCSVList(huge, maxCSVItems, maxCSVItemLen)
	if len(got) > maxCSVItems {
		t.Fatalf("parseCSVList exceeded maxCSVItems cap: got %d > %d", len(got), maxCSVItems)
	}
}

func TestParsePriorityFilter(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"1", 1},
		{"2", 2},
		{"3", 3},
		{"4", 4},
		{"0", 0},      // out of range
		{"5", 0},      // out of range
		{"-1", 0},     // negative
		{"99999", 0},  // out of range — was the silent-overflow bug
		{"abc", 0},    // non-numeric
		{"1.5", 0},    // not an integer
	}
	for _, c := range cases {
		got := parsePriorityFilter(c.in)
		if got != c.want {
			t.Errorf("parsePriorityFilter(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestParsePositiveID(t *testing.T) {
	cases := []struct {
		in     string
		wantID int
		wantOK bool
	}{
		{"", 0, false},
		{"1", 1, true},
		{"42", 42, true},
		{"0", 0, false},      // zero rejected (was a gap in handleKBDelete)
		{"-3", 0, false},     // negative rejected
		{"abc", 0, false},    // non-numeric
		{"  7  ", 0, false},  // whitespace not allowed (path values are pre-trimmed)
	}
	for _, c := range cases {
		gotID, gotOK := parsePositiveID(c.in)
		if gotID != c.wantID || gotOK != c.wantOK {
			t.Errorf("parsePositiveID(%q) = (%d, %t), want (%d, %t)",
				c.in, gotID, gotOK, c.wantID, c.wantOK)
		}
	}
}
