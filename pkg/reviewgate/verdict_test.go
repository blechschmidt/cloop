package reviewgate

import (
	"errors"
	"strings"
	"testing"
)

func TestParseVerdict(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		approved bool
		findings int
		first    string // severity of the first finding
	}{
		{"plain approve", `{"verdict":"approve","summary":"fine","findings":[]}`, true, 0, ""},
		{"request changes", `{"verdict":"request_changes","summary":"bug","findings":[{"severity":"major","file":"a.go","line":3,"title":"nil deref"}]}`, false, 1, "major"},
		{"fenced with prose", "Let me look.\n```json\n{\"verdict\": \"approve\", \"summary\": \"ok\"}\n```\nDone.", true, 0, ""},
		{"last object wins", `thinking {"note": "x"} then {"verdict":"approve","summary":"ok"}`, true, 0, ""},
		{"loose line and severities sorted", `{"verdict":"request_changes","findings":[{"severity":"nit","title":"name"},{"severity":"critical","title":"sql injection","line":"12"}]}`, false, 2, "blocker"},
		{"approve contradicted by a blocker", `{"verdict":"approve","findings":[{"severity":"blocker","title":"leaks the token"}]}`, false, 1, "blocker"},
		{"approve with only nits stays approved", `{"verdict":"approved","findings":[{"severity":"nit","title":"typo"},{"severity":"minor","title":"naming"}]}`, true, 2, "minor"},
		{"unknown severity counts as major", `{"verdict":"approve","findings":[{"severity":"weird","title":"hm"}]}`, false, 1, "major"},
		{"string finding", `{"verdict":"reject","findings":["missing tests"]}`, false, 1, "major"},
		{"prose fallback", "Review done.\n**Verdict:** approve\n", true, 0, ""},
		{"prose fallback reject", "VERDICT: REQUEST_CHANGES\nbecause", false, 0, ""},
		{"braces inside strings", `{"verdict":"request_changes","summary":"uses { and } in text","findings":[{"severity":"major","title":"x {y}"}]}`, false, 1, "major"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, err := ParseVerdict(c.in)
			if err != nil {
				t.Fatalf("ParseVerdict: %v", err)
			}
			if v.Approved != c.approved {
				t.Errorf("approved = %v, want %v", v.Approved, c.approved)
			}
			if len(v.Findings) != c.findings {
				t.Fatalf("findings = %d, want %d: %+v", len(v.Findings), c.findings, v.Findings)
			}
			if c.first != "" && v.Findings[0].Severity != c.first {
				t.Errorf("first severity = %q, want %q", v.Findings[0].Severity, c.first)
			}
		})
	}
}

func TestParseVerdictFailsClosed(t *testing.T) {
	for _, in := range []string{
		"",
		"Looks good to me!",
		`{"summary":"no verdict field"}`,
		`{"verdict":"maybe"}`,
		`{"verdict": "approve"`, // unterminated
	} {
		if v, err := ParseVerdict(in); !errors.Is(err, ErrNoVerdict) {
			t.Errorf("ParseVerdict(%q) = %+v, %v; want ErrNoVerdict", in, v, err)
		}
	}
}

func TestParseVerdictLineNumbers(t *testing.T) {
	v, err := ParseVerdict(`{"verdict":"request_changes","findings":[
		{"severity":"major","title":"a","line":12},
		{"severity":"major","title":"b","line":"7"},
		{"severity":"major","title":"c","line":-4},
		{"severity":"major","title":"d","line":"x"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	got := []int{v.Findings[0].Line, v.Findings[1].Line, v.Findings[2].Line, v.Findings[3].Line}
	want := []int{12, 7, 0, 0}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("finding %d line = %d, want %d", i, got[i], want[i])
		}
	}
}

func TestParseVerdictBoundsFindings(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"verdict":"request_changes","findings":[`)
	for i := 0; i < 50; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"severity":"minor","title":"f"}`)
	}
	b.WriteString(`]}`)
	v, err := ParseVerdict(b.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Findings) != 20 {
		t.Errorf("findings = %d, want the cap of 20", len(v.Findings))
	}
}
