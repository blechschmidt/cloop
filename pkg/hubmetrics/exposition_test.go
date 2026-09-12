package hubmetrics

// A strict reader for the Prometheus text exposition format, used by the tests
// to assert that what the registry renders is actually parseable rather than
// merely containing the substrings we expected.
//
// # Why this is hand-written
//
// The authoritative parser is prometheus/common/expfmt, and using it would be
// the obvious move. It is not in go.mod, and pulling it in would add
// prometheus/common, prometheus/client_model, protobuf and goautoneg to a
// package whose doc comment commits it to being stdlib-only — four modules of
// govulncheck surface for a test helper, on a hub whose security story is that
// its dependency list is short. So the format is implemented here instead,
// narrowly: only the constructs the registry can actually emit, and strict
// about all of them.
//
// The checks that earn their keep are the structural ones a substring
// assertion cannot express:
//
//   - No family declares HELP or TYPE twice. This is what catches the
//     failure mode of exposing a metric from two places at once — the exact
//     hazard of moving the hand-built quota block into the registry while
//     the registry also declares those families.
//   - No (name, labelset) pair appears twice. A duplicate series makes a real
//     scraper reject the whole payload.
//   - Histogram buckets ascend, and le="+Inf" equals _count. A histogram that
//     violates either renders graphs that are wrong rather than absent.

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type sample struct {
	name   string
	labels map[string]string
	value  float64
}

// key renders a sample's identity the way a scraper sees it: name plus the
// full label set, sorted so two spellings of the same series collide.
func (s sample) key() string {
	names := make([]string, 0, len(s.labels))
	for k := range s.labels {
		names = append(names, k)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString(s.name)
	b.WriteByte('{')
	for i, n := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%s=%q", n, s.labels[n])
	}
	b.WriteByte('}')
	return b.String()
}

type family struct {
	name    string
	typ     string
	help    string
	samples []sample
}

// parseExposition validates text and returns the samples it declares. Any
// violation of the format fails the test.
func parseExposition(t *testing.T, text string) map[string]*family {
	t.Helper()

	families := map[string]*family{}
	seenHelp := map[string]bool{}
	seenType := map[string]bool{}
	seenSeries := map[string]int{}

	famFor := func(name string) *family {
		if f, ok := families[name]; ok {
			return f
		}
		f := &family{name: name}
		families[name] = f
		return f
	}

	for i, line := range strings.Split(text, "\n") {
		lineNo := i + 1
		if strings.TrimSpace(line) == "" {
			continue
		}

		if strings.HasPrefix(line, "#") {
			parseComment(t, line, lineNo, famFor, seenHelp, seenType)
			continue
		}

		s := parseSample(t, line, lineNo)
		if s == nil {
			continue
		}
		if prev, dup := seenSeries[s.key()]; dup {
			t.Errorf("line %d: duplicate series %s (first seen on line %d).\n"+
				"A scraper rejects a payload that reports the same series twice.",
				lineNo, s.key(), prev)
		}
		seenSeries[s.key()] = lineNo
		famFor(familyNameOf(s.name, families)).samples = append(
			famFor(familyNameOf(s.name, families)).samples, *s)
	}

	for _, f := range families {
		if f.typ == "histogram" {
			checkHistogram(t, f)
		}
	}
	return families
}

func parseComment(t *testing.T, line string, lineNo int, famFor func(string) *family, seenHelp, seenType map[string]bool) {
	t.Helper()

	fields := strings.SplitN(line, " ", 4)
	if len(fields) < 3 {
		t.Errorf("line %d: malformed comment %q", lineNo, line)
		return
	}
	switch fields[1] {
	case "HELP":
		name := fields[2]
		if seenHelp[name] {
			t.Errorf("line %d: %s declares HELP twice — the family is being "+
				"exported from two places at once", lineNo, name)
		}
		seenHelp[name] = true
		f := famFor(name)
		if len(fields) == 4 {
			f.help = fields[3]
			if strings.Contains(f.help, "\n") {
				t.Errorf("line %d: %s HELP contains a raw newline", lineNo, name)
			}
		}
		if f.help == "" && len(fields) == 4 {
			t.Errorf("line %d: %s declares empty HELP", lineNo, name)
		}
	case "TYPE":
		if len(fields) < 4 {
			t.Errorf("line %d: malformed TYPE %q", lineNo, line)
			return
		}
		name, typ := fields[2], strings.TrimSpace(fields[3])
		if seenType[name] {
			t.Errorf("line %d: %s declares TYPE twice", lineNo, name)
		}
		seenType[name] = true
		switch typ {
		case "counter", "gauge", "histogram", "summary", "untyped":
		default:
			t.Errorf("line %d: %s has unknown type %q", lineNo, name, typ)
		}
		famFor(name).typ = typ
	}
}

// parseSample reads one `name{labels} value` line.
func parseSample(t *testing.T, line string, lineNo int) *sample {
	t.Helper()

	name, rest := line, ""
	labels := map[string]string{}

	if brace := strings.IndexByte(line, '{'); brace >= 0 {
		name = line[:brace]
		var ok bool
		labels, rest, ok = parseLabels(t, line[brace:], lineNo)
		if !ok {
			return nil
		}
	} else if sp := strings.IndexByte(line, ' '); sp >= 0 {
		name, rest = line[:sp], line[sp:]
	} else {
		t.Errorf("line %d: sample %q has no value", lineNo, line)
		return nil
	}

	if !isMetricName(name) {
		t.Errorf("line %d: %q is not a valid metric name", lineNo, name)
		return nil
	}

	fields := strings.Fields(rest)
	if len(fields) == 0 {
		t.Errorf("line %d: %s has no value", lineNo, name)
		return nil
	}
	if len(fields) > 2 {
		t.Errorf("line %d: %s has trailing junk after its value: %q", lineNo, name, rest)
		return nil
	}
	v, err := parseValue(fields[0])
	if err != nil {
		t.Errorf("line %d: %s has unparseable value %q: %v", lineNo, name, fields[0], err)
		return nil
	}
	if len(fields) == 2 {
		if _, err := strconv.ParseInt(fields[1], 10, 64); err != nil {
			t.Errorf("line %d: %s has a non-integer timestamp %q", lineNo, name, fields[1])
		}
	}
	return &sample{name: name, labels: labels, value: v}
}

// parseLabels consumes `{a="1",b="2"}` and returns what follows it.
func parseLabels(t *testing.T, s string, lineNo int) (map[string]string, string, bool) {
	t.Helper()

	labels := map[string]string{}
	i := 1 // skip '{'
	for {
		for i < len(s) && (s[i] == ' ' || s[i] == ',') {
			i++
		}
		if i < len(s) && s[i] == '}' {
			return labels, s[i+1:], true
		}
		start := i
		for i < len(s) && s[i] != '=' {
			i++
		}
		if i >= len(s) {
			t.Errorf("line %d: unterminated label set in %q", lineNo, s)
			return nil, "", false
		}
		name := s[start:i]
		if !isLabelName(name) {
			t.Errorf("line %d: %q is not a valid label name", lineNo, name)
			return nil, "", false
		}
		if _, dup := labels[name]; dup {
			t.Errorf("line %d: label %q repeated in one label set", lineNo, name)
			return nil, "", false
		}
		i++ // '='
		if i >= len(s) || s[i] != '"' {
			t.Errorf("line %d: label %q value is not quoted", lineNo, name)
			return nil, "", false
		}
		i++ // opening quote

		var v strings.Builder
		closed := false
		for i < len(s) {
			c := s[i]
			if c == '\\' {
				if i+1 >= len(s) {
					break
				}
				switch s[i+1] {
				case '\\':
					v.WriteByte('\\')
				case '"':
					v.WriteByte('"')
				case 'n':
					v.WriteByte('\n')
				default:
					t.Errorf("line %d: label %q has invalid escape \\%c", lineNo, name, s[i+1])
					return nil, "", false
				}
				i += 2
				continue
			}
			if c == '"' {
				closed = true
				i++
				break
			}
			if c == '\n' {
				t.Errorf("line %d: label %q value contains a raw newline — "+
					"the value was not escaped and has broken out of its line", lineNo, name)
				return nil, "", false
			}
			v.WriteByte(c)
			i++
		}
		if !closed {
			t.Errorf("line %d: label %q value is unterminated", lineNo, name)
			return nil, "", false
		}
		labels[name] = v.String()
	}
}

func parseValue(s string) (float64, error) {
	switch s {
	case "+Inf":
		return math.Inf(1), nil
	case "-Inf":
		return math.Inf(-1), nil
	case "NaN":
		return math.NaN(), nil
	}
	return strconv.ParseFloat(s, 64)
}

// familyNameOf maps a sample name back to its declared family, accounting for
// the _bucket/_sum/_count suffixes a histogram emits.
func familyNameOf(sampleName string, families map[string]*family) string {
	for _, suffix := range []string{"_bucket", "_sum", "_count"} {
		if !strings.HasSuffix(sampleName, suffix) {
			continue
		}
		base := strings.TrimSuffix(sampleName, suffix)
		if f, ok := families[base]; ok && f.typ == "histogram" {
			return base
		}
	}
	return sampleName
}

// checkHistogram asserts the invariants a histogram must satisfy to graph
// correctly: buckets are cumulative and ascending, and the +Inf bucket agrees
// with _count.
func checkHistogram(t *testing.T, f *family) {
	t.Helper()

	type seriesKey string
	buckets := map[seriesKey][]struct {
		le    float64
		count float64
	}{}
	counts := map[seriesKey]float64{}
	sawSum := map[seriesKey]bool{}

	identity := func(s sample) seriesKey {
		names := make([]string, 0, len(s.labels))
		for k := range s.labels {
			if k == "le" {
				continue
			}
			names = append(names, k)
		}
		sort.Strings(names)
		var b strings.Builder
		for _, n := range names {
			fmt.Fprintf(&b, "%s=%q,", n, s.labels[n])
		}
		return seriesKey(b.String())
	}

	for _, s := range f.samples {
		id := identity(s)
		switch {
		case strings.HasSuffix(s.name, "_bucket"):
			raw, ok := s.labels["le"]
			if !ok {
				t.Errorf("%s: a _bucket sample has no le label", f.name)
				continue
			}
			le, err := parseValue(raw)
			if err != nil {
				t.Errorf("%s: le=%q is not a number", f.name, raw)
				continue
			}
			buckets[id] = append(buckets[id], struct {
				le    float64
				count float64
			}{le, s.value})
		case strings.HasSuffix(s.name, "_count"):
			counts[id] = s.value
		case strings.HasSuffix(s.name, "_sum"):
			sawSum[id] = true
		}
	}

	for id, bs := range buckets {
		sort.Slice(bs, func(i, j int) bool { return bs[i].le < bs[j].le })
		for i := 1; i < len(bs); i++ {
			if bs[i].count < bs[i-1].count {
				t.Errorf("%s{%s}: buckets are not cumulative — le=%v has %v but le=%v has %v",
					f.name, id, bs[i].le, bs[i].count, bs[i-1].le, bs[i-1].count)
			}
		}
		if len(bs) == 0 || !math.IsInf(bs[len(bs)-1].le, 1) {
			t.Errorf("%s{%s}: histogram has no le=\"+Inf\" bucket", f.name, id)
			continue
		}
		if got, want := bs[len(bs)-1].count, counts[id]; got != want {
			t.Errorf("%s{%s}: le=\"+Inf\" is %v but _count is %v — they must agree",
				f.name, id, got, want)
		}
		if !sawSum[id] {
			t.Errorf("%s{%s}: histogram has no _sum", f.name, id)
		}
	}
}

func isMetricName(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		ok := c == '_' || c == ':' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(i > 0 && c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return true
}

func isLabelName(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		ok := c == '_' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(i > 0 && c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return true
}

// find returns the value of one series, located by name and an exact label set.
func find(t *testing.T, fams map[string]*family, name string, labelKV ...string) (float64, bool) {
	t.Helper()

	if len(labelKV)%2 != 0 {
		t.Fatalf("find: odd number of label arguments")
	}
	want := map[string]string{}
	for i := 0; i < len(labelKV); i += 2 {
		want[labelKV[i]] = labelKV[i+1]
	}
	for _, f := range fams {
		for _, s := range f.samples {
			if s.name != name || len(s.labels) != len(want) {
				continue
			}
			match := true
			for k, v := range want {
				if s.labels[k] != v {
					match = false
					break
				}
			}
			if match {
				return s.value, true
			}
		}
	}
	return 0, false
}

// mustFind is find for the cases where absence is a test failure.
func mustFind(t *testing.T, fams map[string]*family, name string, labelKV ...string) float64 {
	t.Helper()

	v, ok := find(t, fams, name, labelKV...)
	if !ok {
		t.Fatalf("no series %s%v in the scrape", name, labelKV)
	}
	return v
}
