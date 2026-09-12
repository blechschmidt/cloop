package hubmetrics

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
)

// ── Registration ────────────────────────────────────────────────────────────

func TestRegisterRejectsMalformedDefinitions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		def  Definition
		want string
	}{
		{"empty name", Definition{Name: "", Help: "h", Type: TypeCounter}, "invalid metric name"},
		{"leading digit", Definition{Name: "9lives", Help: "h", Type: TypeCounter}, "invalid metric name"},
		{"hyphen in name", Definition{Name: "a-b", Help: "h", Type: TypeCounter}, "invalid metric name"},
		{"space in name", Definition{Name: "a b", Help: "h", Type: TypeCounter}, "invalid metric name"},
		{"newline in name", Definition{Name: "a\nb", Help: "h", Type: TypeCounter}, "invalid metric name"},
		{"no help", Definition{Name: "m", Help: "", Type: TypeCounter}, "help text is required"},
		{"blank help", Definition{Name: "m", Help: "   ", Type: TypeCounter}, "help text is required"},
		{"no type", Definition{Name: "m", Help: "h"}, "unknown type"},
		{"bogus type", Definition{Name: "m", Help: "h", Type: MetricType("summary")}, "unknown type"},
		{"bad label", Definition{Name: "m", Help: "h", Type: TypeCounter, Labels: []string{"a-b"}}, "invalid label name"},
		{"reserved label prefix", Definition{Name: "m", Help: "h", Type: TypeCounter, Labels: []string{"__name__"}}, "invalid label name"},
		{"duplicate label", Definition{Name: "m", Help: "h", Type: TypeCounter, Labels: []string{"a", "a"}}, "duplicate label"},
		{
			"le on a histogram",
			Definition{Name: "m", Help: "h", Type: TypeHistogram, Labels: []string{"le"}, Buckets: []float64{1}},
			"reserved for histogram buckets",
		},
		{"histogram without buckets", Definition{Name: "m", Help: "h", Type: TypeHistogram}, "at least one bucket"},
		{
			"buckets out of order",
			Definition{Name: "m", Help: "h", Type: TypeHistogram, Buckets: []float64{5, 1}},
			"buckets must ascend",
		},
		{
			"duplicate bucket bounds",
			Definition{Name: "m", Help: "h", Type: TypeHistogram, Buckets: []float64{1, 1}},
			"buckets must ascend",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := New()
			m, err := r.Register(tc.def)
			if err == nil {
				t.Fatalf("Register(%+v) succeeded, want error containing %q", tc.def, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Register error = %q, want it to contain %q", err, tc.want)
			}
			if m != nil {
				t.Error("Register returned a metric alongside an error")
			}
			// A rejected definition must leave nothing behind, or the name
			// it failed on would be unusable by the corrected definition.
			if got := r.Gather(); strings.Contains(got, tc.def.Name+" ") && tc.def.Name != "" {
				t.Errorf("a rejected metric still appears in the scrape:\n%s", got)
			}
		})
	}
}

func TestRegisterRejectsDuplicateName(t *testing.T) {
	t.Parallel()

	r := New()
	def := Definition{Name: "cloop_test_total", Help: "first", Type: TypeCounter}
	if _, err := r.Register(def); err != nil {
		t.Fatalf("first Register: %v", err)
	}

	// A different shape under the same name is still a duplicate: the name is
	// the identity a scraper keys on, so allowing this would emit two
	// contradictory TYPE lines for one family.
	second := Definition{Name: "cloop_test_total", Help: "second", Type: TypeGauge, Labels: []string{"x"}}
	m, err := r.Register(second)
	if err == nil {
		t.Fatal("re-registering an existing name succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "already registered") {
		t.Errorf("error = %q, want it to mention that the name is taken", err)
	}
	if m != nil {
		t.Error("duplicate Register returned a metric")
	}

	fams := parseExposition(t, r.Gather())
	if got := fams["cloop_test_total"]; got == nil || got.help != "first" {
		t.Errorf("the duplicate overwrote the original family: %+v", got)
	}
}

func TestRegisterAcceptsAWellFormedDefinition(t *testing.T) {
	t.Parallel()

	r := New()
	m, err := r.Register(Definition{
		Name:    "cloop_test_duration_seconds",
		Help:    "h",
		Type:    TypeHistogram,
		Labels:  []string{"kind", "result"},
		Buckets: []float64{0.5, 1, 5},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if m == nil {
		t.Fatal("Register returned a nil metric and a nil error")
	}
}

// TestRegisterCopiesDefinitionSlices — a caller that reuses its Labels or
// Buckets slice must not be able to mutate a registered metric's schema.
func TestRegisterCopiesDefinitionSlices(t *testing.T) {
	t.Parallel()

	r := New()
	labels := []string{"kind"}
	buckets := []float64{1, 2}
	m, err := r.Register(Definition{
		Name: "cloop_test_seconds", Help: "h", Type: TypeHistogram,
		Labels: labels, Buckets: buckets,
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	labels[0] = "mutated"
	buckets[0] = 999

	m.Observe(1.5, "real")
	fams := parseExposition(t, r.Gather())
	if _, ok := find(t, fams, "cloop_test_seconds_bucket", "kind", "real", "le", "1"); !ok {
		t.Errorf("mutating the caller's slices changed the registered schema:\n%s", r.Gather())
	}
}

func TestMustRegisterPanicsOnBadDefinition(t *testing.T) {
	t.Parallel()

	defer func() {
		rec := recover()
		if rec == nil {
			t.Fatal("MustRegister did not panic on a malformed definition")
		}
		if !strings.Contains(fmt.Sprint(rec), "hubmetrics:") {
			t.Errorf("panic value %v does not identify the package", rec)
		}
	}()
	New().MustRegister(Definition{Name: "no-help-and-a-bad-name"})
}

// ── Cardinality ceiling ─────────────────────────────────────────────────────

// TestDefaultMaxSeriesPerMetricIsTheDocumentedValue pins the constant. It is
// referenced by name in the operator docs and sized against the widest label
// enumeration in the catalog, so a silent change is a change to a published
// number.
func TestDefaultMaxSeriesPerMetricIsTheDocumentedValue(t *testing.T) {
	t.Parallel()

	if DefaultMaxSeriesPerMetric != 128 {
		t.Errorf("DefaultMaxSeriesPerMetric = %d, want 128", DefaultMaxSeriesPerMetric)
	}
	if New().MaxSeriesPerMetric != DefaultMaxSeriesPerMetric {
		t.Errorf("New() did not adopt the default ceiling")
	}
}

// TestSeriesCapFoldsOverflowIntoOneBucket is the memory-safety property the
// whole package is built around: unbounded label values must cost a bounded
// number of series.
func TestSeriesCapFoldsOverflowIntoOneBucket(t *testing.T) {
	t.Parallel()

	r := New()
	m := r.MustRegister(Definition{
		Name: "cloop_test_total", Help: "h", Type: TypeCounter, Labels: []string{"tenant"},
	})

	const distinct = DefaultMaxSeriesPerMetric + 72
	for i := 0; i < distinct; i++ {
		m.Inc(fmt.Sprintf("tenant-%d", i))
	}

	// 128 real series plus exactly one overflow series, no matter how far
	// past the ceiling the caller went.
	if got, want := m.SeriesCount(), DefaultMaxSeriesPerMetric+1; got != want {
		t.Errorf("SeriesCount() = %d, want %d (%d real + 1 overflow)",
			got, want, DefaultMaxSeriesPerMetric)
	}

	fams := parseExposition(t, r.Gather())

	// The fold-in series is labelled so it cannot be mistaken for real data.
	folded, ok := find(t, fams, "cloop_test_total", "tenant", overflowLabel)
	if !ok {
		t.Fatalf("no %s series in the scrape:\n%s", overflowLabel, r.Gather())
	}
	if want := float64(distinct - DefaultMaxSeriesPerMetric); folded != want {
		t.Errorf("overflow series = %v, want %v (every sample past the ceiling)", folded, want)
	}

	// And the counter that tells an operator which metric misbehaved.
	dropped := mustFind(t, fams, "cloop_metrics_series_dropped_total", "metric", "cloop_test_total")
	if want := float64(distinct - DefaultMaxSeriesPerMetric); dropped != want {
		t.Errorf("cloop_metrics_series_dropped_total = %v, want %v", dropped, want)
	}

	// Samples are preserved, not discarded: nothing is lost, only identity.
	var total float64
	for _, s := range fams["cloop_test_total"].samples {
		total += s.value
	}
	if total != float64(distinct) {
		t.Errorf("total across all series = %v, want %v — the ceiling dropped samples "+
			"rather than folding them", total, distinct)
	}
}

// TestSeriesCapAdmitsExactlyTheCeiling checks the boundary, where an
// off-by-one would either waste a series or admit one too many.
func TestSeriesCapAdmitsExactlyTheCeiling(t *testing.T) {
	t.Parallel()

	r := New()
	r.MaxSeriesPerMetric = 3
	m := r.MustRegister(Definition{
		Name: "cloop_test_total", Help: "h", Type: TypeCounter, Labels: []string{"k"},
	})

	m.Inc("a")
	m.Inc("b")
	m.Inc("c")
	if got := m.SeriesCount(); got != 3 {
		t.Fatalf("SeriesCount() = %d after 3 distinct values under a ceiling of 3, want 3", got)
	}
	if strings.Contains(r.Gather(), overflowLabel) {
		t.Error("an overflow series appeared before the ceiling was exceeded")
	}

	m.Inc("d")
	if got := m.SeriesCount(); got != 4 {
		t.Errorf("SeriesCount() = %d after exceeding the ceiling, want 4 (3 real + overflow)", got)
	}
	fams := parseExposition(t, r.Gather())
	if _, ok := find(t, fams, "cloop_test_total", "k", overflowLabel); !ok {
		t.Error("the 4th distinct value did not fold into the overflow series")
	}

	// A value already holding a series still resolves to it after the
	// ceiling is hit — the ceiling refuses new series, it does not freeze
	// the metric.
	m.Inc("a")
	if got := mustFind(t, parseExposition(t, r.Gather()), "cloop_test_total", "k", "a"); got != 2 {
		t.Errorf("existing series stopped updating after the ceiling was reached: got %v, want 2", got)
	}
}

func TestPerMetricMaxSeriesOverridesTheRegistryDefault(t *testing.T) {
	t.Parallel()

	r := New()
	r.MaxSeriesPerMetric = 2
	m := r.MustRegister(Definition{
		Name: "cloop_test_total", Help: "h", Type: TypeGauge,
		Labels: []string{"k"}, MaxSeries: 5,
	})
	for i := 0; i < 5; i++ {
		m.Set(1, fmt.Sprintf("v%d", i))
	}
	if got := m.SeriesCount(); got != 5 {
		t.Errorf("SeriesCount() = %d, want 5 — MaxSeries did not override the registry default", got)
	}
	if strings.Contains(r.Gather(), overflowLabel) {
		t.Error("overflowed despite the per-metric ceiling having room")
	}
}

// TestLabelCountMismatchFoldsToOverflow — a wrong-arity call is a programming
// error, but it must not panic a serving hub. It folds and is counted.
func TestLabelCountMismatchFoldsToOverflow(t *testing.T) {
	t.Parallel()

	r := New()
	m := r.MustRegister(Definition{
		Name: "cloop_test_total", Help: "h", Type: TypeCounter, Labels: []string{"a", "b"},
	})

	m.Inc("only-one")       // too few
	m.Inc("a", "b", "c")    // too many
	m.Inc()                 // none at all
	m.Inc("right", "arity") // the correct call still works

	fams := parseExposition(t, r.Gather())
	if got := mustFind(t, fams, "cloop_test_total", "a", overflowLabel, "b", overflowLabel); got != 3 {
		t.Errorf("overflow series = %v, want 3 mis-arity samples", got)
	}
	if got := mustFind(t, fams, "cloop_test_total", "a", "right", "b", "arity"); got != 1 {
		t.Errorf("correct call = %v, want 1", got)
	}
	if got := mustFind(t, fams, "cloop_metrics_series_dropped_total", "metric", "cloop_test_total"); got != 3 {
		t.Errorf("dropped counter = %v, want 3", got)
	}
}

func TestTotalSeriesSpansEveryFamily(t *testing.T) {
	t.Parallel()

	r := New()
	a := r.MustRegister(Definition{Name: "cloop_a_total", Help: "h", Type: TypeCounter, Labels: []string{"k"}})
	b := r.MustRegister(Definition{Name: "cloop_b_total", Help: "h", Type: TypeCounter, Labels: []string{"k"}})
	a.Inc("1")
	a.Inc("2")
	b.Inc("1")
	if got := r.TotalSeries(); got != 3 {
		t.Errorf("TotalSeries() = %d, want 3", got)
	}
}

// ── Label values ────────────────────────────────────────────────────────────

// TestLabelValueTruncation — the second line of defence behind "labels come
// from closed enumerations". If a user-controlled value reaches a label, it
// must at least be bounded in size.
func TestLabelValueTruncation(t *testing.T) {
	t.Parallel()

	r := New()
	m := r.MustRegister(Definition{
		Name: "cloop_test_total", Help: "h", Type: TypeCounter, Labels: []string{"k"},
	})

	long := strings.Repeat("x", maxLabelValueLen*4)
	m.Inc(long)

	fams := parseExposition(t, r.Gather())
	var got string
	for _, s := range fams["cloop_test_total"].samples {
		got = s.labels["k"]
	}
	if len(got) != maxLabelValueLen {
		t.Errorf("label value length = %d, want it truncated to %d", len(got), maxLabelValueLen)
	}
	if got != strings.Repeat("x", maxLabelValueLen) {
		t.Errorf("truncated value = %q, want the first %d bytes", got, maxLabelValueLen)
	}
}

// TestLabelValuesCollapseAfterTruncation is the consequence of truncating that
// a reader should know about: two values differing only past the cap become
// one series. That is the intended trade — bounded memory over fidelity for
// values that were never supposed to be here.
func TestLabelValuesCollapseAfterTruncation(t *testing.T) {
	t.Parallel()

	r := New()
	m := r.MustRegister(Definition{
		Name: "cloop_test_total", Help: "h", Type: TypeCounter, Labels: []string{"k"},
	})

	prefix := strings.Repeat("y", maxLabelValueLen)
	m.Inc(prefix + "-first")
	m.Inc(prefix + "-second")

	if got := m.SeriesCount(); got != 1 {
		t.Errorf("SeriesCount() = %d, want 1 — values sharing a truncated prefix must share a series", got)
	}
	if got := mustFind(t, parseExposition(t, r.Gather()), "cloop_test_total", "k", prefix); got != 2 {
		t.Errorf("collapsed series = %v, want 2", got)
	}
}

func TestLabelValueNormalisation(t *testing.T) {
	t.Parallel()

	cases := []struct{ in, want string }{
		{"", "unknown"},
		{"   ", "unknown"},
		{"\t\n ", "unknown"},
		{"  padded  ", "padded"},
		{"plain", "plain"},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%q", tc.in), func(t *testing.T) {
			t.Parallel()
			if got := sanitizeLabelValue(tc.in); got != tc.want {
				t.Errorf("sanitizeLabelValue(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestHostileLabelValueCannotInjectALine — escaping is not cosmetic. An
// unescaped quote or newline in a label lets the value forge whole metric
// lines, which is log injection with a time-series database downstream.
func TestHostileLabelValueCannotInjectALine(t *testing.T) {
	t.Parallel()

	r := New()
	m := r.MustRegister(Definition{
		Name: "cloop_test_total", Help: "h", Type: TypeCounter, Labels: []string{"k"},
	})
	m.Inc(`a"} 999` + "\n" + `cloop_forged_total{k="x`)

	out := r.Gather()
	if strings.Contains(out, "cloop_forged_total") && strings.Contains(out, "\ncloop_forged_total") {
		t.Fatalf("a hostile label value forged a metric line:\n%s", out)
	}

	// The authoritative check: the payload still parses, and the forged
	// name is not a series in it.
	fams := parseExposition(t, out)
	if _, ok := fams["cloop_forged_total"]; ok {
		t.Errorf("the forged family survived escaping:\n%s", out)
	}
	if n := len(fams["cloop_test_total"].samples); n != 1 {
		t.Errorf("cloop_test_total has %d samples, want 1", n)
	}
}

func TestHelpTextIsEscaped(t *testing.T) {
	t.Parallel()

	r := New()
	r.MustRegister(Definition{
		Name: "cloop_test_total",
		Help: "first line\nsecond line with a \\ backslash",
		Type: TypeCounter,
	})
	out := r.Gather()
	if strings.Contains(out, "second line") && strings.Contains(out, "\nsecond line") {
		t.Errorf("a newline in HELP broke out of its line:\n%s", out)
	}
	parseExposition(t, out)
}

// ── Values ──────────────────────────────────────────────────────────────────

func TestCounterRefusesToGoBackwards(t *testing.T) {
	t.Parallel()

	r := New()
	c := r.MustRegister(Definition{Name: "cloop_c_total", Help: "h", Type: TypeCounter})
	g := r.MustRegister(Definition{Name: "cloop_g", Help: "h", Type: TypeGauge})

	c.Add(5)
	c.Add(-3) // must be refused: a counter that falls makes rate() report a spike
	g.Add(5)
	g.Add(-3) // a gauge may fall

	fams := parseExposition(t, r.Gather())
	if got := mustFind(t, fams, "cloop_c_total"); got != 5 {
		t.Errorf("counter = %v after a negative Add, want 5", got)
	}
	if got := mustFind(t, fams, "cloop_g"); got != 2 {
		t.Errorf("gauge = %v, want 2 — a gauge must accept a negative Add", got)
	}
}

func TestNaNIsIgnored(t *testing.T) {
	t.Parallel()

	r := New()
	g := r.MustRegister(Definition{Name: "cloop_g", Help: "h", Type: TypeGauge})
	h := r.MustRegister(Definition{Name: "cloop_h", Help: "h", Type: TypeHistogram, Buckets: []float64{1}})

	g.Set(7)
	g.Set(math.NaN())
	g.Add(math.NaN())
	h.Observe(0.5)
	h.Observe(math.NaN())

	fams := parseExposition(t, r.Gather())
	if got := mustFind(t, fams, "cloop_g"); got != 7 {
		t.Errorf("gauge = %v after NaN writes, want the last good value 7", got)
	}
	// A NaN observation must not reach _count or _sum. A NaN in _sum is
	// permanent: every later rate() over it returns NaN too.
	if got := mustFind(t, fams, "cloop_h_count"); got != 1 {
		t.Errorf("histogram counted a NaN observation: _count = %v, want 1", got)
	}
	if got := mustFind(t, fams, "cloop_h_sum"); got != 0.5 {
		t.Errorf("_sum = %v, want 0.5 — a NaN poisoned the sum", got)
	}
}

func TestNilMetricIsANoop(t *testing.T) {
	t.Parallel()

	var m *Metric
	// The point of the nil guard: a subsystem can hold an optional metric
	// without wrapping every call site in a check.
	m.Inc("a")
	m.Add(2, "a")
	m.Set(3, "a")
	m.Observe(4, "a")
	m.Reset()
	if got := m.SeriesCount(); got != 0 {
		t.Errorf("SeriesCount() on a nil metric = %d, want 0", got)
	}
}

func TestObserveOnlyAppliesToHistograms(t *testing.T) {
	t.Parallel()

	r := New()
	c := r.MustRegister(Definition{Name: "cloop_c_total", Help: "h", Type: TypeCounter})
	c.Observe(5)

	// Observe on a non-histogram is dropped before a series is even
	// allocated, so the family stays empty rather than reporting a 0 that
	// looks like a real measurement.
	fams := parseExposition(t, r.Gather())
	if n := len(fams["cloop_c_total"].samples); n != 0 {
		t.Errorf("Observe created %d series on a counter, want 0", n)
	}
	if got := c.SeriesCount(); got != 0 {
		t.Errorf("SeriesCount() = %d after Observe on a counter, want 0", got)
	}
}

func TestHistogramBucketsAreCumulative(t *testing.T) {
	t.Parallel()

	r := New()
	h := r.MustRegister(Definition{
		Name: "cloop_test_seconds", Help: "h", Type: TypeHistogram,
		Labels: []string{"kind"}, Buckets: []float64{1, 5, 10},
	})

	for _, v := range []float64{0.5, 7, 100} {
		h.Observe(v, "k")
	}

	// checkHistogram inside parseExposition already asserts monotonicity and
	// that +Inf agrees with _count; these pin the exact bucketing.
	fams := parseExposition(t, r.Gather())
	for _, tc := range []struct {
		le   string
		want float64
	}{
		{"1", 1},    // 0.5
		{"5", 1},    // 0.5
		{"10", 2},   // 0.5, 7
		{"+Inf", 3}, // 0.5, 7, 100 — the 100 lives only here
	} {
		if got := mustFind(t, fams, "cloop_test_seconds_bucket", "kind", "k", "le", tc.le); got != tc.want {
			t.Errorf("bucket le=%s = %v, want %v", tc.le, got, tc.want)
		}
	}
	if got := mustFind(t, fams, "cloop_test_seconds_sum", "kind", "k"); got != 107.5 {
		t.Errorf("_sum = %v, want 107.5", got)
	}
	if got := mustFind(t, fams, "cloop_test_seconds_count", "kind", "k"); got != 3 {
		t.Errorf("_count = %v, want 3", got)
	}
}

// TestResetDropsSeriesRatherThanFreezingThem — a collector-backed gauge whose
// object is gone must stop being exported. A frozen gauge reads as a live
// measurement and holds an alert open forever.
func TestResetDropsSeriesRatherThanFreezingThem(t *testing.T) {
	t.Parallel()

	r := New()
	g := r.MustRegister(Definition{
		Name: "cloop_test_live", Help: "h", Type: TypeGauge, Labels: []string{"id"},
	})
	g.Set(1, "gone")
	g.Set(1, "still-here")

	g.Reset()
	g.Set(1, "still-here")

	fams := parseExposition(t, r.Gather())
	if _, ok := find(t, fams, "cloop_test_live", "id", "gone"); ok {
		t.Error("a series survived Reset and is still being exported as live")
	}
	if got := mustFind(t, fams, "cloop_test_live", "id", "still-here"); got != 1 {
		t.Errorf("repopulated series = %v, want 1", got)
	}
	if got := g.SeriesCount(); got != 1 {
		t.Errorf("SeriesCount() = %d after Reset and one Set, want 1", got)
	}
}

func TestResetClearsTheOverflowSeries(t *testing.T) {
	t.Parallel()

	r := New()
	r.MaxSeriesPerMetric = 1
	g := r.MustRegister(Definition{Name: "cloop_test_live", Help: "h", Type: TypeGauge, Labels: []string{"id"}})
	g.Set(1, "a")
	g.Set(1, "b") // overflows
	if !strings.Contains(r.Gather(), overflowLabel) {
		t.Fatal("expected an overflow series before Reset")
	}
	g.Reset()
	if strings.Contains(r.Gather(), overflowLabel) {
		t.Error("Reset left the overflow series behind, so the metric can never recover its cardinality budget")
	}
}

// ── Exposition ──────────────────────────────────────────────────────────────

// TestGatherIsValidPrometheusText runs everything the registry can emit —
// counters, gauges, histograms, no-label families, empty families, overflow,
// hostile label values — through the format reader.
func TestGatherIsValidPrometheusText(t *testing.T) {
	t.Parallel()

	r := New()
	r.MaxSeriesPerMetric = 4

	c := r.MustRegister(Definition{
		Name: "cloop_requests_total", Help: "Requests, by result.", Type: TypeCounter,
		Labels: []string{"result"},
	})
	g := r.MustRegister(Definition{
		Name: "cloop_live", Help: "Live things.", Type: TypeGauge, Labels: []string{"kind"},
	})
	bare := r.MustRegister(Definition{
		Name: "cloop_enabled", Help: "1 when on.", Type: TypeGauge,
	})
	h := r.MustRegister(Definition{
		Name: "cloop_latency_seconds", Help: `Latency. Note the "quotes" and \ backslash.`,
		Type: TypeHistogram, Labels: []string{"route"}, Buckets: []float64{0.1, 1, 10},
	})
	r.MustRegister(Definition{
		Name: "cloop_never_touched_total", Help: "Nothing has happened yet.", Type: TypeCounter,
		Labels: []string{"reason"},
	})

	c.Inc("allowed")
	c.Add(3, "denied")
	g.Set(2, "executor")
	g.Set(-1, "drift") // gauges may be negative
	bare.Set(1)
	h.Observe(0.05, "/api/state")
	h.Observe(5, "/api/state")
	h.Observe(60, "/metrics")
	for i := 0; i < 10; i++ { // force overflow
		c.Inc(fmt.Sprintf("result-%d", i))
	}
	c.Inc(`hostile"} 1
cloop_forged_total{x="`)

	out := r.Gather()
	fams := parseExposition(t, out)

	for _, want := range []string{
		"cloop_requests_total", "cloop_live", "cloop_enabled",
		"cloop_latency_seconds", "cloop_never_touched_total",
		"cloop_metrics_series_dropped_total",
	} {
		if fams[want] == nil {
			t.Errorf("family %s is missing from the scrape", want)
		}
	}

	// An unobserved family still declares itself. "The build predates this
	// counter" and "nothing has happened" are different diagnoses, and a
	// dashboard rendering "No data" for the second is a false alarm.
	if f := fams["cloop_never_touched_total"]; f == nil || f.typ != "counter" {
		t.Errorf("an unobserved family lost its TYPE: %+v", f)
	} else if len(f.samples) != 0 {
		t.Errorf("an unobserved family emitted %d samples", len(f.samples))
	}

	if got := mustFind(t, fams, "cloop_live", "kind", "drift"); got != -1 {
		t.Errorf("negative gauge = %v, want -1", got)
	}
	if got := mustFind(t, fams, "cloop_enabled"); got != 1 {
		t.Errorf("unlabelled gauge = %v, want 1", got)
	}
}

// TestGatherIsByteStable — families in registration order, series sorted
// within a family. Without this a diff between two scrapes is noise and the
// output depends on Go's map iteration order.
func TestGatherIsByteStable(t *testing.T) {
	t.Parallel()

	r := New()
	m := r.MustRegister(Definition{
		Name: "cloop_test_total", Help: "h", Type: TypeCounter, Labels: []string{"k"},
	})
	for _, v := range []string{"zulu", "alpha", "mike", "bravo"} {
		m.Inc(v)
	}
	first := r.Gather()
	for i := 0; i < 20; i++ {
		if got := r.Gather(); got != first {
			t.Fatalf("scrape %d differs from the first:\n--- first ---\n%s\n--- got ---\n%s", i, first, got)
		}
	}

	idx := func(v string) int { return strings.Index(first, `k="`+v+`"`) }
	if !(idx("alpha") < idx("bravo") && idx("bravo") < idx("mike") && idx("mike") < idx("zulu")) {
		t.Errorf("series are not in sorted label order:\n%s", first)
	}
}

func TestWriteToReportsBytesWritten(t *testing.T) {
	t.Parallel()

	r := New()
	r.MustRegister(Definition{Name: "cloop_test_total", Help: "h", Type: TypeCounter}).Inc()

	var b strings.Builder
	n, err := r.WriteTo(&b)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if int(n) != b.Len() {
		t.Errorf("WriteTo reported %d bytes but wrote %d", n, b.Len())
	}
}

func TestFormatValue(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   float64
		want string
	}{
		{0, "0"},
		{1, "1"},
		{-1, "-1"},
		{1.5, "1.5"},
		{1e15, "1e+15"},
		{math.Inf(1), "+Inf"},
		{math.Inf(-1), "-Inf"},
		{math.NaN(), "NaN"},
	}
	for _, tc := range cases {
		if got := formatValue(tc.in); got != tc.want {
			t.Errorf("formatValue(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ── Collectors ──────────────────────────────────────────────────────────────

func TestCollectorRunsBeforeEveryScrape(t *testing.T) {
	t.Parallel()

	r := New()
	g := r.MustRegister(Definition{Name: "cloop_live", Help: "h", Type: TypeGauge})

	calls := 0
	r.RegisterCollector("counter", func() {
		calls++
		g.Set(float64(calls))
	})

	if got := mustFind(t, parseExposition(t, r.Gather()), "cloop_live"); got != 1 {
		t.Errorf("first scrape = %v, want 1", got)
	}
	if got := mustFind(t, parseExposition(t, r.Gather()), "cloop_live"); got != 2 {
		t.Errorf("second scrape = %v, want 2 — the collector did not re-run", got)
	}
}

// TestBrokenCollectorDoesNotBlankTheScrape — a collector reads live subsystem
// state, so it can panic on a half-initialised hub. The surviving metrics are
// exactly what an operator diagnosing that state needs.
func TestBrokenCollectorDoesNotBlankTheScrape(t *testing.T) {
	t.Parallel()

	r := New()
	good := r.MustRegister(Definition{Name: "cloop_good", Help: "h", Type: TypeGauge})

	r.RegisterCollector("explodes", func() { panic("half-initialised store") })
	r.RegisterCollector("works", func() { good.Set(42) })
	r.RegisterCollector("nil-deref", func() {
		var m map[string]int
		m["boom"] = 1 // assignment to entry in nil map
	})

	out := r.Gather() // must not panic
	fams := parseExposition(t, out)

	if got := mustFind(t, fams, "cloop_good"); got != 42 {
		t.Errorf("a panicking collector suppressed a healthy one: cloop_good = %v, want 42", got)
	}
	// The panic is not silent: it is attributed to the collector by name.
	if got := mustFind(t, fams, "cloop_metrics_series_dropped_total", "metric", "collector:explodes"); got != 1 {
		t.Errorf("panicking collector was not recorded: %v, want 1", got)
	}
	if got := mustFind(t, fams, "cloop_metrics_series_dropped_total", "metric", "collector:nil-deref"); got != 1 {
		t.Errorf("nil-map collector was not recorded: %v, want 1", got)
	}
}

func TestRegisterCollectorIgnoresNil(t *testing.T) {
	t.Parallel()

	r := New()
	r.RegisterCollector("nil", nil)
	r.Gather() // must not panic on a nil func
}

// ── Concurrency ─────────────────────────────────────────────────────────────

// TestConcurrentMutation exercises every mutator against one registry while
// scrapes run underneath. Run under -race this is the test that justifies the
// lock-free CAS in addFloat; the exact totals are what catch a lost update
// that the race detector alone would not flag.
func TestConcurrentMutation(t *testing.T) {
	t.Parallel()

	const (
		goroutines = 16
		iterations = 500
	)

	r := New()
	counter := r.MustRegister(Definition{
		Name: "cloop_ops_total", Help: "h", Type: TypeCounter, Labels: []string{"worker"},
	})
	shared := r.MustRegister(Definition{
		Name: "cloop_shared_total", Help: "h", Type: TypeCounter,
	})
	gauge := r.MustRegister(Definition{
		Name: "cloop_live", Help: "h", Type: TypeGauge, Labels: []string{"worker"},
	})
	hist := r.MustRegister(Definition{
		Name: "cloop_seconds", Help: "h", Type: TypeHistogram,
		Labels: []string{"worker"}, Buckets: []float64{1, 10, 100},
	})

	stop := make(chan struct{})
	var scrapers sync.WaitGroup
	for i := 0; i < 4; i++ {
		scrapers.Add(1)
		go func() {
			defer scrapers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					// Concurrent readers must never observe a torn
					// payload, and must not deadlock against writers.
					_ = r.Gather()
					_ = r.TotalSeries()
				}
			}
		}()
	}

	var writers sync.WaitGroup
	for w := 0; w < goroutines; w++ {
		writers.Add(1)
		go func(w int) {
			defer writers.Done()
			id := fmt.Sprintf("w%d", w)
			for i := 0; i < iterations; i++ {
				counter.Inc(id)
				shared.Inc()  // every goroutine on ONE series
				shared.Add(2) //
				gauge.Set(float64(i), id)
				hist.Observe(float64(i%200), id)
			}
		}(w)
	}
	writers.Wait()
	close(stop)
	scrapers.Wait()

	fams := parseExposition(t, r.Gather())

	// The contended series: 16 goroutines × 500 × (1 + 2). A lost CAS shows
	// up here and nowhere else.
	if got, want := mustFind(t, fams, "cloop_shared_total"), float64(goroutines*iterations*3); got != want {
		t.Errorf("contended counter = %v, want %v — an atomic add was lost", got, want)
	}
	for w := 0; w < goroutines; w++ {
		id := fmt.Sprintf("w%d", w)
		if got := mustFind(t, fams, "cloop_ops_total", "worker", id); got != iterations {
			t.Errorf("cloop_ops_total{worker=%q} = %v, want %d", id, got, iterations)
		}
		if got := mustFind(t, fams, "cloop_seconds_count", "worker", id); got != iterations {
			t.Errorf("cloop_seconds_count{worker=%q} = %v, want %d", id, got, iterations)
		}
		if got := mustFind(t, fams, "cloop_live", "worker", id); got != float64(iterations-1) {
			t.Errorf("cloop_live{worker=%q} = %v, want %d", id, got, iterations-1)
		}
	}
}

// TestConcurrentRegistrationAndReset covers the other two mutating paths:
// declaring families and clearing them while scrapes are in flight.
func TestConcurrentRegistrationAndReset(t *testing.T) {
	t.Parallel()

	r := New()
	victim := r.MustRegister(Definition{
		Name: "cloop_churn", Help: "h", Type: TypeGauge, Labels: []string{"k"},
	})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = r.Register(Definition{
				Name: fmt.Sprintf("cloop_dyn_%d_total", i), Help: "h", Type: TypeCounter,
			})
		}(i)
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				victim.Set(float64(j), fmt.Sprintf("k%d", i))
				if j%50 == 0 {
					victim.Reset()
				}
			}
		}(i)
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = r.Gather()
			}
		}()
	}
	wg.Wait()

	parseExposition(t, r.Gather())
	for i := 0; i < 8; i++ {
		name := fmt.Sprintf("cloop_dyn_%d_total", i)
		if _, err := r.Register(Definition{Name: name, Help: "h", Type: TypeCounter}); err == nil {
			t.Errorf("%s was not registered by the concurrent writer", name)
		}
	}
}

// TestConcurrentOverflow drives many goroutines past the ceiling at once. The
// ceiling has to hold under contention, or the check is decorative.
func TestConcurrentOverflow(t *testing.T) {
	t.Parallel()

	r := New()
	r.MaxSeriesPerMetric = 32
	m := r.MustRegister(Definition{
		Name: "cloop_test_total", Help: "h", Type: TypeCounter, Labels: []string{"k"},
	})

	const goroutines, each = 16, 200
	var wg sync.WaitGroup
	for w := 0; w < goroutines; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				m.Inc(fmt.Sprintf("v%d-%d", w, i))
			}
		}(w)
	}
	wg.Wait()

	if got, want := m.SeriesCount(), 33; got != want {
		t.Errorf("SeriesCount() = %d, want %d (32 real + 1 overflow) — the ceiling leaked under contention", got, want)
	}

	fams := parseExposition(t, r.Gather())
	var total float64
	for _, s := range fams["cloop_test_total"].samples {
		total += s.value
	}
	if want := float64(goroutines * each); total != want {
		t.Errorf("samples across all series = %v, want %v", total, want)
	}
}
