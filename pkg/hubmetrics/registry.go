// Package hubmetrics is the process-level metrics registry for a long-lived
// cloop hub.
//
// It is deliberately not pkg/metrics. That package models one *run*: a
// Metrics value is created by the orchestrator, keyed to a (provider, model)
// pair, and serialised to .cloop/metrics.json when the run ends. A hub is the
// opposite shape — one process, many tenants, many runs, no end — so the two
// cannot share a type. What a hub needs is a registry that outlives every
// individual thing it measures.
//
// The package is stdlib-only, and must stay that way. Every enterprise
// subsystem imports it (pkg/executor, pkg/secretbroker, pkg/sessionstore,
// pkg/apitoken, pkg/writeback, pkg/mergequeue, pkg/gitproxy, pkg/egressbroker),
// several of which sit near the bottom of the import graph. A single
// dependency on a cloop package here would make an import cycle out of the
// next subsystem that wants a counter.
//
// # Cardinality is a safety property, not a tuning knob
//
// A metrics registry in a multi-tenant process is an unbounded-memory hazard
// wearing a friendly name. Every distinct label combination is a series that
// lives until the process exits, so labelling by task ID, project path, or
// identity subject converts tenant activity directly into hub memory — and on
// a hosted hub that is a denial-of-service any signed-in user can trigger by
// creating projects in a loop. The rule is therefore absolute: label values
// come from closed enumerations that exist in the source (executor kinds,
// isolation levels, placement constraints, denial reasons), never from user
// or tenant input.
//
// Because "never" is a property of code review and code review is fallible,
// the registry enforces a ceiling underneath it. Each metric admits at most
// MaxSeriesPerMetric distinct label combinations; past that, samples fold into
// a single overflow series and cloop_metrics_series_dropped_total names the
// metric that overflowed. That turns the failure mode of a mistake from
// "the hub runs out of memory in a week" into "one metric goes flat and a
// counter says which one" — degraded observability instead of an outage.
package hubmetrics

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// DefaultMaxSeriesPerMetric bounds distinct label combinations per metric.
//
// Sized against the real enumerations rather than picked round: the widest
// label schema in the catalog is placement failures by constraint, where
// pkg/executor declares 24 constraints. 128 leaves an order of magnitude of
// headroom for enumerations that grow, while still capping the registry's
// footprint at a few hundred kilobytes for the whole catalog.
const DefaultMaxSeriesPerMetric = 128

// maxLabelValueLen truncates label values defensively. Values are supposed to
// come from source-declared enumerations, all of which are short; a long one
// means something user-controlled reached a label, and truncating bounds the
// damage while leaving the value recognisable in a scrape.
const maxLabelValueLen = 64

// overflowLabel replaces every label value on the fold-in series, so an
// overflowing metric reads unmistakably as "these samples lost their identity"
// rather than as a real measurement.
const overflowLabel = "__overflow__"

// MetricType is the Prometheus exposition type of a metric family.
type MetricType string

const (
	TypeCounter   MetricType = "counter"
	TypeGauge     MetricType = "gauge"
	TypeHistogram MetricType = "histogram"
)

// Registry holds every metric family in the process and renders them in the
// Prometheus text exposition format. The zero value is not usable; call New.
type Registry struct {
	// MaxSeriesPerMetric is the per-metric cardinality ceiling. Read
	// without synchronisation, so set it before the registry is shared.
	MaxSeriesPerMetric int

	mu       sync.RWMutex
	families map[string]*Metric
	order    []string

	// collectorMu serialises scrapes. Collectors reset and repopulate the
	// gauges they own, which is not safe to interleave with another scrape
	// reading those same gauges.
	collectorMu sync.Mutex
	collectors  []namedCollector

	// droppedSeries counts label combinations refused by the cardinality
	// ceiling, per metric name. Exposed as cloop_metrics_series_dropped_total.
	droppedMu sync.Mutex
	dropped   map[string]uint64
}

type namedCollector struct {
	name string
	fn   Collector
}

// Collector recomputes derived gauges immediately before a scrape.
//
// Some of what an operator needs is not a running tally but a reading of state
// that lives elsewhere: how many executors are in each health state, how deep
// the merge queue is, how many leases are live. Counting those at mutation
// time would mean every subsystem maintaining a shadow copy of its own state
// and keeping it consistent — a second source of truth, with the drift that
// implies. A collector reads the real one at scrape time instead.
type Collector func()

// New returns an empty registry.
func New() *Registry {
	return &Registry{
		MaxSeriesPerMetric: DefaultMaxSeriesPerMetric,
		families:           make(map[string]*Metric),
		dropped:            make(map[string]uint64),
	}
}

// Metric is one metric family: a name, a type, a fixed label schema, and the
// series observed for it so far.
type Metric struct {
	reg        *Registry
	name       string
	help       string
	typ        MetricType
	labelNames []string
	buckets    []float64 // histogram upper bounds, ascending, no +Inf
	maxSeries  int       // 0 = take the registry default

	mu       sync.RWMutex
	series   map[string]*series
	order    []string
	overflow *series
}

type series struct {
	labels []string

	// bits holds a float64 for counters and gauges. A CAS loop over the bit
	// pattern gives lock-free adds without a per-series mutex, which matters
	// because auth attempts and task transitions are hot enough that a
	// contended registry would show up as request latency.
	bits atomic.Uint64

	// Histogram state. counts is parallel to Metric.buckets.
	counts   []atomic.Uint64
	sum      atomic.Uint64 // float64 bits
	observed atomic.Uint64
}

// Definition declares a metric family.
type Definition struct {
	Name   string
	Help   string
	Type   MetricType
	Labels []string
	// Buckets are the histogram upper bounds in ascending order, excluding
	// +Inf which is implied. Ignored for counters and gauges.
	Buckets []float64
	// MaxSeries overrides Registry.MaxSeriesPerMetric for this metric. Zero
	// takes the registry default.
	//
	// Raising it is only defensible for a collector-backed gauge, because
	// those Reset before every scrape: their cardinality is the number of
	// objects alive at scrape time rather than the number ever observed, so
	// churn cannot accumulate series the way it does on a counter. A raised
	// ceiling on a counter is just a slower memory leak.
	MaxSeries int
}

// MustRegister declares a metric family and returns it, panicking on a
// malformed definition or a duplicate name.
//
// Panicking is right here and would be wrong almost anywhere else in cloop:
// the catalog is built at package initialisation from string literals, so a
// panic can only fire on a programming error that every single startup would
// hit. Returning an error would mean every call site handling a failure that
// cannot occur at runtime.
func (r *Registry) MustRegister(def Definition) *Metric {
	m, err := r.Register(def)
	if err != nil {
		panic("hubmetrics: " + err.Error())
	}
	return m
}

// Register declares a metric family.
func (r *Registry) Register(def Definition) (*Metric, error) {
	if !validMetricName(def.Name) {
		return nil, fmt.Errorf("invalid metric name %q", def.Name)
	}
	if strings.TrimSpace(def.Help) == "" {
		return nil, fmt.Errorf("metric %s: help text is required", def.Name)
	}
	switch def.Type {
	case TypeCounter, TypeGauge, TypeHistogram:
	default:
		return nil, fmt.Errorf("metric %s: unknown type %q", def.Name, def.Type)
	}
	seen := make(map[string]bool, len(def.Labels))
	for _, l := range def.Labels {
		if !validLabelName(l) {
			return nil, fmt.Errorf("metric %s: invalid label name %q", def.Name, l)
		}
		if l == "le" && def.Type == TypeHistogram {
			return nil, fmt.Errorf("metric %s: label %q is reserved for histogram buckets", def.Name, l)
		}
		if seen[l] {
			return nil, fmt.Errorf("metric %s: duplicate label %q", def.Name, l)
		}
		seen[l] = true
	}
	buckets := append([]float64(nil), def.Buckets...)
	if def.Type == TypeHistogram {
		if len(buckets) == 0 {
			return nil, fmt.Errorf("metric %s: histogram needs at least one bucket", def.Name)
		}
		for i := 1; i < len(buckets); i++ {
			if buckets[i] <= buckets[i-1] {
				return nil, fmt.Errorf("metric %s: buckets must ascend", def.Name)
			}
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.families[def.Name]; dup {
		return nil, fmt.Errorf("metric %s: already registered", def.Name)
	}
	m := &Metric{
		reg:        r,
		name:       def.Name,
		help:       def.Help,
		typ:        def.Type,
		labelNames: append([]string(nil), def.Labels...),
		buckets:    buckets,
		maxSeries:  def.MaxSeries,
		series:     make(map[string]*series),
	}
	r.families[def.Name] = m
	r.order = append(r.order, def.Name)
	return m, nil
}

// RegisterCollector adds a function run before each scrape. name appears in
// the panic-recovery path so a broken collector is identifiable.
func (r *Registry) RegisterCollector(name string, fn Collector) {
	if fn == nil {
		return
	}
	r.collectorMu.Lock()
	defer r.collectorMu.Unlock()
	r.collectors = append(r.collectors, namedCollector{name: name, fn: fn})
}

// Inc adds one to the counter or gauge identified by labelValues.
func (m *Metric) Inc(labelValues ...string) { m.Add(1, labelValues...) }

// Add adds delta to the counter or gauge identified by labelValues.
//
// A nil Metric is a no-op so a subsystem can hold an optional metric without
// guarding every call site, and a negative delta on a counter is dropped
// rather than applied: a counter that can go down breaks rate() in ways that
// surface as impossible graphs long after the bug that caused them.
func (m *Metric) Add(delta float64, labelValues ...string) {
	if m == nil || math.IsNaN(delta) {
		return
	}
	if m.typ == TypeCounter && delta < 0 {
		return
	}
	s := m.lookup(labelValues)
	if s == nil {
		return
	}
	addFloat(&s.bits, delta)
}

// Set assigns an absolute value to the gauge identified by labelValues.
func (m *Metric) Set(value float64, labelValues ...string) {
	if m == nil || math.IsNaN(value) {
		return
	}
	s := m.lookup(labelValues)
	if s == nil {
		return
	}
	s.bits.Store(math.Float64bits(value))
}

// Observe records one sample in the histogram identified by labelValues.
func (m *Metric) Observe(value float64, labelValues ...string) {
	if m == nil || m.typ != TypeHistogram || math.IsNaN(value) {
		return
	}
	s := m.lookup(labelValues)
	if s == nil {
		return
	}
	for i, ub := range m.buckets {
		if value <= ub {
			s.counts[i].Add(1)
		}
	}
	addFloat(&s.sum, value)
	s.observed.Add(1)
}

// Reset drops every series in the metric.
//
// Collector-backed gauges call this before repopulating, so a series whose
// underlying object is gone (a deregistered executor, a closed session) stops
// being exported rather than freezing at its last value. A frozen gauge is
// worse than a missing one: it reads as a live measurement and will hold an
// alert open forever.
func (m *Metric) Reset() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.series = make(map[string]*series)
	m.order = nil
	m.overflow = nil
	m.mu.Unlock()
}

// lookup resolves a label tuple to its series, creating it if the metric has
// cardinality budget left and folding into the overflow series if not.
func (m *Metric) lookup(labelValues []string) *series {
	if len(labelValues) != len(m.labelNames) {
		// A label-count mismatch is a programming error, but panicking
		// here would let a typo in a rarely-taken error path take down a
		// running hub. Route it to the overflow series instead: the
		// samples are preserved, they are visibly wrong, and the dropped
		// counter points at the metric.
		m.reg.noteDropped(m.name)
		return m.overflowSeries()
	}

	values := make([]string, len(labelValues))
	for i, v := range labelValues {
		values[i] = sanitizeLabelValue(v)
	}
	key := strings.Join(values, "\xff")

	m.mu.RLock()
	s := m.series[key]
	m.mu.RUnlock()
	if s != nil {
		return s
	}

	m.mu.Lock()
	if s = m.series[key]; s != nil {
		m.mu.Unlock()
		return s
	}
	max := m.maxSeries
	if max <= 0 {
		max = m.reg.MaxSeriesPerMetric
	}
	if max <= 0 {
		max = DefaultMaxSeriesPerMetric
	}
	if len(m.series) >= max {
		m.mu.Unlock()
		m.reg.noteDropped(m.name)
		return m.overflowSeries()
	}
	s = m.newSeries(values)
	m.series[key] = s
	m.order = append(m.order, key)
	m.mu.Unlock()
	return s
}

func (m *Metric) newSeries(values []string) *series {
	s := &series{labels: values}
	if m.typ == TypeHistogram {
		s.counts = make([]atomic.Uint64, len(m.buckets))
	}
	return s
}

// overflowSeries returns the shared fold-in series, which is exempt from the
// ceiling because it is what the ceiling redirects to.
func (m *Metric) overflowSeries() *series {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.overflow == nil {
		values := make([]string, len(m.labelNames))
		for i := range values {
			values[i] = overflowLabel
		}
		m.overflow = m.newSeries(values)
	}
	return m.overflow
}

func (r *Registry) noteDropped(metric string) {
	r.droppedMu.Lock()
	r.dropped[metric]++
	r.droppedMu.Unlock()
}

// SeriesCount reports how many distinct label combinations a metric holds,
// including the overflow series. Used by tests that assert the ceiling holds.
func (m *Metric) SeriesCount() int {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := len(m.series)
	if m.overflow != nil {
		n++
	}
	return n
}

// TotalSeries reports the registry's whole footprint in series.
func (r *Registry) TotalSeries() int {
	r.mu.RLock()
	families := make([]*Metric, 0, len(r.families))
	for _, m := range r.families {
		families = append(families, m)
	}
	r.mu.RUnlock()
	total := 0
	for _, m := range families {
		total += m.SeriesCount()
	}
	return total
}

// runCollectors refreshes derived gauges, isolating each from the others.
//
// A collector reads live subsystem state, so it can panic on a nil store or a
// half-initialised registry that a hub in a degraded state might present. One
// broken collector must not blank the whole scrape: the surviving metrics are
// exactly what an operator diagnosing that degraded state needs.
func (r *Registry) runCollectors() {
	r.collectorMu.Lock()
	defer r.collectorMu.Unlock()
	for _, c := range r.collectors {
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					r.noteDropped("collector:" + c.name)
				}
			}()
			c.fn()
		}()
	}
}

// WriteTo renders the registry in the Prometheus text exposition format
// (version 0.0.4), running collectors first.
//
// Families are emitted in registration order and series within a family in
// sorted label order, so a scrape is byte-stable when nothing changed. That
// makes diffs between scrapes meaningful and keeps the golden-file tests from
// depending on Go's map iteration order.
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	r.runCollectors()

	var b strings.Builder
	r.mu.RLock()
	order := append([]string(nil), r.order...)
	families := make(map[string]*Metric, len(r.families))
	for k, v := range r.families {
		families[k] = v
	}
	r.mu.RUnlock()

	for _, name := range order {
		families[name].writeTo(&b)
	}
	r.writeDropped(&b)

	n, err := io.WriteString(w, b.String())
	return int64(n), err
}

// Gather renders the registry to a string.
func (r *Registry) Gather() string {
	var b strings.Builder
	_, _ = r.WriteTo(&b)
	return b.String()
}

func (m *Metric) writeTo(b *strings.Builder) {
	m.mu.RLock()
	keys := append([]string(nil), m.order...)
	snapshot := make([]*series, 0, len(keys)+1)
	for _, k := range keys {
		snapshot = append(snapshot, m.series[k])
	}
	if m.overflow != nil {
		snapshot = append(snapshot, m.overflow)
	}
	m.mu.RUnlock()

	// A family with no observations is still emitted with HELP and TYPE.
	// An absent metric and a zero metric are different diagnoses — "the
	// build predates this counter" versus "nothing has happened" — and a
	// dashboard panel that renders "No data" for the second is a false
	// alarm an operator has to chase.
	fmt.Fprintf(b, "# HELP %s %s\n", m.name, escapeHelp(m.help))
	fmt.Fprintf(b, "# TYPE %s %s\n", m.name, m.typ)

	sort.Slice(snapshot, func(i, j int) bool {
		return lessLabels(snapshot[i].labels, snapshot[j].labels)
	})

	for _, s := range snapshot {
		if m.typ == TypeHistogram {
			m.writeHistogram(b, s)
			continue
		}
		fmt.Fprintf(b, "%s%s %s\n",
			m.name, renderLabels(m.labelNames, s.labels, "", ""),
			formatValue(math.Float64frombits(s.bits.Load())))
	}
	b.WriteString("\n")
}

func (m *Metric) writeHistogram(b *strings.Builder, s *series) {
	var cumulative uint64
	for i, ub := range m.buckets {
		cumulative = s.counts[i].Load()
		fmt.Fprintf(b, "%s_bucket%s %d\n",
			m.name, renderLabels(m.labelNames, s.labels, "le", formatValue(ub)), cumulative)
	}
	total := s.observed.Load()
	fmt.Fprintf(b, "%s_bucket%s %d\n",
		m.name, renderLabels(m.labelNames, s.labels, "le", "+Inf"), total)
	fmt.Fprintf(b, "%s_sum%s %s\n",
		m.name, renderLabels(m.labelNames, s.labels, "", ""),
		formatValue(math.Float64frombits(s.sum.Load())))
	fmt.Fprintf(b, "%s_count%s %d\n",
		m.name, renderLabels(m.labelNames, s.labels, "", ""), total)
}

func (r *Registry) writeDropped(b *strings.Builder) {
	r.droppedMu.Lock()
	names := make([]string, 0, len(r.dropped))
	for k := range r.dropped {
		names = append(names, k)
	}
	sort.Strings(names)
	vals := make([]uint64, len(names))
	for i, n := range names {
		vals[i] = r.dropped[n]
	}
	r.droppedMu.Unlock()

	b.WriteString("# HELP cloop_metrics_series_dropped_total Label combinations refused by the per-metric cardinality ceiling. Non-zero means a metric is being labelled with unbounded values and its samples are folding into one overflow series.\n")
	b.WriteString("# TYPE cloop_metrics_series_dropped_total counter\n")
	for i, n := range names {
		fmt.Fprintf(b, "cloop_metrics_series_dropped_total{metric=\"%s\"} %d\n", escapeLabelValue(n), vals[i])
	}
	b.WriteString("\n")
}

// renderLabels builds the {k="v",...} block, optionally appending one extra
// label (used for the histogram "le" dimension, which must come last).
func renderLabels(names, values []string, extraName, extraValue string) string {
	if len(names) == 0 && extraName == "" {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, n := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		v := ""
		if i < len(values) {
			v = values[i]
		}
		fmt.Fprintf(&b, "%s=\"%s\"", n, escapeLabelValue(v))
	}
	if extraName != "" {
		if len(names) > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%s=\"%s\"", extraName, escapeLabelValue(extraValue))
	}
	b.WriteByte('}')
	return b.String()
}

func lessLabels(a, b []string) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// addFloat performs an atomic floating-point add via CAS on the bit pattern.
func addFloat(dst *atomic.Uint64, delta float64) {
	for {
		old := dst.Load()
		next := math.Float64bits(math.Float64frombits(old) + delta)
		if dst.CompareAndSwap(old, next) {
			return
		}
	}
}

// formatValue renders a float in a form Prometheus parses. Integers print
// without a decimal point, +Inf/-Inf/NaN use the spelling the format requires.
func formatValue(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	case v == math.Trunc(v) && math.Abs(v) < 1e15:
		return strconv.FormatFloat(v, 'f', -1, 64)
	default:
		return strconv.FormatFloat(v, 'g', -1, 64)
	}
}

// escapeLabelValue escapes per the exposition format. Even though label values
// are supposed to come from source enumerations, escaping is not optional: an
// unescaped quote or newline in a label would let the value inject whole
// metric lines into the scrape, which is log injection with a Prometheus
// database on the receiving end.
func escapeLabelValue(v string) string {
	if !strings.ContainsAny(v, "\\\"\n") {
		return v
	}
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v)
}

// escapeHelp escapes HELP text, where only backslash and newline are special.
func escapeHelp(v string) string {
	if !strings.ContainsAny(v, "\\\n") {
		return v
	}
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(v)
}

// sanitizeLabelValue normalises a label value before it becomes part of a
// series identity: empty reads as "unknown" so a missing enumeration value is
// distinguishable from a label that was never set, and length is capped so a
// value that escaped the enumeration rule cannot also be large.
func sanitizeLabelValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "unknown"
	}
	if len(v) > maxLabelValueLen {
		v = v[:maxLabelValueLen]
	}
	return v
}

func validMetricName(s string) bool {
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

func validLabelName(s string) bool {
	if s == "" || strings.HasPrefix(s, "__") {
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
