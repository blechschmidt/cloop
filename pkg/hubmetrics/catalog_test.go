package hubmetrics

// Tests over the shipped catalog rather than the registry mechanism.
//
// These are guard tests: they encode the rules the package doc states as prose
// so that breaking one is a build failure instead of a code-review miss. The
// cardinality ceiling is the backstop for when review fails; this file is an
// earlier and much louder one, because a metric that violates the rules fails
// here at `go test` rather than silently folding into __overflow__ on a
// production hub three weeks later.
//
// They run against the package-level Default registry and therefore do not use
// t.Parallel(): Default is process-global shared state, and a collector
// installed by one test is visible to every other.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// catalogNames lists every family the default registry exports, which is the
// operator-visible surface — exactly what the rules below should apply to.
func catalogNames(t *testing.T) []string {
	t.Helper()

	Default.mu.RLock()
	defer Default.mu.RUnlock()
	out := append([]string(nil), Default.order...)
	sort.Strings(out)
	return out
}

func catalogLabels(t *testing.T, name string) []string {
	t.Helper()

	Default.mu.RLock()
	defer Default.mu.RUnlock()
	m, ok := Default.families[name]
	if !ok {
		t.Fatalf("no metric %s in the catalog", name)
	}
	return append([]string(nil), m.labelNames...)
}

func catalogType(t *testing.T, name string) MetricType {
	t.Helper()

	Default.mu.RLock()
	defer Default.mu.RUnlock()
	return Default.families[name].typ
}

// TestCatalogIsNonEmpty guards against the catalog's package-level vars being
// dropped wholesale — every other test here would pass vacuously.
func TestCatalogIsNonEmpty(t *testing.T) {
	if got := len(catalogNames(t)); got < 25 {
		t.Errorf("the catalog declares %d metrics, which is fewer than the "+
			"subsystems that are supposed to be instrumented", got)
	}
}

// TestDefaultCatalogGathersAsValidPrometheusText scrapes the real registry
// with no samples recorded. Every family must still declare itself, and the
// whole payload must parse.
func TestDefaultCatalogGathersAsValidPrometheusText(t *testing.T) {
	out := Default.Gather()
	fams := parseExposition(t, out)

	for _, name := range catalogNames(t) {
		if fams[name] == nil {
			t.Errorf("%s is registered but absent from the scrape", name)
			continue
		}
		if fams[name].typ == "" {
			t.Errorf("%s emitted no TYPE line", name)
		}
	}
}

// TestCatalogNamingConventions. A counter that does not end in _total is a
// counter an operator will graph with the wrong function.
func TestCatalogNamingConventions(t *testing.T) {
	for _, name := range catalogNames(t) {
		if !strings.HasPrefix(name, "cloop_") {
			t.Errorf("%s does not carry the cloop_ prefix, so it collides with "+
				"whatever else the operator scrapes", name)
		}
		switch catalogType(t, name) {
		case TypeCounter:
			if !strings.HasSuffix(name, "_total") {
				t.Errorf("counter %s does not end in _total", name)
			}
		case TypeGauge:
			if strings.HasSuffix(name, "_total") {
				t.Errorf("gauge %s ends in _total, which reads as a counter", name)
			}
		case TypeHistogram:
			if strings.HasSuffix(name, "_total") {
				t.Errorf("histogram %s ends in _total", name)
			}
			// A histogram of durations should say so in its name, since
			// the unit is not otherwise recoverable from a scrape.
			if !strings.HasSuffix(name, "_seconds") && !strings.HasSuffix(name, "_bytes") {
				t.Errorf("histogram %s names no unit", name)
			}
		}
	}
}

func TestCatalogHelpTextIsUsable(t *testing.T) {
	for _, name := range catalogNames(t) {
		Default.mu.RLock()
		help := Default.families[name].help
		Default.mu.RUnlock()

		if len(help) < 20 {
			t.Errorf("%s has help text %q, too terse to orient an operator who "+
				"met this metric in an alert at 3am", name, help)
		}
		if strings.Contains(help, "\n") {
			t.Errorf("%s help text contains a newline", name)
		}
	}
}

// TestCatalogHasNoUnboundedLabels is the important one.
//
// The package's central rule is that label values come from closed
// enumerations declared in source, never from user or tenant input. Labelling
// by a per-object or per-tenant identity turns tenant activity into hub
// memory, which on a hosted hub is a denial of service any signed-in user can
// trigger by creating projects in a loop. This test refuses the label names
// that carry those identities.
func TestCatalogHasNoUnboundedLabels(t *testing.T) {
	// Substrings that indicate a per-object, per-tenant or per-request
	// identity rather than an enumeration.
	forbidden := []string{
		"task", "project", "subject", "executor_id", "branch", "commit",
		"sha", "host", "user", "email", "path", "url", "ip", "addr",
		"session", "token", "repo", "name", "id",
	}

	// The one documented exception, and the reason it is safe: both gauges
	// Reset before every scrape, so their cardinality is the number of
	// identities the hub is accounting right now rather than the number it
	// has ever seen. A tenant cannot grow them by churning. Both also carry
	// a raised-but-finite MaxSeries.
	resetEachScrape := map[string]bool{
		"cloop_quota_limit": true,
		"cloop_quota_usage": true,
	}

	for _, name := range catalogNames(t) {
		for _, label := range catalogLabels(t, name) {
			if label == "identity" && resetEachScrape[name] {
				continue
			}
			for _, bad := range forbidden {
				if !strings.Contains(label, bad) {
					continue
				}
				t.Errorf("%s labels by %q, which looks like a per-object or "+
					"per-tenant identity rather than a closed enumeration.\n"+
					"Every distinct value is a series that lives until the "+
					"process exits. Aggregate instead, or use a "+
					"collector-backed gauge that Resets each scrape.",
					name, label)
			}
		}
	}
}

// TestQuotaIdentityGaugesAreCapped — the exception above is only safe while it
// stays bounded, so the bound is asserted rather than assumed.
func TestQuotaIdentityGaugesAreCapped(t *testing.T) {
	for _, name := range []string{"cloop_quota_limit", "cloop_quota_usage"} {
		Default.mu.RLock()
		m := Default.families[name]
		Default.mu.RUnlock()

		if m.maxSeries <= 0 {
			t.Errorf("%s labels by identity but takes the registry default ceiling", name)
		}
		if m.maxSeries != quotaIdentityCeiling {
			t.Errorf("%s MaxSeries = %d, want %d", name, m.maxSeries, quotaIdentityCeiling)
		}
		if m.typ != TypeGauge {
			t.Errorf("%s is %s; the identity label is only defensible on a "+
				"gauge, because only a gauge is Reset each scrape", name, m.typ)
		}
	}
}

// TestCatalogIsDocumented is the gate the catalog's own header promises.
//
// It checks drift in both directions: a metric the hub exports but the runbook
// does not describe is one an operator meets for the first time in an alert,
// and a metric the runbook describes but the hub no longer exports is worse —
// it sends them looking for a series that will never arrive.
func TestCatalogIsDocumented(t *testing.T) {
	const doc = "../../docs/operations/metrics.md"

	body, err := os.ReadFile(doc)
	if err != nil {
		t.Fatalf("reading %s: %v\n"+
			"catalog.go tells contributors this file documents every metric.",
			filepath.Clean(doc), err)
	}
	text := string(body)

	// What the hub exports is what a scrape contains, which is the catalog
	// plus the registry's own cloop_metrics_series_dropped_total. Deriving
	// the set from a rendered scrape rather than from the catalog vars is
	// what makes both directions of this check answer the operator's
	// question — "will this series arrive?" — instead of an internal one.
	exported := parseExposition(t, Default.Gather())

	for name := range exported {
		if !strings.Contains(text, name) {
			t.Errorf("%s is exported but not documented in %s", name, doc)
		}
	}

	// The reverse direction. Only names carrying the catalog's prefix are
	// considered, so prose or a PromQL example naming something else does
	// not trip it.
	mentioned := regexp.MustCompile(`cloop_[a-z0-9_]+`)
	for _, m := range mentioned.FindAllString(text, -1) {
		// A real metric name never ends in an underscore; a match that
		// does is the regex having run into punctuation, as in the
		// `cloop_pat_...` token example.
		if strings.HasSuffix(m, "_") {
			continue
		}
		if exported[m] != nil {
			continue
		}
		// Histogram sample names are derived, not registered.
		base := m
		for _, suffix := range []string{"_bucket", "_sum", "_count"} {
			base = strings.TrimSuffix(base, suffix)
		}
		if exported[base] != nil {
			continue
		}
		t.Errorf("%s documents %s, which the hub does not export", doc, m)
	}
}

// TestRegisterCollectorsInstallsAtMostOnce.
//
// pkg/ui constructs a Server per test and there are hundreds of them. Without
// the sync.Once each would stack another copy of every collector onto the
// process registry, and each copy would run on every scrape — so a gauge that
// Adds rather than Sets would read several hundred times its true value.
func TestRegisterCollectorsInstallsAtMostOnce(t *testing.T) {
	first, second := 0, 0

	RegisterCollectors(map[string]Collector{
		"test-first": func() { first++ },
	})
	RegisterCollectors(map[string]Collector{
		"test-second": func() { second++ },
	})

	Default.Gather()
	Default.Gather()

	if first != 2 {
		t.Errorf("the first collector ran %d times across 2 scrapes, want 2", first)
	}
	if second != 0 {
		t.Errorf("a second RegisterCollectors call installed %d collectors; "+
			"the sync.Once is supposed to make every call after the first a no-op", second)
	}
}
