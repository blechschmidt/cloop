package version

import (
	"strings"
	"testing"
)

// TestVersionStaysLinkerStampable is the guard on this package's one structural
// requirement. `go doc -all` cannot express "initialised to a constant", and
// the failure mode if someone changes it is silent: -X keeps succeeding and the
// stamp keeps being ignored, so every release would report "dev".
//
// The check is indirect but real — if Version were computed, its value here
// could not be the untouched default under `go test`, which never stamps.
func TestVersionStaysLinkerStampable(t *testing.T) {
	if Version != DevVersion {
		t.Fatalf("Version = %q under go test, want %q; it must be a plain var "+
			"initialised to a constant so -ldflags -X can patch it", Version, DevVersion)
	}
}

func TestParseRejectsNonVersions(t *testing.T) {
	// Each of these has been observed or is plausible on the wire, and each
	// would produce a wrong answer if parsed optimistically.
	for _, in := range []string{
		"", "dev", "dev+g4f7b5bc", "dev+g4f7b5bc.dirty",
		LegacyAgentVersion, // the frozen "1" — must NOT read as 1.0.0
		"1.2", "v1", "latest", "v1.2.x", "v-1.2.3", "1.2.3.4",
	} {
		if _, ok := parse(in); ok {
			t.Errorf("parse(%q) succeeded; want refusal", in)
		}
	}
}

func TestParseAcceptsReleases(t *testing.T) {
	for _, in := range []string{"v0.0.1", "0.0.1", "v1.2.3", "v1.2.3-rc1", "v1.2.3+meta"} {
		if _, ok := parse(in); !ok {
			t.Errorf("parse(%q) failed; want success", in)
		}
	}
}

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"v0.0.1", "v0.0.1", 0, true},
		{"v0.0.1", "v0.0.2", -1, true},
		{"v0.1.0", "v0.0.9", 1, true},
		{"v2.0.0", "v1.9.9", 1, true},
		{"1.2.3", "v1.2.3", 0, true},
		// A prerelease precedes its release.
		{"v1.2.3-rc1", "v1.2.3", -1, true},
		{"v1.2.3", "v1.2.3-rc1", 1, true},
		// Build metadata is not ordering information.
		{"v1.2.3+a", "v1.2.3+b", 0, true},
		// Not comparable — callers must not read 0 as "same build".
		{"dev", "v1.2.3", 0, false},
		{LegacyAgentVersion, "v0.0.1", 0, false},
		{"", "", 0, false},
	}
	for _, tc := range tests {
		got, ok := Compare(tc.a, tc.b)
		if got != tc.want || ok != tc.ok {
			t.Errorf("Compare(%q,%q) = (%d,%v), want (%d,%v)", tc.a, tc.b, got, ok, tc.want, tc.ok)
		}
	}
}

// TestClassifyLegacySentinelIsNotNewerThanHub is the regression test for the
// bug that motivated recognising LegacyAgentVersion at all: the fleet's oldest
// agents report "1", and a naive semver parse ranks that above the hub's
// v0.0.1, so the one device most in need of an upgrade would be reported as
// being ahead of its control plane.
func TestClassifyLegacySentinelIsNotNewerThanHub(t *testing.T) {
	skew, note := Classify("v0.0.1", LegacyAgentVersion)
	if skew != SkewLegacy {
		t.Fatalf("Classify(hub=v0.0.1, agent=%q) = %q, want %q",
			LegacyAgentVersion, skew, SkewLegacy)
	}
	if skew == SkewAhead {
		t.Fatal("legacy sentinel classified as ahead of the hub")
	}
	if !skew.Material() {
		t.Error("a legacy build should be flagged as material skew")
	}
	if note == "" {
		t.Error("legacy skew must carry an operator-facing note")
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name       string
		hub, agent string
		want       Skew
		material   bool
	}{
		{"identical release", "v1.2.3", "v1.2.3", SkewNone, false},
		{"identical dev build", "dev+gabc1234", "dev+gabc1234", SkewNone, false},
		{"patch drift is tolerated", "v1.2.3", "v1.2.1", SkewPatch, false},
		{"minor gap is material", "v1.3.0", "v1.2.9", SkewBehind, true},
		{"major gap is material", "v2.0.0", "v1.9.9", SkewBehind, true},
		{"agent ahead of hub", "v1.2.3", "v1.3.0", SkewAhead, true},
		{"agent reported nothing", "v1.2.3", "", SkewUnknown, false},
		{"legacy sentinel", "v1.2.3", LegacyAgentVersion, SkewLegacy, true},
		{"agent is a dev build", "v1.2.3", "dev+gabc1234", SkewUnversioned, true},
		{"hub is a dev build", "dev", "v1.2.3", SkewUnversioned, true},
		{"agent version is gibberish", "v1.2.3", "nightly", SkewUnversioned, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, note := Classify(tc.hub, tc.agent)
			if got != tc.want {
				t.Fatalf("Classify(%q,%q) = %q, want %q", tc.hub, tc.agent, got, tc.want)
			}
			if got.Material() != tc.material {
				t.Errorf("%q.Material() = %v, want %v", got, got.Material(), tc.material)
			}
			// Every classification an operator is meant to act on must say
			// something; SkewNone must stay silent so the panel is not noisy.
			switch {
			case got == SkewNone && note != "":
				t.Errorf("SkewNone carried a note: %q", note)
			case got != SkewNone && strings.TrimSpace(note) == "":
				t.Errorf("%q carried no note", got)
			}
		})
	}
}

// TestClassifyNeverNamesTheNonexistentFlag is the guard against reintroducing
// the defect this work fixed: the panel told operators to run
// `cloop executor agent install --upgrade` when no such flag existed.
//
// It is asserted here rather than only at the UI because this is now where skew
// prose is written, and a message is the kind of thing that gets helpfully
// "improved" back into a dead end.
func TestClassifyNeverNamesTheNonexistentFlag(t *testing.T) {
	for _, agent := range []string{"", LegacyAgentVersion, "v0.0.1", "dev", "nonsense", "v9.9.9"} {
		_, note := Classify("v1.2.3", agent)
		if strings.Contains(note, "--upgrade") {
			t.Errorf("Classify note for agent %q names a flag: %q\n"+
				"Skew prose must not hardcode a remediation command; the caller owns that.",
				agent, note)
		}
	}
}

func TestResolveEnrichesDevBuildsOnly(t *testing.T) {
	vcs := func(rev string, dirty bool) func() (map[string]string, bool) {
		return func() (map[string]string, bool) {
			m := map[string]string{"vcs.revision": rev}
			if dirty {
				m["vcs.modified"] = "true"
			}
			return m, true
		}
	}
	none := func() (map[string]string, bool) { return nil, false }

	tests := []struct {
		name    string
		stamped string
		build   func() (map[string]string, bool)
		want    string
	}{
		{"release ignores vcs", "v1.2.3", vcs("4f7b5bcdeadbeef", true), "v1.2.3"},
		{"dev gains short revision", DevVersion, vcs("4f7b5bcdeadbeef", false), "dev+g4f7b5bc"},
		{"dirty tree is marked", DevVersion, vcs("4f7b5bcdeadbeef", true), "dev+g4f7b5bc.dirty"},
		{"no build info degrades quietly", DevVersion, none, DevVersion},
		{"no revision degrades quietly", DevVersion, vcs("", false), DevVersion},
		{"empty stamp is dev", "  ", none, DevVersion},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolve(tc.stamped, tc.build); got != tc.want {
				t.Errorf("resolve(%q) = %q, want %q", tc.stamped, got, tc.want)
			}
		})
	}
}

// TestStringIsStableAndNonEmpty covers the property every caller relies on: an
// agent must always have something to report. A hello frame with an empty
// version is indistinguishable from a pre-reporting agent.
func TestStringIsStableAndNonEmpty(t *testing.T) {
	first := String()
	if strings.TrimSpace(first) == "" {
		t.Fatal("String() returned empty; an agent would report no version at all")
	}
	if second := String(); second != first {
		t.Errorf("String() not stable: %q then %q", first, second)
	}
}
