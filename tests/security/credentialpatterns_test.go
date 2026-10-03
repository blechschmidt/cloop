package security

// Guarantee 15: every credential scanner in cloop recognises the same
// credentials, and leaves the same ordinary output alone.
//
// Four places look for credentials nobody told them about, because they handle
// text whose secrets they cannot know in advance:
//
//	cloop audit                 scans .cloop/ history and task artifacts, reports
//	the provider-call audit     scrubs a provider's error before it is stored
//	the secret broker           scrubs every audit reason before it is emitted
//	browser telemetry           scrubs every field before it is stored
//
// They used to keep four lists. The audit's GitHub regexes had never heard of
// gho_, ghu_ or ghr_, and could not match an installation token minted since
// September 2026 — 390 characters, an underscore seven in — so cloop audit
// reported a clean history over a real leak. Telemetry knew only cloop's own
// two prefixes and stored a browser error carrying a GitHub token verbatim. The
// broker knew none of cloop's prefixes at all.
//
// Now there is one registry, pkg/redact's, and one corpus, pkg/redact/redacttest,
// and this file runs every scanner over every fixture. A scanner that misses a
// credential fails here naming itself and the fixture; a scanner that rewrites
// a commit hash, a UUID or a base64 blob in a diff fails here too, because a
// marker over ordinary output teaches a reader to ignore markers.
//
// Exact-value redaction — the lease's own material, matched by a redact.Set —
// stays the primary defence and is asserted in redaction_test.go. These
// patterns are the backstop for text that never passed through a Set.

import (
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/audit"
	"github.com/blechschmidt/cloop/pkg/provideraudit"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/redact/redacttest"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/telemetry"
)

// patternScanner is one of the four, reduced to what it does with text.
type patternScanner struct {
	name string
	// redact returns the text as the scanner would store it, or is nil for a
	// scanner that only reports.
	redact func(string) string
	// marker is what redact leaves where a credential was.
	marker string
	// detect returns the detectors the scanner reports, or is nil for a
	// scanner that only redacts.
	detect func(string) []string
}

func patternScanners() []patternScanner {
	return []patternScanner{
		{name: "cloop-audit", detect: audit.Leaks},
		{name: "provider-call-audit", redact: provideraudit.RedactErrorMessage, marker: "[REDACTED]"},
		{name: "secret-broker-audit", marker: "[redacted]", redact: func(s string) string {
			// Through Redact(Event), the call every emission makes, not just
			// the string helper beneath it.
			return secretbroker.Redact(secretbroker.Event{Action: secretbroker.ActionLease, Reason: s}).Reason
		}},
		{name: "browser-telemetry", redact: telemetry.Scrub, marker: "[redacted]"},
	}
}

// TestEveryScannerCoversEveryCredential is the conformance run.
func TestEveryScannerCoversEveryCredential(t *testing.T) {
	positives := redacttest.Positives()
	if len(positives) < len(redact.Detectors()) {
		t.Fatalf("%d fixtures for %d detectors: the corpus cannot cover the registry", len(positives), len(redact.Detectors()))
	}
	for _, sc := range patternScanners() {
		for _, p := range positives {
			t.Run(sc.name+"/"+p.Name, func(t *testing.T) {
				if sc.detect != nil {
					if got := sc.detect(p.Text); !slices.Contains(got, p.Detector) {
						t.Errorf("%s does not report %s in this text; it reported %v", sc.name, p.Detector, got)
					}
				}
				if sc.redact == nil {
					return
				}
				got := sc.redact(p.Text)
				for _, s := range p.Secrets {
					if strings.Contains(got, s) {
						t.Errorf("%s stores the credential:\n%s", sc.name, preview(got))
					}
				}
				if !strings.Contains(got, sc.marker) {
					t.Errorf("%s left no %s marker, so nothing shows a credential was removed:\n%s", sc.name, sc.marker, preview(got))
				}
				for _, k := range p.Keep {
					if !strings.Contains(got, k) {
						t.Errorf("%s destroyed %q along with the credential:\n%s", sc.name, k, preview(got))
					}
				}
				if again := sc.redact(got); again != got {
					t.Errorf("%s changes its own output on a second pass — the broker's store "+
						"scrubs every reason twice:\n first: %s\nsecond: %s", sc.name, preview(got), preview(again))
				}
			})
		}
	}
}

// TestNoScannerTouchesOrdinaryOutput is the other half: base64 in a diff,
// commit SHAs, UUIDs, digests, metric and nftables names, prose about token
// formats, placeholders, and the scanners' own markers.
func TestNoScannerTouchesOrdinaryOutput(t *testing.T) {
	for _, sc := range patternScanners() {
		for _, n := range redacttest.Negatives() {
			t.Run(sc.name+"/"+n.Name, func(t *testing.T) {
				if sc.detect != nil {
					if got := sc.detect(n.Text); len(got) > 0 {
						t.Errorf("%s reports %v in ordinary output:\n%s", sc.name, got, preview(n.Text))
					}
				}
				if sc.redact != nil {
					if got := sc.redact(n.Text); got != n.Text {
						t.Errorf("%s rewrote ordinary output:\n  in: %s\n out: %s", sc.name, preview(n.Text), preview(got))
					}
				}
			})
		}
	}
}

// TestEveryDetectorIsHeldToTheCorpus: the run above only means something for
// detectors that have a fixture. A detector added to the registry without one
// would be shared by every scanner and checked by none.
func TestEveryDetectorIsHeldToTheCorpus(t *testing.T) {
	covered := map[string]bool{}
	for _, p := range redacttest.Positives() {
		covered[p.Detector] = true
	}
	for _, d := range redact.Detectors() {
		if !covered[d.Name] {
			t.Errorf("detector %s has no fixture in pkg/redact/redacttest", d.Name)
		}
	}
}

// TestTelemetryIngestStoresNoCorpusCredential drives the ingest path rather
// than Scrub alone: Normalize also strips control characters and clamps, and
// a credential must not survive in any field, whichever the page put it in.
func TestTelemetryIngestStoresNoCorpusCredential(t *testing.T) {
	for _, p := range redacttest.Positives() {
		evs := telemetry.Normalize(telemetry.Batch{Session: "s", Events: []telemetry.WireEvent{{
			Kind: "fetch", Seq: 1,
			Message: p.Text, Stack: p.Text, URL: p.Text, Detail: p.Text,
		}}}, telemetry.Context{Source: telemetry.SourceGlasses})
		if len(evs) != 1 {
			t.Fatalf("%s: got %d events, want 1", p.Name, len(evs))
		}
		e := evs[0]
		for _, f := range []struct{ name, val string }{
			{"message", e.Message}, {"stack", e.Stack}, {"url", e.URL}, {"detail", e.Detail},
		} {
			for _, s := range p.Secrets {
				// A field clamped short of the secret holds a prefix of it,
				// which identifies the credential as surely as the whole.
				if strings.Contains(f.val, s) || (len(s) > 24 && strings.Contains(f.val, s[:24])) {
					t.Errorf("%s: the %s field stores the credential:\n%s", p.Name, f.name, preview(f.val))
				}
			}
		}
	}
}

// TestCloopAuditFindsALongFormInstallationTokenInHistory is the defect, end to
// end: a real repository, a .cloop/config.yaml committed with a long-form
// installation token in it and then "fixed" by a second commit, and the real
// cloop audit check over the real git log. Before the registry this reported
// ".cloop/ git history contains no detected API key patterns".
func TestCloopAuditFindsALongFormInstallationTokenInHistory(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	// gitIn closes git's configuration for the commands this test runs; the
	// scan runs git in this process's environment, so close it there too.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")

	r := rand.New(rand.NewPCG(redacttest.Seed, 17))
	tok := redacttest.GitHubLongFormToken(r, "ghs_", '-')

	repo := t.TempDir()
	cfg := filepath.Join(repo, ".cloop", "config.yaml")
	gitIn(t, repo, "init", "-q")
	writeInto(t, cfg, "provider: claudecode\ngithub:\n  token: "+tok+"\n")
	gitIn(t, repo, "add", ".cloop/config.yaml")
	gitIn(t, repo, "commit", "-q", "-m", "configure github")
	writeInto(t, cfg, "provider: claudecode\n")
	gitIn(t, repo, "commit", "-q", "-am", "remove the token")

	findings, err := audit.Audit(repo, nil, audit.DefaultOptions())
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	var history *audit.Finding
	for i := range findings {
		if findings[i].Name == "Credentials in git history" {
			history = &findings[i]
		}
	}
	if history == nil {
		t.Fatalf("the git-history check reported nothing; findings: %+v", findings)
	}
	if history.Level != audit.Fail || !strings.Contains(history.Message, "GitHub token (long form)") {
		t.Errorf("a long-form installation token in .cloop/ history was not reported as one: %+v", *history)
	}
	if strings.Contains(history.Message, tok[:24]) || strings.Contains(history.Fix, tok[:24]) {
		t.Errorf("the finding prints the credential it found: %+v", *history)
	}

	// The same history with nothing in it must come back clean, or the
	// failure above proves only that the check always fails.
	clean := t.TempDir()
	gitIn(t, clean, "init", "-q")
	var negatives strings.Builder
	for _, n := range redacttest.Negatives() {
		negatives.WriteString(n.Text + "\n")
	}
	writeInto(t, filepath.Join(clean, ".cloop", "notes.md"), negatives.String())
	gitIn(t, clean, "add", ".cloop")
	gitIn(t, clean, "commit", "-q", "-m", "notes")
	findings, err = audit.Audit(clean, nil, audit.DefaultOptions())
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	for _, f := range findings {
		if f.Name == "Credentials in git history" && f.Level != audit.Pass {
			t.Errorf("a history of ordinary output was flagged: %+v", f)
		}
	}
}
