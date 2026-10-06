package hubdoctor

// What the configuration loader changed.
//
// config.Load does not refuse a value it cannot honour: it repairs it — resets
// an out-of-range number to its default, or switches off a section that could
// only start unusable or unsafe — and says so once, on stderr, which for a
// service is a journal nobody reads. Everything else in this report then looks
// at the repaired result. A git proxy the loader switched off reads as
// "disabled", exactly like one an operator never enabled, and a section that
// had failed outright reads as a deliberate choice (Task 20387).
//
// So the loader records its repairs (config.LoadRepair) and this reports them:
// a value it reset as a warning — the hub works, not as written — and a
// section it switched off as a failure, because the operator asked for a
// control or a capability that is not running. The three sections with checks
// of their own report their switch-off there, in the terms of what the hub does
// without them.

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
)

// sectionsWithOwnCheck report their own switch-off: see switchedOffFinding.
var sectionsWithOwnCheck = map[string]bool{
	"executors.git_proxy":  true,
	"executors.kube_guard": true,
	"executors.egress":     true,
}

func checkLoadRepairs(cfg *config.Config, add addFn) {
	repairs := cfg.LoadRepairs()
	// A section switched off is one finding, its switch-off, which lists the
	// problems loading found in it; the same problems as value repairs would
	// say the hub runs with a repaired value of a section it runs without.
	off := map[string]bool{}
	for _, r := range repairs {
		if r.SwitchedOff != "" {
			off[r.SwitchedOff] = true
		}
	}
	inSwitchedOff := func(field string) bool {
		for section := range off {
			if field == section || strings.HasPrefix(field, section+".") {
				return true
			}
		}
		return false
	}
	for _, r := range repairs {
		if r.SwitchedOff == "" && inSwitchedOff(r.Field) {
			continue
		}
		if r.SwitchedOff != "" {
			if sectionsWithOwnCheck[r.SwitchedOff] {
				continue
			}
			add(Finding{
				Check: "config.repaired", Title: "Section switched off at load", Severity: SeverityFail,
				Message: fmt.Sprintf("%s is enabled in %s, but %s — the hub runs without it",
					r.SwitchedOff, r.File, r.Detail),
				Remediation: fmt.Sprintf("Correct the values named in %s; %s stays off until they load",
					r.File, r.SwitchedOff),
				Details: map[string]any{"file": r.File, "section": r.SwitchedOff},
			})
			continue
		}
		add(Finding{
			Check: "config.repaired", Title: "Value repaired at load", Severity: SeverityWarn,
			Message: fmt.Sprintf("%s in %s: %s; the hub runs with the repaired value, not the one written",
				r.Field, r.File, r.Detail),
			Remediation: fmt.Sprintf("Correct %s in %s", r.Field, r.File),
			Details:     map[string]any{"file": r.File, "field": r.Field},
		})
	}
}

// switchedOffFinding is the finding for a section the loader switched off,
// reported under the section's own check id, or false when it was not.
// consequence says what the hub does without the section, in a clause.
func switchedOffFinding(cfg *config.Config, section, check, title, consequence string) (Finding, bool) {
	for _, r := range cfg.LoadRepairs() {
		if r.SwitchedOff != section {
			continue
		}
		return Finding{
			Check: check, Title: title, Severity: SeverityFail,
			Message: fmt.Sprintf("%s is enabled in %s, but %s — so %s",
				section, r.File, r.Detail, consequence),
			Remediation: fmt.Sprintf("Correct the values named in %s; the section stays off until they load",
				r.File),
			Details: map[string]any{"file": r.File, "section": section},
		}, true
	}
	return Finding{}, false
}
