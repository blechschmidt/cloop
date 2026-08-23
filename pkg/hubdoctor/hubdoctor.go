// Package hubdoctor diagnoses a cloop *control plane* — the thing an operator
// deploys — as distinct from pkg/doctor, which diagnoses a developer's
// checkout.
//
// # Why it is a separate package
//
// pkg/doctor answers "can this working copy run cloop": is there a .cloop
// directory, is `go` on PATH, is the API key set, is state.json valid JSON.
// Every one of its checks predates the hub, and none of them can fail on a
// deployment that is thoroughly broken as a hub: an issuer that does not
// resolve, a certificate that expired last week, an RBAC policy under which
// nobody is an admin, strict mode with nothing to dispatch to. That hub passes
// `cloop doctor` with fourteen green lines and cannot serve a single request.
//
// So this is a second diagnosis with a different subject, not more checks bolted
// onto the first. Its checks are the ones whose answers only exist once cloop is
// hosted — identity, transport, authorization, image trust, executors, storage
// and admission — and each one is written to be actionable rather than merely
// true: every non-pass finding carries a one-line remediation naming the file,
// field or command that fixes it.
//
// # The contract every check keeps
//
//   - A check never fails the whole run. A hub whose issuer is unreachable must
//     still be told about its expiring certificate, so each check contributes
//     findings and the report is the sum of them.
//   - Severity means something specific. Fail: the hub is broken or unsafe in a
//     way an operator must fix. Warn: it works, but a foreseeable event breaks it
//     or a control is weaker than the deployment implies. Pass: verified, not
//     merely absent.
//   - Absence is not a pass. A check that could not run — no network, no
//     database — reports that as a warning, because "we did not look" and "we
//     looked and it was fine" are different answers and only one of them is
//     worth acting on.
//
// # Exit codes and --json
//
// Run returns a Report; the caller decides how loudly to complain. ExitCode is
// 0 with only passes and warnings, 1 with any failure, so `cloop hub doctor` is
// usable as a CI gate and as a pre-flight in a deployment pipeline. --json emits
// the same Report verbatim, which is why every field has a stable JSON tag and
// every finding has a stable Check id: those ids are the thing a pipeline
// greps for, and renaming one is a breaking change.
package hubdoctor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
)

// Severity is how much a finding matters. The three values are ordered, and
// Report.ExitCode only distinguishes Fail from the rest.
type Severity string

const (
	// SeverityPass: verified working. Not "nothing was configured".
	SeverityPass Severity = "pass"
	// SeverityWarn: works now, but is fragile, weaker than the deployment
	// implies, or could not be verified.
	SeverityWarn Severity = "warn"
	// SeverityFail: broken or unsafe. An operator must act.
	SeverityFail Severity = "fail"
)

// rank orders severities for sorting and for "worst of" reductions.
func (s Severity) rank() int {
	switch s {
	case SeverityFail:
		return 2
	case SeverityWarn:
		return 1
	default:
		return 0
	}
}

// Symbol is the single character the text renderer prefixes a finding with.
func (s Severity) Symbol() string {
	switch s {
	case SeverityFail:
		return "✗"
	case SeverityWarn:
		return "!"
	default:
		return "✔"
	}
}

// Finding is one diagnostic result.
//
// Check is the stable machine-readable identifier ("oidc.discovery"), Title is
// what a human reads, Message says what was observed, and Remediation says what
// to do about it. Remediation is required for anything that is not a pass —
// a diagnostic that reports a problem without naming its fix is the failure
// mode this command exists to remove, and TestEveryNonPassCarriesRemediation
// enforces it.
type Finding struct {
	Check       string         `json:"check"`
	Title       string         `json:"title"`
	Severity    Severity       `json:"severity"`
	Message     string         `json:"message"`
	Remediation string         `json:"remediation,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
}

// Report is the whole diagnosis.
type Report struct {
	// Dir is the control plane's working directory (where .cloop lives).
	Dir string `json:"dir"`
	// CheckedAt is when the run started.
	CheckedAt time.Time `json:"checked_at"`
	// StrictMode reports executors.allow_host_process=false — recorded
	// because it changes what several findings mean.
	StrictMode bool `json:"strict_mode"`
	// Offline reports that network probes were skipped.
	Offline bool `json:"offline"`
	// Findings, in the order the checks produced them.
	Findings []Finding `json:"findings"`
}

// Counts returns the number of findings at each severity.
func (r *Report) Counts() (pass, warn, fail int) {
	for _, f := range r.Findings {
		switch f.Severity {
		case SeverityFail:
			fail++
		case SeverityWarn:
			warn++
		default:
			pass++
		}
	}
	return
}

// Worst returns the highest severity present, or SeverityPass when empty.
func (r *Report) Worst() Severity {
	worst := SeverityPass
	for _, f := range r.Findings {
		if f.Severity.rank() > worst.rank() {
			worst = f.Severity
		}
	}
	return worst
}

// ExitCode is 1 when any check failed, 0 otherwise.
//
// Warnings deliberately do not fail the command. A warning is frequently a
// deployment choice rather than a defect — a hub behind a proxy has no
// certificate of its own — and a gate that goes red on those gets switched off,
// taking the failures with it.
func (r *Report) ExitCode() int {
	if _, _, fail := r.Counts(); fail > 0 {
		return 1
	}
	return 0
}

// JSON renders the report for --json, with a trailing newline.
func (r *Report) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("render report as JSON: %w", err)
	}
	return append(b, '\n'), nil
}

// Options tunes a run.
type Options struct {
	// Offline skips every check that would make a network request: OIDC
	// discovery, the JWKS fetch, registry reachability, and executor health
	// probes that dial. Those checks report a warning saying they were
	// skipped rather than silently vanishing.
	Offline bool

	// Timeout bounds each individual network probe. Zero uses
	// DefaultProbeTimeout.
	Timeout time.Duration

	// HTTPClient overrides the client used for probes. Tests inject one
	// pointed at an httptest server; production leaves it nil so the system
	// trust store (and SSL_CERT_DIR, which the compose stack sets) applies.
	HTTPClient *http.Client

	// Now overrides the clock, so certificate-expiry findings are testable
	// without generating a certificate per case.
	Now func() time.Time

	// LookPath overrides executable lookup, for the cosign check. Tests
	// substitute it; nil means exec.LookPath.
	LookPath func(string) (string, error)
}

// DefaultProbeTimeout bounds one network probe. Ten seconds is long enough for
// a slow IdP behind a cold proxy and short enough that a hub with an
// unreachable issuer, an unreachable registry and three unreachable executors
// still finishes in under a minute.
const DefaultProbeTimeout = 10 * time.Second

func (o Options) timeout() time.Duration {
	if o.Timeout > 0 {
		return o.Timeout
	}
	return DefaultProbeTimeout
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// client returns the HTTP client for probes.
//
// A fresh client with keep-alives disabled rather than http.DefaultClient: a
// doctor run makes a handful of one-shot requests to hosts it will not contact
// again, and leaving pooled connections behind in a short-lived CLI process is
// a leak with no upside.
func (o Options) client() *http.Client {
	if o.HTTPClient != nil {
		return o.HTTPClient
	}
	return &http.Client{
		Timeout:   o.timeout(),
		Transport: &http.Transport{DisableKeepAlives: true},
	}
}

// add is how checks contribute findings. Kept as a function value rather than a
// slice append so a check cannot reorder or drop what a previous one recorded.
type addFn func(Finding)

// Run executes every hub check against the control plane rooted at dir and
// returns the report.
//
// It never returns an error: a hub is diagnosed by *reporting* what is wrong
// with it, and a doctor that aborts on the first unreadable file is a doctor
// that cannot diagnose the case it is most needed for. cfg may be nil, which is
// itself a finding.
func Run(ctx context.Context, dir string, cfg *config.Config, opts Options) *Report {
	if ctx == nil {
		ctx = context.Background()
	}
	rep := &Report{
		Dir:       dir,
		CheckedAt: opts.now(),
		Offline:   opts.Offline,
	}
	add := func(f Finding) { rep.Findings = append(rep.Findings, f) }

	if cfg == nil {
		add(Finding{
			Check:       "config.present",
			Title:       "Hub configuration",
			Severity:    SeverityFail,
			Message:     "no configuration could be loaded, so nothing below could be checked against it",
			Remediation: "Run `cloop hub bootstrap --external-url https://<your-host>` in this directory",
		})
		return rep
	}
	rep.StrictMode = !cfg.Executors.HostProcessAllowed()

	checkExecutionPolicy(cfg, add)
	checkOIDC(ctx, cfg, opts, add)
	checkTLS(cfg, opts, add)
	checkSecretKey(dir, cfg, add)
	checkRBAC(cfg, add)
	checkImagePolicy(ctx, cfg, opts, add)
	checkExecutors(ctx, dir, cfg, opts, add)
	checkGitProxy(cfg, add)
	checkStorage(dir, add)
	checkAdmission(cfg, add)

	return rep
}

// checkExecutionPolicy reports the setting every other executor finding is
// interpreted against.
//
// Unset is called out separately from false because they are different
// statements: false is "no run may fork on this host", unset is "nobody has
// decided", and a hosted deployment that never decided is one config reload
// away from executing a tenant's harness next to its own database.
func checkExecutionPolicy(cfg *config.Config, add addFn) {
	switch {
	case !cfg.Executors.HostProcessExplicit():
		add(Finding{
			Check:    "policy.host_execution",
			Title:    "Host execution policy",
			Severity: SeverityWarn,
			Message:  "executors.allow_host_process is unset, which is permissive by default",
			Remediation: "Set executors.allow_host_process: false in .cloop/config.yaml " +
				"(then enable a container, Kubernetes or remote executor)",
		})
	case cfg.Executors.HostProcessAllowed():
		add(Finding{
			Check:       "policy.host_execution",
			Title:       "Host execution policy",
			Severity:    SeverityWarn,
			Message:     "host execution is explicitly allowed: a run forks a harness beside the control plane",
			Remediation: "Set executors.allow_host_process: false unless this hub is single-user",
		})
	default:
		add(Finding{
			Check:    "policy.host_execution",
			Title:    "Host execution policy",
			Severity: SeverityPass,
			Message:  "strict: no run can fork a harness on this host",
		})
	}
}
