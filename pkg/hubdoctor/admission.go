package hubdoctor

// Admission checks: quotas and budget.
//
// RBAC decides whether an identity may act; quotas decide how much. The two
// fail differently, and quotas fail in a way that is easy to miss: an invalid
// quota policy stops `cloop ui` from starting, but a *silently absent* one lets
// a multi-tenant hub run with no ceilings at all, which is not a refusal
// anywhere — it is a bill, or a hub that one tenant's parallel plan wedges for
// everybody.
//
// So the checks here are less about validity (quota.New already rejects what is
// malformed, loudly, at boot) and more about the gap between what the
// deployment implies and what was actually written down — judged as the hub
// holds it, not as the YAML reads (Task 20387). A quota policy is whatever
// quota.New built from the builder `cloop ui` uses: "-1" is unlimited there,
// so a block of nothing but -1s is no policy, though it reads like one. A
// spend ceiling is whatever budget.EffectiveLimits says a run is held to, from
// the config.yaml runs read: monthly_usd bounds nothing, and an overlay's
// budget is never read.

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/budget"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/globalbudget"
	"github.com/blechschmidt/cloop/pkg/quota"
)

func checkAdmission(dir string, cfg *config.Config, opts Options, add addFn) {
	q := cfg.UI.Quotas

	resolver, err := quota.New(q.QuotaConfig())
	if err != nil {
		add(Finding{
			Check: "quotas.policy", Title: "Quota policy", Severity: SeverityFail,
			Message:     "ui.quotas is invalid and `cloop ui` will refuse to start: " + err.Error(),
			Remediation: "Fix the named value; valid resources are " + resourcesList(),
		})
		return
	}

	multiTenant := cfg.UI.OIDC.Enabled
	switch {
	case !resolver.Constrains() && multiTenant:
		add(Finding{
			Check: "quotas.policy", Title: "Quota policy", Severity: SeverityWarn,
			Message: "single sign-on is on but no quota bounds anything (ui.quotas sets nothing, or only " +
				"ceilings that mean unlimited — a negative one, or max_sessions: 0), so every " +
				"authenticated identity may create unlimited projects and run unlimited concurrent tasks",
			Remediation: "Set ui.quotas.defaults (max_projects, max_concurrent_tasks, daily_token_budget " +
				"are the ones that bound a shared hub)",
		})
	case !resolver.Constrains():
		add(Finding{
			Check: "quotas.policy", Title: "Quota policy", Severity: SeverityPass,
			Message: "no quotas configured; correct for a single-tenant hub",
		})
	default:
		add(Finding{
			Check: "quotas.policy", Title: "Quota policy", Severity: SeverityPass,
			Message: fmt.Sprintf("%d default limit(s), %d binding(s)", len(q.Defaults), len(q.Bindings)),
		})
		checkQuotaSemantics(q.QuotaConfig(), add)
	}

	checkBudget(dir, cfg, opts, add)
}

// checkQuotaSemantics catches the quota mistake that parses cleanly: a limit
// of 0. It is valid, it means "none allowed" for every resource whose
// quota.Resource.ZeroAdmitsNone says so, and it is what somebody writes when
// they meant "unlimited" (which is the key being absent). A tenant with
// max_projects: 0 is refused at every admission with a quota error, and the
// config reads like a generous default. max_sessions: 0 is not that — the hub
// reads it as no cap — and is not reported.
func checkQuotaSemantics(qc quota.Config, add addFn) {
	var zeros []string
	collect := func(prefix string, l quota.Limits) {
		norm, err := l.Normalize()
		if err != nil {
			return // quota.New refused the policy, reported by quotas.policy
		}
		for r, v := range norm {
			if v == 0 && r.ZeroAdmitsNone() {
				zeros = append(zeros, prefix+string(r))
			}
		}
	}
	collect("defaults.", qc.Defaults)
	for _, b := range qc.Bindings {
		collect(fmt.Sprintf("%s=%s.", b.Claim, b.Value), b.Limits)
	}
	if len(zeros) > 0 {
		sort.Strings(zeros)
		add(Finding{
			Check: "quotas.zero_limits", Title: "Zero quota limits", Severity: SeverityWarn,
			Message: fmt.Sprintf("%d limit(s) are set to 0, which means none allowed — not unlimited; "+
				"every admission against them is refused", len(zeros)),
			Remediation: "Remove the key to mean unlimited, or set a positive ceiling",
			Details:     map[string]any{"zero_limits": strings.Join(zeros, ", ")},
		})
	}

	// A binding that carries no limits at all is rejected by quota.New (it
	// would have no effect), so it is reported by quotas.policy above rather
	// than here — this function only sees policies that already parse.
}

// checkBudget reports the spend ceiling. On a hosted hub the provider bill is
// the one resource a tenant can consume without limit through entirely
// legitimate use, and it is charged to the operator.
//
// The ceiling is budget.EffectiveLimits — what budget.Enforce holds a run to —
// over the budget runs read: config.yaml's, because a budget belongs to the
// project and `cloop run` reads no overlay (a config built without a file, in
// a test, is taken as it is). Enforce runs inside `cloop run`, which on an
// isolating executor is the sandboxed workload, given only its leased
// environment: the host-wide caps in ~/.config/cloop reach it there no more
// than the hub's HOME does. So the caps that hold every run back are the
// project's own, and the host-wide ones are reported for what they are.
func checkBudget(dir string, cfg *config.Config, opts Options, add addFn) {
	project := cfg.Budget
	if _, err := os.Stat(config.ConfigPath(dir)); err == nil {
		if pc, err := config.Load(dir); err == nil {
			project = pc.Budget
		}
	}
	everyRun := budget.EffectiveLimits(project, globalbudget.GlobalBudgetConfig{})
	global, _ := opts.globalBudget()
	hostRun := budget.EffectiveLimits(project, global)

	var notes []string
	if hostRun != everyRun {
		notes = append(notes, fmt.Sprintf("runs on this host's own driver are also held to $%.2f and %d "+
			"token(s) a day across the host, from this user's ~/.config/cloop — when the hub runs as this "+
			"user; an isolated run is not given them", hostRun.GlobalDailyUSD, hostRun.GlobalDailyTokens))
	}
	if project.MonthlyUSD > 0 {
		notes = append(notes, fmt.Sprintf("budget.monthly_usd ($%.2f) is reported by `cloop cost report` "+
			"and enforced nowhere", project.MonthlyUSD))
	}
	note := ""
	if len(notes) > 0 {
		note = "; " + strings.Join(notes, "; ")
	}
	switch {
	case !everyRun.Bounded() && cfg.UI.OIDC.Enabled:
		add(Finding{
			Check: "budget.limits", Title: "Spend budget", Severity: SeverityWarn,
			Message: "no budget.daily_usd_limit or budget.daily_token_limit holds a run back on a " +
				"multi-tenant hub, so provider spend is unbounded and billed to the operator" + note,
			Remediation: "Set budget.daily_usd_limit in config.yaml (and ui.quotas.defaults.daily_cost_usd " +
				"for a per-identity cap)",
		})
	case !everyRun.Bounded():
		add(Finding{
			Check: "budget.limits", Title: "Spend budget", Severity: SeverityPass,
			Message: "no spend ceiling configured; acceptable for a single-tenant hub" + note,
		})
	default:
		add(Finding{
			Check: "budget.limits", Title: "Spend budget", Severity: SeverityPass,
			Message: fmt.Sprintf("every run is held to $%.2f and %d token(s) a day per project (0 = no cap)%s",
				everyRun.DailyUSD, everyRun.DailyTokens, note),
		})
	}
}

func resourcesList() string {
	names := make([]string, 0, len(quota.AllResources))
	for _, r := range quota.AllResources {
		names = append(names, string(r))
	}
	return strings.Join(names, ", ")
}
