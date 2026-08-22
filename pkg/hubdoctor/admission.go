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
// deployment implies and what was actually written down.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/quota"
)

func checkAdmission(cfg *config.Config, add addFn) {
	q := cfg.UI.Quotas

	resolver, err := quota.New(quota.Config{
		Defaults: limitsFrom(q.Defaults),
		Bindings: quotaBindings(q.Bindings),
	})
	if err != nil {
		add(Finding{
			Check: "quotas.policy", Title: "Quota policy", Severity: SeverityFail,
			Message:     "ui.quotas is invalid and `cloop ui` will refuse to start: " + err.Error(),
			Remediation: "Fix the named value; valid resources are " + resourcesList(),
		})
		return
	}
	_ = resolver

	multiTenant := cfg.UI.OIDC.Enabled
	switch {
	case !q.Configured() && multiTenant:
		add(Finding{
			Check: "quotas.policy", Title: "Quota policy", Severity: SeverityWarn,
			Message: "single sign-on is on but ui.quotas is empty, so every authenticated identity " +
				"may create unlimited projects and run unlimited concurrent tasks",
			Remediation: "Set ui.quotas.defaults (max_projects, max_concurrent_tasks, daily_token_budget " +
				"are the ones that bound a shared hub)",
		})
	case !q.Configured():
		add(Finding{
			Check: "quotas.policy", Title: "Quota policy", Severity: SeverityPass,
			Message: "no quotas configured; correct for a single-tenant hub",
		})
	default:
		add(Finding{
			Check: "quotas.policy", Title: "Quota policy", Severity: SeverityPass,
			Message: fmt.Sprintf("%d default limit(s), %d binding(s)", len(q.Defaults), len(q.Bindings)),
		})
		checkQuotaSemantics(q, add)
	}

	checkBudget(cfg, add)
}

// checkQuotaSemantics catches the two quota mistakes that parse cleanly.
//
// A limit of 0 is the sharpest: it is valid, it means "none allowed", and it is
// what somebody writes when they meant "unlimited" (which is the key being
// absent). A tenant with max_projects: 0 is refused at every admission with a
// quota error, and the config reads like a generous default.
func checkQuotaSemantics(q config.QuotasConfig, add addFn) {
	var zeros []string
	for name, v := range q.Defaults {
		if v == 0 {
			zeros = append(zeros, "defaults."+name)
		}
	}
	for _, b := range q.Bindings {
		for name, v := range b.Limits {
			if v == 0 {
				zeros = append(zeros, fmt.Sprintf("%s=%s.%s", b.Claim, b.Value, name))
			}
		}
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
func checkBudget(cfg *config.Config, add addFn) {
	daily := cfg.Budget.DailyUSDLimit
	monthly := cfg.Budget.MonthlyUSD
	tokens := cfg.Budget.DailyTokenLimit

	switch {
	case daily <= 0 && monthly <= 0 && tokens <= 0 && cfg.UI.OIDC.Enabled:
		add(Finding{
			Check: "budget.limits", Title: "Spend budget", Severity: SeverityWarn,
			Message: "no budget.daily_usd_limit, budget.monthly_usd or budget.daily_token_limit on a " +
				"multi-tenant hub: provider spend is unbounded and billed to the operator",
			Remediation: "Set budget.daily_usd_limit (and ui.quotas.defaults.daily_cost_usd for a per-identity cap)",
		})
	case daily <= 0 && monthly <= 0 && tokens <= 0:
		add(Finding{
			Check: "budget.limits", Title: "Spend budget", Severity: SeverityPass,
			Message: "no spend ceiling configured; acceptable for a single-tenant hub",
		})
	default:
		add(Finding{
			Check: "budget.limits", Title: "Spend budget", Severity: SeverityPass,
			Message: fmt.Sprintf("daily $%.2f, monthly $%.2f, %d token(s)/day (0 = unset)",
				daily, monthly, tokens),
		})
	}
}

func limitsFrom(m map[string]float64) quota.Limits {
	if len(m) == 0 {
		return nil
	}
	out := make(quota.Limits, len(m))
	for k, v := range m {
		out[quota.Resource(k)] = v
	}
	return out
}

func quotaBindings(in []config.QuotaBinding) []quota.Binding {
	if len(in) == 0 {
		return nil
	}
	out := make([]quota.Binding, 0, len(in))
	for _, b := range in {
		out = append(out, quota.Binding{
			Claim:  authz.ClaimKind(b.Claim),
			Value:  b.Value,
			Limits: limitsFrom(b.Limits),
		})
	}
	return out
}

func resourcesList() string {
	names := make([]string, 0, len(quota.AllResources))
	for _, r := range quota.AllResources {
		names = append(names, string(r))
	}
	return strings.Join(names, ", ")
}
