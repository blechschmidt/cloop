package budget

import (
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/globalbudget"
)

// TestEffectiveLimitsAreWhatEnforceApplies: the project's daily caps, each the
// lower of its own value and its share of the global cap, plus the global caps
// themselves — and never budget.monthly_usd, which nothing enforces.
func TestEffectiveLimitsAreWhatEnforceApplies(t *testing.T) {
	global := globalbudget.GlobalBudgetConfig{DailyUSDLimit: 100, DailyTokenLimit: 1000}

	lim := EffectiveLimits(config.BudgetConfig{DailyUSDLimit: 50, GlobalUSDPct: 10, GlobalTokenPct: 50}, global)
	if lim.DailyUSD != 10 || lim.DailyTokens != 500 || lim.GlobalDailyUSD != 100 || lim.GlobalDailyTokens != 1000 {
		t.Errorf("EffectiveLimits = %+v", lim)
	}

	monthlyOnly := EffectiveLimits(config.BudgetConfig{MonthlyUSD: 500}, globalbudget.GlobalBudgetConfig{})
	if monthlyOnly.Bounded() {
		t.Errorf("monthly_usd alone bounds nothing Enforce applies: %+v", monthlyOnly)
	}
	if !EffectiveLimits(config.BudgetConfig{}, global).Bounded() {
		t.Error("a global cap bounds every project")
	}
}
