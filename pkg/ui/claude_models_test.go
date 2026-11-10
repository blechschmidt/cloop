package ui

import (
	"encoding/json"
	"math"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// The dashboard's model pickers and its cost card are JavaScript, so the
// Claude lineup and its prices are written twice: in Go (provider.ClaudeModels
// and pkg/cost, which the spend caps read) and in 00-core.js. These tests hold
// the shipped script to the Go side. Before them the two drifted apart: the
// pickers lacked four of Anthropic's fifteen models, and the cost card showed
// Opus 4.5 and 4.6 at three times their price.

// claudeModelsStatement returns the served bundle's `const claudeModels = …;`
// statement.
func claudeModelsStatement(t *testing.T) string {
	t.Helper()
	served := loadAssets().served
	start := strings.Index(served, "const claudeModels =")
	if start < 0 {
		t.Fatal("the served bundle has no `const claudeModels =`; the model pickers " +
			"(00-core.js) no longer build their Claude list from it")
	}
	end := strings.Index(served[start:], ";\n")
	if end < 0 {
		t.Fatal("cannot find the end of the claudeModels statement")
	}
	return served[start : start+end+1]
}

func TestDashboard_ClaudeModelPickersOfferTheWholeLineup(t *testing.T) {
	stmt := claudeModelsStatement(t)

	// The IDs, read from the source, in order.
	m := regexp.MustCompile(`const claudeModels = '([a-z0-9 -]+)'`).FindStringSubmatch(stmt)
	if m == nil {
		t.Fatalf("claudeModels is not a quoted, space-separated ID list:\n%s", stmt)
	}
	var ids []string
	for _, id := range strings.Fields(m[1]) {
		ids = append(ids, "claude-"+id)
	}
	if want := provider.ClaudeModelIDs(); strings.Join(ids, " ") != strings.Join(want, " ") {
		t.Fatalf("the dashboard's Claude models are\n  %v\nprovider.ClaudeModels is\n  %v\n"+
			"Keep claudeModels in assets/js/00-core.js in step with pkg/provider/claudemodels.go.", ids, want)
	}

	// The labels, as the browser builds them: run the statement itself.
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; the IDs match, the labels are not checked")
	}
	out, err := exec.Command(node, "-e", stmt+"\nprocess.stdout.write(JSON.stringify(claudeModels));").Output()
	if err != nil {
		t.Fatalf("running the claudeModels statement: %v\n%s", err, stmt)
	}
	var got []struct{ Value, Label string }
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("claudeModels evaluated to %s: %v", out, err)
	}
	if len(got) != len(provider.ClaudeModels) {
		t.Fatalf("claudeModels has %d entries, provider.ClaudeModels %d", len(got), len(provider.ClaudeModels))
	}
	for i, want := range provider.ClaudeModels {
		// The label is exactly the Models API's display name: no annotation
		// such as the Claude Code version note Opus 5.5 once carried.
		if got[i].Value != want.ID || got[i].Label != want.Name {
			t.Errorf("picker entry %d = {%q, %q}, want {%q, %q}", i, got[i].Value, got[i].Label, want.ID, want.Name)
		}
	}
}

func TestDashboard_ClaudePricesMatchPkgCost(t *testing.T) {
	served := loadAssets().served
	start := strings.Index(served, "function estimateCost(")
	if start < 0 {
		t.Fatal("the served bundle has no estimateCost; the cost card's price table moved")
	}
	end := strings.Index(served[start:], "};")
	if end < 0 {
		t.Fatal("cannot find the end of estimateCost's price table")
	}
	table := served[start : start+end]

	rows := map[string][2]float64{}
	for _, m := range regexp.MustCompile(`'(claude-[a-z0-9.-]+)':\s*\[\s*([0-9.]+)\s*,\s*([0-9.]+)\s*\]`).FindAllStringSubmatch(table, -1) {
		in, err1 := strconv.ParseFloat(m[2], 64)
		out, err2 := strconv.ParseFloat(m[3], 64)
		if err1 != nil || err2 != nil {
			t.Fatalf("unparseable price row %q", m[0])
		}
		rows[m[1]] = [2]float64{in, out}
	}

	for _, model := range provider.ClaudeModels {
		if _, ok := rows[model.ID]; !ok {
			t.Errorf("%s is in the model pickers but not in estimateCost's price table, so the "+
				"Overview's cost card would price it by prefix as another model or not at all", model.ID)
		}
	}
	for id, row := range rows {
		in, okIn := cost.Estimate(id, 1_000_000, 0)
		out, okOut := cost.Estimate(id, 0, 1_000_000)
		if !okIn || !okOut {
			t.Errorf("estimateCost prices %s, which pkg/cost does not", id)
			continue
		}
		if math.Abs(row[0]-in) > 1e-9 || math.Abs(row[1]-out) > 1e-9 {
			t.Errorf("estimateCost prices %s at [%v, %v] per million, pkg/cost at [%v, %v]",
				id, row[0], row[1], in, out)
		}
	}
}
