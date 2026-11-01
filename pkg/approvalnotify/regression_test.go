package approvalnotify

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
)

// A requirement regression (Task 20461) is a moment: told once per check, from
// the watermark on, keyed by the project and the check so two projects' check
// ids cannot collide.
func TestScanReportsRecentRegressionsOnce(t *testing.T) {
	now := time.Now()
	since := now.Add(-time.Hour)
	snap := Snapshot{Regressions: []Regression{
		{Project: "shop", ProjectKey: "aaaa", CheckID: 7, RequirementID: 3, RequirementTitle: "Checkout works",
			TaskID: 12, TaskTitle: "Add coupons", Commit: strings.Repeat("c", 40), At: now.Add(-time.Minute)},
		{Project: "blog", ProjectKey: "bbbb", CheckID: 7, RequirementID: 1, At: now.Add(-2 * time.Minute)},
		{Project: "shop", ProjectKey: "aaaa", CheckID: 6, RequirementID: 3, At: since.Add(-time.Minute)},
		{Project: "shop", CheckID: 8, At: now},
	}}
	notices := Scan(snap, since, now)
	keys := map[string]bool{}
	for _, n := range notices {
		if n.Event != config.NotifyEventRequirementRegression {
			t.Errorf("unexpected event %q", n.Event)
		}
		keys[n.Key()] = true
	}
	if len(notices) != 2 || !keys["requirement.regression:aaaa:7"] || !keys["requirement.regression:bbbb:7"] {
		t.Fatalf("notices = %+v", notices)
	}
	for _, n := range notices {
		if Superseded(n, snap, now) {
			t.Errorf("a regression was superseded: %+v", n)
		}
	}
}

func TestRegressionMessage(t *testing.T) {
	now := time.Now()
	n := Notice{Event: config.NotifyEventRequirementRegression, At: now, Project: "shop", ProjectKey: "aaaa", CheckID: 7,
		RequirementID: 3, RequirementTitle: "Checkout works <!channel>", TaskID: 12, TaskTitle: "Add coupons",
		Commit: strings.Repeat("c", 40), WasCommit: strings.Repeat("d", 40)}
	m := compose(n, "https://hub.example/?approvals=1", now)
	if m.title != "Requirement regressed in shop: R-3 Checkout works <!channel>" {
		t.Errorf("title = %q", m.title)
	}
	want := map[string]string{"Project": "shop", "Task": "#12 Add coupons", "Failing at": "cccccccccccc", "Passed at": "dddddddddddd"}
	for _, f := range m.facts {
		if w, ok := want[f.label]; ok && f.value != w {
			t.Errorf("%s = %q, want %q", f.label, f.value, w)
		}
	}
	body, err := Render(config.NotifySlack, n, "https://hub.example/?approvals=1", now)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "<!channel>") {
		t.Errorf("a title reached Slack unescaped: %s", body)
	}
	raw, err := Render(config.NotifyJSON, n, "", now)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("json body: %v\n%s", err, raw)
	}
	if !strings.Contains(string(raw), `"requirement.regression"`) {
		t.Errorf("json body does not name the event: %s", raw)
	}
}
