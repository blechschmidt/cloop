package ratelimit

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// liveUsageBody is /api/oauth/usage as it answered on 2026-11-10, copied
// rather than paraphrased. There is no seven_day_fable key: Fable's weekly
// window is only the weekly_scoped row of limits[], which is why the limit
// views never showed it (Task 20490).
const liveUsageBody = `{"five_hour":null,"seven_day":{"utilization":61.0,"resets_at":"2026-11-13T22:00:00.282942+00:00","limit_dollars":null,"used_dollars":null,"remaining_dollars":null,"locked_reason":null},"seven_day_oauth_apps":null,"seven_day_opus":null,"seven_day_sonnet":null,"seven_day_cowork":null,"seven_day_omelette":null,"tangelo":null,"iguana_necktie":null,"omelette_promotional":null,"nimbus_quill":null,"cinder_cove":null,"copper_kite":null,"brass_thimble":null,"harbor_lantern":null,"wattle_ember":null,"promo_credits":null,"amber_ladder":null,"granite_teacup":null,"amber_cistern":null,"amber_cistern_offer":null,"juniper_tide":null,"cedar_ember":null,"starry_waterfall":null,"amber_gauge":null,"pace":null,"indicator":null,"extra_usage":{"is_enabled":false,"monthly_limit":null,"used_credits":null,"utilization":null,"currency":null,"decimal_places":null,"disabled_reason":null,"user_disabled":true,"spend_limit_reached":false,"credits_ever_enabled":true,"daily":null,"weekly":null},"limits":[{"kind":"weekly_all","group":"weekly","percent":61,"severity":"normal","resets_at":"2026-11-13T22:00:00.282942+00:00","scope":null,"is_active":true},{"kind":"weekly_scoped","group":"weekly","percent":7,"severity":"normal","resets_at":"2026-11-13T22:00:00.283105+00:00","scope":{"model":{"id":null,"display_name":"Fable"},"surface":null},"is_active":false}],"spend":{"used":{"amount_minor":0,"currency":"USD","exponent":2},"limit":null,"percent":0,"severity":"normal","enabled":false,"disabled_reason":null,"cap":null,"balance":null,"auto_reload":null,"disclaimer":"Usage credits cover you when you hit your plan limits. [Learn more](https://support.claude.com/articles/12429409)","can_purchase_credits":false,"can_toggle":false},"member_dashboard_available":false,"seven_day_breakdown":{"as_of":"2026-11-10T21:27:55.306191+00:00","window_started_at":"2026-11-06T22:00:00.282942+00:00","rows":[{"key":"claude_code","display_name":"Claude Code","percent":94},{"key":"chat","display_name":"Chats","percent":4},{"key":"cowork","display_name":"Cowork","percent":2},{"key":"other","display_name":"Other","percent":0}]},"weekly_scoped_shares":[{"limit_index":1,"used_percent_of_weekly":4,"allowance_percent_of_weekly":50}]}`

// fetchBody serves body as the usage API and fetches it the way every caller
// does, under a configuration directory of the test's own so the snapshot it
// caches is nobody else's.
func fetchBody(t *testing.T, body string) *ClaudeUsage {
	t.Helper()
	usageServer(t, http.StatusOK, body, nil)
	dir := t.TempDir()
	t.Cleanup(func() { ClearUsageCacheIn(dir) })
	usage, status, err := fetchUsageWithToken(dir, "test-token")
	if err != nil || status != http.StatusOK {
		t.Fatalf("fetchUsageWithToken = %d, %v", status, err)
	}
	if got := GetCachedUsageIn(dir); got != usage {
		t.Fatal("the fetched snapshot is not the one cached")
	}
	return usage
}

func TestFableWeeklyWindowIsReadFromTheLimitsList(t *testing.T) {
	usage := fetchBody(t, liveUsageBody)

	if len(usage.SevenDayModels) != 1 {
		t.Fatalf("SevenDayModels = %+v, want Fable's window alone", usage.SevenDayModels)
	}
	fable := usage.SevenDayModels[0]
	reset := time.Date(2026, 11, 13, 22, 0, 0, 283105000, time.UTC)
	if fable.Model != "Fable" || fable.Utilization != 7 || !fable.ResetsAt.Equal(reset) {
		t.Errorf("Fable's window = %+v, want Fable at 7%% resetting %v", fable, reset)
	}

	// The weekly_all row is the seven_day key again, not a model's window,
	// and the keys read before are read as before.
	if usage.SevenDay == nil || usage.SevenDay.Utilization != 61 {
		t.Errorf("SevenDay = %+v, want 61%%", usage.SevenDay)
	}
	if usage.FiveHour != nil || usage.SevenDayOpus != nil || usage.SevenDaySonnet != nil {
		t.Errorf("windows the server sent as null were filled: five-hour %+v, Opus %+v, Sonnet %+v",
			usage.FiveHour, usage.SevenDayOpus, usage.SevenDaySonnet)
	}

	// What the dashboard reads: both limit views draw u.seven_day_models
	// with m.model, m.utilization and m.resets_at.
	b, err := json.Marshal(usage)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		SevenDayModels []map[string]any `json:"seven_day_models"`
	}
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"model": "Fable", "utilization": 7.0, "resets_at": "2026-11-13T22:00:00.283105Z"}
	if len(wire.SevenDayModels) != 1 || fmt.Sprint(wire.SevenDayModels[0]) != fmt.Sprint(want) {
		t.Errorf("seven_day_models on the wire = %v, want [%v]", wire.SevenDayModels, want)
	}

	// A snapshot with no such window says nothing about it.
	if b, _ := json.Marshal(&ClaudeUsage{}); strings.Contains(string(b), "seven_day_models") {
		t.Errorf("an empty snapshot carries seven_day_models: %s", b)
	}
}

// The windows the caps are enforced on must not depend on a list this package
// only displays from: a limits[] the parser cannot read costs its rows, never
// the snapshot.
func TestAnUnreadableLimitsListKeepsTheRestOfTheSnapshot(t *testing.T) {
	for name, limits := range map[string]string{
		"an object":         `{"weekly_scoped":{"percent":7}}`,
		"a string":          `"Fable"`,
		"null":              `null`,
		"a list of strings": `["Fable"]`,
	} {
		t.Run(name, func(t *testing.T) {
			usage := fetchBody(t, `{"five_hour":{"utilization":12,"resets_at":"2026-11-10T23:00:00+00:00"},`+
				`"seven_day":{"utilization":61,"resets_at":"2026-11-13T22:00:00+00:00"},"limits":`+limits+`}`)
			if usage.FiveHour == nil || usage.FiveHour.Utilization != 12 ||
				usage.SevenDay == nil || usage.SevenDay.Utilization != 61 {
				t.Errorf("five-hour %+v, weekly %+v: lost to the limits list", usage.FiveHour, usage.SevenDay)
			}
			if usage.SevenDayModels != nil {
				t.Errorf("SevenDayModels = %+v from limits %s", usage.SevenDayModels, limits)
			}
		})
	}
}

func TestModelWindowsReadOnlyModelScopedWeeklyRows(t *testing.T) {
	fable := `{"kind":"weekly_scoped","percent":7,"resets_at":"2026-11-13T22:00:00+00:00","scope":{"model":{"display_name":"Fable"}}}`
	tests := []struct {
		name string
		rows string
		want []string // "name@percent"
	}{
		{"the live shape", `[{"kind":"weekly_all","percent":61,"scope":null},` + fable + `]`, []string{"Fable@7"}},
		{"server order", `[{"kind":"weekly_scoped","percent":30,"scope":{"model":{"display_name":"Fable 5.2"}}},` + fable + `]`,
			[]string{"Fable 5.2@30", "Fable@7"}},
		{"a session row is the five-hour key", `[{"kind":"session","percent":12,"scope":null},` + fable + `]`, []string{"Fable@7"}},
		// Claude Code's /usage screen shows only model-scoped rows too.
		{"a surface-scoped row", `[{"kind":"weekly_scoped","percent":3,"scope":{"surface":{"display_name":"Cowork"}}}]`, nil},
		{"a model row of another kind", `[{"kind":"session_scoped","percent":3,"scope":{"model":{"display_name":"Fable"}}}]`, nil},
		{"no percentage", `[{"kind":"weekly_scoped","percent":null,"scope":{"model":{"display_name":"Fable"}}}]`, nil},
		{"no name", `[{"kind":"weekly_scoped","percent":3,"scope":{"model":{"display_name":" \t"}}}]`, nil},
		{"no scope", `[{"kind":"weekly_scoped","percent":3}]`, nil},
		// One row this cannot read costs that row alone.
		{"a malformed row among good ones", `[{"kind":"weekly_scoped","percent":"7%","scope":{"model":{"display_name":"Opus"}}},` +
			`"junk",null,` + fable + `]`, []string{"Fable@7"}},
		{"names are cleaned", `[{"kind":"weekly_scoped","percent":1,"scope":{"model":{"display_name":" Fable‮\t5.2\u0000\n "}}}]`,
			[]string{"Fable 5.2@1"}},
		{"empty", `[]`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, w := range modelWindows(json.RawMessage(tt.rows)) {
				got = append(got, fmt.Sprintf("%s@%g", w.Model, w.Utilization))
			}
			if fmt.Sprint(got) != fmt.Sprint(tt.want) {
				t.Errorf("modelWindows(%s) = %v, want %v", tt.rows, got, tt.want)
			}
		})
	}

	if got := modelWindows(nil); got != nil {
		t.Errorf("modelWindows(nil) = %+v", got)
	}

	// A reset the server leaves out, or sends as null, is unknown, not now.
	ws := modelWindows(json.RawMessage(`[{"kind":"weekly_scoped","percent":5,"resets_at":null,"scope":{"model":{"display_name":"Fable"}}}]`))
	if len(ws) != 1 || !ws[0].ResetsAt.IsZero() {
		t.Errorf("a null resets_at = %+v, want one window with a zero reset", ws)
	}
}

func TestModelWindowsAreBounded(t *testing.T) {
	var rows []string
	for i := 0; i < 3*maxModelWindows; i++ {
		rows = append(rows, fmt.Sprintf(`{"kind":"weekly_scoped","percent":%d,"scope":{"model":{"display_name":"Model %d"}}}`, i, i))
	}
	got := modelWindows(json.RawMessage("[" + strings.Join(rows, ",") + "]"))
	if len(got) != maxModelWindows || got[0].Model != "Model 0" || got[len(got)-1].Model != fmt.Sprintf("Model %d", maxModelWindows-1) {
		t.Errorf("kept %+v, want the first %d windows", got, maxModelWindows)
	}

	long := strings.Repeat("Ä", 3*maxModelNameRunes)
	got = modelWindows(json.RawMessage(`[{"kind":"weekly_scoped","percent":1,"scope":{"model":{"display_name":"` + long + `"}}}]`))
	if len(got) != 1 || got[0].Model != strings.Repeat("Ä", maxModelNameRunes) {
		t.Errorf("a %d-rune name became %+v, want its first %d runes", 3*maxModelNameRunes, got, maxModelNameRunes)
	}
}

// Opus and Sonnet have keys of their own. A scoped row for either is the meter
// the key already describes, so it fills a key the server left out and is
// never listed beside it: the caps panel would otherwise show the same window
// twice, once as "not reported".
func TestOpusAndSonnetRowsAreFiledUnderTheirOwnKeys(t *testing.T) {
	usage := fetchBody(t, `{"seven_day_sonnet":{"utilization":40,"resets_at":"2026-11-13T22:00:00+00:00"},"limits":[`+
		`{"kind":"weekly_scoped","percent":22,"resets_at":"2026-11-12T10:00:00+00:00","scope":{"model":{"display_name":"Opus"}}},`+
		`{"kind":"weekly_scoped","percent":41,"scope":{"model":{"display_name":"SONNET"}}},`+
		`{"kind":"weekly_scoped","percent":9,"scope":{"model":{"display_name":"Opus 5"}}},`+
		`{"kind":"weekly_scoped","percent":7,"scope":{"model":{"display_name":"Fable"}}}]}`)

	if o := usage.SevenDayOpus; o == nil || o.Utilization != 22 ||
		!o.ResetsAt.Equal(time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("SevenDayOpus = %+v, want the Opus row's 22%% and its reset", o)
	}
	if s := usage.SevenDaySonnet; s == nil || s.Utilization != 40 {
		t.Errorf("SevenDaySonnet = %+v, want the seven_day_sonnet key's 40%%, not the row's", s)
	}
	// A versioned name is another meter than the family's key.
	var got []string
	for _, m := range usage.SevenDayModels {
		got = append(got, m.Model)
	}
	if want := []string{"Opus 5", "Fable"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("SevenDayModels = %v, want %v", got, want)
	}
}

func TestAtDropsModelWindowsThatHaveRolledOver(t *testing.T) {
	now := time.Date(2026, 11, 13, 22, 0, 1, 0, time.UTC)
	usage := &ClaudeUsage{SevenDayModels: []ModelWindow{
		{Model: "Fable", UsageDetail: UsageDetail{Utilization: 100, ResetsAt: now.Add(-time.Second)}},
		{Model: "Fable 5.2", UsageDetail: UsageDetail{Utilization: 40, ResetsAt: now.Add(time.Hour)}},
		{Model: "Opus 5", UsageDetail: UsageDetail{Utilization: 9}}, // no reset reported
	}}

	got := usage.At(now)
	var names []string
	for _, m := range got.SevenDayModels {
		names = append(names, m.Model)
	}
	if want := []string{"Fable 5.2", "Opus 5"}; fmt.Sprint(names) != fmt.Sprint(want) {
		t.Errorf("At(now).SevenDayModels = %v, want %v", names, want)
	}
	// The receiver may be the shared cached snapshot.
	if len(usage.SevenDayModels) != 3 || usage.SevenDayModels[0].Model != "Fable" ||
		usage.SevenDayModels[1].Model != "Fable 5.2" {
		t.Errorf("At modified its receiver: %+v", usage.SevenDayModels)
	}
	if got := (&ClaudeUsage{}).At(now); got.SevenDayModels != nil {
		t.Errorf("At on a snapshot without model windows made %+v", got.SevenDayModels)
	}
}

// A model's own window is shown, not enforced: only runs on that model draw on
// it, so holding every run when Fable's week is used up would stop work that
// cannot reach the wall. The caps and budget.block_extra_usage read the keys
// they always have.
func TestModelWindowsAreShownNotEnforced(t *testing.T) {
	usage := &ClaudeUsage{
		SevenDay:       &UsageDetail{Utilization: 61},
		SevenDayModels: []ModelWindow{{Model: "Fable", UsageDetail: UsageDetail{Utilization: 100}}},
	}
	if got := CheckExhaustedWindows(usage); got != nil {
		t.Errorf("CheckExhaustedWindows = %+v", got)
	}
}
