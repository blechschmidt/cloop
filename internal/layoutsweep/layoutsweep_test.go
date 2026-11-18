package layoutsweep

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// One fault seen at several widths is one finding naming them all, and the
// two page-level faults are reported from the page's own numbers.
func TestFindingsMergeAcrossViewports(t *testing.T) {
	spill := Offender{Kind: "spill", Where: "div#a > span", OverPx: 40, Culprit: "span (text)", CulpritText: "long_word"}
	got := Findings([]Scenario{
		{Name: "tab:tasks", Measurements: []Measurement{
			{Viewport: "phone-360", Theme: "light", Page: Page{ExpectedWidth: 360, InnerWidth: 360},
				Offenders: []Offender{spill}},
			{Viewport: "phone-390", Theme: "dark", Page: Page{ExpectedWidth: 390, InnerWidth: 390},
				Offenders: []Offender{spill}},
			{Viewport: "tablet-768", Theme: "light", Page: Page{ExpectedWidth: 768, InnerWidth: 900, OverflowPx: 132}},
		}},
		{Name: "dialog:x", Measurements: []Measurement{
			{Viewport: "desktop-1280", Page: Page{ExpectedWidth: 1280, InnerWidth: 1280, OverflowPx: 1},
				Offenders: []Offender{{Kind: "control", Where: "button#go", Left: 1270, Right: 1330, Top: 10, Bottom: 40}}},
		}},
	})
	if len(got) != 4 {
		t.Fatalf("got %d findings, want 4: %v", len(got), got)
	}
	if got[0].Kind != "spill" || strings.Join(got[0].At, ",") != "phone-360,phone-390 (dark)" ||
		!strings.Contains(got[0].Detail, `furthest right: span (text) "long_word"`) {
		t.Errorf("the spill was not merged across its two widths: %v", got[0])
	}
	if got[1].Kind != "page" || got[2].Kind != "zoom" || got[1].At[0] != "tablet-768" {
		t.Errorf("the page's own overflow and zoom-out were not reported: %v, %v", got[1], got[2])
	}
	if got[3].Kind != "control" || !strings.Contains(got[3].String(), "dialog:x: control button#go") {
		t.Errorf("the control was not reported, or a 1px overflow was: %v", got[3])
	}
}

func TestNamedViewports(t *testing.T) {
	vs, err := Named("desktop-1280", "phone-360")
	if err != nil || len(vs) != 2 || vs[0].Width != 1280 || vs[1].Width != 360 || !vs[1].Mobile {
		t.Fatalf("Named = %v, %v", vs, err)
	}
	if _, err := Named("phone-999"); err == nil {
		t.Fatal("an unknown viewport was accepted")
	}
}

// The probe's report decodes into these types field for field: a renamed key
// on either side would read as zero, and a clean page.
func TestMeasurementDecodesWhatTheProbeReports(t *testing.T) {
	src, err := os.ReadFile("probe.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"expected_width", "inner_width", "inner_height", "scroll_width", "client_width",
		"overflow_px", "offenders", "allowed", "elements", "controls", "roots", "over_px", "culprit_text"} {
		if !strings.Contains(string(src), key) {
			t.Errorf("probe.js no longer reports %q", key)
		}
	}
	var m Measurement
	raw := `{"page":{"expected_width":360,"inner_width":360,"overflow_px":0},"offenders":[{"kind":"clip",` +
		`"where":"div","over_px":7,"culprit_text":"x"}],"allowed":[{"selector":"#tabNav","over_px":3}],` +
		`"elements":12,"controls":3,"roots":1}`
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	if m.Page.ExpectedWidth != 360 || m.Offenders[0].OverPx != 7 || m.Offenders[0].CulpritText != "x" ||
		m.Allowed[0].Selector != "#tabNav" || m.Elements != 12 || m.Roots != 1 {
		t.Errorf("decoded %+v", m)
	}
}
