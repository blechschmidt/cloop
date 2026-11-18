// Package layoutsweep is the layout sweep's judgement: what a real browser
// measured on the dashboard at a given width, turned into the findings a test
// fails on (Task 20407).
//
// The measuring half is probe.js, beside this file: a script a browser driver
// injects into every document it loads, whose measure() reports the document's
// own sideways scroll, every box whose content runs out of it, and every
// control no scroll brings fully onto the screen, against the width and height
// the driver asked Chrome to emulate. Two sweeps use it:
//
//   - pkg/ui's layout sweep (layout_sweep_browser_test.go, its driver in
//     pkg/ui/testdata), every dashboard tab and dialog against a hub seeded
//     with the longest content real content gets;
//   - the documentation site demo's (tests/demo, its driver
//     scripts/demo/walk.js), the published copy of the dashboard with the
//     recorded data a reader sees (Task 20507).
//
// Both hold the page to the same definition of overflow and the same
// allowlist of boxes meant to scroll sideways, which is why they live here
// rather than in either test. Test-only: tests/arch keeps production code from
// importing it.
package layoutsweep

import (
	"fmt"
	"strings"
)

// Viewport is one emulated screen. Mobile turns on Chrome's mobile emulation,
// which is what brings meta[viewport] into play — and with it the
// shrink-to-fit zoom an overflowing phone page gets.
type Viewport struct {
	Name   string `json:"name"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
	Scale  int    `json:"scale"`
	Mobile bool   `json:"mobile"`
}

// Viewports: the narrowest phone still sold, the one the hub's own users carry
// (telemetry: 360x780 at dpr 3, Task 20473) and the commonest one, a tablet in
// portrait, a small laptop and a common desktop.
var Viewports = []Viewport{
	{Name: "phone-320", Width: 320, Height: 568, Scale: 2, Mobile: true},
	{Name: "phone-360", Width: 360, Height: 780, Scale: 3, Mobile: true},
	{Name: "phone-390", Width: 390, Height: 844, Scale: 3, Mobile: true},
	{Name: "tablet-768", Width: 768, Height: 1024, Scale: 2, Mobile: true},
	{Name: "laptop-1024", Width: 1024, Height: 768, Scale: 1, Mobile: false},
	{Name: "desktop-1280", Width: 1280, Height: 800, Scale: 1, Mobile: false},
}

// Named returns the viewports called names, in that order, or an error naming
// one that Viewports does not have.
func Named(names ...string) ([]Viewport, error) {
	out := make([]Viewport, 0, len(names))
	for _, n := range names {
		found := false
		for _, v := range Viewports {
			if v.Name == n {
				out = append(out, v)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("layoutsweep: no viewport named %q", n)
		}
	}
	return out, nil
}

// ScrollAllowed is an element meant to scroll sideways, and why. MaxWidth is
// the widest viewport it may scroll at; above it, it has to fit like anything
// else (0: it may scroll at every width).
type ScrollAllowed struct {
	Selector string `json:"selector"`
	MaxWidth int    `json:"max_width"`
	Reason   string `json:"-"`
}

// DashboardScrollAllowlist is every box of the dashboard allowed to scroll
// sideways. Anything else that does is reported: a phone user cannot see a
// scrollbar on a box that has not been scrolled yet, so sideways scrolling is a
// decision, not a fallback. pkg/ui's sweep fails an entry it never finds on
// screen as stale.
var DashboardScrollAllowlist = []ScrollAllowed{
	{Selector: ".table-scroll", MaxWidth: 768, Reason: "a table has as many columns as it has facts, and a phone " +
		"has room for three: it scrolls inside its own frame so the page does not, on a phone or a tablet " +
		"in portrait. Wider than that it has to fit, which is what keeps a long name from widening a " +
		"desktop table."},
	{Selector: "#tabNav", MaxWidth: 768, Reason: "a tablet in portrait gets the tab strip rather than the " +
		"phone's menu, and the strip scrolls with its scrollbar hidden: wrapped, twenty-one tabs take " +
		"three header rows. Above 768px it wraps by group instead (Task 20351)."},
	{Selector: "#timelineChart", MaxWidth: 768, Reason: "the Gantt chart draws its time axis at a minimum " +
		"width so that a bar stays wide enough to read; on a narrow screen the chart scrolls."},
	{Selector: "#ciSnippet", MaxWidth: 768, Reason: "a workflow file to copy verbatim: wrapping its lines " +
		"would show YAML indentation that is not in the file."},
}

// ── What the probe reports ───────────────────────────────────────────────────

// Page is the document as a whole: how wide the driver asked the screen to be,
// how wide the layout viewport is (wider once a phone page zoomed out to fit),
// and how far the document scrolls sideways.
type Page struct {
	ExpectedWidth int `json:"expected_width"`
	InnerWidth    int `json:"inner_width"`
	InnerHeight   int `json:"inner_height"`
	ScrollWidth   int `json:"scroll_width"`
	ClientWidth   int `json:"client_width"`
	OverflowPx    int `json:"overflow_px"`
}

// Offender is one element the probe reported: kind is spill, clip, scroll or
// control (see probe.js).
type Offender struct {
	Kind        string `json:"kind"`
	Where       string `json:"where"`
	OverPx      int    `json:"over_px"`
	Text        string `json:"text"`
	Culprit     string `json:"culprit"`
	CulpritText string `json:"culprit_text"`
	Left        int    `json:"left"`
	Right       int    `json:"right"`
	Top         int    `json:"top"`
	Bottom      int    `json:"bottom"`
}

// AllowedScroll is an allowlisted box the probe saw scrolling sideways.
type AllowedScroll struct {
	Selector string `json:"selector"`
	Where    string `json:"where"`
	OverPx   int    `json:"over_px"`
}

// Measurement is one measure() at one viewport. Viewport and Theme are filled
// in by the driver; Elements, Controls and Roots say how much there was to
// measure, so that a scope matching nothing cannot pass for a clean page.
type Measurement struct {
	Viewport  string          `json:"viewport"`
	Theme     string          `json:"theme"`
	Page      Page            `json:"page"`
	Offenders []Offender      `json:"offenders"`
	Allowed   []AllowedScroll `json:"allowed"`
	Elements  int             `json:"elements"`
	Controls  int             `json:"controls"`
	Roots     int             `json:"roots"`
}

// Scenario is one tab, view or dialog, measured at each viewport it exists at.
// Error is why the driver could not open it with its content in place.
type Scenario struct {
	Name         string        `json:"name"`
	Error        string        `json:"error"`
	Measurements []Measurement `json:"measurements"`
}

// ── The judgement ────────────────────────────────────────────────────────────

// Finding is one defect, gathered across every viewport it shows at.
type Finding struct {
	Scenario string
	Kind     string
	Where    string
	Detail   string
	At       []string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s: %s %s — %s [at %s]", f.Scenario, f.Kind, f.Where, f.Detail, strings.Join(f.At, ", "))
}

// Findings turns a run into its defects, merged so that one fault seen at five
// widths in two themes is one finding naming them all. The kinds are those of
// probe.js, and two the page itself shows: "page" when the document scrolls
// sideways, and "zoom" when a phone's layout viewport grew past the screen
// because the page overflowed and the browser zoomed all of it out to fit.
func Findings(scenarios []Scenario) []Finding {
	byKey := map[string]*Finding{}
	var order []string
	add := func(scenario, kind, where, detail, at string) {
		key := scenario + "|" + kind + "|" + where
		f := byKey[key]
		if f == nil {
			f = &Finding{Scenario: scenario, Kind: kind, Where: where, Detail: detail}
			byKey[key] = f
			order = append(order, key)
		}
		f.At = append(f.At, at)
	}
	for _, s := range scenarios {
		for _, m := range s.Measurements {
			at := m.Viewport
			if m.Theme == "dark" {
				at += " (dark)"
			}
			p := m.Page
			if p.OverflowPx > 1 {
				add(s.Name, "page", "the document", fmt.Sprintf("scrolls %dpx sideways", p.OverflowPx), at)
			}
			if p.InnerWidth > p.ExpectedWidth+1 {
				add(s.Name, "zoom", "the document", fmt.Sprintf("the layout viewport is %dpx on a %dpx screen — "+
					"the page overflowed and the browser zoomed all of it out to fit", p.InnerWidth, p.ExpectedWidth), at)
			}
			for _, o := range m.Offenders {
				var d string
				switch o.Kind {
				case "control":
					d = fmt.Sprintf("cannot be brought fully onto the screen (left %d, right %d, top %d, bottom %d)",
						o.Left, o.Right, o.Top, o.Bottom)
				case "scroll":
					d = fmt.Sprintf("scrolls %dpx sideways and is not in layoutsweep.DashboardScrollAllowlist", o.OverPx)
				case "clip":
					d = fmt.Sprintf("hides %dpx of its content", o.OverPx)
				default:
					d = fmt.Sprintf("content runs %dpx out of its box", o.OverPx)
				}
				if o.Culprit != "" {
					d += fmt.Sprintf("; furthest right: %s %q", o.Culprit, o.CulpritText)
				} else if o.Text != "" {
					d += fmt.Sprintf("; text %q", o.Text)
				}
				add(s.Name, o.Kind, o.Where, d, at)
			}
		}
	}
	out := make([]Finding, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out
}
