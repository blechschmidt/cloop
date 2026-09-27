// diagram_contrast_test.go gates the colours the documentation's mermaid
// diagrams paint their boxes with.
//
// This exists because of a specific failure. The lifecycle flowchart in
// docs/getting-started/concepts.md filled its boxes navy, dark green and near
// black, and asked for light text with a classDef `color:`. GitHub honours
// that; the published site does not. Material for MkDocs renders every diagram
// with CSS of its own, which colours the label's <p> directly
// (`.nodeLabel p { color: var(--md-mermaid-label-fg-color) }`), so mermaid's
// `color:` never reaches the text. In the light scheme that colour is #36464e,
// and 38 of the diagram's 67 labels came out below 4.5:1 — down to 1.02:1,
// dark slate on dark green. Two more diagrams had the mirror image: #e8f0fe,
// #fde, #efd and #f6f8fa boxes under the dark scheme's light text, down to
// 1.11:1. Every renderer drew them without complaint.
//
// No opaque fill can serve both schemes: the light scheme's text needs a fill
// of at least 0.43 relative luminance, the dark scheme's one of at most 0.08.
// A tint can — a fill with alpha lets the page show through, so the box is
// light on a light page and dark on a dark one, and the theme's own text colour
// is right on both. So the rule is not "no dark colours"; it is computed. Every
// fill a diagram declares is composited over what each renderer paints behind
// a box and must leave that renderer's label text at 4.5:1. And no diagram may
// set a text colour, which the published site ignores and which on GitHub is
// right in at most one of its two schemes.
package docs_test

import (
	"bytes"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// minLabelContrast is WCAG 2's AA threshold for normal text. Diagram labels
// are small type, so the large-text allowance does not apply.
const minLabelContrast = 4.5

// materialPin is the mkdocs-material release the published site's renderer
// values below were read from. website/requirements.txt must still pin it.
const materialPin = "mkdocs-material==9.7.7"

// rgba is a colour with 0–255 channels and a 0–1 alpha.
type rgba struct{ r, g, b, a float64 }

// renderer is a place the diagrams are read, reduced to what decides whether
// a label is legible: the colour its text is drawn in, the page behind the
// diagram, and the fill the renderer gives a subgraph — which is what a box
// inside one sits on.
type renderer struct {
	name                 string
	text, page, subgraph rgba
}

// renderers are the published site in both schemes and GitHub in both.
//
// The published site's values are mkdocs-material's (materialPin): labels take
// --md-mermaid-label-fg-color, which is --md-code-fg-color; the page is
// --md-default-bg-color; a subgraph is --md-default-fg-color--lightest. The
// slate scheme writes each as hsla() off --md-hue, 225deg. GitHub's are its
// canvas and mermaid's own default and dark themes: textColor #333 and #ccc,
// clusterBkg #ffffde and #474949.
//
// They were checked against real Chromium rather than taken on trust; see
// TestDiagramContrastModelMatchesTheBrowser.
var renderers = []renderer{
	{
		name:     "the published site, light scheme",
		text:     mustHex("#36464e"),
		page:     mustHex("#ffffff"),
		subgraph: mustHex("#00000012"),
	},
	{
		name:     "the published site, dark scheme",
		text:     hsla(225, 0.18, 0.86, 0.82),
		page:     hsla(225, 0.15, 0.14, 1),
		subgraph: hsla(225, 0.15, 0.90, 0.12),
	},
	{
		name:     "GitHub, light",
		text:     mustHex("#333333"),
		page:     mustHex("#ffffff"),
		subgraph: mustHex("#ffffde"),
	},
	{
		name:     "GitHub, dark",
		text:     mustHex("#cccccc"),
		page:     mustHex("#0d1117"),
		subgraph: mustHex("#474949"),
	},
}

// mermaidFence matches a fenced mermaid block and captures its body — the same
// fence the CI job that parses every diagram extracts.
var mermaidFence = regexp.MustCompile("(?ms)^```mermaid[ \\t]*\\r?\\n(.*?)^```")

// styleStatement matches the mermaid statements that carry CSS — a node's or
// subgraph's `style`, a `classDef`, a `linkStyle` — and captures the keyword,
// the target and the declaration list.
var styleStatement = regexp.MustCompile(`^\s*(style|classDef|linkStyle)\s+(\S+)\s+(.*?)\s*;?\s*$`)

// TestMermaidDiagramsReadInBothSchemes is the gate proper.
func TestMermaidDiagramsReadInBothSchemes(t *testing.T) {
	root := repoRoot(t)

	diagrams := 0
	var problems []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Dot directories hold git, the project's own .cloop state and the
			// feature worktrees nested inside it (full copies of docs/); dist
			// holds the staged copy of docs/ the site is built from; polyauth is
			// a separate project sharing the directory.
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "dist" ||
				name == "node_modules" || name == "vendor" || name == "polyauth") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".md") {
			return nil
		}
		text, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		for _, m := range mermaidFence.FindAllSubmatchIndex(text, -1) {
			diagrams++
			firstLine := bytes.Count(text[:m[2]], []byte("\n")) + 1
			problems = append(problems, checkDiagram(filepath.ToSlash(rel), firstLine, string(text[m[2]:m[3]]))...)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the repository for Markdown: %v", err)
	}
	if diagrams == 0 {
		// docs/ has had diagrams since it existed; finding none means the walk
		// or the fence broke, and every diagram would pass unexamined.
		t.Fatal("found no mermaid diagrams — the check is disabled, not passing")
	}
	t.Logf("checked the colours of %d mermaid diagram(s)", diagrams)
	for _, p := range problems {
		t.Error(p)
	}
}

// checkDiagram returns what is wrong with one diagram's colours, one
// "file:line: problem" string each. src is the fenced block's body and
// firstLine the file line it begins on.
func checkDiagram(file string, firstLine int, src string) []string {
	var problems []string
	for i, line := range strings.Split(src, "\n") {
		m := styleStatement.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		where := fmt.Sprintf("%s:%d: %s %s", file, firstLine+i, m[1], m[2])
		decls := map[string]string{}
		for _, d := range strings.Split(m[3], ",") {
			k, v, ok := strings.Cut(d, ":")
			if !ok {
				continue
			}
			v = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), "!important"))
			decls[strings.ToLower(strings.TrimSpace(k))] = v
		}

		if c, ok := decls["color"]; ok {
			problems = append(problems, fmt.Sprintf("%s sets a text colour (color:%s). "+
				"The published site ignores it — Material for MkDocs colours diagram labels itself — "+
				"and on GitHub a fixed text colour is right in at most one of the two schemes. Delete it.",
				where, c))
		}

		// An edge is a line, not a box: nothing is written on its fill.
		fillValue, ok := decls["fill"]
		if !ok || m[1] == "linkStyle" {
			continue
		}
		fill, err := parseColour(fillValue)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: fill:%s is not a colour this check can read (%v); "+
				"write it as #rgb, #rrggbb or #rrggbbaa.", where, fillValue, err))
			continue
		}
		for _, key := range []string{"fill-opacity", "opacity"} {
			if v, ok := decls[key]; ok {
				f, err := parseOpacity(v)
				if err != nil {
					problems = append(problems, fmt.Sprintf("%s: %s:%s is not a number this check can read.", where, key, v))
					continue
				}
				fill.a *= f
			}
		}
		for _, r := range renderers {
			if got := r.worstContrast(fill); got < minLabelContrast {
				problems = append(problems, fmt.Sprintf("%s fill:%s leaves its label at %.2f:1 on %s (needs %.1f:1). "+
					"No opaque fill reads in both schemes; use a tint, e.g. fill:%s26.",
					where, fillValue, got, r.name, minLabelContrast, tintSuggestion(decls)))
				break
			}
		}
	}
	return problems
}

// worstContrast is the lowest contrast the renderer's label text has on a box
// filled with fill, over each thing a box can sit on: the page, the renderer's
// own subgraph fill, and the same tint again — a tinted box inside a subgraph
// tinted the same way.
func (r renderer) worstContrast(fill rgba) float64 {
	worst := math.Inf(1)
	for _, behind := range []rgba{r.page, over(r.subgraph, r.page), over(fill, r.page)} {
		box := over(fill, behind)
		worst = math.Min(worst, contrast(over(r.text, box), box))
	}
	return worst
}

// tintSuggestion names a hue for the failure message: the statement's own
// stroke, which is what keeps a tinted box recognisably its colour, or failing
// that the fill it replaces.
func tintSuggestion(decls map[string]string) string {
	for _, key := range []string{"stroke", "fill"} {
		if c, err := parseColour(decls[key]); err == nil && c.a > 0 {
			return fmt.Sprintf("#%02x%02x%02x", int(c.r), int(c.g), int(c.b))
		}
	}
	return "#888888"
}

// TestDiagramContrastModelMatchesTheBrowser pins the renderer model to the
// published site as a browser actually drew it. Each fill below was rendered
// by mkdocs-material in headless Chromium before this gate existed, and its
// labels measured from the computed styles of the page; the model has to
// reproduce every one. Without this the constants above could drift until the
// gate passed everything.
func TestDiagramContrastModelMatchesTheBrowser(t *testing.T) {
	measured := []struct {
		fill     string
		renderer int // index into renderers
		ratio    float64
		what     string
	}{
		{"#2d4a1e", 0, 1.02, "concepts.md decision boxes, light scheme"},
		{"#1e3a5f", 0, 1.17, "concepts.md plan-store boxes, light scheme"},
		{"#3a2d1e", 0, 1.36, "concepts.md user-input boxes, light scheme"},
		{"#4a1e1e", 0, 1.43, "concepts.md endpoint boxes, light scheme"},
		{"#2a2a2a", 0, 1.46, "concepts.md action boxes, light scheme"},
		{"#fde", 1, 1.11, "security/model.md workload box, dark scheme"},
		{"#e8f0fe", 1, 1.19, "security/model.md hub box, dark scheme"},
	}
	for _, m := range measured {
		fill, err := parseColour(m.fill)
		if err != nil {
			t.Fatal(err)
		}
		r := renderers[m.renderer]
		if got := r.worstContrast(fill); math.Abs(got-m.ratio) > 0.01 {
			t.Errorf("%s: the model puts fill %s at %.2f:1 on %s; the browser measured %.2f:1",
				m.what, m.fill, got, r.name, m.ratio)
		}
	}
}

// TestDiagramContrastCatchesTheDiagramItWasWrittenFor feeds the gate the
// statements that shipped, and the ones that replaced them.
func TestDiagramContrastCatchesTheDiagramItWasWrittenFor(t *testing.T) {
	shipped := strings.Join([]string{
		"flowchart TD",
		"    classDef queue fill:#1e3a5f,stroke:#4a90d9,color:#e8f4fd",
		"    classDef decision fill:#2d4a1e,stroke:#6abf4b,color:#e8f8e8",
		"    classDef action fill:#2a2a2a,stroke:#888,color:#eee",
		"    classDef endpoint fill:#4a1e1e,stroke:#d94a4a,color:#fde8e8",
		"    classDef user fill:#3a2d1e,stroke:#d9944a,color:#fdf0e8",
		"    style H fill:#e8f0fe,stroke:#4674d1,stroke-width:2px",
		"    style hub fill:#f6f8fa,stroke:#999",
	}, "\n")
	problems := checkDiagram("shipped.md", 1, shipped)
	// Seven fills, five text colours: every statement is wrong, and the text
	// colours are wrong independently of the fills they sat on.
	if len(problems) != 12 {
		t.Fatalf("the gate found %d problems in the diagram it exists for, want 12:\n%s",
			len(problems), strings.Join(problems, "\n"))
	}
	if !strings.Contains(problems[1], "fill:#4a90d926") {
		t.Errorf("a failing fill should suggest a tint of the stroke's hue; got:\n%s", problems[1])
	}

	fixed := strings.Join([]string{
		"flowchart TD",
		"    classDef queue fill:#4a90d926,stroke:#4a90d9",
		"    classDef decision fill:#4c9a2a26,stroke:#4c9a2a",
		"    classDef action fill:#88888826,stroke:#888",
		"    classDef endpoint fill:#d94a4a26,stroke:#d94a4a",
		"    classDef user fill:#c27c2c26,stroke:#c27c2c",
		"    style H fill:#4674d126,stroke:#4674d1,stroke-width:2px",
		"    style hub fill:#8888881a,stroke:#888",
		"    style W fill:#cc3399,fill-opacity:0.15,stroke:#c39",
	}, "\n")
	if problems := checkDiagram("fixed.md", 1, fixed); len(problems) != 0 {
		t.Errorf("tints should pass everywhere:\n%s", strings.Join(problems, "\n"))
	}
}

// TestDiagramContrastModelIsForThePinnedTheme fails when the published site
// moves to a different mkdocs-material release. Bumping it is fine; bumping it
// without re-reading the published-site renderer values above would leave
// this gate checking a theme nobody ships. They are in the built site's
// assets/stylesheets/palette.*.css (the slate scheme) and main.*.css (the
// default), and Material's mermaid CSS is in assets/javascripts/bundle.*.js.
func TestDiagramContrastModelIsForThePinnedTheme(t *testing.T) {
	path := filepath.Join(repoRoot(t), "website", "requirements.txt")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if !regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(materialPin) + `\s*$`).Match(b) {
		t.Fatalf("website/requirements.txt no longer pins %s. Re-read the published site's colours "+
			"for the new release, update the renderers in this file, then update materialPin.", materialPin)
	}
}

// ── colour arithmetic ──────────────────────────────────────────────────────

func mustHex(s string) rgba {
	c, err := parseColour(s)
	if err != nil {
		panic(err)
	}
	return c
}

// parseColour reads the colour forms a mermaid style list can carry. rgb() and
// hsl() are out: their commas would split the declaration list.
func parseColour(s string) (rgba, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "none", "transparent":
		return rgba{}, nil
	case "":
		return rgba{}, fmt.Errorf("empty")
	}
	h, ok := strings.CutPrefix(s, "#")
	if !ok {
		return rgba{}, fmt.Errorf("not a hex colour")
	}
	if len(h) == 3 || len(h) == 4 {
		var long strings.Builder
		for _, ch := range h {
			long.WriteRune(ch)
			long.WriteRune(ch)
		}
		h = long.String()
	}
	if len(h) != 6 && len(h) != 8 {
		return rgba{}, fmt.Errorf("want 3, 4, 6 or 8 hex digits")
	}
	v, err := strconv.ParseUint(h, 16, 32)
	if err != nil {
		return rgba{}, err
	}
	a := 1.0
	if len(h) == 8 {
		a = float64(v&0xff) / 255
		v >>= 8
	}
	return rgba{float64(v >> 16 & 0xff), float64(v >> 8 & 0xff), float64(v & 0xff), a}, nil
}

func parseOpacity(s string) (float64, error) {
	s = strings.TrimSpace(s)
	scale := 1.0
	if p, ok := strings.CutSuffix(s, "%"); ok {
		s, scale = p, 0.01
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f*scale < 0 || f*scale > 1 {
		return 0, fmt.Errorf("opacity %q", s)
	}
	return f * scale, nil
}

// hsla converts CSS hsla() to rgba, as the slate scheme writes its colours.
func hsla(h, s, l, a float64) rgba {
	c := (1 - math.Abs(2*l-1)) * s
	hp := math.Mod(h, 360) / 60
	x := c * (1 - math.Abs(math.Mod(hp, 2)-1))
	var r, g, b float64
	switch {
	case hp < 1:
		r, g = c, x
	case hp < 2:
		r, g = x, c
	case hp < 3:
		g, b = c, x
	case hp < 4:
		g, b = x, c
	case hp < 5:
		r, b = x, c
	default:
		r, b = c, x
	}
	m := l - c/2
	return rgba{(r + m) * 255, (g + m) * 255, (b + m) * 255, a}
}

// over composites top onto bottom (source-over).
func over(top, bottom rgba) rgba {
	a := top.a + bottom.a*(1-top.a)
	if a == 0 {
		return rgba{}
	}
	mix := func(t, b float64) float64 { return (t*top.a + b*bottom.a*(1-top.a)) / a }
	return rgba{mix(top.r, bottom.r), mix(top.g, bottom.g), mix(top.b, bottom.b), a}
}

// luminance is WCAG 2's relative luminance.
func luminance(c rgba) float64 {
	channel := func(v float64) float64 {
		v /= 255
		if v <= 0.03928 {
			return v / 12.92
		}
		return math.Pow((v+0.055)/1.055, 2.4)
	}
	return 0.2126*channel(c.r) + 0.7152*channel(c.g) + 0.0722*channel(c.b)
}

// contrast is WCAG 2's contrast ratio of two opaque colours.
func contrast(a, b rgba) float64 {
	la, lb := luminance(a), luminance(b)
	return (math.Max(la, lb) + 0.05) / (math.Min(la, lb) + 0.05)
}
