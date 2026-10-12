package docs_test

// Every residual risk the security model admits cites its evidence (Task
// 20424).
//
// The "What is not mitigated" section of docs/security/model.md is the list of
// what cloop does not defend against. Re-checked against the code, five of its
// twenty-one paragraphs described code that had moved on — one still said
// cloop verified no image signatures, long after it did — and two controls it
// took for granted held on one path and not another. Nothing tied a paragraph
// to the code it described, so nothing noticed.
//
// So each bold paragraph there must cite at least one test function defined in
// this module or one repository .go file that exists, and no citation in the
// section may be dead. The citation worth having is a test that pins the
// residual itself: the fix that retires the residual has to change that test,
// the citation then names nothing, and this gate fails until the paragraph is
// rewritten with the fix.

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// residualSection is the heading of the section this gate reads.
const residualSection = "## What is not mitigated"

// citedGoFile matches a repository .go file cited in prose, in backticks.
var citedGoFile = regexp.MustCompile("`((?:pkg|cmd|internal|tests)/[A-Za-z0-9_./-]+\\.go)`")

// residualParagraph is one bold paragraph of the section.
type residualParagraph struct {
	line  int
	title string
	text  string
}

// residualParagraphs returns the bold paragraphs of the section, in order.
// A paragraph is a run of non-blank lines; the residual ones open with a bold
// sentence at column 0. The section runs to the next level-two heading.
func residualParagraphs(doc string) []residualParagraph {
	lines := strings.Split(doc, "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == residualSection {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return nil
	}
	var out []residualParagraph
	var cur *residualParagraph
	flush := func() {
		if cur != nil {
			out = append(out, *cur)
			cur = nil
		}
	}
	inBlock := false
	for i := start; i < len(lines); i++ {
		l := lines[i]
		if strings.HasPrefix(l, "## ") {
			break
		}
		if strings.TrimSpace(l) == "" {
			inBlock = false
			continue
		}
		if !inBlock && strings.HasPrefix(l, "**") {
			flush()
			cur = &residualParagraph{line: i + 1}
		}
		inBlock = true
		if cur != nil {
			cur.text += l + "\n"
		}
	}
	flush()
	for i := range out {
		// The bold sentence, which may wrap.
		title := strings.TrimPrefix(out[i].text, "**")
		if end := strings.Index(title, "**"); end >= 0 {
			title = title[:end]
		}
		out[i].title = strings.Join(strings.Fields(title), " ")
	}
	return out
}

// residualProblems checks each paragraph's citations: tests against defined,
// files against exists. It returns how many paragraphs it read and what is
// wrong with them.
func residualProblems(doc string, defined map[string]bool, exists func(string) bool) (int, []string) {
	paras := residualParagraphs(doc)
	var problems []string
	for _, p := range paras {
		where := "model.md:" + strconv.Itoa(p.line) + " (" + strconv.Quote(p.title) + ")"
		live := 0
		for _, m := range citedTestName.FindAllStringSubmatch(p.text, -1) {
			if defined[m[1]] {
				live++
				continue
			}
			problems = append(problems, where+" cites "+m[1]+", which is not a test in this module")
		}
		for _, m := range citedGoFile.FindAllStringSubmatch(p.text, -1) {
			if exists(m[1]) {
				live++
				continue
			}
			problems = append(problems, where+" cites "+m[1]+", which does not exist")
		}
		if live == 0 {
			problems = append(problems, where+" cites no test and no file that pins what it says")
		}
	}
	return len(paras), problems
}

// TestEveryResidualRiskCitesEvidence is the gate.
func TestEveryResidualRiskCitesEvidence(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "docs", "security", "model.md"))
	if err != nil {
		t.Fatal(err)
	}
	exists := func(rel string) bool {
		fi, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
		return err == nil && !fi.IsDir()
	}
	n, problems := residualProblems(string(data), definedTests(t, root), exists)
	// Twenty-one when the gate was written. Far fewer is the parser going
	// blind — a renamed heading, a reformatted paragraph — not the list
	// getting shorter overnight.
	if n < 15 {
		t.Fatalf("only %d paragraphs read under %q in docs/security/model.md; the gate is not seeing the "+
			"section it was written for", n, residualSection)
	}
	for _, p := range problems {
		t.Errorf("%s.\n    A residual risk is a claim about the code. Cite the test that pins it — the one a fix "+
			"would have to change — or the file it lives in; when a fix retires it, rewrite the paragraph.", p)
	}
}

// TestResidualRiskGateCatchesAnUncitedParagraph is the gate's falsification
// control: a paragraph citing nothing, one citing a test that does not exist
// and one citing a file that does not exist are each reported; a paragraph
// with a live citation, prose that merely mentions testing, and text after
// the section are not.
func TestResidualRiskGateCatchesAnUncitedParagraph(t *testing.T) {
	doc := "# Model\n\n**Outside.** Not in the section (`TestNowhere`).\n\n" +
		residualSection + "\n\nStated plainly; Testing is prose.\n\n" +
		"**Pinned.** A residual (`TestPinned`) in `pkg/real/file.go`.\n\n" +
		"**Uncited.** Nothing backs this, though it\nspans two lines.\n\n" +
		"**Dead test.** It cites `TestRetired`.\n\n" +
		"**Dead file.** It cites `pkg/gone/file.go`.\n\n" +
		"---\n\n## See also\n\n**After.** Cites nothing and is not read.\n"
	defined := map[string]bool{"TestPinned": true}
	exists := func(rel string) bool { return rel == "pkg/real/file.go" }
	n, problems := residualProblems(doc, defined, exists)
	if n != 4 {
		t.Fatalf("read %d paragraphs, want the 4 in the section", n)
	}
	want := [][2]string{
		{`"Uncited."`, "cites no test"},
		{`"Dead test."`, "cites TestRetired"},
		{`"Dead test."`, "cites no test"},
		{`"Dead file."`, "cites pkg/gone/file.go"},
		{`"Dead file."`, "cites no test"},
	}
	if len(problems) != len(want) {
		t.Fatalf("problems = %q, want %d", problems, len(want))
	}
	for i, w := range want {
		if !strings.Contains(problems[i], w[0]) || !strings.Contains(problems[i], w[1]) {
			t.Errorf("problem %d = %q, want it to name %s and say %q", i, problems[i], w[0], w[1])
		}
	}
}
