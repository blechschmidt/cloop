package main

// emit.go writes findings out: as GitHub workflow commands, within what
// GitHub keeps of them, and as the step summary, which keeps everything.

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// reporter ranks, folds and writes one invocation's findings.
type reporter struct {
	opts     options
	mod      module
	out, log io.Writer
	stepDir  string // CI_WHY_STEP_DIR: the step this runs in, when scripts/ci-step.sh recorded it

	findings []finding
	steps    []stepRecord // -steps: the job's steps
}

// Limits on what one annotation carries. GitHub accepts far more (64 KiB a
// message), but an annotation is read in a list; the summary has the rest.
const (
	maxTitle     = 200
	maxBodyLines = 30
	maxLineWidth = 300
	maxSummary   = 512 << 10 // GitHub refuses a step summary over 1 MiB
	summaryLines = 200       // of one finding, in the summary
)

// annotateFiles emits the findings of the inputs on the command line, for a
// step that annotates its own output.
func (r *reporter) annotateFiles() {
	stepUsed, jobUsed := 0, 0
	if r.stepDir != "" {
		// What the step has emitted so far counts against its own cap, and
		// what the job's other steps emitted against the job's.
		stepUsed = countCommands(filepath.Join(r.stepDir, "log"))[r.opts.level]
		jobUsed = jobCommands(filepath.Dir(r.stepDir))
	}
	budget := min(r.opts.stepMax-stepUsed, r.opts.jobMax-jobUsed)
	emitted := r.emit(budget)
	if emitted > 0 && r.stepDir != "" {
		// The job's last step reads this and leaves the step to us.
		_ = os.WriteFile(filepath.Join(r.stepDir, "annotated"), []byte(strconv.Itoa(emitted)+"\n"), 0o644)
	}
}

// rank orders findings: the first failed step's first, then within a step by
// kind, then in the order they were printed. Findings that say the same
// thing twice — one test reported by two inputs — are kept once.
func rank(fs []finding) []finding {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.step != b.step {
			return a.step < b.step
		}
		if a.kind != b.kind {
			return a.kind < b.kind
		}
		return a.seq < b.seq
	})
	seen := map[string]bool{}
	out := fs[:0]
	for _, f := range fs {
		key := fmt.Sprintf("%d\x00%s\x00%s\x00%s", f.kind, f.pkg, f.test, f.what)
		if f.kind == kindStep {
			key += "\x00" + strconv.Itoa(f.step)
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

// emit writes the findings as annotations, at most budget of them, and the
// full report to the summary. It returns how many annotations it wrote.
func (r *reporter) emit(budget int) int {
	fs := rank(r.findings)
	for i := range fs {
		fs[i].title = r.entitle(fs[i])
	}
	shown := plan(fs, budget)
	for _, f := range shown {
		fmt.Fprintln(r.out, command(r.opts.level, f))
	}
	switch {
	case len(fs) == 0:
	case len(shown) == 0:
		fmt.Fprintf(r.log, "ci-annotate: %d finding(s), and GitHub keeps no more annotations for this step or job; they are in the step summary\n", len(fs))
	default:
		fmt.Fprintf(r.log, "ci-annotate: %d finding(s), %d annotation(s)\n", len(fs), len(shown))
	}
	if len(fs) > 0 || len(r.failedSteps()) > 0 {
		r.writeSummary(fs, len(shown))
	}
	return len(shown)
}

// plan picks the annotations to write: every finding when they fit, and
// otherwise the first budget-1 and one more that lists the rest, so that the
// first cause is never the one GitHub drops.
func plan(fs []finding, budget int) []finding {
	if budget <= 0 || len(fs) == 0 {
		return nil
	}
	if len(fs) <= budget {
		return fs
	}
	if budget == 1 {
		f := fs[0]
		f.body = append(append(append([]string{}, clip(f.body, 12)...), ""), foldLines(fs[1:])...)
		return []finding{f}
	}
	shown := append([]finding{}, fs[:budget-1]...)
	rest := fs[budget-1:]
	return append(shown, finding{
		title: fmt.Sprintf("…and %d more reasons, folded into this one (the step summary has them all)", len(rest)),
		body:  foldLines(rest),
	})
}

func foldLines(fs []finding) []string {
	out := []string{fmt.Sprintf("%d more:", len(fs))}
	for i, f := range fs {
		if i == maxBodyLines-1 {
			out = append(out, fmt.Sprintf("…and %d after that", len(fs)-i))
			break
		}
		where := ""
		if f.file != "" {
			where = " (" + f.file + ":" + strconv.Itoa(f.line) + ")"
		}
		out = append(out, "- "+f.title+where)
	}
	return out
}

// entitle names a finding: "<package> <Test>" for a test, as a reader finds
// it with go test -run, and what went wrong for anything else.
func (r *reporter) entitle(f finding) string {
	who := r.mod.short(f.pkg)
	if who == "" {
		who = f.source
	}
	if f.test != "" {
		who = strings.TrimSpace(who + " " + f.test)
	}
	var t string
	switch {
	case f.kind == kindTest:
		t = who
	case f.kind == kindStep:
		t = f.what
	case who == "":
		t = f.what
	default:
		t = who + ": " + f.what
	}
	return clipLine(t, maxTitle)
}

// command renders a finding as a workflow command.
func command(level string, f finding) string {
	var props []string
	if f.file != "" {
		props = append(props, "file="+escapeProperty(f.file))
		if f.line > 0 {
			props = append(props, "line="+strconv.Itoa(f.line))
		}
		if f.col > 0 {
			props = append(props, "col="+strconv.Itoa(f.col))
		}
	}
	props = append(props, "title="+escapeProperty(clean(f.title)))
	// A step's tail is already the -tail lines it was asked for.
	body := clip(f.body, maxBodyLines)
	if f.kind == kindStep {
		body = append([]string{}, f.body...)
	}
	for i, l := range body {
		body[i] = clipLine(clean(l), maxLineWidth)
	}
	msg := strings.Join(body, "\n")
	if strings.TrimSpace(msg) == "" {
		msg = clean(f.title)
	}
	return "::" + level + " " + strings.Join(props, ",") + "::" + escapeData(msg)
}

// escapeData escapes a workflow command's message as GitHub's runner
// unescapes it: %, CR and LF, so that the message stays on its one line and
// nothing in it can start another command.
func escapeData(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	return strings.ReplaceAll(s, "\n", "%0A")
}

// escapeProperty escapes a property value: the message's escapes, and the
// ':' and ',' that would end the value or the property list.
func escapeProperty(s string) string {
	s = escapeData(s)
	s = strings.ReplaceAll(s, ":", "%3A")
	return strings.ReplaceAll(s, ",", "%2C")
}

var reANSI = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

// clean makes a line of log fit for an annotation: no terminal colours, no
// control characters but the tab and carriage return a reader may want to
// see (the escapes carry those), valid UTF-8.
func clean(s string) string {
	s = reANSI.ReplaceAllString(s, "")
	s = strings.ToValidUTF8(s, "�")
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' && r != '\r' || r == 0x7f {
			return '�'
		}
		return r
	}, s)
}

// clip keeps at most n lines: the first two thirds and the last third, since
// a failure's log ends with what failed and begins with what led to it.
func clip(ls []string, n int) []string {
	if len(ls) <= n {
		return append([]string{}, ls...)
	}
	tail := n / 3
	head := n - tail - 1
	out := append([]string{}, ls[:head]...)
	out = append(out, fmt.Sprintf("… %d more lines …", len(ls)-head-tail))
	return append(out, ls[len(ls)-tail:]...)
}

func clipLine(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	rs := []rune(s)
	return string(rs[:n-1]) + "…"
}

// writeSummary appends the report to the step summary: every finding with
// its full excerpt, which no cap applies to.
func (r *reporter) writeSummary(fs []finding, shown int) {
	if r.opts.summary == "" {
		return
	}
	var b strings.Builder
	b.WriteString("## Why it failed\n\n")
	selfAnnotated := 0
	if failed := r.failedSteps(); len(failed) > 0 {
		b.WriteString("| Step | Exit status | Its script begins |\n| --- | --- | --- |\n")
		for _, s := range failed {
			status := s.status
			if status == "" {
				status = "killed"
			}
			note := ""
			if s.annotated {
				note = " (it annotated its own failure)"
				selfAnnotated++
			}
			fmt.Fprintf(&b, "| %d | %s | %s%s |\n", s.n, status, code(s.command), note)
		}
		b.WriteString("\n")
	}
	switch {
	case len(fs) == 0 && selfAnnotated > 0:
		b.WriteString("The failed steps annotated their own failures.\n")
	case len(fs) == 0:
		b.WriteString("Nothing in the output named a cause.\n")
	case shown == len(fs):
		fmt.Fprintf(&b, "%d reason(s), each annotated on this job.\n\n", len(fs))
	case shown == 0:
		fmt.Fprintf(&b, "%d reason(s). GitHub keeps no more annotations for this step or job, so they are only here.\n\n", len(fs))
	default:
		fmt.Fprintf(&b, "%d reasons. GitHub keeps ten annotations a step and fifty a job, so the first %d are annotated and the last annotation lists the rest.\n\n", len(fs), shown-1)
	}
	for i, f := range fs {
		where := ""
		if f.file != "" {
			where = " — " + code(f.file+":"+strconv.Itoa(f.line))
		}
		fmt.Fprintf(&b, "<details><summary>%d. %s%s</summary>\n\n", i+1, html(f.title), where)
		body := clip(f.body, summaryLines)
		for j, l := range body {
			body[j] = clean(l)
		}
		text := strings.Join(body, "\n")
		fence := fenceFor(text)
		fmt.Fprintf(&b, "%stext\n%s\n%s\n\n</details>\n\n", fence, text, fence)
		if b.Len() > maxSummary {
			fmt.Fprintf(&b, "…and %d more, cut to keep this summary under GitHub's limit.\n", len(fs)-i-1)
			break
		}
	}
	f, err := os.OpenFile(r.opts.summary, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Fprintf(r.log, "ci-annotate: step summary: %v\n", err)
		return
	}
	defer f.Close()
	if _, err := io.WriteString(f, b.String()); err != nil {
		fmt.Fprintf(r.log, "ci-annotate: step summary: %v\n", err)
	}
}

// code renders s as inline Markdown code that survives its own backticks
// and a table's pipes.
func code(s string) string {
	s = strings.ReplaceAll(clean(s), "|", "\\|")
	ticks := "`"
	for strings.Contains(s, ticks) {
		ticks += "`"
	}
	pad := ""
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		pad = " "
	}
	return ticks + pad + s + pad + ticks
}

// fenceFor is a code fence longer than any run of backticks in text.
func fenceFor(text string) string {
	longest, run := 0, 0
	for _, c := range text {
		if c == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	return strings.Repeat("`", max(3, longest+1))
}

func html(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(clean(s))
}
