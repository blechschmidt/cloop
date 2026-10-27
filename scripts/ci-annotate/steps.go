package main

// steps.go is -steps: the job's last step, reading what scripts/ci-step.sh
// recorded of every step before it and annotating the ones that failed.
//
// A recorded step is a numbered directory: script (the step's script), log
// (everything it printed), status (its exit status, written when it ended:
// a step with none was killed — its timeout-minutes, or a cancelled run),
// and annotated when the step annotated its own failure with this tool.

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type stepRecord struct {
	dir       string
	n         int
	status    string // "" when the step never finished
	command   string // the first command of its script
	annotated bool   // it annotated itself
	current   bool   // the step running this
}

func (s stepRecord) failed() bool { return s.status != "0" && !s.current }

func readSteps(dir, current string) []stepRecord {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []stepRecord
	for _, e := range entries {
		n, err := strconv.Atoi(e.Name())
		if err != nil || !e.IsDir() {
			continue
		}
		s := stepRecord{dir: filepath.Join(dir, e.Name()), n: n}
		if b, err := os.ReadFile(filepath.Join(s.dir, "status")); err == nil {
			s.status = strings.TrimSpace(string(b))
		}
		s.command = firstCommand(filepath.Join(s.dir, "script"))
		_, err = os.Stat(filepath.Join(s.dir, "annotated"))
		s.annotated = err == nil
		s.current = current != "" && sameDir(s.dir, current)
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].n < out[j].n })
	return out
}

func sameDir(a, b string) bool {
	sa, ea := os.Stat(a)
	sb, eb := os.Stat(b)
	return ea == nil && eb == nil && os.SameFile(sa, sb)
}

// failedSteps are the steps -steps reports on.
func (r *reporter) failedSteps() []stepRecord {
	var out []stepRecord
	for _, s := range r.steps {
		if s.failed() {
			out = append(out, s)
		}
	}
	return out
}

// annotateSteps annotates the failed steps recorded under dir.
func (r *reporter) annotateSteps(dir string) {
	r.steps = readSteps(dir, r.stepDir)
	// GitHub keeps fifty annotations a job. The job's steps have used some:
	// whatever they emitted themselves, at most ten of each level a step,
	// and the "Process completed with exit code" GitHub adds to each that
	// failed. One more for the notices GitHub adds when it sets a job up.
	used := 1
	for _, s := range r.steps {
		for _, n := range countCommands(filepath.Join(s.dir, "log")) {
			used += min(n, r.opts.stepMax)
		}
		if s.failed() {
			used++
		}
	}
	for _, s := range r.failedSteps() {
		if s.annotated {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, "log"))
		if err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(r.log, "ci-annotate: step %d: %v\n", s.n, err)
		}
		fs := analyze(r.mod, s.command, s.n, data)
		if len(fs) == 0 {
			fs = []finding{r.stepTail(s, data)}
		}
		r.findings = append(r.findings, fs...)
	}
	r.emit(min(r.opts.stepMax, r.opts.jobMax-used))
}

// stepTail is a failed step whose output names no Go failure: its last
// lines say why, as far as anything does.
func (r *reporter) stepTail(s stepRecord, data []byte) finding {
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(data) == 0 {
		lines = []string{"(the step printed nothing)"}
	}
	if len(lines) > r.opts.tail {
		lines = lines[len(lines)-r.opts.tail:]
	}
	what := fmt.Sprintf("A step exited %s: %s", s.status, s.command)
	if s.status == "" {
		what = "A step was killed before it finished (its timeout-minutes, or a cancelled run): " + s.command
	}
	return finding{kind: kindStep, what: what, body: lines, step: s.n, source: s.command}
}

// firstCommand is the first line of a step's script that does something:
// not a comment, not a shell option.
func firstCommand(script string) string {
	f, err := os.Open(script)
	if err != nil {
		return "(the script was not recorded)"
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "set ") || strings.HasPrefix(t, "shopt ") {
			continue
		}
		t = strings.TrimSpace(strings.TrimSuffix(t, "\\"))
		return clipLine(t, 80)
	}
	return "(an empty script)"
}

// countCommands counts the annotation commands a log carries, by level, as
// GitHub's runner reads them: a line that starts with "::error" — after any
// leading whitespace, which the runner trims — or the older "##[error]".
func countCommands(path string) map[string]int {
	counts := map[string]int{}
	f, err := os.Open(path)
	if err != nil {
		return counts
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 64<<10)
	for {
		// The start of each line is enough, however long the line.
		head, isPrefix, err := br.ReadLine()
		if err != nil {
			return counts
		}
		t := strings.TrimLeft(string(head), " \t")
		for _, level := range []string{"error", "warning", "notice"} {
			if strings.HasPrefix(t, "::"+level+" ") || strings.HasPrefix(t, "::"+level+"::") ||
				strings.HasPrefix(t, "##["+level+"]") {
				counts[level]++
			}
		}
		for isPrefix && err == nil {
			_, isPrefix, err = br.ReadLine()
		}
	}
}

// jobCommands is what every recorded step of the job has emitted so far,
// each level capped as GitHub caps it.
func jobCommands(dir string) int {
	used := 0
	for _, s := range readSteps(dir, "") {
		for _, n := range countCommands(filepath.Join(s.dir, "log")) {
			used += min(n, 10)
		}
	}
	return used
}
