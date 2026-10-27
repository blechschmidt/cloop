// Command ci-annotate says why a CI step failed, where a reader without a
// token can see it: in the annotations of the job's check run.
//
// A GitHub Actions job log can only be read with admin rights on the
// repository — GET /repos/{owner}/{repo}/actions/jobs/{id}/logs answers 403
// without them — while a check run's annotations come back from the public
// API to anyone (GET /repos/{owner}/{repo}/check-runs/{id}/annotations; a
// job's id is its check run's). A failed job's only annotation used to be
// "Process completed with exit code 1." (Task 20444).
//
// This reads what go test, go build and go vet print — the plain text a
// tee'd step writes, or go test -json — and emits one GitHub workflow command
// per cause: a failing test, a panic, a data race, a test binary that
// outlived its -timeout, a package that did not build, vet or set up. GitHub
// keeps the first ten annotations of each level a step emits and fifty a job,
// so the causes are ranked — the first failed step first, and within it
// what stopped a package from running at all before what failed inside one —
// and whatever does not fit is folded into the last annotation that does.
// Everything, unabridged, goes to the step summary.
//
//	go run ./scripts/ci-annotate [flags] FILE...   annotate go output (- is stdin)
//	go run ./scripts/ci-annotate -steps DIR        annotate a job's failed steps
//
// The second form is what each CI job's last step runs, through
// scripts/ci-step.sh --why: DIR holds every step's recorded output and exit
// status, and a failed step whose output names no Go failure is annotated
// with its last lines instead.
//
// It never decides a verdict: it exits 0 whatever it finds, and 2 only for a
// command line it cannot use.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}

// options are the command line's.
type options struct {
	level   string // the annotations' level: error, warning or notice
	stepMax int    // annotations of one level GitHub keeps for a step
	jobMax  int    // annotations GitHub keeps for a job
	steps   string // the recorded steps to annotate the failed ones of
	tail    int    // lines of a failed step with no Go finding to annotate
	summary string // Markdown file the report is appended to
	root    string // the module's root
}

func run(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	fs := flag.NewFlagSet("ci-annotate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o options
	fs.StringVar(&o.level, "level", "error", "the annotations' level: error, warning or notice")
	fs.IntVar(&o.stepMax, "max", 10, "annotations of one level GitHub keeps for a step")
	fs.IntVar(&o.jobMax, "job-max", 50, "annotations GitHub keeps for a job")
	fs.StringVar(&o.steps, "steps", "", "a directory of steps scripts/ci-step.sh recorded: annotate the ones that failed")
	fs.IntVar(&o.tail, "tail", 40, "with -steps: how many last lines to annotate of a failed step whose output names no Go failure")
	fs.StringVar(&o.summary, "summary", getenv("GITHUB_STEP_SUMMARY"), "a Markdown file to append the full report to (empty: none)")
	fs.StringVar(&o.root, "root", "", "the module's root (default: the nearest directory above this one holding go.mod)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: ci-annotate [flags] FILE...\n       ci-annotate [flags] -steps DIR\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	switch o.level {
	case "error", "warning", "notice":
	default:
		fmt.Fprintf(stderr, "ci-annotate: -level %q: want error, warning or notice\n", o.level)
		return 2
	}
	if (o.steps == "") == (fs.NArg() == 0) {
		fs.Usage()
		return 2
	}

	mod := findModule(o.root)
	r := &reporter{opts: o, mod: mod, out: stdout, log: stderr, stepDir: getenv("CI_WHY_STEP_DIR")}
	if o.steps != "" {
		r.annotateSteps(o.steps)
		return 0
	}
	for _, name := range fs.Args() {
		data, err := readInput(name)
		if err != nil {
			fmt.Fprintf(stderr, "ci-annotate: %v\n", err)
			continue
		}
		source := filepath.Base(name)
		if name == "-" {
			source = "stdin"
		}
		r.findings = append(r.findings, analyze(mod, source, 0, data)...)
	}
	r.annotateFiles()
	return 0
}

// maxInput bounds what is read of one input. The cause of a failure is
// rarely in a log's middle, and a step that printed more than this has
// printed it many times over; the first and last halves are kept.
const maxInput = 256 << 20

func readInput(name string) ([]byte, error) {
	if name == "-" {
		data, err := io.ReadAll(io.LimitReader(os.Stdin, maxInput))
		_, _ = io.Copy(io.Discard, os.Stdin) // never leave a writer blocked on a full pipe
		return data, err
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() <= maxInput {
		return io.ReadAll(f)
	}
	// Keep the start, where builds fail, and the end, where a test binary
	// that died says so.
	half := int64(maxInput / 2)
	data := make([]byte, half, maxInput+8)
	if _, err := f.ReadAt(data, 0); err != nil {
		return nil, err
	}
	tail := make([]byte, half)
	if _, err := f.ReadAt(tail, st.Size()-half); err != nil {
		return nil, err
	}
	return append(append(data, "\n…\n"...), tail...), nil
}

// module is the Go module the output came from: where it is, so that file
// names can be turned into paths an annotation can point at, and what it is
// called, so that package names can be shortened to the directories a
// reader knows them by.
type module struct {
	root string // absolute; "" when no go.mod was found
	path string
}

func findModule(root string) module {
	if root == "" {
		dir, err := os.Getwd()
		if err != nil {
			return module{}
		}
		for {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				root = dir
				break
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				return module{}
			}
			dir = parent
		}
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return module{}
	}
	m := module{root: abs}
	if data, err := os.ReadFile(filepath.Join(abs, "go.mod")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if f := strings.Fields(line); len(f) >= 2 && f[0] == "module" {
				m.path = strings.Trim(f[1], `"`)
				break
			}
		}
	}
	return m
}

// short names a package the way a reader types it: by its directory within
// the module ("pkg/ui"), or by its import path when it is not in the module.
func (m module) short(pkg string) string {
	switch {
	case pkg == "" || m.path == "":
		return pkg
	case pkg == m.path:
		return "."
	case strings.HasPrefix(pkg, m.path+"/"):
		return pkg[len(m.path)+1:]
	}
	return pkg
}

// file returns the path of p relative to the module's root, slash-separated,
// if p names a file in the module: relative to the root already, or an
// absolute path on this machine or on the one the output was recorded on.
func (m module) file(p string) (string, bool) {
	if m.root == "" || p == "" {
		return "", false
	}
	p = filepath.Clean(filepath.FromSlash(p))
	exists := func(rel string) bool {
		st, err := os.Stat(filepath.Join(m.root, rel))
		return err == nil && !st.IsDir()
	}
	if !filepath.IsAbs(p) {
		if !strings.HasPrefix(p, "..") && exists(p) {
			return filepath.ToSlash(p), true
		}
		return "", false
	}
	if rel, err := filepath.Rel(m.root, p); err == nil && !strings.HasPrefix(rel, "..") && exists(rel) {
		return filepath.ToSlash(rel), true
	}
	// Recorded elsewhere — a runner's checkout, another developer's: the
	// longest tail of the path that names a file here, as long as it keeps
	// a directory (a bare file name would match too much).
	parts := strings.Split(filepath.ToSlash(p), "/")
	for i := 1; i < len(parts)-1; i++ {
		rel := strings.Join(parts[i:], "/")
		if exists(rel) {
			return rel, true
		}
	}
	return "", false
}
