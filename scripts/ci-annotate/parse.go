package main

// parse.go turns what go test, go build and go vet print into findings: the
// reasons a step failed, each with the package and test it is about, the
// lines that show it, and where in the source it points.
//
// Both of go test's formats are read, and one input may mix them: a step
// that pipes go test -json through tee also catches the go command's own
// complaints, which are plain text. Plain output is split into one block per
// package at its result line ("ok  \tpkg\t1.2s", "FAIL\tpkg [build
// failed]"), since go test prints a package's output together even when it
// runs packages in parallel; -json is split by each event's Package. Either
// way a package's lines are then read in order, and a line belongs to a test
// by the rule the format follows: -json names it; -v output names it in its
// last "=== RUN/CONT/NAME" marker; and output without -v prints a failed
// test's log indented under its "--- FAIL" line.
//
// Compiler and vet output is not in any package's block: go prints it as it
// happens, under a "# pkg" header, or with no header at all from go vet.

import (
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// kind is what a finding is about. Its order is the ranking within a step:
// a package that did not build, crashed or hung before its tests finished
// explains more than a test that failed in it.
type kind int

const (
	kindBuild   kind = iota // a package did not build, vet or set up
	kindPanic               // a panic or fatal error crashed a test binary
	kindTimeout             // a test binary outlived its -timeout
	kindRace                // the race detector reported a data race
	kindTest                // a test failed
	kindPackage             // a package failed with no failing test
	kindStep                // a step failed and its output names no Go failure
)

// finding is one reason a step failed, as an annotation states it.
type finding struct {
	kind   kind
	pkg    string   // import path; "" when the output does not say
	test   string   // full test name; "" for a package or a step
	title  string   // set by entitle
	what   string   // a few words: "build failed", "data race in x.f", …
	body   []string // the lines that show it
	file   string   // where it points, relative to the module's root
	line   int
	col    int
	step   int    // the recorded step it came from; 0 outside -steps
	seq    int    // its place in the input
	source string // the input or step, for a finding no package names
}

// event is one line of go test -json (cmd/test2json).
type event struct {
	Action      string
	Package     string
	ImportPath  string // build-output and build-fail events (Go 1.24+)
	Test        string
	Output      string
	FailedBuild string
}

var (
	reResult  = regexp.MustCompile(`^(ok  |FAIL|\?   )\t(\S+)(.*)$`)
	reTestRes = regexp.MustCompile(`^(\s*)--- (FAIL|PASS|SKIP): (.+) \((\d+(?:\.\d+)?)s\)$`)
	reMarker  = regexp.MustCompile(`^=== (RUN|PAUSE|CONT|NAME)\b\s*(.*)$`)
	reHeader  = regexp.MustCompile(`^# (\S+)(?: \[(\S+)\])?$`)
	reVetHdr  = regexp.MustCompile(`^# \[(\S+)\]$`)
	reDiag    = regexp.MustCompile(`^(?:vet: )?([^\s:][^:]*\.go):(\d+):(\d+): (.*)$`)
	reLogLine = regexp.MustCompile(`^\s*([\w.+-]+\.go):(\d+): `)
	reRunning = regexp.MustCompile(`^\t\t(.+) \(([^)]*)\)$`)
	reGorHdr  = regexp.MustCompile(`^goroutine (\d+) \[([^\]]*)\]:$`)
	reFrame   = regexp.MustCompile(`^\s+(\S+\.go):(\d+)(?:\s+\+0x[0-9a-f]+)?$`)
	reAccess  = regexp.MustCompile(`^(?:Previous )?(?:[Aa]tomic )?(?:[Rr]ead|[Ww]rite) at 0x[0-9a-f]+ by (?:goroutine \d+|main goroutine):$`)
	reCreated = regexp.MustCompile(`^Goroutine \d+ \((?:running|finished)\) created at:$`)
	reTestFn  = regexp.MustCompile(`\.(Test[A-Z0-9_]?[A-Za-z0-9_]*)(?:\.func[0-9.]+)*\(`)
	reArgs    = regexp.MustCompile(`\([^()]*\)$`)
)

const raceRule = "=================="

// maxLine bounds one line as it is kept; a test can print a megabyte with no
// newline in it.
const maxLine = 64 << 10

// analyze reads one input and returns its findings, numbered from where it
// came in the step (step) and the order they appeared in.
func analyze(mod module, source string, step int, data []byte) []finding {
	var plain []string
	var events []event
	for _, l := range strings.Split(string(data), "\n") {
		if len(l) > maxLine {
			l = l[:maxLine]
		}
		if strings.HasPrefix(l, "{") {
			var e event
			if json.Unmarshal([]byte(l), &e) == nil && e.Action != "" {
				events = append(events, e)
				continue
			}
		}
		plain = append(plain, l)
	}
	// A trailing newline is not a line.
	if n := len(plain); n > 0 && plain[n-1] == "" {
		plain = plain[:n-1]
	}
	a := &analysis{mod: mod, source: source, step: step, results: map[string]string{}}
	a.plain(plain)
	a.json(events)
	a.builds()
	return a.found
}

// analysis collects one input's findings.
type analysis struct {
	mod    module
	source string
	step   int
	seq    int
	found  []finding

	compiled []buildBlock      // compiler and vet output, until every result is known
	results  map[string]string // package → "ok", "FAIL", "build failed", "setup failed", …
}

func (a *analysis) add(f finding) {
	a.seq++
	f.step, f.seq = a.step, a.seq
	if f.source == "" {
		f.source = a.source
	}
	a.found = append(a.found, f)
}

// buildBlock is compiler or vet output: a "# pkg" header (go vet adds "#
// [pkg]") and the diagnostics under it, or diagnostics with no header.
type buildBlock struct {
	pkg   string
	vet   bool
	lines []string
}

// pkgBlock is one package's lines of plain output and its result.
type pkgBlock struct {
	pkg, result string
	lines       []line
}

// line is a line of a package's output, and the test it belongs to when the
// input says (-json does).
type line struct {
	text  string
	test  string
	named bool
}

// verdict reads a result line's outcome.
func verdict(prefix, rest string) string {
	switch {
	case prefix == "ok  ":
		return "ok"
	case prefix == "?   ":
		return "no test files"
	case strings.Contains(rest, "[build failed]"):
		return "build failed"
	case strings.Contains(rest, "[setup failed]"):
		return "setup failed"
	}
	return "FAIL"
}

// splitBuild takes compiler and vet output out of lines, returning the
// blocks it found and what is left, in order.
func splitBuild(lines []string) (blocks []buildBlock, rest []string) {
	var cur *buildBlock
	flush := func() {
		if cur != nil && len(cur.lines) > 0 {
			blocks = append(blocks, *cur)
		}
		cur = nil
	}
	for _, l := range lines {
		if cur != nil {
			switch {
			case reVetHdr.MatchString(l):
				cur.vet = true
				continue
			case reDiag.MatchString(l), strings.HasPrefix(l, "\t"), strings.HasPrefix(l, "note: "), l == "too many errors":
				cur.lines = append(cur.lines, l)
				continue
			}
			flush()
		}
		if m := reVetHdr.FindStringSubmatch(l); m != nil {
			cur = &buildBlock{pkg: m[1], vet: true}
			continue
		}
		if m := reHeader.FindStringSubmatch(l); m != nil {
			cur = &buildBlock{pkg: m[1]}
			continue
		}
		if reDiag.MatchString(l) {
			// go vet prints its findings with no header.
			cur = &buildBlock{lines: []string{l}}
			continue
		}
		rest = append(rest, l)
	}
	flush()
	return blocks, rest
}

// plain reads go output that is not -json.
func (a *analysis) plain(lines []string) {
	builds, rest := splitBuild(lines)
	a.compiled = append(a.compiled, builds...)
	var blocks []pkgBlock
	var cur pkgBlock
	for _, l := range rest {
		if m := reResult.FindStringSubmatch(l); m != nil {
			cur.pkg, cur.result = m[2], verdict(m[1], m[3])
			a.results[cur.pkg] = cur.result
			blocks = append(blocks, cur)
			cur = pkgBlock{}
			continue
		}
		cur.lines = append(cur.lines, line{text: l})
	}
	if len(cur.lines) > 0 {
		blocks = append(blocks, cur) // a go test that was killed, or no go test at all
	}
	for _, b := range blocks {
		a.pkg(b.pkg, b.result, b.lines)
	}
}

// json reads go test -json events.
func (a *analysis) json(events []event) {
	if len(events) == 0 {
		return
	}
	type stream struct {
		lines   []line
		partial map[string]string // test → output not yet ended by a newline
		result  string
	}
	streams := map[string]*stream{}
	var order []string
	get := func(pkg string) *stream {
		s := streams[pkg]
		if s == nil {
			s = &stream{partial: map[string]string{}}
			streams[pkg] = s
			order = append(order, pkg)
		}
		return s
	}
	buildOut := map[string][]string{} // ImportPath → its build output
	var buildOrder []string
	failedBuild := map[string]string{} // ImportPath → the package whose test it failed
	for _, e := range events {
		switch e.Action {
		case "build-output":
			if _, ok := buildOut[e.ImportPath]; !ok {
				buildOrder = append(buildOrder, e.ImportPath)
			}
			buildOut[e.ImportPath] = append(buildOut[e.ImportPath], strings.TrimSuffix(e.Output, "\n"))
		case "output":
			s := get(e.Package)
			text := s.partial[e.Test] + e.Output
			if !strings.HasSuffix(text, "\n") {
				s.partial[e.Test] = text // test2json splits a long line
				continue
			}
			delete(s.partial, e.Test)
			for _, l := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
				if len(l) > maxLine {
					l = l[:maxLine]
				}
				if e.Test == "" {
					if m := reResult.FindStringSubmatch(l); m != nil {
						s.result = verdict(m[1], m[3])
						a.results[e.Package] = s.result
						continue
					}
				}
				s.lines = append(s.lines, line{text: l, test: e.Test, named: true})
			}
		case "fail":
			if e.Test == "" {
				s := get(e.Package)
				if s.result == "" {
					s.result = "FAIL"
				}
				if e.FailedBuild != "" {
					failedBuild[e.FailedBuild] = e.Package
				}
			}
		case "pass":
			if e.Test == "" {
				if s := get(e.Package); s.result == "" {
					s.result = "ok"
				}
			}
		}
	}
	for _, ip := range buildOrder {
		blocks, _ := splitBuild(buildOut[ip])
		for _, b := range blocks {
			if b.pkg == "" {
				b.pkg = failedBuild[ip]
				if b.pkg == "" {
					b.pkg, _, _ = strings.Cut(ip, " ")
				}
			}
			a.compiled = append(a.compiled, b)
		}
	}
	for _, pkg := range order {
		s := streams[pkg]
		tests := make([]string, 0, len(s.partial))
		for test := range s.partial {
			tests = append(tests, test)
		}
		sort.Strings(tests)
		for _, test := range tests { // output cut off without its newline
			s.lines = append(s.lines, line{text: s.partial[test], test: test, named: true})
		}
		a.pkg(pkg, s.result, s.lines)
	}
}

// special is a block of lines that is one finding on its own: a race
// report, or a panic or timeout and the goroutine dump after it.
type special struct {
	kind       kind
	start, end int // lines[start:end]
}

// pkg reads one package's output.
func (a *analysis) pkg(pkg, result string, lines []line) {
	n := len(lines)
	consumed := make([]bool, n)
	var specials []special
	for i := 0; i < n; {
		t := lines[i].text
		k, end := kind(-1), 0
		switch {
		case t == raceRule && i+1 < n && lines[i+1].text == "WARNING: DATA RACE":
			end = i + 2
			for end < n && lines[end].text != raceRule {
				end++
			}
			k, end = kindRace, min(end+1, n)
		case strings.HasPrefix(t, "panic: test timed out after "), strings.HasPrefix(t, "*** Test killed"):
			k, end = kindTimeout, dumpEnd(lines, i)
		case strings.HasPrefix(t, "panic: "), strings.HasPrefix(t, "fatal error: "):
			k, end = kindPanic, dumpEnd(lines, i)
		}
		if k < 0 {
			i++
			continue
		}
		specials = append(specials, special{kind: k, start: i, end: end})
		for j := i; j < end; j++ {
			consumed[j] = true
		}
		i = end
	}

	// Who each line belongs to.
	owner := make([]string, n)
	noise := make([]bool, n)
	var failed []string
	isFailed := map[string]bool{}
	chatty := false
	for _, l := range lines {
		if strings.HasPrefix(l.text, "=== RUN") {
			chatty = true
			break
		}
	}
	type header struct {
		indent int
		test   string
	}
	var stack []header
	current := ""
	for i, l := range lines {
		t := l.text
		if m := reTestRes.FindStringSubmatch(t); m != nil {
			name := m[3]
			if m[2] == "FAIL" && !isFailed[name] {
				isFailed[name] = true
				failed = append(failed, name)
			}
			indent := len(m[1])
			for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
				stack = stack[:len(stack)-1]
			}
			stack = append(stack, header{indent, name})
			owner[i], noise[i] = name, true
			// With -v a test's output comes before its result, so what
			// follows the result is no longer the test's.
			current = ""
			continue
		}
		if m := reMarker.FindStringSubmatch(t); m != nil {
			current, stack = strings.TrimSpace(m[2]), nil
			owner[i], noise[i] = current, true
			continue
		}
		if l.named {
			owner[i] = l.test
			continue
		}
		indent := len(t) - len(strings.TrimLeft(t, " "))
		if indent > 0 && !consumed[i] {
			found := false
			for k := len(stack) - 1; k >= 0; k-- {
				if stack[k].indent < indent {
					owner[i], found = stack[k].test, true
					break
				}
			}
			if found {
				continue
			}
		}
		if indent == 0 {
			stack = nil
		}
		if chatty {
			owner[i] = current
		}
	}

	explained := map[string]string{} // test → the special that explains its failure
	before := len(a.found)
	for _, s := range specials {
		block := texts(lines[s.start:s.end])
		test := owner[s.start]
		switch s.kind {
		case kindRace:
			if test == "" {
				// Without -v the race is printed before the test's result,
				// which then says it was the one running.
				for i := s.end; i < n && test == ""; i++ {
					if strings.Contains(lines[i].text, "race detected during execution of test") {
						test = owner[i]
					}
				}
			}
			if test == "" {
				test = testInFrames(block, pkg)
			}
			a.race(pkg, test, block)
			explained[test] = "race"
		case kindPanic:
			if test == "" {
				// Without -v the testing package prints a panicking test's
				// "--- FAIL" just before the panic. A panic in a goroutine
				// the test started has none, and the line before it may be
				// another test's: the panicking goroutine's frames decide.
				test = failedJustBefore(lines, s.start)
				var top []string
				if gs := goroutines(block); len(gs) > 0 {
					for _, fr := range gs[0].frames {
						top = append(top, fr.fn)
					}
				}
				if in := testInFrames(top, pkg); in != "" && test != in && !strings.HasPrefix(test, in+"/") {
					test = in
				}
			}
			a.panic(pkg, test, block)
			explained[test] = "panic"
		case kindTimeout:
			for _, r := range a.timeout(pkg, block) {
				explained[r] = "timeout"
			}
		}
	}

	// Failing tests, the ones with a failing subtest left to their subtests
	// unless they say something of their own.
	own := map[string][]string{}
	for i, l := range lines {
		if !consumed[i] && !noise[i] && owner[i] != "" {
			own[owner[i]] = append(own[owner[i]], l.text)
		}
	}
	for _, test := range failed {
		body := trimBlank(own[test])
		if explained[test] == "race" {
			body = dropContaining(body, "race detected during execution of test")
		}
		if len(body) == 0 && (explained[test] != "" || hasFailedChild(test, failed)) {
			continue
		}
		a.test(pkg, test, body)
	}

	// A package that failed with nothing to show for it.
	if result == "FAIL" && len(a.found) == before {
		var body []string
		for i, l := range lines {
			if consumed[i] || noise[i] || owner[i] != "" {
				continue
			}
			switch strings.TrimSpace(l.text) {
			case "", "PASS", "FAIL":
				continue
			}
			body = append(body, l.text)
		}
		f := finding{kind: kindPackage, pkg: pkg, what: "failed outside any test", body: body}
		if len(body) == 0 {
			f.body = []string{"The test binary failed, and printed nothing to say why."}
		}
		a.add(f)
	}
}

// builds turns compiler and vet output into findings, now that every
// package's result is known.
func (a *analysis) builds() {
	named := map[string]bool{}
	for _, b := range a.compiled {
		f := finding{kind: kindBuild, pkg: b.pkg, what: "build failed", body: b.lines}
		switch {
		case b.vet:
			f.what = "vet failed"
		case a.results[b.pkg] == "setup failed":
			f.what = "setup failed"
		case b.pkg == "":
			f.what = "vet failed" // go vet prints its findings without a header
		}
		for _, l := range b.lines {
			if m := reDiag.FindStringSubmatch(l); m != nil {
				if p, ok := a.mod.file(m[1]); ok {
					f.file = p
					f.line, _ = strconv.Atoi(m[2])
					f.col, _ = strconv.Atoi(m[3])
				}
				if f.pkg == "" {
					f.source = dirOf(m[1])
				}
				break
			}
		}
		named[b.pkg] = true
		a.add(f)
	}
	// A package that did not build because a dependency did not has no
	// output of its own.
	var dependents []string
	for pkg, r := range a.results {
		if (r == "build failed" || r == "setup failed") && !named[pkg] {
			dependents = append(dependents, pkg)
		}
	}
	if len(dependents) == 0 {
		return
	}
	sort.Strings(dependents)
	for i := range a.found {
		if a.found[i].kind == kindBuild {
			a.found[i].body = append(a.found[i].body, "", "Not built either, for want of it or of another package above:")
			for _, d := range dependents {
				a.found[i].body = append(a.found[i].body, "  "+a.mod.short(d))
			}
			return
		}
	}
	for _, d := range dependents {
		a.add(finding{kind: kindBuild, pkg: d, what: a.results[d],
			body: []string{"go printed no compiler or vet output for it; the step's log has the rest."}})
	}
}

func (a *analysis) test(pkg, test string, body []string) {
	f := finding{kind: kindTest, pkg: pkg, test: test, body: dedent(body)}
	// The last line the test logged is where it most likely failed: a
	// t.Fatal ends a test, and a t.Error tends to come after what it logged
	// to explain itself.
	for i := len(body) - 1; i >= 0; i-- {
		if m := reLogLine.FindStringSubmatch(body[i]); m != nil {
			f.file, f.line = a.inPackage(pkg, m[1], m[2])
			break
		}
	}
	a.add(f)
}

// inPackage resolves a file name the testing package printed — a base name,
// in the test's own package — to a path in the module.
func (a *analysis) inPackage(pkg, base, lineNo string) (string, int) {
	if a.mod.path == "" || pkg != a.mod.path && !strings.HasPrefix(pkg, a.mod.path+"/") {
		return "", 0
	}
	p, ok := a.mod.file(path.Join(a.mod.short(pkg), base))
	if !ok {
		return "", 0
	}
	n, _ := strconv.Atoi(lineNo)
	return p, n
}

// race reports a data race: both accesses' first frames and the test.
func (a *analysis) race(pkg, test string, block []string) {
	f := finding{kind: kindRace, pkg: pkg, test: test, what: "data race"}
	var first []frame
	for i := 0; i < len(block); i++ {
		l := block[i]
		access := reAccess.MatchString(l)
		if !access && !reCreated.MatchString(l) {
			continue
		}
		j := i + 1
		for j < len(block) && strings.TrimSpace(block[j]) != "" && block[j] != raceRule {
			j++
		}
		frames := parseFrames(block[i+1 : j])
		keep := 3
		if !access {
			keep = 1
		}
		f.body = append(f.body, l)
		for k, fr := range frames {
			if k == keep {
				break
			}
			f.body = append(f.body, "  "+fr.short(), "      "+a.where(fr))
		}
		if access && first == nil {
			first = frames
		}
		i = j - 1
	}
	if len(first) > 0 {
		f.what = "data race in " + first[0].short()
		f.file, f.line = a.anchor(first)
	}
	if test != "" {
		f.body = append(f.body, "", "during "+test)
	}
	a.add(f)
}

// panic reports a panic or fatal error: what it said and the top of the
// stack of the goroutine that raised it, below the runtime's and testing's
// own frames.
func (a *analysis) panic(pkg, test string, block []string) {
	f := finding{kind: kindPanic, pkg: pkg, test: test}
	i := 0
	for ; i < len(block) && i < 8; i++ {
		l := block[i]
		if strings.TrimSpace(l) == "" || reGorHdr.MatchString(l) {
			break
		}
		f.body = append(f.body, l)
	}
	f.what = strings.TrimSuffix(strings.TrimSuffix(block[0], " [recovered, repanicked]"), " [recovered]")
	gs := goroutines(block)
	if len(gs) > 0 {
		g := gs[0]
		frames := g.frames
		for len(frames) > 1 && machinery(frames[0].fn) {
			frames = frames[1:]
		}
		f.body = append(f.body, "", g.header)
		for k, fr := range frames {
			if k == 8 {
				f.body = append(f.body, "…")
				break
			}
			f.body = append(f.body, fr.short(), "\t"+a.where(fr))
		}
		f.file, f.line = a.anchor(frames)
	}
	a.add(f)
}

// timeout reports a test binary that outlived its -timeout: the tests that
// were still running, and where the goroutines running them were.
func (a *analysis) timeout(pkg string, block []string) []string {
	f := finding{kind: kindTimeout, pkg: pkg, what: strings.TrimPrefix(block[0], "panic: ")}
	f.body = append(f.body, block[0])
	var running []string
	for _, l := range block[1:] {
		if m := reRunning.FindStringSubmatch(l); m != nil {
			running = append(running, m[1])
			if len(running) == 1 {
				f.body = append(f.body, "running tests:")
			}
			f.body = append(f.body, "  "+m[1]+" ("+m[2]+")")
		}
	}
	// The deepest test still running is the one waiting.
	for _, r := range running {
		if !hasChild(r, running) {
			f.test = r
			break
		}
	}
	var stuck []string
	var parent frame // a test that is only waiting on its subtests
	prefix := pkg + "."
	for _, g := range goroutines(block) {
		for _, fr := range g.frames {
			if pkg == "" || !strings.HasPrefix(fr.fn, prefix) {
				continue
			}
			stuck = append(stuck, g.header+" "+fr.short()+" at "+a.where(fr))
			// Point at a goroutine that is doing the waiting, not at a
			// parent test blocked in t.Run until its subtest returns.
			waitsOnSubtest := len(g.frames) > 0 && strings.HasPrefix(g.frames[0].fn, "testing.(*T).Run(")
			switch {
			case f.file == "" && !waitsOnSubtest:
				f.file, f.line = a.anchor([]frame{fr})
			case waitsOnSubtest && parent.file == "":
				parent = fr
			}
			break
		}
		if len(stuck) == 5 {
			break
		}
	}
	if f.file == "" && parent.file != "" {
		f.file, f.line = a.anchor([]frame{parent})
	}
	if len(stuck) > 0 {
		f.body = append(f.body, "where the tests' goroutines were:")
		for _, s := range stuck {
			f.body = append(f.body, "  "+s)
		}
	}
	a.add(f)
	return running
}

// where renders a frame's location, relative to the module when it is in it
// and from the source tree or module cache otherwise.
func (a *analysis) where(fr frame) string {
	if p, ok := a.mod.file(fr.file); ok {
		return p + ":" + strconv.Itoa(fr.line)
	}
	file := fr.file
	for _, cut := range []string{"/src/", "/pkg/mod/"} {
		if i := strings.LastIndex(file, cut); i >= 0 {
			file = file[i+len(cut):]
			break
		}
	}
	return file + ":" + strconv.Itoa(fr.line)
}

// anchor is the first of frames that is in the module.
func (a *analysis) anchor(frames []frame) (string, int) {
	for _, fr := range frames {
		if p, ok := a.mod.file(fr.file); ok {
			return p, fr.line
		}
	}
	return "", 0
}

// frame is one call of a stack trace.
type frame struct {
	fn   string
	file string
	line int
}

// short is a frame's function without its import path or arguments.
func (fr frame) short() string {
	fn := strings.TrimPrefix(fr.fn, "created by ")
	if i := strings.Index(fn, " in goroutine "); i >= 0 {
		fn = fn[:i]
	}
	head, tail := fn, ""
	if i := strings.Index(fn, "("); i >= 0 {
		head, tail = fn[:i], fn[i:]
	}
	if i := strings.LastIndex(head, "/"); i >= 0 {
		head = head[i+1:]
	}
	fn = reArgs.ReplaceAllString(head+tail, "")
	if strings.HasPrefix(fr.fn, "created by ") {
		return "created by " + fn
	}
	return fn
}

// parseFrames reads the frames of a stack: a function line, then a line
// naming its file.
func parseFrames(lines []string) []frame {
	var out []frame
	for i := 0; i+1 < len(lines); i++ {
		fn := strings.TrimSpace(lines[i])
		if fn == "" || strings.HasSuffix(fn, ":") {
			continue
		}
		m := reFrame.FindStringSubmatch(lines[i+1])
		if m == nil {
			continue
		}
		n, _ := strconv.Atoi(m[2])
		out = append(out, frame{fn: fn, file: m[1], line: n})
		i++
	}
	return out
}

type goroutine struct {
	header string
	frames []frame
}

// goroutines reads the goroutine dump in a panic or timeout block.
func goroutines(block []string) []goroutine {
	var out []goroutine
	for i := 0; i < len(block); i++ {
		if !reGorHdr.MatchString(block[i]) {
			continue
		}
		j := i + 1
		for j < len(block) && strings.TrimSpace(block[j]) != "" && !reGorHdr.MatchString(block[j]) {
			j++
		}
		out = append(out, goroutine{header: strings.TrimSuffix(block[i], ":"), frames: parseFrames(block[i+1 : j])})
		i = j - 1
	}
	return out
}

// machinery is a frame the runtime or testing package adds above the one
// that panicked.
func machinery(fn string) bool {
	for _, p := range []string{"panic(", "runtime.", "testing.tRunner.func1", "created by "} {
		if strings.HasPrefix(fn, p) {
			return true
		}
	}
	return false
}

// dumpEnd is where the goroutine dump that starts at lines[i] ends.
func dumpEnd(lines []line, i int) int {
	for j := i + 1; j < len(lines); j++ {
		t := lines[j].text
		switch {
		case strings.HasPrefix(t, "=== "), strings.HasPrefix(t, "--- "), t == "FAIL", t == "PASS",
			strings.HasPrefix(t, "FAIL\t"), strings.HasPrefix(t, "ok  \t"), t == raceRule,
			strings.HasPrefix(t, "exit status "):
			return j
		}
	}
	return len(lines)
}

// failedJustBefore is the test whose "--- FAIL" line the testing package
// printed just before re-raising its panic, read back over the test's own
// indented log.
func failedJustBefore(lines []line, i int) string {
	for j := i - 1; j >= 0; j-- {
		t := lines[j].text
		if m := reTestRes.FindStringSubmatch(t); m != nil {
			if m[2] == "FAIL" {
				return m[3]
			}
			return ""
		}
		if !strings.HasPrefix(t, " ") {
			return ""
		}
	}
	return ""
}

// testInFrames names the test a stack runs in, from its frames.
func testInFrames(block []string, pkg string) string {
	for _, l := range block {
		t := strings.TrimSpace(l)
		if pkg != "" && !strings.HasPrefix(t, pkg+".") {
			continue
		}
		if m := reTestFn.FindStringSubmatch(t); m != nil {
			return m[1]
		}
	}
	return ""
}

func hasFailedChild(test string, failed []string) bool { return hasChild(test, failed) }

func hasChild(test string, names []string) bool {
	for _, n := range names {
		if strings.HasPrefix(n, test+"/") {
			return true
		}
	}
	return false
}

func texts(ls []line) []string {
	out := make([]string, len(ls))
	for i, l := range ls {
		out[i] = l.text
	}
	return out
}

func trimBlank(ls []string) []string {
	for len(ls) > 0 && strings.TrimSpace(ls[0]) == "" {
		ls = ls[1:]
	}
	for len(ls) > 0 && strings.TrimSpace(ls[len(ls)-1]) == "" {
		ls = ls[:len(ls)-1]
	}
	return ls
}

func dropContaining(ls []string, s string) []string {
	var out []string
	for _, l := range ls {
		if !strings.Contains(l, s) {
			out = append(out, l)
		}
	}
	return trimBlank(out)
}

// dedent removes the indentation every line shares.
func dedent(ls []string) []string {
	common := -1
	for _, l := range ls {
		if strings.TrimSpace(l) == "" {
			continue
		}
		n := len(l) - len(strings.TrimLeft(l, " "))
		if common < 0 || n < common {
			common = n
		}
	}
	if common <= 0 {
		return ls
	}
	out := make([]string, len(ls))
	for i, l := range ls {
		if len(l) >= common {
			out[i] = l[common:]
		} else {
			out[i] = strings.TrimLeft(l, " ")
		}
	}
	return out
}

func dirOf(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i]
	}
	return "."
}
