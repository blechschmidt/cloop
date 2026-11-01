package requirements

// specfile.go: requirements as code (Task 20459).
//
// A project's requirements live in the hub's database, where the dashboard and
// `cloop requirements` keep them beside their checks. That is no place to
// review a change in a pull request, to keep a requirement beside the code it
// governs, or for a CI job with no hub to gate on. So they have a second home,
// .cloop/requirements.yaml in the project's repository:
//
//	version: 1
//	requirements:
//	  - id: R-3
//	    title: Config errors exit non-zero
//	    status: approved
//	    priority: must
//	    tags: [cli, config]
//	    details: |
//	      A malformed config.yaml makes every command exit 2 and name the line.
//	    tests:
//	      - name: malformed config
//	        command: go test ./pkg/config -run TestMalformed
//	        timeout: 2m
//
// and merge.go reconciles the two homes.
//
// The file is read strictly, because a requirement's tests are commands that
// run: a misspelt key is a field silently dropped, and `test:` for `tests:`
// would be a requirement that checks nothing and passes every gate. So an
// unknown key is an error, as is a key given twice, an id given to two
// requirements, a YAML anchor, alias or tag, a second document, and any field
// outside the bounds the database holds a requirement to (Normalize). Every
// error carries the line it is on, and every error is reported, not only the
// first, up to maxSpecErrors.
//
// The parser walks yaml.Node rather than decoding into structs: a struct
// decode can refuse unknown fields, but it cannot say where a bound was broken,
// and it would quietly expand an alias. ParseSpecFile is also what the hub runs
// on a file an executor sent it — the hub never reads the file itself
// (ReadSpecFile and LoadSpecFile are the CLI's and the executor's; a call-graph
// test in tests/security holds the hub to that) — so it must stand any input:
// FuzzParseSpecFile.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	// SpecFileName is where a project keeps its requirements as code,
	// relative to its root.
	SpecFileName = ".cloop/requirements.yaml"
	// SpecFileVersion is the version of the format this cloop reads and
	// writes.
	SpecFileVersion = 1
	// MaxSpecFileBytes bounds a spec file. An executor sends the hub the
	// whole file, and the hub keeps at most 4 MiB of what a dispatched
	// command prints (the file travels base64-encoded).
	MaxSpecFileBytes = 2 << 20
	// maxSpecErrors bounds how many problems one parse reports.
	maxSpecErrors = 50
)

// ErrNoSpecFile is what reading a project's spec file answers when it has
// none.
var ErrNoSpecFile = errors.New("no requirements spec file")

// specRequirementKeys and specTestKeys are the keys a requirement and a test
// may have, in the order RenderSpecFile writes them.
var (
	specFileKeys        = []string{"version", "requirements"}
	specRequirementKeys = []string{"id", "title", "status", "priority", "tags", "details", "tests"}
	specTestKeys        = []string{"name", "command", "timeout"}
)

// specKeyHints names the key someone most likely meant by a key the format
// does not have: the API's and the database's names for the same fields.
var specKeyHints = map[string]string{
	"description":     "details",
	"desc":            "details",
	"detail":          "details",
	"test":            "tests",
	"tag":             "tags",
	"timeout_seconds": "timeout",
	"cmd":             "command",
	"run":             "command",
}

// SpecError is one problem with a spec file, and where it is.
type SpecError struct {
	Line    int    `json:"line,omitempty"`
	Column  int    `json:"column,omitempty"`
	Message string `json:"message"`
}

func (e SpecError) Error() string {
	switch {
	case e.Line > 0 && e.Column > 0:
		return fmt.Sprintf("line %d, column %d: %s", e.Line, e.Column, e.Message)
	case e.Line > 0:
		return fmt.Sprintf("line %d: %s", e.Line, e.Message)
	}
	return e.Message
}

// SpecErrors is every problem a parse found, in the order of the file. It is
// an ErrInvalid.
type SpecErrors []SpecError

func (es SpecErrors) Error() string {
	if len(es) == 1 {
		return "invalid requirements spec: " + es[0].Error()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "invalid requirements spec, %d problems:", len(es))
	for _, e := range es {
		b.WriteString("\n  " + e.Error())
	}
	return b.String()
}

// Unwrap makes a spec's problems an ErrInvalid: the file's author's mistake.
func (es SpecErrors) Unwrap() error { return ErrInvalid }

// SpecFile is a spec file as read: its requirements, normalised, in the order
// the file gives them.
type SpecFile struct {
	Requirements []Requirement
	lines        map[int]int
}

// Line is the line requirement id starts on, or 0.
func (f SpecFile) Line(id int) int { return f.lines[id] }

// Counts tallies f's requirements by status.
func (f SpecFile) Counts() map[string]int {
	out := map[string]int{}
	for _, r := range f.Requirements {
		out[r.CurrentStatus()]++
	}
	return out
}

// SpecSHA256 is the hex SHA-256 of a spec file's bytes: which file a read, an
// import or an export was about.
func SpecSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ParseSpecFile reads a spec file's contents: every requirement in it,
// normalised, or every problem with it as SpecErrors.
func ParseSpecFile(data []byte) (SpecFile, error) {
	var p specParser
	f := p.parse(data)
	if len(p.errs) == 0 {
		return f, nil
	}
	sort.SliceStable(p.errs, func(i, j int) bool {
		a, b := p.errs[i], p.errs[j]
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Column < b.Column
	})
	if p.truncated {
		p.errs = append(p.errs, SpecError{Message: fmt.Sprintf("and more: fix these %d first", maxSpecErrors)})
	}
	return SpecFile{}, p.errs
}

type specParser struct {
	errs      SpecErrors
	truncated bool
}

// at records a problem at n's line and column (n may be nil).
func (p *specParser) at(n *yaml.Node, format string, a ...any) {
	if len(p.errs) >= maxSpecErrors {
		p.truncated = true
		return
	}
	e := SpecError{Message: fmt.Sprintf(format, a...)}
	if n != nil {
		e.Line, e.Column = n.Line, n.Column
	}
	p.errs = append(p.errs, e)
}

func (p *specParser) parse(data []byte) SpecFile {
	if len(data) > MaxSpecFileBytes {
		p.at(nil, "the file is %d bytes, more than the %d a spec file may hold", len(data), MaxSpecFileBytes)
		return SpecFile{}
	}
	if i := invalidUTF8At(data); i >= 0 {
		p.at(&yaml.Node{Line: 1 + bytes.Count(data[:i], []byte{'\n'})}, "the file is not UTF-8 text")
		return SpecFile{}
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			p.at(nil, "the file is empty: it starts with `version: %d` and lists the requirements under `requirements:`",
				SpecFileVersion)
			return SpecFile{}
		}
		p.yamlError(err)
		return SpecFile{}
	}
	var extra yaml.Node
	switch err := dec.Decode(&extra); {
	case err == nil:
		at := &extra
		if len(extra.Content) > 0 {
			at = extra.Content[0]
		}
		p.at(at, "a second YAML document: a spec file is one document")
		return SpecFile{}
	case !errors.Is(err, io.EOF):
		p.yamlError(err)
		return SpecFile{}
	}

	root := &doc
	if root.Kind == yaml.DocumentNode {
		if len(root.Content) == 0 {
			p.at(nil, "the file is empty: it starts with `version: %d` and lists the requirements under `requirements:`",
				SpecFileVersion)
			return SpecFile{}
		}
		root = root.Content[0]
	}
	// Anchors, aliases and tags are refused before anything is read, so no
	// later step sees an alias where it expects a value.
	if p.checkNodes(root); len(p.errs) > 0 {
		return SpecFile{}
	}
	if root.Kind != yaml.MappingNode {
		p.at(root, "the file must be a mapping with `version: %d` and a `requirements:` list, not %s",
			SpecFileVersion, kindName(root))
		return SpecFile{}
	}
	top := p.mapping(root, "the file", specFileKeys)
	switch v := top["version"]; {
	case v == nil:
		p.at(root, "the file has no version: start it with `version: %d`", SpecFileVersion)
	case v.Kind != yaml.ScalarNode || v.ShortTag() != "!!int":
		p.at(v, "version must be a number: `version: %d`", SpecFileVersion)
	case v.Value != strconv.Itoa(SpecFileVersion):
		n, err := strconv.Atoi(v.Value)
		if err == nil && n > SpecFileVersion {
			p.at(v, "the file is version %d of the format, and this cloop reads version %d: upgrade cloop",
				n, SpecFileVersion)
		} else {
			p.at(v, "version %s is not one: this cloop reads version %d", clipText(v.Value), SpecFileVersion)
		}
	}
	list := top["requirements"]
	switch {
	case list == nil:
		if _, given := top["version"]; given || len(p.errs) == 0 {
			p.at(root, "the file has no `requirements:` list (write `requirements: []` for none)")
		}
		return SpecFile{}
	case list.Kind == yaml.ScalarNode && list.ShortTag() == "!!null":
		return SpecFile{lines: map[int]int{}}
	case list.Kind != yaml.SequenceNode:
		p.at(list, "requirements must be a list, not %s", kindName(list))
		return SpecFile{}
	case len(list.Content) > MaxRequirements:
		p.at(list, "the file lists %d requirements, more than the %d a project may hold", len(list.Content), MaxRequirements)
		return SpecFile{}
	}

	f := SpecFile{lines: map[int]int{}}
	for i, item := range list.Content {
		r, ok := p.requirement(item, i+1)
		if r.ID > 0 {
			if line, dup := f.lines[r.ID]; dup {
				p.at(item, "%s is already the id of the requirement on line %d: an id names one requirement", Key(r.ID), line)
				continue
			}
			f.lines[r.ID] = item.Line
		}
		if ok {
			f.Requirements = append(f.Requirements, r)
		}
	}
	return f
}

// invalidUTF8At is the offset of the first byte of data that is not UTF-8,
// or -1.
func invalidUTF8At(data []byte) int {
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		if r == utf8.RuneError && size <= 1 {
			return i
		}
		i += size
	}
	return -1
}

// yamlLineRE is how yaml.v3 says where a syntax error is.
var yamlLineRE = regexp.MustCompile(`^yaml: line (\d+): (.*)$`)

// yamlParserProblems are the problems yaml.v3's parser, rather than its
// scanner, reports. It numbers the lines of the scanner's from 1 and of the
// parser's from 0 — the line a flow sequence left open on line 4 started on
// comes out as "line 3".
var yamlParserProblems = []string{
	"did not find expected '-' indicator",
	"did not find expected key",
	"did not find expected node content",
	"did not find expected ',' or ']'",
	"did not find expected ',' or '}'",
	"did not find expected <document start>",
	"did not find expected <stream-start>",
	"found undefined tag handle",
	"found duplicate %TAG directive",
	"found duplicate %YAML directive",
	"found incompatible YAML document",
}

func (p *specParser) yamlError(err error) {
	msg := strings.Join(strings.Fields(err.Error()), " ")
	if m := yamlLineRE.FindStringSubmatch(msg); m != nil {
		line, _ := strconv.Atoi(m[1])
		if slices.Contains(yamlParserProblems, m[2]) {
			line++
		}
		p.at(&yaml.Node{Line: line}, "not valid YAML: %s", m[2])
		return
	}
	p.at(nil, "not valid YAML: %s", strings.TrimPrefix(msg, "yaml: "))
}

// checkNodes refuses what a spec file has no use for and a reader would not
// expect: an anchor, an alias — which makes one place in the file say what
// another does — and an explicit tag.
func (p *specParser) checkNodes(root *yaml.Node) {
	stack := []*yaml.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch {
		case n.Kind == yaml.AliasNode:
			p.at(n, "an alias (*%s) is not allowed in a spec file: write the value out", clipText(n.Value))
		case n.Anchor != "":
			p.at(n, "an anchor (&%s) is not allowed in a spec file", clipText(n.Anchor))
		case n.Style&yaml.TaggedStyle != 0:
			p.at(n, "a YAML tag (%s) is not allowed in a spec file: quote the value instead", clipText(n.Tag))
		}
		stack = append(stack, n.Content...)
	}
}

// mapping reads a mapping's keys — each a name, none given twice, each one of
// known — and returns the values by key. A key that breaks a rule is reported
// and left out.
func (p *specParser) mapping(n *yaml.Node, what string, known []string) map[string]*yaml.Node {
	out := map[string]*yaml.Node{}
	keyLine := map[string]int{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind != yaml.ScalarNode {
			p.at(k, "%s has a key that is not a name", what)
			continue
		}
		name := k.Value
		if line, dup := keyLine[name]; dup {
			p.at(k, "%s gives %q twice (first on line %d)", what, clipText(name), line)
			continue
		}
		keyLine[name] = k.Line
		if !slices.Contains(known, name) {
			p.at(k, "%s has an unknown key %q%s: the keys are %s", what, clipText(name), keyHint(name, known),
				strings.Join(known, ", "))
			continue
		}
		out[name] = v
	}
	return out
}

// keyHint suggests the key name was likely meant as: the format's name for a
// field the API or the database calls something else, or a known key one or
// two edits away — misspelt, or the hinted name misspelt.
func keyHint(name string, known []string) string {
	lower := strings.ToLower(name)
	if len([]rune(lower)) < 3 {
		return ""
	}
	near := func(a, b string) bool { return editDistance(a, b, 2) <= max(1, min(2, len(b)/3)) }
	aliases := make([]string, 0, len(specKeyHints))
	for alias := range specKeyHints {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	for _, alias := range aliases {
		if k := specKeyHints[alias]; slices.Contains(known, k) && (lower == alias || near(lower, alias)) {
			return fmt.Sprintf(" (did you mean %q?)", k)
		}
	}
	for _, k := range known {
		if lower == k || near(lower, k) {
			return fmt.Sprintf(" (did you mean %q?)", k)
		}
	}
	return ""
}

// editDistance is the edit distance of a and b, a swap of two neighbouring
// characters counting as one edit (optimal string alignment) — "titel" is one
// edit from "title" — or limit+1 once it is known to exceed limit.
func editDistance(a, b string, limit int) int {
	ar, br := []rune(a), []rune(b)
	if len(ar) > 64 || len(br) > 64 {
		return limit + 1
	}
	if d := len(ar) - len(br); d > limit || -d > limit {
		return limit + 1
	}
	d := make([][]int, len(ar)+1)
	for i := range d {
		d[i] = make([]int, len(br)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(ar); i++ {
		for j := 1; j <= len(br); j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && ar[i-1] == br[j-2] && ar[i-2] == br[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(ar)][len(br)]
}

// text is a scalar's text, "" for null. Anything but a scalar where text
// belongs is reported.
func (p *specParser) text(n *yaml.Node, what, key string) (string, bool) {
	if n.Kind != yaml.ScalarNode {
		p.at(n, "%s: %s must be text, not %s", what, key, kindName(n))
		return "", false
	}
	if n.ShortTag() == "!!null" {
		return "", true
	}
	return n.Value, true
}

// specIDRE is an id as a spec file writes it.
var specIDRE = regexp.MustCompile(`^R-([1-9][0-9]{0,8})$`)

// looseIDRE is an id written some other way, to suggest the right one.
var looseIDRE = regexp.MustCompile(`^(?i:r)?-?0*([1-9][0-9]{0,8})$`)

func (p *specParser) id(n *yaml.Node, what string) (int, bool) {
	if n.Kind != yaml.ScalarNode {
		p.at(n, "%s: an id is R-<number>, not %s", what, kindName(n))
		return 0, false
	}
	if m := specIDRE.FindStringSubmatch(n.Value); m != nil {
		id, err := strconv.Atoi(m[1])
		return id, err == nil
	}
	hint := ""
	if m := looseIDRE.FindStringSubmatch(strings.TrimSpace(n.Value)); m != nil {
		hint = ": write R-" + m[1]
	}
	p.at(n, "%s: id %q is not R-<number>%s", what, clipText(n.Value), hint)
	return 0, false
}

// requirement reads one entry of the requirements list. It reports whether
// the entry is a requirement, and returns its id whenever the entry has a
// valid one, so a duplicate is caught even next to another error.
func (p *specParser) requirement(n *yaml.Node, ordinal int) (Requirement, bool) {
	before := len(p.errs)
	what := fmt.Sprintf("requirement %d", ordinal)
	if n.Kind != yaml.MappingNode {
		p.at(n, "%s must be a mapping of id, title, status and the rest, not %s", what, kindName(n))
		return Requirement{}, false
	}
	var r Requirement
	// The id first, so every other message can name the requirement.
	for i := 0; i+1 < len(n.Content); i += 2 {
		if k := n.Content[i]; k.Kind == yaml.ScalarNode && k.Value == "id" {
			if id, ok := p.id(n.Content[i+1], what); ok {
				r.ID, what = id, Key(id)
			}
			break
		}
	}
	f := p.mapping(n, what, specRequirementKeys)
	if f["id"] == nil {
		p.at(n, "%s has no id: give it R-<number>, a number no requirement of the project ever had", what)
	}

	field := func(key string, norm func(string) (string, error), into *string) {
		v := f[key]
		if v == nil {
			return
		}
		s, ok := p.text(v, what, key)
		if !ok {
			return
		}
		out, err := norm(s)
		if err != nil {
			p.at(v, "%s: %s", what, reason(err))
			return
		}
		*into = out
	}
	if f["title"] == nil {
		p.at(n, "%s has no title", what)
	} else {
		field("title", NormalizeTitle, &r.Title)
	}
	if f["status"] == nil {
		p.at(n, "%s has no status: %s", what, strings.Join(Statuses, ", "))
	} else {
		n0 := len(p.errs)
		field("status", NormalizeStatus, &r.Status)
		if r.Status == "" && len(p.errs) == n0 {
			p.at(f["status"], "%s: status is empty: %s", what, strings.Join(Statuses, ", "))
		}
	}
	field("priority", NormalizePriority, &r.Priority)
	field("details", NormalizeDescription, &r.Description)
	if v := f["tags"]; v != nil {
		r.Tags = p.tags(v, what)
	}
	if v := f["tests"]; v != nil {
		r.Tests = p.tests(v, what)
	}
	if len(p.errs) > before {
		return r, false
	}
	// Each field passed its own check; what is left is the requirement as a
	// whole — the size it takes to send to an executor.
	if err := r.Normalize(); err != nil {
		p.at(n, "%s: %s", what, reason(err))
		return r, false
	}
	return r, true
}

func (p *specParser) tags(n *yaml.Node, what string) []string {
	if n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null" {
		return nil
	}
	if n.Kind != yaml.SequenceNode {
		p.at(n, "%s: tags must be a list, such as [cli, config], not %s", what, kindName(n))
		return nil
	}
	var tags []string
	for _, t := range n.Content {
		s, ok := p.text(t, what, "a tag")
		if !ok {
			continue
		}
		if _, err := normalizeTags([]string{s}); err != nil || strings.TrimSpace(s) == "" {
			msg := "a tag cannot be empty"
			if err != nil {
				msg = reason(err)
			}
			p.at(t, "%s: %s", what, msg)
			continue
		}
		tags = append(tags, s)
	}
	out, err := normalizeTags(tags)
	if err != nil {
		p.at(n, "%s: %s", what, reason(err))
		return nil
	}
	return out
}

func (p *specParser) tests(n *yaml.Node, what string) []Test {
	if n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null" {
		return nil
	}
	if n.Kind != yaml.SequenceNode {
		p.at(n, "%s: tests must be a list of {name, command, timeout}, not %s", what, kindName(n))
		return nil
	}
	if len(n.Content) > MaxTests {
		p.at(n, "%s has %d tests, more than %d", what, len(n.Content), MaxTests)
		return nil
	}
	var out []Test
	for i, tn := range n.Content {
		where := fmt.Sprintf("%s test %d", what, i+1)
		if tn.Kind != yaml.MappingNode {
			p.at(tn, "%s must be a mapping with a command, not %s", where, kindName(tn))
			continue
		}
		before := len(p.errs)
		f := p.mapping(tn, where, specTestKeys)
		var t Test
		if v := f["name"]; v != nil {
			t.Name, _ = p.text(v, where, "name")
		}
		if v := f["command"]; v == nil {
			p.at(tn, "%s has no command", where)
		} else {
			t.Command, _ = p.text(v, where, "command")
		}
		if v := f["timeout"]; v != nil {
			t.TimeoutSeconds = p.timeout(v, where)
		}
		if len(p.errs) > before {
			continue
		}
		norm, err := t.Normalize()
		if err != nil {
			at := tn
			if v := f["command"]; v != nil && strings.Contains(err.Error(), "command") {
				at = v
			} else if v := f["name"]; v != nil && strings.Contains(err.Error(), "name") {
				at = v
			}
			p.at(at, "%s: %s", where, reason(err))
			continue
		}
		out = append(out, norm)
	}
	return out
}

// timeout reads a test's timeout: a duration such as 90s, 10m or 1h30m, a
// whole number of seconds from 1s to MaxTestTimeout.
func (p *specParser) timeout(n *yaml.Node, where string) int {
	s, ok := p.text(n, where, "timeout")
	if !ok || s == "" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		hint := ""
		if _, convErr := strconv.Atoi(s); convErr == nil {
			hint = ": write " + s + "s"
		}
		p.at(n, "%s: timeout %q is not a duration such as 90s, 10m or 1h30m%s", where, clipText(s), hint)
		return 0
	}
	switch {
	case d < time.Second || d%time.Second != 0:
		p.at(n, "%s: a timeout is a whole number of seconds, at least 1s (leave it out for the default, %s)",
			where, formatTimeout(int(DefaultTestTimeout/time.Second)))
		return 0
	case d > MaxTestTimeout:
		p.at(n, "%s: a test may run for at most %s", where, formatTimeout(int(MaxTestTimeout/time.Second)))
		return 0
	}
	return int(d / time.Second)
}

// reason is a validation error without the ErrInvalid prefix every one has.
func reason(err error) string {
	return strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": ")
}

func kindName(n *yaml.Node) string {
	switch n.Kind {
	case yaml.MappingNode:
		return "a mapping"
	case yaml.SequenceNode:
		return "a list"
	case yaml.ScalarNode:
		return "a value"
	case yaml.AliasNode:
		return "an alias"
	}
	return "nothing"
}

// clipText bounds what a message quotes of the file.
func clipText(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	return truncateRunes(s, 80)
}

// formatTimeout writes secs as a spec file does: 90s, 10m, 1h30m.
func formatTimeout(secs int) string {
	var b strings.Builder
	h, m, s := secs/3600, secs%3600/60, secs%60
	if h > 0 {
		fmt.Fprintf(&b, "%dh", h)
	}
	if m > 0 {
		fmt.Fprintf(&b, "%dm", m)
	}
	if s > 0 || b.Len() == 0 {
		fmt.Fprintf(&b, "%ds", s)
	}
	return b.String()
}

// SpecFileReport is what `cloop requirements validate --json` prints: the
// spec file as it is in the checkout the command ran in. The hub reads a
// project's spec file through it, dispatched to the project's executor, and
// parses Content itself; the rest is this cloop's own account of the file,
// for a person reading the output.
type SpecFileReport struct {
	Path string `json:"path"`
	// Found reports that the file is there. Content is its bytes, unless it
	// was too large to send (an error says so).
	Found   bool   `json:"found"`
	Content []byte `json:"content,omitempty"`
	// Commit is HEAD of the checkout; Dirty reports that the file differs
	// from it, Ignored that git ignores it.
	Commit  string      `json:"commit,omitempty"`
	Dirty   bool        `json:"dirty,omitempty"`
	Ignored bool        `json:"ignored,omitempty"`
	Valid   bool        `json:"valid"`
	Count   int         `json:"requirements"`
	Errors  []SpecError `json:"errors,omitempty"`
}

// ── comparing ───────────────────────────────────────────────────────────────

// SameSpec reports whether a and b say the same thing in a spec file: title,
// details, priority, tags, tests and status. Who wrote them and when does not
// count.
func SameSpec(a, b Requirement) bool {
	return a.Title == b.Title && a.Description == b.Description && a.Priority == b.Priority &&
		a.CurrentStatus() == b.CurrentStatus() && slices.Equal(a.Tags, b.Tags) && slices.Equal(a.Tests, b.Tests)
}

// SpecCopy is r as a spec file holds it: its id and definition, without who
// wrote it or when.
func (r Requirement) SpecCopy() Requirement {
	return Requirement{
		ID: r.ID, Title: r.Title, Description: r.Description, Priority: r.Priority, Status: r.Status,
		Tags: slices.Clone(r.Tags), Tests: slices.Clone(r.Tests),
	}
}

// ── writing ─────────────────────────────────────────────────────────────────

// specHeader opens every file RenderSpecFile writes.
const specHeader = `# What this project must keep doing, kept beside its code (cloop requirements).
#
# Review changes here like code. ` + "`cloop requirements import`" + ` brings them into the
# hub, ` + "`cloop requirements export`" + ` writes the hub's back, and
# ` + "`cloop requirements check --file " + SpecFileName + "`" + ` runs the approved
# requirements' tests without a hub. An id is never given to a second
# requirement. Format: docs/guides/requirements.md#requirements-as-code`

// RenderSpecFile writes reqs as a spec file: sorted by id, each normalised,
// every field in a fixed order. It reads back what it wrote and refuses to
// return a file that does not hold exactly reqs, so an export can never write
// a file whose import would change something.
func RenderSpecFile(reqs []Requirement) ([]byte, error) {
	if len(reqs) > MaxRequirements {
		return nil, invalid("%d requirements are more than the %d a spec file may hold", len(reqs), MaxRequirements)
	}
	clean := make([]Requirement, 0, len(reqs))
	for _, r := range reqs {
		c := r.SpecCopy()
		if c.ID <= 0 {
			return nil, invalid("a requirement with no id cannot be written to a spec file")
		}
		if err := c.Normalize(); err != nil {
			return nil, fmt.Errorf("%s: %w", Key(r.ID), err)
		}
		c.Status = c.CurrentStatus()
		clean = append(clean, c)
	}
	sort.Slice(clean, func(i, j int) bool { return clean[i].ID < clean[j].ID })
	for i := 1; i < len(clean); i++ {
		if clean[i].ID == clean[i-1].ID {
			return nil, invalid("%s is given twice", Key(clean[i].ID))
		}
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(specDocument(clean)); err != nil {
		return nil, fmt.Errorf("render the spec file: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("render the spec file: %w", err)
	}
	out := buf.Bytes()
	if len(out) > MaxSpecFileBytes {
		return nil, invalid("the requirements take %d bytes as a spec file, more than the %d one may hold",
			len(out), MaxSpecFileBytes)
	}

	back, err := ParseSpecFile(out)
	if err != nil {
		return nil, fmt.Errorf("the rendered spec file does not read back: %w", err)
	}
	if len(back.Requirements) != len(clean) {
		return nil, fmt.Errorf("the rendered spec file reads back %d requirements, not %d", len(back.Requirements), len(clean))
	}
	for i := range clean {
		if back.Requirements[i].ID != clean[i].ID || !SameSpec(back.Requirements[i], clean[i]) {
			return nil, fmt.Errorf("the rendered spec file does not read back %s as it is", Key(clean[i].ID))
		}
	}
	return out, nil
}

func specDocument(reqs []Requirement) *yaml.Node {
	list := &yaml.Node{Kind: yaml.SequenceNode}
	for _, r := range reqs {
		m := &yaml.Node{Kind: yaml.MappingNode}
		add := func(m *yaml.Node, key string, v *yaml.Node) { m.Content = append(m.Content, specString(key), v) }
		add(m, "id", specString(Key(r.ID)))
		add(m, "title", specString(r.Title))
		add(m, "status", specString(r.Status))
		if r.Priority != "" {
			add(m, "priority", specString(r.Priority))
		}
		if len(r.Tags) > 0 {
			tags := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
			for _, t := range r.Tags {
				tags.Content = append(tags.Content, specString(t))
			}
			add(m, "tags", tags)
		}
		if r.Description != "" {
			add(m, "details", specBlock(r.Description))
		}
		if len(r.Tests) > 0 {
			tests := &yaml.Node{Kind: yaml.SequenceNode}
			for _, t := range r.Tests {
				tm := &yaml.Node{Kind: yaml.MappingNode}
				if t.Name != "" {
					add(tm, "name", specString(t.Name))
				}
				add(tm, "command", specBlock(t.Command))
				if t.TimeoutSeconds > 0 {
					add(tm, "timeout", specString(formatTimeout(t.TimeoutSeconds)))
				}
				tests.Content = append(tests.Content, tm)
			}
			add(m, "tests", tests)
		}
		list.Content = append(list.Content, m)
	}
	root := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
		specString("version"), {Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(SpecFileVersion)},
		specString("requirements"), list,
	}}
	return &yaml.Node{Kind: yaml.DocumentNode, HeadComment: specHeader, Content: []*yaml.Node{root}}
}

// specString is s as a string, quoted by the encoder wherever the plain form
// would read as something else.
func specString(s string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s}
}

// specBlock is a string that may run over lines: a literal block when it does
// and every character is one a literal block keeps as it is, double-quoted
// otherwise — a carriage return or a Unicode line separator would come back
// from a block as a plain line break.
func specBlock(s string) *yaml.Node {
	n := specString(s)
	if !strings.Contains(s, "\n") {
		return n
	}
	for _, r := range s {
		if r != '\n' && r != '\t' && (!unicode.IsPrint(r) || r == 0xFEFF) {
			n.Style = yaml.DoubleQuotedStyle
			return n
		}
	}
	n.Style = yaml.LiteralStyle
	return n
}

// ── files ───────────────────────────────────────────────────────────────────

// ReadSpecFile reads the spec file name names, relative to dir (empty is
// SpecFileName). A name inside dir is opened through an os.Root, so neither a
// symbolic link nor a ".." takes the read out of the project. A name a person
// gave that leads elsewhere — an absolute path — is read where it is. A file
// that is not there is ErrNoSpecFile; one larger than MaxSpecFileBytes is
// refused without being read whole.
func ReadSpecFile(dir, name string) ([]byte, error) {
	if name == "" {
		name = SpecFileName
	}
	var (
		f   *os.File
		err error
	)
	if rel := filepath.Clean(name); filepath.IsLocal(rel) {
		root, rerr := os.OpenRoot(dir)
		if rerr != nil {
			return nil, rerr
		}
		defer root.Close()
		f, err = root.Open(rel)
	} else {
		f, err = os.Open(name)
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w at %s", ErrNoSpecFile, name)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, SpecErrors{{Message: name + " is not a regular file"}}
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxSpecFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxSpecFileBytes {
		return nil, SpecErrors{{Message: fmt.Sprintf("the file is larger than the %d bytes a spec file may hold", MaxSpecFileBytes)}}
	}
	return data, nil
}

// LoadSpecFile reads and parses a spec file (see ReadSpecFile). The bytes are
// returned whenever they could be read, parsed or not.
func LoadSpecFile(dir, name string) (SpecFile, []byte, error) {
	data, err := ReadSpecFile(dir, name)
	if err != nil {
		return SpecFile{}, nil, err
	}
	f, err := ParseSpecFile(data)
	return f, data, err
}

// WriteSpecFile replaces the spec file name names, relative to dir (empty is
// SpecFileName), with data, atomically: a reader sees the old file or the new
// one. Its directory is created if need be. Like ReadSpecFile, a name inside
// dir is written through an os.Root.
func WriteSpecFile(dir, name string, data []byte) error {
	if name == "" {
		name = SpecFileName
	}
	rel := filepath.Clean(name)
	if !filepath.IsLocal(rel) {
		return writeAtomic(name, data)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	if parent := filepath.Dir(rel); parent != "." {
		if err := root.MkdirAll(parent, 0o755); err != nil {
			return err
		}
	}
	tmp := fmt.Sprintf("%s.%d.tmp", rel, os.Getpid())
	if err := root.WriteFile(tmp, data, 0o644); err != nil {
		_ = root.Remove(tmp)
		return err
	}
	if err := root.Rename(tmp, rel); err != nil {
		_ = root.Remove(tmp)
		return err
	}
	return nil
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(name, 0o644)
	}
	if werr == nil {
		werr = os.Rename(name, path)
	}
	if werr != nil {
		_ = os.Remove(name)
	}
	return werr
}
