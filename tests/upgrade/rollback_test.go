package upgrade_test

// The backward rehearsal: once the build under test has migrated a hub, the
// release — a member still running mid-rollout, or the image a rollback goes
// back to — tolerates or refuses the migrated database exactly as
// docs/operations/runbook.md#rollback says, and when it refuses it says so in
// the words the runbook shows an operator.
//
// The migrations the build under test really applied are judged first, by the
// runbook's rule: tolerated when every one of them is recorded additive, or
// additive-columns and the release is from Task 20388 on. Those are often all
// additive, so the refusal would go unexercised; copies of the migrated
// database with one more migration recorded under each verdict exercise every
// branch of the rule, and the escape hatch, on every run.

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/version"
)

// toleratedBy reports whether a release tolerates a migration recorded with
// verdict, by the runbook's rule.
func toleratedBy(verdict string, knowsAdditiveColumns bool) bool {
	switch verdict {
	case "additive":
		return true
	case "additive-columns":
		return knowsAdditiveColumns
	}
	return false
}

// knowsAdditiveColumns reports whether a release is from Task 20388 on, the
// first build to write the three rewritten tables in place and to know the
// additive-columns verdict. v0.0.5 is the first release after it.
func knowsAdditiveColumns(tag string) bool {
	cmp, ok := version.Compare(tag, "v0.0.5")
	return ok && cmp >= 0
}

func TestRollbackToTheReleaseAfterMainMigrated(t *testing.T) {
	w := newWorld(t)
	tmpl := readRunbookRefusals(t)

	// The release builds a hub and a project; the build under test opens
	// both, as its first member does, and migrates them.
	w.cli(buildRelease, w.hubDir, "init", "--provider", "mock", "--skip-clarify", "the hub's control plane")
	w.cli(buildRelease, w.proj, "init", "--provider", "claudecode", "--skip-clarify", "Roll back")
	w.cli(buildRelease, w.proj, "task", "add", "Saved by the release", "--no-ai", "--auto")
	for _, dir := range []string{w.hubDir, w.proj} {
		w.cli(buildMain, dir, "status")
		if got := w.schemaVersion(dir); got != w.mainInfo.Schema {
			t.Fatalf("the build under test left %s at schema %d, want %d", dir, got, w.mainInfo.Schema)
		}
	}
	columnsTolerated := knowsAdditiveColumns(w.rel.tag)

	t.Run("the migrations the build under test applied", func(t *testing.T) {
		var blocked []string
		for _, r := range w.query(w.hubDir, `SELECT version, name, compat FROM schema_migrations WHERE version > ? ORDER BY version`,
			w.rel.info.Schema) {
			t.Logf("migration %s %s is recorded %q", r[0], r[1], r[2])
			if !toleratedBy(r[2], columnsTolerated) {
				blocked = append(blocked, r[1])
			}
		}
		if len(blocked) > 0 {
			w.assertRefused(t, w.hubDir, tmpl, blocked)
			return
		}
		// Tolerated: the release's commands open and save the migrated
		// project, and a release member serves the migrated hub.
		w.cli(buildRelease, w.proj, "status")
		w.cli(buildRelease, w.proj, "task", "add", "Saved by the release after the migration", "--no-ai", "--auto")
		if got := w.query(w.proj, `SELECT title FROM plan_tasks ORDER BY id`); len(got) != 2 {
			t.Errorf("the project's tasks after the release saved the migrated database: %v", got)
		}
		w.assertServes(t, w.hubDir, nil)
	})

	for _, tc := range []struct {
		verdict string
		refused bool
		why     string
	}{
		{"breaking", true, "a migration that altered, dropped or constrained something"},
		{"rehearsal-unknown", true, "a verdict the reading build does not know"},
		{"", true, "a migration nothing classified"},
		{"additive", false, "a migration that only added objects"},
		{"additive-columns", !columnsTolerated, "a column appended to a table older builds rewrote"},
	} {
		tc := tc
		name := tc.verdict
		if name == "" {
			name = "unclassified"
		}
		t.Run("one more migration recorded "+name, func(t *testing.T) {
			dir, mig := w.copyWithMigration(t, tc.verdict)
			t.Logf("%s: %s", mig, tc.why)
			if tc.refused {
				w.assertRefused(t, dir, tmpl, []string{mig})
			} else {
				w.assertServes(t, dir, nil)
			}
		})
	}

	t.Run("the escape hatch", func(t *testing.T) {
		dir, mig := w.copyWithMigration(t, "breaking")
		env := []string{"CLOOP_ALLOW_SCHEMA_DOWNGRADE=1"}
		w.assertServes(t, dir, env)
		if f := w.doctorFinding(t, dir, env, "storage.schema_guard"); f.Severity != "fail" {
			t.Errorf("with %s ahead and CLOOP_ALLOW_SCHEMA_DOWNGRADE=1 the release's doctor says storage.schema_guard "+
				"%s (%s), and the runbook says a failure while a skew is present", mig, f.Severity, f.Message)
		}
	})
}

// copyWithMigration copies the migrated hub's database into a directory of
// its own and records one more migration there, as the build after the one
// under test would, with verdict.
func (w *world) copyWithMigration(t *testing.T, verdict string) (string, string) {
	t.Helper()
	dir, err := os.MkdirTemp(w.root, "hub-copy-")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(w.hubDir, ".cloop", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, ".cloop", "config.yaml"), string(data), 0o600)
	// A consistent snapshot, write-ahead log included.
	conn, err := statedb.OpenConn(dbPath(w.hubDir), statedb.ReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.ExecContext(w.ctx, `VACUUM INTO ?`, dbPath(dir))
	_ = conn.Close()
	if err != nil {
		t.Fatalf("snapshot %s: %v", dbPath(w.hubDir), err)
	}
	v := w.mainInfo.Schema + 1
	slug := strings.ReplaceAll(verdict, "-", "_")
	if verdict == "" {
		slug = "unclassified"
	}
	mig := fmt.Sprintf("%04d_rehearsal_%s.sql", v, slug)
	w.exec(dir, fmt.Sprintf(`INSERT INTO schema_migrations (version, applied_at, name, applied_by, compat)
		VALUES (%d, '%s', '%s', '%s', '%s')`, v, time.Now().UTC().Format(time.RFC3339), mig, w.mainInfo.Version, verdict))
	return dir, mig
}

// assertServes starts a release member on dir and requires it to serve.
func (w *world) assertServes(t *testing.T, dir string, extra []string) {
	t.Helper()
	port := freePort(t)
	env := append(w.hubSideEnv(filepath.Dir(w.rel.bin)), extra...)
	p := w.spawn(fmt.Sprintf("release-on-%s-%d", filepath.Base(dir), port), dir, env, w.rel.bin,
		"ui", "--port", strconv.Itoa(port), "--listen", "127.0.0.1", "--no-browser")
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	w.eventually("the release to serve the migrated database at "+base, 90*time.Second, func() bool {
		if !p.running() {
			t.Fatalf("the release refused a database the runbook says it tolerates:\n%s", tailFile(p.log, 30))
		}
		r := w.api(base, http.MethodGet, "/readyz", nil)
		return r.status == http.StatusOK
	})
	if r := w.api(base, http.MethodGet, "/api/projects", nil); r.status != http.StatusOK {
		t.Errorf("the release member on the migrated database answers /api/projects with %s", r)
	}
	p.signal(syscall.SIGTERM)
	select {
	case <-p.exited:
	case <-time.After(60 * time.Second):
		t.Fatalf("the release member did not stop within 60s:\n%s", tailFile(p.log, 30))
	}
}

// assertRefused starts a release member on dir and requires it to refuse,
// before it binds its port or takes the control-plane lease, with the error
// the runbook shows naming exactly the migrations in blocked; and the
// release's doctor to report it as storage.schema without a hub running.
func (w *world) assertRefused(t *testing.T, dir string, tmpl map[string]runbookRefusal, blocked []string) {
	t.Helper()
	controlRows := func() string {
		var b strings.Builder
		// The control-plane lease, the cluster's membership and what its
		// members own: a member that refuses must have written none of it.
		for _, table := range []string{"hub_instances", "hub_members", "hub_owners"} {
			rows, err := w.tryQuery(dir, `SELECT * FROM "`+table+`"`)
			if err != nil {
				t.Fatalf("read %s: %v", table, err)
			}
			fmt.Fprintf(&b, "%s: %v\n", table, rows)
		}
		return b.String()
	}
	before := controlRows()
	port := freePort(t)
	p := w.spawn(fmt.Sprintf("release-refusing-%s-%d", filepath.Base(dir), port), dir,
		w.hubSideEnv(filepath.Dir(w.rel.bin)), w.rel.bin,
		"ui", "--port", strconv.Itoa(port), "--listen", "127.0.0.1", "--no-browser")
	deadline := time.After(90 * time.Second)
	for p.running() {
		if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond); err == nil {
			_ = c.Close()
			t.Fatalf("the release bound :%d on a database it must refuse:\n%s", port, tailFile(p.log, 30))
		}
		select {
		case <-deadline:
			t.Fatalf("the release neither refused nor served within 90s:\n%s", tailFile(p.log, 30))
		case <-p.exited:
		case <-time.After(50 * time.Millisecond):
		}
	}
	if code := p.cmd.ProcessState.ExitCode(); code == 0 {
		t.Fatalf("the release exited 0 on a database it must refuse:\n%s", tailFile(p.log, 30))
	}
	if after := controlRows(); after != before {
		t.Errorf("the refusing release wrote the control plane's membership and lease rows:\nbefore %s\nafter  %s", before, after)
	}
	stamp := w.query(dir, `SELECT version, name, applied_at, applied_by FROM schema_migrations ORDER BY version DESC LIMIT 1`)[0]
	at, err := time.Parse(time.RFC3339Nano, stamp[2])
	if err != nil {
		t.Fatalf("schema_migrations records applied_at %q", stamp[2])
	}
	// The member, and a command run in the same directory.
	cliOut, cliErr := w.cliErr(buildRelease, dir, nil, "status")
	if cliErr == nil {
		t.Errorf("the release's `cloop status` succeeded on a database it must refuse:\n%s", cliOut)
	}
	for _, got := range []struct{ command, out string }{{"ui", readFile(p.log)}, {"status", cliOut}} {
		ex := tmpl[got.command]
		want, err := ex.pattern(dbPath(dir), stamp[0], strconv.Itoa(w.rel.info.Schema), stamp[3], stamp[1],
			at.UTC().Format(time.RFC3339), blocked)
		if err != nil {
			t.Fatal(err)
		}
		if !want.MatchString(normalizeSpace(got.out)) {
			t.Errorf("the release's `cloop %s` refusal is not the error docs/operations/runbook.md#rollback names.\n"+
				"runbook: %s\nwant:    %s\ngot:\n%s", got.command, ex.text, want, tail(got.out, 20))
		} else {
			t.Logf("`cloop %s` refused, as the runbook says: %s", got.command, firstLineWith(got.out, "Error: "))
		}
	}
	f := w.doctorFinding(t, dir, nil, "storage.schema")
	if f.Severity != "fail" {
		t.Errorf("the release's doctor says storage.schema %s (%s) on a database the release refuses", f.Severity, f.Message)
	}
	for _, mig := range blocked {
		if !strings.Contains(f.Message, mig) {
			t.Errorf("the release's doctor does not name %s in storage.schema: %s", mig, f.Message)
		}
	}
}

// finding is one check of `cloop hub doctor --json`.
type finding struct {
	Check    string `json:"check"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// doctorFinding runs the release's doctor in dir, offline, and returns one
// check's finding.
func (w *world) doctorFinding(t *testing.T, dir string, extra []string, check string) finding {
	t.Helper()
	out, _ := w.cliErr(buildRelease, dir, extra, "hub", "doctor", "--offline", "--json", "--port", "0")
	start := strings.Index(out, "{")
	if start < 0 {
		t.Fatalf("the release's doctor printed no report:\n%s", out)
	}
	var report struct {
		Findings []finding `json:"findings"`
	}
	dec := json.NewDecoder(strings.NewReader(out[start:]))
	if err := dec.Decode(&report); err != nil && err != io.EOF {
		t.Fatalf("decode the release's doctor report: %v\n%s", err, out)
	}
	for _, f := range report.Findings {
		if f.Check == check {
			return f
		}
	}
	t.Fatalf("the release's doctor reports no %s:\n%s", check, out)
	return finding{}
}

// ── the runbook's refusal ────────────────────────────────────────────────────

// runbookRefusal is one refusal docs/operations/runbook.md#rollback shows,
// with the values its example names.
type runbookRefusal struct {
	command                     string
	text                        string
	path, db, bin, by, name, at string
}

var runbookExample = regexp.MustCompile(`^Error: (?:hubcluster: open (\S+): )?statedb: database schema is newer than this binary: ` +
	`database is at schema version (\d+) but this binary carries (\d+) \(applied by cloop (\S+) as (\S+) at (\S+)\); … ` +
	`Incompatible: (\S+)\. …$`)

// readRunbookRefusals reads the example refusals out of the Rollback
// section, by the command each follows.
func readRunbookRefusals(t *testing.T) map[string]runbookRefusal {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(), "docs", "operations", "runbook.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	start := strings.Index(doc, "\n## Rollback\n")
	if start < 0 {
		t.Fatal("docs/operations/runbook.md has no Rollback section")
	}
	section := doc[start+1:]
	if end := strings.Index(section, "\n## "); end > 0 {
		section = section[:end]
	}
	open := strings.Index(section, "```console\n")
	if open < 0 {
		t.Fatal("the runbook's Rollback section shows no console example of the refusal")
	}
	block := section[open+len("```console\n"):]
	block = block[:strings.Index(block, "```")]
	out := map[string]runbookRefusal{}
	var command string
	var lines []string
	flush := func() {
		if command == "" {
			return
		}
		text := normalizeSpace(strings.Join(lines, " "))
		m := runbookExample.FindStringSubmatch(text)
		if m == nil {
			t.Fatalf("the runbook's refusal after `$ cloop %s` no longer has the shape this test reads (%s): %s",
				command, runbookExample, text)
		}
		if m[5] != m[7] {
			t.Fatalf("the runbook's example names %s as the newest migration and %s as the incompatible one", m[5], m[7])
		}
		out[command] = runbookRefusal{command: command, text: text, path: m[1], db: m[2], bin: m[3], by: m[4],
			name: m[5], at: m[6]}
	}
	for _, line := range strings.Split(block, "\n") {
		if cmd, ok := strings.CutPrefix(line, "$ cloop "); ok {
			flush()
			command, lines = strings.TrimSpace(cmd), nil
			continue
		}
		lines = append(lines, line)
	}
	flush()
	for _, want := range []string{"ui", "status"} {
		if _, ok := out[want]; !ok {
			t.Fatalf("the runbook's Rollback section shows no refusal by `cloop %s`", want)
		}
	}
	return out
}

// pattern is the runbook's refusal with the example's values replaced by the
// ones a database at hand should produce: what an operator reading the
// runbook expects to see, with "…" standing for anything.
func (r runbookRefusal) pattern(path, db, bin, by, name, at string, blocked []string) (*regexp.Regexp, error) {
	var incompatible []string
	for _, b := range blocked {
		// A verdict the reading build does not know, or none, is named
		// with what was recorded, in parentheses.
		incompatible = append(incompatible, regexp.QuoteMeta(b)+`(?: \([^)]*\))?`)
	}
	repl := []struct{ from, to string }{
		{"schema version " + r.db + " ", "schema version " + db + " "},
		{"carries " + r.bin + " ", "carries " + bin + " "},
		{"applied by cloop " + r.by + " ", "applied by cloop " + by + " "},
		{" as " + r.name + " at " + r.at + ")", " as " + name + " at " + at + ")"},
	}
	if r.path != "" {
		repl = append(repl, struct{ from, to string }{"open " + r.path + ": ", "open " + path + ": "})
	}
	text := r.text
	for _, p := range repl {
		if strings.Count(text, p.from) != 1 {
			return nil, fmt.Errorf("the runbook's refusal does not say %q exactly once: %s", p.from, r.text)
		}
		text = strings.Replace(text, p.from, p.to, 1)
	}
	const incompat = "Incompatible: "
	i := strings.Index(text, incompat+r.name+".")
	if i < 0 {
		return nil, fmt.Errorf("the runbook's refusal does not end its Incompatible list with %s: %s", r.name, r.text)
	}
	head, rest := text[:i], text[i+len(incompat)+len(r.name):]
	quote := func(s string) string {
		parts := strings.Split(s, "…")
		for k := range parts {
			parts[k] = regexp.QuoteMeta(parts[k])
		}
		return strings.Join(parts, ".*?")
	}
	return regexp.Compile(`(?s)` + quote(head) + regexp.QuoteMeta(incompat) + strings.Join(incompatible, ", ") + quote(rest))
}

// normalizeSpace collapses every run of whitespace to one space.
func normalizeSpace(s string) string { return strings.Join(strings.Fields(s), " ") }

func firstLineWith(s, sub string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, sub) {
			return strings.TrimSpace(line)
		}
	}
	return ""
}
