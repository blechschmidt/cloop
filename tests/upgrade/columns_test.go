package upgrade_test

// Every column the build under test added must survive a save by a release
// member that does not know it.
//
// The release reads around a column it does not know, since no statement of
// statedb's names * — but a writer that replaces whole rows resets every
// column it does not name, and before Task 20388 three writers did. So the
// check is made where it can fail: the columns the build under test added are
// found by comparing the two schemas, set wherever they hold their default,
// and then release members are made to write — a task saved, a CI exchange
// recorded, the quota gauges rebuilt by a release member starting on the
// migrated database, a session touched — and every row that was there before
// must still hold what it held. Rows are matched by their primary key, not
// their rowid, so a row deleted and inserted again counts as rewritten.
//
// The columns the build under test adds change with every release, and in
// some cycles none of them is on a table a release member writes. So the
// tables the older builds rewrote — plan_tasks, ci_exchanges, quota_counters —
// also get a column no build of cloop knows, standing in for the one the next
// migration may add there, and the same writes must leave it alone.

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// probeColumn is the column no build knows.
const probeColumn = "rehearsal_probe"

// probedTables are the tables a build before Task 20388 rewrote, and where
// each lives.
var probedTables = []struct{ db, table string }{
	{"project", "plan_tasks"},
	{"second project", "plan_tasks"},
	{"control plane", "ci_exchanges"},
	{"control plane", "quota_counters"},
}

// column is one column, as PRAGMA table_info reports it.
type column struct {
	name, typ, dflt string
	notNull         bool
	pk              int
}

// schema is a database's tables and their columns.
type schema map[string][]column

func (w *world) schemaOf(dir string) schema {
	w.t.Helper()
	out := schema{}
	for _, row := range w.query(dir, `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`) {
		for _, c := range w.query(dir, `SELECT name, type, "notnull", COALESCE(dflt_value, ''), pk FROM pragma_table_info(?)`, row[0]) {
			pk := 0
			fmt.Sscan(c[4], &pk)
			out[row[0]] = append(out[row[0]], column{name: c[0], typ: strings.ToUpper(c[1]), dflt: c[3],
				notNull: c[2] == "1", pk: pk})
		}
	}
	return out
}

func (s schema) has(table, col string) bool {
	for _, c := range s[table] {
		if c.name == col {
			return true
		}
	}
	return false
}

// added lists the columns after has and before does not, on tables both have:
// a table that is new is invisible to the older build.
func (s schema) added(before schema) []column2 {
	var out []column2
	for table, cols := range s {
		if _, ok := before[table]; !ok {
			continue
		}
		for _, c := range cols {
			if !before.has(table, c.name) {
				out = append(out, column2{table: table, column: c})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].table != out[j].table {
			return out[i].table < out[j].table
		}
		return out[i].column.name < out[j].column.name
	})
	return out
}

// column2 is a column of a table.
type column2 struct {
	table  string
	column column
}

// schemaVersion is the highest migration recorded in dir's database.
func (w *world) schemaVersion(dir string) int {
	rows, err := w.tryQuery(dir, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`)
	if err != nil || len(rows) == 0 {
		return 0
	}
	v := 0
	fmt.Sscan(rows[0][0], &v)
	return v
}

// checkVerdicts: every migration the build under test applied past the
// release's schema is recorded with its verdict and the build that applied it.
func (w *world) checkVerdicts(name, dir string, from int) {
	w.t.Helper()
	rows := w.query(dir, `SELECT version, name, applied_by, compat FROM schema_migrations WHERE version > ? ORDER BY version`, from)
	if len(rows) != w.mainInfo.Schema-from {
		w.t.Fatalf("the %s database records %d migrations past schema %d, want %d: %v",
			name, len(rows), from, w.mainInfo.Schema-from, rows)
	}
	for _, r := range rows {
		switch r[3] {
		case "additive", "additive-columns", "breaking":
		default:
			w.t.Errorf("%s migration %s (%s) records no verdict: compat %q", name, r[0], r[1], r[3])
		}
		if r[2] != w.mainInfo.Version {
			w.t.Errorf("%s migration %s (%s) is recorded as applied by %q, want %s", name, r[0], r[1], r[2], w.mainInfo.Version)
		}
		w.t.Logf("%s migration %s %s: %s, applied by %s", name, r[0], r[1], r[3], r[2])
	}
}

// sentinel is a value of col's kind that its default is not.
func sentinel(table string, col column) string {
	switch name := col.name; {
	case strings.HasSuffix(name, "_at"):
		return "'2001-02-03T04:05:06Z'"
	case strings.HasSuffix(name, "_json"):
		return `'{"rehearsal":true}'`
	case strings.Contains(col.typ, "INT"):
		return "20452"
	case strings.Contains(col.typ, "REAL"), strings.Contains(col.typ, "FLOA"), strings.Contains(col.typ, "DOUB"):
		return "20452.5"
	case strings.Contains(col.typ, "BLOB"):
		return "X'2045'"
	default:
		return "'rehearsal: " + table + "." + name + "'"
	}
}

// tableRows is every row of a table, keyed by its primary key.
type tableRows map[string]map[string]string

// snapshot reads every row of table in dir.
func (w *world) snapshot(dir, table string, cols []column) tableRows {
	w.t.Helper()
	var pk []string
	for _, c := range cols {
		if c.pk > 0 {
			pk = append(pk, c.name)
		}
	}
	key := "rowid"
	if len(pk) > 0 {
		sort.Slice(pk, func(i, j int) bool { return pkOrder(cols, pk[i]) < pkOrder(cols, pk[j]) })
		quoted := make([]string, len(pk))
		for i, p := range pk {
			quoted[i] = fmt.Sprintf(`quote("%s")`, p)
		}
		key = strings.Join(quoted, ` || '|' || `)
	}
	names := make([]string, len(cols))
	for i, c := range cols {
		names[i] = fmt.Sprintf(`"%s"`, c.name)
	}
	out := tableRows{}
	for _, r := range w.query(dir, fmt.Sprintf(`SELECT %s, %s FROM "%s"`, key, strings.Join(names, ", "), table)) {
		row := map[string]string{}
		for i, c := range cols {
			row[c.name] = r[i+1]
		}
		out[r[0]] = row
	}
	return out
}

func pkOrder(cols []column, name string) int {
	for _, c := range cols {
		if c.name == name {
			return c.pk
		}
	}
	return 0
}

// watched is one column whose values must survive.
type watched struct {
	db, dir, table string
	column         column
	probe          bool
}

func (c watched) String() string {
	kind := "added by the build under test"
	if c.probe {
		kind = "known to no build"
	}
	return fmt.Sprintf("%s %s.%s (%s)", c.db, c.table, c.column.name, kind)
}

// checkColumnsSurviveReleaseWrites runs the check described at the top of
// this file while release members a and b serve beside c, the build under
// test.
func (s *scene) checkColumnsSurviveReleaseWrites(releaseSchema map[string]schema, a, b, c *member) {
	t := s.t
	dirs := map[string]string{"control plane": s.hubDir, "project": s.proj, "second project": s.proj2}

	var cols []watched
	for db, dir := range dirs {
		for _, col := range s.schemaOf(dir).added(releaseSchema[db]) {
			cols = append(cols, watched{db: db, dir: dir, table: col.table, column: col.column})
		}
	}
	for _, p := range probedTables {
		dir := dirs[p.db]
		if !s.schemaOf(dir).has(p.table, probeColumn) {
			s.exec(dir, fmt.Sprintf(`ALTER TABLE "%s" ADD COLUMN %s TEXT NOT NULL DEFAULT ''`, p.table, probeColumn))
		}
		cols = append(cols, watched{db: p.db, dir: dir, table: p.table, probe: true,
			column: column{name: probeColumn, typ: "TEXT", dflt: "''", notNull: true}})
	}
	sort.Slice(cols, func(i, j int) bool { return cols[i].String() < cols[j].String() })

	// A session the build under test writes itself, with what it records
	// about it — the column it added for sudo mode, at the time of writing.
	mainBrowser := s.signIn(c.url(), operatorEmail, operatorGroup)

	// Every row holding a column's default gets a value of its own: the
	// build under test's writes would have set them, and a row that keeps
	// the default proves nothing when it comes back with it.
	for _, col := range cols {
		value := sentinel(col.table, col.column)
		if col.probe {
			value = fmt.Sprintf(`'probe of %s row ' || rowid`, col.table)
		}
		s.exec(col.dir, fmt.Sprintf(`UPDATE "%s" SET "%s" = %s WHERE "%s" IS NULL OR "%s" = '' OR "%s" = 0`,
			col.table, col.column.name, value, col.column.name, col.column.name, col.column.name))
	}
	// The sessions have been idle for a while, as a person's do between two
	// requests: a member records a session's use at most once a minute, and
	// counts that minute from the last use the row records.
	idle := time.Now().Add(-2 * time.Minute).UTC().Format(time.RFC3339Nano)
	s.exec(s.hubDir, fmt.Sprintf(`UPDATE sessions SET last_seen = '%s'`, idle))
	tables := map[string]watched{}
	for _, col := range cols {
		tables[col.db+"/"+col.table] = col
	}
	before := map[string]tableRows{}
	for key, col := range tables {
		before[key] = s.snapshot(col.dir, col.table, s.schemaOf(col.dir)[col.table])
	}
	wrote := map[string]string{} // table → the release write that reached it

	// ── the release members write ──────────────────────────────────────────
	// A run on the second project, dispatched by the release member holding
	// the agent's connection and settled by it: its quota slot taken and
	// given back, its result merged into a project the build under test
	// migrated.
	st := s.waitCluster(c.url(), "the agent's connection to be held by a release member", func(cs clusterStatus) bool {
		o := cs.owner("agent", s.executorID)
		return o == a.id || o == b.id
	})
	dispatcher := s.memberByID(st.owner("agent", s.executorID))
	slot := func() string {
		rows, _ := s.tryQuery(s.hubDir, `SELECT value, updated_at FROM quota_counters WHERE identity = ? AND bucket = ''`, operatorEmail)
		return fmt.Sprint(rows)
	}
	slotBefore := slot()
	r := s.do(s.operator, s.lb.url(), http.MethodPost, fmt.Sprintf("/api/run?project_idx=%d", s.proj2Idx), nil, "")
	if r.status != http.StatusOK {
		t.Fatalf("start the second project's run mid-upgrade: %s", r)
	}
	if r.servedBy != dispatcher.id {
		t.Fatalf("the second project's run was dispatched by %s, not by %s, which holds the agent's connection",
			short(r.servedBy), dispatcher)
	}
	s.eventually("the second project's task to be done", 120*time.Second, func() bool {
		return s.taskStatusIn(s.proj2, 1) == "done"
	})
	s.eventually("the second project's run to be settled", 60*time.Second, func() bool {
		owner, _ := s.runOwnerOf(s.proj2)
		return owner == "" && s.projectStatusIn(s.proj2) == "complete"
	})
	if results := s.query(s.proj2, `SELECT message FROM events WHERE type = 'project_result'`); len(results) != 1 {
		t.Errorf("the second project's result was merged %d times, want once: %v", len(results), results)
	}
	t.Logf("the second project's run was dispatched and settled by %s on the migrated database", dispatcher)
	if slot() != slotBefore {
		wrote["control plane/quota_counters"] = "the concurrency slot " + dispatcher.String() + " took and gave back"
	}
	if got := s.query(s.proj2, `SELECT status FROM plan_tasks WHERE id = 1`); len(got) == 1 && got[0][0] == "done" {
		wrote["second project/plan_tasks"] = "the run's result, merged by " + dispatcher.String()
	}

	// A task saved through a release member.
	if r := s.api(a.url(), http.MethodPut, fmt.Sprintf("/api/tasks/2?project_idx=%d", s.projIdx), map[string]any{
		"title":       "Written by the release and finished",
		"description": "edited through " + a.String() + " mid-upgrade",
		"status":      "done",
	}); r.status != http.StatusOK {
		t.Fatalf("a release member could not save a task in the migrated project: %s", r)
	}
	if got := s.query(s.proj, `SELECT description FROM plan_tasks WHERE id = 2`); len(got) == 1 && strings.Contains(got[0][0], a.String()) {
		wrote["project/plan_tasks"] = "task 2, saved through " + a.String()
	}

	// A CI exchange recorded by a release member.
	exchanges := len(s.query(s.hubDir, `SELECT id FROM ci_exchanges`))
	if r := s.do(nil, a.url(), http.MethodPost, "/api/ci/token", map[string]string{"token": "not-a-token"}, ""); r.status == http.StatusOK {
		t.Fatalf("a CI exchange with no federation was accepted: %s", r)
	}
	if len(s.query(s.hubDir, `SELECT id FROM ci_exchanges`)) > exchanges {
		wrote["control plane/ci_exchanges"] = "an exchange recorded by " + a.String()
	}

	// The session the build under test wrote, used at a release member,
	// which records that it was used.
	session := sessionCookie(t, mainBrowser, c.url())
	lastSeen := func() string {
		rows := s.query(s.hubDir, `SELECT last_seen FROM sessions ORDER BY last_seen DESC`)
		var all []string
		for _, r := range rows {
			all = append(all, r[0])
		}
		return strings.Join(all, ",")
	}
	seenBefore := lastSeen()
	time.Sleep(10 * time.Millisecond) // the touch moves last_seen forward only
	if r := s.do(mainBrowser, a.url(), http.MethodGet, "/api/projects", nil, ""); r.status != http.StatusOK {
		t.Fatalf("a release member refused the session the build under test signed in: %s", r)
	}
	s.eventually("the release member to record the session's use", 15*time.Second, func() bool {
		return lastSeen() != seenBefore
	})
	if session != "" {
		wrote["control plane/sessions"] = "the build under test's session, used at " + a.String()
	}

	// ── what is left ───────────────────────────────────────────────────────
	for key, col := range tables {
		after := s.snapshot(col.dir, col.table, s.schemaOf(col.dir)[col.table])
		var kept, rewritten, gone int
		for pk, row := range before[key] {
			now, ok := after[pk]
			if !ok {
				gone++
				continue
			}
			changed := false
			for name, v := range row {
				if now[name] != v && !isWatched(cols, col.db, col.table, name) {
					changed = true
				}
			}
			if changed {
				rewritten++
			}
			for _, w := range cols {
				if w.db != col.db || w.table != col.table {
					continue
				}
				if now[w.column.name] != row[w.column.name] {
					t.Errorf("%s was changed in row %s: %q → %q, by a write that did not know it",
						w, pk, row[w.column.name], now[w.column.name])
				} else {
					kept++
				}
			}
		}
		t.Logf("%s %s: %d row(s) before, %d rewritten, %d gone, %d new; %d watched value(s) kept; release write: %s",
			col.db, col.table, len(before[key]), rewritten, gone, len(after)-(len(before[key])-gone), kept,
			orNone(wrote[key]))
	}
	for _, col := range cols {
		t.Logf("watched: %s", col)
	}
	// The writes this check stands on reached the tables they were meant to.
	for _, want := range []string{"project/plan_tasks", "second project/plan_tasks", "control plane/ci_exchanges",
		"control plane/quota_counters", "control plane/sessions"} {
		if _, ok := tables[want]; ok && wrote[want] == "" {
			t.Errorf("no release member wrote %s during the check, so it proves nothing there", want)
		}
	}
}

func isWatched(cols []watched, db, table, name string) bool {
	for _, c := range cols {
		if c.db == db && c.table == table && c.column.name == name {
			return true
		}
	}
	return false
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
