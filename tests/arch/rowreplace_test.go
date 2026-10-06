package arch_test

// No writer replaces a row it does not wholly own (Task 20388).
//
// A migration that appends a nullable or defaulted column is recorded
// additive (pkg/statedb/schema_compat.go), so a binary that predates it keeps
// opening the database: a hub cluster member mid-way through a rolling update,
// a long-lived run, an older CLI, a rolled-back image. That is safe only while
// every write such a binary makes leaves the new column alone, and two shapes
// of write do not:
//
//	INSERT OR REPLACE, REPLACE INTO. On a conflict SQLite deletes the stored
//	row and inserts the new one, so every column the statement does not name
//	is reset to its default. UPDATE OR REPLACE and a table declared ON
//	CONFLICT REPLACE delete the row they collide with in the same way.
//
//	A DELETE, then an INSERT into the same table — the same thing written out
//	by hand. SaveState emptied plan_tasks and inserted the plan again, and
//	ReplaceQuotaGauges did it to the gauge rows.
//
// Every one of those writes reset the columns its binary did not know, on
// every write. On this deployment a run built before 0054 erased the thirteen
// task columns 0054 added each time it saved. The safe spelling is an upsert —
// INSERT ... ON CONFLICT(key) DO UPDATE SET the columns this binary knows —
// and a DELETE of exactly the rows that are going away. This gate rejects the
// other two, in the module's production Go code and in its migrations.
//
// What it reads. Every string literal in a function; every package-level
// constant or variable the function names, since that is where a statement
// built once lives; and every function of the same package it calls,
// transitively — the bug this was written for was split across two of them:
// saveStateLocked held the DELETE, and insertTasks the INSERT, through a
// package variable. A delete and an insert of one table count when the DELETE
// can run first in one call: it comes earlier in the source, or both sit in
// one loop, and they are not in different branches of one if, switch or
// select, nor is the DELETE in a branch that returns. A statement whose table
// is assembled at run time counts as every table. Inserting first and then
// deleting what is not wanted is not a replacement — the DELETE cannot be
// clearing the way for a row this call already wrote — and passes.
//
// What it does not. Calls into another package are not followed: two exported
// operations composed by a caller, a clear and then a set, are each safe, and
// the audit that added this gate found no caller composing them on one row.
// Branches are judged by their shape, not their conditions.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// rowReplaceAllowed lists the findings that may stand, each with its reason,
// keyed as rowReplacement.key renders them:
//
//	"<dir>.<func> <table>"   a delete-then-insert in that function
//	"<file> <func>"          a replacing statement in that function
//
// A reason must say why no row is replaced — or, if one is, why it has to be,
// and that the table is added to rewrittenTables in
// pkg/statedb/schema_compat.go, so that a later ADD COLUMN on it is recorded
// additive-columns: the verdict the builds that replace its rows refuse.
// TestRowReplaceAllowancesAreStillUsed rejects an entry nothing needs.
var rowReplaceAllowed = map[string]string{}

func TestNoWriterReplacesRows(t *testing.T) {
	root := repoRoot(t)
	found, seen, err := rowReplacements(root)
	if err != nil {
		t.Fatal(err)
	}
	// Without this the gate passes on a tree it has stopped reading — a moved
	// package, a renamed variable, a parser that sees no SQL. The plan's
	// writer is the statement this gate exists for; it must be in view.
	for _, want := range []string{"insert plan_tasks", "delete plan_tasks", "insert ci_exchanges", "delete quota_counters"} {
		if !seen[want] {
			t.Fatalf("the gate found no %q anywhere in pkg/statedb; it is not reading the SQL it was "+
				"written for, so a pass would mean nothing", want)
		}
	}
	for _, f := range found {
		if _, ok := rowReplaceAllowed[f.key]; ok {
			continue
		}
		t.Errorf("%s:%d: %s\n"+
			"    A write that replaces a row resets every column its statement does not name, and a\n"+
			"    binary one migration behind does not name the columns that migration added: each of\n"+
			"    its writes erases them. Write the columns you know with INSERT ... ON CONFLICT(key)\n"+
			"    DO UPDATE SET, and delete only the rows that are going away — after the upsert, or\n"+
			"    in a branch that does not also insert. If this is not a replacement, or has to be,\n"+
			"    add %q to rowReplaceAllowed in tests/arch/rowreplace_test.go with the reason.",
			f.file, f.line, f.what, f.key)
	}
}

func TestRowReplaceAllowancesAreStillUsed(t *testing.T) {
	root := repoRoot(t)
	found, _, err := rowReplacements(root)
	if err != nil {
		t.Fatal(err)
	}
	used := map[string]bool{}
	for _, f := range found {
		used[f.key] = true
	}
	for key, reason := range rowReplaceAllowed {
		if !used[key] {
			t.Errorf("rowReplaceAllowed has %q, which the gate no longer finds — remove it", key)
		}
		if len(reason) < 40 {
			t.Errorf("rowReplaceAllowed[%q] does not say why the write may stand", key)
		}
	}
}

// The gate must flag what it exists for, and only that.
func TestRowReplaceGateFlagsWhatItShould(t *testing.T) {
	root := t.TempDir()
	write := func(rel, src string) {
		t.Helper()
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/m\n")
	write("pkg/store/store.go", "package store\n"+
		"type DB struct{}\n"+
		"func (DB) Exec(q string, args ...any) {}\n"+
		"var upsertRow = func() string { return `INSERT INTO rows(id, v) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET v = excluded.v` }()\n"+
		"const wipeRows = `DELETE FROM rows`\n"+
		// The SaveState shape: the DELETE here, the INSERT in a helper, through a variable.
		"func (d DB) SaveAll(ids []int) {\n"+
		"	d.Exec(`DELETE FROM rows`)\n"+
		"	d.writeRows(ids)\n"+
		"}\n"+
		"func (d DB) writeRows(ids []int) {\n"+
		"	for _, id := range ids { d.Exec(upsertRow, id) }\n"+
		"}\n"+
		// A caller of SaveAll is not a second finding.
		"func (d DB) Save() { d.SaveAll(nil) }\n"+
		// The fix: upsert, then delete what is not wanted.
		"func (d DB) SaveRows(ids []int) {\n"+
		"	d.writeRows(ids)\n"+
		"	d.Exec(`DELETE FROM rows WHERE id NOT IN (SELECT value FROM json_each(?))`)\n"+
		"}\n"+
		// Alternatives, not a sequence: AdjustQuotaCounter and PutQuotaCounter.
		"func (d DB) Adjust(v int) {\n"+
		"	if v <= 0 {\n"+
		"		d.Exec(`DELETE FROM rows WHERE id = ?`)\n"+
		"	} else if v > 9 {\n"+
		"		d.Exec(`INSERT INTO rows(id) VALUES (?) ON CONFLICT(id) DO UPDATE SET id = id`)\n"+
		"	}\n"+
		"}\n"+
		"func (d DB) Put(v int) error {\n"+
		"	if v <= 0 {\n"+
		"		d.Exec(`DELETE FROM rows WHERE id = ?`)\n"+
		"		return nil\n"+
		"	}\n"+
		"	d.Exec(upsertRow)\n"+
		"	return nil\n"+
		"}\n"+
		"func (d DB) Kind(k string) {\n"+
		"	switch k {\n"+
		"	case \"gone\":\n"+
		"		d.Exec(wipeRows)\n"+
		"	default:\n"+
		"		d.writeRows(nil)\n"+
		"	}\n"+
		"}\n"+
		// A return inside a closure leaves the closure, not the function.
		"func (d DB) InTx(f func() error) { _ = f() }\n"+
		"func (d DB) Closure() {\n"+
		"	d.InTx(func() error {\n"+
		"		d.Exec(`DELETE FROM rows WHERE id = 1`)\n"+
		"		return nil\n"+
		"	})\n"+
		"	d.Exec(`INSERT INTO rows(id) VALUES (1)`)\n"+
		"}\n"+
		// In one loop the next iteration's INSERT follows this one's DELETE.
		"func (d DB) Loop(ids []int) {\n"+
		"	for range ids {\n"+
		"		d.Exec(`INSERT INTO rows(id) VALUES (?)`)\n"+
		"		d.Exec(`DELETE FROM rows WHERE id = ?`)\n"+
		"	}\n"+
		"}\n"+
		"func (d DB) OneString() { d.Exec(`DELETE FROM rows; INSERT INTO rows(id) VALUES (1)`) }\n"+
		"func (d DB) Dynamic(table string) {\n"+
		"	d.Exec(`DELETE FROM ` + table + ` WHERE k = ?`)\n"+
		"	d.Exec(`INSERT INTO rows(id) VALUES (1)`)\n"+
		"}\n"+
		"func (d DB) OtherTable() {\n"+
		"	d.Exec(`DELETE FROM other`)\n"+
		"	d.Exec(`INSERT INTO rows(id) VALUES (1)`)\n"+
		"}\n"+
		"func (d DB) Replace() { d.Exec(`INSERT OR REPLACE INTO rows(id) VALUES (1)`) }\n"+
		"func (d DB) ReplaceInto() { d.Exec(`replace into rows(id) values (1)`) }\n"+
		"func (d DB) UpdateOrReplace() { d.Exec(`UPDATE OR REPLACE rows SET id = 2`) }\n"+
		"func (d DB) Ignore() { d.Exec(`INSERT OR IGNORE INTO rows(id) VALUES (1)`) }\n"+
		"func (d DB) Words() error { return fmt.Errorf(\"cannot delete from rows: %w\", nil) }\n"+
		"var replaceRow = \"INSERT OR REPLACE INTO rows(id) VALUES (?)\"\n")
	write("pkg/store/store_test.go", "package store\n"+
		"func (d DB) inTest() { d.Exec(`DELETE FROM rows`); d.Exec(`INSERT OR REPLACE INTO rows VALUES (1)`) }\n")
	write("tests/harness/h.go", "package harness\n"+
		"func h(exec func(string)) { exec(`DELETE FROM rows`); exec(`INSERT INTO rows VALUES (1)`) }\n")
	write("pkg/statedb/migrations/0001_init.sql", "-- an INSERT OR REPLACE in a comment is prose\n"+
		"CREATE TABLE rows (id INTEGER PRIMARY KEY);\n")
	write("pkg/statedb/migrations/0002_backfill.sql", "INSERT OR REPLACE INTO rows(id) SELECT 1;\n")
	write("pkg/statedb/migrations/0003_constraint.sql",
		"CREATE TABLE t2 (id INTEGER PRIMARY KEY ON CONFLICT REPLACE);\n")
	write("nested/go.mod", "module example.com/nested\n")
	write("nested/n.go", "package nested\nfunc n(exec func(string)) { exec(`REPLACE INTO rows VALUES (1)`) }\n")

	got, _, err := rowReplacements(root)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, f := range got {
		keys = append(keys, f.key)
	}
	sort.Strings(keys)
	want := []string{
		"pkg/statedb/migrations/0002_backfill.sql (migration)",
		"pkg/statedb/migrations/0003_constraint.sql (migration)",
		"pkg/store.DB.Closure rows",
		"pkg/store.DB.Dynamic rows",
		"pkg/store.DB.Loop rows",
		"pkg/store.DB.OneString rows",
		"pkg/store.DB.SaveAll rows",
		"pkg/store/store.go DB.Replace",
		"pkg/store/store.go DB.ReplaceInto",
		"pkg/store/store.go DB.UpdateOrReplace",
		"pkg/store/store.go replaceRow",
	}
	if strings.Join(keys, "\n") != strings.Join(want, "\n") {
		t.Fatalf("flagged:\n  %s\nwant:\n  %s", strings.Join(keys, "\n  "), strings.Join(want, "\n  "))
	}
}

// ── The analysis ─────────────────────────────────────────────────────────────

// rowReplacement is one finding.
type rowReplacement struct {
	key  string
	file string // slash-separated, relative to the repository root
	line int
	what string
}

var (
	// replacingSQL matches the statements that replace a row on conflict.
	replacingSQL = regexp.MustCompile(`(?i)\b(INSERT\s+OR\s+REPLACE|REPLACE\s+INTO|UPDATE\s+OR\s+REPLACE|ON\s+CONFLICT\s+REPLACE)\b`)
	// deleteSQL and insertSQL find the table a statement writes. When the
	// literal does not name it — it ends at FROM or INTO, or carries a format
	// verb there — the group captures nothing, and tableAt reads that as
	// anyTable.
	deleteSQL = regexp.MustCompile(`(?i)\bDELETE\s+FROM\s+(?:["` + "`" + `\[]?([A-Za-z_][A-Za-z0-9_]*)|%[a-z]|$)`)
	insertSQL = regexp.MustCompile(`(?i)\b(?:INSERT\s+(?:OR\s+[A-Za-z]+\s+)?|REPLACE\s+)INTO\s+(?:["` + "`" + `\[]?([A-Za-z_][A-Za-z0-9_]*)|%[a-z]|$)`)
)

// anyTable stands for a table whose name the gate cannot read.
const anyTable = "*"

// rowWrite is one DELETE or INSERT a function can perform, directly or
// through a callee.
type rowWrite struct {
	insert bool
	table  string
	pos    token.Pos // the literal, or the call that leads to it
	order  int       // position for ordering: file offset, plus the offset inside the literal
	call   token.Pos // the call it was reached through; 0 when direct
	via    string
}

type gateFunc struct {
	key    string // "Recv.Name", or "Name"
	file   string
	decl   *ast.FuncDecl
	direct []rowWrite
	calls  []gateCall
	// eff is every (insert, table) this function can reach, filled lazily.
	eff     map[rowWrite]bool
	visited bool
}

type gateCall struct {
	name string
	pos  token.Pos
}

type gatePkg struct {
	dir     string
	fset    *token.FileSet
	vals    map[string][]*ast.BasicLit // package-level const/var → the string literals of its value
	valFile map[string]string          // the file each of those is declared in
	funcs   map[string][]*gateFunc     // function or method name → every declaration of it
	all     []*gateFunc
}

// rowReplacements walks root's production Go code and migrations. seen
// records "insert <table>" and "delete <table>" for every write it read, so a
// caller can tell a clean tree from one the gate cannot see into.
func rowReplacements(root string) ([]rowReplacement, map[string]bool, error) {
	var out []rowReplacement
	seen := map[string]bool{}
	byDir := map[string][]string{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "testdata", "vendor", ".cloop":
				return filepath.SkipDir
			}
			if path != root {
				if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
					return filepath.SkipDir // another module
				}
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		dir := filepath.ToSlash(filepath.Dir(rel))
		if _, ok := testOnly[dir]; ok || isTestHarness(dir) {
			return nil
		}
		switch {
		case strings.HasSuffix(rel, ".sql") && strings.HasSuffix(dir, "/migrations"):
			f, err := migrationReplacement(path, rel)
			if err != nil {
				return err
			}
			out = append(out, f...)
		case strings.HasSuffix(rel, ".go") && !strings.HasSuffix(rel, "_test.go"):
			byDir[dir] = append(byDir[dir], path)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	dirs := make([]string, 0, len(byDir))
	for dir := range byDir {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		p, err := loadGatePkg(root, dir, byDir[dir])
		if err != nil {
			return nil, nil, err
		}
		out = append(out, p.findings(seen)...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].file != out[j].file {
			return out[i].file < out[j].file
		}
		return out[i].line < out[j].line
	})
	return out, seen, nil
}

// migrationReplacement flags a replacing statement in a migration file, with
// its `--` comments stripped: they are prose, and several of them discuss
// exactly the statements this gate forbids.
func migrationReplacement(path, rel string) ([]rowReplacement, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for i, line := range strings.Split(string(data), "\n") {
		if c := strings.Index(line, "--"); c >= 0 {
			line = line[:c]
		}
		if m := replacingSQL.FindString(line); m != "" {
			return []rowReplacement{{
				key: rel + " (migration)", file: rel, line: i + 1,
				what: fmt.Sprintf("the migration uses %s, which deletes the row it conflicts with", strings.ToUpper(m)),
			}}, nil
		}
	}
	return nil, nil
}

func loadGatePkg(root, dir string, paths []string) (*gatePkg, error) {
	p := &gatePkg{dir: dir, fset: token.NewFileSet(), vals: map[string][]*ast.BasicLit{},
		valFile: map[string]string{}, funcs: map[string][]*gateFunc{}}
	sort.Strings(paths)
	var files []*ast.File
	for _, path := range paths {
		f, err := parser.ParseFile(p.fset, path, nil, 0)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if i < len(vs.Values) {
						p.vals[name.Name] = stringLits(vs.Values[i])
					} else if len(vs.Values) == 1 {
						p.vals[name.Name] = stringLits(vs.Values[0])
					}
					p.valFile[name.Name] = filepath.ToSlash(rel)
				}
			}
		}
	}
	for i, f := range files {
		rel, err := filepath.Rel(root, paths[i])
		if err != nil {
			return nil, err
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			gf := &gateFunc{key: funcKey(fd), file: filepath.ToSlash(rel), decl: fd}
			p.collect(gf)
			p.funcs[fd.Name.Name] = append(p.funcs[fd.Name.Name], gf)
			p.all = append(p.all, gf)
		}
	}
	return p, nil
}

func funcKey(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	typ := fd.Recv.List[0].Type
	for {
		switch t := typ.(type) {
		case *ast.StarExpr:
			typ = t.X
			continue
		case *ast.IndexExpr:
			typ = t.X
			continue
		case *ast.IndexListExpr:
			typ = t.X
			continue
		case *ast.Ident:
			return t.Name + "." + fd.Name.Name
		}
		return fd.Name.Name
	}
}

func stringLits(n ast.Node) []*ast.BasicLit {
	var out []*ast.BasicLit
	ast.Inspect(n, func(n ast.Node) bool {
		if bl, ok := n.(*ast.BasicLit); ok && bl.Kind == token.STRING {
			out = append(out, bl)
		}
		return true
	})
	return out
}

// collect records the writes in gf's own body and the calls it makes. A
// package-level value the body names contributes its statements at the
// point it is named.
func (p *gatePkg) collect(gf *gateFunc) {
	ast.Inspect(gf.decl.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.BasicLit:
			if n.Kind == token.STRING {
				gf.direct = append(gf.direct, p.writesIn(n, n.Pos())...)
			}
		case *ast.Ident:
			for _, bl := range p.vals[n.Name] {
				gf.direct = append(gf.direct, p.writesIn(bl, n.Pos())...)
			}
		case *ast.CallExpr:
			switch fn := n.Fun.(type) {
			case *ast.Ident:
				gf.calls = append(gf.calls, gateCall{fn.Name, n.Pos()})
			case *ast.SelectorExpr:
				// A method of this package, called on any receiver. Without
				// type information every method of that name is a candidate,
				// which errs toward following too much rather than too little.
				gf.calls = append(gf.calls, gateCall{fn.Sel.Name, n.Pos()})
			}
		}
		return true
	})
}

// writesIn lists the DELETEs and INSERTs in one literal, placed at pos.
func (p *gatePkg) writesIn(bl *ast.BasicLit, pos token.Pos) []rowWrite {
	s, err := strconv.Unquote(bl.Value)
	if err != nil {
		return nil
	}
	base := p.fset.Position(pos).Offset * 1_000_000
	var out []rowWrite
	for _, m := range deleteSQL.FindAllStringSubmatchIndex(s, -1) {
		out = append(out, rowWrite{table: tableAt(s, m), pos: pos, order: base + m[0]})
	}
	for _, m := range insertSQL.FindAllStringSubmatchIndex(s, -1) {
		out = append(out, rowWrite{insert: true, table: tableAt(s, m), pos: pos, order: base + m[0]})
	}
	return out
}

func tableAt(s string, m []int) string {
	if m[2] < 0 {
		return anyTable
	}
	return strings.ToLower(s[m[2]:m[3]])
}

// reach returns every write gf can perform, through any same-package callee.
func (p *gatePkg) reach(gf *gateFunc) map[rowWrite]bool {
	if gf.eff != nil || gf.visited {
		return gf.eff
	}
	gf.visited = true
	eff := map[rowWrite]bool{}
	for _, w := range gf.direct {
		eff[rowWrite{insert: w.insert, table: w.table}] = true
	}
	for _, c := range gf.calls {
		for _, callee := range p.funcs[c.name] {
			for w := range p.reach(callee) {
				eff[w] = true
			}
		}
	}
	gf.eff = eff
	return eff
}

// writes is everything gf does, in its own body's terms: its direct
// statements, and each callee's reach placed at the call.
func (p *gatePkg) writes(gf *gateFunc) []rowWrite {
	out := append([]rowWrite(nil), gf.direct...)
	for _, c := range gf.calls {
		order := p.fset.Position(c.pos).Offset * 1_000_000
		for _, callee := range p.funcs[c.name] {
			for w := range p.reach(callee) {
				out = append(out, rowWrite{insert: w.insert, table: w.table, pos: c.pos,
					order: order, call: c.pos, via: callee.key})
			}
		}
	}
	return out
}

func (p *gatePkg) findings(seen map[string]bool) []rowReplacement {
	var out []rowReplacement
	// A replacing statement held in a package-level value, used or not.
	names := make([]string, 0, len(p.vals))
	for name := range p.vals {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, bl := range p.vals[name] {
			if s, err := strconv.Unquote(bl.Value); err == nil {
				if m := replacingSQL.FindString(s); m != "" {
					out = append(out, rowReplacement{
						key: p.valFile[name] + " " + name, file: p.valFile[name], line: p.fset.Position(bl.Pos()).Line,
						what: fmt.Sprintf("%s holds %s, which deletes the row it conflicts with and inserts "+
							"a new one", name, strings.Join(strings.Fields(strings.ToUpper(m)), " ")),
					})
				}
			}
		}
	}
	for _, gf := range p.all {
		for _, w := range gf.direct {
			kind := "delete"
			if w.insert {
				kind = "insert"
			}
			seen[kind+" "+w.table] = true
		}
		// A replacing statement, wherever it is written.
		ast.Inspect(gf.decl.Body, func(n ast.Node) bool {
			bl, ok := n.(*ast.BasicLit)
			if !ok || bl.Kind != token.STRING {
				return true
			}
			if s, err := strconv.Unquote(bl.Value); err == nil {
				if m := replacingSQL.FindString(s); m != "" {
					out = append(out, rowReplacement{
						key: gf.file + " " + gf.key, file: gf.file, line: p.fset.Position(bl.Pos()).Line,
						what: fmt.Sprintf("%s uses %s, which deletes the row it conflicts with and inserts "+
							"a new one", gf.key, strings.Join(strings.Fields(strings.ToUpper(m)), " ")),
					})
				}
			}
			return true
		})

		// A DELETE that can run before an INSERT of the same table.
		ws := p.writes(gf)
		reported := map[string]bool{}
		for _, d := range ws {
			if d.insert {
				continue
			}
			for _, i := range ws {
				if !i.insert || (d.table != i.table && d.table != anyTable && i.table != anyTable) {
					continue
				}
				// Both through one call: that callee's pair, found there.
				if d.call != 0 && d.call == i.call {
					continue
				}
				if !(d.order < i.order || p.inOneLoop(gf.decl.Body, d.pos, i.pos)) {
					continue
				}
				if p.exclusive(gf.decl.Body, d.pos, i.pos) {
					continue
				}
				table := i.table
				if table == anyTable {
					table = d.table
				}
				if reported[table] {
					continue
				}
				reported[table] = true
				out = append(out, rowReplacement{
					key: p.dir + "." + gf.key + " " + table, file: gf.file, line: p.fset.Position(d.pos).Line,
					what: fmt.Sprintf("%s deletes from %s%s and then inserts into it%s (line %d)", gf.key, table,
						viaText(d), viaText(i), p.fset.Position(i.pos).Line),
				})
			}
		}
	}
	return out
}

func viaText(w rowWrite) string {
	if w.via == "" {
		return ""
	}
	return " through " + w.via
}

// inOneLoop reports whether a for or range statement in body holds both
// positions, so that the next iteration's statement at one follows this
// iteration's at the other.
func (p *gatePkg) inOneLoop(body *ast.BlockStmt, a, b token.Pos) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found || n == nil {
			return false
		}
		var loop *ast.BlockStmt
		switch s := n.(type) {
		case *ast.ForStmt:
			loop = s.Body
		case *ast.RangeStmt:
			loop = s.Body
		}
		if loop != nil && within(loop, a) && within(loop, b) {
			found = true
			return false
		}
		return true
	})
	return found
}

// exclusive reports whether the statements at a and b cannot both run in one
// call: they are in different branches of one if, switch or select, or a (the
// DELETE) is in a branch that ends by returning or panicking, which b is
// outside of — within the same function body, since a return in a closure
// leaves only the closure.
func (p *gatePkg) exclusive(body *ast.BlockStmt, a, b token.Pos) bool {
	ex := false
	ast.Inspect(body, func(n ast.Node) bool {
		if ex || n == nil {
			return false
		}
		switch s := n.(type) {
		case *ast.IfStmt:
			if s.Else != nil && ((within(s.Body, a) && within(s.Else, b)) || (within(s.Else, a) && within(s.Body, b))) {
				ex = true
			}
			if terminates(s.Body) && within(s.Body, a) && !within(s.Body, b) && sameFunc(body, a, b) {
				ex = true
			}
			if blk, ok := s.Else.(*ast.BlockStmt); ok && terminates(blk) && within(blk, a) && !within(blk, b) && sameFunc(body, a, b) {
				ex = true
			}
		case *ast.SwitchStmt:
			ex = clausesExclusive(s.Body, a, b, body)
		case *ast.TypeSwitchStmt:
			ex = clausesExclusive(s.Body, a, b, body)
		case *ast.SelectStmt:
			ex = clausesExclusive(s.Body, a, b, body)
		}
		return !ex
	})
	return ex
}

// clausesExclusive: a and b in different clauses of one switch or select, or
// a in a clause that returns and b outside it.
func clausesExclusive(clauses *ast.BlockStmt, a, b token.Pos, body *ast.BlockStmt) bool {
	var ca, cb ast.Stmt
	for _, c := range clauses.List {
		if within(c, a) {
			ca = c
		}
		if within(c, b) {
			cb = c
		}
	}
	if ca == nil {
		return false
	}
	stmts := clauseBody(ca)
	if len(stmts) > 0 {
		if br, ok := stmts[len(stmts)-1].(*ast.BranchStmt); ok && br.Tok == token.FALLTHROUGH {
			return false
		}
	}
	if cb != nil && ca != cb {
		return true
	}
	return cb == nil && terminatesList(stmts) && sameFunc(body, a, b)
}

func clauseBody(c ast.Stmt) []ast.Stmt {
	switch c := c.(type) {
	case *ast.CaseClause:
		return c.Body
	case *ast.CommClause:
		return c.Body
	}
	return nil
}

func terminates(b *ast.BlockStmt) bool { return b != nil && terminatesList(b.List) }

func terminatesList(list []ast.Stmt) bool {
	if len(list) == 0 {
		return false
	}
	switch s := list[len(list)-1].(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.ExprStmt:
		if call, ok := s.X.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "panic" {
				return true
			}
		}
	}
	return false
}

// sameFunc reports whether a and b sit in the same function literal (or both
// in none), which is what makes a return between them the end of both.
func sameFunc(body *ast.BlockStmt, a, b token.Pos) bool {
	same := true
	ast.Inspect(body, func(n ast.Node) bool {
		if !same || n == nil {
			return false
		}
		if lit, ok := n.(*ast.FuncLit); ok && within(lit, a) != within(lit, b) {
			same = false
		}
		return same
	})
	return same
}

func within(n ast.Node, pos token.Pos) bool {
	return n != nil && n.Pos() <= pos && pos < n.End()
}
