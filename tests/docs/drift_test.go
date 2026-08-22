// Package docs_test gates the documentation against the code it describes.
//
// Ten enterprise subsystems shipped before docs/ existed, which is the normal
// way documentation rots: nothing fails when a new executor backend, a new
// grantable credential kind, or a new RBAC role ships undocumented. The feature
// works, the tests pass, and the gap is invisible until an operator hits it.
//
// So the enumerations that define cloop's security surface are read out of the
// source with go/ast — not copied into a list here, which would rot the same
// way — and each value must appear in docs/ as a backticked literal. Adding a
// fifth Kind* constant to pkg/executor/executor.go fails this test until the
// architecture doc mentions it.
//
// Backticks rather than a bare substring search on purpose: role "none" and
// kind "env" are ordinary English words that would match any prose by accident,
// making the gate vacuous for exactly the short names most likely to be
// forgotten. A literal is how a constant's value should be written anyway.
package docs_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// requiredDocs must exist and be non-trivial. Without this, deleting docs/
// would make every other check in this file pass vacuously.
var requiredDocs = []string{
	"README.md",
	"architecture/executors.md",
	"security/model.md",
	"security/threat-model.md",
	"guides/secrets.md",
	"operations/runbook.md",
}

// enumeration is one set of constants that must be documented, and where the
// author should go when it is not.
type enumeration struct {
	what       string // human name, used in failure messages
	file       string // source file to parse, relative to the repo root
	namePrefix string // constant names to collect, e.g. "Kind"
	typeName   string // required declared type; "" accepts untyped constants
	documentIn string // the doc a new value most likely belongs in
}

var enumerations = []enumeration{
	{
		what:       "executor kind",
		file:       "pkg/executor/executor.go",
		namePrefix: "Kind",
		typeName:   "", // KindLocalProcess = "localprocess" — untyped
		documentIn: "docs/architecture/executors.md (add a section under Backends)",
	},
	{
		what:       "grantable secret kind",
		file:       "pkg/secretbroker/model.go",
		namePrefix: "Kind",
		typeName:   "Kind",
		documentIn: "docs/guides/secrets.md (add a row to the kind table and a worked example)",
	},
	{
		what:       "authz role",
		file:       "pkg/authz/authz.go",
		namePrefix: "Role",
		typeName:   "Role",
		documentIn: "docs/security/model.md (add a row to the role ladder)",
	},
}

func TestRequiredDocsExist(t *testing.T) {
	root := repoRoot(t)
	for _, rel := range requiredDocs {
		path := filepath.Join(root, "docs", rel)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("docs/%s is missing: %v\n"+
				"This file is part of the documented contract; if it moved, update requiredDocs.", rel, err)
			continue
		}
		// A stub would satisfy the constant checks below while telling an
		// operator nothing.
		if info.Size() < 500 {
			t.Errorf("docs/%s is %d bytes — too short to be real documentation", rel, info.Size())
		}
	}
}

// TestEveryEnumeratedConstantIsDocumented is the drift gate proper.
func TestEveryEnumeratedConstantIsDocumented(t *testing.T) {
	root := repoRoot(t)
	corpus := docsCorpus(t, root)

	for _, e := range enumerations {
		t.Run(e.what, func(t *testing.T) {
			values := constStrings(t, filepath.Join(root, e.file), e.namePrefix, e.typeName)
			if len(values) == 0 {
				// Either the constants moved or the prefix/type changed. Both
				// silently disable the check, so neither may pass quietly.
				t.Fatalf("found no %s constants in %s (prefix %q, type %q) — "+
					"the check is disabled, not passing", e.what, e.file, e.namePrefix, e.typeName)
			}

			for name, value := range values {
				if strings.Contains(corpus, "`"+value+"`") {
					continue
				}
				t.Errorf("%s %s = %q is not documented.\n"+
					"  declared: %s\n"+
					"  document: %s\n"+
					"  write the value as a backticked literal, e.g. `%s`",
					e.what, name, value, e.file, e.documentIn, value)
			}
		})
	}
}

// TestEveryPermissionIsDocumented covers the other half of the RBAC surface:
// roles are meaningless without the permissions they bundle, and a new
// permission is exactly the kind of thing that gets wired into a route and
// never written down.
func TestEveryPermissionIsDocumented(t *testing.T) {
	root := repoRoot(t)
	corpus := docsCorpus(t, root)

	perms := constStrings(t, filepath.Join(root, "pkg/authz/authz.go"), "Perm", "Permission")
	if len(perms) == 0 {
		t.Fatal("found no Permission constants in pkg/authz/authz.go — the check is disabled, not passing")
	}
	for name, value := range perms {
		if !strings.Contains(corpus, "`"+value+"`") {
			t.Errorf("permission %s = %q is not documented.\n"+
				"  document: docs/security/model.md (the permission list)\n"+
				"  write the value as a backticked literal, e.g. `%s`", name, value, value)
		}
	}
}

// constStrings collects string-valued constants whose name starts with
// namePrefix and, when typeName is non-empty, whose declared type matches.
//
// Parsing the source rather than importing the package is deliberate: an import
// can only reach constants someone remembered to add to an exported slice,
// which is the same list-that-rots problem one level down. The AST sees every
// declaration, including the one added five minutes ago.
func constStrings(t *testing.T, path, namePrefix, typeName string) map[string]string {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	out := make(map[string]string)
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		// Within one const block a spec with no type inherits the previous
		// spec's type, so carry it forward.
		declared := ""
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			if vs.Type != nil {
				if ident, ok := vs.Type.(*ast.Ident); ok {
					declared = ident.Name
				} else {
					declared = ""
				}
			} else if len(vs.Values) > 0 {
				// An explicit value with no type resets the inheritance.
				declared = ""
			}
			if typeName != "" && declared != typeName {
				continue
			}
			for i, name := range vs.Names {
				if !strings.HasPrefix(name.Name, namePrefix) || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				value, err := strconv.Unquote(lit.Value)
				if err != nil || value == "" {
					continue
				}
				out[name.Name] = value
			}
		}
	}
	return out
}

// docsCorpus concatenates every Markdown file under docs/ into one lowercase
// blob. Lowercase because a constant may reasonably be written in a heading
// that title-cases it.
func docsCorpus(t *testing.T, root string) string {
	t.Helper()

	var b strings.Builder
	docsDir := filepath.Join(root, "docs")
	err := filepath.WalkDir(docsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		b.Write(data)
		b.WriteByte('\n')
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", docsDir, err)
	}
	if b.Len() == 0 {
		t.Fatalf("no Markdown found under %s", docsDir)
	}
	return strings.ToLower(b.String())
}

// repoRoot locates the repository from this file's compile-time path, so the
// test works regardless of the working directory it runs in.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate drift_test.go")
	}
	// tests/docs/drift_test.go -> repo root
	return filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
}
