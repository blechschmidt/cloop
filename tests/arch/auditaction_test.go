package arch_test

// Structural gate on the audit action vocabulary.
//
// pkg/auditaction is the registry of every name the hub may write to the
// `event_type` column of `audit_events`. A registry nothing checks is a list
// that goes stale, so this file is the check: it parses the module with go/ast
// and fails when an emission site names an action the registry does not know.
//
// The failure it exists to prevent is silent. An action name is a string in a
// column; a typo produces rows that append cleanly, verify cleanly, export
// cleanly to a SIEM, and match no detection rule anybody wrote. Nothing in the
// build, the vet pass, or any package's own tests can see it — which is
// precisely the argument for a structural gate, and the same argument
// orphan_test.go makes about a package nothing imports.
//
// Three directions are checked:
//
//   - Emission sites (TestEveryEmittedActionIsRegistered). Every expression
//     that lands in an action column must be a registered literal, a
//     pkg/auditaction constant, or a value that provably came from one.
//   - Source enums (TestEveryActionEnumMapsToARegisteredAction). Four families
//     take their name from an enum that exists for its own reasons —
//     pkg/gitproxy's EventKind, pkg/secretbroker's Action. A new member of one
//     of those fails here until it is registered.
//   - Constants (TestEveryActionConstantHasARegistryEntry). A constant in
//     actions.go with no entry in registry.go documents nothing and would
//     render as a gap on the generated page.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/auditaction"
)

// ── What counts as an emission site ────────────────────────────────────────

// actionFields are the composite-literal fields whose value becomes an action
// name, keyed by the fully-qualified type that declares them.
//
// Qualified rather than spelled as written, because how a type is written
// depends on where: `AuditEvent` inside pkg/statedb and `statedb.AuditEvent`
// outside it are the same struct, and `Event` is a common enough name that
// accepting it unqualified would make this gate walk composite literals in
// packages that have nothing to do with the audit trail. The walk resolves a
// bare name against its own package before looking here.
var actionFields = map[string]string{
	"statedb.AuditEvent":       "EventType",
	"eventlog.AuditEvent":      "EventType", // an alias for the above
	"statedb.SecretAuditInput": "EventType",
	"statedb.AttachAuditInput": "Event",
	"ui.tokenAuditRecord":      "EventType",
	"secretbroker.Event":       "Action",
	"auditaction.Entry":        "Action", // the registry itself
}

// readSideTypes have a field named like an action column, but they read it
// rather than write it: a query filter, a JSON projection, an export record.
// They are listed rather than skipped by shape, so a new carrier type has to be
// classified as one or the other instead of silently escaping the gate — see
// TestEveryActionCarrierTypeIsClassified.
var readSideTypes = map[string]string{
	"eventlog.AuditFilter":    "the filter for reading the trail back; its EventType is a predicate, not a row",
	"statedb.AuditFilter":     "the same type, before pkg/eventlog re-exports it",
	"ui.auditEventJSON":       "the JSON pkg/ui serves to the Audit panel; EventType is copied from a stored row",
	"auditexport.jsonlRecord": "the SIEM export record; EventType is copied from a stored row",
}

// TestEveryNamedTypeExists keeps the two maps above honest.
//
// A key naming a type that was since renamed is a gate that has silently
// stopped covering something — the exact failure mode, a hand-maintained list
// nobody revisits, that pkg/auditaction exists to end. It would be poor form
// for its own gate to have one, so the list checks itself instead of being
// checked by a second list.
func TestEveryNamedTypeExists(t *testing.T) {
	fields := structFieldTypes(t, goSourceFiles(t, repoRoot(t)))
	exists := func(what, name string) map[string]string {
		declared, ok := fields[name]
		if !ok {
			t.Errorf("%s names type %s, which this module does not declare.\n"+
				"    Either it was renamed — update the key — or it is gone, and the\n"+
				"    entry should go with it. Leaving it is how the gate quietly stops\n"+
				"    covering an emission path.", what, name)
			return nil
		}
		return declared
	}
	// actionFields maps a type to the field carrying the action, so both halves
	// are checkable.
	for name, field := range actionFields {
		declared := exists("actionFields", name)
		if declared == nil {
			continue
		}
		if _, ok := declared[field]; !ok {
			t.Errorf("actionFields says %s carries the action in field %q, which that struct does not have.",
				name, field)
		}
	}
	// readSideTypes maps a type to the reason it is exempt, so only the type is
	// checkable — the reason is for a human.
	for name := range readSideTypes {
		exists("readSideTypes", name)
	}
}

// carrierTypes are the types a value may have on its way to an action column.
//
// An identifier at an emission site is accepted when its declared type is one
// of these — resolved from the source, not matched by name. Two kinds qualify:
//
//   - auditaction.Action, whose only values come from the registry.
//   - A foreign enum whose every member TestEveryActionEnumMapsToARegisteredAction
//     proves registered. Accepting one of these is not a weakening: it is the
//     same guarantee arrived at from the declaration side instead of the use
//     side, and it is why pkg/secretbroker keeps its own Action type rather
//     than having a domain concept rewritten to satisfy a documentation gate.
var carrierTypes = map[string]string{
	"auditaction.Action":    "the registry's own type",
	"secretbroker.Action":   "gated by the secret broker action enum",
	"gitproxy.EventKind":    "gated by the gitproxy event kind enum",
	"kubeguard.EventKind":   "gated by the kubeguard event kind enum",
	"claudeproxy.EventKind": "gated by the CI relay event kind enum",
}

// passThroughNames is the escape hatch for a carrier that genuinely cannot be
// typed, each entry with the reason — the same shape as orphan_test.go's
// exempt map.
//
// Keep it empty. Every entry is a place this gate stops looking, and the
// tree it was written against needed none: each of the forty-two emission
// sites resolved to a carrier type instead.
var passThroughNames = map[string]string{}

func TestEveryEmittedActionIsRegistered(t *testing.T) {
	root := repoRoot(t)
	files := goSourceFiles(t, root)
	fields := structFieldTypes(t, files)
	pkgs := packageScopes(files)

	var sites int
	for _, f := range files {
		for _, decl := range f.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			scope := funcScope(fn, f.file.Name.Name)
			r := &resolver{fields: fields, scope: scope, pkgs: pkgs, pkg: f.file.Name.Name}
			ast.Inspect(fn, func(n ast.Node) bool {
				cl, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				field, ok := actionFields[qualifiedTypeName(cl.Type, f.file.Name.Name)]
				if !ok {
					return true
				}
				for _, el := range cl.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, ok := kv.Key.(*ast.Ident)
					if !ok || key.Name != field {
						continue
					}
					sites++
					where := fmt.Sprintf("%s:%d", f.rel, f.fset.Position(kv.Pos()).Line)
					checkActionExpr(t, where, kv.Value, r)
				}
				return true
			})
		}
	}

	// Without this the gate passes on a tree where the walk found nothing —
	// a renamed struct, a broken parse, a changed field name.
	if sites < 30 {
		t.Errorf("only %d emission sites found; the walk is not seeing the tree it used to.\n"+
			"    Check actionFields against the audit carrier structs before trusting a pass.", sites)
	}
}

// checkActionExpr decides whether one action-valued expression is acceptable.
func checkActionExpr(t *testing.T, where string, e ast.Expr, r *resolver) {
	t.Helper()
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			t.Errorf("%s: action is a non-string literal %s", where, v.Value)
			return
		}
		lit, err := strconv.Unquote(v.Value)
		if err != nil {
			t.Errorf("%s: unparseable string literal %s", where, v.Value)
			return
		}
		if !auditaction.Registered(auditaction.Action(lit)) {
			t.Errorf("%s: emits audit action %q, which pkg/auditaction does not know.\n"+
				"    Nothing else can catch this: the row appends, the hash chain verifies,\n"+
				"    the SIEM export succeeds, and no detection rule ever matches it.\n"+
				"    Fix it one of two ways:\n"+
				"      (a) the name is right     — add a constant to pkg/auditaction/actions.go\n"+
				"                                  and an entry to registry.go, then run `make docs-audit`;\n"+
				"      (b) the name is a typo    — correct it to a registered action.\n"+
				"    Either way, reference the constant here rather than writing the literal again.",
				where, lit)
			return
		}
		t.Errorf("%s: writes the literal %q where a pkg/auditaction constant belongs.\n"+
			"    The name is registered, so this is not a typo — but a literal is how the\n"+
			"    next one becomes a typo. Reference the constant instead.", where, lit)

	case *ast.SelectorExpr:
		// auditaction.ActionX — the intended shape.
		if pkg, ok := v.X.(*ast.Ident); ok && pkg.Name == "auditaction" {
			return
		}
		// A constant from a package whose whole enum the gate below proves.
		if pkg, ok := v.X.(*ast.Ident); ok && enumPackages[pkg.Name] {
			return
		}
		// A field on a carrier struct: in.Event, ev.Action, rec.EventType.
		// Resolved through the declaration, not matched by name.
		if typ := r.selectorType(v); carrierTypes[typ] != "" {
			return
		}
		if passThroughNames[exprText(v)] != "" {
			return
		}
		reportUncheckable(t, where, exprText(v), r)

	case *ast.Ident:
		if carrierTypes[r.identType(v.Name)] != "" {
			return
		}
		if passThroughNames[v.Name] != "" {
			return
		}
		reportUncheckable(t, where, v.Name, r)

	case *ast.CallExpr:
		// string(x) and auditaction.Action(x) are conversions: check the
		// operand. auditaction.Family(verb) is a registry constructor, whose
		// domain the enum gate proves.
		fn := exprText(v.Fun)
		switch {
		case fn == "string", fn == "auditaction.Action":
			if len(v.Args) == 1 {
				checkActionExpr(t, where, v.Args[0], r)
				return
			}
		case strings.HasPrefix(fn, "auditaction."):
			return
		}
		reportUncheckable(t, where, fn+"(...)", r)

	case *ast.BinaryExpr:
		t.Errorf("%s: composes an action name with string concatenation (%s).\n"+
			"    This is the shape no gate can check, because half the name is not in\n"+
			"    this file. Use the pkg/auditaction constructor for the family —\n"+
			"    ExecutorLifecycle, WorkspacePhase, GitProxyEvent, KubeGuardEvent,\n"+
			"    AuthzOutcome — so the composition happens somewhere a test can walk\n"+
			"    the source enum and prove every member of it is registered.",
			where, exprText(v))

	default:
		reportUncheckable(t, where, fmt.Sprintf("%T", e), r)
	}
}

func reportUncheckable(t *testing.T, where, what string, r *resolver) {
	t.Helper()
	got := "an unresolved type"
	if typ := r.identType(what); typ != "" {
		got = "type " + typ
	}
	t.Errorf("%s: action comes from %s (%s), which this gate cannot trace to the registry.\n"+
		"    Give the carrier — the parameter, field, or variable — the type\n"+
		"    auditaction.Action, and pass a constant at the outermost caller. A\n"+
		"    plain string can hold anything; an Action can only have come from the\n"+
		"    registry, which is what makes it checkable here.\n"+
		"    If it genuinely cannot be typed, add %q to passThroughNames in\n"+
		"    tests/arch/auditaction_test.go with a reason a reader can check.",
		where, what, got, what)
}

// ── A small type resolver ──────────────────────────────────────────────────
//
// The gate needs to answer one question — what type does this identifier hold
// — and the honest way to answer it is to resolve the declaration, not to
// match the name. A name-matching gate accepts `ev.Action` because *something*
// somewhere is called Action, which is indistinguishable from accepting it
// because it is the right type, and the difference only shows up the day it
// matters.
//
// go/types would answer it properly and would also mean type-checking the
// whole module inside a structural test that currently runs in under a second.
// What is implemented instead is the narrow slice the emission sites actually
// use: function parameters, receivers, and locals declared from a composite
// literal, resolved against a module-wide map of struct field types. Anything
// outside that slice resolves to nothing and is reported rather than assumed —
// the failure mode is a false alarm a human reads, not a silent pass.

type resolver struct {
	fields map[string]map[string]string // qualified struct type -> field -> qualified field type
	scope  map[string]string            // identifier -> qualified type, within one function
	pkgs   map[string]map[string]string // package -> package-level identifier -> qualified type
	pkg    string                       // package the function is declared in
}

// identType returns the qualified type of a plain identifier, looking in the
// function's own scope first and then at package level — the order Go itself
// resolves in.
func (r *resolver) identType(name string) string {
	if t := r.scope[name]; t != "" {
		return t
	}
	return r.pkgs[r.pkg][name]
}

// selectorType returns the qualified type of x.Sel, when x is an identifier
// whose type is a struct this module declares.
func (r *resolver) selectorType(sel *ast.SelectorExpr) string {
	base, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	typ := r.scope[base.Name]
	if typ == "" {
		return ""
	}
	return r.fields[typ][sel.Sel.Name]
}

// funcScope maps every identifier a function binds by declaration — receiver,
// parameters, results, and locals assigned from a composite literal or a var
// declaration — to its qualified type.
func funcScope(fn *ast.FuncDecl, pkg string) map[string]string {
	scope := map[string]string{}
	add := func(names []*ast.Ident, typ ast.Expr) {
		q := qualify(typ, pkg)
		if q == "" {
			return
		}
		for _, n := range names {
			scope[n.Name] = q
		}
	}
	if fn.Recv != nil {
		for _, f := range fn.Recv.List {
			add(f.Names, f.Type)
		}
	}
	if fn.Type.Params != nil {
		for _, f := range fn.Type.Params.List {
			add(f.Names, f.Type)
		}
	}
	if fn.Type.Results != nil {
		for _, f := range fn.Type.Results.List {
			add(f.Names, f.Type)
		}
	}
	ast.Inspect(fn, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.ValueSpec:
			add(v.Names, v.Type)
		case *ast.AssignStmt:
			// x := T{...} and x := &T{...} — the composite-literal locals the
			// audit helpers build before emitting.
			if v.Tok != token.DEFINE || len(v.Lhs) != len(v.Rhs) {
				return true
			}
			for i, lhs := range v.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok {
					continue
				}
				rhs := v.Rhs[i]
				if u, ok := rhs.(*ast.UnaryExpr); ok && u.Op == token.AND {
					rhs = u.X
				}
				if cl, ok := rhs.(*ast.CompositeLit); ok {
					if q := qualify(cl.Type, pkg); q != "" {
						scope[id.Name] = q
					}
				}
			}
		case *ast.FuncLit:
			// Closure parameters: the proxy audit sinks are all
			// `func(e gitproxy.Event) { ... }`, so without this the one
			// identifier that carries the family's event kind is invisible.
			if v.Type.Params != nil {
				for _, f := range v.Type.Params.List {
					add(f.Names, f.Type)
				}
			}
		}
		return true
	})
	return scope
}

// qualify renders a type expression as pkg.Name, resolving a bare identifier
// against the package it was written in. Pointers and the one-level
// indirections the audit paths use are followed; anything else yields "".
func qualify(e ast.Expr, pkg string) string {
	switch v := e.(type) {
	case *ast.StarExpr:
		return qualify(v.X, pkg)
	case *ast.Ident:
		if isBuiltinType(v.Name) {
			return v.Name
		}
		return pkg + "." + v.Name
	case *ast.SelectorExpr:
		if p, ok := v.X.(*ast.Ident); ok {
			return p.Name + "." + v.Sel.Name
		}
	}
	return ""
}

func isBuiltinType(name string) bool {
	switch name {
	case "string", "int", "int64", "bool", "byte", "rune", "error", "any", "float64":
		return true
	}
	return false
}

// packageScopes maps each package's top-level constants and variables to their
// qualified types.
//
// Two forms are recognised. An explicit type is taken as written. A constant
// with no type is inferred only when its value is a pkg/auditaction Action
// constant — `const AuditSpendRefused = auditaction.ActionQuotaSpendRefused`,
// which is how a package gives its own name to a registry entry instead of
// repeating the literal. Nothing else is inferred: an unrecognised form
// resolves to nothing and the emission site is reported rather than assumed
// safe.
func packageScopes(files []parsedFile) map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, f := range files {
		pkg := f.file.Name.Name
		if out[pkg] == nil {
			out[pkg] = map[string]string{}
		}
		for _, decl := range f.file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				if q := qualify(vs.Type, pkg); q != "" {
					for _, n := range vs.Names {
						out[pkg][n.Name] = q
					}
					continue
				}
				for i, n := range vs.Names {
					if i >= len(vs.Values) {
						break
					}
					if isAuditActionConstant(vs.Values[i]) {
						out[pkg][n.Name] = "auditaction.Action"
					}
				}
			}
		}
	}
	return out
}

// isAuditActionConstant reports whether e is a reference to one of
// pkg/auditaction's Action constants. Matching on the Action name prefix
// rather than accepting any auditaction identifier keeps the family-name
// constants — FamilyExecutor and its siblings, which are plain strings — from
// being mistaken for actions.
func isAuditActionConstant(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "auditaction" && strings.HasPrefix(sel.Sel.Name, "Action")
}

// structFieldTypes maps every struct this module declares to its fields'
// qualified types, so a selector can be resolved without a type checker.
func structFieldTypes(t *testing.T, files []parsedFile) map[string]map[string]string {
	t.Helper()
	out := map[string]map[string]string{}
	aliases := map[string]string{}
	for _, f := range files {
		pkg := f.file.Name.Name
		for _, decl := range f.file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				// `type AuditEvent = statedb.AuditEvent`. pkg/eventlog
				// re-exports the audit row and the audit filter this way, so a
				// resolver that ignored aliases would fail to resolve every
				// selector written against the eventlog spelling — which is
				// the spelling pkg/ui and cmd actually use.
				if ts.Assign.IsValid() {
					if target := qualify(ts.Type, pkg); target != "" {
						aliases[pkg+"."+ts.Name.Name] = target
					}
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok || st.Fields == nil {
					continue
				}
				name := pkg + "." + ts.Name.Name
				if out[name] == nil {
					out[name] = map[string]string{}
				}
				for _, field := range st.Fields.List {
					q := qualify(field.Type, pkg)
					for _, n := range field.Names {
						out[name][n.Name] = q
					}
				}
			}
		}
	}
	// Point each alias at the fields of the type it names. One pass is enough:
	// the module has no alias of an alias, and a chain deeper than that is
	// better reported as unresolved than followed silently.
	for name, target := range aliases {
		if fields, ok := out[target]; ok {
			out[name] = fields
		}
	}
	if len(out) < 100 {
		t.Fatalf("resolved only %d struct types; the walk is not seeing the module", len(out))
	}
	return out
}

// TestEveryActionCarrierTypeIsClassified fails when a composite literal sets a
// field named like an action column on a type this file has never heard of.
//
// Without it the gate has an open flank: a new carrier struct — an outbox row,
// a queued event, a second export format — would set EventType from anywhere
// and never be walked, and the gate would keep passing while the vocabulary it
// guards leaked out through the new type.
func TestEveryActionCarrierTypeIsClassified(t *testing.T) {
	root := repoRoot(t)
	unknown := map[string]string{}
	for _, f := range goSourceFiles(t, root) {
		ast.Inspect(f.file, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			name := qualifiedTypeName(cl.Type, f.file.Name.Name)
			if name == "" || actionFields[name] != "" || readSideTypes[name] != "" {
				return true
			}
			for _, el := range cl.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "EventType" {
					unknown[name] = fmt.Sprintf("%s:%d", f.rel, f.fset.Position(kv.Pos()).Line)
				}
			}
			return true
		})
	}
	for name, where := range unknown {
		t.Errorf("%s: type %s sets an EventType field but is classified neither as an\n"+
			"    emission site nor as a read-side projection.\n"+
			"    Add it to actionFields (if a value written here reaches the audit\n"+
			"    column) or to readSideTypes (if it only copies a stored row), in\n"+
			"    tests/arch/auditaction_test.go. Leaving it unclassified is the one\n"+
			"    outcome to avoid: the gate would keep passing while this type carried\n"+
			"    unregistered names.", where, name)
	}
}

// ── Source enums ───────────────────────────────────────────────────────────

// actionEnum is a set of constants declared outside pkg/auditaction whose
// values become audit actions, either directly or under a family prefix.
type actionEnum struct {
	what       string // human name for failure messages
	file       string // source file, relative to the repo root
	namePrefix string // constant names to collect
	typeName   string // required declared type; "" accepts untyped constants
	prefix     string // family prefix the emitter prepends; "" if the value is already qualified
	skip       map[string]bool
}

var actionEnums = []actionEnum{
	{
		// The git proxy's event kinds are bare verbs; pkg/ui prefixes them.
		// A seventh EventKind lands in the audit table as gitproxy.<verb> and
		// must be documented before it does.
		what:       "gitproxy event kind",
		file:       "pkg/gitproxy/event.go",
		namePrefix: "Event",
		typeName:   "EventKind",
		prefix:     auditaction.FamilyGitProxy,
	},
	{
		what:       "kubeguard event kind",
		file:       "pkg/kubeguard/event.go",
		namePrefix: "Event",
		typeName:   "EventKind",
		prefix:     auditaction.FamilyKubeGuard,
	},
	{
		// claudeproxy's kinds are already fully qualified — "ci.relay.denied"
		// — so no prefix is prepended.
		what:       "CI relay event kind",
		file:       "pkg/claudeproxy/event.go",
		namePrefix: "Event",
		typeName:   "EventKind",
	},
	{
		what:       "secret broker action",
		file:       "pkg/secretbroker/audit.go",
		namePrefix: "Action",
		typeName:   "Action",
	},
}

// Not listed, on purpose: pkg/oidcauth's AuditSession* constants and
// pkg/executorstore's AuditEvent* constants.
//
// Both used to declare their own string literals and both were gated here.
// They now read `= auditaction.ActionSessionCreated` and friends — the literal
// is gone, and the constant is an alias for a registry entry rather than a
// second copy of it. TestEveryActionConstantHasARegistryEntry covers them from
// the registry side, which is strictly stronger than matching two strings and
// hoping nobody edits one.
//
// pkg/secretbroker and the three proxy packages keep their own enums because
// their values are domain concepts with behaviour attached, not just audit
// labels: secretbroker.Action drives the broker's own dispatch, and an
// EventKind decides what a proxy does as well as what it records. Rewriting
// those to satisfy a documentation gate would be the tail wagging the dog,
// so the gate reaches across to them instead.

// enumPackages are the packages whose constants the enum gate proves. A
// selector into one of them at an emission site is accepted for that reason.
var enumPackages = map[string]bool{
	"gitproxy":      true,
	"kubeguard":     true,
	"claudeproxy":   true,
	"secretbroker":  true,
	"oidcauth":      true,
	"executorstore": true,
}

func TestEveryActionEnumMapsToARegisteredAction(t *testing.T) {
	root := repoRoot(t)
	var checked int
	for _, e := range actionEnums {
		consts := constStrings(t, filepath.Join(root, e.file), e.namePrefix, e.typeName)
		if len(consts) == 0 {
			t.Errorf("%s: no constants named %s* with type %q in %s.\n"+
				"    The declaration moved or was renamed; update actionEnums or this\n"+
				"    family is no longer gated at all.", e.what, e.namePrefix, e.typeName, e.file)
			continue
		}
		names := make([]string, 0, len(consts))
		for name := range consts {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if e.skip[name] {
				continue
			}
			value := consts[name]
			action := auditaction.Action(value)
			if e.prefix != "" {
				action = auditaction.Action(e.prefix + "." + value)
			}
			checked++
			if auditaction.Registered(action) {
				continue
			}
			t.Errorf("%s %s = %q reaches the audit table as %q, which pkg/auditaction does not know.\n"+
				"    declared: %s\n"+
				"    Add the constant to pkg/auditaction/actions.go and the entry to\n"+
				"    registry.go, then run `make docs-audit`.",
				e.what, name, value, action, e.file)
		}
	}
	if checked < 40 {
		t.Errorf("only %d enum members checked; the enum gate is not reading what it used to", checked)
	}
}

// TestEveryActionConstantHasARegistryEntry catches the other half of a
// half-finished addition: a constant in actions.go with no entry in
// registry.go. The constant would compile, emit, and render as nothing on the
// generated page — documented by its own absence.
func TestEveryActionConstantHasARegistryEntry(t *testing.T) {
	root := repoRoot(t)
	consts := constStrings(t, filepath.Join(root, "pkg/auditaction/actions.go"), "Action", "Action")
	if len(consts) < 80 {
		t.Fatalf("parsed only %d Action constants from pkg/auditaction/actions.go; "+
			"the file moved or the declarations changed shape", len(consts))
	}
	names := make([]string, 0, len(consts))
	for name := range consts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !auditaction.Registered(auditaction.Action(consts[name])) {
			t.Errorf("pkg/auditaction.%s = %q has no entry in registry.go.\n"+
				"    A constant without an entry is an action with no documented trigger,\n"+
				"    no payload shape, and no row on docs/reference/audit-events.md.",
				name, consts[name])
		}
	}
	// And the reverse: every registered action should have a constant, or
	// emission sites would have nothing to reference and would write literals.
	byValue := map[string]bool{}
	for _, v := range consts {
		byValue[v] = true
	}
	for _, e := range auditaction.All() {
		if !byValue[string(e.Action)] {
			t.Errorf("action %q is in registry.go with no constant in actions.go.\n"+
				"    Emission sites have nothing to reference, so they will write the\n"+
				"    literal — which is the arrangement this package exists to end.", e.Action)
		}
	}
}

// ── AST helpers ────────────────────────────────────────────────────────────

type parsedFile struct {
	rel  string
	file *ast.File
	fset *token.FileSet
}

// goSourceFiles parses every non-test .go file in the module. Test files are
// excluded on purpose: a test may legitimately construct an event with a made
// up action to check that a reader handles an unknown one.
func goSourceFiles(t *testing.T, root string) []parsedFile {
	t.Helper()
	var out []parsedFile
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "testdata", "dist", "node_modules", ".venv":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		out = append(out, parsedFile{rel: rel, file: f, fset: fset})
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if len(out) < 100 {
		t.Fatalf("parsed only %d source files under %s", len(out), root)
	}
	return out
}

// constStrings collects string constants from one file by name prefix and
// declared type, using go/ast so a constant added today is seen today. The
// same idiom as tests/docs/drift_test.go, which reads the executor-kind and
// role enums the same way.
func constStrings(t *testing.T, path, namePrefix, typeName string) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	out := map[string]string{}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Values) == 0 {
				continue
			}
			if typeName != "" {
				id, ok := vs.Type.(*ast.Ident)
				if !ok || id.Name != typeName {
					continue
				}
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) || !strings.HasPrefix(name.Name, namePrefix) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				val, err := strconv.Unquote(lit.Value)
				if err != nil {
					continue
				}
				out[name.Name] = val
			}
		}
	}
	return out
}

// qualifiedTypeName renders a composite literal's type as pkg.Type, resolving
// a bare name against the package the literal was written in.
func qualifiedTypeName(e ast.Expr, pkg string) string {
	switch v := e.(type) {
	case *ast.Ident:
		return pkg + "." + v.Name
	case *ast.SelectorExpr:
		if p, ok := v.X.(*ast.Ident); ok {
			return p.Name + "." + v.Sel.Name
		}
	}
	return ""
}

func exprText(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprText(v.X) + "." + v.Sel.Name
	case *ast.BasicLit:
		return v.Value
	case *ast.CallExpr:
		return exprText(v.Fun) + "(...)"
	case *ast.BinaryExpr:
		return exprText(v.X) + " + " + exprText(v.Y)
	}
	return fmt.Sprintf("%T", e)
}
