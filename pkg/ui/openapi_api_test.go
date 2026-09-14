package ui

// Anti-drift gates for the generated OpenAPI document (Task 20257).
//
// Generating a description from the route table removes one failure mode and
// introduces another. It cannot go stale — there is only one table — but it
// can go *incomplete*: a route whose pattern shape the conversion mishandles
// drops out of the document with nothing failing, and a silently short
// document is worse than an honestly absent one, because an integrator reads
// the absence as "this hub does not expose that".
//
// So the round trip is asserted in both directions. Every registered route
// appears in the document, every path in the document is a registered route,
// and the counts match — which is what makes "exactly" mean exactly. These
// are modelled on TestRegisterRoutesUsesTheRouteTable in authz_test.go: the
// same idea, applied to the description rather than the registration.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/apidoc"
	"github.com/blechschmidt/cloop/pkg/authz"
)

// opKey identifies one operation for set comparison.
type opKey struct{ method, path string }

func (k opKey) String() string { return k.method + " " + k.path }

// registeredOps is the set of operations the route table actually serves,
// derived from the table itself rather than from apiRoutes — the value under
// test must not define its own expectation.
func registeredOps(t *testing.T) map[opKey]routeSpec {
	t.Helper()
	out := map[opKey]routeSpec{}
	for _, rs := range (&Server{}).routeTable() {
		method, path, ok := splitPattern(rs.Pattern)
		methods := []string{method}
		if !ok {
			methods = rs.Methods
		}
		if len(methods) == 0 {
			t.Fatalf("route %q serves no methods; validate() should have refused it", rs.Pattern)
		}
		for _, m := range methods {
			k := opKey{m, path}
			if prev, dup := out[k]; dup {
				t.Errorf("two routes both serve %s: %q and %q", k, prev.Pattern, rs.Pattern)
			}
			out[k] = rs
		}
	}
	return out
}

// documentOps reads the operations back out of a rendered OpenAPI document,
// parsing it as an integrator's tooling would rather than inspecting the Go
// values that produced it.
func documentOps(t *testing.T, doc map[string]any) map[opKey]map[string]any {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("the generated document does not marshal to JSON: %v", err)
	}
	var parsed struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("the generated document does not parse back: %v", err)
	}
	out := map[opKey]map[string]any{}
	for path, item := range parsed.Paths {
		for method, opRaw := range item {
			var op map[string]any
			if err := json.Unmarshal(opRaw, &op); err != nil {
				t.Fatalf("operation %s %s does not parse: %v", method, path, err)
			}
			out[opKey{strings.ToUpper(method), path}] = op
		}
	}
	return out
}

// TestOpenAPICoversExactlyTheRouteTable is the drift gate: adding or removing
// a route must change the document, and any route the conversion cannot
// express must fail here rather than disappear.
func TestOpenAPICoversExactlyTheRouteTable(t *testing.T) {
	t.Parallel()

	registered := registeredOps(t)
	documented := documentOps(t, apidoc.OpenAPI(openAPIInfo(), APIRoutes()))

	var missing, extra []string
	for k := range registered {
		if _, ok := documented[k]; !ok {
			missing = append(missing, k.String())
		}
	}
	for k := range documented {
		if _, ok := registered[k]; !ok {
			extra = append(extra, k.String())
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)

	if len(missing) > 0 {
		t.Errorf("%d registered route(s) are absent from the generated OpenAPI document:\n  %s\n"+
			"The document is generated from routeTable(), so this means apiRoutes() could not "+
			"express the route — most likely an unhandled pattern shape in splitPattern.",
			len(missing), strings.Join(missing, "\n  "))
	}
	if len(extra) > 0 {
		t.Errorf("%d operation(s) in the generated OpenAPI document are not registered routes:\n  %s\n"+
			"The document must describe the hub that serves it, and nothing else.",
			len(extra), strings.Join(extra, "\n  "))
	}
	if len(registered) != len(documented) {
		t.Errorf("route table serves %d operations, document describes %d", len(registered), len(documented))
	}
	// Guards against the whole gate passing vacuously if both sides ever
	// collapse to empty.
	if len(registered) < 100 {
		t.Errorf("only %d operations found; the hub serves well over 100 — the table did not load", len(registered))
	}
}

// TestOpenAPIStatesEachRoutesPermission checks the fact the document exists to
// carry. A path list an integrator cannot act on is a sitemap; the permission
// is what makes it an API description.
func TestOpenAPIStatesEachRoutesPermission(t *testing.T) {
	t.Parallel()

	registered := registeredOps(t)
	documented := documentOps(t, apidoc.OpenAPI(openAPIInfo(), APIRoutes()))

	for k, op := range documented {
		rs, ok := registered[k]
		if !ok {
			continue // reported by the coverage test
		}
		want := rs.permFor(k.method)
		isPublic := want == authz.PermPublic

		gotPublic, ok := op["x-cloop-public"].(bool)
		if !ok {
			t.Errorf("%s: no x-cloop-public flag", k)
			continue
		}
		if gotPublic != isPublic {
			t.Errorf("%s: x-cloop-public = %v, but the table declares %q", k, gotPublic, want)
		}

		gotPerm, has := op["x-cloop-permission"].(string)
		switch {
		case isPublic && has:
			t.Errorf("%s: public route names permission %q; public is not a permission and no role holds it", k, gotPerm)
		case !isPublic && gotPerm != string(want):
			t.Errorf("%s: x-cloop-permission = %q, table requires %q", k, gotPerm, want)
		}

		// A public operation must clear the document-wide security
		// requirement, or generated clients demand a credential to reach
		// the login flow — which would break sign-in for every consumer.
		if isPublic {
			sec, ok := op["security"].([]any)
			if !ok || len(sec) != 0 {
				t.Errorf("%s: public route does not override security with an empty list (got %#v)", k, op["security"])
			}
		}
	}
}

// TestOpenAPIOperationIDsAreUnique guards the property every code generator
// depends on: colliding operation IDs silently overwrite one another, so two
// endpoints become one in any generated client.
func TestOpenAPIOperationIDsAreUnique(t *testing.T) {
	t.Parallel()

	seen := map[string]string{}
	for _, rt := range APIRoutes() {
		id := apidoc.OperationID(rt.Method, rt.Path)
		if id == "" {
			t.Errorf("%s %s produced an empty operationId", rt.Method, rt.Path)
			continue
		}
		key := rt.Method + " " + rt.Path
		if prev, dup := seen[id]; dup {
			t.Errorf("operationId %q is produced by both %q and %q", id, prev, key)
		}
		seen[id] = key
	}
}

// TestOpenAPIRouteIsItselfInTheTable keeps the description honest about
// itself: a document served from a route it does not list is already drifting.
func TestOpenAPIRouteIsItselfInTheTable(t *testing.T) {
	t.Parallel()

	const path = "/api/openapi.json"
	documented := documentOps(t, apidoc.OpenAPI(openAPIInfo(), APIRoutes()))
	op, ok := documented[opKey{http.MethodGet, path}]
	if !ok {
		t.Fatalf("the OpenAPI endpoint %s is not described by the document it serves", path)
	}
	if public, _ := op["x-cloop-public"].(bool); public {
		t.Errorf("%s is public; the task requires it to carry an explicit permission", path)
	}
	if perm, _ := op["x-cloop-permission"].(string); perm != string(authz.PermProjectRead) {
		t.Errorf("%s requires %q, want %q", path, perm, authz.PermProjectRead)
	}
}

// TestHandleOpenAPIServesAParsableDocument exercises the handler end to end:
// the generator can be correct while the route serves the wrong content type
// or an unencodable value.
func TestHandleOpenAPIServesAParsableDocument(t *testing.T) {
	t.Parallel()

	// registerRoutes is what renders the document, so the handler is
	// exercised the way the server actually reaches it.
	srv := &Server{}
	srv.registerRoutes(http.NewServeMux())

	rr := httptest.NewRecorder()
	srv.handleOpenAPI(rr, httptest.NewRequest(http.MethodGet, "/api/openapi.json", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var doc struct {
		OpenAPI string                            `json:"openapi"`
		Info    struct{ Title string }            `json:"info"`
		Paths   map[string]map[string]interface{} `json:"paths"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatalf("response is not a parsable OpenAPI document: %v", err)
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.") {
		t.Errorf("openapi = %q, want a 3.x version", doc.OpenAPI)
	}
	if doc.Info.Title == "" {
		t.Error("info.title is empty")
	}
	if len(doc.Paths) < 100 {
		t.Errorf("document describes %d paths; the hub serves far more", len(doc.Paths))
	}
}

// TestEveryMethodLessRouteDeclaresItsVerbs locks in the field that made the
// description possible. http.ServeMux routes every verb to a pattern with no
// method prefix, so without Methods the table cannot say what such a route
// answers — and a generated document would have to guess.
func TestEveryMethodLessRouteDeclaresItsVerbs(t *testing.T) {
	t.Parallel()

	for _, rs := range (&Server{}).routeTable() {
		if _, _, hasMethod := splitPattern(rs.Pattern); hasMethod {
			if len(rs.Methods) > 0 {
				t.Errorf("route %q carries a method prefix and must not also declare Methods", rs.Pattern)
			}
			continue
		}
		if len(rs.Methods) == 0 {
			t.Errorf("route %q is registered without a method prefix and declares no Methods, "+
				"so nothing can say which verbs it serves", rs.Pattern)
			continue
		}
		for _, m := range rs.Methods {
			if !methodAllowed(rs.permFor(m), m) {
				t.Errorf("route %q declares %s, but that verb resolves to %q and the gate refuses it as read-only",
					rs.Pattern, m, rs.permFor(m))
			}
		}
	}
}
