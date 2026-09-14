package apiserver

// Anti-drift gates for the hand-written OpenAPI document (Task 20257).
//
// buildOpenAPISpec describes eight endpoints. Before this file, nothing tied
// it to the eight the daemon actually registers: a ninth route shipped with a
// green CI and a spec that did not mention it, which is the failure mode a
// published API description exists to prevent. An integrator trusts the
// document precisely because they cannot read the server.
//
// The gate is a two-way set comparison against routeTable(). Modelled on
// TestRegisterRoutesUsesTheRouteTable in pkg/ui/authz_test.go — same idea,
// applied to a surface whose description is written by hand rather than
// generated: the table is the source of truth for *which* endpoints exist,
// and the document must cover exactly those.

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// serverSource is pkg/apiserver/server.go, read as text so the backstop below
// can prove registration still goes through the table.
//
//go:embed server.go
var serverSource string

// specOps reads the (method, path) pairs out of the hand-written document.
func specOps(t *testing.T) map[string]bool {
	t.Helper()

	raw, err := json.Marshal(buildOpenAPISpec(8080, true))
	if err != nil {
		t.Fatalf("the spec does not marshal to JSON: %v", err)
	}
	var parsed struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("the spec does not parse back as OpenAPI: %v", err)
	}

	out := map[string]bool{}
	for path, item := range parsed.Paths {
		for method := range item {
			out[strings.ToUpper(method)+" "+path] = true
		}
	}
	return out
}

// registeredOps is the set the daemon actually serves.
func registeredOps(t *testing.T) map[string]bool {
	t.Helper()

	out := map[string]bool{}
	for _, rt := range (&Server{}).routeTable() {
		method, path, ok := splitPattern(rt.Pattern)
		if !ok {
			t.Errorf("route %q has no method prefix; every route on this surface must name its verb", rt.Pattern)
			continue
		}
		key := method + " " + path
		if out[key] {
			t.Errorf("route %q is registered twice", rt.Pattern)
		}
		out[key] = true
	}
	return out
}

// TestOpenAPISpecMatchesRegisteredRoutes fails when the document and the mux
// disagree in either direction.
func TestOpenAPISpecMatchesRegisteredRoutes(t *testing.T) {
	t.Parallel()

	registered := registeredOps(t)
	documented := specOps(t)

	var undocumented, phantom []string
	for op := range registered {
		if !documented[op] {
			undocumented = append(undocumented, op)
		}
	}
	for op := range documented {
		if !registered[op] {
			phantom = append(phantom, op)
		}
	}
	sort.Strings(undocumented)
	sort.Strings(phantom)

	if len(undocumented) > 0 {
		t.Errorf("%d registered route(s) are missing from buildOpenAPISpec:\n  %s\n"+
			"Add them to the `paths` map in server.go — the spec is published at "+
			"/openapi.json and is the only description an integrator has.",
			len(undocumented), strings.Join(undocumented, "\n  "))
	}
	if len(phantom) > 0 {
		t.Errorf("%d path(s) in buildOpenAPISpec are not registered routes:\n  %s\n"+
			"Either register them in routeTable() or remove them from the spec; "+
			"a documented endpoint that 404s is worse than an undocumented one.",
			len(phantom), strings.Join(phantom, "\n  "))
	}

	// Without this the gate would pass vacuously if both sides emptied.
	if len(registered) == 0 {
		t.Fatal("the route table is empty; the daemon serves nothing")
	}
}

// TestRunRegistersOnlyFromTheRouteTable is the backstop. The comparison above
// is only meaningful while routeTable() is what Run actually registers; a
// hand-added mux.HandleFunc would serve a route the drift test never sees.
func TestRunRegistersOnlyFromTheRouteTable(t *testing.T) {
	t.Parallel()

	// Any mux.HandleFunc whose first argument is a string literal is a
	// route registered outside the table.
	if loc := regexp.MustCompile(`mux\.HandleFunc\("`).FindStringIndex(serverSource); loc != nil {
		line := 1 + strings.Count(serverSource[:loc[0]], "\n")
		t.Errorf("server.go:%d registers a route with a literal path via mux.HandleFunc, "+
			"so it is invisible to the OpenAPI drift test. Add it to routeTable() in routes.go instead.",
			line)
	}
	if !strings.Contains(serverSource, "s.registerRoutes(mux)") {
		t.Error("Run no longer registers through the route table; the spec drift gate would " +
			"be comparing against a surface the daemon does not serve")
	}
}

// TestSpecDescribesEveryOperationUsefully catches the other way a
// hand-written document decays: an entry that exists only to satisfy the gate.
func TestSpecDescribesEveryOperationUsefully(t *testing.T) {
	t.Parallel()

	raw, err := json.Marshal(buildOpenAPISpec(8080, true))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var parsed struct {
		Paths map[string]map[string]struct {
			Summary     string          `json:"summary"`
			OperationID string          `json:"operationId"`
			Responses   json.RawMessage `json:"responses"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	seenIDs := map[string]string{}
	for path, item := range parsed.Paths {
		for method, op := range item {
			where := strings.ToUpper(method) + " " + path
			if strings.TrimSpace(op.Summary) == "" {
				t.Errorf("%s has no summary", where)
			}
			if op.OperationID == "" {
				t.Errorf("%s has no operationId", where)
				continue
			}
			if prev, dup := seenIDs[op.OperationID]; dup {
				t.Errorf("operationId %q is used by both %s and %s; generated clients would "+
					"collapse them into one method", op.OperationID, prev, where)
			}
			seenIDs[op.OperationID] = where
			if len(op.Responses) == 0 || string(op.Responses) == "{}" {
				t.Errorf("%s describes no responses", where)
			}
		}
	}
}

// TestAPIRoutesMatchesTheRouteTable checks the exported view used to generate
// docs/reference/http-api.md. The docs page is only as complete as this.
func TestAPIRoutesMatchesTheRouteTable(t *testing.T) {
	t.Parallel()

	registered := registeredOps(t)
	exported := map[string]bool{}
	for _, rt := range APIRoutes() {
		if rt.Method == "" {
			t.Errorf("APIRoutes reported %q with no method", rt.Path)
			continue
		}
		if rt.Summary == "" {
			t.Errorf("APIRoutes reported %s %s with no summary; the docs table would have a blank cell",
				rt.Method, rt.Path)
		}
		exported[rt.Method+" "+rt.Path] = true
	}

	for op := range registered {
		if !exported[op] {
			t.Errorf("%s is registered but absent from APIRoutes, so it is missing from the docs page", op)
		}
	}
	for op := range exported {
		if !registered[op] {
			t.Errorf("%s is reported by APIRoutes but is not registered", op)
		}
	}
}
