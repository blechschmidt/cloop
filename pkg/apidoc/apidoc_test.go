package apidoc

import (
	"encoding/json"
	"strings"
	"testing"
)

// sample is a small surface exercising every shape the renderers must handle:
// a public route, a gated one, a path parameter, a subtree, and two verbs on
// one path.
var sample = []Route{
	{Method: "GET", Path: "/api/me", Public: true, Scope: "global", Summary: "Who am I"},
	{Method: "GET", Path: "/api/tasks/{id}", Permission: "project.read", Scope: "project"},
	{Method: "DELETE", Path: "/api/tasks/{id}", Permission: "task.mutate", Scope: "project"},
	{Method: "GET", Path: "/assets/", Public: true, Subtree: true},
}

func renderDoc(t *testing.T, info Info, routes []Route) map[string]any {
	t.Helper()
	raw, err := json.Marshal(OpenAPI(info, routes))
	if err != nil {
		t.Fatalf("document does not marshal: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("document does not round-trip: %v", err)
	}
	return out
}

func TestOpenAPIPlacesEveryRouteUnderItsPathAndVerb(t *testing.T) {
	doc := renderDoc(t, Info{Title: "t", Version: "v"}, sample)

	paths, ok := doc["paths"].(map[string]any)
	if !ok {
		t.Fatal("no paths object")
	}
	if len(paths) != 3 {
		t.Errorf("got %d paths, want 3 (two verbs share /api/tasks/{id})", len(paths))
	}

	item, ok := paths["/api/tasks/{id}"].(map[string]any)
	if !ok {
		t.Fatal("/api/tasks/{id} missing")
	}
	for _, verb := range []string{"get", "delete"} {
		if _, ok := item[verb]; !ok {
			t.Errorf("/api/tasks/{id} has no %s operation", verb)
		}
	}
}

func TestOpenAPICarriesThePermissionExtensions(t *testing.T) {
	doc := renderDoc(t, Info{Title: "t", Version: "v"}, sample)
	paths := doc["paths"].(map[string]any)

	del := paths["/api/tasks/{id}"].(map[string]any)["delete"].(map[string]any)
	if got := del["x-cloop-permission"]; got != "task.mutate" {
		t.Errorf("x-cloop-permission = %v, want task.mutate", got)
	}
	if got := del["x-cloop-scope"]; got != "project" {
		t.Errorf("x-cloop-scope = %v, want project", got)
	}
	if got := del["x-cloop-public"]; got != false {
		t.Errorf("x-cloop-public = %v, want false", got)
	}

	// A public route names no permission: public is not one, and reporting
	// it as though a role could hold it would be a lie a client acts on.
	me := paths["/api/me"].(map[string]any)["get"].(map[string]any)
	if _, named := me["x-cloop-permission"]; named {
		t.Errorf("public route names a permission: %v", me["x-cloop-permission"])
	}
	if got := me["x-cloop-public"]; got != true {
		t.Errorf("x-cloop-public = %v, want true", got)
	}

	assets := paths["/assets/"].(map[string]any)["get"].(map[string]any)
	if got := assets["x-cloop-subtree"]; got != true {
		t.Errorf("x-cloop-subtree = %v, want true", got)
	}
}

// TestPublicOperationsClearTheSecurityRequirement is the one that breaks a
// consumer if it regresses: without the empty override, a generated client
// demands a credential to reach the endpoints that exist to be reached
// without one.
func TestPublicOperationsClearTheSecurityRequirement(t *testing.T) {
	doc := renderDoc(t, Info{Title: "t", Version: "v", BearerAuth: true}, sample)
	paths := doc["paths"].(map[string]any)

	me := paths["/api/me"].(map[string]any)["get"].(map[string]any)
	sec, ok := me["security"].([]any)
	if !ok {
		t.Fatalf("public operation has no security override (got %#v)", me["security"])
	}
	if len(sec) != 0 {
		t.Errorf("public operation security = %#v, want an empty list", sec)
	}

	// A gated operation must inherit the document-wide requirement rather
	// than restate or clear it.
	get := paths["/api/tasks/{id}"].(map[string]any)["get"].(map[string]any)
	if _, overridden := get["security"]; overridden {
		t.Errorf("gated operation overrides security: %#v", get["security"])
	}
	if _, ok := doc["security"].([]any); !ok {
		t.Error("document declares no top-level security requirement")
	}
}

// TestNoSecuritySchemesWhenNoneConfigured covers the single-tenant hub: with
// no credential offered, an empty `security` on every public route would be
// noise, and an unbacked scheme reference would make the document invalid.
func TestNoSecuritySchemesWhenNoneConfigured(t *testing.T) {
	doc := renderDoc(t, Info{Title: "t", Version: "v"}, sample)
	if _, ok := doc["security"]; ok {
		t.Error("document declares a security requirement with no schemes configured")
	}
	if _, ok := doc["components"]; ok {
		t.Error("document declares components with no schemes configured")
	}
	me := doc["paths"].(map[string]any)["/api/me"].(map[string]any)["get"].(map[string]any)
	if _, ok := me["security"]; ok {
		t.Error("public operation overrides a security requirement that does not exist")
	}
}

func TestPathParametersAreDeclared(t *testing.T) {
	doc := renderDoc(t, Info{Title: "t", Version: "v"}, sample)
	op := doc["paths"].(map[string]any)["/api/tasks/{id}"].(map[string]any)["get"].(map[string]any)

	params, ok := op["parameters"].([]any)
	if !ok || len(params) != 1 {
		t.Fatalf("parameters = %#v, want one entry for {id}", op["parameters"])
	}
	p := params[0].(map[string]any)
	if p["name"] != "id" || p["in"] != "path" || p["required"] != true {
		t.Errorf("parameter = %#v, want a required path parameter named id", p)
	}

	// A path with no template must not declare an empty parameter list.
	me := doc["paths"].(map[string]any)["/api/me"].(map[string]any)["get"].(map[string]any)
	if _, ok := me["parameters"]; ok {
		t.Errorf("parameterless path declares parameters: %#v", me["parameters"])
	}
}

func TestPathParams(t *testing.T) {
	for _, tc := range []struct {
		path string
		want []string
	}{
		{"/api/me", nil},
		{"/api/tasks/{id}", []string{"id"}},
		{"/api/projects/{idx}/run", []string{"idx"}},
		{"/api/quotas/{identity}", []string{"identity"}},
		{"/a/{one}/b/{two}", []string{"one", "two"}},
		// ServeMux's trailing-wildcard form names the same parameter.
		{"/files/{rest...}", []string{"rest"}},
		// Malformed templates must not hang or panic.
		{"/broken/{unclosed", nil},
	} {
		got := pathParams(tc.path)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("pathParams(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestOperationIDIsStableAndDistinct(t *testing.T) {
	for _, tc := range []struct{ method, path, want string }{
		{"GET", "/api/tasks/{id}", "getApiTasksId"},
		{"DELETE", "/api/tasks/{id}", "deleteApiTasksId"},
		{"GET", "/api/provider-calls", "getApiProviderCalls"},
		{"GET", "/manifest.webmanifest", "getManifestWebmanifest"},
		// "/" and "/assets/" both reduce to the bare verb without the suffix.
		{"GET", "/", "getRoot"},
	} {
		if got := OperationID(tc.method, tc.path); got != tc.want {
			t.Errorf("OperationID(%q, %q) = %q, want %q", tc.method, tc.path, got, tc.want)
		}
	}
}

func TestMarkdownIsDeterministic(t *testing.T) {
	shuffled := []Route{sample[3], sample[1], sample[0], sample[2]}
	surfaces := func(rs []Route) []Surface {
		return []Surface{{Title: "S", Intro: "intro", Routes: rs}}
	}
	a := Markdown("# T\n", surfaces(sample))
	b := Markdown("# T\n", surfaces(shuffled))
	if a != b {
		t.Error("Markdown output depends on input order; the checked-in page would churn")
	}
}

func TestMarkdownRendersPermissionColumnsForAGradedSurface(t *testing.T) {
	out := Markdown("# T\n", []Surface{{Title: "Hub", Routes: sample}})

	if !strings.Contains(out, "| Method | Path | Permission | Scope |") {
		t.Error("graded surface did not get the permission columns")
	}
	for _, want := range []string{
		"| DELETE | `/api/tasks/{id}` | `task.mutate` | project |",
		"| GET | `/api/me` | `public` | global |",
		"| GET | `/assets/` *(subtree)* | `public` | — |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing row:\n  %s\ngot:\n%s", want, out)
		}
	}
	// The per-permission summary is the fastest answer to "what can this
	// role reach"; losing it would leave only a flat list.
	if !strings.Contains(out, "| `task.mutate` | 1 |") {
		t.Errorf("permission summary missing a task.mutate count:\n%s", out)
	}
}

func TestMarkdownRendersSummariesForAnUngradedSurface(t *testing.T) {
	daemon := []Route{
		{Method: "GET", Path: "/plan", Summary: "The plan"},
		{Method: "GET", Path: "/openapi.json", Public: true, Summary: "This document"},
	}
	out := Markdown("# T\n", []Surface{{Title: "Daemon", Routes: daemon}})

	if !strings.Contains(out, "| Method | Path | Auth | Description |") {
		t.Errorf("ungraded surface did not get the description columns:\n%s", out)
	}
	if strings.Contains(out, "| Permission | Endpoints |") {
		t.Error("ungraded surface rendered a permission summary it has no data for")
	}
	for _, want := range []string{
		"| GET | `/plan` | token | The plan |",
		"| GET | `/openapi.json` | `none` | This document |",
		"except the 1 marked `none`",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestMarkdownCoversEveryRoute(t *testing.T) {
	out := Markdown("# T\n", []Surface{{Title: "Hub", Routes: sample}})
	for _, rt := range sample {
		if !strings.Contains(out, "`"+rt.Path+"`") {
			t.Errorf("route %s %s is absent from the rendering", rt.Method, rt.Path)
		}
	}
}
