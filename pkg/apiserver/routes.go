package apiserver

// The REST daemon's route table (Task 20257).
//
// `cloop serve` hand-writes an OpenAPI document in buildOpenAPISpec and serves
// it at /openapi.json. That document was written beside the registrations
// rather than derived from them, and nothing connected the two: registering a
// ninth route left the spec describing eight, and CI stayed green. The gap is
// the ordinary fate of a hand-maintained description — it is correct exactly
// once, on the day it is written.
//
// Moving registration into a table does not by itself fix that, but it makes
// the fix possible: TestOpenAPISpecMatchesRegisteredRoutes in
// openapi_drift_test.go compares the document against this table in both
// directions, so a route added without a corresponding spec entry — or a spec
// entry for a route that no longer exists — fails the build.
//
// The document stays hand-written here, unlike the hub's in pkg/ui, and that
// is deliberate rather than an omission. These eight endpoints have real
// request and response schemas worth describing, and generating those from a
// route table would mean inventing them. The table's job is to make sure the
// hand-written half stays complete; the prose inside it is still a human's.

import (
	"net/http"

	"github.com/blechschmidt/cloop/pkg/apidoc"
)

// apiRoute is one registered endpoint of the REST daemon.
//
// There is no permission field: `cloop serve` authenticates with a single
// bearer token and draws no distinction between capabilities, unlike the hub.
// A route is either behind the token or exempt from it — see Exempt.
type apiRoute struct {
	// Pattern is the method-prefixed http.ServeMux pattern.
	Pattern string

	// Handler serves the route.
	Handler http.HandlerFunc

	// Exempt marks a route that answers without the bearer token. Only the
	// self-description qualifies: tooling has to be able to discover the
	// API before it can be configured with a credential for it. The
	// authentication middleware owns the actual decision (see probeBypass
	// and authMiddleware); this flag records it for the description.
	Exempt bool

	// Summary is the one-line description used in the generated Markdown
	// reference. The OpenAPI document carries its own, richer prose.
	Summary string
}

// routeTable is the complete set of routes the daemon serves.
//
// A method (not a package var) because the handlers are Server methods, and
// for the same reason as pkg/ui's: tests walk the same table Run registers,
// so a route cannot be described by tests and absent in production.
func (s *Server) routeTable() []apiRoute {
	return []apiRoute{
		// The self-description, exempt from auth so tooling can discover
		// the API before it holds a credential for it.
		{Pattern: "GET /openapi.json", Handler: s.handleOpenAPI, Exempt: true,
			Summary: "OpenAPI 3.0 description of this API"},

		{Pattern: "GET /plan", Handler: s.handleGetPlan,
			Summary: "The project's goal and its full task list"},

		{Pattern: "PATCH /tasks/{id}", Handler: s.handlePatchTask,
			Summary: "Update a task's status, title, priority or tags"},

		{Pattern: "POST /run/start", Handler: s.handleRunStart,
			Summary: "Start a run"},
		{Pattern: "POST /run/stop", Handler: s.handleRunStop,
			Summary: "Stop the running plan"},

		{Pattern: "GET /status", Handler: s.handleStatus,
			Summary: "Lightweight run status and task counts"},
		{Pattern: "GET /metrics", Handler: s.handleMetrics,
			Summary: "Run metrics, as JSON or Prometheus text"},

		{Pattern: "GET /artifacts/{taskId}", Handler: s.handleArtifact,
			Summary: "The recorded output of a completed task"},
	}
}

// registerRoutes wires the table onto mux. The only registration path, so
// that the drift test's view of the surface is the served surface.
func (s *Server) registerRoutes(mux *http.ServeMux) {
	for _, rt := range s.routeTable() {
		mux.HandleFunc(rt.Pattern, rt.Handler)
	}
}

// APIRoutes describes this surface for the documentation generator in
// tests/docs, which renders docs/reference/http-api.md from it and from
// pkg/ui.APIRoutes.
//
// Builds a zero Server: the handlers are method values, well-formed without
// server state, and nothing else about a route depends on a running daemon.
func APIRoutes() []apidoc.Route {
	var out []apidoc.Route
	for _, rt := range (&Server{}).routeTable() {
		method, path, ok := splitPattern(rt.Pattern)
		if !ok {
			// Every row in this table is method-prefixed; a row that is
			// not would be described with an empty verb, so report the
			// pattern as-is and let the drift test fail on it loudly.
			method, path = "", rt.Pattern
		}
		out = append(out, apidoc.Route{
			Method:  method,
			Path:    path,
			Public:  rt.Exempt,
			Summary: rt.Summary,
		})
	}
	return out
}

// splitPattern separates the method prefix from a ServeMux pattern. ok is
// false when there is none.
func splitPattern(pattern string) (method, path string, ok bool) {
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == ' ' {
			return pattern[:i], pattern[i+1:], true
		}
	}
	return "", pattern, false
}
