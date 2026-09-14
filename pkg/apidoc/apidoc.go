// Package apidoc renders a description of an HTTP surface from the route
// table that serves it (Task 20257).
//
// cloop exposes two HTTP APIs — the hub dashboard (pkg/ui, 140+ routes) and
// the standalone REST daemon (pkg/apiserver, 8 routes) — and until this
// package existed neither had a machine-readable description. An enterprise
// integrating against a hub read Go source, and the one OpenAPI document that
// did exist was hand-written beside the mux that it described, with nothing
// holding the two together.
//
// The fix is not a better hand-written document; it is to stop hand-writing
// one. A caller hands over its own route table and gets back the OpenAPI
// document and the Markdown reference for it, so the table stays the single
// source of truth and a new route appears in both the moment it is registered.
// What this package cannot do is invent facts the table does not carry: if a
// route's method or permission is missing from the table, it is missing here
// too, which is why the callers' drift tests assert the round trip rather than
// trusting it.
//
// The rendering is deliberately dependency-free — maps and strings, no OpenAPI
// library — because the document's shape is fixed by the route table and an
// external schema builder would add a dependency to gain nothing.
package apidoc

import (
	"fmt"
	"sort"
	"strings"
)

// Route is one (method, path) pair a surface serves, together with the access
// decision it carries.
//
// A Route describes a single OpenAPI operation, so a pattern that serves more
// than one verb yields one Route per verb. That is what lets the same value
// describe a method-prefixed pattern and one registered bare: the expansion
// happens in the caller, which is the only place that knows.
type Route struct {
	// Method is the HTTP verb, upper case ("GET").
	Method string

	// Path is the request path, with ServeMux wildcards left as OpenAPI
	// template parameters — {id} means the same thing in both, which is
	// why no translation is needed.
	Path string

	// Permission is the authorization required, as the wire string the
	// audit trail and /api/me use ("audit.read"). Empty for a surface with
	// no permission model — pkg/apiserver authenticates with a single
	// bearer token and does not distinguish capabilities.
	Permission string

	// Public marks a route reachable before authorization is evaluated.
	// Distinct from an empty Permission: public is a decision, absent is a
	// surface that never makes one.
	Public bool

	// Scope names what the permission is evaluated against ("global",
	// "project", "project-index", "executor"). Empty when not applicable.
	Scope string

	// Summary is a one-line description, shown in both renderings.
	Summary string

	// Subtree marks a ServeMux pattern ending in "/", which matches every
	// path beneath it rather than only itself. Recorded because OpenAPI has
	// no way to express it and a reader would otherwise assume the literal.
	Subtree bool
}

// Surface is one HTTP API: how to describe it, and what it serves.
type Surface struct {
	// Title names the surface in the Markdown reference.
	Title string

	// Intro is the lead paragraph, rendered as-is (Markdown).
	Intro string

	// Routes is the complete route set, in any order; both renderings sort.
	Routes []Route
}

// Info is the OpenAPI document's metadata.
type Info struct {
	Title       string
	Version     string
	Description string

	// ServerURL is the base URL advertised in `servers`. Empty omits it,
	// which is correct for a hub that does not know its own external URL.
	ServerURL string

	// BearerAuth and CookieAuth select the security schemes offered.
	BearerAuth bool
	CookieAuth string // cookie name; empty disables the scheme
}

// sortRoutes orders routes by path then by a fixed verb order, so both
// renderings — and therefore the checked-in docs page — are deterministic.
func sortRoutes(routes []Route) []Route {
	out := append([]Route(nil), routes...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return methodRank(out[i].Method) < methodRank(out[j].Method)
	})
	return out
}

// methodOrder is the conventional order operations are listed in, matching
// how OpenAPI tooling renders them. Unknown verbs sort last, alphabetically.
var methodOrder = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}

func methodRank(m string) int {
	for i, known := range methodOrder {
		if m == known {
			return i
		}
	}
	return len(methodOrder)
}

// pathParams returns the wildcard names in a path template, in order.
func pathParams(path string) []string {
	var out []string
	rest := path
	for {
		open := strings.Index(rest, "{")
		if open < 0 {
			return out
		}
		close := strings.Index(rest[open:], "}")
		if close < 0 {
			return out
		}
		name := rest[open+1 : open+close]
		// ServeMux's "{name...}" matches the remainder of the path; the
		// parameter is still called "name".
		name = strings.TrimSuffix(name, "...")
		if name != "" && name != "$" {
			out = append(out, name)
		}
		rest = rest[open+close+1:]
	}
}

// OperationID derives a stable, unique identifier for an operation.
//
// Exported because the drift tests assert uniqueness across a whole surface:
// two routes colliding here would silently overwrite one another in any
// generated client, and that is exactly the failure a generated document is
// supposed to make impossible.
func OperationID(method, path string) string {
	var b strings.Builder
	b.WriteString(strings.ToLower(method))
	upperNext := true
	for _, r := range path {
		switch {
		case r == '/' || r == '-' || r == '.' || r == '_' || r == '{' || r == '}':
			upperNext = true
		case upperNext:
			b.WriteString(strings.ToUpper(string(r)))
			upperNext = false
		default:
			b.WriteRune(r)
		}
	}
	id := b.String()
	// "/" and "/assets/" reduce to just the verb; keep them distinguishable.
	if id == strings.ToLower(method) {
		return id + "Root"
	}
	return id
}

// OpenAPI renders an OpenAPI 3.0 document for routes.
//
// The returned value is a plain map so it can be served with the same JSON
// encoder as every other endpoint, and compared field-by-field in tests
// without a schema library.
func OpenAPI(info Info, routes []Route) map[string]any {
	doc := map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":       info.Title,
			"version":     info.Version,
			"description": info.Description,
		},
	}
	if info.ServerURL != "" {
		doc["servers"] = []any{map[string]any{"url": info.ServerURL}}
	}

	schemes := map[string]any{}
	var security []any
	if info.BearerAuth {
		schemes["bearerAuth"] = map[string]any{
			"type":         "http",
			"scheme":       "bearer",
			"bearerFormat": "token",
			"description": "An API token minted by the hub (cloop_pat_…), sent as " +
				"`Authorization: Bearer <token>`.",
		}
		security = append(security, map[string]any{"bearerAuth": []any{}})
	}
	if info.CookieAuth != "" {
		schemes["cookieAuth"] = map[string]any{
			"type": "apiKey",
			"in":   "cookie",
			"name": info.CookieAuth,
			"description": "The session cookie set by the OIDC login flow. " +
				"Used by the dashboard; machine clients should hold a token instead.",
		}
		security = append(security, map[string]any{"cookieAuth": []any{}})
	}
	if len(schemes) > 0 {
		doc["components"] = map[string]any{"securitySchemes": schemes}
		doc["security"] = security
	}

	paths := map[string]any{}
	for _, rt := range sortRoutes(routes) {
		item, _ := paths[rt.Path].(map[string]any)
		if item == nil {
			item = map[string]any{}
			paths[rt.Path] = item
		}
		item[strings.ToLower(rt.Method)] = operation(rt, len(security) > 0)
	}
	doc["paths"] = paths
	return doc
}

// operation renders one OpenAPI operation object.
func operation(rt Route, surfaceHasAuth bool) map[string]any {
	op := map[string]any{
		"operationId": OperationID(rt.Method, rt.Path),
		"summary":     rt.Summary,
		"responses":   responses(rt),
	}
	if rt.Summary == "" {
		op["summary"] = rt.Method + " " + rt.Path
	}

	if params := pathParams(rt.Path); len(params) > 0 {
		var list []any
		for _, name := range params {
			list = append(list, map[string]any{
				"name":     name,
				"in":       "path",
				"required": true,
				"schema":   map[string]any{"type": "string"},
			})
		}
		op["parameters"] = list
	}

	// Extensions carry what OpenAPI has no vocabulary for, and they are the
	// reason this document is worth generating: the permission a route
	// requires is the fact an integrator most needs and the one no
	// hand-written spec kept current.
	if rt.Permission != "" {
		op["x-cloop-permission"] = rt.Permission
	}
	if rt.Scope != "" {
		op["x-cloop-scope"] = rt.Scope
	}
	op["x-cloop-public"] = rt.Public
	if rt.Subtree {
		op["x-cloop-subtree"] = true
	}

	// A public route must not inherit the document-wide security
	// requirement: an empty list is OpenAPI's way of saying "no
	// authentication", and without it a generated client would demand a
	// credential to reach the login endpoint.
	if rt.Public && surfaceHasAuth {
		op["security"] = []any{}
	}
	return op
}

// responses renders the response set. Deliberately coarse: the route table
// records access control, not payload schemas, and inventing response bodies
// here would produce exactly the hand-maintained fiction this package exists
// to replace. The status codes below are the ones the middleware itself
// produces and can therefore be stated truthfully.
func responses(rt Route) map[string]any {
	out := map[string]any{
		"200": map[string]any{"description": "Success"},
	}
	if !rt.Public {
		out["401"] = map[string]any{"description": "No or invalid credential"}
		out["403"] = map[string]any{"description": "The caller's role does not grant " + rt.Permission}
		// A project the caller cannot see is reported as absent rather
		// than forbidden, so the 404 is part of the access-control
		// contract and not only a routing outcome.
		if rt.Scope == "project" || rt.Scope == "project-index" || rt.Scope == "executor" {
			out["404"] = map[string]any{"description": "The resource does not exist, or is not visible to this caller"}
		}
	}
	if rt.Permission == "project.read" || rt.Permission == "executor.read" || rt.Permission == "audit.read" {
		if rt.Method != "GET" && rt.Method != "HEAD" && rt.Method != "OPTIONS" {
			out["405"] = map[string]any{"description": "Read-only endpoint"}
		}
	}
	return out
}

// Markdown renders the human-readable endpoint reference.
//
// intro is the page's lead, rendered before the surfaces. The output is
// deterministic so it can be checked in and gated against the route tables it
// was generated from.
func Markdown(intro string, surfaces []Surface) string {
	var b strings.Builder
	b.WriteString(intro)
	if !strings.HasSuffix(intro, "\n") {
		b.WriteString("\n")
	}

	for _, sf := range surfaces {
		fmt.Fprintf(&b, "\n## %s\n\n", sf.Title)
		if sf.Intro != "" {
			b.WriteString(strings.TrimRight(sf.Intro, "\n"))
			b.WriteString("\n\n")
		}
		writeSummary(&b, sf.Routes)
		writeTable(&b, sf.Routes)
	}
	return b.String()
}

// writeSummary renders the per-permission counts: the fastest answer to
// "what can this role actually reach", which a flat table buries.
func writeSummary(b *strings.Builder, routes []Route) {
	counts := map[string]int{}
	anyPermission := false
	for _, rt := range routes {
		switch {
		case rt.Public:
			counts["public"]++
		case rt.Permission == "":
			counts[""]++
		default:
			counts[rt.Permission]++
			anyPermission = true
		}
	}
	if !anyPermission {
		// A surface with no permission model has only one thing to say
		// about access, and saying it once beats a column of dashes.
		exempt := counts["public"]
		fmt.Fprintf(b, "%d endpoints. When the server is started with a token, every one "+
			"requires it", len(routes))
		if exempt > 0 {
			fmt.Fprintf(b, " except the %d marked `none`", exempt)
		}
		b.WriteString(".\n\n")
		return
	}

	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	// public first — it is the unauthenticated surface, and the one worth
	// reading before any other — then alphabetically.
	sort.Slice(keys, func(i, j int) bool {
		if (keys[i] == "public") != (keys[j] == "public") {
			return keys[i] == "public"
		}
		return keys[i] < keys[j]
	})

	fmt.Fprintf(b, "%d endpoints, by the permission each one requires:\n\n", len(routes))
	b.WriteString("| Permission | Endpoints |\n|------------|-----------|\n")
	for _, k := range keys {
		label := "`" + k + "`"
		if k == "public" {
			label = "`public` (no permission)"
		}
		fmt.Fprintf(b, "| %s | %d |\n", label, counts[k])
	}
	b.WriteString("\n")
}

// writeTable renders every route, sorted by path.
//
// The columns follow the surface. A permission model is worth four columns; a
// surface without one would fill two of them with dashes, so it gets the
// endpoint summaries instead — which is the useful thing to say about eight
// endpoints and the wrong thing to try to say about a hundred and fifty.
func writeTable(b *strings.Builder, routes []Route) {
	graded := false
	for _, rt := range routes {
		if rt.Permission != "" {
			graded = true
			break
		}
	}

	if graded {
		b.WriteString("| Method | Path | Permission | Scope |\n")
		b.WriteString("|--------|------|------------|-------|\n")
	} else {
		b.WriteString("| Method | Path | Auth | Description |\n")
		b.WriteString("|--------|------|------|-------------|\n")
	}

	for _, rt := range sortRoutes(routes) {
		path := "`" + rt.Path + "`"
		if rt.Subtree {
			path += " *(subtree)*"
		}

		if !graded {
			auth := "token"
			if rt.Public {
				auth = "`none`"
			}
			fmt.Fprintf(b, "| %s | %s | %s | %s |\n", rt.Method, path, auth, rt.Summary)
			continue
		}

		perm := "—"
		switch {
		case rt.Public:
			perm = "`public`"
		case rt.Permission != "":
			perm = "`" + rt.Permission + "`"
		}
		scope := rt.Scope
		if scope == "" {
			scope = "—"
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s |\n", rt.Method, path, perm, scope)
	}
}
