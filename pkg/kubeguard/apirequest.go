// Package kubeguard is the monitor that sits between a sandbox and a
// Kubernetes cluster (Task 20277).
//
// # Why a proxy and not a narrower kubeconfig
//
// pkg/secretbroker already minimises a kubeconfig: a grant names contexts and
// namespaces, MinimizeKubeconfig drops every context outside the allowlist,
// and the clusters and users nothing references go with them. That is real —
// a sandbox cannot reach a cluster whose credential it was never given.
//
// It cannot do the two things this package exists for.
//
//   - A namespace in a kubeconfig context is a *client-side default*. It is
//     the value kubectl uses when you do not pass -n. `kubectl -n kube-system
//     get secrets` ignores it entirely. So "this project may only touch
//     namespace app" was, until now, a suggestion written on the honour
//     system.
//   - Read-only cannot be expressed in a kubeconfig at all. There is no field
//     for it. A kubeconfig carries a credential, and the credential's
//     authority is whatever the cluster's RBAC says — which the hub does not
//     control and often cannot narrow, because the kubeconfig a developer
//     uploads is frequently the one their own admin-grade user holds.
//
// Both need something that reads each request and decides. That something
// must live outside the sandbox, because anything inside it is advice to
// code that is under no obligation to take it. So: the hub holds the real
// credential, the sandbox gets a token worth only what the policy allows, and
// every request passes through a process the sandbox does not control.
//
// This is the same bargain pkg/gitproxy makes for git, and the packages are
// deliberately shaped alike.
//
// # This file
//
// apirequest.go turns an HTTP method and path into the tuple an authorization
// decision is actually about: verb, API group, resource, subresource,
// namespace, name. It is the security boundary of the package — everything
// policy.go decides, it decides about the output of this file — so it is a
// pure function over a method, a path and a query, with no I/O, and it is
// tested against the path shapes the real API server accepts rather than the
// ones kubectl happens to send.
//
// The parse deliberately mirrors the apiserver's own
// k8s.io/apiserver/pkg/endpoints/request.RequestInfoFactory. Not out of
// deference: if this package's idea of "which namespace is this request
// about" differs from the API server's by even one path shape, the difference
// *is* the vulnerability. A request the proxy reads as namespace "app" and
// the cluster reads as namespace "kube-system" is a bypass, and it would look
// like a working allowlist right up until it did not.
package kubeguard

import (
	"net/http"
	"net/url"
	"strings"
)

// Verb constants. These are RBAC's verbs, spelled the way RBAC spells them,
// because an operator writing an allowlist is going to copy it out of a Role
// they already have.
const (
	VerbGet              = "get"
	VerbList             = "list"
	VerbWatch            = "watch"
	VerbCreate           = "create"
	VerbUpdate           = "update"
	VerbPatch            = "patch"
	VerbDelete           = "delete"
	VerbDeleteCollection = "deletecollection"
)

// ReadVerbs are the verbs that only read. This is the definition of "read
// access" the task is about, and it is the package's default policy.
//
// It is exactly RBAC's read set. Notably absent is "deletecollection", which
// reads as a plural of something and is not.
var ReadVerbs = []string{VerbGet, VerbList, VerbWatch}

// namespaceSubresources are the path segments that follow a namespace name
// and belong to the namespace object itself rather than naming a nested
// resource. The API server hard-codes this same pair; anything else after
// /namespaces/<name>/ is a resource in its own right.
var namespaceSubresources = map[string]bool{"status": true, "finalize": true}

// dangerousSubresources are the subresources that carry a capability rather
// than data, and which therefore must never be reachable under a read policy
// regardless of the HTTP method used to ask for them.
//
// This map is the single most important eight lines in the package, because
// the obvious implementation is wrong in a way that looks right:
//
//	GET /api/v1/namespaces/app/pods/web-0/exec?command=sh
//
// A verb-only allowlist of {get, list, watch} admits that request — the method
// is GET and the request names a resource, so the verb is "get". The API
// server answers it by upgrading the connection to a websocket and giving the
// caller a shell inside the pod. "Read-only" would have meant remote code
// execution on the cluster.
//
// The same is true of attach (a shell on an existing process), portforward (a
// tunnel to anything the pod can reach, which on a cluster network is usually
// everything), and proxy (arbitrary requests to the kubelet or a Service,
// laundered through the API server's credential).
//
// So these are denied by subresource, ahead of the verb check, and a policy
// cannot opt back into them. An operator who genuinely wants a sandbox to
// exec into pods does not want this proxy in the path; they want a grant
// without it.
var dangerousSubresources = map[string]bool{
	"exec":        true,
	"attach":      true,
	"portforward": true,
	"proxy":       true,
}

// APIRequest is one request, reduced to what a decision is about.
//
// A request is either about a resource (IsResource true, and the fields below
// are populated) or about a non-resource path such as /version or /healthz
// (IsResource false, and Path carries it). RBAC makes the same split, for the
// same reason: there is no namespace or verb-set that means anything about
// /openapi/v2.
type APIRequest struct {
	// Verb is the RBAC verb this request performs.
	Verb string
	// APIGroup is "" for the core group ("/api/v1/..."), otherwise the group
	// name from "/apis/<group>/<version>/...".
	APIGroup string
	// APIVersion is the version segment.
	APIVersion string
	// Resource is the plural resource name ("pods", "deployments").
	Resource string
	// Subresource is the trailing segment when one is present ("log",
	// "status", "exec").
	Subresource string
	// Namespace is the namespace the request is about, empty for a
	// cluster-scoped request or a collection across all namespaces.
	Namespace string
	// Name is the object name, empty for a collection request.
	Name string
	// IsResource reports whether this is a resource request at all.
	IsResource bool
	// Path is the cleaned request path, always populated.
	Path string
	// Upgrade reports that the client asked to switch protocols
	// (SPDY or websocket). See policy.go for why that is refused.
	Upgrade bool
}

// ResourceString renders the resource the way RBAC writes it, for audit rows
// and refusal messages: "pods", "pods/log", "apps/deployments".
func (r APIRequest) ResourceString() string {
	if !r.IsResource {
		return r.Path
	}
	s := r.Resource
	if r.APIGroup != "" {
		s = r.APIGroup + "/" + s
	}
	if r.Subresource != "" {
		s += "/" + r.Subresource
	}
	return s
}

// String renders the request for a log line: "get pods/log in namespace app".
func (r APIRequest) String() string {
	if !r.IsResource {
		return r.Verb + " " + r.Path
	}
	s := r.Verb + " " + r.ResourceString()
	if r.Name != "" {
		s += " " + r.Name
	}
	if r.Namespace != "" {
		s += " in namespace " + r.Namespace
	} else {
		s += " across all namespaces"
	}
	return s
}

// ClusterScoped reports that the request names no namespace. That is true
// both of a genuinely cluster-scoped resource (nodes) and of a collection
// request spanning every namespace (/api/v1/pods) — which is exactly why
// policy.go treats the two the same: both reach outside any one namespace.
func (r APIRequest) ClusterScoped() bool { return r.IsResource && r.Namespace == "" }

// Dangerous reports that the request names a subresource that confers a
// capability rather than data.
func (r APIRequest) Dangerous() bool {
	return r.IsResource && dangerousSubresources[r.Subresource]
}

// Parse reduces an HTTP request to an APIRequest.
//
// It never fails: a path this function does not recognise as a resource
// request becomes a non-resource request, which policy.go evaluates against
// the non-resource allowlist and denies by default. Returning an error for an
// unparseable path would push the fail-closed decision onto every caller;
// making it a request nobody allowed keeps it here.
func Parse(r *http.Request) APIRequest {
	if r == nil {
		return APIRequest{Verb: "", Path: "/"}
	}
	return parse(r.Method, r.URL, r.Header)
}

// parse is the testable core of Parse.
func parse(method string, u *url.URL, h http.Header) APIRequest {
	path := "/"
	var query url.Values
	if u != nil {
		path = cleanPath(u.Path)
		query = u.Query()
	}

	out := APIRequest{Path: path, Upgrade: isUpgrade(h)}

	// Split into segments, discarding the empties that leading and trailing
	// slashes produce. "//api//v1//pods" and "/api/v1/pods" must not be
	// different requests to this parser when they are the same request to the
	// API server.
	parts := splitPath(path)
	if len(parts) < 3 {
		// "/", "/version", "/api", "/apis", "/api/v1" — discovery and health.
		// Too short to name a resource.
		out.Verb = nonResourceVerb(method)
		return out
	}

	// Establish the group and version, and position parts at the first
	// segment after them.
	switch parts[0] {
	case "api":
		// /api/<version>/...
		out.APIGroup = ""
		out.APIVersion = parts[1]
		parts = parts[2:]
	case "apis":
		// /apis/<group>/<version>/...
		if len(parts) < 4 {
			// "/apis/apps/v1" is group discovery, not a resource request.
			out.Verb = nonResourceVerb(method)
			return out
		}
		out.APIGroup = parts[1]
		out.APIVersion = parts[2]
		parts = parts[3:]
	default:
		// /healthz/etcd, /openapi/v2, /metrics, /logs/... — non-resource.
		out.Verb = nonResourceVerb(method)
		return out
	}

	if len(parts) == 0 {
		out.Verb = nonResourceVerb(method)
		return out
	}

	// Namespace handling, mirroring the API server exactly.
	//
	// "/api/v1/namespaces/app/pods/web-0" is a request about pods in app.
	// "/api/v1/namespaces/app" is a request about the *namespace object*
	// named app — resource "namespaces", name "app" — and the API server
	// *also* records the namespace as app, so a namespace allowlist covers
	// reading the namespace's own object. Both readings matter and they are
	// not in conflict.
	if parts[0] == "namespaces" {
		if len(parts) > 1 {
			out.Namespace = parts[1]
			if len(parts) > 2 && !namespaceSubresources[parts[2]] {
				// A nested resource: drop "namespaces/<name>" and carry on
				// parsing from the resource that follows.
				parts = parts[2:]
			}
			// Otherwise parts still begins with "namespaces", so the request
			// is read as being about the namespace object itself — including
			// "/api/v1/namespaces/app/status", whose subresource is picked up
			// by the generic handling below.
		}
		// A bare "/api/v1/namespaces" is a collection request across every
		// namespace, and Namespace stays empty, which is the honest reading.
	}

	out.IsResource = true
	out.Resource = parts[0]
	if len(parts) > 1 {
		out.Name = parts[1]
	}
	if len(parts) > 2 {
		// "/api/v1/namespaces/app/pods/web-0/log" and everything deeper.
		// Only the first segment is the subresource; the remainder is that
		// subresource's own path (as with nodes/<n>/proxy/<path>), and it
		// changes nothing about the decision — proxy is denied whatever
		// follows it.
		out.Subresource = parts[2]
	}

	out.Verb = resourceVerb(method, out.Name != "", query)
	return out
}

// resourceVerb maps an HTTP method onto an RBAC verb.
//
// The mapping is the API server's. Two cases are worth naming:
//
//   - GET without a name is "list", with a name is "get", and either becomes
//     "watch" when the query asks for one. Watch is a distinct verb in RBAC
//     and so it is distinct here; a policy that allows get and list but not
//     watch is a policy someone may reasonably write.
//   - DELETE without a name is "deletecollection", not "delete". Calling it
//     delete would let an allowlist that permits deleting one object permit
//     emptying a namespace.
func resourceVerb(method string, hasName bool, query url.Values) string {
	switch strings.ToUpper(method) {
	case http.MethodPost:
		return VerbCreate
	case http.MethodPut:
		return VerbUpdate
	case http.MethodPatch:
		return VerbPatch
	case http.MethodDelete:
		if hasName {
			return VerbDelete
		}
		return VerbDeleteCollection
	case http.MethodGet, http.MethodHead:
		if isWatch(query) {
			return VerbWatch
		}
		if hasName {
			return VerbGet
		}
		return VerbList
	default:
		// CONNECT, OPTIONS, TRACE and anything else. Named so the denial
		// message can say what it was rather than "".
		return strings.ToLower(method)
	}
}

// nonResourceVerb maps a method onto the lowercase verb RBAC uses for
// non-resource URLs ("get", "post", ...). RBAC spells these differently from
// resource verbs — nonResourceURLs rules are written with "get" and "post" —
// and the difference is preserved rather than smoothed over.
func nonResourceVerb(method string) string {
	m := strings.ToUpper(method)
	if m == http.MethodHead {
		return "get"
	}
	return strings.ToLower(m)
}

// isWatch reports whether the query asks for a watch.
//
// The API server accepts "watch=true", "watch=1" and a bare "watch", and
// treats anything else as false. Getting this wrong in the permissive
// direction would be harmless (a watch read as a list is still a read); in
// the restrictive direction it would let a policy that denies watch be
// satisfied by a request the cluster treats as a watch. So the check follows
// strconv.ParseBool, which is what the API server uses, plus the bare form.
func isWatch(query url.Values) bool {
	if query == nil {
		return false
	}
	if !query.Has("watch") {
		return false
	}
	switch strings.ToLower(query.Get("watch")) {
	case "", "1", "t", "true":
		return true
	}
	return false
}

// isUpgrade reports that the client asked to switch protocols.
//
// Checked on the Connection and Upgrade headers together, the way net/http
// and the API server both read it. A request carrying these is refused by
// policy.go rather than parsed further; see the comment there.
func isUpgrade(h http.Header) bool {
	if h == nil {
		return false
	}
	if strings.TrimSpace(h.Get("Upgrade")) != "" {
		return true
	}
	for _, v := range h.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
				return true
			}
		}
	}
	return false
}

// cleanPath normalises a request path without resolving it against a
// filesystem.
//
// It collapses repeated slashes and removes "." and ".." segments, so a path
// cannot be dressed up to read as one resource here and another at the API
// server. "/api/v1/namespaces/app/../kube-system/secrets" must not parse as
// namespace "app".
//
// url.URL.Path is already percent-decoded by net/url, so a "%2e%2e" arrives
// here as "..", which is the point at which it has to be handled.
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	hadTrailingSlash := strings.HasSuffix(p, "/")
	segs := splitPath(p)
	out := make([]string, 0, len(segs))
	for _, s := range segs {
		switch s {
		case ".":
			// No-op segment.
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, s)
		}
	}
	cleaned := "/" + strings.Join(out, "/")
	if hadTrailingSlash && len(out) > 0 {
		cleaned += "/"
	}
	return cleaned
}

// splitPath returns the non-empty segments of p.
func splitPath(p string) []string {
	raw := strings.Split(p, "/")
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
