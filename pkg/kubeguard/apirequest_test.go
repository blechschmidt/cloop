package kubeguard

// apirequest_test.go tests the parser against the path shapes the *API
// server* accepts, not the ones kubectl happens to send.
//
// That distinction is the point of the file. A sandbox is not obliged to use
// kubectl; it can issue any HTTP request it likes. So every case here that
// looks obscure — a doubled slash, a "..", a namespace object's own
// subresource, a GET to pods/exec — is a request some code could send on
// purpose, and the parser reading it differently from the API server would be
// the vulnerability rather than a cosmetic disagreement.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func mustParse(t *testing.T, method, target string) APIRequest {
	t.Helper()
	return Parse(httptest.NewRequest(method, target, nil))
}

func TestParseResourcePaths(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		target  string
		want    APIRequest
		wantStr string
	}{
		{
			name:   "core group collection across all namespaces",
			method: http.MethodGet, target: "/api/v1/pods",
			want: APIRequest{Verb: VerbList, APIVersion: "v1", Resource: "pods", IsResource: true},
		},
		{
			name:   "core group collection in a namespace",
			method: http.MethodGet, target: "/api/v1/namespaces/app/pods",
			want: APIRequest{Verb: VerbList, APIVersion: "v1", Resource: "pods",
				Namespace: "app", IsResource: true},
		},
		{
			name:   "core group named object",
			method: http.MethodGet, target: "/api/v1/namespaces/app/pods/web-0",
			want: APIRequest{Verb: VerbGet, APIVersion: "v1", Resource: "pods",
				Namespace: "app", Name: "web-0", IsResource: true},
		},
		{
			name:   "subresource",
			method: http.MethodGet, target: "/api/v1/namespaces/app/pods/web-0/log",
			want: APIRequest{Verb: VerbGet, APIVersion: "v1", Resource: "pods",
				Subresource: "log", Namespace: "app", Name: "web-0", IsResource: true},
		},
		{
			name:   "named api group",
			method: http.MethodGet, target: "/apis/apps/v1/namespaces/app/deployments/web",
			want: APIRequest{Verb: VerbGet, APIGroup: "apps", APIVersion: "v1",
				Resource: "deployments", Namespace: "app", Name: "web", IsResource: true},
		},
		{
			name:   "cluster scoped resource",
			method: http.MethodGet, target: "/api/v1/nodes/node-1",
			want: APIRequest{Verb: VerbGet, APIVersion: "v1", Resource: "nodes",
				Name: "node-1", IsResource: true},
		},
		{
			// The API server reads this as the namespace *object* named app,
			// and also records the namespace as app. Both readings matter:
			// the resource is "namespaces" so a resource allowlist sees it,
			// and the namespace is "app" so a namespace allowlist does too.
			name:   "the namespace object itself",
			method: http.MethodGet, target: "/api/v1/namespaces/app",
			want: APIRequest{Verb: VerbGet, APIVersion: "v1", Resource: "namespaces",
				Namespace: "app", Name: "app", IsResource: true},
		},
		{
			name:   "a namespace subresource stays on the namespace",
			method: http.MethodPut, target: "/api/v1/namespaces/app/status",
			want: APIRequest{Verb: VerbUpdate, APIVersion: "v1", Resource: "namespaces",
				Subresource: "status", Namespace: "app", Name: "app", IsResource: true},
		},
		{
			name:   "namespaces collection",
			method: http.MethodGet, target: "/api/v1/namespaces",
			want: APIRequest{Verb: VerbList, APIVersion: "v1", Resource: "namespaces",
				IsResource: true},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mustParse(t, tc.method, tc.target)
			got.Path, got.Upgrade = "", false // compared separately
			if got != tc.want {
				t.Errorf("Parse(%s %s)\n got %+v\nwant %+v", tc.method, tc.target, got, tc.want)
			}
		})
	}
}

// TestParseVerbMapping locks the method→verb table, including the two cases
// that are easy to get wrong and expensive when wrong.
func TestParseVerbMapping(t *testing.T) {
	tests := []struct {
		method, target, want string
	}{
		{http.MethodGet, "/api/v1/namespaces/app/pods", VerbList},
		{http.MethodGet, "/api/v1/namespaces/app/pods/web-0", VerbGet},
		{http.MethodHead, "/api/v1/namespaces/app/pods/web-0", VerbGet},
		{http.MethodPost, "/api/v1/namespaces/app/pods", VerbCreate},
		{http.MethodPut, "/api/v1/namespaces/app/pods/web-0", VerbUpdate},
		{http.MethodPatch, "/api/v1/namespaces/app/pods/web-0", VerbPatch},
		{http.MethodDelete, "/api/v1/namespaces/app/pods/web-0", VerbDelete},
		// DELETE without a name empties the collection. Reading it as
		// "delete" would let an allowlist that permits removing one object
		// permit emptying a namespace.
		{http.MethodDelete, "/api/v1/namespaces/app/pods", VerbDeleteCollection},
		// Watch is a distinct RBAC verb, so it is distinct here.
		{http.MethodGet, "/api/v1/namespaces/app/pods?watch=true", VerbWatch},
		{http.MethodGet, "/api/v1/namespaces/app/pods?watch=1", VerbWatch},
		{http.MethodGet, "/api/v1/namespaces/app/pods?watch", VerbWatch},
		{http.MethodGet, "/api/v1/namespaces/app/pods?watch=false", VerbList},
		{http.MethodGet, "/api/v1/namespaces/app/pods?watch=no", VerbList},
	}
	for _, tc := range tests {
		t.Run(tc.method+" "+tc.target, func(t *testing.T) {
			if got := mustParse(t, tc.method, tc.target).Verb; got != tc.want {
				t.Errorf("verb = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseNonResourcePaths(t *testing.T) {
	for _, target := range []string{
		"/", "/version", "/healthz", "/readyz", "/livez",
		"/api", "/apis", "/api/v1", "/apis/apps/v1",
		"/openapi/v2", "/openapi/v3/apis/apps/v1", "/metrics", "/logs/kube-apiserver.log",
	} {
		t.Run(target, func(t *testing.T) {
			got := mustParse(t, http.MethodGet, target)
			if got.IsResource {
				t.Errorf("Parse(%q).IsResource = true, want false (got %+v)", target, got)
			}
			if got.Verb != "get" {
				t.Errorf("Parse(%q).Verb = %q, want %q", target, got.Verb, "get")
			}
		})
	}
}

// TestParseNormalisesPathsThatWouldReadDifferentlyUpstream is the traversal
// case. url.URL.Path arrives percent-decoded, so "%2e%2e" is already ".." by
// the time the parser sees it — which is exactly where it has to be handled.
// A path the parser read as namespace "app" and the API server read as
// "kube-system" would be a bypass that looked like a working allowlist.
func TestParseNormalisesPathsThatWouldReadDifferentlyUpstream(t *testing.T) {
	tests := []struct {
		name, target  string
		wantNamespace string
		wantResource  string
	}{
		{"dot dot escape", "/api/v1/namespaces/app/../kube-system/secrets", "kube-system", "secrets"},
		{"encoded dot dot", "/api/v1/namespaces/app/%2e%2e/kube-system/secrets", "kube-system", "secrets"},
		{"single dot", "/api/v1/namespaces/./app/pods", "app", "pods"},
		{"doubled slashes", "/api//v1//namespaces//app//pods", "app", "pods"},
		{"leading doubled slash", "//api/v1/namespaces/app/pods", "app", "pods"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mustParse(t, http.MethodGet, tc.target)
			if got.Namespace != tc.wantNamespace {
				t.Errorf("namespace = %q, want %q (path %q -> %q)",
					got.Namespace, tc.wantNamespace, tc.target, got.Path)
			}
			if got.Resource != tc.wantResource {
				t.Errorf("resource = %q, want %q", got.Resource, tc.wantResource)
			}
		})
	}
}

// TestParseMarksDangerousSubresources is the check the whole package turns
// on. A verb-only allowlist admits "GET .../pods/web-0/exec" as an ordinary
// read; the API server answers it with a shell.
func TestParseMarksDangerousSubresources(t *testing.T) {
	for _, sub := range []string{"exec", "attach", "portforward", "proxy"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			t.Run(method+" "+sub, func(t *testing.T) {
				r := mustParse(t, method, "/api/v1/namespaces/app/pods/web-0/"+sub)
				if !r.Dangerous() {
					t.Fatalf("%s pods/%s not marked dangerous: %+v", method, sub, r)
				}
			})
		}
	}
	// A deeper path under proxy is still proxy: nodes/<n>/proxy/<anything>
	// reaches the kubelet API, and only the first segment decides.
	r := mustParse(t, http.MethodGet, "/api/v1/nodes/node-1/proxy/run/cmd")
	if !r.Dangerous() {
		t.Errorf("nodes/proxy/... not marked dangerous: %+v", r)
	}
	// And an ordinary subresource is not.
	if mustParse(t, http.MethodGet, "/api/v1/namespaces/app/pods/web-0/log").Dangerous() {
		t.Error("pods/log marked dangerous")
	}
}

func TestParseDetectsUpgrade(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		{"none", nil, false},
		{"upgrade header", map[string]string{"Upgrade": "websocket"}, true},
		{"connection token", map[string]string{"Connection": "Upgrade"}, true},
		{"connection token among others", map[string]string{"Connection": "keep-alive, Upgrade"}, true},
		{"connection lowercase", map[string]string{"Connection": "upgrade"}, true},
		{"spdy", map[string]string{"Upgrade": "SPDY/3.1"}, true},
		{"ordinary keep-alive", map[string]string{"Connection": "keep-alive"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/app/pods", nil)
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			if got := Parse(r).Upgrade; got != tc.want {
				t.Errorf("Upgrade = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAPIRequestResourceString(t *testing.T) {
	tests := []struct{ target, want string }{
		{"/api/v1/namespaces/app/pods", "pods"},
		{"/api/v1/namespaces/app/pods/web-0/log", "pods/log"},
		{"/apis/apps/v1/namespaces/app/deployments/web", "apps/deployments"},
		{"/apis/apps/v1/namespaces/app/deployments/web/scale", "apps/deployments/scale"},
		{"/version", "/version"},
	}
	for _, tc := range tests {
		t.Run(tc.target, func(t *testing.T) {
			if got := mustParse(t, http.MethodGet, tc.target).ResourceString(); got != tc.want {
				t.Errorf("ResourceString() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClusterScopedReportsCollectionsSpanningEveryNamespace(t *testing.T) {
	// The request `kubectl get pods --all-namespaces` sends. It names no
	// namespace and reads every one, which is why ClusterScoped covers it.
	if !mustParse(t, http.MethodGet, "/api/v1/pods").ClusterScoped() {
		t.Error("/api/v1/pods is not reported as cluster-scoped")
	}
	if mustParse(t, http.MethodGet, "/api/v1/namespaces/app/pods").ClusterScoped() {
		t.Error("a namespaced collection is reported as cluster-scoped")
	}
}

func TestParseNilRequestDoesNotPanic(t *testing.T) {
	if got := Parse(nil); got.IsResource {
		t.Errorf("Parse(nil) = %+v, want a non-resource request", got)
	}
}
