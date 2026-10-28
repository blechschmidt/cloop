// Package registrytest is a container registry for tests: the distribution
// API's manifest endpoint behind a bearer-token service, over TLS, holding
// manifests and image indexes under tags a test can repoint (Task 20457).
//
// It serves what a resolution reads and nothing else — no blobs, no push API —
// and records what it was asked, so a test can assert which login reached which
// registry and which method fetched which reference.
package registrytest

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Media types a registry serves a manifest under.
const (
	MediaOCIIndex          = "application/vnd.oci.image.index.v1+json"
	MediaOCIManifest       = "application/vnd.oci.image.manifest.v1+json"
	MediaDockerList        = "application/vnd.docker.distribution.manifest.list.v2+json"
	MediaDockerManifest    = "application/vnd.docker.distribution.manifest.v2+json"
	tokenPath              = "/token"
	tokenPrefix            = "registrytest-token-"
	challengeService       = "registrytest"
	unknownManifestMessage = `{"errors":[{"code":"MANIFEST_UNKNOWN","message":"manifest unknown"}]}`
)

// Login is a username and password the token service accepts.
type Login struct {
	Username string
	Password string
}

// Request is one request the registry answered.
type Request struct {
	Method string
	Path   string
	// Basic is the username of the Basic credential the request carried, at
	// the token service; empty for an anonymous one.
	Basic string
	// Bearer reports that a manifest request carried a token.
	Bearer bool
	// Scope is the token request's scope.
	Scope string
}

// Registry is a registry. Create one with New.
type Registry struct {
	t   testing.TB
	srv *httptest.Server

	mu        sync.Mutex
	manifests map[string]manifest          // by digest
	tags      map[string]map[string]string // repository → tag → digest
	private   map[string]bool              // repositories that need Login
	login     *Login
	noDigest  bool
	requests  []Request
}

type manifest struct {
	mediaType string
	body      []byte
}

// New starts a registry on 127.0.0.1 over TLS, closed when the test ends.
func New(t testing.TB) *Registry {
	t.Helper()
	r := &Registry{
		t:         t,
		manifests: map[string]manifest{},
		tags:      map[string]map[string]string{},
		private:   map[string]bool{},
	}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.srv.Close)
	return r
}

// Host is the registry as an image reference names it: "127.0.0.1:<port>".
func (r *Registry) Host() string { return strings.TrimPrefix(r.srv.URL, "https://") }

// URL is the registry's base URL.
func (r *Registry) URL() string { return r.srv.URL }

// Client trusts the registry's certificate.
func (r *Registry) Client() *http.Client { return r.srv.Client() }

// Close stops the registry: every request after it fails to connect, as an
// unreachable registry does.
func (r *Registry) Close() { r.srv.Close() }

// RequireLogin makes repository private: its token service grants a pull only
// to login.
func (r *Registry) RequireLogin(repository string, login Login) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.private[repository] = true
	r.login = &login
}

// OmitDigestHeader makes manifest responses carry no Docker-Content-Digest, as
// some registries' HEAD does; the digest is then the hash of what GET serves.
func (r *Registry) OmitDigestHeader() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.noDigest = true
}

// PushManifest stores an image manifest for one platform under tag, its
// content made distinct by marker, and returns its digest.
func (r *Registry) PushManifest(repository, tag, mediaType, marker string) string {
	body, _ := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     mediaType,
		"config": map[string]any{
			"mediaType": "application/vnd.oci.image.config.v1+json",
			"digest":    digestOf([]byte("config " + marker)),
			"size":      len("config " + marker),
		},
		"layers":      []any{},
		"annotations": map[string]string{"org.cloop.test.marker": marker},
	})
	return r.Push(repository, tag, mediaType, body)
}

// PushIndex stores an image index over the given manifest digests under tag,
// and returns its digest: the one a multi-platform tag names.
func (r *Registry) PushIndex(repository, tag, mediaType string, platforms ...string) string {
	var entries []any
	for _, d := range platforms {
		entries = append(entries, map[string]any{
			"mediaType": MediaOCIManifest,
			"digest":    d,
			"size":      1,
			"platform":  map[string]string{"os": "linux", "architecture": "amd64"},
		})
	}
	body, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": mediaType, "manifests": entries})
	return r.Push(repository, tag, mediaType, body)
}

// Push stores body under tag — repointing the tag if it names something else
// already — and returns the digest of body.
func (r *Registry) Push(repository, tag, mediaType string, body []byte) string {
	d := digestOf(body)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.manifests[d] = manifest{mediaType: mediaType, body: append([]byte(nil), body...)}
	if r.tags[repository] == nil {
		r.tags[repository] = map[string]string{}
	}
	if tag != "" {
		r.tags[repository][tag] = d
	}
	return d
}

// Requests returns what the registry has answered so far.
func (r *Registry) Requests() []Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Request(nil), r.requests...)
}

// ManifestRequests returns the methods of the manifest requests answered so far.
func (r *Registry) ManifestRequests() []string {
	var out []string
	for _, q := range r.Requests() {
		if strings.Contains(q.Path, "/manifests/") {
			out = append(out, q.Method)
		}
	}
	return out
}

func (r *Registry) record(q Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, q)
}

func (r *Registry) serve(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == tokenPath {
		r.serveToken(w, req)
		return
	}
	rest, ok := strings.CutPrefix(req.URL.Path, "/v2/")
	if !ok {
		http.NotFound(w, req)
		return
	}
	i := strings.LastIndex(rest, "/manifests/")
	if i < 0 {
		r.record(Request{Method: req.Method, Path: req.URL.Path})
		w.WriteHeader(http.StatusOK)
		return
	}
	repository, reference := rest[:i], rest[i+len("/manifests/"):]
	auth := req.Header.Get("Authorization")
	r.record(Request{Method: req.Method, Path: req.URL.Path, Bearer: strings.HasPrefix(auth, "Bearer ")})

	if !r.authorized(auth, repository) {
		w.Header().Set("Www-Authenticate", fmt.Sprintf(`Bearer realm=%q,service=%q,scope="repository:%s:pull"`,
			r.srv.URL+tokenPath, challengeService, repository))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	r.mu.Lock()
	d := reference
	if !strings.HasPrefix(reference, "sha256:") {
		d = r.tags[repository][reference]
	}
	m, found := r.manifests[d]
	noDigest := r.noDigest
	r.mu.Unlock()
	if !found {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(unknownManifestMessage))
		return
	}
	if !strings.Contains(req.Header.Get("Accept"), m.mediaType) {
		// A registry that cannot serve the stored type in one the client
		// accepts says it has no such manifest.
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", m.mediaType)
	if !noDigest {
		w.Header().Set("Docker-Content-Digest", d)
	}
	w.Header().Set("Content-Length", fmt.Sprint(len(m.body)))
	if req.Method == http.MethodGet {
		_, _ = w.Write(m.body)
	}
}

// authorized reports whether a manifest request carries a token the token
// service issued for repository — every repository needs one, as on a public
// registry, where the token is anonymous.
func (r *Registry) authorized(auth, repository string) bool {
	token, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok {
		return false
	}
	return equal(token, tokenPrefix+repository)
}

// equal compares two credentials in constant time, as anything that checks
// one in this repository does.
func equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// serveToken issues a pull token for the scope asked, to anyone for a public
// repository and to the login for a private one.
func (r *Registry) serveToken(w http.ResponseWriter, req *http.Request) {
	scope := req.URL.Query().Get("scope")
	user, pass, hasBasic := req.BasicAuth()
	q := Request{Method: req.Method, Path: req.URL.Path, Scope: scope}
	if hasBasic {
		q.Basic = user
	}
	r.record(q)

	repository, ok := strings.CutPrefix(scope, "repository:")
	if !ok || !strings.HasSuffix(repository, ":pull") {
		http.Error(w, "unsupported scope", http.StatusBadRequest)
		return
	}
	repository = strings.TrimSuffix(repository, ":pull")
	r.mu.Lock()
	private, login := r.private[repository], r.login
	r.mu.Unlock()
	if private && (!hasBasic || login == nil || !equal(user, login.Username) || !equal(pass, login.Password)) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"token": tokenPrefix + repository})
}

// DockerConfig renders login as the config.json `docker login` writes for the
// registry at host.
func DockerConfig(host string, login Login) []byte {
	b, _ := json.Marshal(map[string]any{"auths": map[string]any{
		host: map[string]string{"username": login.Username, "password": login.Password},
	}})
	return b
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
