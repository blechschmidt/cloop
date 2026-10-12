package imagepolicy

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// fakeRegistry is a registry with a token service, speaking the manifest
// endpoint and nothing else.
type fakeRegistry struct {
	t   *testing.T
	srv *httptest.Server

	// digest is what HEAD answers in Docker-Content-Digest; empty leaves the
	// header out, as some registries do.
	digest string
	// manifest is what GET serves.
	manifest []byte
	// bearer makes the manifest endpoint demand a token from /token; basic
	// makes it demand Basic credentials instead.
	bearer bool
	basic  bool
	// login is the credential the token service or the Basic challenge
	// accepts; empty accepts anonymous token requests.
	login RegistryCredential
	// challengeScope is the scope the 401 asks for.
	challengeScope string
	// realm overrides the token service the challenge names.
	realm string

	mu          sync.Mutex
	tokenScopes []string
	methods     []string
}

const fakeToken = "registry-test-pull-token"

func newFakeRegistry(t *testing.T, configure func(*fakeRegistry)) *fakeRegistry {
	t.Helper()
	f := &fakeRegistry{t: t, digest: goodDigest, manifest: []byte(`{"schemaVersion":2}`)}
	if configure != nil {
		configure(f)
	}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// host is the registry as a reference names it.
func (f *fakeRegistry) host() string { return strings.TrimPrefix(f.srv.URL, "https://") }

// seen returns the token scopes and manifest methods requested so far.
func (f *fakeRegistry) seen() (scopes, methods []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.tokenScopes...), append([]string(nil), f.methods...)
}

func (f *fakeRegistry) resolver() *RegistryResolver {
	return &RegistryResolver{
		Client:      f.srv.Client(),
		Credentials: func(string) (RegistryCredential, bool) { return RegistryCredential{}, false },
	}
}

func (f *fakeRegistry) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/token" {
		f.mu.Lock()
		f.tokenScopes = append(f.tokenScopes, r.URL.Query().Get("scope"))
		f.mu.Unlock()
		if f.login.Username != "" {
			user, pass, ok := r.BasicAuth()
			if !ok || user != f.login.Username || pass != f.login.Password {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		_, _ = fmt.Fprintf(w, `{"token":%q}`, fakeToken)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/v2/acme/tools/manifests/") {
		http.NotFound(w, r)
		return
	}
	f.mu.Lock()
	f.methods = append(f.methods, r.Method)
	f.mu.Unlock()
	if !strings.Contains(r.Header.Get("Accept"), "application/vnd.oci.image.index.v1+json") {
		f.t.Errorf("manifest request accepts %q, which leaves out the index type", r.Header.Get("Accept"))
	}
	switch {
	case f.bearer && r.Header.Get("Authorization") != "Bearer "+fakeToken:
		realm := f.realm
		if realm == "" {
			realm = f.srv.URL + "/token"
		}
		w.Header().Set("Www-Authenticate", fmt.Sprintf(`Bearer realm=%q,service="fake-registry",scope=%q`,
			realm, f.challengeScope))
		w.WriteHeader(http.StatusUnauthorized)
		return
	case f.basic:
		user, pass, ok := r.BasicAuth()
		if !ok || user != f.login.Username || pass != f.login.Password {
			w.Header().Set("Www-Authenticate", `Basic realm="fake-registry"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	if strings.HasSuffix(r.URL.Path, "/manifests/missing") {
		http.NotFound(w, r)
		return
	}
	if f.digest != "" {
		w.Header().Set("Docker-Content-Digest", f.digest)
	}
	w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
	if r.Method == http.MethodGet {
		_, _ = w.Write(f.manifest)
	}
}

// TestRegistryResolverResolvesATagThroughATokenService is the ordinary public
// registry: an anonymous 401, a pull token from the service it names, and the
// digest in the HEAD's Docker-Content-Digest.
//
// The token is asked for this repository's pull and nothing else, whatever the
// challenge asked for: a resolution reads one manifest.
func TestRegistryResolverResolvesATagThroughATokenService(t *testing.T) {
	reg := newFakeRegistry(t, func(f *fakeRegistry) {
		f.bearer = true
		f.challengeScope = "repository:acme/tools:pull,push"
	})
	got, err := reg.resolver().ResolveDigest(context.Background(), reg.host()+"/acme/tools:3.12")
	if err != nil {
		t.Fatalf("ResolveDigest: %v", err)
	}
	if got != goodDigest {
		t.Fatalf("digest = %q, want %q", got, goodDigest)
	}
	scopes, methods := reg.seen()
	if len(scopes) != 1 || scopes[0] != "repository:acme/tools:pull" {
		t.Errorf("token scopes requested = %q, want only this repository's pull", scopes)
	}
	if strings.Join(methods, ",") != "HEAD,HEAD" {
		t.Errorf("manifest requests = %v, want an anonymous HEAD and one with the token", methods)
	}
}

// TestRegistryResolverHashesTheManifestWhenHeadCarriesNoDigest: some
// registries answer HEAD without the digest header. The digest is then the
// hash of the manifest served, which is what a pull by that digest is checked
// against.
func TestRegistryResolverHashesTheManifestWhenHeadCarriesNoDigest(t *testing.T) {
	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)
	reg := newFakeRegistry(t, func(f *fakeRegistry) {
		f.digest = ""
		f.manifest = manifest
	})
	got, err := reg.resolver().ResolveDigest(context.Background(), reg.host()+"/acme/tools:3.12")
	if err != nil {
		t.Fatalf("ResolveDigest: %v", err)
	}
	sum := sha256.Sum256(manifest)
	if want := "sha256:" + hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("digest = %q, want the hash of the served manifest %q", got, want)
	}
}

// TestRegistryResolverUsesTheHostsLogin: a private repository answers with the
// login this host holds for it — at the token service, or as Basic — and
// refuses without one, naming where a login would come from.
func TestRegistryResolverUsesTheHostsLogin(t *testing.T) {
	login := RegistryCredential{Username: "robot", Password: "registry-test-password"}
	for _, scheme := range []string{"bearer", "basic"} {
		t.Run(scheme, func(t *testing.T) {
			reg := newFakeRegistry(t, func(f *fakeRegistry) {
				f.bearer, f.basic = scheme == "bearer", scheme == "basic"
				f.login = login
			})
			r := reg.resolver()
			ref := reg.host() + "/acme/tools:3.12"

			_, err := r.ResolveDigest(context.Background(), ref)
			if !errors.Is(err, ErrRegistry) || !strings.Contains(err.Error(), "docker login") {
				t.Fatalf("without a login: %v, want a registry refusal naming where a login comes from", err)
			}

			r.Credentials = func(registry string) (RegistryCredential, bool) {
				if registry != reg.host() {
					t.Errorf("login asked for %q, want the reference's registry %q", registry, reg.host())
				}
				return login, true
			}
			got, err := r.ResolveDigest(context.Background(), ref)
			if err != nil || got != goodDigest {
				t.Fatalf("with the login: %q, %v; want %q", got, err, goodDigest)
			}
		})
	}
}

// TestRegistryResolverRefusesWhatItCannotTrust: every way the answer can be
// missing or unusable is an ErrRegistry naming the registry — never a digest,
// and never a password sent somewhere it would travel in the clear.
func TestRegistryResolverRefusesWhatItCannotTrust(t *testing.T) {
	t.Run("unknown tag", func(t *testing.T) {
		reg := newFakeRegistry(t, nil)
		_, err := reg.resolver().ResolveDigest(context.Background(), reg.host()+"/acme/tools:missing")
		if !errors.Is(err, ErrRegistry) || !strings.Contains(err.Error(), "no manifest") {
			t.Fatalf("err = %v, want ErrRegistry saying the tag is unknown", err)
		}
	})
	t.Run("unreachable registry", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		host := l.Addr().String()
		_ = l.Close()
		r := &RegistryResolver{Credentials: func(string) (RegistryCredential, bool) { return RegistryCredential{}, false }}
		_, err = r.ResolveDigest(context.Background(), host+"/acme/tools:3.12")
		if !errors.Is(err, ErrRegistry) || !strings.Contains(err.Error(), "unreachable") {
			t.Fatalf("err = %v, want ErrRegistry saying the registry is unreachable", err)
		}
	})
	t.Run("not a digest", func(t *testing.T) {
		reg := newFakeRegistry(t, func(f *fakeRegistry) { f.digest = "sha256:NOTHEX" })
		_, err := reg.resolver().ResolveDigest(context.Background(), reg.host()+"/acme/tools:3.12")
		if !errors.Is(err, ErrRegistry) || !strings.Contains(err.Error(), "not a digest") {
			t.Fatalf("err = %v, want ErrRegistry refusing the answer", err)
		}
	})
	t.Run("plain-HTTP token service", func(t *testing.T) {
		var asked atomic.Bool
		elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { asked.Store(true) }))
		defer elsewhere.Close()
		// Its loopback address under a name that is not one, as a token
		// service on another machine would be named.
		u, _ := url.Parse(elsewhere.URL)
		u.Host = "token.example.test:" + u.Port()
		reg := newFakeRegistry(t, func(f *fakeRegistry) {
			f.bearer = true
			f.realm = u.String() + "/token"
		})
		r := reg.resolver()
		r.Credentials = func(string) (RegistryCredential, bool) {
			return RegistryCredential{Username: "robot", Password: "must-not-travel"}, true
		}
		_, err := r.ResolveDigest(context.Background(), reg.host()+"/acme/tools:3.12")
		if !errors.Is(err, ErrRegistry) || !strings.Contains(err.Error(), "plain HTTP") {
			t.Fatalf("err = %v, want a refusal of the plain-HTTP token service", err)
		}
		if asked.Load() {
			t.Fatal("the login was offered to a token service over plain HTTP")
		}
	})
	t.Run("no registry", func(t *testing.T) {
		_, err := NewRegistryResolver().ResolveDigest(context.Background(), "alpine:3.20")
		if !errors.Is(err, ErrRegistry) {
			t.Fatalf("err = %v, want ErrRegistry for a reference naming no registry", err)
		}
	})
}

// TestRegistryResolverDoesNotResolveAPinnedReference: a digest names itself.
// Asking a registry about it would only add a way for the answer to differ.
func TestRegistryResolverDoesNotResolveAPinnedReference(t *testing.T) {
	r := &RegistryResolver{Client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("a pinned reference was sent to a registry")
		return nil, nil
	})}}
	got, err := r.ResolveDigest(context.Background(), "ghcr.io/acme/tools@"+goodDigest)
	if err != nil || got != goodDigest {
		t.Fatalf("ResolveDigest = %q, %v; want the reference's own digest", got, err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestDockerConfigCredential reads the logins cosign's keychain would use, in
// its order, under every spelling a Docker Hub key comes in.
func TestDockerConfigCredential(t *testing.T) {
	dir := t.TempDir()
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	write(filepath.Join(dir, "docker", "config.json"), `{"auths":{
		"https://index.docker.io/v1/": {"auth": "`+enc("hubuser:hubpass")+`"},
		"https://GHCR.io": {"username": "ghuser", "password": "ghpass"},
		"broken.example": {"auth": "not base64!"}
	}, "credsStore": "desktop"}`)
	write(filepath.Join(dir, "podman", "auth.json"), `{"auths":{"quay.io":{"auth":"`+enc("quser:qpass")+`"}}}`)
	t.Setenv("DOCKER_CONFIG", filepath.Join(dir, "docker"))
	t.Setenv("REGISTRY_AUTH_FILE", filepath.Join(dir, "podman", "auth.json"))
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "none"))

	for registry, want := range map[string]RegistryCredential{
		"docker.io": {Username: "hubuser", Password: "hubpass"},
		"ghcr.io":   {Username: "ghuser", Password: "ghpass"},
		"quay.io":   {Username: "quser", Password: "qpass"},
	} {
		got, ok := DockerConfigCredential(registry)
		if !ok || got != want {
			t.Errorf("DockerConfigCredential(%q) = %+v, %v; want %+v", registry, got, ok, want)
		}
	}
	for _, registry := range []string{"broken.example", "registry.example"} {
		if got, ok := DockerConfigCredential(registry); ok {
			t.Errorf("DockerConfigCredential(%q) = %+v; want no login", registry, got)
		}
	}
}

// TestParseChallenge reads the WWW-Authenticate values registries send,
// including a quoted value with a comma in it.
func TestParseChallenge(t *testing.T) {
	scheme, params := parseChallenge(`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",` +
		`scope="repository:library/alpine:pull,push"`)
	if scheme != "Bearer" || params["realm"] != "https://auth.docker.io/token" ||
		params["service"] != "registry.docker.io" || params["scope"] != "repository:library/alpine:pull,push" {
		t.Fatalf("parseChallenge = %q %v", scheme, params)
	}
	if scheme, params := parseChallenge(`Basic realm="a \"quoted\" realm"`); scheme != "Basic" ||
		params["realm"] != `a "quoted" realm` {
		t.Fatalf("parseChallenge(Basic) = %q %v", scheme, params)
	}
}
