package imagepolicy

// registrylogins_test.go: the logins a Kubernetes executor resolves tags with,
// and what a registry it asks may make this host do (Task 20457).

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// TestParseDockerConfigReadsEachLoginForItsOwnRegistry: both spellings of an
// "auths" entry, under every spelling of its key, each found for its registry
// alone — Docker Hub's aliases fold into its one login.
func TestParseDockerConfigReadsEachLoginForItsOwnRegistry(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte("hubuser:hub-pass"))
	logins, err := ParseDockerConfig([]byte(`{"auths":{
		"https://index.docker.io/v1/": {"auth": "` + enc + `"},
		"https://GHCR.io/": {"username": "robot", "password": "ghcr-pass"},
		"registry.internal:5000": {"username": "ci", "password": "internal-pass"}}}`))
	if err != nil {
		t.Fatalf("ParseDockerConfig: %v", err)
	}
	for registry, want := range map[string]RegistryCredential{
		"docker.io":              {Username: "hubuser", Password: "hub-pass"},
		"registry-1.docker.io":   {Username: "hubuser", Password: "hub-pass"},
		"ghcr.io":                {Username: "robot", Password: "ghcr-pass"},
		"registry.internal:5000": {Username: "ci", Password: "internal-pass"},
	} {
		if got, ok := logins.Login(registry); !ok || got != want {
			t.Errorf("Login(%s) = %+v, %t; want %+v", registry, got, ok, want)
		}
	}
	for _, other := range []string{"quay.io", "registry.internal", "registry.internal:5001", "ghcr.io.evil.example", ""} {
		if _, ok := logins.Login(other); ok {
			t.Errorf("Login(%q) found a login it was not stored for", other)
		}
	}
	if got := strings.Join(logins.Registries(), ","); got != "docker.io,ghcr.io,registry.internal:5000" {
		t.Errorf("Registries() = %s", got)
	}
}

// TestParseDockerConfigRefusesWhatIsNotALoginSet without quoting the secret:
// every error names a key at most, never a value.
func TestParseDockerConfigRefusesWhatIsNotALoginSet(t *testing.T) {
	const secret = "s3cret-value-never-echoed"
	for name, in := range map[string]string{
		"user:password":        "robot:" + secret,
		"not json":             "{" + secret,
		"no auths":             `{"credsStore":"` + secret + `"}`,
		"empty auths":          `{"auths":{}}`,
		"undecodable auth":     `{"auths":{"ghcr.io":{"auth":"` + secret + `!!"}}}`,
		"password, no user":    `{"auths":{"ghcr.io":{"password":"` + secret + `"}}}`,
		"two logins, one host": `{"auths":{"ghcr.io":{"username":"a","password":"` + secret + `"},"https://ghcr.io/":{"username":"b","password":"x"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseDockerConfig([]byte(in))
			if err == nil {
				t.Fatal("accepted")
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("the error quotes the secret: %v", err)
			}
		})
	}
}

// TestRegistryRedirectsAreFollowedOverHTTPSOnly: a registry elsewhere may not
// bounce this host to a plain-HTTP address of its choosing — the hub's own
// loopback services, a metadata endpoint — and a resolution follows a few hops
// at most. Plain HTTP stays possible within this host's loopback, for a
// registry it serves itself.
func TestRegistryRedirectsAreFollowedOverHTTPSOnly(t *testing.T) {
	req := func(raw string) *http.Request {
		u, _ := url.Parse(raw)
		return &http.Request{URL: u}
	}
	for _, c := range []struct {
		next string
		via  []string
		ok   bool
	}{
		{"https://cdn.example/manifest", []string{"https://registry.example/v2/x"}, true},
		{"http://127.0.0.1:8080/api/admin", []string{"https://registry.example/v2/x"}, false},
		{"http://169.254.169.254/latest/meta-data/", []string{"https://registry.example/v2/x"}, false},
		{"http://localhost:5001/v2/x", []string{"http://localhost:5000/v2/x"}, true},
		{"http://10.0.0.5/v2/x", []string{"http://127.0.0.1:5000/v2/x"}, false},
		{"https://e.example/4", []string{"https://e.example/1", "https://e.example/2", "https://e.example/3"}, false},
	} {
		via := make([]*http.Request, 0, len(c.via))
		for _, v := range c.via {
			via = append(via, req(v))
		}
		if err := checkRegistryRedirect(req(c.next), via); (err == nil) != c.ok {
			t.Errorf("redirect to %s after %v: %v, want allowed=%t", c.next, c.via, err, c.ok)
		}
	}

	// And it holds on a client the caller configured.
	var reached atomic.Bool
	plain := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Store(true) }))
	defer plain.Close()
	bouncer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/v2/acme/tools/manifests/1", http.StatusTemporaryRedirect)
	}))
	defer bouncer.Close()
	r := &RegistryResolver{Client: bouncer.Client(),
		Credentials: func(string) (RegistryCredential, bool) { return RegistryCredential{}, false }}
	_, err := r.ResolveDigest(context.Background(), strings.TrimPrefix(bouncer.URL, "https://")+"/acme/tools:1")
	if !errors.Is(err, ErrRegistry) || !strings.Contains(err.Error(), "refused a redirect") {
		t.Fatalf("a redirect to plain HTTP: %v, want it refused", err)
	}
	if reached.Load() {
		t.Fatal("the plain-HTTP target of the redirect was fetched")
	}
}

// TestATokenServiceOnThisHostIsForARegistryOnThisHost: a registry elsewhere
// that names a token service on the hub's own loopback is asking the hub to
// read one of its local services and present the answer back as a token. Only a
// registry on this host may.
func TestATokenServiceOnThisHostIsForARegistryOnThisHost(t *testing.T) {
	realm := func(raw string) *url.URL { u, _ := url.Parse(raw); return u }
	for _, c := range []struct {
		manifest, realm string
		ok              bool
	}{
		{"https://registry.example/v2/x/manifests/1", "https://auth.example/token", true},
		{"https://registry.example/v2/x/manifests/1", "https://127.0.0.1:8443/token", false},
		{"https://registry.example/v2/x/manifests/1", "http://localhost:8080/api", false},
		{"https://registry.example/v2/x/manifests/1", "https://[::1]:9000/token", false},
		{"https://127.0.0.1:5000/v2/x/manifests/1", "https://127.0.0.1:5001/token", true},
		{"https://localhost:5000/v2/x/manifests/1", "http://localhost:5001/token", true},
	} {
		if got := realmAllowed(c.manifest, realm(c.realm)); got != c.ok {
			t.Errorf("registry %s naming %s: allowed=%t, want %t", c.manifest, c.realm, got, c.ok)
		}
	}

	// Through a resolution: a registry known by a name that is not this
	// host's, answering from this host only because the test dials it here,
	// whose challenge names a token service on 127.0.0.1.
	var tokenAsked atomic.Bool
	var port string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			tokenAsked.Store(true)
			_, _ = w.Write([]byte(`{"token":"t"}`))
			return
		}
		w.Header().Set("Www-Authenticate", `Bearer realm="https://127.0.0.1:`+port+`/token"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()
	_, port, _ = strings.Cut(addr, ":")
	transport := srv.Client().Transport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	transport.TLSClientConfig.ServerName = "example.com"
	r := &RegistryResolver{Client: &http.Client{Transport: transport},
		Credentials: func(string) (RegistryCredential, bool) { return RegistryCredential{}, false }}
	_, err := r.ResolveDigest(context.Background(), "registry.example.test:"+port+"/acme/tools:1")
	if !errors.Is(err, ErrRegistry) || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("a registry elsewhere naming a loopback token service: %v, want it refused", err)
	}
	if tokenAsked.Load() {
		t.Fatal("the loopback token service was asked")
	}
}

// TestCosignIsHandedTheLoginForItsImagesRegistryAlone: a verification under a
// context carrying logins runs cosign with DOCKER_CONFIG naming a private copy
// of the one login for the image's registry, removed when it ends; without one
// for that registry, cosign keeps its own environment.
func TestCosignIsHandedTheLoginForItsImagesRegistryAlone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the cosign stand-in is a POSIX shell script")
	}
	dir := t.TempDir()
	seen := filepath.Join(dir, "seen")
	bin := filepath.Join(dir, "cosign")
	script := "#!/bin/sh\nif [ -n \"$DOCKER_CONFIG\" ]; then echo \"$DOCKER_CONFIG\" > '" + seen + ".dir'; " +
		"cat \"$DOCKER_CONFIG/config.json\" > '" + seen + "'; ls -ld \"$DOCKER_CONFIG\" > '" + seen + ".mode'; " +
		"else echo none > '" + seen + "'; fi\nexit 0\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_CONFIG", "")
	logins, err := ParseDockerConfig([]byte(`{"auths":{"ghcr.io":{"username":"robot","password":"ghcr-pass"},` +
		`"quay.io":{"username":"other","password":"quay-pass"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{RequireSignature: true, CosignPublicKeys: []string{"/k.pub"}}
	ctx := WithRegistryLogins(context.Background(), logins)

	v := &CosignVerifier{Binary: bin}
	if err := v.Verify(ctx, "ghcr.io/acme/tools@"+goodDigest, policy); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	cfg, _ := os.ReadFile(seen)
	got, err := ParseDockerConfig(cfg)
	if err != nil || strings.Join(got.Registries(), ",") != "ghcr.io" || strings.Contains(string(cfg), "quay-pass") {
		t.Fatalf("cosign saw %s (%v), want the ghcr.io login alone", cfg, err)
	}
	if mode, _ := os.ReadFile(seen + ".mode"); !strings.HasPrefix(string(mode), "drwx------") {
		t.Errorf("the login's directory is %q, want it private to the hub", mode)
	}
	if d, _ := os.ReadFile(seen + ".dir"); len(d) == 0 {
		t.Fatal("no directory recorded")
	} else if _, err := os.Stat(strings.TrimSpace(string(d))); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the staged login outlived the verification: %v", err)
	}

	// No login for this image's registry: nothing staged.
	if err := (&CosignVerifier{Binary: bin}).Verify(ctx, "docker.io/library/alpine@"+goodDigest, policy); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if b, _ := os.ReadFile(seen); strings.TrimSpace(string(b)) != "none" {
		t.Errorf("cosign was handed %q for a registry the logins do not cover", b)
	}
}

// TestDockerHubsLoginIsRenderedUnderItsIndexKey: the key go-containerregistry's
// keychain looks Docker Hub up under, so cosign finds the login there.
func TestDockerHubsLoginIsRenderedUnderItsIndexKey(t *testing.T) {
	logins, err := ParseDockerConfig([]byte(`{"auths":{"docker.io":{"username":"u","password":"p"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	cfg, ok := logins.dockerConfigFor("docker.io")
	if !ok || !strings.Contains(string(cfg), `"https://index.docker.io/v1/"`) {
		t.Fatalf("rendered %s, %t", cfg, ok)
	}
}
