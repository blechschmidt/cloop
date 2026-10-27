package imagepolicy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// labelRegistry serves one repository the way ghcr.io does: a token service in
// front of it, a multi-platform index under a tag, an image manifest per
// platform, and configuration blobs answered with a redirect to a storage
// host.
type labelRegistry struct {
	t       *testing.T
	srv     *httptest.Server
	storage *httptest.Server

	blobs map[string][]byte // digest -> content, manifests and configs alike
	tags  map[string]string // tag -> digest

	// tamper serves these bytes for a blob instead of its content.
	tamper map[string][]byte

	mu     sync.Mutex
	tokens int
	paths  []string
}

func newLabelRegistry(t *testing.T) *labelRegistry {
	t.Helper()
	reg := &labelRegistry{t: t, blobs: map[string][]byte{}, tags: map[string]string{}, tamper: map[string][]byte{}}
	reg.storage = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		digest := strings.TrimPrefix(r.URL.Path, "/storage/")
		if b, ok := reg.tamper[digest]; ok {
			_, _ = w.Write(b)
			return
		}
		b, ok := reg.blobs[digest]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(reg.storage.Close)
	reg.srv = httptest.NewTLSServer(http.HandlerFunc(reg.serve))
	t.Cleanup(reg.srv.Close)
	return reg
}

func (reg *labelRegistry) host() string { return strings.TrimPrefix(reg.srv.URL, "https://") }

func (reg *labelRegistry) resolver() *RegistryResolver {
	return &RegistryResolver{
		Client:      reg.srv.Client(),
		Credentials: func(string) (RegistryCredential, bool) { return RegistryCredential{}, false },
	}
}

// put stores content and returns its digest.
func (reg *labelRegistry) put(v any) string {
	reg.t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		reg.t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	d := "sha256:" + hex.EncodeToString(sum[:])
	reg.blobs[d] = b
	return d
}

// image stores a configuration with labels and the manifest naming it.
func (reg *labelRegistry) image(labels map[string]string) string {
	cfg := reg.put(map[string]any{"architecture": "amd64", "config": map[string]any{"Labels": labels}})
	return reg.put(map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg},
	})
}

func (reg *labelRegistry) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/token" {
		reg.mu.Lock()
		reg.tokens++
		reg.mu.Unlock()
		_, _ = fmt.Fprintf(w, `{"token":%q}`, fakeToken)
		return
	}
	reg.mu.Lock()
	reg.paths = append(reg.paths, r.URL.Path)
	reg.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+fakeToken {
		w.Header().Set("Www-Authenticate", fmt.Sprintf(`Bearer realm=%q,service="fake"`, reg.srv.URL+"/token"))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	const repo = "/v2/acme/harness/"
	switch {
	case strings.HasPrefix(r.URL.Path, repo+"manifests/"):
		ref := strings.TrimPrefix(r.URL.Path, repo+"manifests/")
		if d, ok := reg.tags[ref]; ok {
			ref = d
		}
		b, ok := reg.blobs[ref]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if t, ok := reg.tamper[ref]; ok {
			b = t
		}
		_, _ = w.Write(b)
	case strings.HasPrefix(r.URL.Path, repo+"blobs/"):
		http.Redirect(w, r, reg.storage.URL+"/storage/"+strings.TrimPrefix(r.URL.Path, repo+"blobs/"),
			http.StatusTemporaryRedirect)
	default:
		http.NotFound(w, r)
	}
}

// TestRegistryLabelsReadsTheLinuxImageOfAnIndex is the published image: a tag
// naming an index of two platforms and two attestations. The labels come from
// the linux/amd64 image's configuration, reached through the redirect, with
// one token for the whole conversation.
func TestRegistryLabelsReadsTheLinuxImageOfAnIndex(t *testing.T) {
	reg := newLabelRegistry(t)
	amd64 := reg.image(map[string]string{HarnessesLabel: "claude,copilot,cloop,git"})
	arm64 := reg.image(map[string]string{HarnessesLabel: "something,else"})
	attestation := reg.image(nil)
	index := reg.put(map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
		"manifests": []map[string]any{
			{"digest": attestation, "platform": map[string]string{"os": "unknown", "architecture": "unknown"}},
			{"digest": arm64, "platform": map[string]string{"os": "linux", "architecture": "arm64"}},
			{"digest": amd64, "platform": map[string]string{"os": "linux", "architecture": "amd64"}},
		},
	})
	reg.tags["latest"] = index

	labels, err := reg.resolver().Labels(context.Background(), reg.host()+"/acme/harness:latest")
	if err != nil {
		t.Fatalf("Labels: %v", err)
	}
	if got := labels[HarnessesLabel]; got != "claude,copilot,cloop,git" {
		t.Errorf("label = %q, want the linux/amd64 image's", got)
	}
	if reg.tokens != 1 {
		t.Errorf("token service asked %d times, want once for the whole conversation", reg.tokens)
	}

	// By digest too: the index the hub resolved and verified.
	labels, err = reg.resolver().Labels(context.Background(), reg.host()+"/acme/harness@"+index)
	if err != nil || labels[HarnessesLabel] == "" {
		t.Fatalf("Labels by digest = %v, %v", labels, err)
	}
}

// TestRegistryLabelsOfAnUnlabelledImageAreNone: an image with no labels yields
// none and no error — which CheckHarness reads as unknown.
func TestRegistryLabelsOfAnUnlabelledImageAreNone(t *testing.T) {
	reg := newLabelRegistry(t)
	reg.tags["1"] = reg.image(nil)
	labels, err := reg.resolver().Labels(context.Background(), reg.host()+"/acme/harness:1")
	if err != nil || len(labels) != 0 {
		t.Fatalf("Labels = %v, %v; want none and no error", labels, err)
	}
	if err := CheckHarness("x", labels, "copilot", ""); err != nil {
		t.Errorf("an unlabelled image was refused: %v", err)
	}
}

// TestRegistryLabelsRefuseBytesThatAreNotTheDigest: a configuration blob that
// does not hash to the digest its manifest names describes some other image,
// and its labels are not read; nor is a manifest that is not the digest it was
// asked for.
func TestRegistryLabelsRefuseBytesThatAreNotTheDigest(t *testing.T) {
	reg := newLabelRegistry(t)
	man := reg.image(map[string]string{HarnessesLabel: "claude"})
	reg.tags["1"] = man
	var m ociManifest
	if err := json.Unmarshal(reg.blobs[man], &m); err != nil {
		t.Fatal(err)
	}
	reg.tamper[m.Config.Digest] = []byte(`{"config":{"Labels":{"org.cloop.harnesses":"copilot"}}}`)
	_, err := reg.resolver().Labels(context.Background(), reg.host()+"/acme/harness:1")
	if !errors.Is(err, ErrRegistry) || !strings.Contains(err.Error(), "whose digest is") {
		t.Errorf("a tampered configuration = %v, want a refusal naming the digest", err)
	}

	reg2 := newLabelRegistry(t)
	man2 := reg2.image(map[string]string{HarnessesLabel: "claude"})
	reg2.tamper[man2] = []byte(`{"schemaVersion":2}`)
	if _, err := reg2.resolver().Labels(context.Background(), reg2.host()+"/acme/harness@"+man2); !errors.Is(err, ErrRegistry) {
		t.Errorf("a manifest that is not its digest = %v, want ErrRegistry", err)
	}
}

// TestRegistryLabelsOfAMissingTagIsARegistryError: not knowing is an error the
// caller decides about, never a nil map that would read as "unlabelled".
func TestRegistryLabelsOfAMissingTagIsARegistryError(t *testing.T) {
	reg := newLabelRegistry(t)
	if _, err := reg.resolver().Labels(context.Background(), reg.host()+"/acme/harness:missing"); !errors.Is(err, ErrRegistry) {
		t.Errorf("Labels of a missing tag = %v, want ErrRegistry", err)
	}
	if _, err := reg.resolver().Labels(context.Background(), "acme/harness:1"); !errors.Is(err, ErrRegistry) {
		t.Errorf("Labels of a reference naming no registry = %v, want ErrRegistry", err)
	}
}
