package kubernetes

// imageresolve_test.go: the hub resolves every tag a Pod would carry to the
// digest its registry serves for it, before the Pod is built (Task 20457).
//
// The registry is pkg/imagepolicy/registrytest: the distribution API's manifest
// endpoint behind a bearer-token service, over TLS, with tags a test repoints.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
	"github.com/blechschmidt/cloop/pkg/imagepolicy/registrytest"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// resolvingExecutor is the hub's driver — tags resolved, the registry's
// certificate trusted — with policy and whatever mutate adds.
func resolvingExecutor(t *testing.T, reg *registrytest.Registry, policy imagepolicy.Policy,
	mutate func(*Options)) (*Executor, *fakeAPI, *fakeSource) {
	t.Helper()
	return newTestExecutor(t, func(o *Options) {
		o.Image = hubDefaultImage
		o.ImagePolicy = policy
		o.ResolveTags = true
		o.RegistryClient = reg.Client()
		if mutate != nil {
			mutate(o)
		}
	})
}

// staticLogins is a registry secret's logins, or the error reading it gave.
type staticLogins struct {
	config []byte
	err    error
}

func (s staticLogins) RegistryLogins(context.Context) (imagepolicy.DockerLogins, error) {
	if s.err != nil {
		return imagepolicy.DockerLogins{}, s.err
	}
	return imagepolicy.ParseDockerConfig(s.config)
}

func (s staticLogins) Describe() string { return "registry secret test-robot" }

// spec names image as the project's sandbox image.
func projectSpec(image string) executor.Spec {
	s := testSpec()
	s.Image = image
	return s
}

// TestAPodCarriesTheDigestItsTagResolvedTo is the property: a project's tag
// goes into the Pod as the digest the registry served for it at dispatch, and
// the run's log says so. The registry's token service is asked anonymously, for
// this repository's pull alone.
func TestAPodCarriesTheDigestItsTagResolvedTo(t *testing.T) {
	reg := registrytest.New(t)
	digest := reg.PushManifest("acme/rust", "1.79", registrytest.MediaOCIManifest, "a")
	ex, _, _ := resolvingExecutor(t, reg, imagepolicy.Policy{AllowedRegistries: []string{reg.Host()}}, nil)

	tag := reg.Host() + "/acme/rust:1.79"
	req, err := ex.podRequestFor(context.Background(), projectSpec(tag), "h1", "cloop", "")
	if err != nil {
		t.Fatalf("podRequestFor: %v", err)
	}
	if want := reg.Host() + "/acme/rust@" + digest; req.Image != want {
		t.Fatalf("Pod image = %q, want the digest the tag resolved to, %q", req.Image, want)
	}
	if log := strings.Join(req.ImageLog, ""); !strings.Contains(log, "image "+tag+" resolved at "+reg.Host()+
		" to "+req.Image) || strings.Contains(log, "signed in") {
		t.Errorf("the run's log does not say what the tag resolved to, anonymously: %q", log)
	}
	var scopes []string
	for _, q := range reg.Requests() {
		if q.Scope != "" {
			scopes = append(scopes, q.Scope)
			if q.Basic != "" {
				t.Errorf("an anonymous resolution presented a login (%q) to the token service", q.Basic)
			}
		}
	}
	if strings.Join(scopes, ",") != "repository:acme/rust:pull" {
		t.Errorf("token scopes = %q, want this repository's pull alone", scopes)
	}
	if got := strings.Join(reg.ManifestRequests(), ","); got != "HEAD,HEAD" {
		t.Errorf("manifest requests = %s, want the challenged HEAD and one with the token", got)
	}
}

// TestARepointedTagDoesNotMoveARunningPod: once a Pod is created it names a
// digest, so the registry repointing the tag a moment later changes nothing for
// it — while the next dispatch resolves the tag afresh. The handle and the row
// that persists it name the digest that ran.
func TestARepointedTagDoesNotMoveARunningPod(t *testing.T) {
	reg := registrytest.New(t)
	first := reg.PushManifest("acme/rust", "stable", registrytest.MediaOCIManifest, "first")
	store := executor.NewMemoryHandleStore()
	ex, api, _ := resolvingExecutor(t, reg, imagepolicy.Policy{}, func(o *Options) { o.HandleStore = store })
	tag := reg.Host() + "/acme/rust:stable"

	h1, err := ex.Start(context.Background(), projectSpec(tag))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	pod1 := api.onlyPodName(t)
	second := reg.PushManifest("acme/rust", "stable", registrytest.MediaOCIManifest, "second")
	if first == second {
		t.Fatal("the two pushes share a digest; the test proves nothing")
	}
	h2, err := ex.Start(context.Background(), projectSpec(tag))
	if err != nil {
		t.Fatalf("Start after the repoint: %v", err)
	}

	pinned := func(d string) string { return reg.Host() + "/acme/rust@" + d }
	if got := podContainerImage(t, api, pod1); got != pinned(first) {
		t.Errorf("the first Pod carries %q after the tag moved, want %q", got, pinned(first))
	}
	if h1.Image != pinned(first) || h2.Image != pinned(second) {
		t.Errorf("handles name %q and %q, want %q then %q", h1.Image, h2.Image, pinned(first), pinned(second))
	}
	rows, err := store.ListHandles(ex.ID())
	if err != nil {
		t.Fatal(err)
	}
	recorded := map[string]string{}
	for _, r := range rows {
		recorded[r.HandleID] = r.Image
	}
	if recorded[h1.ID] != pinned(first) || recorded[h2.ID] != pinned(second) {
		t.Errorf("handle rows record %v, want each run's own digest", recorded)
	}
}

// podContainerImage is the harness container's image in the Pod the fake API
// holds under name.
func podContainerImage(t *testing.T, api *fakeAPI, name string) string {
	t.Helper()
	api.mu.Lock()
	defer api.mu.Unlock()
	p := api.pods[name]
	if p == nil {
		t.Fatalf("no pod %q", name)
	}
	for _, c := range p.Spec.Containers {
		if c.Name == ContainerName {
			return c.Image
		}
	}
	t.Fatalf("pod %q has no %q container", name, ContainerName)
	return ""
}

// TestEveryManifestMediaTypeResolvesToItsOwnDigest: a multi-platform tag names
// an index — OCI or Docker's manifest list — and the Pod carries the index's
// digest, the one `docker pull` records and a signing pipeline signs; a
// single-platform tag names its manifest. A registry whose HEAD leaves the
// digest out is read with GET, and the digest is the hash of what it served.
func TestEveryManifestMediaTypeResolvesToItsOwnDigest(t *testing.T) {
	for _, omit := range []bool{false, true} {
		t.Run(fmt.Sprintf("digest header omitted=%t", omit), func(t *testing.T) {
			reg := registrytest.New(t)
			if omit {
				reg.OmitDigestHeader()
			}
			platform := reg.PushManifest("acme/tools", "", registrytest.MediaOCIManifest, "amd64")
			want := map[string]string{
				"oci-index":       reg.PushIndex("acme/tools", "oci-index", registrytest.MediaOCIIndex, platform),
				"docker-list":     reg.PushIndex("acme/tools", "docker-list", registrytest.MediaDockerList, platform),
				"oci-manifest":    reg.PushManifest("acme/tools", "oci-manifest", registrytest.MediaOCIManifest, "oci"),
				"docker-manifest": reg.PushManifest("acme/tools", "docker-manifest", registrytest.MediaDockerManifest, "v2"),
			}
			ex, _, _ := resolvingExecutor(t, reg, imagepolicy.Policy{}, nil)
			for tag, digest := range want {
				req, err := ex.podRequestFor(context.Background(), projectSpec(reg.Host()+"/acme/tools:"+tag),
					"h1", "cloop", "")
				if err != nil {
					t.Fatalf("%s: %v", tag, err)
				}
				if req.Image != reg.Host()+"/acme/tools@"+digest {
					t.Errorf("%s: Pod image %q, want the %s's own digest %s", tag, req.Image, tag, digest)
				}
			}
			if gets := strings.Count(strings.Join(reg.ManifestRequests(), ","), "GET"); omit != (gets > 0) {
				t.Errorf("GETs = %d with the header omitted=%t", gets, omit)
			}
		})
	}
}

// newRegistryBroker is a secret store holding a shared registry secret named
// name with payload.
func newRegistryBroker(t *testing.T, name string, payload []byte, owner string) *secretbroker.Broker {
	t.Helper()
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLOOP_SECRET_KEY", base64.StdEncoding.EncodeToString(key[:]))
	b, err := secretbroker.New(newMemStore())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Mint(context.Background(), secretbroker.MintRequest{
		Name: name, Kind: secretbroker.KindRegistry, Payload: payload, Actor: "test",
		Owner: owner, Personal: owner != "",
	}); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return b
}

// TestTheRegistrySecretSignsInAtItsOwnRegistryOnly: a private repository is
// resolved with the login the hub holds in executors.kubernetes.registry_secret
// — read from the secret store, through the broker — and that login is
// presented to its own registry and to no other: an image on another registry
// is asked about anonymously.
func TestTheRegistrySecretSignsInAtItsOwnRegistryOnly(t *testing.T) {
	private, public := registrytest.New(t), registrytest.New(t)
	login := registrytest.Login{Username: "robot", Password: "registry-secret-" + strings.Repeat("x", 12)}
	private.RequireLogin("acme/private", login)
	privateDigest := private.PushManifest("acme/private", "1", registrytest.MediaOCIManifest, "p")
	publicDigest := public.PushManifest("acme/public", "1", registrytest.MediaOCIManifest, "q")
	broker := newRegistryBroker(t, "ci-robot", registrytest.DockerConfig(private.Host(), login), "")

	// One client trusting both test certificates: they are distinct servers.
	client := &http.Client{Transport: mergedRoots(t, private, public)}
	ex, _, _ := newTestExecutor(t, func(o *Options) {
		o.Image = hubDefaultImage
		o.ResolveTags = true
		o.RegistryClient = client
		o.RegistryLogins = BrokerRegistryLogins{Broker: broker, Secret: "ci-robot"}
	})
	req, err := ex.podRequestFor(context.Background(), projectSpec(private.Host()+"/acme/private:1"), "h1", "cloop", "")
	if err != nil || req.Image != private.Host()+"/acme/private@"+privateDigest {
		t.Fatalf("private image: %q, %v; want its digest", req.Image, err)
	}
	if !strings.Contains(strings.Join(req.ImageLog, ""), "signed in with the registry secret ci-robot") {
		t.Errorf("the run's log does not say which login resolved it: %q", req.ImageLog)
	}
	req, err = ex.podRequestFor(context.Background(), projectSpec(public.Host()+"/acme/public:1"), "h1", "cloop", "")
	if err != nil || req.Image != public.Host()+"/acme/public@"+publicDigest {
		t.Fatalf("public image: %q, %v; want its digest", req.Image, err)
	}
	for _, q := range private.Requests() {
		if q.Scope != "" && q.Basic != login.Username {
			t.Errorf("the private registry's token service was asked without the login: %+v", q)
		}
	}
	for _, q := range public.Requests() {
		if q.Basic != "" {
			t.Errorf("the login for %s was presented to %s: %+v", private.Host(), public.Host(), q)
		}
	}

	// Without the secret the private tag is not resolved: kept, with the
	// registry's refusal, on a hub that does not insist on digests.
	ex, _, _ = newTestExecutor(t, func(o *Options) {
		o.Image = hubDefaultImage
		o.ImagePolicy = imagepolicy.Policy{AllowedRegistries: []string{private.Host()}}
		o.ResolveTags = true
		o.RegistryClient = client
	})
	tag := private.Host() + "/acme/private:1"
	req, err = ex.podRequestFor(context.Background(), projectSpec(tag), "h1", "cloop", "")
	if err != nil || req.Image != tag {
		t.Fatalf("anonymous, private: %q, %v; want the tag kept", req.Image, err)
	}
	if log := strings.Join(req.ImageLog, ""); !strings.Contains(log, "warning:") || !strings.Contains(log, "refused") {
		t.Errorf("the kept tag is not explained: %q", log)
	}
}

// TestAPersonalOrMalformedRegistrySecretIsRefusedNotIgnored: the hub signs in
// only with a shared secret in the Docker configuration form, and anything else
// fails resolution naming the secret — never an anonymous attempt in its place,
// which is what lets a private image fail without anybody learning why.
func TestAPersonalOrMalformedRegistrySecretIsRefusedNotIgnored(t *testing.T) {
	reg := registrytest.New(t)
	reg.PushManifest("acme/rust", "1", registrytest.MediaOCIManifest, "a")
	for name, c := range map[string]struct {
		payload []byte
		owner   string
		want    string
	}{
		"personal":      {registrytest.DockerConfig(reg.Host(), registrytest.Login{Username: "u", Password: "p"}), "alice@example.com", "belongs to"},
		"user:password": {[]byte("robot:hunter2-registry"), "", "names no registry"},
		"no auths":      {[]byte(`{"credsStore":"desktop"}`), "", "holds no login"},
	} {
		t.Run(name, func(t *testing.T) {
			broker := newRegistryBroker(t, "robot", c.payload, c.owner)
			before := len(reg.Requests())
			for _, strict := range []bool{false, true} {
				ex, _, _ := resolvingExecutor(t, reg, imagepolicy.Policy{RequireDigest: strict},
					func(o *Options) { o.RegistryLogins = BrokerRegistryLogins{Broker: broker, Secret: "robot"} })
				// A project's tag on a lenient hub; the operator's under
				// require_digest, which a project's tag would not reach.
				tag := reg.Host() + "/acme/rust:1"
				spec := projectSpec(tag)
				if strict {
					spec = testSpec()
					ex.opts.Image = tag
				}
				req, err := ex.podRequestFor(context.Background(), spec, "h1", "cloop", "")
				switch {
				case strict:
					var denied *imagepolicy.DenyError
					if !errors.As(err, &denied) || denied.Rule != imagepolicy.RuleResolution ||
						!strings.Contains(denied.Reason, c.want) {
						t.Fatalf("strict: %v, want a %s refusal saying %q", err, imagepolicy.RuleResolution, c.want)
					}
				case err != nil:
					t.Fatalf("lenient: %v", err)
				case req.Image != tag:
					t.Fatalf("lenient: Pod image %q, want the tag kept", req.Image)
				}
			}
			if after := len(reg.Requests()); after != before {
				t.Errorf("%d requests reached the registry with the secret unusable; want none", after-before)
			}
			if strings.Contains(fmt.Sprint(reg.Requests()), "hunter2") {
				t.Error("the secret's value reached the registry")
			}
		})
	}
}

// TestAnUnreachableRegistryInEachMode: when the hub cannot reach the registry,
// require_digest and require_signature refuse — naming the registry and what to
// do — and every other policy keeps the tag with the warning a policy-bearing
// hub prints. A project's tag under require_digest is refused at evaluation, as
// it always was, and the registry is never asked.
func TestAnUnreachableRegistryInEachMode(t *testing.T) {
	reg := registrytest.New(t)
	host := reg.Host()
	reg.Close()
	tag := host + "/acme/rust:1.79"
	keys := []string{"/etc/cloop/cosign.pub"}
	for _, c := range []struct {
		mode    string
		policy  imagepolicy.Policy
		project string // the rule refusing a project's tag, "" for kept
		op      string // the same for the operator's
		warns   bool
	}{
		{"no policy", imagepolicy.Policy{}, "", "", false},
		{"allowlist", imagepolicy.Policy{AllowedRegistries: []string{host}}, "", "", true},
		{"require_digest", imagepolicy.Policy{AllowedRegistries: []string{host}, RequireDigest: true},
			imagepolicy.RuleDigest, imagepolicy.RuleResolution, false},
		{"require_signature", imagepolicy.Policy{AllowedRegistries: []string{host}, RequireSignature: true,
			CosignPublicKeys: keys}, imagepolicy.RuleResolution, imagepolicy.RuleResolution, false},
	} {
		t.Run(c.mode, func(t *testing.T) {
			for _, who := range []string{"project", "operator"} {
				ex, _, _ := resolvingExecutor(t, reg, c.policy, nil)
				spec, rule := projectSpec(tag), c.project
				if who == "operator" {
					spec, rule = testSpec(), c.op
					ex.opts.Image = tag
				}
				req, err := ex.podRequestFor(context.Background(), spec, "h1", "cloop", "")
				if rule != "" {
					var denied *imagepolicy.DenyError
					if !errors.As(err, &denied) || denied.Rule != rule {
						t.Fatalf("%s: %v, want a %s refusal", who, err, rule)
					}
					if rule == imagepolicy.RuleResolution && (!strings.Contains(denied.Reason, host) ||
						!strings.Contains(denied.Reason, "unreachable") ||
						!strings.Contains(denied.Remediation, "by digest") ||
						!strings.Contains(denied.Remediation, "registry_secret")) {
						t.Errorf("%s: the refusal does not name the registry and the remedy: %v", who, err)
					}
					continue
				}
				if err != nil || req.Image != tag {
					t.Fatalf("%s: %q, %v; want the tag kept", who, req.Image, err)
				}
				warned := strings.Contains(strings.Join(req.ImageLog, ""), "runs from a mutable tag")
				if warned != c.warns {
					t.Errorf("%s: warned=%t, want %t: %q", who, warned, c.warns, req.ImageLog)
				}
			}
		})
	}
}

// stubCosign is a cosign whose verify passes only for a reference ending in
// signed, writing each reference it was asked about, and the registry login it
// was handed in $DOCKER_CONFIG, to files beside it.
func stubCosign(t *testing.T, signed string) (bin, asked, login string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the cosign stand-in is a POSIX shell script")
	}
	dir := t.TempDir()
	asked, login = filepath.Join(dir, "asked"), filepath.Join(dir, "login")
	script := `#!/bin/sh
ref=
for a in "$@"; do ref=$a; done
echo "$ref" >> '` + asked + `'
if [ -n "$DOCKER_CONFIG" ]; then cat "$DOCKER_CONFIG/config.json" >> '` + login + `'; echo "$DOCKER_CONFIG" > '` + login + `.dir'; fi
case "$ref" in
  *@` + signed + `) exit 0 ;;
  *) echo "Error: no matching signatures" >&2; exit 1 ;;
esac
`
	bin = filepath.Join(dir, "cosign")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, asked, login
}

// TestASignatureIsVerifiedOnTheDigestTheTagResolvedTo: under require_signature
// a tag is resolved, cosign is asked about the digest — never the tag — as the
// login that resolved it, and the Pod carries the digest it verified. A tag
// whose digest is not signed is refused.
func TestASignatureIsVerifiedOnTheDigestTheTagResolvedTo(t *testing.T) {
	reg := registrytest.New(t)
	login := registrytest.Login{Username: "robot", Password: "registry-secret-pw"}
	reg.RequireLogin("acme/signed", login)
	reg.RequireLogin("acme/unsigned", login)
	signed := reg.PushManifest("acme/signed", "v1", registrytest.MediaOCIManifest, "s")
	reg.PushManifest("acme/unsigned", "v1", registrytest.MediaOCIManifest, "u")
	bin, asked, seenLogin := stubCosign(t, signed)

	policy := imagepolicy.Policy{AllowedRegistries: []string{reg.Host()}, RequireSignature: true,
		CosignPublicKeys: []string{"/etc/cloop/cosign.pub"}}
	ex, _, _ := resolvingExecutor(t, reg, policy, func(o *Options) {
		o.RegistryLogins = staticLogins{config: registrytest.DockerConfig(reg.Host(), login)}
	})
	ex.verifier = &imagepolicy.CosignVerifier{Binary: bin}

	req, err := ex.podRequestFor(context.Background(), projectSpec(reg.Host()+"/acme/signed:v1"), "h1", "cloop", "")
	if err != nil {
		t.Fatalf("a signed image: %v", err)
	}
	if want := reg.Host() + "/acme/signed@" + signed; req.Image != want {
		t.Fatalf("Pod image %q, want the verified digest %q", req.Image, want)
	}
	if got, _ := os.ReadFile(asked); strings.TrimSpace(string(got)) != req.Image {
		t.Errorf("cosign was asked about %q, want only the digest %q", got, req.Image)
	}
	cfg, _ := os.ReadFile(seenLogin)
	logins, err := imagepolicy.ParseDockerConfig(cfg)
	if err != nil || strings.Join(logins.Registries(), ",") != reg.Host() {
		t.Errorf("cosign was handed %s (%v), want the one login for %s", cfg, err, reg.Host())
	}
	if dir, _ := os.ReadFile(seenLogin + ".dir"); len(dir) == 0 {
		t.Error("cosign ran without DOCKER_CONFIG")
	} else if _, err := os.Stat(strings.TrimSpace(string(dir))); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the login staged for cosign outlived the verification: %v", err)
	}

	_, err = ex.podRequestFor(context.Background(), projectSpec(reg.Host()+"/acme/unsigned:v1"), "h1", "cloop", "")
	var denied *imagepolicy.DenyError
	if !errors.As(err, &denied) || denied.Rule != imagepolicy.RuleSignature {
		t.Fatalf("an unsigned image: %v, want a %s refusal", err, imagepolicy.RuleSignature)
	}
}

// TestTheOperatorsTagIsPinnedNotGoverned: the operator's image is not held to
// the project rules — the allowlist here would refuse it — but its tag still
// reaches the kubelet as a digest, and under require_digest one the hub cannot
// resolve is not sent at all.
func TestTheOperatorsTagIsPinnedNotGoverned(t *testing.T) {
	reg := registrytest.New(t)
	digest := reg.PushManifest("ops/harness", "v3", registrytest.MediaOCIIndex, "h")
	policy := imagepolicy.Policy{AllowedRegistries: []string{"quay.io"}, RequireDigest: true}
	ex, _, _ := resolvingExecutor(t, reg, policy, func(o *Options) { o.Image = reg.Host() + "/ops/harness:v3" })
	p, err := ex.buildPodFor(context.Background(), testSpec(), "h1", "cloop", "")
	if err != nil {
		t.Fatalf("the operator's image was refused: %v", err)
	}
	if got := harnessImage(t, p); got != reg.Host()+"/ops/harness@"+digest {
		t.Fatalf("Pod image %q, want the operator's tag pinned", got)
	}

	ex.opts.Image = reg.Host() + "/ops/harness:missing"
	_, err = ex.buildPodFor(context.Background(), testSpec(), "h1", "cloop", "")
	var denied *imagepolicy.DenyError
	if !errors.As(err, &denied) || denied.Rule != imagepolicy.RuleResolution ||
		!strings.Contains(denied.Reason, "executors.kubernetes.image") || !strings.Contains(denied.Reason, "no manifest") {
		t.Fatalf("an unresolvable operator tag under require_digest: %v, want a refusal naming the field", err)
	}
}

// TestStartResolvesBeforeAnythingIsLeased: a refusal for the image costs no
// credential — the kubeconfig lease is not taken, and nothing is created.
func TestStartResolvesBeforeAnythingIsLeased(t *testing.T) {
	reg := registrytest.New(t)
	host := reg.Host()
	reg.Close()
	ex, api, src := resolvingExecutor(t, reg, imagepolicy.Policy{RequireDigest: true},
		func(o *Options) { o.Image = host + "/ops/harness:v3" })
	if _, err := ex.Start(context.Background(), testSpec()); !errors.Is(err, imagepolicy.ErrDenied) {
		t.Fatalf("Start = %v, want the image refused", err)
	}
	src.mu.Lock()
	acquired := len(src.acquired)
	src.mu.Unlock()
	if acquired != 0 || len(api.creates()) != 0 {
		t.Fatalf("a refused image cost %d leases and created %v", acquired, api.creates())
	}
}

// TestTheRunLogSaysWhatTheTagResolvedTo: the first lines of the run's log name
// the tag, the registry and the digest the Pod runs.
func TestTheRunLogSaysWhatTheTagResolvedTo(t *testing.T) {
	reg := registrytest.New(t)
	digest := reg.PushManifest("acme/rust", "1.79", registrytest.MediaOCIManifest, "a")
	ex, api, _ := resolvingExecutor(t, reg, imagepolicy.Policy{}, nil)
	tag := reg.Host() + "/acme/rust:1.79"
	h, err := ex.Start(context.Background(), projectSpec(tag))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	stream, err := ex.Stream(context.Background(), h.ID)
	if err != nil {
		t.Fatal(err)
	}
	name := api.onlyPodName(t)
	api.run(name)
	api.terminate(name, 0, "Completed")
	var out strings.Builder
	timeout := time.After(5 * time.Second)
	for done := false; !done; {
		select {
		case line, ok := <-stream:
			if !ok {
				done = true
				break
			}
			out.WriteString(line.Text)
		case <-timeout:
			t.Fatal("the stream never closed")
		}
	}
	want := "[cloop] image " + tag + " resolved at " + reg.Host() + " to " + reg.Host() + "/acme/rust@" + digest
	if !strings.Contains(out.String(), want) {
		t.Errorf("the run's log %q does not carry %q", out.String(), want)
	}
}

// TestPreflightReportsTheRegistryLoginAndTheImagesDigest: `cloop executor
// test` says which registries the secret covers and what the executor's own tag
// resolves to — and fails a secret it cannot read.
func TestPreflightReportsTheRegistryLoginAndTheImagesDigest(t *testing.T) {
	reg := registrytest.New(t)
	digest := reg.PushManifest("ops/harness", "v3", registrytest.MediaOCIManifest, "h")
	login := registrytest.Login{Username: "robot", Password: "pw"}
	ex, _, _ := resolvingExecutor(t, reg, imagepolicy.Policy{}, func(o *Options) {
		o.Image = reg.Host() + "/ops/harness:v3"
		o.RegistryLogins = staticLogins{config: registrytest.DockerConfig(reg.Host(), login)}
	})
	got := map[string]Finding{}
	for _, f := range ex.Preflight(context.Background()).Findings {
		got[f.Name] = f
	}
	if f := got["registry-login"]; f.Level != LevelOK || !strings.Contains(f.Message, reg.Host()) {
		t.Errorf("registry-login: %+v", f)
	}
	if f := got["image-resolution"]; f.Level != LevelOK || !strings.Contains(f.Message, digest) {
		t.Errorf("image-resolution: %+v", f)
	}

	ex.opts.RegistryLogins = staticLogins{err: errors.New("sealing key retired")}
	got = map[string]Finding{}
	for _, f := range ex.Preflight(context.Background()).Findings {
		got[f.Name] = f
	}
	if f := got["registry-login"]; f.Level != LevelFail || !strings.Contains(f.Message, "sealing key retired") {
		t.Errorf("an unreadable secret: %+v", f)
	}
}

// mergedRoots is a transport that sends each request to its registry's own
// client, so one client trusts every test registry's certificate.
func mergedRoots(t *testing.T, regs ...*registrytest.Registry) *roundTripRouter {
	t.Helper()
	r := &roundTripRouter{byHost: map[string]*registrytest.Registry{}}
	for _, reg := range regs {
		r.byHost[reg.Host()] = reg
	}
	return r
}

type roundTripRouter struct {
	byHost map[string]*registrytest.Registry
}

func (r *roundTripRouter) RoundTrip(req *http.Request) (*http.Response, error) {
	if reg, ok := r.byHost[req.URL.Host]; ok {
		return reg.Client().Transport.RoundTrip(req)
	}
	return nil, fmt.Errorf("no test registry at %s", req.URL.Host)
}
