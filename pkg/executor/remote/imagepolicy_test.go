package remote_test

// The hub's image trust policy on the device path (Task 20424).
//
// A device in container mode, and every virtual executor, runs the image a
// project names, and nothing on the device checks it: its container driver is
// built with no policy. Before Task 20424 the hub checked such an image against
// the allowlists and the digest rule only, so require_signature held on the
// hub's own container and Kubernetes executors and on no device. These tests
// drive the remote executor's Start: a signature the policy requires is
// verified on the hub, the start frame names the digest that was verified, and
// every way of not verifying refuses before anything reaches the device.
//
// The scripted-peer tests read the start frame itself. The loopback test runs a
// real agent against a stand-in engine that holds only the verified digest, so
// "the device runs the bytes the hub verified" is observed where the device
// runs them.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
)

const (
	// signedDigest is the digest the stand-in cosign accepts a signature on.
	signedDigest = "sha256:5e1f4c0d9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d"
	// unsignedDigest is any other.
	unsignedDigest = "sha256:0badc0de0badc0de0badc0de0badc0de0badc0de0badc0de0badc0de0badc0de"
)

// stubCosign writes a cosign whose `verify` passes only for a reference pinned
// to one of signed, as cosign passes only for a digest an accepted key signed,
// and returns its path. Each reference it was asked about is appended to the
// file named by the second return value.
func stubCosign(t *testing.T, signed ...string) (bin, asked string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the cosign stand-in is a POSIX shell script")
	}
	dir := t.TempDir()
	asked = filepath.Join(dir, "asked")
	var cases strings.Builder
	for _, d := range signed {
		fmt.Fprintf(&cases, "  *@%s) exit 0 ;;\n", d)
	}
	script := `#!/bin/sh
ref=
for a in "$@"; do ref=$a; done
echo "$ref" >> '` + asked + `'
case "$ref" in
` + cases.String() + `  *) echo "Error: no matching signatures: invalid signature when validating ASN.1 encoded signature" >&2; exit 1 ;;
esac
`
	bin = filepath.Join(dir, "cosign")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, asked
}

// signaturePolicy requires a signature on every image from registry.
func signaturePolicy(registry string) func() (imagepolicy.Policy, error) {
	return func() (imagepolicy.Policy, error) {
		return imagepolicy.Policy{
			AllowedRegistries: []string{registry},
			RequireSignature:  true,
			CosignPublicKeys:  []string{"/etc/cloop/cosign.pub"},
		}, nil
	}
}

// tagResolver stands in for a registry: the digest each tag names.
type tagResolver struct {
	digests map[string]string
	err     error
	calls   atomic.Int32
}

func (r *tagResolver) ResolveDigest(_ context.Context, ref string) (string, error) {
	r.calls.Add(1)
	if r.err != nil {
		return "", r.err
	}
	if d, ok := r.digests[ref]; ok {
		return d, nil
	}
	return "", fmt.Errorf("%w: no manifest for %s", imagepolicy.ErrRegistry, ref)
}

// countingVerifier records that a verification was asked for.
type countingVerifier struct {
	inner imagepolicy.Verifier
	calls atomic.Int32
}

func (v *countingVerifier) Verify(ctx context.Context, ref string, p imagepolicy.Policy) error {
	v.calls.Add(1)
	return v.inner.Verify(ctx, ref, p)
}

// imageDevice is a device whose sandbox is s, at the current protocol and able
// to start a VM, on a hub enforcing policy with resolver and verifier.
func imageDevice(t *testing.T, s executor.SandboxSettings, policy func() (imagepolicy.Policy, error),
	resolver imagepolicy.Resolver, verifier imagepolicy.Verifier) (*remote.Executor, *peer) {
	t.Helper()
	hello := helloAt(remote.ProtocolVersion)
	hello.Capabilities.Virtualization = true
	ex, err := remote.NewExecutor(remote.Options{
		ID: "agent-1", Name: "edge-1",
		Sandbox:       func() (executor.SandboxSettings, error) { return s, nil },
		ImagePolicy:   policy,
		ImageResolver: resolver,
		ImageVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, hello, nil)
	t.Cleanup(func() { _ = sess.Close() })
	return ex, p
}

// noStartFrame asserts the device is sent no start frame within d.
func noStartFrame(t *testing.T, p *peer, d time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	for {
		f, err := p.conn.ReadFrame(ctx)
		if err != nil {
			return
		}
		if f.Type == remote.TypeStart {
			t.Fatal("a start frame reached the device for an image the hub refused")
		}
	}
}

// wantDenial asserts err is an image policy refusal under rule.
func wantDenial(t *testing.T, err error, rule string) *imagepolicy.DenyError {
	t.Helper()
	var denied *imagepolicy.DenyError
	if !errors.As(err, &denied) || denied.Rule != rule {
		t.Fatalf("Start = %v, want an image policy denial under %s", err, rule)
	}
	if denied.Remediation == "" {
		t.Errorf("the denial carries no remediation: %v", err)
	}
	return denied
}

// TestDeviceDispatchNamesTheVerifiedDigest is the property: under
// require_signature the hub resolves the tag, verifies the digest, and the
// start frame names that digest — never the tag, which the device would
// resolve in a store the hub cannot see.
func TestDeviceDispatchNamesTheVerifiedDigest(t *testing.T) {
	cosign, asked := stubCosign(t, signedDigest)
	resolver := &tagResolver{digests: map[string]string{"ghcr.io/acme/tools:3.12": signedDigest}}
	ex, p := imageDevice(t, containerMode, signaturePolicy("ghcr.io"), resolver,
		&imagepolicy.CosignVerifier{Binary: cosign})

	spec := plainSpec(t.TempDir())
	spec.Image = "ghcr.io/acme/tools:3.12"
	sent := answerStart(t, p)
	h, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start of a signed image: %v", err)
	}
	payload := <-sent
	want := "ghcr.io/acme/tools@" + signedDigest
	if payload.Spec.Image != want {
		t.Fatalf("the start frame names %q, want the verified digest %q", payload.Spec.Image, want)
	}
	if h.Image != want {
		t.Errorf("handle image = %q, want the verified digest %q", h.Image, want)
	}
	if got, _ := os.ReadFile(asked); strings.TrimSpace(string(got)) != want {
		t.Errorf("cosign was asked about %q, want only the digest %q", got, want)
	}
}

// TestDeviceRefusesAnUnsignedImage: a tag naming an unsigned digest, and an
// unsigned digest written out, are refused on the hub — audited as an image
// denial by the dispatch path — and the device is never sent anything.
func TestDeviceRefusesAnUnsignedImage(t *testing.T) {
	cosign, _ := stubCosign(t, signedDigest)
	resolver := &tagResolver{digests: map[string]string{"ghcr.io/acme/tools:3.12": unsignedDigest}}
	ex, p := imageDevice(t, containerMode, signaturePolicy("ghcr.io"), resolver,
		&imagepolicy.CosignVerifier{Binary: cosign})

	for _, image := range []string{"ghcr.io/acme/tools:3.12", "ghcr.io/acme/tools@" + unsignedDigest} {
		spec := plainSpec(t.TempDir())
		spec.Image = image
		_, err := ex.Start(context.Background(), spec)
		denied := wantDenial(t, err, imagepolicy.RuleSignature)
		if !strings.Contains(denied.Reason, "no matching signatures") {
			t.Errorf("%s: the denial does not carry cosign's own diagnosis: %v", image, err)
		}
	}
	noStartFrame(t, p, 300*time.Millisecond)
	if n := len(ex.Handles()); n != 0 {
		t.Errorf("%d handles recorded for refused dispatches", n)
	}
}

// TestDeviceRefusesATagTheHubCannotResolve: with nothing to verify against,
// the answer is a refusal — not the tag, handed to a device that would pin it
// in its own store and run it unverified.
func TestDeviceRefusesATagTheHubCannotResolve(t *testing.T) {
	cosign, _ := stubCosign(t, signedDigest)
	verifier := &countingVerifier{inner: &imagepolicy.CosignVerifier{Binary: cosign}}
	resolver := &tagResolver{err: fmt.Errorf("%w: ghcr.io is unreachable from this host: dial tcp: connection refused",
		imagepolicy.ErrRegistry)}
	ex, p := imageDevice(t, containerMode, signaturePolicy("ghcr.io"), resolver, verifier)

	spec := plainSpec(t.TempDir())
	spec.Image = "ghcr.io/acme/tools:3.12"
	_, err := ex.Start(context.Background(), spec)
	denied := wantDenial(t, err, imagepolicy.RuleResolution)
	if !strings.Contains(denied.Reason, "unreachable") || !strings.Contains(denied.Remediation, "digest") {
		t.Errorf("the denial should name the registry failure and the digest pin that avoids it: %v", err)
	}
	if verifier.calls.Load() != 0 {
		t.Error("a signature was checked with no digest to check it on")
	}
	noStartFrame(t, p, 300*time.Millisecond)
}

// TestDeviceRefusesWhenTheHubCannotReadItsPolicy: an unreadable configuration
// never stands in for the zero policy, which admits every image.
func TestDeviceRefusesWhenTheHubCannotReadItsPolicy(t *testing.T) {
	resolver := &tagResolver{digests: map[string]string{"ghcr.io/acme/tools:3.12": signedDigest}}
	ex, p := imageDevice(t, containerMode, func() (imagepolicy.Policy, error) {
		return imagepolicy.Policy{}, errors.New("load .cloop/config.yaml: yaml: line 3: did not find expected key")
	}, resolver, nil)

	spec := plainSpec(t.TempDir())
	spec.Image = "ghcr.io/acme/tools:3.12"
	_, err := ex.Start(context.Background(), spec)
	denied := wantDenial(t, err, imagepolicy.RuleConfig)
	if !strings.Contains(denied.Reason, "yaml") {
		t.Errorf("the denial does not say why the policy could not be read: %v", err)
	}
	if resolver.calls.Load() != 0 {
		t.Error("the tag was resolved under a policy nobody could read")
	}
	noStartFrame(t, p, 300*time.Millisecond)
}

// TestDeviceRefusesWithoutCosign: a hub that requires signatures and cannot
// check one refuses; a missing binary is never a skipped check.
func TestDeviceRefusesWithoutCosign(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	resolver := &tagResolver{digests: map[string]string{"ghcr.io/acme/tools:3.12": signedDigest}}
	ex, p := imageDevice(t, containerMode, signaturePolicy("ghcr.io"), resolver, imagepolicy.NewCosignVerifier())

	spec := plainSpec(t.TempDir())
	spec.Image = "ghcr.io/acme/tools:3.12"
	_, err := ex.Start(context.Background(), spec)
	if !errors.Is(err, imagepolicy.ErrCosignMissing) {
		t.Fatalf("Start = %v, want a refusal naming the missing cosign", err)
	}
	wantDenial(t, err, imagepolicy.RuleSignature)
	noStartFrame(t, p, 300*time.Millisecond)
}

// TestDeviceLeavesTheOperatorsImageAlone: the device's configured sandbox
// image is the operator's choice, made beside the policy, and is exempt as
// executors.container.image is on the hub's container driver. Only the image
// a project names is checked.
func TestDeviceLeavesTheOperatorsImageAlone(t *testing.T) {
	cosign, _ := stubCosign(t)
	verifier := &countingVerifier{inner: &imagepolicy.CosignVerifier{Binary: cosign}}
	resolver := &tagResolver{}
	mode := executor.SandboxSettings{Mode: executor.SandboxModeContainer, Image: "ghcr.io/acme/base:1"}
	ex, p := imageDevice(t, mode, signaturePolicy("ghcr.io"), resolver, verifier)

	sent := answerStart(t, p)
	if _, err := ex.Start(context.Background(), plainSpec(t.TempDir())); err != nil {
		t.Fatalf("the device's own image was refused: %v", err)
	}
	payload := <-sent
	if payload.Spec.Image != "" || payload.Sandbox.Image != "ghcr.io/acme/base:1" {
		t.Errorf("start frame image = %q, sandbox image %q", payload.Spec.Image, payload.Sandbox.Image)
	}
	if resolver.calls.Load() != 0 || verifier.calls.Load() != 0 {
		t.Error("the operator's image was resolved or verified as if a project had named it")
	}
}

// TestDeviceWithoutASignatureRuleResolvesNothing: a policy that requires no
// signature needs no digest from the hub — the device pins an accepted tag in
// its own store, as before — but the device is sent the reference the policy
// read, qualified with its default registry, so the registry the allowlist
// admitted is the one the device's engine pulls from.
func TestDeviceWithoutASignatureRuleResolvesNothing(t *testing.T) {
	resolver := &tagResolver{}
	ex, p := imageDevice(t, containerMode, func() (imagepolicy.Policy, error) {
		return imagepolicy.Policy{AllowedRegistries: []string{"docker.io"}, DefaultRegistry: "docker.io"}, nil
	}, resolver, nil)

	spec := plainSpec(t.TempDir())
	spec.Image = "alpine:3.20"
	sent := answerStart(t, p)
	h, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := (<-sent).Spec.Image; got != "docker.io/library/alpine:3.20" {
		t.Errorf("start frame image = %q, want the reference the policy admitted", got)
	}
	if resolver.calls.Load() != 0 {
		t.Error("a registry was asked about a tag no signature rule needed resolved")
	}
	if h.Image != "" {
		t.Errorf("handle image = %q for a tag the device pins itself", h.Image)
	}

	// And a registry off the allowlist is refused here too, not only at the
	// hub's early check — this is the check a dispatch cannot route around.
	spec.Image = "quay.io/acme/tools:1"
	_, err = ex.Start(context.Background(), spec)
	wantDenial(t, err, imagepolicy.RuleRegistry)
}

// TestVirtualExecutorVerifiesTheProjectImage: a virtual executor — here a Kata
// one — runs project images under its own sandbox settings, and its dispatch
// is held to the same rule as the device's.
func TestVirtualExecutorVerifiesTheProjectImage(t *testing.T) {
	cosign, _ := stubCosign(t, signedDigest)
	resolver := &tagResolver{digests: map[string]string{
		"ghcr.io/acme/tools:3.12": signedDigest,
		"ghcr.io/acme/tools:3.13": unsignedDigest,
	}}
	parent, p := imageDevice(t, executor.SandboxSettings{Mode: executor.SandboxModeHost}, signaturePolicy("ghcr.io"),
		resolver, &imagepolicy.CosignVerifier{Binary: cosign})
	v := virtualOver(t, parent, "vx-kata", executor.VirtualSpec{
		Sandbox: executor.SandboxSettings{Mode: executor.SandboxModeContainer, Engine: "podman", Runtime: "kata"},
	})

	spec := plainSpec(t.TempDir())
	spec.Image = "ghcr.io/acme/tools:3.13"
	_, err := v.Start(context.Background(), spec)
	wantDenial(t, err, imagepolicy.RuleSignature)

	spec.Image = "ghcr.io/acme/tools:3.12"
	sent := answerStart(t, p)
	if _, err := v.Start(context.Background(), spec); err != nil {
		t.Fatalf("Start of a signed image through the virtual executor: %v", err)
	}
	payload := <-sent
	if payload.Spec.Image != "ghcr.io/acme/tools@"+signedDigest || payload.Sandbox.Runtime != "kata" {
		t.Errorf("start frame image = %q under runtime %q, want the verified digest under kata",
			payload.Spec.Image, payload.Sandbox.Runtime)
	}
}

// ── the loopback agent ──────────────────────────────────────────────────────

// standInEngine puts a `docker` first on PATH that holds exactly the images in
// its store file — inspecting anything else fails as a missing image does —
// and logs every `run`. It runs nothing: a container is "running" until it is
// removed or killed, as with internal/drivertest's.
type standInEngine struct {
	dir, store, runs, configs string
}

func newStandInEngine(t *testing.T) *standInEngine {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in engine is a POSIX shell script")
	}
	dir := t.TempDir()
	e := &standInEngine{dir: dir, store: filepath.Join(dir, "store"), runs: filepath.Join(dir, "runs"),
		configs: filepath.Join(dir, "configs")}
	gone := filepath.Join(dir, "removed")
	// An image held with a configuration answers it as `{{json .Config}}`
	// renders one, the third field of the container driver's inspect.
	script := fmt.Sprintf(`#!/bin/sh
case "$1" in
image)
  ref=; for a in "$@"; do ref=$a; done
  if grep -qxF -- "$ref" '%[1]s' 2>/dev/null; then
    cfg=$(awk -F '\t' -v r="$ref" '$1 == r { print $2 }' '%[4]s' 2>/dev/null)
    printf '%%s\037%%s\037%%s\n' "$ref" 'sha256:5f3b8f9c2b' "$cfg"; exit 0; fi
  echo "Error: No such image: $ref" >&2; exit 1 ;;
run) echo "$*" >> '%[2]s'; echo "stand-in-container"; exit 0 ;;
logs) i=0; while [ ! -e '%[3]s' ] && [ "$i" -lt 1200 ]; do sleep 0.1; i=$((i+1)); done; exit 0 ;;
wait) i=0; while [ ! -e '%[3]s' ] && [ "$i" -lt 1200 ]; do sleep 0.1; i=$((i+1)); done; echo 137; exit 0 ;;
inspect) if [ -e '%[3]s' ]; then echo "Error: No such container" >&2; exit 1; fi
  echo '{"Status":"running","Running":true,"ExitCode":0,"StartedAt":"2026-01-01T00:00:00Z","FinishedAt":"0001-01-01T00:00:00Z"}'; exit 0 ;;
rm|kill|stop) : > '%[3]s'; exit 0 ;;
network) echo '{}'; exit 0 ;;
*) exit 0 ;;
esac
`, e.store, e.runs, gone, e.configs)
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.WriteFile(gone, nil, 0o600) })
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return e
}

// hold puts ref in the engine's store.
func (e *standInEngine) hold(t *testing.T, ref string) {
	t.Helper()
	f, err := os.OpenFile(e.store, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := fmt.Fprintln(f, ref); err != nil {
		t.Fatal(err)
	}
}

// holdConfigured puts ref in the engine's store with an image configuration,
// as `{{json .Config}}` would render it.
func (e *standInEngine) holdConfigured(t *testing.T, ref, config string) {
	t.Helper()
	e.hold(t, ref)
	f, err := os.OpenFile(e.configs, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "%s\t%s\n", ref, config); err != nil {
		t.Fatal(err)
	}
}

// ran returns the argv of every `run` the device made.
func (e *standInEngine) ran() []string {
	data, _ := os.ReadFile(e.runs)
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// tagRegistry is a registry over TLS serving one repository, whose tags can be
// repointed while the test runs.
type tagRegistry struct {
	srv  *httptest.Server
	mu   sync.Mutex
	tags map[string]string
}

func newTagRegistry(t *testing.T, repo string, tags map[string]string) *tagRegistry {
	t.Helper()
	r := &tagRegistry{tags: tags}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		tag, ok := strings.CutPrefix(req.URL.Path, "/v2/"+repo+"/manifests/")
		r.mu.Lock()
		digest, known := r.tags[tag]
		r.mu.Unlock()
		if !ok || !known {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Docker-Content-Digest", digest)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *tagRegistry) host() string { return strings.TrimPrefix(r.srv.URL, "https://") }

func (r *tagRegistry) point(tag, digest string) {
	r.mu.Lock()
	r.tags[tag] = digest
	r.mu.Unlock()
}

// containerDevice puts the loopback device in container mode under docker.
func containerDevice(o *remote.HubOptions) {
	o.SandboxSource = func(string) func() (executor.SandboxSettings, error) {
		return func() (executor.SandboxSettings, error) {
			return executor.SandboxSettings{Mode: executor.SandboxModeContainer, Engine: "docker"}, nil
		}
	}
}

// deviceWorkDir is a directory on the loopback device a container may run in:
// the sandbox runs as the workspace's owner and refuses uid 0, who owns what a
// test running as root creates.
func deviceWorkDir(t *testing.T, lb *loopback) string {
	t.Helper()
	dir := filepath.Join(lb.root, "image-trust")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(dir, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestLoopbackDeviceRunsOnlyTheDigestTheHubVerified: a real hub and a real
// agent. The hub resolves the project's tag at a registry, verifies the
// digest's signature with cosign, and the device's container engine is asked
// to run that digest and nothing else. When the registry repoints the tag at
// an unsigned image, or loses it, the hub refuses and the device's engine is
// never asked anything.
func TestLoopbackDeviceRunsOnlyTheDigestTheHubVerified(t *testing.T) {
	engine := newStandInEngine(t)
	reg := newTagRegistry(t, "acme/tools", map[string]string{"3.12": signedDigest})
	cosign, _ := stubCosign(t, signedDigest)
	lb := newLoopbackHub(t, func(o *remote.HubOptions) {
		containerDevice(o)
		o.ImagePolicy = signaturePolicy(reg.host())
		o.ImageResolver = &imagepolicy.RegistryResolver{
			Client:      reg.srv.Client(),
			Credentials: func(string) (imagepolicy.RegistryCredential, bool) { return imagepolicy.RegistryCredential{}, false },
		}
		o.ImageVerifier = &imagepolicy.CosignVerifier{Binary: cosign}
	})
	ex := lb.executor(t)
	verified := reg.host() + "/acme/tools@" + signedDigest
	// The device holds the verified bytes, and — under the tag — the bytes
	// the tag named before it moved, which the hub must never let it run.
	engine.hold(t, verified)
	engine.hold(t, reg.host()+"/acme/tools:3.12")
	work := deviceWorkDir(t, lb)

	spec := executor.Spec{WorkDir: work, Argv: []string{"/bin/sh", "-c", "true"}, Image: reg.host() + "/acme/tools:3.12"}
	h, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start of a signed image on the device: %v", err)
	}
	runs := engine.ran()
	if len(runs) != 1 || !strings.Contains(runs[0], " "+verified+" ") {
		t.Fatalf("the device's engine ran %q, want one run of the verified digest %s", runs, verified)
	}
	if h.Image != verified {
		t.Errorf("handle image = %q, want %q", h.Image, verified)
	}
	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := ex.Signal(sctx, h.ID, executor.SignalKill); err != nil {
		t.Fatalf("stop the workload: %v", err)
	}

	// The tag moves to an unsigned image the device happens to hold too.
	reg.point("3.12", unsignedDigest)
	engine.hold(t, reg.host()+"/acme/tools@"+unsignedDigest)
	_, err = ex.Start(context.Background(), spec)
	wantDenial(t, err, imagepolicy.RuleSignature)

	// And a tag the registry does not know.
	spec.Image = reg.host() + "/acme/tools:gone"
	_, err = ex.Start(context.Background(), spec)
	wantDenial(t, err, imagepolicy.RuleResolution)

	if runs := engine.ran(); len(runs) != 1 {
		t.Fatalf("the device's engine was asked to run %d workloads, want only the verified one: %q", len(runs), runs)
	}
}

// TestIntegration_DeviceRunsTheVerifiedDigestOnARealEngine is the loopback test
// on a real engine: the device inspects and runs the digest the hub verified
// in docker's own store, by digest. The registry is a stand-in answering for
// docker.io; the image is the alpine:3.20 already in the store.
//
//	CLOOP_AGENT_SANDBOX_E2E=1 go test ./pkg/executor/remote -run TestIntegration_DeviceRunsTheVerifiedDigestOnARealEngine -v
func TestIntegration_DeviceRunsTheVerifiedDigestOnARealEngine(t *testing.T) {
	if os.Getenv("CLOOP_AGENT_SANDBOX_E2E") != "1" {
		t.Skip("set CLOOP_AGENT_SANDBOX_E2E=1 to start a real sandbox")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	out, err := exec.Command("docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}", "alpine:3.20").Output()
	if err != nil {
		t.Skip("alpine:3.20 is not in docker's local store")
	}
	_, digest, ok := strings.Cut(strings.TrimSpace(string(out)), "@")
	if !ok {
		t.Skip("alpine:3.20 has no repo digest in docker's store")
	}
	reg := newTagRegistry(t, "library/alpine", map[string]string{"3.20": digest})
	cosign, _ := stubCosign(t, digest)
	lb := newLoopbackHub(t, func(o *remote.HubOptions) {
		containerDevice(o)
		o.ImagePolicy = signaturePolicy("docker.io")
		o.ImageResolver = &imagepolicy.RegistryResolver{
			Client:      reg.srv.Client(),
			Credentials: func(string) (imagepolicy.RegistryCredential, bool) { return imagepolicy.RegistryCredential{}, false },
			Endpoint:    func(string) string { return reg.srv.URL },
		}
		o.ImageVerifier = &imagepolicy.CosignVerifier{Binary: cosign}
	})
	ex := lb.executor(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	res, err := executor.Run(ctx, ex, executor.Spec{
		WorkDir: deviceWorkDir(t, lb),
		Argv:    []string{"/bin/sh", "-c", "echo verified-image-ran; grep '^ID=' /etc/os-release"},
		Image:   "docker.io/library/alpine:3.20",
	})
	if err != nil {
		t.Fatalf("Run: %v (output %q)", err, res.Output)
	}
	// Alpine's os-release, so the workload ran in the image rather than on
	// the device's host.
	if !strings.Contains(string(res.Output), "verified-image-ran") || !strings.Contains(string(res.Output), "ID=alpine") {
		t.Fatalf("the workload did not run in the verified image: %q", res.Output)
	}
	if want := "docker.io/library/alpine@" + digest; res.Handle.Image != want {
		t.Errorf("handle image = %q, want %q", res.Handle.Image, want)
	}

	reg.point("3.20", unsignedDigest)
	_, err = executor.Run(ctx, ex, executor.Spec{
		WorkDir: deviceWorkDir(t, lb), Argv: []string{"/bin/sh", "-c", "true"}, Image: "docker.io/library/alpine:3.20",
	})
	wantDenial(t, err, imagepolicy.RuleSignature)
}

// Compile-time: the stand-ins are what the hub takes.
var (
	_ imagepolicy.Resolver = (*tagResolver)(nil)
	_ imagepolicy.Verifier = (*countingVerifier)(nil)
)
