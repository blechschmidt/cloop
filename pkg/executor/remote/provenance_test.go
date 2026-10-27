package remote_test

// provenance_test.go: the hub's check of cloop's own images on the device path
// (Task 20453). A device whose sandbox runs a container runs an image the
// device's own store holds and the hub cannot read, so the hub resolves the tag
// at its registry — imagepolicy.RegistryResolver, here a stand-in — verifies
// the digest against the workflow that publishes cloop's images, and the start
// frame names the digest it verified. The device's driver never pulls and
// inspects exactly the reference it is given.

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
	"github.com/blechschmidt/cloop/pkg/provenance"
)

// harnessDigest is the digest the stand-in registry serves for the default.
const harnessDigest = "sha256:3ad7a636d68631752784810d823b827a1747022840f3c8877af15decc831b213"

var pinnedHarness = "ghcr.io/blechschmidt/cloop-harness@" + harnessDigest

// deviceVerifier answers one verdict for every digest and counts the asks.
type deviceVerifier struct {
	verdict imagepolicy.ProvenanceVerdict
	asked   atomic.Int32
}

func (v *deviceVerifier) VerifyProvenance(_ context.Context, ref string) imagepolicy.ProvenanceVerdict {
	v.asked.Add(1)
	if !strings.Contains(ref, "@sha256:") {
		return imagepolicy.ProvenanceVerdict{Status: imagepolicy.ProvenanceUnverifiable, Detail: "asked about a tag"}
	}
	return v.verdict
}

func (v *deviceVerifier) TrustRoot() (string, string) {
	return provenance.DefaultIssuer, provenance.ImagesIdentityRegexp
}

func deviceVerdict(s imagepolicy.ProvenanceStatus, detail string) *deviceVerifier {
	return &deviceVerifier{verdict: imagepolicy.ProvenanceVerdict{Status: s, Detail: detail}}
}

// ownImageDevice is a device whose sandbox is s, on a hub that resolves with
// resolver and verifies cloop's images with verifier, under policy.
func ownImageDevice(t *testing.T, s executor.SandboxSettings, resolver imagepolicy.Resolver,
	verifier imagepolicy.ProvenanceVerifier, policy func() (imagepolicy.Policy, error)) (*remote.Executor, *peer) {
	t.Helper()
	if policy == nil {
		policy = func() (imagepolicy.Policy, error) { return imagepolicy.Policy{}, nil }
	}
	hello := helloAt(remote.ProtocolVersion)
	hello.Capabilities.Virtualization = true
	ex, err := remote.NewExecutor(remote.Options{
		ID: "agent-1", Name: "edge-1",
		Sandbox:            func() (executor.SandboxSettings, error) { return s, nil },
		ImagePolicy:        policy,
		ImageResolver:      resolver,
		ProvenanceVerifier: verifier,
		VerifyOwnImages:    true,
	})
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, hello, nil)
	t.Cleanup(func() { _ = sess.Close() })
	// The verdicts are the process's; start from none, and leave none behind.
	imagepolicy.ResetRecentProvenance()
	t.Cleanup(imagepolicy.ResetRecentProvenance)
	return ex, p
}

func setRequired(t *testing.T, required bool) {
	t.Helper()
	prev := executor.SetImageProvenanceRequired(required)
	t.Cleanup(func() { executor.SetImageProvenanceRequired(prev) })
}

func defaultRegistry() *tagResolver {
	return &tagResolver{digests: map[string]string{executor.DefaultHarnessImage: harnessDigest}}
}

// TestADeviceRunsTheDigestTheHubVerified: a container-mode device with no image
// of its own runs the default; the hub resolves it at the registry, verifies
// the digest, and the start frame names that digest.
func TestADeviceRunsTheDigestTheHubVerified(t *testing.T) {
	setRequired(t, true)
	verifier := deviceVerdict(imagepolicy.ProvenanceVerified, "ok")
	ex, p := ownImageDevice(t, containerMode, defaultRegistry(), verifier, nil)
	sent := answerStart(t, p)
	h, err := ex.Start(context.Background(), plainSpec(t.TempDir()))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	payload := <-sent
	if payload.Spec.Image != pinnedHarness {
		t.Fatalf("the start frame names %q, want the verified digest %q", payload.Spec.Image, pinnedHarness)
	}
	if h.Image != pinnedHarness || !h.ImageProvenance.Verified() || h.ImageProvenance.VerifiedDigest() != harnessDigest {
		t.Errorf("handle = %q with %+v, want the verified digest recorded", h.Image, h.ImageProvenance)
	}
	if recs := imagepolicy.RecentProvenance(); len(recs) != 1 || recs[0].Executor != "agent-1" || !recs[0].Verified() {
		t.Errorf("the verdict was not recorded for the doctor: %+v", recs)
	}
}

// TestADeviceIsNeverSentAWronglySignedImage: in both modes, and for the
// device's configured image, the default and an image a project names.
func TestADeviceIsNeverSentAWronglySignedImage(t *testing.T) {
	for _, required := range []bool{false, true} {
		setRequired(t, required)
		resolver := &tagResolver{digests: map[string]string{
			executor.DefaultHarnessImage:                       harnessDigest,
			"ghcr.io/blechschmidt/cloop-harness-copilot:0.0.8": harnessDigest,
		}}
		for name, c := range map[string]struct {
			sandbox executor.SandboxSettings
			image   string
		}{
			"the default":              {containerMode, ""},
			"the device's image":       {executor.SandboxSettings{Mode: executor.SandboxModeContainer, Image: "ghcr.io/blechschmidt/cloop-harness-copilot:0.0.8"}, ""},
			"an image a project names": {containerMode, "ghcr.io/blechschmidt/cloop-harness-copilot:0.0.8"},
		} {
			ex, p := ownImageDevice(t, c.sandbox, resolver,
				deviceVerdict(imagepolicy.ProvenanceMismatch, "no matching CertificateIdentity found"), nil)
			spec := plainSpec(t.TempDir())
			spec.Image = c.image
			_, err := ex.Start(context.Background(), spec)
			denied := wantDenial(t, err, imagepolicy.RuleProvenance)
			if !strings.Contains(denied.Reason, "no matching CertificateIdentity") {
				t.Errorf("required=%t, %s: the refusal lost cosign's diagnosis: %v", required, name, err)
			}
			noStartFrame(t, p, 200*time.Millisecond)
		}
	}
}

// TestAnUnsignedDeviceImageWarnsOrIsRefused: by default the device runs the
// tag it holds, with the warning on the run's log — a digest the hub could not
// verify would only strand a device holding an older copy — and under required
// it is refused before anything reaches the device. A registry the hub cannot
// reach is the same.
func TestAnUnsignedDeviceImageWarnsOrIsRefused(t *testing.T) {
	for name, c := range map[string]struct {
		resolver *tagResolver
		verifier *deviceVerifier
		why      string
	}{
		"unsigned": {defaultRegistry(), deviceVerdict(imagepolicy.ProvenanceUnsigned, "Error: no signatures found"),
			"no signatures found"},
		"registry unreachable": {&tagResolver{err: fmt.Errorf("%w: ghcr.io is unreachable from this host",
			imagepolicy.ErrRegistry)}, deviceVerdict(imagepolicy.ProvenanceVerified, "ok"), "unreachable"},
	} {
		t.Run(name, func(t *testing.T) {
			setRequired(t, false)
			ex, p := ownImageDevice(t, containerMode, c.resolver, c.verifier, nil)
			sent := answerStart(t, p)
			h, err := ex.Start(context.Background(), plainSpec(t.TempDir()))
			if err != nil {
				t.Fatalf("warn: Start: %v", err)
			}
			if got := (<-sent).Spec.Image; got != "" {
				t.Errorf("warn: the start frame names %q; an unverified image is left to the device's own pin", got)
			}
			if h.ImageProvenance == nil || h.ImageProvenance.Verified() || !strings.Contains(h.ImageProvenance.Warning, c.why) {
				t.Errorf("warn: handle provenance = %+v", h.ImageProvenance)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			lines, err := ex.Stream(ctx, h.ID)
			if err != nil {
				t.Fatalf("Stream: %v", err)
			}
			if first := <-lines; !strings.Contains(first.Text, "warning: ") || !strings.Contains(first.Text, c.why) {
				t.Errorf("the run's log does not open with the warning: %q", first.Text)
			}

			setRequired(t, true)
			ex, p = ownImageDevice(t, containerMode, c.resolver, c.verifier, nil)
			_, err = ex.Start(context.Background(), plainSpec(t.TempDir()))
			wantDenial(t, err, imagepolicy.RuleProvenance)
			noStartFrame(t, p, 200*time.Millisecond)
		})
	}
}

// TestAVirtualExecutorsCloopImageIsVerified: a virtual executor's own sandbox
// image, held to the same pin, and dispatched as the verified digest.
func TestAVirtualExecutorsCloopImageIsVerified(t *testing.T) {
	setRequired(t, true)
	const copilot = "ghcr.io/blechschmidt/cloop-harness-copilot:latest"
	resolver := &tagResolver{digests: map[string]string{copilot: harnessDigest}}
	parent, p := ownImageDevice(t, executor.SandboxSettings{Mode: executor.SandboxModeHost}, resolver,
		deviceVerdict(imagepolicy.ProvenanceVerified, "ok"), nil)
	v := virtualOver(t, parent, "vx-copilot", executor.VirtualSpec{
		Sandbox: executor.SandboxSettings{Mode: executor.SandboxModeContainer, Engine: "docker", Image: copilot},
	})
	sent := answerStart(t, p)
	h, err := v.Start(context.Background(), plainSpec(t.TempDir()))
	if err != nil {
		t.Fatalf("Start through the virtual executor: %v", err)
	}
	payload := <-sent
	if want := "ghcr.io/blechschmidt/cloop-harness-copilot@" + harnessDigest; payload.Spec.Image != want ||
		payload.Sandbox.Image != copilot {
		t.Errorf("start frame image = %q over sandbox image %q, want %q", payload.Spec.Image, payload.Sandbox.Image, want)
	}
	if !h.ImageProvenance.Verified() {
		t.Errorf("handle provenance = %+v", h.ImageProvenance)
	}
	if recs := imagepolicy.RecentProvenance(); len(recs) != 1 || recs[0].Executor != "vx-copilot" {
		t.Errorf("recorded as %+v, want the virtual executor", recs)
	}
}

// TestAHostModeDeviceRunsNoImageToCheck: no container, no image, nothing asked.
func TestAHostModeDeviceRunsNoImageToCheck(t *testing.T) {
	setRequired(t, true)
	resolver := defaultRegistry()
	verifier := deviceVerdict(imagepolicy.ProvenanceMismatch, "never asked")
	ex, p := ownImageDevice(t, executor.SandboxSettings{Mode: executor.SandboxModeHost}, resolver, verifier, nil)
	sent := answerStart(t, p)
	h, err := ex.Start(context.Background(), plainSpec(t.TempDir()))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	<-sent
	if resolver.calls.Load() != 0 || verifier.asked.Load() != 0 || h.ImageProvenance != nil {
		t.Errorf("a host-mode dispatch resolved %d and verified %d images", resolver.calls.Load(), verifier.asked.Load())
	}
}

// TestADevicesOwnImageIsGovernedOnlyWhenAsked: the device's image that is not
// cloop's is left alone, and under govern_operator_images held to the project
// rules: refused off the allowlist, and dispatched as the verified digest under
// require_signature.
func TestADevicesOwnImageIsGovernedOnlyWhenAsked(t *testing.T) {
	setRequired(t, false)
	cosign, _ := stubCosign(t, signedDigest)
	mode := executor.SandboxSettings{Mode: executor.SandboxModeContainer, Image: "ghcr.io/acme/base:1"}
	resolver := &tagResolver{digests: map[string]string{"ghcr.io/acme/base:1": signedDigest}}
	policy := func(govern bool, registry string) func() (imagepolicy.Policy, error) {
		return func() (imagepolicy.Policy, error) {
			return imagepolicy.Policy{AllowedRegistries: []string{registry}, RequireSignature: true,
				CosignPublicKeys: []string{"/etc/cloop/cosign.pub"}, GovernOperatorImages: govern}, nil
		}
	}
	verifier := &countingVerifier{inner: &imagepolicy.CosignVerifier{Binary: cosign}}
	build := func(p func() (imagepolicy.Policy, error)) (*remote.Executor, *peer) {
		hello := helloAt(remote.ProtocolVersion)
		ex, err := remote.NewExecutor(remote.Options{ID: "agent-1", Name: "edge-1",
			Sandbox:     func() (executor.SandboxSettings, error) { return mode, nil },
			ImagePolicy: p, ImageResolver: resolver, ImageVerifier: verifier, VerifyOwnImages: true,
			ProvenanceVerifier: deviceVerdict(imagepolicy.ProvenanceMismatch, "never asked")})
		if err != nil {
			t.Fatal(err)
		}
		peer, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, hello, nil)
		t.Cleanup(func() { _ = sess.Close() })
		return ex, peer
	}

	ex, p := build(policy(false, "quay.io"))
	sent := answerStart(t, p)
	if _, err := ex.Start(context.Background(), plainSpec(t.TempDir())); err != nil {
		t.Fatalf("ungoverned: %v", err)
	}
	if got := (<-sent).Spec.Image; got != "" || verifier.calls.Load() != 0 {
		t.Errorf("ungoverned: start frame image %q after %d verifications", got, verifier.calls.Load())
	}

	ex, p = build(policy(true, "quay.io"))
	_, err := ex.Start(context.Background(), plainSpec(t.TempDir()))
	wantDenial(t, err, imagepolicy.RuleRegistry)
	noStartFrame(t, p, 200*time.Millisecond)

	ex, p = build(policy(true, "ghcr.io"))
	sent = answerStart(t, p)
	if _, err := ex.Start(context.Background(), plainSpec(t.TempDir())); err != nil {
		t.Fatalf("governed and signed: %v", err)
	}
	if got := (<-sent).Spec.Image; got != "ghcr.io/acme/base@"+signedDigest {
		t.Errorf("governed: start frame image %q, want the verified digest", got)
	}
}

// TestWithoutVerifyOwnImagesTheDeviceIsLeftToItsOwnPin: an executor built
// outside a hub asks no registry anything — the hub is what sets the switch.
func TestWithoutVerifyOwnImagesTheDeviceIsLeftToItsOwnPin(t *testing.T) {
	setRequired(t, true)
	resolver := defaultRegistry()
	hello := helloAt(remote.ProtocolVersion)
	ex, err := remote.NewExecutor(remote.Options{ID: "agent-1", Name: "edge-1",
		Sandbox:            func() (executor.SandboxSettings, error) { return containerMode, nil },
		ImageResolver:      resolver,
		ProvenanceVerifier: deviceVerdict(imagepolicy.ProvenanceMismatch, "never asked")})
	if err != nil {
		t.Fatal(err)
	}
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, hello, nil)
	t.Cleanup(func() { _ = sess.Close() })
	sent := answerStart(t, p)
	h, err := ex.Start(context.Background(), plainSpec(t.TempDir()))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := (<-sent).Spec.Image; got != "" || resolver.calls.Load() != 0 || h.ImageProvenance != nil {
		t.Errorf("start frame image %q after %d resolutions, provenance %+v", got, resolver.calls.Load(), h.ImageProvenance)
	}
}
