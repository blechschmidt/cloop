package imagepolicy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeResolver stands in for a local image store.
type fakeResolver struct {
	digest string
	err    error
	calls  atomic.Int32
	sawRef atomic.Value // string
}

func (f *fakeResolver) ResolveDigest(_ context.Context, ref string) (string, error) {
	f.calls.Add(1)
	f.sawRef.Store(ref)
	return f.digest, f.err
}

// TestAuthorizePinsAnAcceptedTag is the TOCTOU property.
//
// The tag was acceptable at the moment it was evaluated. What the caller runs
// must be the artifact that tag named *then*, not whatever it names when a
// runtime gets round to pulling it — so Authorize returns a digest reference
// and the tag never reaches the executor.
func TestAuthorizePinsAnAcceptedTag(t *testing.T) {
	res := &fakeResolver{digest: goodDigest}
	e := Enforcer{
		Policy:   Policy{AllowedRegistries: []string{"ghcr.io"}},
		Resolver: res,
	}

	got, err := e.Authorize(context.Background(), "ghcr.io/acme/tools:3.12")
	if err != nil {
		t.Fatal(err)
	}
	want := "ghcr.io/acme/tools@" + goodDigest
	if got.Ref != want {
		t.Fatalf("Authorize().Ref = %q, want the pinned %q", got.Ref, want)
	}
	if !got.Pinned() || got.Digest != goodDigest {
		t.Fatalf("Authorize().Digest = %q, want %q", got.Digest, goodDigest)
	}
	if strings.Contains(got.Ref, ":3.12") {
		t.Errorf("the mutable tag survived into the reference the caller will run: %q", got.Ref)
	}
	if n := res.calls.Load(); n != 1 {
		t.Errorf("resolver called %d times, want exactly 1 — pinning must not be re-done per use", n)
	}
}

// TestAuthorizeRecheckesThePinnedReference: resolution is a step where a
// reference could in principle change identity. The verdict must be re-reached
// on what will actually run, not inherited from what was asked for.
func TestAuthorizeRecheckesThePinnedReference(t *testing.T) {
	// A resolver whose digest is fine, but whose *policy* stopped allowing the
	// repository between the two evaluations, stands in for the general case.
	// Here: the second Evaluate sees the canonical form, which drops the tag —
	// a policy keyed on the tag would silently pass it. Assert the recheck runs
	// by making the resolver return a digest the policy cannot accept.
	e := Enforcer{
		Policy:   Policy{AllowedRegistries: []string{"ghcr.io"}},
		Resolver: &fakeResolver{digest: "sha256:short"},
	}
	_, err := e.Authorize(context.Background(), "ghcr.io/acme/tools:1")
	if err == nil {
		t.Fatal("a resolver returning an unusable digest was accepted")
	}
	if !strings.Contains(err.Error(), "unusable digest") {
		t.Errorf("error = %q, want it to name the resolver's bad digest", err)
	}
}

// TestAuthorizeWithoutAResolverKeepsTheTagAndSaysSo.
//
// The Kubernetes backend has no local image store. A hub that does not require
// digests still runs there, but the run is not reproducible and the operator
// must be told rather than left to infer it.
func TestAuthorizeWithoutAResolverKeepsTheTagAndSaysSo(t *testing.T) {
	e := Enforcer{Policy: Policy{AllowedRegistries: []string{"ghcr.io"}}}

	got, err := e.Authorize(context.Background(), "ghcr.io/acme/tools:1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Pinned() {
		t.Fatal("Authorize claimed a pin with no resolver to produce one")
	}
	if got.Ref != "ghcr.io/acme/tools:1" {
		t.Fatalf("Authorize().Ref = %q, want the original reference", got.Ref)
	}
	if len(got.Warnings) == 0 {
		t.Error("an unpinnable image produced no warning; the operator has no way to know")
	}
}

// TestRequireDigestIsEnforcedBeforeAnythingRuns: with require_digest set, a tag
// is refused at evaluation. It must never reach the resolver, because on an
// executor with no resolver that would be the difference between a config error
// and a silently unpinned Pod.
func TestRequireDigestIsEnforcedBeforeAnythingRuns(t *testing.T) {
	res := &fakeResolver{digest: goodDigest}
	e := Enforcer{
		Policy:   Policy{AllowedRegistries: []string{"ghcr.io"}, RequireDigest: true},
		Resolver: res,
	}
	_, err := e.Authorize(context.Background(), "ghcr.io/acme/tools:1")
	if err == nil {
		t.Fatal("a tag reference was accepted under require_digest")
	}
	var denied *DenyError
	if !errors.As(err, &denied) || denied.Rule != RuleDigest {
		t.Fatalf("error = %v, want a %s denial", err, RuleDigest)
	}
	if n := res.calls.Load(); n != 0 {
		t.Errorf("the resolver ran %d times for a reference the policy had already refused", n)
	}
}

// TestUnpinnableImageCannotBeSignatureVerified: a locally built image has no
// registry digest, so there is nothing to check a signature against. That is a
// refusal, not a pass.
func TestUnpinnableImageCannotBeSignatureVerified(t *testing.T) {
	e := Enforcer{
		Policy: Policy{
			AllowedRegistries: []string{"ghcr.io"},
			RequireSignature:  true,
			CosignPublicKeys:  []string{"/etc/cloop/cosign.pub"},
		},
		Resolver: &fakeResolver{err: ErrNoDigest},
		Verifier: alwaysVerifies{},
	}
	_, err := e.Authorize(context.Background(), "ghcr.io/acme/tools:1")
	if err == nil {
		t.Fatal("an image with no digest was signature-verified")
	}
	var denied *DenyError
	if !errors.As(err, &denied) || denied.Rule != RuleSignature {
		t.Fatalf("error = %v, want a %s denial", err, RuleSignature)
	}
}

// TestResolverFailureIsNotAPolicyDenial: "the image is not present" and "the
// image is not allowed" are different problems for different people. Flattening
// them sends an operator to edit an allowlist that was never the issue.
func TestResolverFailureIsNotAPolicyDenial(t *testing.T) {
	missing := errors.New("image is not present locally (fix: podman pull …)")
	e := Enforcer{
		Policy:   Policy{AllowedRegistries: []string{"ghcr.io"}},
		Resolver: &fakeResolver{err: missing},
	}
	_, err := e.Authorize(context.Background(), "ghcr.io/acme/tools:1")
	if !errors.Is(err, missing) {
		t.Fatalf("error = %v, want the driver's own diagnostic", err)
	}
	if errors.Is(err, ErrDenied) {
		t.Error("a missing image was reported as a policy denial")
	}
}

type alwaysVerifies struct{}

func (alwaysVerifies) Verify(context.Context, string, Policy) error { return nil }

type neverVerifies struct{ err error }

func (n neverVerifies) Verify(context.Context, string, Policy) error { return n.err }

// TestSignatureVerificationRunsOnTheDigest: cosign must be handed the pinned
// reference. Verifying a tag verifies whatever it pointed at during the check.
func TestSignatureVerificationRunsOnTheDigest(t *testing.T) {
	var saw string
	e := Enforcer{
		Policy: Policy{
			AllowedRegistries: []string{"ghcr.io"},
			RequireSignature:  true,
			CosignPublicKeys:  []string{"/k.pub"},
		},
		Resolver: &fakeResolver{digest: goodDigest},
		Verifier: verifierFunc(func(_ context.Context, ref string, _ Policy) error {
			saw = ref
			return nil
		}),
	}
	got, err := e.Authorize(context.Background(), "ghcr.io/acme/tools:1")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Verified {
		t.Error("Result.Verified is false after a passing verification")
	}
	if saw != "ghcr.io/acme/tools@"+goodDigest {
		t.Fatalf("verifier saw %q, want the digest-pinned reference", saw)
	}
}

type verifierFunc func(context.Context, string, Policy) error

func (f verifierFunc) Verify(ctx context.Context, ref string, p Policy) error { return f(ctx, ref, p) }

// TestMissingVerifierFailsClosed is the property this whole file exists for: a
// hub that cannot verify signatures must refuse images, not admit them
// unverified. The difference is invisible in every other observable — both look
// like a hub that started fine.
func TestMissingVerifierFailsClosed(t *testing.T) {
	e := Enforcer{
		Policy: Policy{
			AllowedRegistries: []string{"ghcr.io"},
			RequireSignature:  true,
			CosignPublicKeys:  []string{"/k.pub"},
		},
		Resolver: &fakeResolver{digest: goodDigest},
		Verifier: nil, // cosign was never wired up
	}
	_, err := e.Authorize(context.Background(), "ghcr.io/acme/tools@"+goodDigest)
	if err == nil {
		t.Fatal("require_signature with no verifier admitted an unverified image")
	}
	var denied *DenyError
	if !errors.As(err, &denied) || denied.Rule != RuleSignature {
		t.Fatalf("error = %v, want a %s denial", err, RuleSignature)
	}
	if !strings.Contains(strings.ToLower(denied.Remediation), "cosign") {
		t.Errorf("remediation %q does not tell the operator to install cosign", denied.Remediation)
	}
}

// TestCosignMissingFailsClosed drives the real verifier with a PATH that has no
// cosign on it. Skipping verification when the binary is absent is the specific
// bug this asserts against: it produces a hub that reports every image as fine
// while checking nothing.
func TestCosignMissingFailsClosed(t *testing.T) {
	// An empty PATH makes exec.LookPath fail the same way a host without
	// cosign installed does.
	t.Setenv("PATH", t.TempDir())

	v := NewCosignVerifier()
	p := Policy{
		AllowedRegistries: []string{"ghcr.io"},
		RequireSignature:  true,
		CosignPublicKeys:  []string{"/k.pub"},
	}
	err := v.Verify(context.Background(), "ghcr.io/acme/tools@"+goodDigest, p)
	if err == nil {
		t.Fatal("verification passed with no cosign installed")
	}
	if !errors.Is(err, ErrCosignMissing) {
		t.Errorf("errors.Is(err, ErrCosignMissing) = false: %v", err)
	}
	if !errors.Is(err, ErrDenied) {
		t.Errorf("a missing cosign must read as a denial, not a neutral error: %v", err)
	}
	if !strings.Contains(err.Error(), "sigstore.dev") {
		t.Errorf("error %q does not point at an installation guide", err)
	}

	// And through the Enforcer, which is how a driver reaches it.
	e := Enforcer{Policy: p, Verifier: v}
	if _, err := e.Authorize(context.Background(), "ghcr.io/acme/tools@"+goodDigest); err == nil {
		t.Fatal("Authorize admitted an image with no cosign installed")
	}
}

// TestCosignVerifierDrivesTheBinary uses a stub script so the argv construction
// is exercised without a real registry: the digest must be the final argument,
// after a "--" terminator.
func TestCosignVerifierDrivesTheBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stub is POSIX")
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "argv")
	stub := filepath.Join(dir, "cosign")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + out + "\nexit 0\n"
	if err := os.WriteFile(stub, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	v := &CosignVerifier{Binary: stub}
	ref := "ghcr.io/acme/tools@" + goodDigest
	p := Policy{RequireSignature: true, CosignPublicKeys: []string{"/etc/cloop/cosign.pub"}}
	if err := v.Verify(context.Background(), ref, p); err != nil {
		t.Fatalf("Verify with a passing cosign: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	argv := strings.Split(strings.TrimSpace(string(data)), "\n")
	if argv[0] != "verify" {
		t.Errorf("argv[0] = %q, want \"verify\"", argv[0])
	}
	if argv[len(argv)-1] != ref {
		t.Errorf("last argument = %q, want the reference %q", argv[len(argv)-1], ref)
	}
	if argv[len(argv)-2] != "--" {
		t.Errorf("the reference is not preceded by \"--\": %v", argv)
	}
	if !contains(argv, "--key") || !contains(argv, "/etc/cloop/cosign.pub") {
		t.Errorf("argv does not carry the configured key: %v", argv)
	}

	// A second call must not re-spawn: verification of a digest is cached.
	if err := os.Remove(stub); err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(context.Background(), ref, p); err != nil {
		t.Fatalf("a verified digest was not cached: %v", err)
	}
	// …but a policy change must invalidate it, or a key rotation would be
	// ignored until the process restarts.
	rotated := Policy{RequireSignature: true, CosignPublicKeys: []string{"/etc/cloop/new.pub"}}
	if err := v.Verify(context.Background(), ref, rotated); err == nil {
		t.Fatal("a rotated key reused the cached verdict from the old one")
	}
}

// TestCosignFailureIsReportedNotSwallowed: a non-zero cosign exit is a denial
// carrying cosign's own last line, which is where its diagnosis lives.
func TestCosignFailureIsReportedNotSwallowed(t *testing.T) {
	e := Enforcer{
		Policy: Policy{
			RequireSignature: true,
			CosignPublicKeys: []string{"/k.pub"},
		},
		Verifier: neverVerifies{err: errors.New("no matching signatures")},
	}
	_, err := e.Authorize(context.Background(), "ghcr.io/acme/tools@"+goodDigest)
	if err == nil {
		t.Fatal("an unsigned image was accepted")
	}
	if !strings.Contains(err.Error(), "no matching signatures") {
		t.Errorf("error %q lost the verifier's diagnosis", err)
	}
	var denied *DenyError
	if !errors.As(err, &denied) || denied.Rule != RuleSignature {
		t.Fatalf("error = %v, want a %s denial", err, RuleSignature)
	}
}

// TestUnconfiguredPolicyStillPins: pinning is worth doing whether or not an
// allowlist exists, so a hub with no policy at all still records what ran.
func TestUnconfiguredPolicyStillPins(t *testing.T) {
	e := Enforcer{Resolver: &fakeResolver{digest: goodDigest}}
	got, err := e.Authorize(context.Background(), "ghcr.io/acme/tools:1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Ref != "ghcr.io/acme/tools@"+goodDigest {
		t.Fatalf("Authorize().Ref = %q, want the pinned form", got.Ref)
	}
}

func contains(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}
