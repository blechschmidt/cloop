package imagepolicy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/provenance"
)

const (
	ownDigest   = "sha256:3ad7a636d68631752784810d823b827a1747022840f3c8877af15decc831b213"
	otherDigest = "sha256:0918c8d393a1345d4c9c0c088485b78cade867efd3493c290bdb1b225c324cd1"
)

// TestIsOwnImage: whole names on the parsed reference. The names of the
// near-misses are built rather than written out, because tests/docs holds every
// first-party image named in this tree to one the publishing workflow pushes.
func TestIsOwnImage(t *testing.T) {
	owner := "ghcr.io/blechschmidt/"
	for ref, want := range map[string]bool{
		"ghcr.io/blechschmidt/cloop-harness:latest":              true,
		"ghcr.io/blechschmidt/cloop-harness-copilot:0.0.8":       true,
		"ghcr.io/blechschmidt/cloop@" + ownDigest:                true,
		"ghcr.io/blechschmidt/cloop-harness:v1@" + ownDigest:     true,
		"GHCR.IO/blechschmidt/cloop-harness:latest":              true,
		owner + "cloop-harness" + "-evil:latest":                 false,
		owner + "cloop" + "x:1":                                  false,
		"ghcr.io/blechschmidt/cloop-harness/nested:1":            false,
		"ghcr.io.evil.example/blechschmidt/cloop-harness:latest": false,
		"evil.example/ghcr.io/blechschmidt/cloop-harness:latest": false,
		"docker.io/blechschmidt/cloop-harness:latest":            false,
		"blechschmidt/cloop-harness:latest":                      false,
		"ghcr.io/acme/cloop-harness:latest":                      false,
		"localhost/cloop-sandbox:abc":                            false,
		"":                                                       false,
		"--privileged":                                           false,
		"ghcr.io/blechschmidt/cloop-harness:latest; rm -rf /":    false,
		"ghcr.io/blechschmidt/cloop-harness:latest\n":            true, // trimmed, as configuration is
	} {
		if got := IsOwnImage(ref); got != want {
			t.Errorf("IsOwnImage(%q) = %t, want %t", ref, got, want)
		}
	}
}

// provResolver is a registry or a store: the digest each reference names.
type provResolver struct {
	digests map[string]string
	err     error
	calls   int
}

func (r *provResolver) ResolveDigest(_ context.Context, ref string) (string, error) {
	r.calls++
	if r.err != nil {
		return "", r.err
	}
	if d, ok := r.digests[ref]; ok {
		return d, nil
	}
	return "", fmt.Errorf("container: image %s is not present locally (fix: docker pull %s)", ref, ref)
}

// provVerifier answers a verdict per digest-pinned reference.
type provVerifier struct {
	verdicts map[string]ProvenanceVerdict
	asked    []string
}

func (v *provVerifier) VerifyProvenance(_ context.Context, ref string) ProvenanceVerdict {
	v.asked = append(v.asked, ref)
	if got, ok := v.verdicts[ref]; ok {
		return got
	}
	return ProvenanceVerdict{Status: ProvenanceUnsigned, Detail: "Error: no signatures found"}
}

func (v *provVerifier) TrustRoot() (string, string) {
	return provenance.DefaultIssuer, provenance.ImagesIdentityRegexp
}

const harness = "ghcr.io/blechschmidt/cloop-harness:latest"

func verifiedFor(refs ...string) *provVerifier {
	v := &provVerifier{verdicts: map[string]ProvenanceVerdict{}}
	for _, r := range refs {
		v.verdicts[r] = ProvenanceVerdict{Status: ProvenanceVerified, Detail: "ok"}
	}
	return v
}

// TestOwnImageCheckVerifiesAndPinsTheDefault is the property for the default
// image: the tag is resolved, the digest is what is verified, and the record
// names the digest-pinned reference a dispatch must run.
func TestOwnImageCheckVerifiesAndPinsTheDefault(t *testing.T) {
	pinned := "ghcr.io/blechschmidt/cloop-harness@" + ownDigest
	resolver := &provResolver{digests: map[string]string{harness: ownDigest}}
	verifier := verifiedFor(pinned)
	for _, required := range []bool{false, true} {
		p, err := OwnImageCheck{Image: harness, Resolver: resolver, Verifier: verifier, Required: required}.Run(context.Background())
		if err != nil {
			t.Fatalf("required=%t: %v", required, err)
		}
		if !p.Verified() || p.Ref != pinned || p.Digest != ownDigest || p.VerifiedDigest() != ownDigest || p.Warning != "" {
			t.Errorf("required=%t: %+v, want verified and pinned to %s", required, p, pinned)
		}
		if p.Identity != provenance.ImagesIdentityRegexp || p.Issuer != provenance.DefaultIssuer {
			t.Errorf("the record does not name the pin it was checked against: %+v", p)
		}
	}
	for _, asked := range verifier.asked {
		if asked != pinned {
			t.Errorf("the verifier was asked about %q; only a digest may be verified", asked)
		}
	}
}

// TestOwnImageCheckRefusesAWrongSignatureInEveryMode: present and wrong is
// never a warning.
func TestOwnImageCheckRefusesAWrongSignatureInEveryMode(t *testing.T) {
	pinned := "ghcr.io/blechschmidt/cloop-harness@" + ownDigest
	verifier := &provVerifier{verdicts: map[string]ProvenanceVerdict{pinned: {
		Status: ProvenanceMismatch,
		Detail: `failed to verify certificate identity: no matching CertificateIdentity found, last error: expected SAN value to match regex`,
	}}}
	for _, required := range []bool{false, true} {
		p, err := OwnImageCheck{Image: harness, Resolver: &provResolver{digests: map[string]string{harness: ownDigest}},
			Verifier: verifier, Required: required}.Run(context.Background())
		var denied *DenyError
		if !errors.As(err, &denied) || denied.Rule != RuleProvenance || !errors.Is(err, ErrDenied) {
			t.Fatalf("required=%t: err = %v, want a %s denial", required, err, RuleProvenance)
		}
		if p.Status != ProvenanceMismatch || !strings.Contains(denied.Reason, "no matching CertificateIdentity") ||
			!strings.Contains(denied.Remediation, "Do not run it") {
			t.Errorf("required=%t: the refusal does not carry cosign's diagnosis or the remedy: %v", required, err)
		}
		if denied.Malformed() {
			t.Error("a wrong signature is reported as a malformed reference")
		}
	}
}

// TestOwnImageCheckWarnsOrRefusesWhatIsNotVerified: an unsigned image, one with
// no registry digest, one the registry would not resolve, one with no verifier,
// and a tag where nothing can resolve one each run with a warning by default
// and are refused under required.
func TestOwnImageCheckWarnsOrRefusesWhatIsNotVerified(t *testing.T) {
	pinned := "ghcr.io/blechschmidt/cloop-harness@" + ownDigest
	for name, c := range map[string]struct {
		check  OwnImageCheck
		status ProvenanceStatus
		why    string
		remedy string
	}{
		"unsigned": {OwnImageCheck{Image: harness, Resolver: &provResolver{digests: map[string]string{harness: ownDigest}},
			Verifier: &provVerifier{}}, ProvenanceUnsigned, "no signatures found", "verify-image"},
		"locally built": {OwnImageCheck{Image: harness, Resolver: &provResolver{err: fmt.Errorf("%w: no repo digest", ErrNoDigest)},
			Verifier: verifiedFor(pinned)}, ProvenanceUnverifiable, "built locally", "Install cosign"},
		"registry unreachable": {OwnImageCheck{Image: harness, Resolver: &provResolver{err: fmt.Errorf("%w: ghcr.io is unreachable", ErrRegistry)},
			Verifier: verifiedFor(pinned)}, ProvenanceUnverifiable, "unreachable", "Install cosign"},
		"no verifier": {OwnImageCheck{Image: harness, Resolver: &provResolver{digests: map[string]string{harness: ownDigest}}},
			ProvenanceUnverifiable, "no signature verifier", "Install cosign"},
		"a tag on Kubernetes": {OwnImageCheck{Image: harness, Verifier: verifiedFor(pinned), Field: "executors.kubernetes.image"},
			ProvenanceUnverifiable, "cannot resolve a tag", "Pin executors.kubernetes.image by digest"},
	} {
		t.Run(name, func(t *testing.T) {
			p, err := c.check.Run(context.Background())
			if err != nil {
				t.Fatalf("warn mode refused: %v", err)
			}
			if p.Status != c.status || !strings.Contains(p.Detail, c.why) {
				t.Errorf("verdict = %s (%s), want %s naming %q", p.Status, p.Detail, c.status, c.why)
			}
			if !strings.Contains(p.Warning, c.why) || !strings.Contains(p.Warning, c.remedy) {
				t.Errorf("the run's warning %q does not say why (%q) and what to do (%q)", p.Warning, c.why, c.remedy)
			}
			if p.Verified() || p.VerifiedDigest() != "" {
				t.Error("an unverified image reads as verified")
			}

			c.check.Required = true
			_, err = c.check.Run(context.Background())
			var denied *DenyError
			if !errors.As(err, &denied) || denied.Rule != RuleProvenance {
				t.Fatalf("required: err = %v, want a %s denial", err, RuleProvenance)
			}
			if !strings.Contains(denied.Reason, "image_provenance is required") || !strings.Contains(denied.Remediation, c.remedy) {
				t.Errorf("required: the refusal does not name the setting and the remedy: %v", err)
			}
		})
	}
}

// TestOwnImageCheckPassesAMissingImageThrough: "the image is not present
// locally (fix: docker pull …)" is not a verdict on its signature, and the
// driver's own diagnostic is what the operator must see.
func TestOwnImageCheckPassesAMissingImageThrough(t *testing.T) {
	p, err := OwnImageCheck{Image: harness, Resolver: &provResolver{}, Verifier: &provVerifier{}, Required: true}.Run(context.Background())
	if err == nil || errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), "docker pull") {
		t.Fatalf("err = %v, want the store's own pull diagnostic", err)
	}
	if p.Status != "" {
		t.Errorf("a lookup failure was given a verdict: %s", p.Status)
	}
}

// TestOwnImageCheckRefusesAMalformedReferenceAsSyntax: a reference that is not
// one is the author's broken file, not a provenance verdict.
func TestOwnImageCheckRefusesAMalformedReferenceAsSyntax(t *testing.T) {
	_, err := OwnImageCheck{Image: "ghcr.io/blechschmidt/cloop-harness:la test", Resolver: &provResolver{},
		Verifier: &provVerifier{}}.Run(context.Background())
	var denied *DenyError
	if !errors.As(err, &denied) || !denied.Malformed() {
		t.Fatalf("err = %v, want a malformed-reference denial", err)
	}
}

// stubCosign writes a cosign that answers as the real one did when measured
// (cosign v2.6.3 and v3.1.4 against ghcr.io, Task 20453): mode "verified",
// "unsigned", "mismatch", "unreachable" or "hang". Each argument list is
// appended to the second return value's file, one per line.
func stubCosign(t *testing.T, mode string) (bin, calls string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the cosign stand-in is a POSIX shell script")
	}
	dir := t.TempDir()
	calls = filepath.Join(dir, "calls")
	var body string
	switch mode {
	case "verified":
		body = `echo "Verification for $ref --"; echo '[{"critical":{}}]'; exit 0`
	case "unsigned":
		body = `echo "Error: no signatures found" >&2; echo "error during command execution: no signatures found" >&2; exit 10`
	case "mismatch":
		body = `echo "Error: no matching attestations: failed to verify log inclusion: transparency log certificate does not match" >&2
echo 'failed to verify certificate identity: no matching CertificateIdentity found, last error: expected SAN value to match regex "x", got "keyless@projectsigstore.iam.gserviceaccount.com"' >&2
echo "error during command execution: no matching attestations" >&2; exit 1`
	case "unreachable":
		body = `echo 'Error: Get "https://ghcr.io/v2/": dial tcp: lookup ghcr.io on 127.0.0.53:53: no such host' >&2; exit 1`
	case "hang":
		body = `exec sleep 30`
	}
	script := "#!/bin/sh\necho \"$*\" >> '" + calls + "'\nref=\nfor a in \"$@\"; do ref=$a; done\n" + body + "\n"
	bin = filepath.Join(dir, "cosign")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, calls
}

func callCount(t *testing.T, calls string) int {
	t.Helper()
	b, err := os.ReadFile(calls)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(b), "\n")
}

// TestCosignProvenanceVerifierReadsCosignsAnswers: each of cosign's answers to
// the class it means, the pin on the command line, a digest after "--", and
// only a verified verdict from exit status 0.
func TestCosignProvenanceVerifierReadsCosignsAnswers(t *testing.T) {
	ref := "ghcr.io/blechschmidt/cloop-harness@" + ownDigest
	for mode, want := range map[string]ProvenanceStatus{
		"verified":    ProvenanceVerified,
		"unsigned":    ProvenanceUnsigned,
		"mismatch":    ProvenanceMismatch,
		"unreachable": ProvenanceUnverifiable,
	} {
		t.Run(mode, func(t *testing.T) {
			bin, calls := stubCosign(t, mode)
			got := (&CosignProvenanceVerifier{Binary: bin}).VerifyProvenance(context.Background(), ref)
			if got.Status != want {
				t.Fatalf("verdict = %+v, want %s", got, want)
			}
			if mode != "verified" && (got.Detail == "" || strings.Contains(got.Detail, "error during command execution")) {
				t.Errorf("the detail should keep cosign's own error and drop its repetition: %q", got.Detail)
			}
			b, _ := os.ReadFile(calls)
			args := string(b)
			for _, w := range []string{"verify", "--certificate-oidc-issuer " + provenance.DefaultIssuer,
				"--certificate-identity-regexp " + provenance.ImagesIdentityRegexp, "-- " + ref} {
				if !strings.Contains(args, w) {
					t.Errorf("cosign was run without %q: %s", w, args)
				}
			}
		})
	}
}

// TestCosignProvenanceVerifierNeverVerifiesATag: a tag reaches no cosign.
func TestCosignProvenanceVerifierNeverVerifiesATag(t *testing.T) {
	bin, calls := stubCosign(t, "verified")
	got := (&CosignProvenanceVerifier{Binary: bin}).VerifyProvenance(context.Background(), harness)
	if got.Status != ProvenanceUnverifiable || callCount(t, calls) != 0 {
		t.Fatalf("a tag = %+v after %d cosign runs, want unverifiable and none", got, callCount(t, calls))
	}
}

// TestCosignProvenanceVerifierWithoutCosign: absent is unverifiable, never a
// pass.
func TestCosignProvenanceVerifierWithoutCosign(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	got := (&CosignProvenanceVerifier{}).VerifyProvenance(context.Background(), "ghcr.io/blechschmidt/cloop-harness@"+ownDigest)
	if got.Status != ProvenanceUnverifiable || !strings.Contains(got.Detail, "cosign is not installed") {
		t.Fatalf("no cosign = %+v", got)
	}
}

// TestCosignProvenanceVerifierRemembersVerdictsButNotRefusals: a verified or
// unsigned digest is not re-run on the next dispatch; a mismatch, a refusal,
// is asked again every time.
func TestCosignProvenanceVerifierRemembersVerdictsButNotRefusals(t *testing.T) {
	ref := "ghcr.io/blechschmidt/cloop-harness@" + ownDigest
	for mode, runs := range map[string]int{"verified": 1, "unsigned": 1, "mismatch": 3} {
		bin, calls := stubCosign(t, mode)
		v := &CosignProvenanceVerifier{Binary: bin}
		for i := 0; i < 3; i++ {
			v.VerifyProvenance(context.Background(), ref)
		}
		if got := callCount(t, calls); got != runs {
			t.Errorf("%s: cosign ran %d times for three dispatches, want %d", mode, got, runs)
		}
		// Another pin is another question.
		if mode == "verified" {
			v.Identity = `^https://github\.com/acme/cloop/\.github/workflows/images\.yml@refs/heads/main$`
			v.VerifyProvenance(context.Background(), ref)
			if got := callCount(t, calls); got != 2 {
				t.Errorf("a changed pin reused the verdict reached under the old one (%d runs)", got)
			}
		}
	}
}

// TestCosignProvenanceVerifierIsBounded: a cosign that never answers costs a
// dispatch the timeout and is unverifiable.
func TestCosignProvenanceVerifierIsBounded(t *testing.T) {
	prev := provenanceTimeout
	provenanceTimeout = 300 * time.Millisecond
	t.Cleanup(func() { provenanceTimeout = prev })
	bin, _ := stubCosign(t, "hang")
	start := time.Now()
	got := (&CosignProvenanceVerifier{Binary: bin}).VerifyProvenance(context.Background(), "ghcr.io/blechschmidt/cloop@"+otherDigest)
	if got.Status != ProvenanceUnverifiable || time.Since(start) > 10*time.Second {
		t.Fatalf("a hung cosign = %+v after %s", got, time.Since(start))
	}
}

// TestRecentProvenanceKeepsTheLatestPerImage feeds the doctor.
func TestRecentProvenanceKeepsTheLatestPerImage(t *testing.T) {
	ResetRecentProvenance()
	t.Cleanup(ResetRecentProvenance)
	old := Provenance{Image: harness, Status: ProvenanceUnsigned, CheckedAt: time.Now().Add(-time.Minute)}
	newer := Provenance{Image: harness, Status: ProvenanceVerified, CheckedAt: time.Now()}
	RecordProvenance("container", old)
	RecordProvenance("container", newer)
	RecordProvenance("edge-1", old)
	got := RecentProvenance()
	if len(got) != 2 || got[0].Executor != "container" || got[0].Status != ProvenanceVerified || got[1].Executor != "edge-1" {
		t.Fatalf("RecentProvenance = %+v", got)
	}
}

// TestCosignVersionReadsTheBuildWithoutRunningIt: a Go binary stamped the way
// cosign's release builds stamp themselves, and something that is not a Go
// program at all.
func TestCosignVersionReadsTheBuildWithoutRunningIt(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("needs the go toolchain to build a stand-in")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/fakecosign\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Exits at once: the test must prove the version is read, not executed.
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() { panic(\"executed\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "cosign")
	build := exec.Command(gobin, "build", "-ldflags", "-X sigs.k8s.io/release-utils/version.gitVersion=v3.1.4", "-o", out, ".")
	build.Dir = dir
	build.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	if v, err := CosignVersion(out); err != nil || v != "v3.1.4" {
		t.Fatalf("CosignVersion = %q, %v; want v3.1.4", v, err)
	}
	script := filepath.Join(dir, "script")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho v9\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if v, err := CosignVersion(script); err == nil {
		t.Fatalf("a shell script reported version %q", v)
	}
}
