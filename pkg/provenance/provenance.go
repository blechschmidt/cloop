// Package provenance verifies that a release artifact was built and signed by
// cloop's own release workflow, rather than merely arriving intact.
//
// # Why a checksum is not enough
//
// The release publishes checksums.txt beside the archives, and both the
// installer and `cloop upgrade` check the download against it. That check is
// worth keeping — it catches a truncated download and a corrupted mirror —
// but it proves transport integrity and nothing more. checksums.txt is fetched
// from the same GitHub release as the artifact it vouches for, so anyone who
// can replace the asset can replace the checksum alongside it and both sides
// of the comparison move together. The verification passes and says nothing.
//
// Provenance is the property the checksum cannot express: not "these are the
// bytes someone published" but "these are the bytes *our release workflow*
// produced". That distinction is what this package exists for, and it matters
// here more than in most projects, because the artifact being installed is the
// executor agent — the component an enterprise deliberately places on
// high-value hosts and then hands credentials to.
//
// # Keyless, and what is actually pinned
//
// Signing is Sigstore keyless: the release workflow proves its identity to
// Fulcio with the ambient GitHub Actions OIDC token and receives a short-lived
// certificate naming the workflow that requested it. There is no long-lived
// private key to leak, rotate, or store in a repository secret — the signing
// identity is the workflow file itself.
//
// Verification therefore pins two things, and both are necessary:
//
//   - The OIDC issuer, so only GitHub's token service can vouch for identity.
//     Without this an attacker could present a certificate from any issuer
//     Fulcio federates with and satisfy the identity match with, say, an
//     email address they control.
//   - The certificate identity, so only *this repository's release workflow*
//     on a tag is accepted. A signature from another workflow in this repo, a
//     fork, or a branch build fails — which is the point: an attacker who can
//     replace a release asset still cannot make our tagged release workflow
//     sign their bytes.
//
// # A subprocess, not a library
//
// pkg/imagepolicy reached this conclusion first and for the same reasons, so
// this package follows it: sigstore's Go verification path pulls Fulcio,
// Rekor, TUF and a certificate chain implementation into the process, and
// here that process is `cloop upgrade` replacing its own binary. cosign is a
// single static binary, it is what the sigstore documentation describes, and
// it is what an operator will reach for by hand when a verification fails and
// they want to know why.
//
// # Fail closed, including when the tool is absent
//
// The dangerous failure is not a bad signature — that is a clean refusal. It
// is "cosign is not installed", which the obvious implementation turns into a
// skipped check: every artifact reports fine while nothing is verified, and
// the misconfiguration is invisible precisely because it looks like success.
// So a missing cosign is a refusal with an install hint, never a warning.
//
// The escape hatch is explicit and separate: callers that set SkipVerify have
// made a decision a human can find in a command line or a unit file, which is
// the property a silent degradation lacks.
package provenance

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// CosignBinary is the executable looked up on PATH.
const CosignBinary = "cosign"

// BundleSuffix is appended to an artifact's name to form its bundle's name.
//
// One file per artifact, rather than the detached .sig/.pem pair cosign v1 and
// v2 produced: a Sigstore bundle carries the signature, the signing
// certificate and the Rekor inclusion proof together, so the transparency-log
// evidence travels with the signature instead of having to be re-fetched at
// verification time. cosign v3 removed --output-signature and
// --output-certificate from sign-blob, so this is also the only shape the
// current tool emits.
const BundleSuffix = ".sigstore.json"

// The trust root. These two constants are the whole of what is trusted; every
// other check in the install and upgrade paths is integrity, not provenance.
const (
	// DefaultIssuer is GitHub's OIDC token service, the only issuer whose
	// assertions about a workflow's identity are accepted.
	DefaultIssuer = "https://token.actions.githubusercontent.com"

	// DefaultIdentityRegexp matches the SAN Fulcio issues to this repository's
	// release workflow when it runs on a tag.
	//
	// Anchored at both ends, and `[^/]+` rather than `.*` for the tag, so it
	// cannot be satisfied by a longer path that merely begins this way — a
	// workflow reachable at .../release.yml@refs/tags/v1/../../heads/main
	// would otherwise match. The literal dots in the workflow path are escaped
	// for the same reason: unescaped, `.github` matches `xgithub`.
	//
	// refs/tags, not refs/heads: a release is cut from a tag, so a signature
	// produced by this same workflow running on a branch is rejected. That
	// closes the path where someone who can push a branch — but not tag a
	// release — gets the release workflow to sign artifacts for them.
	DefaultIdentityRegexp = `^https://github\.com/blechschmidt/cloop/\.github/workflows/release\.yml@refs/tags/v[^/]+$`
)

// Environment overrides, for an enterprise that builds cloop from a fork and
// signs with its own workflow.
//
// This exists so that such an operator has an alternative to switching
// verification off wholesale, which is what a hard-coded identity would force
// on them — an all-or-nothing pin is one an organisation eventually disables.
// Repointing the trust root keeps a signature required; only the identity that
// satisfies it changes.
const (
	IssuerEnv   = "CLOOP_PROVENANCE_ISSUER"
	IdentityEnv = "CLOOP_PROVENANCE_IDENTITY"
)

// VerifyTimeout bounds one verification. Keyless verification reads the
// bundle's own Rekor proof but may still consult the transparency log, so this
// is a network operation and needs a bound — an unreachable log must fail the
// upgrade rather than wedge it.
const VerifyTimeout = 2 * time.Minute

var (
	// ErrCosignMissing reports that the cosign binary is not installed. It is a
	// sentinel so callers can print an install hint instead of a generic
	// failure, and so tests can assert the fail-closed behaviour specifically.
	ErrCosignMissing = errors.New("provenance: cosign is not installed")

	// ErrBundleMissing reports that no signature bundle accompanies the
	// artifact. Distinct from a failed verification: it usually means the
	// artifact came from somewhere other than a cloop release.
	ErrBundleMissing = errors.New("provenance: no signature bundle for this artifact")

	// ErrUnverified reports that cosign rejected the signature — wrong
	// identity, wrong issuer, or bytes that do not match what was signed.
	ErrUnverified = errors.New("provenance: signature verification failed")
)

// Verifier checks Sigstore bundles with the cosign CLI.
//
// The zero value is usable: it finds cosign on PATH and pins the trust root
// above.
type Verifier struct {
	// Binary overrides the cosign executable. Tests set it; deployments do not.
	Binary string

	// Issuer and Identity override the pinned trust root. Empty means the
	// DefaultIssuer/DefaultIdentityRegexp constants, after the environment
	// overrides above are applied.
	Issuer   string
	Identity string
}

// issuer returns the OIDC issuer to require.
func (v *Verifier) issuer() string {
	if s := strings.TrimSpace(v.Issuer); s != "" {
		return s
	}
	if s := strings.TrimSpace(os.Getenv(IssuerEnv)); s != "" {
		return s
	}
	return DefaultIssuer
}

// identity returns the certificate identity regexp to require.
func (v *Verifier) identity() string {
	if s := strings.TrimSpace(v.Identity); s != "" {
		return s
	}
	if s := strings.TrimSpace(os.Getenv(IdentityEnv)); s != "" {
		return s
	}
	return DefaultIdentityRegexp
}

// binary returns the cosign executable to run.
func (v *Verifier) binary() string {
	if s := strings.TrimSpace(v.Binary); s != "" {
		return s
	}
	return CosignBinary
}

// TrustRoot describes what a verification will require, for display.
//
// Operators need to be able to read the pin without running an upgrade, and
// a support reply of "check that your identity matches" is only actionable if
// there is a command that prints the identity in force.
func (v *Verifier) TrustRoot() (issuer, identity string) {
	return v.issuer(), v.identity()
}

// Available reports whether cosign can be found. It does not run a
// verification.
//
// Callers use this to fail *early* with an install hint — before downloading
// an archive that is about to be refused — not to decide whether to verify.
// Nothing in this package treats an unavailable cosign as a pass.
func (v *Verifier) Available() error {
	if _, err := exec.LookPath(v.binary()); err != nil {
		return fmt.Errorf("%w: %s not found on PATH", ErrCosignMissing, v.binary())
	}
	return nil
}

// VerifyBlob checks that blobPath's bytes were signed, by the pinned identity,
// with the signature material in bundlePath.
//
// Both paths must already exist on disk: cosign reads files, so a caller
// holding a download in memory must stage it — to a private temporary
// directory, never to the destination, so that nothing is placed where it
// could be executed before it has been proven.
func (v *Verifier) VerifyBlob(ctx context.Context, blobPath, bundlePath string) error {
	if err := v.Available(); err != nil {
		return err
	}
	if _, err := os.Stat(bundlePath); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrBundleMissing, bundlePath, err)
	}

	ctx, cancel := context.WithTimeout(ctx, VerifyTimeout)
	defer cancel()

	// --certificate-identity-regexp rather than --certificate-identity: the
	// identity embeds the tag that produced the release, so an exact string
	// could only ever match one version and would have to be edited for each.
	// The regexp is anchored (see DefaultIdentityRegexp) so it is a pin, not a
	// prefix match.
	args := []string{
		"verify-blob",
		"--bundle", bundlePath,
		"--certificate-oidc-issuer", v.issuer(),
		"--certificate-identity-regexp", v.identity(),
		blobPath,
	}

	cmd := exec.CommandContext(ctx, v.binary(), args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return fmt.Errorf("%w: cosign timed out after %s verifying %s",
			ErrUnverified, VerifyTimeout, blobPath)
	}

	// cosign's own message names the actual mismatch — wrong identity, wrong
	// issuer, bad signature — and is far more useful to whoever has to act on
	// this than anything reconstructed here. Pass it through rather than
	// flattening every cause into one sentence.
	detail := strings.TrimSpace(string(out))
	if detail == "" {
		detail = err.Error()
	}
	return fmt.Errorf("%w: %s was not signed by %s (issuer %s): %s",
		ErrUnverified, blobPath, v.identity(), v.issuer(), detail)
}

// BundleNameFor returns the bundle's file name for an artifact name.
func BundleNameFor(artifact string) string { return artifact + BundleSuffix }

// SkipNotice is the single warning printed wherever verification is disabled.
//
// It is one constant so that every path says the same thing, and so that
// grepping a support log for it finds an unverified install regardless of
// which entry point performed it.
const SkipNotice = "provenance verification is DISABLED (--insecure-skip-verify): " +
	"the artifact's origin has not been checked"
