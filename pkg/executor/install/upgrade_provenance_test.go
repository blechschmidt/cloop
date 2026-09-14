package install

// upgrade_provenance_test.go covers the check that answers "where did this
// binary come from", as distinct from upgrade_verify_test.go's "will this
// binary run".
//
// The two are genuinely different questions and the second cannot stand in for
// the first: a hostile build runs perfectly, reports whatever version suits it,
// and stays up long enough to satisfy the settle timeout. Executability is a
// test of competence, not of origin.
//
// cosign is stood in for here rather than invoked for real. What these tests
// assert is cloop's behaviour around the verdict — that a refusal blocks the
// install, that a missing bundle is not silently treated as a pass, that the
// binary is not executed before its origin is settled — and a real cosign
// would require a real Fulcio certificate, which needs an OIDC token that
// exists only inside the release workflow. pkg/provenance carries the round
// trip against the genuine tool.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/provenance"
)

// writeFakeCosign renders a stand-in cosign that exits with the given code,
// and records the arguments it saw so a test can prove what was asked of it.
func writeFakeCosign(t *testing.T, exitCode int, message, argsFile string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "cosign")
	script := "#!/bin/sh\n"
	if argsFile != "" {
		script += "for a in \"$@\"; do printf '%s\\n' \"$a\" >> '" + argsFile + "'; done\n"
	}
	if message != "" {
		script += "printf '%s\\n' '" + message + "' >&2\n"
	}
	if exitCode == 0 {
		script += "exit 0\n"
	} else {
		script += "exit 1\n"
	}
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("writing fake cosign: %v", err)
	}
	return bin
}

// stubProvenance points the package verifier at a stand-in cosign for the rest
// of the test.
//
// Note what this does *not* do: it does not switch verification off. The bundle
// must still be present and cosign is still invoked, so a regression that
// stopped calling verifyProvenance entirely would still be caught by the tests
// below — which is the whole reason the fixture stubs the tool rather than
// setting SkipVerify.
func stubProvenance(t *testing.T, exitCode int, message string) {
	t.Helper()
	stubProvenanceRecording(t, exitCode, message, "")
}

func stubProvenanceRecording(t *testing.T, exitCode int, message, argsFile string) {
	t.Helper()
	prev := provenanceVerifier
	provenanceVerifier = &provenance.Verifier{
		Binary: writeFakeCosign(t, exitCode, message, argsFile),
	}
	t.Cleanup(func() { provenanceVerifier = prev })
}

// TestUpgradeRefusesABinaryWhoseSignatureDoesNotVerify is the mirror of
// TestContainerInstallerRefusesATamperedArchive, one layer down: same refusal,
// asserted on the path the hub actually asks a device to take.
func TestUpgradeRefusesABinaryWhoseSignatureDoesNotVerify(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD")
	// After the fixture: newUpgradeFixture installs its own accepting stub, so
	// stubbing before it would be silently overwritten.
	stubProvenance(t, 1, "error: no matching signatures")
	src := f.stageBinary(t, fakeCloop("v2.0.0", "NEW BUILD"))

	res, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src})
	if err == nil {
		t.Fatal("the upgrade installed a binary whose signature did not verify")
	}
	if !errors.Is(err, provenance.ErrUnverified) {
		t.Errorf("refused, but not for provenance — the refusal may be incidental: %v", err)
	}

	// The device must be exactly as it was. A refusal that still replaced the
	// binary, or still bounced the service, would be a refusal in name only.
	if got := f.installed(t); got != "OLD BUILD" {
		t.Errorf("the installed binary is now %q; the refusal did not protect the device", got)
	}
	if res.BinaryReplaced || res.Restarted {
		t.Errorf("BinaryReplaced=%v Restarted=%v after a failed verification",
			res.BinaryReplaced, res.Restarted)
	}
	if res.ProvenanceVerified {
		t.Error("ProvenanceVerified = true after cosign rejected the signature")
	}
	if len(*f.commands) != 0 {
		t.Errorf("the service was touched despite the refusal: %v", *f.commands)
	}
}

// TestUpgradeRefusesASignatureFromAnUnexpectedIdentity is the second half of
// the task's requirement, and the more interesting one.
//
// A wrong-identity signature is *valid*: it verifies, it is in the transparency
// log, it was issued by Fulcio. Everything about it is real except who signed
// it. That is precisely the attack keyless signing has to withstand — anyone
// can obtain a Sigstore signature over any bytes — so accepting a signature
// without pinning the identity would leave the check proving nothing at all.
func TestUpgradeRefusesASignatureFromAnUnexpectedIdentity(t *testing.T) {
	argsFile := filepath.Join(t.TempDir(), "args")
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD")
	// After the fixture, which installs its own accepting stub. This is what
	// cosign says when the signature is cryptographically fine but the
	// certificate names someone else.
	stubProvenanceRecording(t, 1,
		"error: none of the expected identities matched what was in the certificate", argsFile)
	src := f.stageBinary(t, fakeCloop("v2.0.0", "ATTACKER BUILD"))

	_, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src})
	if err == nil {
		t.Fatal("the upgrade accepted a signature from an unexpected identity")
	}
	if !strings.Contains(err.Error(), "none of the expected identities matched") {
		t.Errorf("cosign's diagnosis was lost, so an operator cannot tell a wrong "+
			"signer from a corrupt download: %v", err)
	}
	if got := f.installed(t); got != "OLD BUILD" {
		t.Errorf("the attacker's build was installed: %q", got)
	}

	// The refusal above only means anything if cloop actually asked cosign to
	// check the identity. Without these flags cosign would accept any valid
	// Sigstore signature, and this test would pass against a verifier that
	// checks nothing.
	raw, readErr := os.ReadFile(argsFile)
	if readErr != nil {
		t.Fatalf("cosign was never invoked: %v", readErr)
	}
	args := string(raw)
	if !strings.Contains(args, "--certificate-identity-regexp") {
		t.Error("cosign was invoked without --certificate-identity-regexp: any signer would pass")
	}
	if !strings.Contains(args, "--certificate-oidc-issuer") {
		t.Error("cosign was invoked without --certificate-oidc-issuer: any issuer would pass")
	}
	if !strings.Contains(args, provenance.DefaultIdentityRegexp) {
		t.Errorf("cosign was not pinned to the release workflow identity; got:\n%s", args)
	}
}

// TestUpgradeRefusesWhenNoBundleAccompaniesTheBinary closes the bypass that a
// "verify only if a signature is present" design would leave wide open: an
// attacker who can place a binary can also decline to place a signature beside
// it, and a check that can be skipped by omission is not a check.
func TestUpgradeRefusesAnUnsignedBinary(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD")
	stubProvenance(t, 0, "") // cosign would accept; it must never be reached
	src := f.stageBinary(t, fakeCloop("v2.0.0", "UNSIGNED BUILD"))

	// Exactly the attacker's move: drop the signature rather than forge one.
	if err := os.Remove(provenance.BundleNameFor(src)); err != nil {
		t.Fatalf("removing the bundle: %v", err)
	}

	_, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src})
	if err == nil {
		t.Fatal("an unsigned binary was installed; omitting the signature bypasses verification")
	}
	if !errors.Is(err, provenance.ErrBundleMissing) {
		t.Errorf("refused, but not for a missing bundle: %v", err)
	}
	if got := f.installed(t); got != "OLD BUILD" {
		t.Errorf("the unsigned build was installed: %q", got)
	}
}

// TestUpgradeSkipVerifyIsAnExplicitDecision covers the air-gapped escape hatch,
// and that it reports itself. A skipped verification rendered as a plain
// success would leave an operator believing the fleet is signed when it is not.
func TestUpgradeSkipVerifyIsAnExplicitDecision(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD")
	// After the fixture: newUpgradeFixture installs its own accepting stub, so
	// stubbing before it would be silently overwritten.
	stubProvenance(t, 1, "error: no matching signatures")
	src := f.stageBinary(t, fakeCloop("v2.0.0", "UNSIGNED BUILD"))
	if err := os.Remove(provenance.BundleNameFor(src)); err != nil {
		t.Fatalf("removing the bundle: %v", err)
	}

	var logged strings.Builder
	f.inst.Logf = func(format string, a ...any) {
		logged.WriteString(fmt.Sprintf(format, a...))
	}

	res, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{
		Source: src, SkipVerify: true,
	})
	if err != nil {
		t.Fatalf("--insecure-skip-verify did not install an unsigned binary: %v", err)
	}
	if !res.BinaryReplaced {
		t.Error("the binary was not replaced despite the skip")
	}
	if res.ProvenanceVerified {
		t.Error("ProvenanceVerified = true after verification was skipped — " +
			"an operator would read this fleet as signed")
	}
	if !strings.Contains(logged.String(), "DISABLED") {
		t.Errorf("skipping verification was not reported to the operator: %q", logged.String())
	}
}

// TestUpgradeVerifiesProvenanceBeforeExecutingTheBinary is the ordering test,
// and the reason verifyProvenance sits above verifyUpgrade rather than beside
// it.
//
// verifyUpgrade works by *running* the candidate. Against a binary that turns
// out to be hostile, running it first means the host is compromised by the
// check that was supposed to protect it — and the refusal that follows is
// bookkeeping. The unsigned binary here records the fact that it ran; the test
// requires that it never got the chance.
func TestUpgradeVerifiesProvenanceBeforeExecutingTheBinary(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD")
	// After the fixture: newUpgradeFixture installs its own accepting stub, so
	// stubbing before it would be silently overwritten.
	stubProvenance(t, 1, "error: no matching signatures")

	canary := filepath.Join(t.TempDir(), "it-ran")
	src := f.stageBinary(t, "#!/bin/sh\ntouch '"+canary+"'\necho 'cloop v2.0.0'\n")

	if _, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src}); err == nil {
		t.Fatal("the upgrade accepted an unverified binary")
	}

	if _, err := os.Stat(canary); err == nil {
		t.Fatal("the unverified binary was EXECUTED before its provenance was checked — " +
			"a hostile build would already have run as this user")
	}
}

// TestStagedInstallStillVerifiesProvenance. A staged install legitimately
// cannot execute the candidate: it is being built for another architecture, so
// verifyUpgrade is skipped there. Checking a signature only reads bytes, so
// there is no such excuse for provenance — and an image build is exactly where
// an unverified binary propagates to every device made from it.
func TestStagedInstallStillVerifiesProvenance(t *testing.T) {
	stubProvenance(t, 1, "error: no matching signatures")

	root := t.TempDir()
	spec := Spec{
		ServiceName: "cloop-executor",
		BinaryPath:  "/usr/local/bin/cloop",
		StateDir:    "/var/lib/cloop-executor",
		UnitDir:     "/etc/systemd/system",
		Server:      "wss://hub.example:8888/api/executors/connect",
	}
	norm, err := spec.Normalize()
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	inst := &Installer{Root: root, Logf: func(string, ...any) {}}
	mustWrite(t, filepath.Join(root, norm.BinaryPath), "OLD ARM BINARY", BinaryMode)
	mustWrite(t, filepath.Join(root, norm.UnitPath()), SystemdUnit(norm), UnitFileMode)

	src := filepath.Join(t.TempDir(), "cloop-arm64")
	mustWrite(t, src, corruptBinary, BinaryMode)
	mustWrite(t, provenance.BundleNameFor(src), "{}", 0o644)

	if _, err := inst.Upgrade(norm, OutputSystemd, UpgradeOptions{Source: src}); err == nil {
		t.Fatal("a staged install accepted a binary whose signature did not verify; " +
			"every device built from this image would carry it")
	}
}
