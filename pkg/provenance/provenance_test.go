package provenance

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// fakeCosign writes a script standing in for cosign that records the arguments
// it was called with and exits with the given code. It returns the script path
// and the path the arguments are recorded to.
//
// The recording is the point: most of what this package does is decide *what
// to ask cosign*, and a test that only checked the exit code would pass just as
// happily against a verifier that forgot to pin the issuer.
func fakeCosign(t *testing.T, exitCode int, stderr string) (bin, argsFile string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake cosign is a shell script")
	}
	dir := t.TempDir()
	bin = filepath.Join(dir, "cosign")
	argsFile = filepath.Join(dir, "args")

	// argsFile is quoted: t.TempDir() derives its path from the test's name, so
	// a subtest called "a b" yields a path with a space in it and an unquoted
	// redirect would silently write to the wrong file — the arguments would
	// simply never be recorded and every assertion about them would vanish.
	script := "#!/bin/sh\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\" >> " + shellSingleQuote(argsFile) + "; done\n"
	if stderr != "" {
		script += "printf '%s\\n' " + shellSingleQuote(stderr) + " >&2\n"
	}
	script += "exit " + strconv.Itoa(exitCode) + "\n"

	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("writing fake cosign: %v", err)
	}
	return bin, argsFile
}

func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// stageBlob writes a blob and a stand-in bundle beside it.
func stageBlob(t *testing.T) (blob, bundle string) {
	t.Helper()
	dir := t.TempDir()
	blob = filepath.Join(dir, "cloop_linux_amd64.tar.gz")
	bundle = BundleNameFor(blob)
	if err := os.WriteFile(blob, []byte("artifact bytes"), 0o644); err != nil {
		t.Fatalf("writing blob: %v", err)
	}
	if err := os.WriteFile(bundle, []byte(`{"mediaType":"stub"}`), 0o644); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}
	return blob, bundle
}

func readArgs(t *testing.T, argsFile string) []string {
	t.Helper()
	b, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("cosign was never invoked (no %s): %v", argsFile, err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

// argValue returns the value following flag in an argv slice.
func argValue(args []string, flag string) (string, bool) {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

// TestVerifyPinsIssuerAndIdentity is the test that matters most: a verification
// that reaches cosign without both pins is not a provenance check at all. It
// would accept a signature from any Fulcio-federated issuer, or from any
// workflow in any repository — which is exactly the property a bare checksum
// already failed to provide.
func TestVerifyPinsIssuerAndIdentity(t *testing.T) {
	bin, argsFile := fakeCosign(t, 0, "")
	blob, bundle := stageBlob(t)

	v := &Verifier{Binary: bin}
	if err := v.VerifyBlob(context.Background(), blob, bundle); err != nil {
		t.Fatalf("verification failed against a cosign that exits 0: %v", err)
	}

	args := readArgs(t, argsFile)
	if args[0] != "verify-blob" {
		t.Errorf("invoked cosign %q, want verify-blob", args[0])
	}

	issuer, ok := argValue(args, "--certificate-oidc-issuer")
	if !ok {
		t.Fatal("no --certificate-oidc-issuer: any federated issuer would be accepted")
	}
	if issuer != DefaultIssuer {
		t.Errorf("issuer pinned to %q, want %q", issuer, DefaultIssuer)
	}

	identity, ok := argValue(args, "--certificate-identity-regexp")
	if !ok {
		t.Fatal("no --certificate-identity-regexp: any signer would be accepted")
	}
	if identity != DefaultIdentityRegexp {
		t.Errorf("identity pinned to %q, want %q", identity, DefaultIdentityRegexp)
	}

	if got, _ := argValue(args, "--bundle"); got != bundle {
		t.Errorf("verified against bundle %q, want %q", got, bundle)
	}
	if args[len(args)-1] != blob {
		t.Errorf("verified blob %q, want %q", args[len(args)-1], blob)
	}
}

// TestVerifyFailsWhenCosignRejects confirms a non-zero exit is a refusal and
// that cosign's own diagnosis survives into the error. An operator who sees
// only "verification failed" cannot tell a wrong identity from a corrupt
// download, and those have opposite remedies.
func TestVerifyFailsWhenCosignRejects(t *testing.T) {
	bin, _ := fakeCosign(t, 1, "error: certificate identity does not match")
	blob, bundle := stageBlob(t)

	err := (&Verifier{Binary: bin}).VerifyBlob(context.Background(), blob, bundle)
	if err == nil {
		t.Fatal("cosign exited 1 and the verification still passed")
	}
	if !errors.Is(err, ErrUnverified) {
		t.Errorf("error is not ErrUnverified: %v", err)
	}
	if !strings.Contains(err.Error(), "certificate identity does not match") {
		t.Errorf("cosign's diagnosis was dropped from the error: %v", err)
	}
}

// TestMissingCosignIsARefusalNotASkip guards the failure mode this package's
// doc comment is mostly about. An implementation that treated an absent cosign
// as "nothing to check" would report every artifact as fine while verifying
// none of them, and the misconfiguration would be invisible because it looks
// exactly like success.
func TestMissingCosignIsARefusalNotASkip(t *testing.T) {
	blob, bundle := stageBlob(t)
	v := &Verifier{Binary: filepath.Join(t.TempDir(), "definitely-not-installed")}

	err := v.VerifyBlob(context.Background(), blob, bundle)
	if err == nil {
		t.Fatal("cosign is absent and the verification passed — nothing was checked")
	}
	if !errors.Is(err, ErrCosignMissing) {
		t.Errorf("error is not ErrCosignMissing: %v", err)
	}
	if err := v.Available(); !errors.Is(err, ErrCosignMissing) {
		t.Errorf("Available() did not report the missing binary: %v", err)
	}
}

// TestMissingBundleIsDistinctFromAFailedVerification keeps the two apart: no
// bundle usually means the artifact did not come from a cloop release, while a
// failed verification means it claims to have and the claim did not hold.
func TestMissingBundleIsDistinctFromAFailedVerification(t *testing.T) {
	bin, _ := fakeCosign(t, 0, "")
	blob, bundle := stageBlob(t)
	if err := os.Remove(bundle); err != nil {
		t.Fatalf("removing bundle: %v", err)
	}

	err := (&Verifier{Binary: bin}).VerifyBlob(context.Background(), blob, bundle)
	if !errors.Is(err, ErrBundleMissing) {
		t.Fatalf("missing bundle gave %v, want ErrBundleMissing", err)
	}
}

// TestTrustRootIsOverridableForForks covers the enterprise that builds cloop
// itself. Without this they would have to disable verification wholesale, and
// an all-or-nothing pin is one an organisation eventually turns off.
func TestTrustRootIsOverridableForForks(t *testing.T) {
	bin, argsFile := fakeCosign(t, 0, "")
	blob, bundle := stageBlob(t)

	const forkIssuer = "https://gitlab.example.com"
	const forkIdentity = `^https://gitlab\.example\.com/infra/cloop//release@refs/tags/v.+$`
	t.Setenv(IssuerEnv, forkIssuer)
	t.Setenv(IdentityEnv, forkIdentity)

	v := &Verifier{Binary: bin}
	issuer, identity := v.TrustRoot()
	if issuer != forkIssuer {
		t.Errorf("TrustRoot issuer %q did not honour %s", issuer, IssuerEnv)
	}
	if identity != forkIdentity {
		t.Errorf("TrustRoot identity %q did not honour %s", identity, IdentityEnv)
	}

	if err := v.VerifyBlob(context.Background(), blob, bundle); err != nil {
		t.Fatalf("verification with an overridden trust root failed: %v", err)
	}
	args := readArgs(t, argsFile)
	if got, _ := argValue(args, "--certificate-oidc-issuer"); got != "https://gitlab.example.com" {
		t.Errorf("cosign was pinned to %q, not the overridden issuer", got)
	}

	// The override must not be a way to end up with *no* pin: an empty value
	// falls back to the default rather than passing an empty flag, which
	// cosign would treat as "match anything".
	t.Setenv(IssuerEnv, "   ")
	if got, _ := v.TrustRoot(); got != DefaultIssuer {
		t.Errorf("a blank override gave issuer %q, want the default %q", got, DefaultIssuer)
	}
}

// TestIdentityRegexpIsAnchoredToTaggedReleases checks the pin itself rather
// than the plumbing around it. The regexp is the entire trust decision, so the
// strings it must reject are worth stating explicitly — each of these is a
// signature an attacker could plausibly obtain.
func TestIdentityRegexpIsAnchoredToTaggedReleases(t *testing.T) {
	re, err := regexp.Compile(DefaultIdentityRegexp)
	if err != nil {
		t.Fatalf("the pinned identity is not a valid regexp: %v", err)
	}

	const base = "https://github.com/blechschmidt/cloop/.github/workflows/release.yml"
	if !re.MatchString(base + "@refs/tags/v0.0.1") {
		t.Error("the pin rejects a genuine tagged release; every upgrade would fail")
	}
	if !re.MatchString(base + "@refs/tags/v1.2.3-rc1") {
		t.Error("the pin rejects a pre-release tag")
	}
	// An odd tag name is still accepted, deliberately. `[^/]+` bounds the tag
	// to a single path segment, not to a version grammar: anyone who can create
	// a tag in this repository can already cut a release, so constraining the
	// shape of the tag buys nothing and would only break an unusual-but-honest
	// one. The security boundary is the repository and workflow, not the tag.
	if !re.MatchString(base + "@refs/tags/v2024.01.02.build7") {
		t.Error("the pin rejects an unusual but legitimate tag from this repository")
	}

	for _, bad := range []string{
		// A branch build: someone who can push a branch but not tag a release.
		base + "@refs/heads/main",
		// Another workflow in this repository — CI, say, which runs on every PR
		// and would otherwise be a signing oracle for anyone who opens one.
		"https://github.com/blechschmidt/cloop/.github/workflows/ci.yml@refs/tags/v1.0.0",
		// A fork's release workflow.
		"https://github.com/attacker/cloop/.github/workflows/release.yml@refs/tags/v1.0.0",
		// A repository whose name merely starts the same way.
		"https://github.com/blechschmidt/cloop-evil/.github/workflows/release.yml@refs/tags/v1.0.0",
		// Path traversal past the tag, which `.*` instead of `[^/]+` would let
		// through.
		base + "@refs/tags/v1/../../heads/main",
		// An unanchored regexp would match this, since the genuine identity
		// appears within it.
		"https://evil.example/" + base + "@refs/tags/v1.0.0",
	} {
		if re.MatchString(bad) {
			t.Errorf("the pin ACCEPTS %q — this identity could sign a release", bad)
		}
	}
}

// TestRealCosignRejectsATamperedBlob runs the actual tool.
//
// Everything above stands in for cosign, so it proves what cloop asks for and
// not that the asking works. This closes that gap end to end: sign real bytes,
// change them, and confirm the signature no longer verifies. Keyless signing
// needs an ambient OIDC token that exists only in CI, so this uses a local key
// pair — the identity pin is therefore not exercised here, but the bundle
// format, the flag spelling and the tamper detection are.
func TestRealCosignRejectsATamperedBlob(t *testing.T) {
	cosign, err := exec.LookPath(CosignBinary)
	if err != nil {
		t.Skip("cosign is not installed; skipping the real round trip")
	}

	dir := t.TempDir()
	blob := filepath.Join(dir, "cloop_linux_amd64.tar.gz")
	bundle := BundleNameFor(blob)
	if err := os.WriteFile(blob, []byte("the real artifact"), 0o644); err != nil {
		t.Fatalf("writing blob: %v", err)
	}

	run := func(args ...string) (string, error) {
		cmd := exec.Command(cosign, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "COSIGN_PASSWORD=")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	if out, err := run("generate-key-pair"); err != nil {
		t.Skipf("cosign generate-key-pair failed (offline?): %v\n%s", err, out)
	}
	key := filepath.Join(dir, "cosign.key")
	pub := filepath.Join(dir, "cosign.pub")

	if out, err := run("sign-blob", "--yes", "--key", key, "--bundle", bundle, blob); err != nil {
		t.Skipf("cosign sign-blob failed (offline?): %v\n%s", err, out)
	}

	// The signature verifies over the bytes that were signed...
	if out, err := run("verify-blob", "--key", pub, "--bundle", bundle, blob); err != nil {
		t.Fatalf("a freshly signed blob did not verify: %v\n%s", err, out)
	}

	// ...and stops verifying the moment those bytes change, with the bundle
	// left untouched. This is the substitution a co-located checksum cannot
	// detect, because the attacker rewrites the checksum too.
	if err := os.WriteFile(blob, []byte("the substituted artifact"), 0o644); err != nil {
		t.Fatalf("tampering with blob: %v", err)
	}
	out, err := run("verify-blob", "--key", pub, "--bundle", bundle, blob)
	if err == nil {
		t.Fatalf("cosign verified a tampered blob against its original bundle:\n%s", out)
	}
}
