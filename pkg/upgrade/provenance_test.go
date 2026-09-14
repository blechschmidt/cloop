package upgrade

// provenance_test.go covers the verification `cloop upgrade` performs before it
// overwrites the binary that is currently running.
//
// That destination is what makes this path worth its own tests: an upgrade does
// not install a new program beside the old one, it replaces the executable the
// operator invokes by name from then on. A bad archive accepted here is
// persistent and self-perpetuating — the next `cloop upgrade` is run by the
// attacker's binary.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/provenance"
)

// fakeCosign writes a stand-in cosign exiting with the given code.
func fakeCosign(t *testing.T, exitCode int, message string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "cosign")
	script := "#!/bin/sh\n"
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

// releaseServing publishes the given files and returns a Release whose assets
// point at them, so verifyArchiveProvenance can fetch a bundle for real.
func releaseServing(t *testing.T, files map[string]string) *Release {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := files[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	rel := &Release{TagName: "v9.9.9"}
	for name := range files {
		rel.Assets = append(rel.Assets, Asset{
			Name:               name,
			BrowserDownloadURL: srv.URL + "/" + name,
		})
	}
	return rel
}

const testAsset = "cloop_linux_amd64.tar.gz"

// TestUpgradeRefusesAnArchiveWhoseSignatureDoesNotVerify is the mirror of the
// installer's tamper test on the self-update path.
func TestUpgradeRefusesAnArchiveWhoseSignatureDoesNotVerify(t *testing.T) {
	rel := releaseServing(t, map[string]string{
		testAsset:                           "archive bytes",
		provenance.BundleNameFor(testAsset): "{}",
	})
	opts := Options{Verifier: &provenance.Verifier{
		Binary: fakeCosign(t, 1, "error: no matching signatures"),
	}}

	err := verifyArchiveProvenance(rel, testAsset, []byte("archive bytes"), opts, func(string) {})
	if err == nil {
		t.Fatal("an archive whose signature did not verify was accepted")
	}
	if !errors.Is(err, provenance.ErrUnverified) {
		t.Errorf("refused, but not for provenance: %v", err)
	}
	if !strings.Contains(err.Error(), "no matching signatures") {
		t.Errorf("cosign's diagnosis was dropped: %v", err)
	}
}

// TestUpgradeRefusesAReleaseWithNoBundle covers the downgrade attack that an
// "verify if present" design invites: strip the bundle and the check evaporates.
//
// It is also the honest case of an old release predating signing, which is why
// the error has to say so — an operator hitting this needs to tell "you are
// upgrading to a pre-signing version" apart from "someone removed the
// signature".
func TestUpgradeRefusesAReleaseWithNoBundle(t *testing.T) {
	rel := releaseServing(t, map[string]string{testAsset: "archive bytes"})
	opts := Options{Verifier: &provenance.Verifier{Binary: fakeCosign(t, 0, "")}}

	err := verifyArchiveProvenance(rel, testAsset, []byte("archive bytes"), opts, func(string) {})
	if !errors.Is(err, provenance.ErrBundleMissing) {
		t.Fatalf("a release with no signature bundle gave %v, want ErrBundleMissing", err)
	}
	if !strings.Contains(err.Error(), "--insecure-skip-verify") {
		t.Errorf("the refusal does not name the escape hatch: %v", err)
	}
}

// TestUpgradeFailsClosedWithoutCosign. The upgrade path is non-interactive and
// its output scrolls past; a warning here would be read by nobody and every
// upgrade would silently become unverified.
func TestUpgradeFailsClosedWithoutCosign(t *testing.T) {
	rel := releaseServing(t, map[string]string{
		testAsset:                           "archive bytes",
		provenance.BundleNameFor(testAsset): "{}",
	})
	opts := Options{Verifier: &provenance.Verifier{
		Binary: filepath.Join(t.TempDir(), "not-installed"),
	}}

	err := verifyArchiveProvenance(rel, testAsset, []byte("archive bytes"), opts, func(string) {})
	if !errors.Is(err, provenance.ErrCosignMissing) {
		t.Fatalf("a missing cosign gave %v, want ErrCosignMissing", err)
	}
	if !strings.Contains(err.Error(), "sigstore/cosign") {
		t.Errorf("the error does not say where to get cosign: %v", err)
	}
}

// TestUpgradeVerificationStagesOutsideTheDestination checks that nothing is
// written where it could be executed before the verdict is in.
//
// cosign reads files, so the download has to be staged somewhere — and the
// tempting place is the destination, "we will overwrite it anyway". That would
// put unverified, executable bytes at the path the operator runs by name, for
// as long as verification takes. The test proves the staged copy is elsewhere
// and is cleaned up.
func TestUpgradeVerificationStagesOutsideTheDestination(t *testing.T) {
	rel := releaseServing(t, map[string]string{
		testAsset:                           "archive bytes",
		provenance.BundleNameFor(testAsset): "{}",
	})

	// A cosign that records where it was pointed, so the test can inspect the
	// staging path rather than infer it.
	seen := filepath.Join(t.TempDir(), "seen")
	bin := filepath.Join(t.TempDir(), "cosign")
	script := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> '" + seen + "'; done\nexit 0\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("writing cosign: %v", err)
	}

	opts := Options{Verifier: &provenance.Verifier{Binary: bin}}
	if err := verifyArchiveProvenance(rel, testAsset, []byte("archive bytes"), opts, func(string) {}); err != nil {
		t.Fatalf("verification failed: %v", err)
	}

	raw, err := os.ReadFile(seen)
	if err != nil {
		t.Fatalf("cosign was never invoked: %v", err)
	}
	var staged string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.HasSuffix(line, testAsset) {
			staged = line
		}
	}
	if staged == "" {
		t.Fatalf("cosign was not pointed at the archive; saw:\n%s", raw)
	}
	self, err := os.Executable()
	if err == nil && staged == self {
		t.Error("the archive was staged over the running binary before being verified")
	}
	// The staging directory is removed on the way out, verified or not: an
	// unverified release binary left in /tmp is a file someone else may run.
	if _, err := os.Stat(staged); err == nil {
		t.Errorf("the staged archive survived verification at %s", staged)
	}
}

// TestSkipVerifyIsOptIn pins the default. A security check whose default
// depends on every caller remembering to ask for it is one that will be
// forgotten at some call site nobody is looking at.
func TestSkipVerifyIsOptIn(t *testing.T) {
	if (Options{}).SkipVerify {
		t.Fatal("the zero Options skips verification; the safe path must be the default")
	}
}
