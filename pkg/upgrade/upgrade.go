// Package upgrade implements self-update from GitHub releases.
package upgrade

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/provenance"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// maxArchiveBytes caps a release tarball download. Cloop's binary is single-
// digit MB; 256 MiB is far above any realistic GoReleaser archive but
// prevents a hijacked download URL from streaming an unbounded payload.
const maxArchiveBytes int64 = 256 << 20

// maxChecksumsBytes caps the checksums.txt download. Real checksums files
// are a few hundred bytes; 1 MiB leaves room for any legitimate growth.
const maxChecksumsBytes int64 = 1 << 20

// maxBundleBytes caps a Sigstore bundle download. Bundles carrying a
// certificate chain and a Rekor inclusion proof run to a few KiB; 1 MiB is the
// same order of headroom the checksums cap allows.
const maxBundleBytes int64 = 1 << 20

const (
	githubAPIBase = "https://api.github.com"
	repoOwner     = "blechschmidt"
	repoName      = "cloop"
)

// Release represents a GitHub release response (subset of fields used).
type Release struct {
	TagName string  `json:"tag_name"`
	Name    string  `json:"name"`
	Assets  []Asset `json:"assets"`
}

// Asset is a single file attached to a GitHub release.
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// CheckResult is the result of a version check.
type CheckResult struct {
	Current         string
	Latest          string
	UpdateAvailable bool
	Release         *Release
}

// httpClient is used for all GitHub API requests with a reasonable timeout.
var httpClient = &http.Client{Timeout: 30 * time.Second}

// FetchLatestRelease queries the GitHub releases API for the latest release.
func FetchLatestRelease() (*Release, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/releases/latest", githubAPIBase, repoOwner, repoName)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("querying GitHub API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}

	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &rel, nil
}

// Check compares current against the latest GitHub release tag and returns a
// CheckResult describing whether an update is available.
func Check(current string) (*CheckResult, error) {
	rel, err := FetchLatestRelease()
	if err != nil {
		return nil, err
	}
	result := &CheckResult{
		Current: current,
		Latest:  rel.TagName,
		Release: rel,
	}
	// Strip leading "v" for comparison so "v1.2.3" == "1.2.3".
	cur := strings.TrimPrefix(current, "v")
	lat := strings.TrimPrefix(rel.TagName, "v")
	result.UpdateAvailable = cur != lat && current != "dev"
	return result, nil
}

// assetName returns the expected release asset name for the current OS/arch.
// Convention: cloop_<os>_<arch>.tar.gz
func assetName() string {
	return assetNameFor(runtime.GOOS, runtime.GOARCH)
}

// assetNameFor is assetName with the platform passed in rather than taken from
// the running binary, so the naming can be asserted for platforms other than
// the one the test happens to run on.
//
// This is one half of a contract: scripts/build-release.sh publishes the names
// this function computes, and release_assets_test.go fails if the two drift.
//
// The name carries no version. That is not a simplification — it is what lets
// https://github.com/.../releases/latest/download/<name> resolve, which is the
// URL the bootstrap installer served at GET /install.sh hardcodes. The
// upgrader itself could cope with a versioned name (it resolves assets through
// the releases API, where the tag is already known), so the constraint comes
// entirely from the installer; both are kept on one name so there is one thing
// to be right about. See scripts/build-release.sh for the full rationale.
func assetNameFor(goos, goarch string) string {
	return fmt.Sprintf("cloop_%s_%s.tar.gz", goos, goarch)
}

// legacyAssetNameFor is the versioned name published through v0.0.1, before
// Task 20240 dropped the version so that /releases/latest/download/ could
// resolve.
//
// It is still consulted when the unversioned name is absent, because the
// release this binary upgrades *from* may predate the rename: a binary built
// after the change, checking against v0.0.1, would otherwise report "no
// release asset found" for a release whose asset is sitting right there. The
// fallback costs one map lookup and can be deleted once no supported release
// carries versioned assets.
func legacyAssetNameFor(version, goos, goarch string) string {
	tag := strings.TrimPrefix(version, "v")
	return fmt.Sprintf("cloop_%s_%s_%s.tar.gz", tag, goos, goarch)
}

// findAsset returns the asset whose Name matches needle (case-insensitive), or nil.
func findAsset(assets []Asset, needle string) *Asset {
	for i := range assets {
		if strings.EqualFold(assets[i].Name, needle) {
			return &assets[i]
		}
	}
	return nil
}

// downloadBytes fetches a URL and returns the full body, refusing bodies
// larger than maxBytes so a hijacked or misconfigured download endpoint
// cannot OOM the upgrader.
func downloadBytes(url string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}
	return provider.ReadResponseBody(resp.Body, maxBytes)
}

// parseChecksums parses a GNU-style SHA-256 checksums file (e.g., from GoReleaser)
// into a map of filename → expected hex digest.
func parseChecksums(data []byte) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format: "<hash>  <filename>" or "<hash> <filename>"
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			m[parts[1]] = parts[0]
		}
	}
	return m
}

// verifySHA256 returns an error if the SHA-256 of data does not match expected.
func verifySHA256(data []byte, expected string) error {
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if !strings.EqualFold(got, expected) {
		return fmt.Errorf("checksum mismatch: got %s, want %s", got, expected)
	}
	return nil
}

// extractBinaryFromTarGz extracts the "cloop" (or "cloop.exe") binary from a
// .tar.gz archive and returns the raw bytes of the executable.
func extractBinaryFromTarGz(data []byte) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar read: %w", err)
		}
		base := filepath.Base(hdr.Name)
		if base == "cloop" || base == "cloop.exe" {
			return io.ReadAll(tr)
		}
	}
	return nil, fmt.Errorf("binary 'cloop' not found in archive")
}

// selfPath returns the absolute path of the running binary.
func selfPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolving executable path: %w", err)
	}
	return filepath.EvalSymlinks(exe)
}

// atomicReplace writes newBinary to a temp file next to dst, then renames it
// over dst (atomic on POSIX systems).
func atomicReplace(dst string, newBinary []byte, mode os.FileMode) error {
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".cloop-upgrade-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(newBinary); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("writing new binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("replacing binary: %w", err)
	}
	return nil
}

// Options controls how an upgrade verifies what it is about to install.
//
// The zero value verifies, deliberately: a security check whose default
// depends on a caller remembering to enable it is one that will eventually be
// forgotten at some call site nobody is looking at.
type Options struct {
	// SkipVerify installs without proving the archive's provenance.
	//
	// It exists for air-gapped mirrors that cannot reach Sigstore, and for
	// nothing else. It does not disable the checksum: that still runs, and
	// still proves only that the download arrived intact — checksums.txt is
	// served from the same release as the archive, so an attacker who can
	// replace one replaces the other.
	SkipVerify bool

	// Verifier overrides the provenance verifier. Tests set it.
	Verifier *provenance.Verifier
}

// verifyArchiveProvenance proves archiveData came from cloop's release
// workflow, using the bundle published beside it.
//
// cosign reads files, so the download has to be staged — but it is staged into
// a private temporary directory that is removed on every path out of here, not
// to the destination. Nothing is written where it could be executed until it
// has been proven, which is the ordering the whole exercise is about.
func verifyArchiveProvenance(
	rel *Release, assetName string, archiveData []byte, opts Options, progress func(string),
) error {
	v := opts.Verifier
	if v == nil {
		v = &provenance.Verifier{}
	}

	// Fail before downloading anything else if the tool is absent, so the
	// diagnostic names the actual problem rather than surfacing as a
	// verification failure on an artifact that is probably fine.
	if err := v.Available(); err != nil {
		return fmt.Errorf(
			"%w\n\nInstall cosign from https://github.com/sigstore/cosign/releases, "+
				"or re-run with --insecure-skip-verify to upgrade without checking "+
				"where this binary came from", err)
	}

	bundleName := provenance.BundleNameFor(assetName)
	bundleAsset := findAsset(rel.Assets, bundleName)
	if bundleAsset == nil {
		return fmt.Errorf(
			"%w: release %s publishes no %s.\n\n"+
				"Releases from before signing was introduced have no bundle. Verify "+
				"the download by hand, or re-run with --insecure-skip-verify",
			provenance.ErrBundleMissing, rel.TagName, bundleName)
	}

	progress(fmt.Sprintf("Downloading signature bundle %s...", bundleName))
	bundleData, err := downloadBytes(bundleAsset.BrowserDownloadURL, maxBundleBytes)
	if err != nil {
		return fmt.Errorf("downloading signature bundle: %w", err)
	}

	dir, err := os.MkdirTemp("", "cloop-verify-")
	if err != nil {
		return fmt.Errorf("staging download for verification: %w", err)
	}
	defer os.RemoveAll(dir)

	blobPath := filepath.Join(dir, assetName)
	bundlePath := filepath.Join(dir, bundleName)
	// 0600: this is a root-owned binary on its way to /usr/local/bin, and for
	// the moment it sits in a world-traversable /tmp it should not be readable
	// — let alone replaceable — by another local user between the write and
	// the verification.
	if err := os.WriteFile(blobPath, archiveData, 0o600); err != nil {
		return fmt.Errorf("staging archive: %w", err)
	}
	if err := os.WriteFile(bundlePath, bundleData, 0o600); err != nil {
		return fmt.Errorf("staging signature bundle: %w", err)
	}

	issuer, identity := v.TrustRoot()
	progress(fmt.Sprintf("Verifying signature (issuer %s)...", issuer))
	if err := v.VerifyBlob(context.Background(), blobPath, bundlePath); err != nil {
		return fmt.Errorf(
			"%w\n\nThis archive was not signed by cloop's release workflow "+
				"(expected identity %s), so it is not a cloop release regardless of "+
				"what its checksum says. Refusing to replace the running binary",
			err, identity)
	}
	progress("Signature verified.")
	return nil
}

// Upgrade downloads and installs the latest release, replacing the running binary.
// It returns the new version tag on success.
//
// It verifies provenance; UpgradeWithOptions is the form that can be told not
// to.
func Upgrade(current string, progress func(msg string)) (string, error) {
	return UpgradeWithOptions(current, Options{}, progress)
}

// UpgradeWithOptions is Upgrade with explicit control over verification.
func UpgradeWithOptions(current string, opts Options, progress func(msg string)) (string, error) {
	if progress == nil {
		progress = func(string) {}
	}

	progress("Fetching latest release information...")
	rel, err := FetchLatestRelease()
	if err != nil {
		return "", err
	}

	name := assetName()
	progress(fmt.Sprintf("Looking for asset: %s", name))

	binaryAsset := findAsset(rel.Assets, name)
	legacy := legacyAssetNameFor(rel.TagName, runtime.GOOS, runtime.GOARCH)
	if binaryAsset == nil {
		binaryAsset = findAsset(rel.Assets, legacy)
		if binaryAsset != nil {
			progress(fmt.Sprintf("Falling back to pre-rename asset: %s", legacy))
		}
	}
	if binaryAsset == nil {
		return "", fmt.Errorf(
			"no release asset found for %s/%s (tag %s); expected %s (or %s)",
			runtime.GOOS, runtime.GOARCH, rel.TagName, name, legacy,
		)
	}

	checksumAsset := findAsset(rel.Assets, "checksums.txt")

	// Download the binary archive.
	progress(fmt.Sprintf("Downloading %s (%d bytes)...", binaryAsset.Name, binaryAsset.Size))
	archiveData, err := downloadBytes(binaryAsset.BrowserDownloadURL, maxArchiveBytes)
	if err != nil {
		return "", fmt.Errorf("downloading archive: %w", err)
	}

	// Verify checksum if available.
	if checksumAsset != nil {
		progress("Verifying SHA-256 checksum...")
		checksumData, err := downloadBytes(checksumAsset.BrowserDownloadURL, maxChecksumsBytes)
		if err != nil {
			return "", fmt.Errorf("downloading checksums: %w", err)
		}
		sums := parseChecksums(checksumData)
		expected, ok := sums[binaryAsset.Name]
		if !ok {
			return "", fmt.Errorf("checksum not found for %s in checksums.txt", binaryAsset.Name)
		}
		if err := verifySHA256(archiveData, expected); err != nil {
			return "", err
		}
		progress("Checksum verified.")
	} else {
		progress("Warning: no checksums.txt asset found; skipping checksum verification.")
	}

	// Provenance. This is the check the checksum above cannot make: it ran
	// against a checksums.txt fetched from the same release as the archive, so
	// it proves the download arrived intact and says nothing about who
	// produced it. Nothing has been written outside a private temp directory
	// at this point, and nothing will be if this fails.
	if opts.SkipVerify {
		progress("Warning: " + provenance.SkipNotice)
	} else if err := verifyArchiveProvenance(rel, binaryAsset.Name, archiveData, opts, progress); err != nil {
		return "", err
	}

	// Extract the binary from the archive.
	progress("Extracting binary...")
	newBinary, err := extractBinaryFromTarGz(archiveData)
	if err != nil {
		return "", fmt.Errorf("extracting binary: %w", err)
	}

	// Locate the running binary.
	exe, err := selfPath()
	if err != nil {
		return "", err
	}

	// Preserve the file mode of the existing binary.
	info, err := os.Stat(exe)
	if err != nil {
		return "", fmt.Errorf("stat current binary: %w", err)
	}

	progress(fmt.Sprintf("Installing to %s...", exe))
	if err := atomicReplace(exe, newBinary, info.Mode()); err != nil {
		return "", err
	}

	return rel.TagName, nil
}
