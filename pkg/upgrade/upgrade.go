// Package upgrade implements self-update from GitHub releases.
package upgrade

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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
)

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
// Convention: cloop_<version>_<os>_<arch>.tar.gz  (GoReleaser default).
func assetName(version string) string {
	tag := strings.TrimPrefix(version, "v")
	return fmt.Sprintf("cloop_%s_%s_%s.tar.gz", tag, runtime.GOOS, runtime.GOARCH)
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

// downloadBytes fetches a URL and returns the full body.
func downloadBytes(url string) ([]byte, error) {
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
	return io.ReadAll(resp.Body)
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

// Upgrade downloads and installs the latest release, replacing the running binary.
// It returns the new version tag on success.
func Upgrade(current string, progress func(msg string)) (string, error) {
	if progress == nil {
		progress = func(string) {}
	}

	progress("Fetching latest release information...")
	rel, err := FetchLatestRelease()
	if err != nil {
		return "", err
	}

	name := assetName(rel.TagName)
	progress(fmt.Sprintf("Looking for asset: %s", name))

	binaryAsset := findAsset(rel.Assets, name)
	if binaryAsset == nil {
		return "", fmt.Errorf(
			"no release asset found for %s/%s (tag %s); expected %s",
			runtime.GOOS, runtime.GOARCH, rel.TagName, name,
		)
	}

	checksumAsset := findAsset(rel.Assets, "checksums.txt")

	// Download the binary archive.
	progress(fmt.Sprintf("Downloading %s (%d bytes)...", binaryAsset.Name, binaryAsset.Size))
	archiveData, err := downloadBytes(binaryAsset.BrowserDownloadURL)
	if err != nil {
		return "", fmt.Errorf("downloading archive: %w", err)
	}

	// Verify checksum if available.
	if checksumAsset != nil {
		progress("Verifying SHA-256 checksum...")
		checksumData, err := downloadBytes(checksumAsset.BrowserDownloadURL)
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
