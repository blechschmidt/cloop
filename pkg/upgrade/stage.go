package upgrade

// Staging a release without installing it (Task 20331).
//
// `cloop upgrade` fetches a release and replaces the running binary in one
// motion, because that is the whole of what it does. A remote executor agent
// asked to upgrade itself needs the same fetch but a different install: its
// binary is managed by a service unit, and rolling it forward means backup,
// atomic replace, restart, settle and rollback — which pkg/executor/install
// already implements and this package has no business duplicating.
//
// So the fetch is separated from the install here. StageRelease performs every
// step up to and including proving where the bytes came from, and stops with a
// verified binary on disk. The caller decides what to do with it.
//
// The ordering is the same one verifyArchiveProvenance exists to preserve, and
// it is the reason this is not simply "download to a path": nothing is written
// where it could be executed until its signature has been checked against
// cloop's release workflow. Verification happens on the archive in a private
// temporary directory; only then is the binary extracted to destDir.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Staged describes a release that has been fetched, verified and written to
// disk, but not installed.
type Staged struct {
	// Tag is the release this came from, resolved — so a caller that asked
	// for "latest" learns what latest meant.
	Tag string
	// BinaryPath is the extracted cloop executable.
	BinaryPath string
	// AssetName is the release archive the binary came out of.
	AssetName string
	// ProvenanceVerified records that the archive's signature was checked
	// against cloop's pinned release identity. False only when the caller
	// passed Options.SkipVerify.
	ProvenanceVerified bool
}

// FetchRelease queries the GitHub releases API for one release by tag.
//
// Separate from FetchLatestRelease because a fleet upgrade is usually *to a
// named version* rather than to whatever is newest: an operator rolling a
// hundred devices forward wants them to land on the same build, and "latest"
// evaluated once per device is not that — a release published midway through
// the rollout would split the fleet across two versions.
func FetchRelease(tag string) (*Release, error) {
	tag = strings.TrimSpace(tag)
	if tag == "" || strings.EqualFold(tag, "latest") {
		return FetchLatestRelease()
	}
	url := fmt.Sprintf("%s/repos/%s/%s/releases/tags/%s",
		githubAPIBase, repoOwner, repoName, tag)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("querying GitHub API for release %s: %w", tag, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Named separately from the generic status error because this is the
		// failure an operator actually hits — a typo in a tag, or a version
		// that exists in their head but was never published — and "HTTP 404"
		// does not say which.
		return nil, fmt.Errorf("no release tagged %s was published for %s/%s",
			tag, repoOwner, repoName)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned HTTP %d for release %s", resp.StatusCode, tag)
	}

	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &rel, nil
}

// StageRelease downloads the release for tag, proves it came from cloop's
// release workflow, and extracts the binary into destDir.
//
// It returns before anything is installed. The caller is responsible for
// destDir's lifetime; a staged binary left behind is an executable nobody is
// watching, so callers that stage into a temporary directory should remove it.
func StageRelease(tag, destDir string, opts Options, progress func(string)) (Staged, error) {
	if progress == nil {
		progress = func(string) {}
	}
	var staged Staged

	rel, err := FetchRelease(tag)
	if err != nil {
		return staged, err
	}
	staged.Tag = rel.TagName

	name := assetName()
	binaryAsset := findAsset(rel.Assets, name)
	legacy := legacyAssetNameFor(rel.TagName, runtime.GOOS, runtime.GOARCH)
	if binaryAsset == nil {
		if binaryAsset = findAsset(rel.Assets, legacy); binaryAsset != nil {
			name = legacy
		}
	}
	if binaryAsset == nil {
		return staged, fmt.Errorf(
			"release %s publishes no asset for %s/%s; expected %s (or %s)",
			rel.TagName, runtime.GOOS, runtime.GOARCH, name, legacy)
	}
	staged.AssetName = binaryAsset.Name

	progress(fmt.Sprintf("Downloading %s...", binaryAsset.Name))
	archiveData, err := downloadBytes(binaryAsset.BrowserDownloadURL, maxArchiveBytes)
	if err != nil {
		return staged, fmt.Errorf("downloading archive: %w", err)
	}

	// The checksum proves the download arrived intact, and nothing more —
	// checksums.txt ships from the same release as the archive. The signature
	// below is the check that matters; this one catches a truncated transfer
	// before cosign reports it as a bad signature, which is a much worse
	// diagnostic for the same underlying problem.
	if checksumAsset := findAsset(rel.Assets, "checksums.txt"); checksumAsset != nil {
		checksumData, err := downloadBytes(checksumAsset.BrowserDownloadURL, maxChecksumsBytes)
		if err != nil {
			return staged, fmt.Errorf("downloading checksums: %w", err)
		}
		expected, ok := parseChecksums(checksumData)[binaryAsset.Name]
		if !ok {
			return staged, fmt.Errorf("checksum not found for %s in checksums.txt", binaryAsset.Name)
		}
		if err := verifySHA256(archiveData, expected); err != nil {
			return staged, err
		}
	}

	if opts.SkipVerify {
		// Reached only when a caller in this process said so. Nothing that
		// crosses the wire can set it — see pkg/executor/remote/upgradeproto.go.
		progress("WARNING: installing without verifying where this binary came from")
	} else {
		if err := verifyArchiveProvenance(rel, binaryAsset.Name, archiveData, opts, progress); err != nil {
			return staged, err
		}
		staged.ProvenanceVerified = true
	}

	binaryData, err := extractBinaryFromTarGz(archiveData)
	if err != nil {
		return staged, fmt.Errorf("extracting cloop from %s: %w", binaryAsset.Name, err)
	}
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return staged, fmt.Errorf("creating staging directory: %w", err)
	}
	// 0700, matching the staging directory: between this write and the
	// installer consuming it, the file is an unreferenced executable, and no
	// other local user should be able to read or replace it.
	path := filepath.Join(destDir, "cloop")
	if err := os.WriteFile(path, binaryData, 0o700); err != nil {
		return staged, fmt.Errorf("writing staged binary: %w", err)
	}
	staged.BinaryPath = path
	return staged, nil
}
