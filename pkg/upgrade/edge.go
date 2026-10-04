package upgrade

// edge.go stages builds from the edge channel (Task 20376).
//
// A hub that deploys main speaks a newer executor protocol than any release,
// and a device can only be moved onto a signed artifact. The edge channel is
// that artifact for main: after CI passes on a commit, .github/workflows/
// edge.yml builds it for every release platform, stamped the way the hub's own
// deploy stamps it (dev+g<short sha>), and signs each archive plus a manifest
// that binds them to the commit. Everything is attached to one prerelease,
// tagged "edge", that is never marked latest — so neither `cloop upgrade` nor
// the installer, which only ever ask for the latest release, can see it.
//
// A device names an edge build "edge:<commit>". Resolving that is this file's
// job, and it follows the same rule as a release: the device fetches from its
// own pinned repository, at URLs it computes, and proves every byte against a
// pinned signing identity before anything is extracted. What differs is the
// identity — provenance.EdgeIdentityRegexp, edge.yml on refs/heads/main, never
// the release identity — and one extra binding, because a signature alone does
// not say which commit was built:
//
//  1. The manifest is verified first, against the edge identity, and must name
//     exactly the commit that was asked for. A manifest re-uploaded under
//     another commit's name is refused here.
//  2. Each archive's SHA-256 must be the one the verified manifest lists for
//     it, and the archive must carry its own verified signature. An older
//     signed archive swapped in under a newer commit's name fails the first
//     check even though its signature is genuine.
//  3. The installer then runs the extracted binary and requires it to report
//     the manifest's version (install.UpgradeOptions.ExpectVersion).
//
// So an attacker who can replace release assets but cannot make edge.yml on
// main sign for them can, at most, make an edge upgrade fail.

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/blechschmidt/cloop/pkg/version"
)

const (
	// EdgeTag is the tag of the single prerelease every edge build is attached
	// to. The tag is created once, by the first publish, and never moved: the
	// assets carry their commits in their names, so what the tag points at is
	// immaterial — and a moved tag would rewrite history for anyone who
	// fetched it.
	EdgeTag = "edge"

	// EdgeTargetPrefix starts an upgrade target that names an edge build:
	// "edge:<commit>".
	EdgeTargetPrefix = "edge:"

	// EdgeManifestSchema is the manifest version this build reads.
	EdgeManifestSchema = 1

	// EdgeRetainedCommits is how many commits' builds edge.yml keeps. Older
	// ones are pruned, so a device cannot be sent a build from months ago —
	// and an operator who wants that needs a release.
	EdgeRetainedCommits = 30

	// maxManifestBytes caps a manifest download: the real one is a few hundred
	// bytes.
	maxManifestBytes int64 = 64 << 10
)

// ErrEdgeNotPublished reports that no edge build exists for a commit: CI has
// not published it yet, it failed, or the build was pruned.
var ErrEdgeNotPublished = errors.New("upgrade: no edge build is published for that commit")

// ErrEdgeTarget reports a target that is not edge:<commit>.
var ErrEdgeTarget = version.ErrEdgeTarget

// ErrEdgeManifest reports a manifest that does not describe the build that
// was asked for.
var ErrEdgeManifest = errors.New("upgrade: the edge manifest does not match")

// EdgeTarget formats the upgrade target naming commit's edge build.
func EdgeTarget(commit string) string { return version.EdgeTarget(commit) }

// IsEdgeTarget reports whether s names an edge build; see version.IsEdgeTarget.
func IsEdgeTarget(s string) bool { return version.IsEdgeTarget(s) }

// ParseEdgeTarget returns the commit an "edge:<commit>" target names.
func ParseEdgeTarget(s string) (string, error) { return version.ParseEdgeTarget(s) }

// isHexCommit reports whether s is between min and 40 lowercase hex digits.
func isHexCommit(s string, min int) bool { return version.IsCommit(s, min) }

// isHex reports whether s is exactly n lowercase hex digits.
func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, r := range s {
		if !('0' <= r && r <= '9' || 'a' <= r && r <= 'f') {
			return false
		}
	}
	return true
}

// IsFullCommit reports whether s is a full 40-digit commit id.
func IsFullCommit(s string) bool { return len(s) == 40 && isHexCommit(s, 40) }

// EdgeArchiveName is the asset name of commit's archive for one platform.
//
// The release name with the commit in it. scripts/build-edge.sh renames the
// release script's archives to exactly this, and edge_assets_test.go fails if
// the two drift.
func EdgeArchiveName(commit, goos, goarch string) string {
	return fmt.Sprintf("cloop_%s_%s_%s.tar.gz", commit, goos, goarch)
}

// EdgeManifestName is the asset name of commit's manifest.
func EdgeManifestName(commit string) string {
	return fmt.Sprintf("cloop_%s_manifest.json", commit)
}

// EdgeManifest describes one commit's edge build. edge.yml writes it, signs it,
// and publishes it beside the archives.
type EdgeManifest struct {
	// Schema is EdgeManifestSchema.
	Schema int `json:"schema"`
	// Commit is the full commit id that was built.
	Commit string `json:"commit"`
	// Version is what the binaries report: dev+g<short commit>, the stamp the
	// hub's own deploy gives the same commit.
	Version string `json:"version"`
	// Protocol is the newest executor protocol the binaries speak, read from
	// the built binary itself (`cloop version --json`). The hub offers a
	// device this build only if it does not lower the device's protocol.
	Protocol int `json:"protocol"`
	// Archives maps each archive's asset name to its SHA-256.
	Archives map[string]string `json:"archives"`
	// BuiltAt and Run say when and by which workflow run, for a human.
	BuiltAt string `json:"built_at,omitempty"`
	Run     string `json:"run,omitempty"`
}

// Validate checks that m describes commit's edge build. commit must be the
// full 40-digit id.
func (m EdgeManifest) Validate(commit string) error {
	commit = strings.ToLower(strings.TrimSpace(commit))
	switch {
	case m.Schema != EdgeManifestSchema:
		return fmt.Errorf("%w: schema %d, this build reads %d", ErrEdgeManifest, m.Schema, EdgeManifestSchema)
	case m.Commit != commit:
		return fmt.Errorf("%w: it describes commit %q, not %s", ErrEdgeManifest, m.Commit, commit)
	case !versionNamesCommit(m.Version, commit):
		return fmt.Errorf("%w: version %q is not dev+g<a prefix of %s>", ErrEdgeManifest, m.Version, commit)
	case m.Protocol < 1:
		return fmt.Errorf("%w: protocol %d", ErrEdgeManifest, m.Protocol)
	case len(m.Archives) == 0:
		return fmt.Errorf("%w: it lists no archives", ErrEdgeManifest)
	}
	for name, sum := range m.Archives {
		if !strings.HasPrefix(name, "cloop_"+commit+"_") || !strings.HasSuffix(name, ".tar.gz") {
			return fmt.Errorf("%w: archive %q is not named for commit %s", ErrEdgeManifest, name, commit)
		}
		if !isHex(sum, 64) {
			return fmt.Errorf("%w: archive %q has no SHA-256", ErrEdgeManifest, name)
		}
	}
	return nil
}

// versionNamesCommit reports whether v is dev+g<prefix of commit>, the prefix
// at least seven digits.
func versionNamesCommit(v, commit string) bool {
	rest, ok := strings.CutPrefix(v, "dev+g")
	return ok && isHexCommit(rest, 7) && strings.HasPrefix(commit, rest)
}

// EdgeVersion is the version an edge build of commit reports: dev+g and the
// first seven digits, which is what pkg/version gives an in-checkout build and
// what the hub's deploy stamps today.
func EdgeVersion(commit string) string {
	c := strings.ToLower(strings.TrimSpace(commit))
	if len(c) > 7 {
		c = c[:7]
	}
	return "dev+g" + c
}

// VersionCommit returns the commit prefix a dev build's version names; see
// version.CommitOf.
func VersionCommit(v string) (string, bool) { return version.CommitOf(v) }

// SameCommit reports whether two versions or commits name the same commit;
// see version.SameCommit.
func SameCommit(a, b string) bool { return version.SameCommit(a, b) }

// edgeDownloadBase is where the pinned repository serves the edge release's
// assets. A function of the pinned owner and name, not configuration: the hub
// never supplies it, and neither does anything else that crosses the wire.
func edgeDownloadBase() string {
	return fmt.Sprintf("https://github.com/%s/%s/releases/download/%s/", repoOwner, repoName, EdgeTag)
}

// EdgeAssetURL is the download URL of one edge asset, for display.
func EdgeAssetURL(name string) string { return edgeDownloadBase() + name }

// downloadEdge fetches one asset, distinguishing "not there" from a failure.
func downloadEdge(ctx context.Context, base, name string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+name, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("%w: %s is not published", ErrEdgeNotPublished, name)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("downloading %s: HTTP %d", name, resp.StatusCode)
	}
	return provider.ReadResponseBody(resp.Body, maxBytes)
}

// parseManifest decodes a manifest.
func parseManifest(data []byte) (EdgeManifest, error) {
	var m EdgeManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return m, fmt.Errorf("%w: not JSON: %v", ErrEdgeManifest, err)
	}
	return m, nil
}

// FetchEdgeManifest downloads commit's manifest WITHOUT verifying its
// signature, for the hub's advice: whether the build exists and which protocol
// it claims. The hub decides only what to offer with it; the device that
// installs the build verifies everything itself and refuses a lower protocol
// on its own. commit must be the full id.
func FetchEdgeManifest(ctx context.Context, commit string) (EdgeManifest, error) {
	return fetchEdgeManifestFrom(ctx, edgeDownloadBase(), commit)
}

func fetchEdgeManifestFrom(ctx context.Context, base, commit string) (EdgeManifest, error) {
	commit = strings.ToLower(strings.TrimSpace(commit))
	if !IsFullCommit(commit) {
		return EdgeManifest{}, fmt.Errorf("%w: %q is not a full commit id", ErrEdgeTarget, commit)
	}
	data, err := downloadEdge(ctx, base, EdgeManifestName(commit), maxManifestBytes)
	if err != nil {
		return EdgeManifest{}, err
	}
	m, err := parseManifest(data)
	if err != nil {
		return m, err
	}
	return m, m.Validate(commit)
}

// StageEdge downloads the edge build target names ("edge:<commit>"), proves it
// was signed by edge.yml on main and built from that commit, and extracts the
// binary into destDir. Nothing is installed.
//
// A short commit is resolved to the full id through the GitHub API first. The
// returned Staged carries the version the binary must report (pass it to the
// installer as ExpectVersion) and the protocol the manifest claims.
//
// There is no unverified mode: Options.SkipVerify is refused here. An
// air-gapped site has no use for builds of main, and the signature is the
// channel's whole trust root.
func StageEdge(target, destDir string, opts Options, progress func(string)) (Staged, error) {
	if progress == nil {
		progress = func(string) {}
	}
	var staged Staged
	if opts.SkipVerify {
		return staged, fmt.Errorf("upgrade: edge builds are installed verified or not at all — " +
			"--insecure-skip-verify does not apply to the edge channel")
	}
	commit, err := ParseEdgeTarget(target)
	if err != nil {
		return staged, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if !IsFullCommit(commit) {
		progress(fmt.Sprintf("Resolving commit %s...", commit))
		full, err := ResolveCommit(ctx, commit)
		if err != nil {
			return staged, err
		}
		commit = full
	}
	staged.Tag = EdgeTarget(commit)
	staged.Commit = commit
	staged.Channel = provenance.ChannelEdge

	base := strings.TrimSpace(opts.EdgeBaseURL)
	if base == "" {
		base = edgeDownloadBase()
	} else if !strings.HasSuffix(base, "/") {
		base += "/"
	}

	verifier := opts.Verifier.ForChannel(provenance.ChannelEdge)
	if err := verifier.Available(); err != nil {
		return staged, fmt.Errorf("%w\n\nInstall cosign from https://github.com/sigstore/cosign/releases: "+
			"every edge build is verified with it before it is installed", err)
	}

	dir, err := os.MkdirTemp("", "cloop-edge-verify-")
	if err != nil {
		return staged, fmt.Errorf("staging download for verification: %w", err)
	}
	defer os.RemoveAll(dir)

	// The manifest first, verified, because it is what says which commit the
	// archives are and what they must hash to.
	manifestName := EdgeManifestName(commit)
	progress(fmt.Sprintf("Downloading %s...", manifestName))
	manifestData, err := downloadEdge(ctx, base, manifestName, maxManifestBytes)
	if err != nil {
		return staged, err
	}
	if err := verifyEdgeAsset(ctx, verifier, base, dir, manifestName, manifestData); err != nil {
		return staged, err
	}
	manifest, err := parseManifest(manifestData)
	if err != nil {
		return staged, err
	}
	if err := manifest.Validate(commit); err != nil {
		return staged, err
	}
	staged.Version = manifest.Version
	staged.Protocol = manifest.Protocol

	name := EdgeArchiveName(commit, runtime.GOOS, runtime.GOARCH)
	want, ok := manifest.Archives[name]
	if !ok {
		return staged, fmt.Errorf("%w: the edge build of %s has no archive for %s/%s (%s)",
			ErrEdgeNotPublished, commit, runtime.GOOS, runtime.GOARCH, name)
	}
	staged.AssetName = name
	progress(fmt.Sprintf("Downloading %s...", name))
	archiveData, err := downloadEdge(ctx, base, name, maxArchiveBytes)
	if err != nil {
		return staged, err
	}
	if err := verifySHA256(archiveData, want); err != nil {
		return staged, fmt.Errorf("%w: %s does not hash to what the signed manifest lists: %v",
			ErrEdgeManifest, name, err)
	}
	if err := verifyEdgeAsset(ctx, verifier, base, dir, name, archiveData); err != nil {
		return staged, err
	}
	staged.ProvenanceVerified = true

	binaryData, err := extractBinaryFromTarGz(archiveData)
	if err != nil {
		return staged, fmt.Errorf("extracting cloop from %s: %w", name, err)
	}
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return staged, fmt.Errorf("creating staging directory: %w", err)
	}
	path := filepath.Join(destDir, "cloop")
	if err := os.WriteFile(path, binaryData, 0o700); err != nil {
		return staged, fmt.Errorf("writing staged binary: %w", err)
	}
	staged.BinaryPath = path
	progress(fmt.Sprintf("Staged %s (%s, protocol v%d).", staged.Tag, staged.Version, staged.Protocol))
	return staged, nil
}

// verifyEdgeAsset fetches name's bundle and verifies data against it with v,
// staging both in dir (private, removed by the caller).
func verifyEdgeAsset(ctx context.Context, v *provenance.Verifier, base, dir, name string, data []byte) error {
	bundleName := provenance.BundleNameFor(name)
	bundleData, err := downloadEdge(ctx, base, bundleName, maxBundleBytes)
	if err != nil {
		if errors.Is(err, ErrEdgeNotPublished) {
			return fmt.Errorf("%w: %s has no signature bundle (%s)", provenance.ErrBundleMissing, name, bundleName)
		}
		return err
	}
	blobPath := filepath.Join(dir, name)
	bundlePath := filepath.Join(dir, bundleName)
	if err := os.WriteFile(blobPath, data, 0o600); err != nil {
		return fmt.Errorf("staging %s: %w", name, err)
	}
	if err := os.WriteFile(bundlePath, bundleData, 0o600); err != nil {
		return fmt.Errorf("staging %s: %w", bundleName, err)
	}
	if err := v.VerifyBlob(ctx, blobPath, bundlePath); err != nil {
		_, identity := v.TrustRoot()
		return fmt.Errorf("%w\n\n%s was not signed by cloop's edge workflow on main (expected identity %s), "+
			"so it is not an edge build of this repository whatever its name says. Refusing to install it",
			err, name, identity)
	}
	return nil
}
