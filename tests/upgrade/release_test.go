package upgrade_test

// Obtaining the release to rehearse from.
//
// Which release: the latest one GitHub serves, unless the build under test is
// itself a release (a tag's CI, the release workflow), in which case "latest"
// may already be that very build — a rehearsal from a build to itself proves
// nothing — and the release before it in the published table is used instead.
// CLOOP_UPGRADE_FROM pins one.
//
// How: the archive, its Sigstore bundle and the release's checksums.txt are
// downloaded from the release's download URLs, not the REST API, which allows
// sixty unauthenticated requests an hour per address. They are cached by tag.
// Every use, cached or not, checks the archive against checksums.txt and then
// verifies the bundle with cosign against the release identity pkg/provenance
// pins — the same check a device's installer makes — and only then extracts the
// binary, which must report the tag it was asked for. A cached archive that
// fails is dropped and downloaded again once; nothing unverified is ever run.

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/provenance"
	"github.com/blechschmidt/cloop/pkg/version"
)

const (
	// githubRepo is where releases are published.
	githubRepo = "https://github.com/blechschmidt/cloop"
	// releaseAsset is the archive rehearsed: linux-amd64, the platform every
	// hub this repository deploys runs on, and the one CI runs on.
	releaseAsset = "cloop_linux_amd64.tar.gz"
	// checksumsAsset is the release's own list of what it published.
	checksumsAsset = "checksums.txt"

	maxArchiveBytes = 256 << 20
	maxSmallBytes   = 1 << 20
	maxBinaryBytes  = 512 << 20
)

// errNoNetwork marks a host that could not be reached. It skips the
// rehearsal, naming the host; every other failure fails it.
var errNoNetwork = errors.New("no network")

// releaseSource is where releases are read from: GitHub, or a test's mirror.
type releaseSource struct {
	base   string
	client *http.Client
}

func githubReleases() releaseSource {
	return releaseSource{base: githubRepo, client: &http.Client{Timeout: 2 * time.Minute}}
}

// latestTag resolves releases/latest by the redirect GitHub answers it with,
// which names the tag without spending an API request.
func (s releaseSource) latestTag(ctx context.Context) (string, error) {
	u := s.base + "/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	client := *s.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return "", classifyFetchError(u, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxSmallBytes))
	loc := resp.Header.Get("Location")
	if resp.StatusCode < 300 || resp.StatusCode > 399 || loc == "" {
		return "", fmt.Errorf("GET %s answered %d without a redirect to a tag", u, resp.StatusCode)
	}
	tag := path.Base(strings.TrimRight(loc, "/"))
	if !version.IsRelease(tag) {
		return "", fmt.Errorf("GET %s redirected to %s, which names no release tag", u, loc)
	}
	return tag, nil
}

// fetch downloads one asset of a release.
func (s releaseSource) fetch(ctx context.Context, tag, name string, limit int64) ([]byte, error) {
	u := s.base + "/releases/download/" + url.PathEscape(tag) + "/" + url.PathEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, classifyFetchError(u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s answered %d: release %s publishes no %s", u, resp.StatusCode, tag, name)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, classifyFetchError(u, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("GET %s: larger than %d bytes", u, limit)
	}
	return data, nil
}

// classifyFetchError wraps a failure to reach a host in errNoNetwork.
func classifyFetchError(u string, err error) error {
	if isNetworkError(err) {
		return fmt.Errorf("%w: %s: %v", errNoNetwork, u, err)
	}
	return fmt.Errorf("GET %s: %w", u, err)
}

// isNetworkError reports a failure to reach a host at all — no route, no DNS,
// nothing answering, a timeout — as opposed to a host that answered wrongly.
func isNetworkError(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	var opErr *net.OpError
	if errors.As(err, &dnsErr) || errors.As(err, &opErr) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return networkWords(err.Error())
}

// networkWords recognises an unreachable host in a tool's own words: cosign
// reaching Sigstore's TUF repository and Rekor reports it in prose.
func networkWords(s string) bool {
	s = strings.ToLower(s)
	for _, w := range []string{
		"dial tcp", "no such host", "connection refused", "network is unreachable",
		"i/o timeout", "tls handshake timeout", "temporary failure in name resolution",
		"server misbehaving", "connection reset by peer",
	} {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// ── which release ────────────────────────────────────────────────────────────

// fromPlan is the release a rehearsal starts from, and why that one.
type fromPlan struct {
	tag string
	why string
}

// planFrom decides the release to rehearse from. pinned is CLOOP_UPGRADE_FROM;
// own is the release the build under test is, "" for any other build; table is
// the published-release table that build carries; latest resolves
// releases/latest and is called only when it is needed.
func planFrom(pinned, own string, table []version.Release, latest func() (string, error)) (fromPlan, error) {
	if pinned = strings.TrimSpace(pinned); pinned != "" {
		if !version.IsRelease(pinned) {
			return fromPlan{}, fmt.Errorf("%s=%q names no release tag", fromEnv, pinned)
		}
		return fromPlan{tag: pinned, why: fromEnv + " pins it"}, nil
	}
	if own != "" {
		// The newest published release ordered before this one. latest may
		// already be own itself, or even a later release when an older tag's
		// workflow is re-run.
		var prev string
		for _, r := range table {
			if cmp, ok := version.Compare(r.Tag, own); ok && cmp < 0 {
				prev = r.Tag
			}
		}
		if prev == "" {
			return fromPlan{}, fmt.Errorf("the build under test is release %s, and its published-release "+
				"table lists no release before it to rehearse from", own)
		}
		return fromPlan{tag: prev, why: "the build under test is release " + own + ", so the release before it"}, nil
	}
	tag, err := latest()
	if err != nil {
		return fromPlan{}, err
	}
	return fromPlan{tag: tag, why: "releases/latest"}, nil
}

// ownReleaseTag is the release the build under test is, or "": the version it
// reports when that is a release tag, else the tag a tag's workflow runs for,
// else a release tag pointing at the checkout's HEAD.
func ownReleaseTag(info binInfo) string {
	if version.IsRelease(info.Version) {
		return info.Version
	}
	if os.Getenv("GITHUB_REF_TYPE") == "tag" && version.IsRelease(os.Getenv("GITHUB_REF_NAME")) {
		return os.Getenv("GITHUB_REF_NAME")
	}
	out, err := exec.Command("git", "-C", repoRoot(), "tag", "--points-at", "HEAD").Output()
	if err != nil {
		return ""
	}
	for _, tag := range strings.Fields(string(out)) {
		if version.IsRelease(tag) {
			return tag
		}
	}
	return ""
}

// ── fetching, verifying, caching ─────────────────────────────────────────────

// release is a published release, verified and extracted.
type release struct {
	tag    string
	bin    string
	info   binInfo
	cached bool
}

// releaseFiles are the three files a release is verified from.
var releaseFiles = []string{releaseAsset, provenance.BundleNameFor(releaseAsset), checksumsAsset}

// obtainRelease returns tag's binary, extracted into dir from an archive that
// passed its checksum and its signature, from the cache when it holds the tag.
func obtainRelease(ctx context.Context, src releaseSource, cache, tag, dir string, v *provenance.Verifier,
	logf func(string, ...any)) (release, error) {
	if !version.IsRelease(tag) {
		return release{}, fmt.Errorf("%q is not a release tag", tag)
	}
	if err := v.Available(); err != nil {
		return release{}, fmt.Errorf("%w — the release is verified before it runs: install cosign "+
			"(https://github.com/sigstore/cosign/releases) or name it with %s", err, cosignEnv)
	}
	entry := filepath.Join(cache, tag)
	cached := cacheHolds(entry)
	if !cached {
		if err := download(ctx, src, cache, tag); err != nil {
			return release{}, err
		}
	}
	rel, err := verifyAndExtract(ctx, entry, tag, dir, v)
	if err != nil && cached && !errors.Is(err, errNoNetwork) {
		// A cache entry that fails is never used: say so, drop it, and try
		// once more with what GitHub serves now.
		logf("the cached %s failed verification (%v); downloading it again", tag, err)
		if rmErr := os.RemoveAll(entry); rmErr != nil {
			return release{}, fmt.Errorf("drop the cached %s: %w", tag, rmErr)
		}
		cached = false
		if err := download(ctx, src, cache, tag); err != nil {
			return release{}, err
		}
		rel, err = verifyAndExtract(ctx, entry, tag, dir, v)
	}
	if err != nil {
		return release{}, err
	}
	rel.cached = cached
	return rel, nil
}

func cacheHolds(entry string) bool {
	for _, name := range releaseFiles {
		if fi, err := os.Stat(filepath.Join(entry, name)); err != nil || !fi.Mode().IsRegular() || fi.Size() == 0 {
			return false
		}
	}
	return true
}

// download fetches the release's three files into the cache, under a
// temporary name renamed into place, so a run that dies midway leaves no
// half-written entry behind.
func download(ctx context.Context, src releaseSource, cache, tag string) error {
	if err := os.MkdirAll(cache, 0o755); err != nil {
		return fmt.Errorf("create the release cache %s: %w", cache, err)
	}
	tmp, err := os.MkdirTemp(cache, "."+tag+".partial-")
	if err != nil {
		return fmt.Errorf("stage a download in %s: %w", cache, err)
	}
	defer os.RemoveAll(tmp)
	limits := map[string]int64{releaseAsset: maxArchiveBytes}
	for _, name := range releaseFiles {
		limit := limits[name]
		if limit == 0 {
			limit = maxSmallBytes
		}
		data, err := src.fetch(ctx, tag, name, limit)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(tmp, name), data, 0o644); err != nil {
			return err
		}
	}
	entry := filepath.Join(cache, tag)
	_ = os.RemoveAll(entry)
	if err := os.Rename(tmp, entry); err != nil {
		return fmt.Errorf("move the download into the cache: %w", err)
	}
	return nil
}

// verifyAndExtract checks the cached archive against checksums.txt and its
// signature, then extracts the binary into dir and asks it what it is.
func verifyAndExtract(ctx context.Context, entry, tag, dir string, v *provenance.Verifier) (release, error) {
	archive := filepath.Join(entry, releaseAsset)
	data, err := os.ReadFile(archive)
	if err != nil {
		return release{}, err
	}
	sums, err := os.ReadFile(filepath.Join(entry, checksumsAsset))
	if err != nil {
		return release{}, err
	}
	want, ok := parseChecksums(sums)[releaseAsset]
	if !ok {
		return release{}, fmt.Errorf("%s's checksums.txt lists no %s", tag, releaseAsset)
	}
	got := sha256.Sum256(data)
	if hex.EncodeToString(got[:]) != want {
		return release{}, fmt.Errorf("%s's %s does not match its checksum: %x, want %s", tag, releaseAsset, got, want)
	}
	if err := v.VerifyBlob(ctx, archive, filepath.Join(entry, provenance.BundleNameFor(releaseAsset))); err != nil {
		if networkWords(err.Error()) {
			return release{}, fmt.Errorf("%w: cosign could not reach Sigstore to verify %s: %v", errNoNetwork, tag, err)
		}
		return release{}, fmt.Errorf("%s's %s is not signed by cloop's release workflow: %w", tag, releaseAsset, err)
	}
	bin, err := extractBinary(data, dir)
	if err != nil {
		return release{}, fmt.Errorf("extract cloop from %s's %s: %w", tag, releaseAsset, err)
	}
	info, err := readBinInfo(bin)
	if err != nil {
		return release{}, err
	}
	if info.Version != tag {
		return release{}, fmt.Errorf("the binary in %s's %s reports version %q", tag, releaseAsset, info.Version)
	}
	return release{tag: tag, bin: bin, info: info}, nil
}

// parseChecksums reads the "<hex>  <name>" lines sha256sum writes.
func parseChecksums(data []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 {
			out[strings.TrimPrefix(f[1], "*")] = strings.ToLower(f[0])
		}
	}
	return out
}

// extractBinary writes the archive's cloop executable to dir/cloop.
func extractBinary(archive []byte, dir string) (string, error) {
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return "", err
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return "", errors.New("no cloop executable in the archive")
		}
		if err != nil {
			return "", err
		}
		if hdr.Typeflag != tar.TypeReg || path.Base(path.Clean(hdr.Name)) != "cloop" {
			continue
		}
		if hdr.Size > maxBinaryBytes {
			return "", fmt.Errorf("cloop in the archive is %d bytes", hdr.Size)
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
		bin := filepath.Join(dir, "cloop")
		f, err := os.OpenFile(bin, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(f, io.LimitReader(tr, maxBinaryBytes)); err != nil {
			_ = f.Close()
			return "", err
		}
		return bin, f.Close()
	}
}

// ── what a binary is ─────────────────────────────────────────────────────────

// binInfo is what `cloop version --json` reports.
type binInfo struct {
	Version     string `json:"version"`
	Protocol    int    `json:"protocol"`
	MinProtocol int    `json:"min_protocol"`
	Commit      string `json:"commit"`
	Sequence    int    `json:"sequence"`
	Schema      int    `json:"schema"`
}

func readBinInfo(bin string) (binInfo, error) {
	cmd := exec.Command(bin, "version", "--json")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + os.TempDir(), "NO_COLOR=1", "TERM=dumb"}
	cmd.Dir = os.TempDir()
	out, err := cmd.Output()
	if err != nil {
		return binInfo{}, fmt.Errorf("%s version --json: %w", bin, err)
	}
	var info binInfo
	if err := json.Unmarshal(out, &info); err != nil {
		return binInfo{}, fmt.Errorf("%s version --json printed %q: %w", bin, out, err)
	}
	if info.Schema <= 0 {
		return binInfo{}, fmt.Errorf("%s version --json reports no schema: %s", bin, out)
	}
	return info, nil
}

// repoRoot is this checkout's root.
func repoRoot() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return filepath.Join(wd, "..", "..")
}
