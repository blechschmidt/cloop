package featurehub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/feature"
)

// ShipMode says how a feature's branch travels to its sandbox.
type ShipMode string

const (
	// ShipOverlay: the executor clones the parent's upstream at the feature's
	// base, and the bundle carries only the commits the feature added.
	ShipOverlay ShipMode = "overlay"
	// ShipFull: the bundle carries the whole branch.
	ShipFull ShipMode = "full"
	// ShipShallow: the bundle carries the newest commits of the branch, its
	// lower edge recorded as a shallow boundary.
	ShipShallow ShipMode = "shallow"
)

// shallowDepths are the slices tried, deepest first, when the whole branch is
// over the cap. A deep slice keeps enough history for a harness's `git log` to
// mean something; one commit is the floor below which there is no tree.
var shallowDepths = []int{50, 1}

// ShipRequest asks for a feature's branch as a bundle.
type ShipRequest struct {
	// FeatureDir is the feature's worktree on the hub.
	FeatureDir string
	// Upstream is the parent repository's https upstream, normalised, when the
	// executor the feature runs on can fetch it; empty ships the whole branch.
	// The caller decides — it knows the executor and the project's grants.
	Upstream string
	// MaxBytes caps the bundle. 0 is executor.DefaultBranchBundleBytes; a
	// value over executor.MaxBranchBundleBytes is refused.
	MaxBytes int64
}

// Shipment is a feature's branch, ready to travel.
type Shipment struct {
	Mode ShipMode
	// Branch and Head are the feature's branch and the commit it is at.
	Branch string
	Head   string
	// Base and Upstream are, for an overlay, the commit the executor's clone
	// is pinned at and the repository it clones.
	Base     string
	Upstream string
	// Shallow is a shallow slice's lower edge.
	Shallow []string
	// File is the bundle, owned by the caller (see Remove); empty when the
	// overlay ships no commits.
	File   string
	Bytes  int64
	SHA256 string
}

// TooLargeError reports a branch that does not fit under the cap even as a
// single commit.
type TooLargeError struct {
	Branch string
	// Smallest is the smallest bundle that could be built.
	Smallest int64
	Limit    int64
}

func (e *TooLargeError) Error() string {
	return fmt.Sprintf("the feature's branch %s is %s even as a single commit, over the %s limit for "+
		"shipping it to an isolating executor (executors.feature_bundle_mb); raise the limit, or "+
		"push the branch's base to the project's https upstream so only the feature's own commits "+
		"have to travel", e.Branch, mib(e.Smallest), mib(e.Limit))
}

// Is lets callers match executor.ErrWorkspaceUnavailable.
func (e *TooLargeError) Is(target error) bool { return target == executor.ErrWorkspaceUnavailable }

func mib(n int64) string {
	if n >= 1<<20 {
		return strconv.FormatFloat(float64(n)/(1<<20), 'f', 1, 64) + " MiB"
	}
	return strconv.FormatInt(n, 10) + " bytes"
}

// BranchBundle is the shipment's metadata as a Spec carries it.
func (s *Shipment) BranchBundle() *executor.BranchBundle {
	b := &executor.BranchBundle{Branch: s.Branch, Head: s.Head, Bytes: s.Bytes, SHA256: s.SHA256}
	if len(s.Shallow) > 0 {
		b.Shallow = append([]string(nil), s.Shallow...)
	}
	return b
}

// Workspace is the workspace a Spec carries for this shipment: a git workspace
// pinned at the base with the branch on top for an overlay, a bundle workspace
// otherwise. grant names the credential the overlay's clone is fetched with.
func (s *Shipment) Workspace(sizeLimitMB int, grant string) executor.Workspace {
	if s.Mode == ShipOverlay {
		return executor.Workspace{
			Kind:            executor.WorkspaceGit,
			Repo:            s.Upstream,
			Ref:             s.Base,
			CredentialGrant: grant,
			SizeLimitMB:     sizeLimitMB,
			Branch:          s.BranchBundle(),
		}
	}
	return executor.Workspace{Kind: executor.WorkspaceBundle, SizeLimitMB: sizeLimitMB, Branch: s.BranchBundle()}
}

// Describe renders the shipment for the run's journal.
func (s *Shipment) Describe() string {
	switch s.Mode {
	case ShipOverlay:
		if s.Bytes == 0 {
			return fmt.Sprintf("%s at %s, cloned from %s with no commits of its own yet",
				s.Branch, executor.ShortSHA(s.Head), s.Upstream)
		}
		return fmt.Sprintf("%s at %s, its commits shipped as a %s bundle on top of %s at %s",
			s.Branch, executor.ShortSHA(s.Head), mib(s.Bytes), s.Upstream, executor.ShortSHA(s.Base))
	case ShipShallow:
		return fmt.Sprintf("%s at %s, its newest history shipped as a %s shallow bundle",
			s.Branch, executor.ShortSHA(s.Head), mib(s.Bytes))
	default:
		return fmt.Sprintf("%s at %s, shipped whole as a %s bundle",
			s.Branch, executor.ShortSHA(s.Head), mib(s.Bytes))
	}
}

// Remove deletes the bundle file. Idempotent and nil-safe.
func (s *Shipment) Remove() {
	if s == nil || s.File == "" {
		return
	}
	_ = os.Remove(s.File)
	s.File = ""
}

// Ship produces the bundle a feature's sandbox is built from.
func Ship(ctx context.Context, req ShipRequest) (*Shipment, error) {
	parent, slug, ok := feature.ParentOf(req.FeatureDir)
	if !ok {
		return nil, fmt.Errorf("%s is not a feature", req.FeatureDir)
	}
	meta, err := feature.LoadMeta(req.FeatureDir)
	if err != nil {
		return nil, fmt.Errorf("read the feature's record: %w", err)
	}
	if meta.Slug != slug {
		return nil, fmt.Errorf("the feature record in %s names %q", req.FeatureDir, meta.Slug)
	}
	limit := req.MaxBytes
	switch {
	case limit == 0:
		limit = executor.DefaultBranchBundleBytes
	case limit < 0 || limit > executor.MaxBranchBundleBytes:
		return nil, fmt.Errorf("a branch bundle limit of %d bytes is outside (0, %d]", limit, executor.MaxBranchBundleBytes)
	}

	g, err := newGitRunner(ctx, parent)
	if err != nil {
		return nil, err
	}
	branchRef := "refs/heads/" + meta.Branch
	head, err := g.commitOf(ctx, branchRef)
	if err != nil {
		return nil, fmt.Errorf("the feature's branch %s cannot be read: %w", meta.Branch, err)
	}
	sh := &Shipment{Branch: meta.Branch, Head: head}
	smallest := int64(-1)
	note := func(n int64) {
		if smallest < 0 || n < smallest {
			smallest = n
		}
	}

	if up := strings.TrimSpace(req.Upstream); up != "" && overlayable(ctx, g, meta.BaseCommit, head) {
		sh.Mode, sh.Base, sh.Upstream = ShipOverlay, meta.BaseCommit, up
		if head == meta.BaseCommit {
			return sh, nil
		}
		file, size, err := g.bundle(ctx, meta.BaseCommit+".."+branchRef)
		if err != nil {
			return nil, err
		}
		if size <= limit {
			return sh, sh.finish(file, size)
		}
		_ = os.Remove(file)
		note(size)
		// The commits alone are over the cap. A shallow slice of the whole
		// branch can still be smaller — a feature that churned a large file
		// many times carries every version in the range and one in a slice —
		// so the bundle modes below get their turn.
		sh.Mode, sh.Base, sh.Upstream = "", "", ""
	}

	file, size, err := g.bundle(ctx, branchRef)
	if err != nil {
		return nil, err
	}
	if size <= limit {
		sh.Mode = ShipFull
		return sh, sh.finish(file, size)
	}
	_ = os.Remove(file)
	note(size)

	for _, depth := range shallowDepths {
		file, size, shallow, err := g.shallowBundle(ctx, parent, meta.Branch, depth)
		if err != nil {
			return nil, err
		}
		if size <= limit {
			sh.Mode, sh.Shallow = ShipShallow, shallow
			return sh, sh.finish(file, size)
		}
		_ = os.Remove(file)
		note(size)
	}
	return nil, &TooLargeError{Branch: meta.Branch, Smallest: smallest, Limit: limit}
}

// overlayable reports whether a feature can be shipped as its commits on top
// of an upstream clone: its base is a commit, is on the upstream as of the
// last fetch, and is still an ancestor of the branch. A base that was never
// pushed, or a branch rebased off it, cannot be.
func overlayable(ctx context.Context, g *gitRunner, base, head string) bool {
	if executor.ValidateCommitSHA(base) != nil {
		return false
	}
	out, err := g.run(ctx, "for-each-ref", "--contains", base, "--count=1", "--format=%(refname)", "refs/remotes/origin/")
	if err != nil || strings.TrimSpace(out) == "" {
		return false
	}
	ok, err := g.isAncestor(ctx, base, head)
	return err == nil && ok
}

// finish records the bundle file on the shipment.
func (s *Shipment) finish(file string, size int64) error {
	digest, err := fileDigest(file)
	if err != nil {
		_ = os.Remove(file)
		return err
	}
	s.File, s.Bytes, s.SHA256 = file, size, digest
	return nil
}

// bundle writes `git bundle create` of revs to a new temporary file.
func (g *gitRunner) bundle(ctx context.Context, revs ...string) (string, int64, error) {
	return g.bundleIn(ctx, g.dir, revs...)
}

func (g *gitRunner) bundleIn(ctx context.Context, dir string, revs ...string) (string, int64, error) {
	f, err := os.CreateTemp("", "cloop-feature-*.bundle")
	if err != nil {
		return "", 0, fmt.Errorf("create a bundle file: %w", err)
	}
	path := f.Name()
	_ = f.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		_ = os.Remove(path)
		return "", 0, err
	}
	args := append([]string{"bundle", "create", "--quiet", path}, revs...)
	if _, err := g.runIn(ctx, dir, nil, args...); err != nil {
		_ = os.Remove(path)
		return "", 0, fmt.Errorf("bundle the feature's branch: %w", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		_ = os.Remove(path)
		return "", 0, err
	}
	return path, info.Size(), nil
}

// shallowBundle bundles the newest depth commits of branch, by way of a shallow
// clone of the parent: a bundle made in a shallow repository carries no
// prerequisites, and the clone's shallow file is the boundary the receiver has
// to record before fetching it.
func (g *gitRunner) shallowBundle(ctx context.Context, parent, branch string, depth int) (string, int64, []string, error) {
	tmp, err := os.MkdirTemp("", "cloop-feature-shallow-")
	if err != nil {
		return "", 0, nil, err
	}
	defer os.RemoveAll(tmp)
	repo := filepath.Join(tmp, "repo")
	if _, err := g.runIn(ctx, tmp, [][2]string{{"protocol.file.allow", "always"}},
		"clone", "--quiet", "--bare", "--no-local", "--no-tags", "--single-branch",
		"--depth", strconv.Itoa(depth), "--branch", branch, "--", "file://"+parent, repo); err != nil {
		return "", 0, nil, fmt.Errorf("take a shallow copy of the feature's branch: %w", err)
	}
	var shallow []string
	if raw, err := os.ReadFile(filepath.Join(repo, "shallow")); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				if err := executor.ValidateCommitSHA(line); err != nil {
					return "", 0, nil, fmt.Errorf("the shallow copy's boundary is unreadable: %w", err)
				}
				shallow = append(shallow, line)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", 0, nil, err
	}
	if len(shallow) > executor.MaxBranchBundleShallow {
		return "", 0, nil, fmt.Errorf("the shallow copy has %d boundary commits, more than the %d a "+
			"bundle may carry", len(shallow), executor.MaxBranchBundleShallow)
	}
	path, size, err := g.bundleIn(ctx, repo, "refs/heads/"+branch)
	if err != nil {
		return "", 0, nil, err
	}
	return path, size, shallow, nil
}

// fileDigest is the hex SHA-256 of a file.
func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
