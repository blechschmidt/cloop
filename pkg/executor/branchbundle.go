// branchbundle.go describes how one git branch travels into a sandbox with a
// Spec (Task 20367).
//
// A feature (pkg/feature) is a linked git worktree of a project's repository,
// on the hub. Its .git is a one-line pointer to the parent repository's
// .git/worktrees/<slug>, by absolute path, so the worktree is meaningless
// anywhere but on the hub: a container that mounts it sees a .git that names a
// directory it does not have, and a remote device never sees it at all. Mounting
// the parent's .git in as well would make it resolve — and would hand the
// sandbox the hub's own repository configuration and hooks, which run on the
// host at the next hub-side git operation. That is not an option.
//
// So a feature does not travel as a worktree. It travels as a standalone
// checkout of its branch, built on the far side from a git bundle the hub
// produces:
//
//   - on top of a git workspace (Kind git), when the parent repository has an
//     https upstream that already holds the feature's base: the executor clones
//     the upstream at the base exactly as it would for the project, and the
//     bundle carries only the commits the feature has added;
//   - on its own (Kind bundle), for a repository that exists only on the hub:
//     the bundle carries the whole branch, or — when that is too large — a
//     shallow slice of it, with the commits whose parents were left out named
//     in Shallow so the receiver can record the boundary before it fetches.
//
// Either way the tree ends up on the branch itself, attached, so a harness that
// commits commits to the feature's branch; and the work comes back as a
// write-back bundle onto the same branch, vetted on the hub before anything
// moves (see writeback.go and pkg/writeback).
//
// The bytes never travel inside the Spec. A Spec is persisted, audited and
// re-read after a restart, and tens of megabytes of pack in any of those is an
// outage; the bundle rides beside it — Spec.BranchBundleFile on the hub, a
// stream of chunk frames on the wire — and BranchBundle is only the metadata
// that lets the receiver refuse anything other than the bytes the hub meant.
package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// Bounds on a shipped branch. Both directions of a feature run move bundles,
// and the two ceilings are deliberately the same numbers as a write-back's: a
// project that may return 32 MiB of work should be able to receive as much.
const (
	// DefaultBranchBundleBytes is the cap a hub applies to a shipped branch
	// when its configuration names none.
	DefaultBranchBundleBytes int64 = DefaultWriteBackBundleBytes
	// MaxBranchBundleBytes is the hard ceiling: no configuration may raise a
	// shipped branch past it, and a receiver refuses anything larger whatever
	// the metadata says.
	MaxBranchBundleBytes int64 = MaxWriteBackBundleBytes
	// MaxBranchBundleShallow bounds the shallow boundary. A shallow slice of a
	// branch has one boundary commit per parent left out, which is one for a
	// linear history and a handful for a merge-heavy one; this is far above
	// any real slice and small enough that a receiver writing them to
	// .git/shallow is not an unbounded write.
	MaxBranchBundleShallow = 256
)

// BranchBundle is the metadata of a git branch shipped with a Spec.
//
// It carries no credential and no bytes: the bundle itself travels beside the
// Spec, and this is what lets the receiver check that what arrived is what the
// control plane sent.
type BranchBundle struct {
	// Branch is the branch the provisioned tree is left on, attached, so the
	// harness's commits land on it. It must live under the cloop/ namespace —
	// the same rule a write-back branch obeys, and for the same reason: the
	// receiver force-creates it.
	Branch string `json:"branch"`
	// Head is the commit Branch points at in the bundle, full 40-hex. The
	// receiver verifies the checkout lands exactly here.
	Head string `json:"head"`
	// Bytes is the bundle's size. Zero means nothing was shipped: on a git
	// workspace the feature has no commits of its own yet, and Branch is
	// created at Workspace.Ref, which must then equal Head.
	Bytes int64 `json:"bytes,omitempty"`
	// SHA256 is the hex digest of the bundle, so a truncated or substituted
	// stream is refused before git reads a byte of it.
	SHA256 string `json:"sha256,omitempty"`
	// Shallow lists the commits at the bundle's lower edge whose parents were
	// deliberately left out, for a Kind bundle workspace shipped as a shallow
	// slice. The receiver records them as shallow before fetching; without
	// that git refuses the bundle as incomplete.
	Shallow []string `json:"shallow,omitempty"`
}

// Describe renders the bundle for a log line. It can never contain a
// credential — BranchBundle has no field that could hold one.
func (b *BranchBundle) Describe() string {
	if b == nil {
		return "no branch"
	}
	s := fmt.Sprintf("branch %s at %s", strings.TrimSpace(b.Branch), ShortSHA(b.Head))
	switch {
	case b.Bytes == 0:
		s += " (no commits shipped)"
	case len(b.Shallow) > 0:
		s += fmt.Sprintf(" (%d-byte shallow bundle)", b.Bytes)
	default:
		s += fmt.Sprintf(" (%d-byte bundle)", b.Bytes)
	}
	return s
}

// validate checks the bundle's own invariants and its fit with the workspace it
// rides on.
//
// Every field becomes an argv element, a ref name or a file write a moment
// later on a machine the hub does not run, which is why each is held to the
// same rule its neighbour in workspace.go or writeback.go already obeys rather
// than to a looser one of its own.
func (b *BranchBundle) validate(w Workspace) error {
	if err := ValidateWriteBackBranch(b.Branch); err != nil {
		return fmt.Errorf("%w: workspace branch_bundle.branch: %w", ErrInvalidSpec, err)
	}
	if err := ValidateCommitSHA(b.Head); err != nil {
		return fmt.Errorf("%w: workspace branch_bundle.head: %w", ErrInvalidSpec, err)
	}
	switch {
	case b.Bytes < 0:
		return fmt.Errorf("%w: workspace branch_bundle.bytes must be >= 0, got %d", ErrInvalidSpec, b.Bytes)
	case b.Bytes > MaxBranchBundleBytes:
		return fmt.Errorf("%w: workspace branch_bundle is %d bytes, over the hard limit of %d",
			ErrInvalidSpec, b.Bytes, MaxBranchBundleBytes)
	}
	if b.Bytes > 0 {
		if !isHexDigest(b.SHA256) {
			return fmt.Errorf("%w: workspace branch_bundle.sha256 %q is not a hex SHA-256 digest",
				ErrInvalidSpec, b.SHA256)
		}
	} else if strings.TrimSpace(b.SHA256) != "" || len(b.Shallow) > 0 {
		// The fields that describe bytes must be empty when there are none,
		// rather than ignored — the same rule Workspace applies to its
		// git-only fields.
		return fmt.Errorf("%w: workspace branch_bundle describes a digest or a shallow boundary "+
			"but ships no bytes", ErrInvalidSpec)
	}
	if len(b.Shallow) > MaxBranchBundleShallow {
		return fmt.Errorf("%w: workspace branch_bundle names %d shallow commits, at most %d are allowed",
			ErrInvalidSpec, len(b.Shallow), MaxBranchBundleShallow)
	}
	for i, s := range b.Shallow {
		if err := ValidateCommitSHA(s); err != nil {
			return fmt.Errorf("%w: workspace branch_bundle.shallow[%d]: %w", ErrInvalidSpec, i, err)
		}
	}

	switch w.Kind {
	case WorkspaceGit:
		// An overlay on a clone: the clone is pinned to the base the bundle
		// was cut from, because a bundle of base..head names base as its
		// prerequisite and is unusable on top of anything else.
		if err := ValidateCommitSHA(w.Ref); err != nil {
			return fmt.Errorf("%w: a branch shipped on top of a git workspace needs the workspace "+
				"pinned to the commit the branch builds on, but the ref is %q: %v",
				ErrInvalidSpec, w.Ref, err)
		}
		if b.Bytes == 0 && b.Head != strings.TrimSpace(w.Ref) {
			return fmt.Errorf("%w: workspace branch_bundle ships no commits, so its head must be the "+
				"workspace ref %s, not %s", ErrInvalidSpec, ShortSHA(w.Ref), ShortSHA(b.Head))
		}
		if len(b.Shallow) > 0 {
			return fmt.Errorf("%w: a branch shipped on top of a git workspace carries a range, not a "+
				"shallow slice; shallow belongs to a bundle workspace", ErrInvalidSpec)
		}
	case WorkspaceBundle:
		if b.Bytes == 0 {
			return fmt.Errorf("%w: a bundle workspace has nothing to build the tree from but the "+
				"bundle, and this one ships no bytes", ErrInvalidSpec)
		}
	default:
		return fmt.Errorf("%w: workspace kind %q cannot carry a shipped branch", ErrInvalidSpec, w.Kind)
	}
	return nil
}

// VerifyFile checks that the file at path is exactly the bundle b describes: a
// regular file, of the stated size, with the stated digest. A bundle that ships
// no bytes has nothing to verify.
//
// Lstat, not Stat: on a machine where a workload has had write access near this
// path, a symbolic link standing in for the bundle would make git read a file
// of the workload's choosing.
func (b *BranchBundle) VerifyFile(path string) error {
	if b == nil || b.Bytes == 0 {
		return nil
	}
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("the bundle for %s did not arrive on this machine", b.Branch)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("the bundle for %s cannot be read: %v", b.Branch, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("the bundle for %s is not a regular file", b.Branch)
	}
	if info.Size() != b.Bytes {
		return fmt.Errorf("the bundle for %s is %d bytes, but the control plane sent %d",
			b.Branch, info.Size(), b.Bytes)
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("the bundle for %s cannot be read: %v", b.Branch, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, MaxBranchBundleBytes+1)); err != nil {
		return fmt.Errorf("the bundle for %s cannot be read: %v", b.Branch, err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != b.SHA256 {
		return fmt.Errorf("the bundle for %s does not match what the control plane sent "+
			"(digest %s, want %s); it was truncated or altered on the way",
			b.Branch, got[:16], b.SHA256[:16])
	}
	return nil
}

// isHexDigest reports whether s is a lowercase hex SHA-256.
func isHexDigest(s string) bool {
	v := strings.TrimSpace(s)
	if len(v) != 64 || v != s {
		return false
	}
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

// BranchBundleExplainer is implemented by a driver that can say why it cannot
// receive a branch shipped from the hub right now: a remote agent knows the
// protocol its device speaks and whether the device has git, and those have
// different remedies. Like EgressScopeExplainer, a method rather than a field,
// so the answer comes from the driver that knows it.
type BranchBundleExplainer interface {
	// ExplainBranchBundleRefusal returns a sentence completing "this executor
	// cannot receive a branch shipped from the control plane; ...", or "" when
	// the driver has nothing more specific than the generic remedy.
	ExplainBranchBundleRefusal() string
}

// branchBundleRemedy asks the driver why, falling back to the generic advice.
func branchBundleRemedy(ex Executor) string {
	if e, ok := ex.(BranchBundleExplainer); ok {
		if s := strings.TrimSpace(e.ExplainBranchBundleRefusal()); s != "" {
			return strings.TrimSuffix(s, ".")
		}
	}
	return "run the feature on a container executor, or on a remote agent whose device has git and " +
		"whose agent is new enough to receive a branch"
}
