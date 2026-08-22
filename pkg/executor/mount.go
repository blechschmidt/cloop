package executor

// mount.go defines the one filesystem primitive a per-project sandbox spec may
// ask for: re-exposing a sub-path of the workload's own workspace at a second
// path inside the sandbox.
//
// The shape is deliberately narrow because of where the request comes from.
// A per-project sandbox spec is repo-committed (.cloop/sandbox.yaml) — it is
// whatever a pull request says it is — so a mount whose source could name an
// arbitrary host path would turn "merge this PR" into "read the control plane's
// /etc/shadow, then bind it somewhere the harness will print it". Sources are
// therefore workspace-relative and nothing else: a sandbox may rearrange what
// it has already been given, never reach past it.
//
// The set of accepted shapes is also the intersection of what both isolated
// drivers can express *identically*. The container driver renders a SpecMount
// as a bind of <workdir>/<source>; Kubernetes renders it as a subPath mount on
// the workspace volume. Anything one driver would have had to approximate was
// left out rather than silently meaning two different things.

import (
	"fmt"
	"path"
	"strings"
)

// MaxSpecMounts bounds how many mounts one spec may request. The limit is not
// about resource exhaustion — it is that a spec approaching it has stopped
// describing a sandbox and started describing a filesystem, and every entry is
// another chance to shadow something the harness needs.
const MaxSpecMounts = 16

// SpecMount re-exposes a path inside the workload's workspace at another
// absolute path inside the sandbox.
//
// The canonical use is a cache: `source: .cache/pip, target: /home/agent/.cache/pip`
// lets a project keep its dependency cache in the repo tree — where it is
// already bind-mounted, already size-bounded, and already discarded with the
// workspace — while the toolchain finds it at the fixed path it insists on.
type SpecMount struct {
	// Source is a slash-separated path relative to Spec.WorkDir. It may not
	// be absolute and may not contain a ".." element.
	Source string `json:"source"`
	// Target is the absolute path the source appears at inside the sandbox.
	Target string `json:"target"`
	// ReadOnly maps the source read-only.
	ReadOnly bool `json:"read_only,omitempty"`
}

// Validate enforces the containment rules.
//
// Rejections are stated in terms of the offending field rather than as a
// generic "invalid mount", because the author of the file is a developer
// writing YAML in a repo, not the operator who will read the log.
func (m SpecMount) Validate() error {
	src, dst := strings.TrimSpace(m.Source), strings.TrimSpace(m.Target)

	switch {
	case src == "":
		return fmt.Errorf("%w: mount source is empty", ErrInvalidSpec)
	case dst == "":
		return fmt.Errorf("%w: mount target is empty (source %q)", ErrInvalidSpec, src)
	}

	// A colon is checked before anything else because it is not merely an
	// invalid path character: the container runtimes' -v flag is
	// colon-separated, so a source containing one would append arbitrary
	// mount options — ":rw", or a third path entirely — to a flag the
	// operator believed they controlled.
	for _, f := range []struct{ name, val string }{{"source", src}, {"target", dst}} {
		if strings.ContainsAny(f.val, ":\x00\n\r") {
			return fmt.Errorf("%w: mount %s %q contains a colon, NUL or newline", ErrInvalidSpec, f.name, f.val)
		}
		if strings.Contains(f.val, `\`) {
			return fmt.Errorf("%w: mount %s %q contains a backslash; use forward slashes", ErrInvalidSpec, f.name, f.val)
		}
	}

	// --- source: relative, clean, contained --------------------------------
	if strings.HasPrefix(src, "/") {
		return fmt.Errorf("%w: mount source %q is absolute; sources are relative to the "+
			"project workspace so a sandbox spec cannot name a host path", ErrInvalidSpec, src)
	}
	if hasDotDot(src) {
		return fmt.Errorf("%w: mount source %q contains a \"..\" element, which would escape the workspace",
			ErrInvalidSpec, src)
	}
	// Cleanliness is checked after the ".." scan so the clearer message wins:
	// path.Clean resolves "a/../../b" to "../b", and reporting that as "not
	// clean" would hide that the author tried to climb out.
	if c := path.Clean(src); c != src {
		return fmt.Errorf("%w: mount source %q is not a clean path (did you mean %q?)", ErrInvalidSpec, src, c)
	}
	if src == "." {
		return fmt.Errorf("%w: mount source \".\" is the whole workspace, which is already mounted", ErrInvalidSpec)
	}

	// --- target: absolute, clean, not the root -----------------------------
	if !strings.HasPrefix(dst, "/") {
		return fmt.Errorf("%w: mount target %q is relative; targets are absolute paths inside the sandbox",
			ErrInvalidSpec, dst)
	}
	if hasDotDot(dst) {
		return fmt.Errorf("%w: mount target %q contains a \"..\" element", ErrInvalidSpec, dst)
	}
	if c := path.Clean(dst); c != dst {
		return fmt.Errorf("%w: mount target %q is not a clean path (did you mean %q?)", ErrInvalidSpec, dst, c)
	}
	if dst == "/" {
		return fmt.Errorf("%w: mount target \"/\" would shadow the sandbox root filesystem", ErrInvalidSpec)
	}
	return nil
}

// hasDotDot reports whether any element of a slash-separated path is "..".
//
// It scans elements rather than substring-matching, so a legitimate directory
// named "..config" or "a..b" is not rejected.
func hasDotDot(p string) bool {
	for _, elem := range strings.Split(p, "/") {
		if elem == ".." {
			return true
		}
	}
	return false
}

// ValidateSpecMounts checks a whole mount list: each entry individually, the
// list length, and that no two entries claim the same target.
//
// Duplicate targets are an error rather than last-one-wins because the two
// drivers resolve the collision differently — the container runtimes take the
// last -v, the kubelet refuses the Pod — and a spec that works on one executor
// and is rejected by the other is exactly the portability break this whole
// feature exists to remove.
func ValidateSpecMounts(mounts []SpecMount) error {
	if len(mounts) > MaxSpecMounts {
		return fmt.Errorf("%w: %d mounts requested, at most %d are allowed",
			ErrInvalidSpec, len(mounts), MaxSpecMounts)
	}
	seen := make(map[string]struct{}, len(mounts))
	for i, m := range mounts {
		if err := m.Validate(); err != nil {
			return fmt.Errorf("mount[%d]: %w", i, err)
		}
		target := strings.TrimSpace(m.Target)
		if _, dup := seen[target]; dup {
			return fmt.Errorf("%w: mount target %q is claimed twice", ErrInvalidSpec, target)
		}
		seen[target] = struct{}{}
	}
	return nil
}
