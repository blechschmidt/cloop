package netfilter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// apply.go installs a compiled policy into the host kernel with nft(8).
//
// Shelling out to nft rather than speaking netlink is deliberate. The ruleset
// this package produces is meant to be read: an operator debugging a sandbox
// that cannot reach its registry should be able to run `nft list table inet
// cloop_sbx_<id>` and see the same text cloop generated, with the same
// comments. A netlink implementation would produce equivalent kernel state
// and nothing an operator could diff against the policy.
//
// The whole script goes in on stdin as one `nft -f -` invocation, which nft
// commits as a single transaction. Either the sandbox is filtered by the
// entire policy or it is filtered by none of it and the run fails; there is
// no half-applied state to reason about.

// ErrUnavailable reports that host-side filtering cannot be performed. It is
// a sentinel so callers can degrade deliberately — refusing to start an
// unfiltered sandbox — rather than by pattern-matching an error string.
var ErrUnavailable = errors.New("netfilter: host packet filtering is unavailable")

// applyTimeout bounds an nft invocation. Loading a ruleset is a syscall and a
// commit; a version of it that takes longer than this is a hung host, and
// blocking a task start on it forever is worse than failing the start.
const applyTimeout = 15 * time.Second

// Applier installs and removes rulesets on the host.
//
// The nft path is resolved once at construction, for the same reason
// pkg/executor/container resolves its runtime once: a PATH that changes
// mid-run must not change which binary manipulates the host firewall.
type Applier struct {
	nftPath string
}

// NewApplier locates nft. It performs no privileged operation, so a caller
// can construct one to ask Available() what would happen.
func NewApplier() (*Applier, error) {
	path, err := exec.LookPath("nft")
	if err != nil {
		return nil, fmt.Errorf("%w: nft(8) is not on PATH — install nftables "+
			"(apt install nftables / dnf install nftables)", ErrUnavailable)
	}
	return &Applier{nftPath: path}, nil
}

// Path reports the resolved nft binary, for diagnostics.
func (a *Applier) Path() string { return a.nftPath }

// Available reports whether this process can actually install a ruleset.
//
// It checks by listing, which needs the same CAP_NET_ADMIN a load does but
// changes nothing — so a preflight can call it on a healthy host without side
// effects. The distinction it draws matters: "nft is missing" and "nft is
// present but this process is unprivileged" have completely different fixes,
// and a caller that reported them as one error would send an operator to
// install a package they already have.
func (a *Applier) Available(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, applyTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, a.nftPath, "list", "tables")
	cmd.Env = minimalEnv()
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		detail := firstLine(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		if os.Geteuid() != 0 {
			return fmt.Errorf("%w: nft(8) needs CAP_NET_ADMIN and this process runs as uid %d (%s)",
				ErrUnavailable, os.Geteuid(), detail)
		}
		return fmt.Errorf("%w: nft(8) is present but not usable (%s)", ErrUnavailable, detail)
	}
	return nil
}

// Apply installs the policy, replacing any ruleset previously installed under
// the same table.
//
// Replacement rather than mutation is what makes this safe to call again for
// the same sandbox: the rendered script deletes the table and recreates it in
// one transaction, so a second Apply cannot leave rules from the first
// behind. That is the property a reconcile loop needs.
func (a *Applier) Apply(ctx context.Context, p Policy, opts NftablesOptions) error {
	script, err := RenderNftables(p, opts)
	if err != nil {
		return err
	}
	if err := a.run(ctx, script); err != nil {
		return fmt.Errorf("netfilter: installing table inet %s: %w", opts.Table, err)
	}
	return nil
}

// Remove deletes a sandbox's table.
//
// A table that is already gone is success. Teardown runs on paths that also
// run after a crash, and a cleanup that fails because it has nothing to do
// turns every restart into a spurious error in the log.
func (a *Applier) Remove(ctx context.Context, table string) error {
	if err := ValidateNftName(table); err != nil {
		return err
	}
	// Add-then-delete for the same reason the rendered script does it: the
	// add is a no-op on an existing table and makes the delete total.
	script := fmt.Sprintf("add table inet %s\ndelete table inet %s\n", table, table)
	if err := a.run(ctx, script); err != nil {
		return fmt.Errorf("netfilter: removing table inet %s: %w", table, err)
	}
	return nil
}

// run feeds a script to nft on stdin.
//
// stdin rather than a temp file keeps the ruleset off disk — it names the
// addresses a sandbox is allowed to reach, which is exactly the map an
// attacker on the host would want — and removes a cleanup path that could
// leave one behind.
func (a *Applier) run(ctx context.Context, script string) error {
	ctx, cancel := context.WithTimeout(ctx, applyTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, a.nftPath, "-f", "-")
	cmd.Env = minimalEnv()
	cmd.Stdin = strings.NewReader(script)
	var stderr strings.Builder
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		detail := firstLine(stderr.String())
		if ctx.Err() != nil {
			return fmt.Errorf("nft timed out after %s", applyTimeout)
		}
		if detail == "" {
			detail = err.Error()
		}
		if os.Geteuid() != 0 && strings.Contains(strings.ToLower(detail), "permission denied") {
			return fmt.Errorf("%w: %s (this process runs as uid %d and needs CAP_NET_ADMIN)",
				ErrUnavailable, detail, os.Geteuid())
		}
		return errors.New(detail)
	}
	return nil
}

// minimalEnv is the environment nft runs with.
//
// nft reads no secrets, and the control plane's environment holds provider
// API keys and broker tokens. Handing it an empty-but-for-PATH environment
// costs nothing and keeps one more child process off the list of things that
// could leak them.
func minimalEnv() []string {
	return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
}

// firstLine returns the first non-empty line, which for nft is the one
// naming the file position and the syntax error. The rest is a caret diagram
// that does not survive being embedded in a Go error.
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}

// TableName builds a table name for a sandbox from an identifier.
//
// nft identifiers are narrower than the handle IDs and executor IDs cloop
// generates, so every character outside the grammar becomes an underscore
// and the result is truncated to fit. Collisions are possible in principle
// and harmless in practice only if the caller passes something unique; pass
// the handle ID, which is.
func TableName(prefix, id string) string {
	var b strings.Builder
	b.WriteString("cloop_")
	if prefix != "" {
		b.WriteString(sanitizeNftPart(prefix))
		b.WriteString("_")
	}
	b.WriteString(sanitizeNftPart(id))
	out := b.String()
	if len(out) > nftMaxNameLen {
		out = out[:nftMaxNameLen]
	}
	return strings.TrimRight(out, "_-")
}

func sanitizeNftPart(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}
