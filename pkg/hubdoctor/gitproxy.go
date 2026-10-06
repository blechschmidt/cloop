package hubdoctor

// Git interception proxy checks: is a sandbox that pushes a work product
// holding a forge credential, or a session token that can only reach the
// write-back namespace?
//
// This is worth its own check because both states look identical from
// everywhere else. A hub with the proxy off runs, dispatches, provisions and
// pushes exactly like one with it on; the difference is only visible in what a
// sandbox could do if it tried something it was not asked to. Nothing fails,
// so nothing reports — which is precisely the shape of finding this command
// exists to surface.
//
// Reading the config answers most of this, but it cannot answer for the
// advertised URL. That value is handed to a sandbox and consumed on the far
// side of a network boundary, so loopback is the only wrongness legible in the
// text — an address that resolves on the hub and nowhere a Pod can see it
// reads exactly like a correct one. reachability.go dials it for that reason,
// and is deliberate about what a dial from here settles: the hub is not on the
// sandbox's network, and a Service name that fails to resolve here is
// frequently the correct configuration, so the probe reports and never fails.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// checkBranchRestrictedGrants reports GitHub grants whose branch allowlist this
// hub cannot enforce (Task 20340).
//
// A grant can limit its pushes to particular branches, and only the git proxy
// can hold a push to that list. On a hub without one the broker withholds the
// push instead — an App token is minted read-only, a PAT is not delivered — so
// the grant's holder finds out as a refused push or a missing credential, in a
// run, long after whoever wrote the list has moved on. Nothing about that is an
// error anywhere else, which is why it is a finding here.
//
// Read-only over the store's own listing: grants and secret kinds are not
// sealed, so this needs neither the sealing key nor a broker, and it reports
// nothing rather than a second storage failure when the database will not open.
func checkBranchRestrictedGrants(dir string, cfg *config.Config, add addFn) {
	if cfg.Executors.GitProxy.Enabled {
		return
	}
	apps, pats := branchRestrictedGrants(dir)
	if apps+pats == 0 {
		return
	}
	var parts []string
	if apps > 0 {
		parts = append(parts, fmt.Sprintf("%d github_app grant(s) are delivered read-only", apps))
	}
	if pats > 0 {
		parts = append(parts, fmt.Sprintf("%d github_pat grant(s) are not delivered at all", pats))
	}
	add(Finding{
		Check:    "gitproxy.branch_grants",
		Title:    "Branch-restricted GitHub grants",
		Severity: SeverityWarn,
		Message: fmt.Sprintf("%d active grant(s) limit pushes to particular branches, which only the "+
			"git proxy can enforce, and it is disabled: %s", apps+pats, strings.Join(parts, "; ")),
		Remediation: "Enable executors.git_proxy so the branch lists are enforced on the push, or " +
			"re-grant without --branches if an unrestricted push is what was meant. See " +
			"docs/guides/secrets.md#limiting-pushes-to-particular-branches",
		Details: map[string]any{"github_app": apps, "github_pat": pats},
	})
}

// branchRestrictedGrants counts the active GitHub grants that carry a branch
// allowlist, by kind. Zeros when there is no database to read.
func branchRestrictedGrants(dir string) (apps, pats int) {
	grants, _ := activeGitHubGrants(dir)
	for _, g := range grants {
		if !g.restricted {
			continue
		}
		switch g.kind {
		case secretbroker.KindGitHubApp:
			apps++
		case secretbroker.KindGitHubPAT:
			pats++
		}
	}
	return apps, pats
}

// activeGrant is one active grant of a secret.
type activeGrant struct {
	kind       secretbroker.Kind
	restricted bool // carries a branch allowlist
}

// activeGitHubGrants lists the control plane's active grants of GitHub
// credentials; see activeGrants for known.
func activeGitHubGrants(dir string) ([]activeGrant, bool) {
	return activeGrants(dir, secretbroker.KindGitHubApp, secretbroker.KindGitHubPAT)
}

// activeGrants lists the control plane's active grants of secrets of the given
// kinds, read from the store's own listing in the database the hub's broker
// uses. Grants and secret kinds are not sealed, so this needs neither the
// sealing key nor a broker. None, and known, when there is no database yet;
// known is false when there is one and it could not be read, which a caller
// must not take for "no grant" (checkStorage reports why).
func activeGrants(dir string, kinds ...secretbroker.Kind) ([]activeGrant, bool) {
	dbPath := state.DBPath(dir)
	if _, err := os.Stat(dbPath); err != nil {
		return nil, true
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, false
	}
	defer func() { _ = db.Close() }()
	store, err := secretstore.New(db)
	if err != nil {
		return nil, false
	}
	secrets, err := store.ListSecrets()
	if err != nil {
		return nil, false
	}
	want := make(map[secretbroker.Kind]bool, len(kinds))
	for _, k := range kinds {
		want[k] = true
	}
	kindOf := make(map[string]secretbroker.Kind, len(secrets))
	for _, s := range secrets {
		kindOf[s.ID] = s.Kind
	}
	grants, err := store.ListGrants()
	if err != nil {
		return nil, false
	}
	now := time.Now()
	var out []activeGrant
	for _, g := range grants {
		kind := kindOf[g.SecretID]
		if !g.Active(now) || !want[kind] {
			continue
		}
		out = append(out, activeGrant{kind: kind, restricted: g.Constraints.RestrictsBranches()})
	}
	return out, true
}

// checkGitProxy reports whether git pushes from sandboxes are brokered.
func checkGitProxy(ctx context.Context, dir string, cfg *config.Config, opts Options, add addFn) {
	g := cfg.Executors.GitProxy
	likely := gitWorkspacesLikely(dir, cfg)

	if !g.Enabled {
		if f, ok := switchedOffFinding(cfg, "executors.git_proxy", "gitproxy.enabled", "Git interception proxy",
			"the hub runs without the proxy and provisions workspaces as it did before it existed, "+
				"handing the forge credential into the sandbox"); ok {
			add(f)
			return
		}
		// A warning rather than a pass only when there is something to protect.
		// A single-machine install whose executors share the host filesystem
		// never provisions a git workspace at all, so telling its operator to
		// stand up a TLS proxy would be advice for a problem they do not have.
		if !likely {
			add(Finding{
				Check:    "gitproxy.enabled",
				Title:    "Git interception proxy",
				Severity: SeverityPass,
				Message: "disabled, and no configured executor or enrolled device provisions a git " +
					"workspace and no GitHub credential is granted, so no forge credential is " +
					"delivered into a sandbox",
			})
			return
		}
		add(Finding{
			Check:    "gitproxy.enabled",
			Title:    "Git interception proxy",
			Severity: SeverityWarn,
			Message: "disabled while executors that clone the project source, or GitHub grants, " +
				"are configured, so a sandbox is handed the forge credential and the cloop/ branch " +
				"rule is enforced only by code the sandbox itself runs",
			Remediation: "Set executors.git_proxy.enabled: true with cert_file, key_file and " +
				"advertise_url, so the credential stays on the hub and the branch allowlist " +
				"is enforced on the push. See docs/git-interception-proxy.md",
		})
		return
	}

	// --- enabled: does it start, and where does it point sandboxes? ---------

	starts := proxyTLS("gitproxy.tls", "Git proxy TLS material", "executors.git_proxy",
		g.CertFile, g.KeyFile, g.MinTLSVersion,
		"every dispatch that needs a git workspace is refused rather than handed the forge credential", add)

	// The advertised base is the single most common way this is
	// misconfigured, because the wrong value works perfectly on the machine
	// it was written on.
	ep, err := resolveProxyEndpoint(g.AdvertiseURL, g.ListenAddr, gitproxy.DefaultListenAddr, opts.Offline,
		gitproxy.AdvertisedBaseURL, gitproxy.NormalizeBaseURL)
	if err != nil && !ep.fromBind && strings.TrimSpace(g.AdvertiseURL) != "" {
		starts = false
		add(Finding{
			Check: "gitproxy.advertise_url", Title: "Git proxy advertised URL", Severity: SeverityFail,
			Message: fmt.Sprintf("the proxy will not start: %v — executors.git_proxy is enabled, so every "+
				"dispatch that needs a git workspace is refused", err),
			Remediation: "Set executors.git_proxy.advertise_url to an https:// base with a host and no path, " +
				"such as https://cloop-gitproxy.cloop.svc:8443",
		})
	} else {
		reportProxyEndpoint(ctx, opts, ep, err, likely, proxyLabels{
			advertiseCheck: "gitproxy.advertise_url", advertiseTitle: "Git proxy advertised URL",
			reachCheck: "gitproxy.advertise_reachable", reachTitle: "Git proxy reachability",
			what: "the git proxy", key: "executors.git_proxy.advertise_url",
			consequence: "their clone and write-back push will fail to connect",
			example:     "https://cloop-gitproxy.cloop.svc:8443",
		}, add)
	}

	// A widened allowlist is legitimate and deliberate, and worth saying out
	// loud: it is the one setting that decides which branches a sandbox can
	// reach, and its default is the reason the subsystem is a boundary at all.
	pol := g.Policy()
	if widened := widenedRefs(pol.AllowedRefs); len(widened) > 0 {
		add(Finding{
			Check:    "gitproxy.allowed_refs",
			Title:    "Git proxy branch allowlist",
			Severity: SeverityWarn,
			Message: fmt.Sprintf("allows %s, which reaches outside the cloop/ write-back "+
				"namespace, so a sandbox may push to branches a human owns",
				strings.Join(widened, ", ")),
			Remediation: "Remove the widened patterns from executors.git_proxy.allowed_refs " +
				"unless a workload genuinely needs them; the default is " + gitproxy.DefaultAllowedRef,
			Details: map[string]any{"allowed_refs": pol.AllowedRefs},
		})
	}
	if g.AllowDelete {
		add(Finding{
			Check:    "gitproxy.allow_delete",
			Title:    "Git proxy delete authority",
			Severity: SeverityWarn,
			Message: "executors.git_proxy.allow_delete is on, so a sandbox may delete the " +
				"branches it can write — a write-back never needs this",
			Remediation: "Set executors.git_proxy.allow_delete: false",
		})
	}

	if !starts {
		// The failure above is the verdict; a pass here would be a second,
		// contradicting one.
		return
	}
	add(Finding{
		Check:    "gitproxy.enabled",
		Title:    "Git interception proxy",
		Severity: SeverityPass,
		Message: fmt.Sprintf("enabled; the forge credential stays on the hub and pushes are "+
			"limited to %s for %d minutes per session",
			strings.Join(pol.AllowedRefs, ", "), g.SessionTTLMinutes()),
		Details: map[string]any{
			"advertise_url":   ep.base,
			"allowed_refs":    pol.AllowedRefs,
			"session_minutes": g.SessionTTLMinutes(),
		},
	})
}

// gitWorkspacesLikely reports whether a forge credential would reach a
// sandbox on this hub with the proxy off.
//
// The Kubernetes driver and enrolled edge devices provision a git workspace
// (the container driver bind-mounts, and the host driver is the host); strict
// mode is the closest available signal that a hub expects devices it has not
// enrolled yet, and it is the mode under which they are the only way work runs
// at all. And a GitHub grant puts the credential into a sandbox of any kind.
func gitWorkspacesLikely(dir string, cfg *config.Config) bool {
	if cfg.Executors.Kubernetes.Enabled || !cfg.Executors.HostProcessAllowed() {
		return true
	}
	agents, agentsKnown := enrolledAgentsKnown(dir)
	grants, grantsKnown := activeGitHubGrants(dir)
	// A store that could not be read is not evidence of nothing in it.
	return len(agents) > 0 || len(grants) > 0 || !agentsKnown || !grantsKnown
}

// widenedRefs returns the patterns that reach outside the write-back namespace.
//
// The comparison is a prefix test against the default rather than an attempt to
// decide what a glob can match, because the honest question is "did somebody
// add something", not "is this pattern dangerous" — and a check that tried to
// prove the latter would either miss cases or cry wolf. The namespace is the
// proxy's own default, not a copy of it.
func widenedRefs(patterns []string) []string {
	namespace := strings.TrimSuffix(gitproxy.DefaultAllowedRef, "**")
	var out []string
	for _, p := range patterns {
		if !strings.HasPrefix(p, namespace) {
			out = append(out, p)
		}
	}
	return out
}
