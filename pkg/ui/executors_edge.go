package ui

// executors_edge.go is what the hub knows about its own build on the edge
// channel (Task 20376), for the Executors panel's Upgrade dialog, the Upgrade
// API and the auto-update planner.
//
// The hub at :8888 runs dev+g<commit> from main. After CI passes on that
// commit, edge.yml publishes a signed build of it, and a device whose operator
// put it on the edge channel can be moved there from here. Whether that has
// happened — and if not, which of "the deploy built an unpushed commit", "CI
// has not published it yet" and "CI failed" is true — is resolved through
// GitHub and cached like "latest": GitHub's unauthenticated API allows sixty
// requests an hour, and a panel reload must not spend them.
//
// What is resolved here is advice. The hub reads the manifest without
// verifying it, to decide what to offer and to keep its promise never to
// lower a device's protocol; the device that installs the build verifies the
// manifest and every archive against the edge workflow's identity itself, and
// refuses a lower protocol on its own.

import (
	"context"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/upgrade"
	"github.com/blechschmidt/cloop/pkg/version"
)

// edgeLookupTimeout bounds one resolution: a commit lookup, a manifest
// download and, on a miss, one workflow-runs request.
const edgeLookupTimeout = 8 * time.Second

// edgePendingTTL is how long an unpublished answer is reused. Shorter than a
// published one's (latestReleaseTTL): "CI is still running" is expected to
// change within the hour, and the operator waiting on it should see it do so.
const edgePendingTTL = 5 * time.Minute

// resolveEdgeBuild asks GitHub. Indirected so tests never do.
var resolveEdgeBuild = upgrade.ResolveEdgeBuild

// edgeBuildCache remembers the last answer for the hub's build. One lookup at
// a time: a caller arriving while another is resolving waits for it and then
// reads the cache, so a fleet's worth of panel cards costs one lookup.
type edgeBuildCache struct {
	lookup sync.Mutex

	mu      sync.Mutex
	version string
	build   upgrade.EdgeBuild
	at      time.Time
	// commits maps a short commit to its full id. A commit's id never
	// changes, so this is kept for good and the lookup is never repeated.
	commits map[string]string
	now     func() time.Time
}

var hubEdgeCache = newEdgeBuildCache()

func newEdgeBuildCache() *edgeBuildCache {
	return &edgeBuildCache{commits: map[string]string{}, now: time.Now}
}

// cached returns a fresh answer for v, if there is one.
func (c *edgeBuildCache) cached(v string) (upgrade.EdgeBuild, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.version != v || c.at.IsZero() {
		return upgrade.EdgeBuild{}, false
	}
	ttl := edgePendingTTL
	if c.build.Published() {
		ttl = latestReleaseTTL
	}
	if c.now().Sub(c.at) >= ttl {
		return upgrade.EdgeBuild{}, false
	}
	return c.build, true
}

// get resolves v, from the cache when it can.
func (c *edgeBuildCache) get(ctx context.Context, v string) upgrade.EdgeBuild {
	if b, ok := c.cached(v); ok {
		return b
	}
	c.lookup.Lock()
	defer c.lookup.Unlock()
	if b, ok := c.cached(v); ok {
		return b
	}
	short, _ := version.CommitOf(v)
	c.mu.Lock()
	full := c.commits[short]
	c.mu.Unlock()

	b := resolveEdgeBuild(ctx, v, full)

	c.mu.Lock()
	defer c.mu.Unlock()
	if b.Commit != "" && short != "" {
		c.commits[short] = b.Commit
	}
	// A failure to ask is not an answer: the next caller asks again, bounded
	// by its own timeout, as latestReleaseCache does.
	if b.Status != upgrade.EdgeUnknown {
		c.version, c.build, c.at = v, b, c.now()
	}
	return b
}

// hubEdgeOffer describes this hub's own edge build for the offer and refusal
// sentences, or returns nil when the hub runs a release — which the Upgrade
// dialog already offers by name, and which no edge build stands for.
func hubEdgeOffer(ctx context.Context) *executor.EdgeBuild {
	v := hubVersion()
	if version.IsRelease(v) {
		return nil
	}
	return edgeOfferFrom(hubEdgeCache.get(ctx, v))
}

// edgeOfferFrom converts a resolution into what pkg/executor writes from.
func edgeOfferFrom(b upgrade.EdgeBuild) *executor.EdgeBuild {
	return &executor.EdgeBuild{
		Short:     b.Label(),
		Target:    b.Target(),
		Published: b.Published(),
		Protocol:  b.Manifest.Protocol,
		WhyNot:    b.Reason(),
	}
}

// resolveEdgeTarget looks up the edge build a request names, for the
// protocol check: the hub's own from the cache, any other commit directly.
// It returns the normalised target, the protocol its manifest claims (0 when
// unknown), and why it is unknown.
func resolveEdgeTarget(ctx context.Context, target string) (string, int, string) {
	commit, err := version.ParseEdgeTarget(target)
	if err != nil {
		return target, 0, err.Error()
	}
	if hub := hubVersion(); !version.IsRelease(hub) && version.SameCommit(hub, commit) {
		b := hubEdgeCache.get(ctx, hub)
		if b.Published() {
			return b.Target(), b.Manifest.Protocol, ""
		}
		return version.EdgeTarget(commit), 0, b.Reason()
	}
	full := commit
	if !upgrade.IsFullCommit(full) {
		var err error
		if full, err = upgrade.ResolveCommit(ctx, commit); err != nil {
			return version.EdgeTarget(commit), 0, err.Error()
		}
	}
	b := resolveEdgeBuild(ctx, "", full)
	if b.Published() {
		return b.Target(), b.Manifest.Protocol, ""
	}
	return version.EdgeTarget(full), 0, b.Reason()
}
