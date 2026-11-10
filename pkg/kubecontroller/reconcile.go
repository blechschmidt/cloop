package kubecontroller

// reconcile.go brings one ExecutorPool's runners to what its demand needs.
//
// Each pass reads the pool, its runner Pods and their Secrets from the
// informers, and the hub's record of the pool from its feed, and decides:
//
//  1. Finished runners go. A runner Pod that Succeeded or Failed is deleted
//     with its Secret, whatever else holds; a Failed one's termination report
//     becomes an Event. So do the orphans a crash leaves: a runner Pod whose
//     Secret never came (the controller died between the two creates).
//  2. An invalid spec stops there: the Invalid condition names every problem,
//     and nothing is started or retired.
//  3. The hub decides who is busy. A runner is busy, idle or pending only by
//     the feed's runner states; a feed that has not answered for feedFresh
//     is stale, and a stale pass retires and deletes nothing it would need
//     the hub's word for. A runner the hub no longer lists, past its token's
//     expiry, was retired or never enrolled, and its Pod is deleted; one it
//     lists as pending with no Secret anywhere in the namespace, minted
//     longer ago than orphanHubGrace, was minted by a controller that died
//     before starting it, and is retired so it stops holding a place under
//     max_runners.
//  4. desired = clamp(minRunners, minRunners + busy + queued, maxRunners),
//     where minRunners is the idle target, busy the runners the hub says
//     hold a run, queued the hub's demand, and maxRunners the lower of the
//     spec's and the hub pool's.
//  5. Fewer runners than desired: start the difference — at most
//     maxCreatePerPass at a time and never more than the hub's spare — each
//     as a Pod first, then its configuration from the hub, then the Secret
//     owned by the Pod. A failure at any step undoes that runner's earlier
//     steps.
//  6. More than desired: ask the hub to retire idle runners that have idled
//     for scaleDownDelay, oldest first. The hub retires one only while it is
//     still idle, so a runner handed a run in the same moment keeps it; a
//     retired runner exits by itself and its Pod is collected by step 1. A
//     busy runner is never retired and its Pod never deleted.
//  7. The status says what was found — replica counts, observedGeneration,
//     and the Ready, Degraded and Invalid conditions, Degraded carrying the
//     hub's own error text — and is written only when it changed.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Reconcile timing.
var (
	// feedFresh is how old the hub's last answer may be for the controller to
	// act on it: two long-poll waits and some slack.
	feedFresh = 2*feedWait + 10*time.Second
	// podSecretGrace is how long a runner Pod may wait for its Secret before
	// it is taken for a crash's orphan.
	podSecretGrace = time.Minute
	// expiredGrace is how long past its token's expiry a runner the hub no
	// longer lists keeps its Pod.
	expiredGrace = 30 * time.Second
	// orphanHubGrace is how long a pending runner the hub lists, with no
	// Secret in the cluster, is left before it is retired.
	orphanHubGrace = 5 * time.Minute
	// maxCreatePerPass bounds the runners one pass starts.
	maxCreatePerPass = 10
	// requeueWhileStarting re-checks a pool whose runners are starting.
	requeueWhileStarting = 15 * time.Second
	// minIdleBeforeRetire is the least a runner idles before it is retired
	// to scale down, whatever scaleDownDelay says: a runner retired the
	// instant it enrolled meets its retirement mid-handshake.
	minIdleBeforeRetire = 5 * time.Second
)

// testHookReconcile, when set by a test, runs at the start of every pass.
var testHookReconcile atomic.Pointer[func(*ExecutorPool)]

// result is what a reconcile asks of the queue.
type result struct {
	requeueAfter time.Duration
}

// sooner keeps the earliest positive requeue.
func (r *result) sooner(d time.Duration) {
	if d <= 0 {
		return
	}
	if r.requeueAfter == 0 || d < r.requeueAfter {
		r.requeueAfter = d
	}
}

// runnerView is one runner as this pass sees it.
type runnerView struct {
	pod          *Pod
	secret       *secretMeta
	enrollmentID string
	expiresAt    time.Time
	hub          *executorpool.RunnerState
}

// classes of runners.
const (
	runnerStarting = "starting"
	runnerPending  = "pending"
	runnerIdle     = "idle"
	runnerBusy     = "busy"
)

// passState is what one pass decided, for the status.
type passState struct {
	invalid  []string
	degraded []string
	reasons  []string
	desired  int
	runners  int
	pending  int
	idle     int
	busy     int
	queued   int
}

func (s *passState) degrade(reason, msg string) {
	s.reasons = append(s.reasons, reason)
	s.degraded = append(s.degraded, msg)
}

// reconcile is one pass over the pool key.
func (c *Controller) reconcile(ctx context.Context, key string) (result, error) {
	var res result
	cached, ok := c.pools.get(key)
	feeds := c.feeds.Load()
	if !ok {
		// Deleted: its runner Pods are owned by it and go with it, their
		// Secrets with them.
		if feeds != nil {
			feeds.stop(key)
		}
		return res, nil
	}
	pool, err := deepCopyPool(cached)
	if err != nil {
		return res, err
	}
	if hook := testHookReconcile.Load(); hook != nil {
		(*hook)(pool)
	}
	if pool.Metadata.DeletionTimestamp != "" {
		if feeds != nil {
			feeds.stop(key)
		}
		return res, nil
	}
	pool.Spec = pool.Spec.Normalize()
	now := c.now()
	st := &passState{}

	views, created, deleted := c.runnersOf(pool, now)
	live := c.collect(ctx, pool, views, deleted, now, &res)

	if problems := pool.Spec.Validate(); len(problems) > 0 {
		if feeds != nil {
			feeds.stop(key)
		}
		st.invalid = problems
		c.events.record(ctx, pool, EventWarning, ReasonInvalidSpec, "the spec is invalid: "+strings.Join(problems, "; "))
		st.runners = len(live) + len(created)
		return res, c.writeStatus(ctx, cached, pool, st, nil, now)
	}
	if feeds == nil {
		return res, nil
	}
	f, err := feeds.ensure(key, hubConfigFor(pool))
	if err != nil {
		st.degrade(ReasonHubUnavailable, err.Error())
		return res, c.writeStatus(ctx, cached, pool, st, nil, now)
	}
	fs := f.snapshot()
	fresh := fs.Have && fs.Err == nil && now.Sub(fs.At) <= feedFresh
	var snap *executorpool.Snapshot
	if fs.Have {
		snap = &fs.Msg.Snapshot
	}
	if fs.Err != nil {
		reason := ReasonHubUnavailable
		var he *HubError
		var ce *credentialError
		switch {
		case errors.As(fs.Err, &he) && he.Unauthorized():
			reason = ReasonHubRefused
		case errors.As(fs.Err, &ce):
			reason = ReasonCredentialMissing
		}
		st.degrade(reason, fs.Err.Error())
		c.events.record(ctx, pool, EventWarning, reason, fs.Err.Error())
	}

	// A hub that predates per-runner states (Task 20482's) cannot say which
	// runner is busy: nothing that needs that is decided on its word.
	if fresh && snap.RunnerStates == nil {
		msg := fmt.Sprintf("the hub at %s does not report its runners' states; it is older than this "+
			"controller, which starts and stops no runner until the hub is upgraded", pool.Spec.HubURL)
		st.degrade(ReasonHubTooOld, msg)
		c.events.record(ctx, pool, EventWarning, ReasonHubTooOld, msg)
		fresh = false
	}

	// The hub's word on each runner, when it is fresh.
	if fresh {
		states := map[string]*executorpool.RunnerState{}
		for i := range snap.RunnerStates {
			states[snap.RunnerStates[i].EnrollmentID] = &snap.RunnerStates[i]
		}
		for _, v := range live {
			if v.enrollmentID != "" {
				v.hub = states[v.enrollmentID]
			}
		}
		live = c.collectGone(ctx, pool, live, now, &res)
		if c.duplicateOf(pool, snap) == "" {
			c.collectHubOrphans(ctx, pool, f, snap, now)
		}
	}

	// Count.
	var idle []*runnerView
	for _, v := range live {
		switch classify(v) {
		case runnerBusy:
			st.busy++
		case runnerIdle:
			st.idle++
			idle = append(idle, v)
		default:
			st.pending++
		}
	}
	st.pending += len(created)
	st.runners = st.busy + st.idle + st.pending
	if snap != nil {
		st.queued = snap.Demand
	}
	maxRunners := pool.Spec.MaxRunners
	if snap != nil && snap.MaxRunners > 0 {
		maxRunners = min(maxRunners, snap.MaxRunners)
	}
	st.desired = clamp(pool.Spec.MinRunners, pool.Spec.MinRunners+st.busy+st.queued, maxRunners)

	image := imageChoice{}
	if dup := c.duplicateOf(pool, snap); dup != "" {
		msg := fmt.Sprintf("ExecutorPool %s already serves hub pool %s; one hub pool takes one ExecutorPool, "+
			"or each would retire the other's runners", dup, snap.PoolID)
		st.degrade(ReasonDuplicatePool, msg)
		c.events.record(ctx, pool, EventWarning, ReasonDuplicatePool, msg)
		fresh = false
	} else {
		image = c.images.choose(ctx, pool)
		if image.Err != nil {
			st.degrade(ReasonImageUnresolved, image.Err.Error())
			c.events.record(ctx, pool, EventWarning, ReasonImageUnresolved, image.Err.Error())
		} else if image.Warning != "" {
			c.events.record(ctx, pool, EventWarning, ReasonImageUnverified, image.Warning)
		}
	}

	switch {
	case !fresh:
		// Nothing is started or retired without the hub's current word.
	case st.desired > st.runners && image.Err == nil:
		n := min(st.desired-st.runners, maxCreatePerPass)
		if snap.Spare < n {
			if snap.Spare <= 0 {
				c.events.record(ctx, pool, EventWarning, ReasonRunnersRefused, fmt.Sprintf(
					"the hub's pool %s is at its max_runners (%d): no runner is started until one leaves",
					snap.Name, snap.MaxRunners))
			}
			n = max(0, snap.Spare)
		}
		if n > 0 {
			started, err := c.startRunners(ctx, pool, f, image.Image, n, now)
			st.pending += started
			st.runners += started
			if err != nil {
				st.degrade(reasonOf(err), err.Error())
			}
		}
		res.sooner(requeueWhileStarting)
	case st.runners > st.desired:
		retired, wait := c.scaleDown(ctx, pool, f, idle, st.runners-st.desired, now)
		st.idle -= retired
		st.runners -= retired
		res.sooner(wait)
	}
	if st.pending > 0 {
		res.sooner(requeueWhileStarting)
	}
	if fs.Err != nil || !fs.Have {
		res.sooner(feedBackoffBase * 5)
	}
	return res, c.writeStatus(ctx, cached, pool, st, &fs, now)
}

// classify places a runner by the hub's record.
func classify(v *runnerView) string {
	if v.hub == nil {
		return runnerStarting
	}
	switch v.hub.State {
	case statedb.PoolRunnerBusy:
		return runnerBusy
	case statedb.PoolRunnerIdle:
		return runnerIdle
	}
	return runnerPending
}

func clamp(lo, v, hi int) int {
	if v < lo {
		v = lo
	}
	if v > hi {
		v = hi
	}
	return v
}

// runnersOf joins a pool's runner Pods with their Secrets, and returns the
// Pods this leader created that the cache does not show yet, and those it
// deleted that it still shows.
func (c *Controller) runnersOf(pool *ExecutorPool, now time.Time) ([]*runnerView, map[string]bool, map[string]bool) {
	var views []*runnerView
	names := map[string]bool{}
	for _, p := range c.pods.list() {
		if p.Metadata.Namespace != pool.Metadata.Namespace || controllerOf(p.Metadata) != pool.Metadata.UID {
			continue
		}
		names[p.Metadata.Name] = true
		v := &runnerView{pod: p}
		if s, ok := c.secrets.get(p.Metadata.Namespace + "/" + p.Metadata.Name); ok && controllerOf(s.Metadata) == p.Metadata.UID {
			v.secret = s
			v.enrollmentID = s.Metadata.Annotations[AnnotationEnrollmentID]
			if t, err := time.Parse(time.RFC3339, s.Metadata.Annotations[AnnotationExpiresAt]); err == nil {
				v.expiresAt = t
			}
		}
		views = append(views, v)
	}
	created, deleted := c.expect.view(pool.Key(), func(name string) bool { return names[name] }, now)
	return views, created, deleted
}

// collect deletes finished runners and runner Pods orphaned without their
// Secret, and returns the runners still live.
func (c *Controller) collect(ctx context.Context, pool *ExecutorPool, views []*runnerView, deleted map[string]bool,
	now time.Time, res *result) []*runnerView {
	var live []*runnerView
	for _, v := range views {
		p := v.pod
		switch {
		case deleted[p.Metadata.Name] || p.Metadata.DeletionTimestamp != "":
			// Going.
		case p.Status.Phase == PodSucceeded || p.Status.Phase == PodFailed:
			if p.Status.Phase == PodFailed {
				c.reportFailedRunner(ctx, pool, p)
			}
			c.deleteRunner(ctx, pool, v, now)
		case v.secret == nil:
			// A runner Pod without its Secret is an orphan only while it has
			// never started — it cannot, until the Secret its volume names
			// exists. One that started had its Secret mounted: the Secret
			// went later, or the cache has not caught up, and the runner may
			// be busy, so it is left to finish.
			age := now.Sub(parseTime(p.Metadata.CreationTimestamp, now))
			if !neverStarted(p) {
				live = append(live, v)
				continue
			}
			if age < podSecretGrace {
				res.sooner(podSecretGrace - age)
				live = append(live, v)
				continue
			}
			if c.secretExists(ctx, p) {
				live = append(live, v)
				continue
			}
			c.logf("collect runner Pod %s/%s: its Secret never came; the controller stopped between creating "+
				"the two", p.Metadata.Namespace, p.Metadata.Name)
			c.events.record(ctx, pool, EventNormal, ReasonOrphanCollected,
				fmt.Sprintf("deleted runner Pod %s, whose configuration Secret was never created", p.Metadata.Name))
			c.deleteRunner(ctx, pool, v, now)
		default:
			live = append(live, v)
		}
	}
	return live
}

// neverStarted reports whether a Pod is Pending with no container that ever
// ran: the state of a runner Pod whose Secret volume cannot be mounted.
func neverStarted(p *Pod) bool {
	if p.Status.Phase != "" && p.Status.Phase != PodPending {
		return false
	}
	for _, cs := range p.Status.ContainerStatuses {
		if cs.State.Waiting == nil {
			return false
		}
	}
	return true
}

// secretExists asks the API server, not the cache, whether a runner Pod's
// Secret exists: a cache that is behind must not get a Pod deleted. An answer
// that is not a clear "not found" counts as "it exists".
func (c *Controller) secretExists(ctx context.Context, p *Pod) bool {
	exists, err := c.api.secretExists(ctx, p.Metadata.Namespace, p.Metadata.Name)
	return exists || err != nil
}

// collectGone deletes the Pods of runners the hub no longer lists, past their
// token's expiry: retired, or never enrolled. Never a runner the hub lists.
func (c *Controller) collectGone(ctx context.Context, pool *ExecutorPool, live []*runnerView, now time.Time,
	res *result) []*runnerView {
	var keep []*runnerView
	for _, v := range live {
		if v.hub != nil || v.secret == nil || v.expiresAt.IsZero() {
			keep = append(keep, v)
			continue
		}
		if wait := v.expiresAt.Add(expiredGrace).Sub(now); wait > 0 {
			res.sooner(wait)
			keep = append(keep, v)
			continue
		}
		c.logf("collect runner Pod %s/%s: the hub no longer counts runner %s (retired, or its token lapsed "+
			"unredeemed)", v.pod.Metadata.Namespace, v.pod.Metadata.Name, v.enrollmentID)
		c.deleteRunner(ctx, pool, v, now)
	}
	return keep
}

// collectHubOrphans retires runners the hub lists for this pool, minted with
// this controller's credential, that no Secret in the namespace carries: a
// pending one was minted by a controller that died before it started it; an
// idle one lost its Pod while the hub could not hear it go — the hub was
// down, say — and would otherwise hold its place under max_runners until the
// hub's idle limit. Busy ones are never touched: a lost run is settled by the
// hub's failover. The hub retires a runner only in the state it is in.
func (c *Controller) collectHubOrphans(ctx context.Context, pool *ExecutorPool, f *feed, snap *executorpool.Snapshot,
	now time.Time) {
	known := map[string]bool{}
	for _, s := range c.secrets.list() {
		if s.Metadata.Namespace == pool.Metadata.Namespace {
			if id := s.Metadata.Annotations[AnnotationEnrollmentID]; id != "" {
				known[id] = true
			}
		}
	}
	// Only this controller's own: a runner another controller of the same
	// pool minted, with another credential, is that controller's to start.
	mine := f.creds.id()
	if mine == "" {
		return
	}
	var orphans []string
	for _, r := range snap.RunnerStates {
		if r.CredentialID != mine || known[r.EnrollmentID] || now.Sub(r.MintedAt) < orphanHubGrace {
			continue
		}
		if r.State == statedb.PoolRunnerPending || r.State == statedb.PoolRunnerIdle {
			orphans = append(orphans, r.EnrollmentID)
		}
	}
	if len(orphans) == 0 {
		return
	}
	if len(orphans) > executorpool.MaxRunnersPerRequest {
		orphans = orphans[:executorpool.MaxRunnersPerRequest]
	}
	results, err := f.client.Retire(ctx, orphans)
	if err != nil {
		c.logf("retire orphaned runners of %s: %v", pool.Key(), err)
		return
	}
	n := 0
	for _, r := range results {
		if r.Outcome == "retired" {
			n++
		}
	}
	if n > 0 {
		c.events.record(ctx, pool, EventNormal, ReasonOrphanCollected, fmt.Sprintf(
			"retired %d runner(s) the hub had minted for this pool and no runner Pod carries", n))
	}
}

// deleteRunner deletes a runner's Pod and its Secret.
func (c *Controller) deleteRunner(ctx context.Context, pool *ExecutorPool, v *runnerView, now time.Time) {
	p := v.pod
	if err := c.api.deletePod(ctx, p.Metadata.Namespace, p.Metadata.Name, p.Metadata.UID); err != nil {
		c.logf("delete runner Pod %s/%s: %v", p.Metadata.Namespace, p.Metadata.Name, err)
		return
	}
	c.expect.noteDeleted(pool.Key(), p.Metadata.Name, now)
	if v.secret != nil {
		if err := c.api.deleteSecret(ctx, v.secret.Metadata.Namespace, v.secret.Metadata.Name, v.secret.Metadata.UID); err != nil {
			// Owned by the Pod: the garbage collector takes it regardless.
			c.logf("delete runner Secret %s/%s: %v", v.secret.Metadata.Namespace, v.secret.Metadata.Name, err)
		}
	}
}

// reportFailedRunner turns a failed runner's termination report into an
// Event.
func (c *Controller) reportFailedRunner(ctx context.Context, pool *ExecutorPool, p *Pod) {
	for _, cs := range p.Status.ContainerStatuses {
		if cs.Name != runnerContainer || cs.State.Terminated == nil {
			continue
		}
		t := cs.State.Terminated
		msg := fmt.Sprintf("runner Pod %s exited %d", p.Metadata.Name, t.ExitCode)
		var report struct {
			Retired bool   `json:"retired"`
			By      string `json:"by"`
			Reason  string `json:"reason"`
		}
		if json.Unmarshal([]byte(strings.TrimSpace(t.Message)), &report) == nil && report.By != "" {
			if report.Retired {
				return
			}
			msg += ": " + report.Reason
		} else if t.Reason != "" {
			msg += " (" + t.Reason + ")"
		}
		c.events.record(ctx, pool, EventWarning, ReasonRunnerFailed, msg)
		return
	}
	if p.Status.Reason != "" || p.Status.Message != "" {
		c.events.record(ctx, pool, EventWarning, ReasonRunnerFailed,
			fmt.Sprintf("runner Pod %s failed: %s %s", p.Metadata.Name, p.Status.Reason, p.Status.Message))
	}
}

// duplicateOf names another ExecutorPool, older than pool, that serves the
// same hub pool; "" when none does.
func (c *Controller) duplicateOf(pool *ExecutorPool, snap *executorpool.Snapshot) string {
	if snap == nil || snap.PoolID == "" {
		return ""
	}
	mine := parseTime(pool.Metadata.CreationTimestamp, time.Time{})
	for _, other := range c.pools.list() {
		if other.Metadata.UID == pool.Metadata.UID || other.Status.PoolID != snap.PoolID ||
			other.Metadata.DeletionTimestamp != "" {
			continue
		}
		theirs := parseTime(other.Metadata.CreationTimestamp, time.Time{})
		if theirs.Before(mine) || (theirs.Equal(mine) && other.Key() < pool.Key()) {
			return other.Key()
		}
	}
	return ""
}

// startRunners starts n runners: Pods first, then their configurations from
// the hub in one request, then a Secret owned by each Pod. It returns how
// many it started.
func (c *Controller) startRunners(ctx context.Context, pool *ExecutorPool, f *feed, image string, n int,
	now time.Time) (int, error) {
	var pods []*Pod
	var podErr error
	for i := 0; i < n; i++ {
		p, err := c.createRunnerPod(ctx, pool, image)
		if err != nil {
			podErr = err
			break
		}
		pods = append(pods, p)
		c.expect.noteCreated(pool.Key(), p.Metadata.Name, now)
	}
	if len(pods) == 0 {
		c.events.record(ctx, pool, EventWarning, ReasonPodRefused, podErr.Error())
		return 0, podErr
	}
	configs, err := f.client.MintRunners(ctx, len(pods))
	if err != nil {
		for _, p := range pods {
			c.deleteRunner(ctx, pool, &runnerView{pod: p}, now)
		}
		// A runner the hub did mint is given back rather than left to lapse.
		c.giveBack(ctx, f, configs)
		c.events.record(ctx, pool, EventWarning, ReasonRunnersRefused, "the hub refused runners: "+err.Error())
		return 0, &refusal{reason: ReasonRunnersRefused, err: err}
	}
	started := 0
	for i, p := range pods {
		cfg := configs[i]
		secret, err := buildRunnerSecret(pool, p, cfg, pool.Spec.HubCAPin)
		if err == nil {
			err = c.api.createSecret(ctx, secret)
		}
		if err != nil {
			c.logf("start runner %s for %s: create its Secret: %v", p.Metadata.Name, pool.Key(), err)
			c.deleteRunner(ctx, pool, &runnerView{pod: p}, now)
			c.giveBack(ctx, f, configs[i:i+1])
			podErr = err
			continue
		}
		started++
	}
	if started > 0 {
		c.events.record(ctx, pool, EventNormal, ReasonScaledUp, fmt.Sprintf("started %d runner(s)", started))
	}
	if podErr != nil {
		if started == 0 {
			c.events.record(ctx, pool, EventWarning, ReasonPodRefused, podErr.Error())
		}
		return started, &refusal{reason: ReasonPodRefused, err: podErr}
	}
	return started, nil
}

// createRunnerPod creates one runner Pod under a fresh name.
func (c *Controller) createRunnerPod(ctx context.Context, pool *ExecutorPool, image string) (*Pod, error) {
	for attempt := 0; ; attempt++ {
		name, err := runnerPodName(pool)
		if err != nil {
			return nil, err
		}
		p, err := c.api.createPod(ctx, buildRunnerPod(pool, name, image))
		if kubernetes.IsConflict(err) && attempt < 3 {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("create runner Pod %s: %w", name, err)
		}
		return p, nil
	}
}

// giveBack retires runners the hub minted that the controller did not start.
func (c *Controller) giveBack(ctx context.Context, f *feed, configs []RunnerConfig) {
	if len(configs) == 0 {
		return
	}
	ids := make([]string, 0, len(configs))
	for _, cfg := range configs {
		ids = append(ids, cfg.EnrollmentID)
	}
	if _, err := f.client.Retire(ctx, ids); err != nil {
		c.logf("give back %d unstarted runner(s): %v; their tokens lapse unredeemed", len(ids), err)
	}
}

// scaleDown asks the hub to retire up to excess idle runners that have idled
// for the scale-down delay, oldest first. It returns how many the hub
// retired, and when to look again for the rest.
func (c *Controller) scaleDown(ctx context.Context, pool *ExecutorPool, f *feed, idle []*runnerView, excess int,
	now time.Time) (int, time.Duration) {
	delay := max(pool.Spec.ScaleDownDelayDuration(), minIdleBeforeRetire)
	sort.Slice(idle, func(i, j int) bool { return idle[i].hub.EnrolledAt.Before(idle[j].hub.EnrolledAt) })
	var ids []string
	var wait time.Duration
	for _, v := range idle {
		if len(ids) >= excess {
			break
		}
		since := v.hub.EnrolledAt
		if since.IsZero() {
			since = v.hub.MintedAt
		}
		if left := since.Add(delay).Sub(now); left > 0 {
			if wait == 0 || left < wait {
				wait = left
			}
			continue
		}
		ids = append(ids, v.enrollmentID)
	}
	if len(ids) == 0 {
		return 0, wait
	}
	results, err := f.client.Retire(ctx, ids)
	if err != nil {
		c.events.record(ctx, pool, EventWarning, ReasonRetireRefused, "the hub did not retire idle runners: "+err.Error())
		return 0, requeueWhileStarting
	}
	retired := 0
	for _, r := range results {
		if r.Outcome == "retired" {
			retired++
		}
	}
	if retired > 0 {
		c.events.record(ctx, pool, EventNormal, ReasonScaledDown, fmt.Sprintf(
			"retired %d idle runner(s) that had idled for %s", retired, delay))
	}
	if retired < len(ids) && wait == 0 {
		wait = requeueWhileStarting
	}
	return retired, wait
}

// refusal is a step the API server or the hub refused, with the Degraded
// reason it shows as.
type refusal struct {
	reason string
	err    error
}

func (r *refusal) Error() string { return r.err.Error() }
func (r *refusal) Unwrap() error { return r.err }

func reasonOf(err error) string {
	var r *refusal
	if errors.As(err, &r) {
		return r.reason
	}
	return ReasonPodRefused
}

// credentialError is a pool credential the controller could not read.
type credentialError struct{ err error }

func (e *credentialError) Error() string { return e.err.Error() }
func (e *credentialError) Unwrap() error { return e.err }

// parseTime reads an RFC 3339 timestamp, or returns def.
func parseTime(s string, def time.Time) time.Time {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return def
}

// deepCopyPool copies a cached pool so a pass never writes into the cache.
func deepCopyPool(p *ExecutorPool) (*ExecutorPool, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	var out ExecutorPool
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ── status ─────────────────────────────────────────────────────────────────

// writeStatus writes the pass's status when it differs from what the cached
// object shows.
func (c *Controller) writeStatus(ctx context.Context, cached, pool *ExecutorPool, st *passState, fs *feedState,
	now time.Time) error {
	next := cached.Status
	next.Conditions = append([]Condition(nil), cached.Status.Conditions...)
	next.ObservedGeneration = pool.Metadata.Generation
	next.DesiredRunners, next.Runners = st.desired, st.runners
	next.PendingRunners, next.IdleRunners, next.BusyRunners = st.pending, st.idle, st.busy
	next.QueuedRuns = st.queued
	if fs != nil && fs.Have {
		next.PoolID, next.PoolName = fs.Msg.Snapshot.PoolID, fs.Msg.Snapshot.Name
		next.LastHubContact = fs.At.UTC().Truncate(time.Minute).Format(time.RFC3339)
	}
	if img, ok := c.imageOf(pool); ok {
		next.Image = img
	}

	gen := pool.Metadata.Generation
	if len(st.invalid) > 0 {
		setCondition(&next, ConditionInvalid, ConditionTrue, ReasonInvalidSpec, strings.Join(st.invalid, "; "), gen, now)
		setCondition(&next, ConditionReady, ConditionFalse, ReasonInvalidSpec,
			"the spec is invalid; no runner is started for it", gen, now)
	} else {
		setCondition(&next, ConditionInvalid, ConditionFalse, "Valid", "the spec is valid", gen, now)
		switch {
		case len(st.degraded) > 0:
			setCondition(&next, ConditionDegraded, ConditionTrue, st.reasons[0], strings.Join(st.degraded, "; "), gen, now)
			setCondition(&next, ConditionReady, ConditionFalse, st.reasons[0], strings.Join(st.degraded, "; "), gen, now)
		case fs == nil || !fs.Have:
			setCondition(&next, ConditionDegraded, ConditionFalse, "AsExpected", "nothing is wrong", gen, now)
			setCondition(&next, ConditionReady, ConditionUnknown, "Connecting", "waiting for the hub's demand feed", gen, now)
		default:
			setCondition(&next, ConditionDegraded, ConditionFalse, "AsExpected", "nothing is wrong", gen, now)
			setCondition(&next, ConditionReady, ConditionTrue, "Serving", fmt.Sprintf(
				"serving hub pool %s: %d runner(s), %d busy, %d queued run(s)", fs.Msg.Snapshot.Name, st.runners, st.busy,
				st.queued), gen, now)
		}
	}
	if reflect.DeepEqual(next, cached.Status) {
		return nil
	}
	out := *pool
	out.Spec = cached.Spec
	out.Status = next
	updated, err := c.api.updatePoolStatus(ctx, &out)
	switch {
	case kubernetes.IsNotFound(err):
		return nil
	case kubernetes.IsConflict(err):
		// Someone wrote the pool since the cache was read; the watch brings
		// the new version, and its event another pass.
		return nil
	case err != nil:
		return fmt.Errorf("write the status of %s: %w", pool.Key(), err)
	}
	c.pools.observe(updated, cached.Metadata.ResourceVersion)
	return nil
}

// imageOf is the image the chooser last chose for pool, if any.
func (c *Controller) imageOf(pool *ExecutorPool) (string, bool) {
	ref := strings.TrimSpace(pool.Spec.Template.Image)
	if ref == "" {
		ref = DefaultRunnerImage()
	}
	c.images.mu.Lock()
	defer c.images.mu.Unlock()
	if ch, ok := c.images.cache[ref]; ok && ch.Err == nil && ch.Image != "" {
		return ch.Image, true
	}
	if ref == strings.TrimSpace(pool.Spec.Template.Image) {
		return ref, true
	}
	return "", false
}

// setCondition sets a condition, keeping its transition time when its status
// did not change.
func setCondition(s *ExecutorPoolStatus, typ, status, reason, msg string, gen int64, now time.Time) {
	msg = trimMessage(msg)
	if cur := s.condition(typ); cur != nil {
		if cur.Status != status {
			cur.LastTransitionTime = now.UTC().Format(time.RFC3339)
		}
		cur.Status, cur.Reason, cur.Message, cur.ObservedGeneration = status, reason, msg, gen
		return
	}
	s.Conditions = append(s.Conditions, Condition{Type: typ, Status: status, ObservedGeneration: gen,
		LastTransitionTime: now.UTC().Format(time.RFC3339), Reason: reason, Message: msg})
}

// ── the sweep ──────────────────────────────────────────────────────────────

// sweep deletes what no pool owns any more: runner Pods whose ExecutorPool is
// gone, and runner Secrets whose Pod is gone. The API server's garbage
// collector does both on its own; the sweep is for a cluster whose collector
// is behind, and for the Secret a crash left between its two creates.
func (c *Controller) sweep(ctx context.Context) {
	defer c.recoverGoroutine("sweep")
	now := c.now()
	pools := map[string]bool{}
	for _, p := range c.pools.list() {
		pools[p.Metadata.UID] = true
	}
	pods := map[string]string{}
	for _, p := range c.pods.list() {
		pods[metaKey(p.Metadata)] = p.Metadata.UID
		owner := controllerOf(p.Metadata)
		if owner == "" || pools[owner] || p.Metadata.DeletionTimestamp != "" {
			continue
		}
		if now.Sub(parseTime(p.Metadata.CreationTimestamp, now)) < podSecretGrace {
			continue
		}
		if err := c.api.deletePod(ctx, p.Metadata.Namespace, p.Metadata.Name, p.Metadata.UID); err != nil {
			c.logf("sweep: delete runner Pod %s/%s of a deleted pool: %v", p.Metadata.Namespace, p.Metadata.Name, err)
		}
	}
	for _, s := range c.secrets.list() {
		owner := controllerOf(s.Metadata)
		if owner != "" && pods[metaKey(s.Metadata)] == owner {
			continue
		}
		if now.Sub(parseTime(s.Metadata.CreationTimestamp, now)) < podSecretGrace {
			continue
		}
		// The cache says its Pod is gone; the API server has the last word.
		if live, err := c.api.getPod(ctx, s.Metadata.Namespace, s.Metadata.Name); err == nil {
			if owner != "" && live.Metadata.UID == owner {
				continue
			}
		} else if !kubernetes.IsNotFound(err) {
			continue
		}
		if err := c.api.deleteSecret(ctx, s.Metadata.Namespace, s.Metadata.Name, s.Metadata.UID); err != nil {
			c.logf("sweep: delete runner Secret %s/%s: %v", s.Metadata.Namespace, s.Metadata.Name, err)
		}
	}
}
