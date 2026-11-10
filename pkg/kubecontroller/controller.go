package kubecontroller

// controller.go wires the controller together: three informers, the leader
// election, the work queue and its workers, the hub feeds, and a health
// endpoint.
//
// Every replica keeps its informers warm, so a follower that takes the lease
// over starts from a synced cache; only the leader reconciles, and only while
// its term lasts. A term starts its workers and its feeds under the term's
// context and waits for all of them to stop before the replica counts itself
// a follower again — so a replica that lost the lease has stopped scaling
// before a rival could take it (see leader.go).

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
)

// Options configure a Controller.
type Options struct {
	// REST reaches the API server; Token, when set, supplies its bearer token
	// per request (the in-cluster ServiceAccount token, re-read as the kubelet
	// rotates it).
	REST  *kubernetes.RESTConfig
	Token func() (string, error)
	// Namespace is where the controller watches ExecutorPools and keeps their
	// runners; "" is every namespace, which needs cluster-wide RBAC.
	Namespace string
	// LeaderElection is the Lease that keeps one replica scaling; nil runs
	// without one, which is only safe with exactly one replica.
	LeaderElection *LeaderElection
	// Resync relists everything and reconciles every pool this often; zero
	// is five minutes.
	Resync time.Duration
	// Workers is how many pools reconcile at once; zero is two.
	Workers int
	// HealthAddr serves /healthz and /readyz; "" serves nothing.
	HealthAddr string
	// ImageProvenanceRequired refuses a runner image of cloop's own whose
	// signature could not be verified, instead of warning.
	ImageProvenanceRequired bool
	// Logf receives operational messages; nil logs to stderr.
	Logf func(format string, args ...any)

	// Test seams. HubTransport replaces the pinned TLS transport to the hub;
	// ImageResolver and ImageVerifier replace the registry and cosign.
	HubTransport  http.RoundTripper
	ImageResolver imagepolicy.Resolver
	ImageVerifier imagepolicy.ProvenanceVerifier
	// NoImageVerifier leaves the verifier out when ImageVerifier is nil.
	NoImageVerifier bool
	Now             func() time.Time
}

// Controller is the executor controller.
type Controller struct {
	opts   Options
	api    *kubeAPI
	logf   func(string, ...any)
	now    func() time.Time
	images *imageChooser
	events *recorder

	pools   *informer[ExecutorPool, *ExecutorPool]
	pods    *informer[Pod, *Pod]
	secrets *informer[secretMeta, *secretMeta]
	// claims are the runner volumes (Task 20484).
	claims *informer[PersistentVolumeClaim, *PersistentVolumeClaim]
	// reports remembers, per pool, what was last told the hub about its
	// storage, so a report is sent on a change and refreshed — not every pass.
	reports *storageReports
	// claimObs remembers when this replica first saw each volume claim.
	claimObs *claimObservations

	// queue is the leader term's queue, nil between terms.
	queue atomic.Pointer[workQueue]
	// feeds is the leader term's feeds, nil between terms.
	feeds  atomic.Pointer[feedManager]
	expect *expectations

	elector *elector
	leading atomic.Bool
	panics  atomic.Int64
	// reconciles counts finished reconciles, for the health check and tests.
	reconciles atomic.Int64
}

// New builds a controller. It performs no I/O.
func New(opts Options) (*Controller, error) {
	if opts.REST == nil {
		return nil, errors.New("kubecontroller: no API server configuration")
	}
	if opts.Resync <= 0 {
		opts.Resync = 5 * time.Minute
	}
	if opts.Workers <= 0 {
		opts.Workers = 2
	}
	logf := opts.Logf
	if logf == nil {
		logf = func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "[executor-controller] "+format+"\n", args...)
		}
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	client, err := kubernetes.NewAPIClient(opts.REST, kubernetes.APIClientOptions{
		UserAgent: "cloop-executor-controller", Token: opts.Token})
	if err != nil {
		return nil, err
	}
	resolver := opts.ImageResolver
	if resolver == nil {
		resolver = &imagepolicy.RegistryResolver{Credentials: func(string) (imagepolicy.RegistryCredential, bool) {
			// Anonymous: cloop's images are public, and the controller has
			// no business with anybody's registry logins.
			return imagepolicy.RegistryCredential{}, false
		}}
	}
	var verifier imagepolicy.ProvenanceVerifier
	switch {
	case opts.ImageVerifier != nil:
		verifier = opts.ImageVerifier
	case !opts.NoImageVerifier:
		verifier = imagepolicy.SharedProvenanceVerifier()
	}
	c := &Controller{opts: opts, api: &kubeAPI{c: client}, logf: logf, now: now,
		images: newImageChooser(resolver, verifier, opts.ImageProvenanceRequired), expect: newExpectations()}
	instance := "controller"
	if opts.LeaderElection != nil {
		if err := opts.LeaderElection.Validate(); err != nil {
			return nil, err
		}
		instance = opts.LeaderElection.Identity
		c.elector = newElector(c.api, *opts.LeaderElection, logf)
		c.elector.now = now
	}
	c.images.now = now
	c.events = newRecorder(c.api, instance, logf)
	c.events.now = now

	managed := LabelManagedBy + "=" + ManagedBy
	c.pools = newInformer[ExecutorPool](c.api, resPools, opts.Namespace, "", opts.Resync, logf,
		func(_, cur *ExecutorPool) {
			if cur != nil {
				c.enqueue(cur.Key())
			}
		})
	c.pods = newInformer[Pod](c.api, resPods, opts.Namespace, managed, opts.Resync, logf,
		func(old, cur *Pod) { c.enqueueOwner(old, cur) })
	c.secrets = newInformer[secretMeta](c.api, resSecrets, opts.Namespace, managed, opts.Resync, logf, nil)
	c.claims = newInformer[PersistentVolumeClaim](c.api, resClaims, opts.Namespace, managed, opts.Resync, logf,
		func(old, cur *PersistentVolumeClaim) { c.enqueueClaimPool(old, cur) })
	c.reports = newStorageReports()
	c.claimObs = newClaimObservations()
	return c, nil
}

// enqueueClaimPool queues the pool a runner volume belongs to: released,
// bound or deleted, it may let a runner start.
func (c *Controller) enqueueClaimPool(old, cur *PersistentVolumeClaim) {
	cl := cur
	if cl == nil {
		cl = old
	}
	if cl == nil {
		return
	}
	if name := cl.Metadata.Annotations[AnnotationStoragePool]; name != "" {
		c.enqueue(cl.Metadata.Namespace + "/" + name)
	}
}

// enqueue queues a pool when this replica leads.
func (c *Controller) enqueue(key string) {
	if q := c.queue.Load(); q != nil {
		q.Add(key)
	}
}

// enqueueOwner queues the pool that controls a runner Pod.
func (c *Controller) enqueueOwner(old, cur *Pod) {
	p := cur
	if p == nil {
		p = old
	}
	if p == nil {
		return
	}
	uid := controllerOf(p.Metadata)
	if uid == "" {
		return
	}
	for _, pool := range c.pools.list() {
		if pool.Metadata.UID == uid {
			c.enqueue(pool.Key())
			return
		}
	}
}

// Run runs the controller until ctx ends, and returns once everything it
// started has stopped.
func (c *Controller) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	defer wg.Wait()

	if c.opts.HealthAddr != "" {
		srv, ln, err := c.healthServer(c.opts.HealthAddr)
		if err != nil {
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = srv.Serve(ln)
		}()
		stop := context.AfterFunc(ctx, func() {
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(sctx)
		})
		defer stop()
	}

	for _, run := range []func(context.Context){c.pools.run, c.pods.run, c.secrets.run, c.claims.run} {
		run := run
		wg.Add(1)
		go func() {
			defer wg.Done()
			// An informer that panics is started again: a cache nobody keeps
			// would go on answering, ever more out of date.
			for ctx.Err() == nil {
				func() {
					defer c.recoverGoroutine("informer")
					run(ctx)
				}()
				sleep(ctx, time.Second)
			}
		}()
	}

	if c.elector == nil {
		c.lead(ctx)
		return nil
	}
	c.elector.run(ctx, c.lead)
	return nil
}

// lead is one leader term: workers, feeds and the resync tick, until ctx
// ends. It returns once they have all stopped.
func (c *Controller) lead(ctx context.Context) {
	if !c.waitForSync(ctx) {
		return
	}
	q := newWorkQueue()
	feeds := newFeedManager(ctx, c.api, c.opts.HubTransport, c.logf, c.enqueue)
	c.feeds.Store(feeds)
	c.queue.Store(q)
	c.leading.Store(true)
	defer func() {
		c.leading.Store(false)
		c.queue.Store(nil)
		q.Close()
		feeds.stopAll()
		c.feeds.Store(nil)
		c.expect.reset()
		// A new term tells the hub where storage stands again, healthy or
		// not: another leader may have reported in between.
		c.reports.reset()
	}()

	var wg sync.WaitGroup
	for i := 0; i < c.opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.worker(ctx, q)
		}()
	}
	c.enqueueAll()
	c.sweep(ctx)
	tick := time.NewTicker(c.opts.Resync)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			q.Close()
			wg.Wait()
			return
		case <-tick.C:
			c.enqueueAll()
			c.sweep(ctx)
		}
	}
}

// waitForSync waits for the informers' first lists.
func (c *Controller) waitForSync(ctx context.Context) bool {
	for {
		if c.synced() {
			return true
		}
		if !sleep(ctx, 100*time.Millisecond) {
			return false
		}
	}
}

// synced reports whether every informer has made its first list.
func (c *Controller) synced() bool {
	return c.pools.HasSynced() && c.pods.HasSynced() && c.secrets.HasSynced() && c.claims.HasSynced()
}

func (c *Controller) enqueueAll() {
	for _, p := range c.pools.list() {
		c.enqueue(p.Key())
	}
}

// worker reconciles keys from q until ctx ends.
func (c *Controller) worker(ctx context.Context, q *workQueue) {
	for {
		key, ok := q.Get(ctx)
		if !ok {
			return
		}
		res, err := c.reconcileSafely(ctx, key)
		switch {
		case ctx.Err() != nil:
		case err != nil:
			c.logf("reconcile %s: %v", key, err)
			q.AddRateLimited(key)
		default:
			q.Forget(key)
			if res.requeueAfter > 0 {
				q.AddAfter(key, res.requeueAfter)
			}
		}
		q.Done(key)
		c.reconciles.Add(1)
	}
}

// reconcileSafely is reconcile with a panic turned into an error: one pool's
// bad object must not take every other pool's scaling down with the process.
func (c *Controller) reconcileSafely(ctx context.Context, key string) (res result, err error) {
	defer func() {
		if r := recover(); r != nil {
			c.panics.Add(1)
			c.logf("reconcile %s panicked: %v\n%s", key, r, debug.Stack())
			err = fmt.Errorf("reconcile panicked: %v", r)
		}
	}()
	return c.reconcile(ctx, key)
}

// recoverGoroutine logs a panic in a long-lived goroutine instead of letting
// it end the process.
func (c *Controller) recoverGoroutine(what string) {
	if r := recover(); r != nil {
		c.panics.Add(1)
		c.logf("%s panicked: %v\n%s", what, r, debug.Stack())
	}
}

// healthServer serves /healthz (the process is up) and /readyz (its caches
// are synced).
func (c *Controller) healthServer(addr string) (*http.Server, net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("kubecontroller: health endpoint %s: %w", addr, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if !c.synced() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("caches not synced\n"))
			return
		}
		role := "follower"
		if c.leading.Load() {
			role = "leader"
		}
		_, _ = w.Write([]byte("ok " + role + "\n"))
	})
	return &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}, ln, nil
}

// Leading reports whether this replica leads now.
func (c *Controller) Leading() bool { return c.leading.Load() }

// ── feeds ──────────────────────────────────────────────────────────────────

// feedManager runs one feed per pool for a leader term.
type feedManager struct {
	ctx       context.Context
	api       *kubeAPI
	transport http.RoundTripper
	logf      func(string, ...any)
	changed   func(key string)

	mu    sync.Mutex
	feeds map[string]*feed
	wg    sync.WaitGroup
}

func newFeedManager(ctx context.Context, api *kubeAPI, transport http.RoundTripper, logf func(string, ...any),
	changed func(string)) *feedManager {
	return &feedManager{ctx: ctx, api: api, transport: transport, logf: logf, changed: changed, feeds: map[string]*feed{}}
}

// ensure returns key's feed for cfg, starting it — or restarting it when its
// configuration changed.
func (m *feedManager) ensure(key string, cfg hubConfig) (*feed, error) {
	m.mu.Lock()
	if f, ok := m.feeds[key]; ok {
		if f.cfg == cfg {
			m.mu.Unlock()
			return f, nil
		}
		delete(m.feeds, key)
		m.mu.Unlock()
		f.cancel()
		<-f.done
		m.mu.Lock()
	}
	defer m.mu.Unlock()
	if m.ctx.Err() != nil {
		return nil, m.ctx.Err()
	}
	creds := &credentialSource{api: m.api, cfg: cfg}
	client, err := newHubClient(cfg, creds, m.transport)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(m.ctx)
	f := &feed{cfg: cfg, client: client, creds: creds, cancel: func() { cancel(); creds.forget() },
		done: make(chan struct{})}
	m.feeds[key] = f
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				m.logf("hub feed for %s panicked: %v\n%s", key, r, debug.Stack())
			}
		}()
		f.run(ctx, func() { m.changed(key) }, m.logf)
	}()
	return f, nil
}

// get returns key's feed, nil when none runs.
func (m *feedManager) get(key string) *feed {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.feeds[key]
}

// stop ends key's feed.
func (m *feedManager) stop(key string) {
	m.mu.Lock()
	f, ok := m.feeds[key]
	delete(m.feeds, key)
	m.mu.Unlock()
	if ok {
		f.cancel()
		<-f.done
	}
}

// stopAll ends every feed and waits for them.
func (m *feedManager) stopAll() {
	m.mu.Lock()
	all := m.feeds
	m.feeds = map[string]*feed{}
	m.mu.Unlock()
	for _, f := range all {
		f.cancel()
	}
	m.wg.Wait()
}

// ── expectations ───────────────────────────────────────────────────────────

// expectationTTL bounds how long a create or delete the informer has not
// shown yet is assumed: the watch delivers it in well under this.
var expectationTTL = 2 * time.Minute

// expectations remember, per pool, the runner Pods this leader created or
// deleted that the Pod informer does not reflect yet, so a reconcile in the
// gap counts them as they are rather than as the cache says — without which
// a quick second reconcile would start the same runners twice. In memory
// only: a new leader relists, and its cache is the truth from the start.
type expectations struct {
	mu      sync.Mutex
	created map[string]map[string]time.Time
	deleted map[string]map[string]time.Time
	// holds is the tenant each created runner's volume holds (Task 20484),
	// so a Pod the cache has not shown yet counts as the runner it is.
	holds map[string]map[string]string
}

func newExpectations() *expectations {
	return &expectations{created: map[string]map[string]time.Time{}, deleted: map[string]map[string]time.Time{},
		holds: map[string]map[string]string{}}
}

func (e *expectations) note(m map[string]map[string]time.Time, pool, pod string, at time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if m[pool] == nil {
		m[pool] = map[string]time.Time{}
	}
	m[pool][pod] = at
}

// noteCreatedHolding records a runner Pod created at at, and the tenant its
// volume holds ("" for none) until the cache shows the Pod.
func (e *expectations) noteCreatedHolding(pool, pod, tenant string, at time.Time) {
	e.note(e.created, pool, pod, at)
	if tenant == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.holds[pool] == nil {
		e.holds[pool] = map[string]string{}
	}
	e.holds[pool][pod] = tenant
}

// heldBy is the tenant a created runner's volume holds, "" for none.
func (e *expectations) heldBy(pool, pod string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.holds[pool][pod]
}
func (e *expectations) noteDeleted(pool, pod string, at time.Time) {
	e.note(e.deleted, pool, pod, at)
	// A Pod deleted before the cache ever showed it is not one to wait for.
	e.mu.Lock()
	delete(e.created[pool], pod)
	e.mu.Unlock()
}

// view returns the Pods created and not yet cached, and the Pods deleted and
// still cached, dropping what the cache now reflects or what aged out.
func (e *expectations) view(pool string, cached func(name string) bool, now time.Time) (created, deleted map[string]bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	created, deleted = map[string]bool{}, map[string]bool{}
	for name, at := range e.created[pool] {
		if cached(name) || now.Sub(at) > expectationTTL {
			delete(e.created[pool], name)
			delete(e.holds[pool], name)
			continue
		}
		created[name] = true
	}
	for name, at := range e.deleted[pool] {
		if !cached(name) || now.Sub(at) > expectationTTL {
			delete(e.deleted[pool], name)
			continue
		}
		deleted[name] = true
	}
	return created, deleted
}

func (e *expectations) reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.created = map[string]map[string]time.Time{}
	e.deleted = map[string]map[string]time.Time{}
	e.holds = map[string]map[string]string{}
}

// hubConfigFor is a pool's hub connection.
func hubConfigFor(p *ExecutorPool) hubConfig {
	return hubConfig{URL: strings.TrimSpace(p.Spec.HubURL), Pin: strings.TrimSpace(p.Spec.HubCAPin),
		CABundle: strings.TrimSpace(p.Spec.HubCABundle), Namespace: p.Metadata.Namespace,
		Secret: p.Spec.PoolCredentialSecretRef.Name, Key: p.Spec.PoolCredentialSecretRef.Key}
}
