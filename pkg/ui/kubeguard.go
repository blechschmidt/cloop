package ui

// kubeguard.go runs the Kubernetes access monitor alongside the hub and
// routes every kubeconfig grant through it (Task 20277).
//
// It is the Kubernetes counterpart of gitproxy.go and gitguard.go, and the
// structure is deliberately the same: a process singleton started before any
// executor registers, a secretbroker seam the broker calls during material
// construction, and a close path that revokes sessions when the lease ends.
//
// # Why it lives in the hub process
//
// Sessions live in a *kubeguard.Registry, which is memory, and hold the
// cluster credential. The process that mints must be the process that serves;
// a standalone `cloop kube-guard` would authenticate against an empty
// registry and refuse every request the hub had authorised. The alternative
// is a shared session store, which means a kubeconfig at rest in a second
// place for a topology nobody has asked for.
//
// # What turning it on changes
//
// One thing, and only for kubeconfig grants: the delivered kubeconfig points
// at the monitor instead of the cluster, and carries a session token instead
// of the cluster credential. `kubectl` inside the sandbox is unchanged — it
// reads $KUBECONFIG and talks to the server it names. What changes is that
// the server is now something that reads the request before the API server
// does.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/kubeguard"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// kubeGuardReapInterval is how often lapsed sessions are swept. Expiry is
// enforced at authentication regardless, so this is hygiene.
const kubeGuardReapInterval = 5 * time.Minute

// kubeGuardService is the running monitor and the registry it authenticates
// against. The zero value is "not configured", which every method tolerates
// so callers need no nil checks.
type kubeGuardService struct {
	reg         *kubeguard.Registry
	proxy       *kubeguard.Proxy
	baseURL     string
	policy      kubeguard.Policy
	ttl         time.Duration
	listener    net.Listener
	stopReaping context.CancelFunc
	auditDB     *statedb.DB
}

var (
	kubeGuardSingleton atomic.Pointer[kubeGuardService]
	kubeGuardOnce      sync.Once
	// kubeGuardRequired records that the config asked for a monitor. Set even
	// when starting one failed, which is the point: "the operator wants
	// enforcement" and "enforcement is available" are different facts, and
	// conflating them is how a security control silently becomes optional.
	kubeGuardRequired atomic.Bool
)

// activeKubeGuard returns the running monitor, or nil.
func activeKubeGuard() *kubeGuardService { return kubeGuardSingleton.Load() }

// ensureKubeGuard starts the monitor configured in dir, once per process.
//
// Called from the top of bootstrapExecutors alongside ensureGitProxy, and for
// the same ordering reason: the broker is constructed per lease but the
// monitor is a singleton, and a broker built before the monitor existed would
// route nothing.
//
// A failure is loud but not fatal, with one consequence worth stating plainly
// in the message: with the monitor down, a kubeconfig grant cannot be
// delivered at all, because attachKubeGuard installs a refusing guard rather
// than letting the cluster credential through while the config says it
// cannot.
func ensureKubeGuard(dir string) {
	kubeGuardOnce.Do(func() {
		cfg, err := config.Load(dir)
		if err != nil || cfg == nil {
			return
		}
		kubeGuardRequired.Store(cfg.Executors.KubeGuard.Enabled)
		svc, err := startKubeGuard(cfg, dir)
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"ui: kubernetes access monitor NOT started: %v\n"+
					"    executors.kube_guard is enabled, so no kubeconfig grant can be\n"+
					"    delivered: leases needing one will be refused rather than handed the\n"+
					"    cluster credential directly. Fix the section or set enabled: false.\n", err)
			return
		}
		kubeGuardSingleton.Store(svc)
	})
}

// startKubeGuard builds and starts the monitor described by cfg, or returns
// nil when the section is disabled.
func startKubeGuard(cfg *config.Config, dir string) (*kubeGuardService, error) {
	if cfg == nil || !cfg.Executors.KubeGuard.Enabled {
		return nil, nil
	}
	k := cfg.Executors.KubeGuard

	tlsCfg, err := tlsconf.ServerConfig(k.CertFile, k.KeyFile, k.MinTLSVersion)
	if err != nil {
		return nil, fmt.Errorf("kubernetes monitor TLS: %w", err)
	}

	// Listen first: with no advertise URL the base is the bound address, and
	// an ephemeral port is not knowable until the listener exists.
	addr := strings.TrimSpace(k.ListenAddr)
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("kubernetes monitor listen on %s: %w", addr, err)
	}

	baseURL, err := kubeGuardBaseURL(k.AdvertiseURL, ln.Addr())
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	reg, err := kubeguard.NewRegistry(baseURL)
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("kubernetes monitor registry: %w", err)
	}

	// The trust anchor the sandbox's kubectl will use. Unlike git, a
	// kubeconfig can carry its own, so a self-signed hub certificate needs no
	// change to the sandbox image — which is why this is read here rather
	// than left to the operator.
	bundle, err := kubeGuardCABundle(k)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	reg.CABundle = bundle

	var auditDB *statedb.DB
	if db, dbErr := statedb.Open(state.DBPath(dir)); dbErr == nil {
		auditDB = db
	} else {
		fmt.Fprintf(os.Stderr,
			"ui: kubernetes monitor decisions will go to stderr, not the audit trail: %v\n", dbErr)
	}
	reg.OnEvent = kubeGuardAuditSink(auditDB)

	px, err := kubeguard.New(reg, kubeguard.Options{})
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("kubernetes monitor: %w", err)
	}

	reapCtx, stopReaping := context.WithCancel(context.Background())
	svc := &kubeGuardService{
		reg:         reg,
		proxy:       px,
		baseURL:     baseURL,
		policy:      k.Policy(),
		ttl:         time.Duration(k.SessionTTLMinutes()) * time.Minute,
		listener:    ln,
		stopReaping: stopReaping,
		auditDB:     auditDB,
	}

	go func() {
		if err := px.Serve(tls.NewListener(ln, tlsCfg)); err != nil {
			fmt.Fprintf(os.Stderr, "ui: kubernetes monitor stopped: %v\n", err)
		}
	}()
	go svc.reap(reapCtx)

	fmt.Fprintf(os.Stderr,
		"ui: kubernetes access monitor on %s, advertised as %s; policy floor %s\n",
		ln.Addr(), baseURL, svc.policy.Summary())
	return svc, nil
}

// kubeGuardCABundle returns the PEM a sandbox should trust for the monitor.
//
// ca_file when set, otherwise the serving certificate itself — which is the
// right answer for a self-signed certificate and harmless for one signed by a
// public CA, since a kubeconfig's certificate-authority-data replaces the
// trust store rather than adding to it, and the serving certificate's own
// chain is exactly what will be presented.
func kubeGuardCABundle(k config.KubeGuardConfig) ([]byte, error) {
	path := strings.TrimSpace(k.CAFile)
	label := "executors.kube_guard.ca_file"
	if path == "" {
		path = strings.TrimSpace(k.CertFile)
		label = "executors.kube_guard.cert_file"
	}
	if path == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	return pem, nil
}

// kubeGuardBaseURL resolves what sandboxes are pointed at.
//
// The bound address is only correct when the sandbox shares the hub's network
// namespace. Falling back to it rather than refusing keeps the single-host
// case working with no configuration, and a wrong choice surfaces immediately
// as a kubectl that cannot connect rather than as a credential going
// somewhere it should not.
func kubeGuardBaseURL(advertise string, bound net.Addr) (string, error) {
	if s := strings.TrimSpace(advertise); s != "" {
		u, err := url.Parse(s)
		if err != nil {
			return "", fmt.Errorf("kubernetes monitor advertise_url %q: %w", s, err)
		}
		return strings.TrimSuffix(u.String(), "/"), nil
	}
	tcp, ok := bound.(*net.TCPAddr)
	if !ok {
		return "", fmt.Errorf("kubernetes monitor listener is not TCP (%T), so no URL can be "+
			"advertised; set executors.kube_guard.advertise_url", bound)
	}
	host := tcp.IP.String()
	if tcp.IP == nil || tcp.IP.IsUnspecified() {
		// 0.0.0.0 is a bind address, never a destination.
		host = "127.0.0.1"
	}
	return "https://" + net.JoinHostPort(host, fmt.Sprint(tcp.Port)), nil
}

// reap sweeps lapsed sessions until ctx ends.
func (s *kubeGuardService) reap(ctx context.Context) {
	if s == nil {
		return
	}
	t := time.NewTicker(kubeGuardReapInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.reg.ReapExpired()
		}
	}
}

// Close stops serving and drops every live session.
func (s *kubeGuardService) Close() {
	if s == nil {
		return
	}
	if s.stopReaping != nil {
		s.stopReaping()
	}
	for _, sess := range s.reg.Sessions() {
		s.reg.Close(sess.ID, "the hub is shutting down")
	}
	if s.proxy != nil {
		_ = s.proxy.Close()
	}
	if s.auditDB != nil {
		_ = s.auditDB.Close()
	}
}

// Addr reports where the monitor is listening, for diagnostics.
func (s *kubeGuardService) Addr() string {
	if s == nil || s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// BaseURL reports what sandboxes are pointed at.
func (s *kubeGuardService) BaseURL() string {
	if s == nil {
		return ""
	}
	return s.baseURL
}

// kubeGuard adapts the monitor service to the broker's seam.
type kubeGuard struct{ svc *kubeGuardService }

// GuardKubeconfig mints a scoped monitor session for a kubeconfig grant.
//
// A nil service declines rather than failing, which is how a hub with no
// monitor configured keeps delivering kubeconfigs the old way. The broker
// treats a declined guard and a configured-but-broken one differently on
// purpose: only the second is a security control that was asked for and is
// not there, and that one fails the lease.
func (g kubeGuard) GuardKubeconfig(ctx context.Context, req secretbroker.KubeGuardRequest) (secretbroker.KubeGuardResult, error) {
	if g.svc == nil || g.svc.reg == nil {
		return secretbroker.KubeGuardResult{}, nil
	}
	if err := ctx.Err(); err != nil {
		return secretbroker.KubeGuardResult{}, err
	}
	if len(req.Kubeconfig) == 0 {
		return secretbroker.KubeGuardResult{}, fmt.Errorf("no kubeconfig to guard")
	}

	// The hub's configured floor narrowed by the grant. Neither party can be
	// surprised by the other: an operator who set the deployment to read-only
	// cannot be widened by any grant, and a grant that asks for less than the
	// floor allows gets only what it asked for.
	policy, err := g.svc.policy.Intersect(kubeguard.Policy{
		Verbs:      req.Verbs,
		Namespaces: req.Namespaces,
	})
	if err == nil {
		err = policy.Validate()
	}
	if err != nil {
		// Refused rather than defaulted. An empty intersection means the
		// grant asks for something the deployment floor excludes, and a
		// session built from a silently-substituted default would enforce a
		// policy nobody wrote — or, worse for the glob dimensions, no policy
		// at all, since an empty namespace list means "every namespace".
		return secretbroker.KubeGuardResult{}, fmt.Errorf(
			"grant %s cannot be honoured under this hub's kube_guard policy (%s): %w",
			req.GrantID, g.svc.policy.Summary(), err)
	}

	// The actor is the credential's owner when there is one. A personal
	// kubeconfig spent on a project should name the person in the monitor's
	// audit rows, not the executor that happened to run the task.
	actor := strings.TrimSpace(req.Owner)
	if actor == "" {
		actor = strings.TrimSpace(req.Actor)
	}
	if actor == "" {
		actor = workspaceLeaseActor
	}

	m, err := g.svc.reg.Mint(kubeguard.MintRequest{
		Kubeconfig: req.Kubeconfig,
		Policy:     policy,
		TTL:        g.svc.ttl,
		ProjectID:  req.ProjectID,
		ExecutorID: req.ExecutorID,
		Actor:      actor,
		GrantID:    req.GrantID,
		LeaseID:    req.LeaseID,
	})
	if err != nil {
		return secretbroker.KubeGuardResult{}, err
	}

	return secretbroker.KubeGuardResult{
		Kubeconfig: m.Kubeconfig,
		SessionID:  m.Session.ID,
		ExpiresAt:  m.Session.ExpiresAt,
		ReadOnly:   policy.ReadOnly(),
		Summary:    policy.Summary() + " via monitor",
	}, nil
}

// attachKubeGuard points a broker at the running monitor, if there is one.
//
// Called wherever the UI opens a broker, because the broker is constructed
// per call and the monitor is a process singleton started earlier in boot.
func attachKubeGuard(b *secretbroker.Broker) *secretbroker.Broker {
	if b == nil {
		return b
	}
	svc := activeKubeGuard()
	if svc == nil {
		if kubeGuardRequired.Load() {
			// The operator asked for enforcement and there is none. Refusing
			// here is the same trade attachGitGuard makes: a kubeconfig lease
			// fails loudly instead of delivering the cluster credential into
			// a sandbox while the config says it cannot happen.
			b.KubeGuard = unavailableKubeGuard()
		}
		return b
	}
	b.KubeGuard = kubeGuard{svc: svc}
	return b
}

// unavailableKubeGuard is what a hub that asked for a monitor and has not got
// one attaches, so a kubeconfig lease fails instead of falling back.
func unavailableKubeGuard() secretbroker.KubeGuard {
	return secretbroker.UnavailableKubeGuard{Reason: "executors.kube_guard is enabled but the " +
		"Kubernetes access monitor is not running, so a kubeconfig cannot be delivered " +
		"without handing the cluster credential to the sandbox directly"}
}

// closeKubeGuardSessions revokes every monitor session a lease's materials
// named. Safe with a nil lease, on a hub with no monitor, and more than once.
//
// Without this, revoking a lease wipes the kubeconfig file in the sandbox
// while the session it already authenticated with keeps working until its
// TTL — the gap Task 20178 closed for the other kinds.
func closeKubeGuardSessions(lease *secretbroker.Lease) {
	if lease == nil {
		return
	}
	svc := activeKubeGuard()
	if svc == nil || svc.reg == nil {
		return
	}
	for _, m := range lease.Materials {
		id := strings.TrimSpace(m.Env[secretbroker.KubeGuardSessionEnvKey])
		if id == "" {
			continue
		}
		svc.reg.Close(id, "lease released")
	}
}

// kubeGuardAuditSink forwards the monitor's decisions to the hub's
// hash-chained audit trail, falling back to stderr when there is no database.
//
// request_denied is the row that matters: it is the only place a sandbox's
// attempt to write to, or read outside, its granted scope is written down.
// The handler runs on the request goroutine, so it does only a single insert.
func kubeGuardAuditSink(db *statedb.DB) func(kubeguard.Event) {
	if db == nil {
		return func(e kubeguard.Event) {
			fmt.Fprintf(os.Stderr, "kube-guard: %s\n", e.String())
		}
	}
	return func(e kubeguard.Event) {
		// Identifiers, resource names, namespaces and reasons only.
		// kubeguard.Event has no field that could hold credential material or
		// object content, which is what makes this safe to write to a table
		// an operator exports.
		payload, err := json.Marshal(map[string]any{
			"kind":        string(e.Kind),
			"session_id":  e.SessionID,
			"cluster":     e.Cluster,
			"context":     e.Context,
			"verb":        e.Verb,
			"resource":    e.Resource,
			"namespace":   e.Namespace,
			"object":      e.Name,
			"reason":      string(e.Reason),
			"project_id":  e.ProjectID,
			"task_id":     e.TaskID,
			"executor_id": e.ExecutorID,
			"grant_id":    e.GrantID,
			"lease_id":    e.LeaseID,
			"detail":      e.Detail,
		})
		if err != nil {
			payload = []byte(`{}`)
		}
		if err := db.AppendAuditEvent(&statedb.AuditEvent{
			Timestamp:  e.At,
			Actor:      e.Actor,
			EventType:  string(auditaction.KubeGuardEvent(string(e.Kind))),
			EntityType: "kubeguard",
			EntityID:   e.SessionID,
			Payload:    string(payload),
		}); err != nil {
			// A request must not fail because the audit sink did, but a
			// decision that went unrecorded has to be visible somewhere.
			fmt.Fprintf(os.Stderr, "kube-guard: audit write failed (%v) for: %s\n", err, e.String())
		}
	}
}

// Interface check at the wiring layer, where a signature change should fail.
var _ secretbroker.KubeGuard = kubeGuard{}
