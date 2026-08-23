package ui

// gitproxy.go runs the git interception proxy alongside the hub and routes
// every git workspace through it (Task 20184).
//
// # Why it lives in the hub process and not in a `cloop git-proxy` command
//
// A session is minted at dispatch, in the driver, and authenticated later by
// the proxy when the sandbox's git connects. Sessions live in a
// *gitproxy.Registry, which is memory — so the process that mints must be the
// process that serves. A standalone proxy command would authenticate against
// an empty registry and refuse every request the hub had authorised.
//
// That is a property of the design rather than an omission: the alternative is
// a shared session store, which means the forge credential at rest in a second
// place, for a topology nobody has asked for.
//
// # What turning it on changes
//
// One thing, and only for git workspaces: the sandbox's remote becomes the
// proxy's URL and its credential becomes a session token. The forge PAT stops
// being delivered into sandboxes at all. Everything downstream — the
// provisioning fetch, the write-back push, grant matching, the audit rows —
// works unchanged, because gitproxy.Minted.RepoURL preserves the owner/name
// path that executor.Workspace.RepoPath reads.

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

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitproxycreds"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// gitProxyReapInterval is how often lapsed sessions are swept out of the
// registry. Expiry is enforced at authentication regardless, so this is
// hygiene — without it the map grows for the life of the process — and the
// interval only decides how long a dead entry occupies memory.
const gitProxyReapInterval = 5 * time.Minute

// gitProxyService is the running proxy and the registry it authenticates
// against. The zero value is "not configured", which every method tolerates so
// callers need no nil checks.
type gitProxyService struct {
	reg      *gitproxy.Registry
	proxy    *gitproxy.Proxy
	baseURL  string
	policy   gitproxy.Policy
	ttl      time.Duration
	listener net.Listener
	// stopReaping ends the sweep goroutine on Close. The reaper outlives any
	// single request context — sessions are minted at dispatch and swept long
	// after — so it is tied to the service's own life, not a caller's.
	stopReaping context.CancelFunc
	// auditDB is the handle the event sink writes through. May be nil.
	auditDB *statedb.DB
}

// gitProxySingleton is the process's proxy, or nil when none is configured.
//
// Process-wide, like the executor registry and the agent hub it feeds, and for
// the same reason: two Server instances in one process share one set of
// executors, so they must share the registry whose sessions those executors'
// sandboxes authenticate against. It is also what lets the two wiring sites —
// the agent hub's credential factory and reconciliation's Kubernetes driver —
// find the proxy without either of them being handed a Server.
var (
	gitProxySingleton atomic.Pointer[gitProxyService]
	gitProxyOnce      sync.Once
	// gitProxyRequired records that the config asked for a proxy. It is set
	// even when starting one failed, which is the whole point: "the operator
	// wants interception" and "interception is available" are different facts,
	// and conflating them is how a security control silently becomes optional.
	gitProxyRequired atomic.Bool
)

// activeGitProxy returns the running proxy, or nil.
func activeGitProxy() *gitProxyService { return gitProxySingleton.Load() }

// ensureGitProxy starts the proxy configured in dir, once per process.
//
// It must run before any executor is registered: the Kubernetes driver is
// given its credential source during reconciliation, which happens in New,
// and a source handed out before the proxy existed would route nothing. That
// ordering is the reason this is called from the top of bootstrapExecutors
// rather than from Run alongside the other background services.
//
// A failure is loud but not fatal. `cloop ui` is also how a single-project
// install runs, and refusing to boot the whole dashboard over a proxy
// certificate would be a poor trade — but a hub that silently dropped a
// security control its config asked for would be worse, so the message says
// exactly what is not in effect.
func ensureGitProxy(dir string) {
	gitProxyOnce.Do(func() {
		cfg, err := config.Load(dir)
		if err != nil || cfg == nil {
			return
		}
		gitProxyRequired.Store(cfg.Executors.GitProxy.Enabled)
		svc, err := startGitProxy(cfg, dir)
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"ui: git interception proxy NOT started: %v\n"+
					"    executors.git_proxy is enabled, so no git workspace can be provisioned:\n"+
					"    dispatches needing one will be refused rather than handed the forge\n"+
					"    credential directly. Fix the section or set enabled: false.\n", err)
			return
		}
		gitProxySingleton.Store(svc)
	})
}

// startGitProxy builds and starts the proxy described by cfg, or returns nil
// when the section is disabled.
//
// An enabled-but-broken section is an error rather than a silent skip. The
// proxy is a security control, and a hub that came up without one an operator
// had asked for would be a hub whose sandboxes hold forge credentials while
// its config file says they do not.
func startGitProxy(cfg *config.Config, dir string) (*gitProxyService, error) {
	if cfg == nil || !cfg.Executors.GitProxy.Enabled {
		return nil, nil
	}
	g := cfg.Executors.GitProxy

	tlsCfg, err := tlsconf.ServerConfig(g.CertFile, g.KeyFile, g.MinTLSVersion)
	if err != nil {
		return nil, fmt.Errorf("git proxy TLS: %w", err)
	}

	// Listen first: with no advertise URL the base is the bound address, and
	// an ephemeral port is not knowable until the listener exists.
	addr := strings.TrimSpace(g.ListenAddr)
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("git proxy listen on %s: %w", addr, err)
	}

	baseURL, err := gitProxyBaseURL(g.AdvertiseURL, ln.Addr())
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	reg, err := gitproxy.NewRegistry(baseURL)
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("git proxy registry: %w", err)
	}
	// The audit handle is opened here and held for the proxy's life, which is
	// the process's. That is the same bargain the agent hub makes with its own
	// handle: a connection per dispatch would leak, a connection per process
	// does not. A database that will not open costs the audit trail, not the
	// boundary — the proxy still refuses what it should.
	var auditDB *statedb.DB
	if db, dbErr := statedb.Open(state.DBPath(dir)); dbErr == nil {
		auditDB = db
	} else {
		fmt.Fprintf(os.Stderr,
			"ui: git proxy decisions will go to stderr, not the audit trail: %v\n", dbErr)
	}
	reg.OnEvent = gitProxyAuditSink(auditDB)

	px, err := gitproxy.New(reg, gitproxy.Options{})
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("git proxy: %w", err)
	}

	reapCtx, stopReaping := context.WithCancel(context.Background())
	svc := &gitProxyService{
		reg:         reg,
		proxy:       px,
		baseURL:     baseURL,
		policy:      g.Policy(),
		ttl:         time.Duration(g.SessionTTLMinutes()) * time.Minute,
		listener:    ln,
		stopReaping: stopReaping,
		auditDB:     auditDB,
	}

	go func() {
		if err := px.Serve(tls.NewListener(ln, tlsCfg)); err != nil {
			fmt.Fprintf(os.Stderr, "ui: git proxy stopped: %v\n", err)
		}
	}()
	go svc.reap(reapCtx)

	fmt.Fprintf(os.Stderr,
		"ui: git interception proxy on %s, advertised as %s; pushes limited to %s\n",
		ln.Addr(), baseURL, strings.Join(svc.policy.AllowedRefs, ", "))
	return svc, nil
}

// gitProxyBaseURL resolves what sandboxes are pointed at.
//
// The bound address is only correct when the sandbox shares the hub's network
// namespace, which is why an operator running containers, Pods or edge devices
// sets advertise_url. Falling back to it anyway — rather than refusing — keeps
// the single-host case working with no configuration, and a wrong choice here
// surfaces immediately as a fetch that cannot connect rather than as a
// credential going somewhere it should not.
func gitProxyBaseURL(advertise string, bound net.Addr) (string, error) {
	if s := strings.TrimSpace(advertise); s != "" {
		u, err := url.Parse(s)
		if err != nil {
			return "", fmt.Errorf("git proxy advertise_url %q: %w", s, err)
		}
		return strings.TrimSuffix(u.String(), "/"), nil
	}
	tcp, ok := bound.(*net.TCPAddr)
	if !ok {
		return "", fmt.Errorf("git proxy listener is not TCP (%T), so no URL can be advertised; "+
			"set executors.git_proxy.advertise_url", bound)
	}
	host := tcp.IP.String()
	if tcp.IP == nil || tcp.IP.IsUnspecified() {
		// 0.0.0.0 is a bind address, never a destination. Naming loopback is
		// the honest reading of "wherever this hub is", and an operator whose
		// sandboxes are elsewhere has to say where.
		host = "127.0.0.1"
	}
	return "https://" + net.JoinHostPort(host, fmt.Sprint(tcp.Port)), nil
}

// reap sweeps lapsed sessions until ctx ends.
func (s *gitProxyService) reap(ctx context.Context) {
	if s == nil {
		return
	}
	t := time.NewTicker(gitProxyReapInterval)
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

// Wrap decorates a credential source so its workspaces route through the
// proxy. A nil service returns src unchanged, which is what makes every call
// site free of configuration checks.
//
// A source that cannot be decorated is returned undecorated *and* reported,
// rather than dropped: refusing to lease at all would take out private-repo
// fetches on an executor whose only fault is that a proxy could not be
// interposed, and silently proceeding would be worse. In practice New only
// fails on programmer error — the policy and TTL were validated at load.
func (s *gitProxyService) Wrap(execID string, src executor.WorkspaceCredentialSource) executor.WorkspaceCredentialSource {
	if src == nil {
		return src
	}
	if s == nil {
		if gitProxyRequired.Load() {
			// The config asked for interception and there is none. Handing back
			// the undecorated source would deliver the forge PAT into every
			// sandbox while the config file says otherwise — the exact silent
			// downgrade the section exists to prevent. Refusing costs the git
			// workspaces on this hub and nothing else; the dashboard, the
			// bind-mount executors and every non-git workload keep working.
			return unavailableWorkspaceSource{}
		}
		return src
	}
	wrapped, err := gitproxycreds.New(src, s.reg, s.policy, s.ttl, execID, workspaceLeaseActor)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"ui: executor %s is NOT routed through the git proxy: %v\n", execID, err)
		return src
	}
	return wrapped
}

// Close stops serving and drops every live session.
//
// Sessions are closed rather than merely abandoned so the audit trail records
// why they ended, and so their counters land in the closing rows instead of
// disappearing with the process.
func (s *gitProxyService) Close() {
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

// unavailableWorkspaceSource refuses every workspace, for the hub that was
// told to intercept and could not.
//
// It refuses rather than returning no source at all because the two are read
// differently downstream: a nil source means "this hub has no broker", whose
// remedy is to create a grant, while this means "the proxy the operator
// configured is not running", whose remedy is to fix the section. Sending an
// operator after a grant they already have is a bad hour.
type unavailableWorkspaceSource struct{}

func (unavailableWorkspaceSource) ForWorkspace(_ context.Context, _ string, _ executor.Workspace) (executor.WorkspaceAccess, func(), error) {
	return executor.WorkspaceAccess{}, func() {}, fmt.Errorf(
		"%w: executors.git_proxy is enabled but the git interception proxy is not running, "+
			"so no workspace credential can be brokered; see the hub's startup log for why it "+
			"failed to start, or set executors.git_proxy.enabled: false to provision workspaces "+
			"by handing the forge credential to the sandbox as before",
		executor.ErrWorkspaceUnavailable)
}

// Addr reports where the proxy is listening, for diagnostics.
func (s *gitProxyService) Addr() string {
	if s == nil || s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// BaseURL reports what sandboxes are pointed at.
func (s *gitProxyService) BaseURL() string {
	if s == nil {
		return ""
	}
	return s.baseURL
}

// gitProxyAuditSink forwards the proxy's authorisation decisions to the hub's
// hash-chained audit trail, falling back to stderr when there is no database.
//
// push_denied is the row that matters: it is the only place a sandbox's
// attempt to reach a protected branch is written down, and nothing else in
// cloop would record it. The handler runs on the request goroutine, so it does
// only a single insert — a slow sink here would block a push.
func gitProxyAuditSink(db *statedb.DB) func(gitproxy.Event) {
	if db == nil {
		return func(e gitproxy.Event) {
			fmt.Fprintf(os.Stderr, "git-proxy: %s\n", e.String())
		}
	}
	return func(e gitproxy.Event) {
		// Only identifiers, ref names and reasons — the same fields
		// Event.String renders. gitproxy.Event has no field that could hold
		// credential material or object content, which is what makes this
		// safe to write to a table an operator exports.
		payload, err := json.Marshal(map[string]any{
			"kind":       string(e.Kind),
			"session_id": e.SessionID,
			"repo":       e.RepoPath,
			"project_id": e.ProjectID,
			"task_id":    e.TaskID,
			"refs":       e.Refs,
			"detail":     e.Detail,
		})
		if err != nil {
			payload = []byte(`{}`)
		}
		if err := db.AppendAuditEvent(&statedb.AuditEvent{
			Timestamp:  e.At,
			Actor:      e.Actor,
			EventType:  "gitproxy." + string(e.Kind),
			EntityType: "gitproxy",
			EntityID:   e.SessionID,
			Payload:    string(payload),
		}); err != nil {
			// A push must not fail because the audit sink did, but a decision
			// that went unrecorded has to be visible somewhere.
			fmt.Fprintf(os.Stderr, "git-proxy: audit write failed (%v) for: %s\n", err, e.String())
		}
	}
}
