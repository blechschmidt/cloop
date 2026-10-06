package ui

// egressproxy.go hosts the egress broker's forward proxy in the hub (Task
// 20378).
//
// # Why it lives in the hub process
//
// The same reason the git proxy does (gitproxy.go). A session is redeemed at
// dispatch and authenticated later, when the sandbox's first request reaches
// the proxy, and sessions are memory: the broker that minted one is the only
// one that can authenticate it. So the process that dispatches a run must be
// the process whose proxy serves it. In a hub cluster every member binds a
// proxy of its own and the member that dispatches a run redeems its session
// there; no session is ever shared, and none is persisted.
//
// # What runs where
//
// `cloop ui` hosts it, when executors.egress.enabled is set in the hub's
// effective configuration. `cloop serve` does not: it dispatches nothing to a
// sandbox. A `cloop run` on a developer's machine, and an executor agent on an
// edge device, host none either — a device's sandboxes reach the proxy of the
// hub that dispatched to them, at executors.egress.advertise_addr. Only
// `cloop egress test` runs a proxy outside a hub, in its own process, for the
// length of one test.
//
// # Failure
//
// A proxy that will not bind is loud and not fatal, like the git proxy: the
// dashboard still serves, the reason is on stderr, in the status `cloop hub
// doctor` reads, and on every run that needed the proxy — refused with it when
// its .cloop/sandbox.yaml names a grant, journaled when it merely holds one.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/hublease"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// egressProxyService is the running proxy and the broker it authenticates
// against.
type egressProxyService struct {
	dir    string
	broker *egressbroker.Broker
	proxy  *egressbroker.Proxy
	// db is the control-plane handle the broker's store and auditor write
	// through, held for the proxy's life and closed after it: a session's
	// close row must land before the handle goes.
	db *statedb.DB
	// bound is where the proxy listens.
	bound *net.TCPAddr
	// advertised is the configured advertise_addr with a port, or "".
	advertised string
	// served is closed when Serve returns.
	served chan struct{}
	// statusKey names this process's hub_owners row.
	statusKey string
}

var (
	// egressProxyMu serialises starting and stopping the service.
	egressProxyMu sync.Mutex
	// egressProxyCurrent is the running service, or nil.
	egressProxyCurrent atomic.Pointer[egressProxyService]
	// egressProxyFailure is why the proxy the configuration asked for is not
	// running, or nil when it is, or was not asked for.
	egressProxyFailure atomic.Pointer[string]
	// egressProxyWanted records that the configuration enabled the proxy,
	// whether or not it then started — "the operator wants this" and "this is
	// available" are different facts, and a run is refused on the second only
	// once the first is known.
	egressProxyWanted atomic.Bool
)

// activeEgressProxy returns the running service, or nil.
func activeEgressProxy() *egressProxyService { return egressProxyCurrent.Load() }

// egressProxyUnavailable says why runs get no proxy session on this hub, or ""
// when the proxy is running.
func egressProxyUnavailable() string {
	if activeEgressProxy() != nil {
		return ""
	}
	if r := egressProxyFailure.Load(); r != nil && *r != "" {
		return "the hub's egress proxy is not running: " + *r
	}
	if egressProxyWanted.Load() {
		return "the hub's egress proxy is not running"
	}
	return "executors.egress is not enabled on this hub, so it hosts no egress proxy"
}

// egressProxyRemedy is what to do about egressProxyUnavailable's reason.
func egressProxyRemedy() string {
	if egressProxyWanted.Load() {
		return "See `cloop hub doctor` for why the hub's egress proxy did not start; fix executors.egress " +
			"and restart the hub."
	}
	return "Set executors.egress.enabled on the hub and restart it."
}

// ensureEgressProxy starts the proxy cfg enables for the control plane in dir,
// unless this process already hosts one for it.
//
// Called from bootstrapExecutors with the hub's effective configuration, so an
// executors.egress section in the per-instance overlay starts the proxy for
// that hub alone (Task 20364). A nil cfg is a configuration that could not be
// read, and starts nothing.
func ensureEgressProxy(cfg *config.Config, dir string, port int) {
	if strings.TrimSpace(dir) == "" {
		return
	}
	egressProxyMu.Lock()
	defer egressProxyMu.Unlock()
	if svc := activeEgressProxy(); svc != nil {
		// One proxy per process, like the executor registry it serves: a
		// second Server built in the same process (tests, embedders) shares
		// the first's rather than racing it for the port.
		return
	}
	wanted := cfg != nil && cfg.Executors.Egress.Enabled
	egressProxyWanted.Store(wanted)
	egressProxyFailure.Store(nil)
	if !wanted {
		return
	}
	svc, err := startEgressProxy(cfg, dir, port)
	if err != nil {
		reason := err.Error()
		egressProxyFailure.Store(&reason)
		fmt.Fprintf(os.Stderr,
			"ui: egress proxy NOT started: %v\n"+
				"    executors.egress is enabled, so runs that need the proxy are refused (a\n"+
				"    .cloop/sandbox.yaml naming an egress grant) or journaled as getting none\n"+
				"    (a project merely holding one). Fix the section, or set enabled: false.\n", err)
		recordEgressProxyStatus(nil, dir, port, egressbroker.HostedStatus{Enabled: true, Error: reason, HubPort: port})
		return
	}
	egressProxyCurrent.Store(svc)
	recordEgressProxyStatus(svc, dir, port, svc.status(port))
	fmt.Fprintf(os.Stderr, "ui: egress proxy listening on %s, advertised as %s\n", svc.bound, svc.defaultEndpoint())
}

// startEgressProxy binds and serves the proxy cfg describes.
func startEgressProxy(cfg *config.Config, dir string, port int) (*egressProxyService, error) {
	e := cfg.Executors.Egress
	addr := strings.TrimSpace(e.ListenAddr)
	if addr == "" {
		addr = egressbroker.DefaultListenAddr
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("bind executors.egress.listen_addr %s: %w", addr, err)
	}
	bound, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		_ = ln.Close()
		return nil, fmt.Errorf("executors.egress.listen_addr %s is not a TCP listener (%T)", addr, ln.Addr())
	}
	advertised, err := executor.EgressAdvertised(e.AdvertiseAddr, bound.Port)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}

	// The handle the broker's store and auditor write through, for the
	// proxy's life. Without it there is no grant to enforce and no trail to
	// write a decision into, so a proxy that cannot have one does not start.
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("open the control-plane database for the egress broker: %w", err)
	}
	// Egress is the hub's: its grants and decisions belong in the control
	// plane's chain, whichever project a session was issued for.
	db.AsControlPlane()

	svc := &egressProxyService{
		dir:        dir,
		db:         db,
		bound:      bound,
		advertised: advertised,
		served:     make(chan struct{}),
		statusKey:  egressProxyStatusKey(port),
	}
	broker, err := newEgressBroker(db, cfg, svc.defaultEndpoint())
	if err != nil {
		_ = ln.Close()
		_ = db.Close()
		return nil, err
	}
	proxy, err := egressbroker.NewProxy(broker, egressbroker.Options{
		ListenAddr:  addr,
		Endpoint:    svc.defaultEndpoint(),
		DialTimeout: time.Duration(e.DialTimeoutSeconds) * time.Second,
		// A run's session whose holder stopped waits for the process adopting
		// the run to restore it (Task 20383).
		AwaitSession: egressSessionHold,
	})
	if err != nil {
		_ = ln.Close()
		_ = db.Close()
		return nil, err
	}
	svc.broker, svc.proxy = broker, proxy
	go func() {
		defer close(svc.served)
		defer recoverGoroutine("egress proxy")
		if err := proxy.Serve(ln); err != nil {
			fmt.Fprintf(os.Stderr, "ui: egress proxy stopped: %v\n", err)
		}
	}()
	return svc, nil
}

// newEgressBroker builds an egress broker over the control plane's database
// with the hub's configuration applied: the session ceiling, the default
// quotas, and the auditor every decision is written through. The hosted proxy
// and the grants API both build theirs here, so the two cannot disagree about
// what a session may do.
func newEgressBroker(db *statedb.DB, cfg *config.Config, endpoint string) (*egressbroker.Broker, error) {
	store, err := secretstore.NewEgressStore(db)
	if err != nil {
		return nil, err
	}
	// Every run's session is recorded, so the process that adopts the run
	// after this one stops restores it with its counters (Task 20383).
	opts := append(egressBrokerOptions(secretstore.NewAuditor(db), cfg, endpoint),
		egressbroker.WithSessionStore(newEgressSessionStore(db)))
	return egressbroker.New(store, opts...)
}

// egressBrokerOptions are the broker options a hub's configuration implies.
func egressBrokerOptions(auditor secretbroker.Auditor, cfg *config.Config, endpoint string) []egressbroker.Option {
	opts := []egressbroker.Option{egressbroker.WithAuditor(auditor)}
	if endpoint != "" {
		opts = append(opts, egressbroker.WithEndpoint(endpoint))
	}
	if cfg == nil {
		return opts
	}
	e := cfg.Executors.Egress
	if m := e.MaxSessionMinutes; m > 0 {
		opts = append(opts, egressbroker.WithMaxSessionTTL(time.Duration(m)*time.Minute))
	}
	// Validated at load (clampEgressConfig), so an error here is a value that
	// was cleared there; zero is "no default".
	up, _ := egressbroker.ParseBytes(e.DefaultMaxBytesUp)
	down, _ := egressbroker.ParseBytes(e.DefaultMaxBytesDown)
	return append(opts, egressbroker.WithDefaultQuotas(up, down))
}

// defaultEndpoint is the address a sandbox with no route of its own is
// pointed at: the advertised address, or the bound one — with an unspecified
// bind read as loopback, because 0.0.0.0 is a bind address and never a
// destination.
func (s *egressProxyService) defaultEndpoint() string {
	if s.advertised != "" {
		return s.advertised
	}
	return net.JoinHostPort(s.boundHost(), strconv.Itoa(s.bound.Port))
}

// boundHost is the bound address as a destination on this host.
func (s *egressProxyService) boundHost() string {
	if s.bound.IP == nil || s.bound.IP.IsUnspecified() {
		return "127.0.0.1"
	}
	return s.bound.IP.String()
}

// status renders the service for its hub_owners row.
func (s *egressProxyService) status(port int) egressbroker.HostedStatus {
	return egressbroker.HostedStatus{
		Enabled:    true,
		Listening:  s.bound.String(),
		Advertised: s.defaultEndpoint(),
		HubPort:    port,
	}
}

// closeEgressProxy stops the proxy hosted for the control plane in dir, closing
// every live session first so the trail records why each one ended. dir ""
// stops whichever is running.
func closeEgressProxy(dir string) {
	egressProxyMu.Lock()
	svc := activeEgressProxy()
	if svc == nil || (dir != "" && svc.dir != dir) {
		egressProxyMu.Unlock()
		return
	}
	egressProxyCurrent.Store(nil)
	egressProxyMu.Unlock()

	// The runs first: their keepalives stop and each session is journaled on
	// its project, before the broker closes what is left underneath them. A
	// recorded run's session is suspended rather than closed (Task 20383):
	// the run outlives this process on its executor, and the process that
	// adopts it restores the session, counters and all.
	suspendAllRunEgress("the hub is shutting down")
	abortSessionHolds()
	svc.broker.CloseAllSessions("the hub is shutting down")
	_ = svc.proxy.Close()
	select {
	case <-svc.served:
	case <-time.After(10 * time.Second):
		fmt.Fprintln(os.Stderr, "ui: egress proxy did not stop within 10s")
	}
	releaseEgressProxyStatus(svc)
	_ = svc.db.Close()
}

// egressProxyStatusKey names this process's status row: its cluster instance
// id, or its host and hub port when it is not a cluster member. The port is
// part of it because two hubs on one host may share a control plane — this
// host's :8888 and its old stable dashboard do.
func egressProxyStatusKey(port int) string {
	if id := processInstanceID(); id != "" {
		return id
	}
	host, _ := os.Hostname()
	return "hub@" + host + ":" + strconv.Itoa(port)
}

// recordEgressProxyStatus writes this process's status row. Best-effort: a
// status that cannot be recorded costs `cloop hub doctor` its answer, not the
// proxy its function.
func recordEgressProxyStatus(svc *egressProxyService, dir string, port int, st egressbroker.HostedStatus) {
	id := hublease.LocalIdentity()
	st.Hostname, st.PID, st.BootID = id.Hostname, id.PID, id.BootID
	st.UpdatedAt = time.Now().UTC()
	meta, err := json.Marshal(st)
	if err != nil {
		return
	}
	key := egressProxyStatusKey(port)
	write := func(db *statedb.DB) error {
		return db.PutHubOwner(statedb.HubOwnerRow{
			Kind: egressbroker.HostedStatusKind, Key: key, InstanceID: key, Meta: string(meta),
		})
	}
	if svc != nil {
		if err := write(svc.db); err != nil {
			fmt.Fprintf(os.Stderr, "ui: record egress proxy status: %v\n", err)
		}
		return
	}
	path := state.DBPath(dir)
	if _, err := os.Stat(path); err != nil {
		return
	}
	db, err := statedb.Open(path)
	if err != nil {
		return
	}
	defer db.Close()
	if err := write(db); err != nil {
		fmt.Fprintf(os.Stderr, "ui: record egress proxy status: %v\n", err)
	}
}

// releaseEgressProxyStatus removes this process's status row on a clean stop,
// so `cloop hub doctor` does not report a proxy that is no longer listening.
func releaseEgressProxyStatus(svc *egressProxyService) {
	if svc == nil || svc.db == nil {
		return
	}
	if _, err := svc.db.ReleaseHubOwner(egressbroker.HostedStatusKind, svc.statusKey, svc.statusKey); err != nil &&
		!errors.Is(err, statedb.ErrHubOwnerNotFound) {
		fmt.Fprintf(os.Stderr, "ui: clear egress proxy status: %v\n", err)
	}
}

// hostedEgressBroker returns the running proxy's broker when it serves the
// control plane at dir. The grants API revokes through it, which is what
// lets a revocation in the dashboard close the live sessions under the grant
// at once: those sessions exist in this broker and nowhere else.
func hostedEgressBroker(dir string) *egressbroker.Broker {
	svc := activeEgressProxy()
	if svc == nil || svc.dir != dir {
		return nil
	}
	return svc.broker
}

// egressProxyContext bounds a single broker call made on the dispatch path.
func egressProxyContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), leaseTimeout)
}
