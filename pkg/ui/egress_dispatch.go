package ui

// egress_dispatch.go gives each run its own egress proxy session (Task 20378).
//
// A project holding an egress grant has, until now, been granted nothing a
// run could use: the hub hosted no proxy and no dispatch redeemed a session,
// so `cloop egress grant` wrote a row and every sandbox stayed where its
// executor's network put it. Here, at dispatch, a run whose policy project
// holds an active grant aimed at it is redeemed one session on the hub's own
// proxy, and the session's proxy URL goes into the workload's environment.
//
// What the session is:
//
//   - one per run, for the run's lifetime: renewed while the run lives
//     (egressKeepaliveTick), never past its grant, and closed when the run
//     ends, is stopped, or the hub stops — and the moment its grant is
//     revoked, by any route, with its open tunnels cut;
//   - issued to the run's user and run id, which every audit row it produces
//     carries;
//   - held to the grant's policy and quotas, or the hub's default quotas when
//     the grant names none;
//   - reached by a route chosen for the executor it runs on (routeFor): a
//     container by its bridge's gateway, a Pod by the advertised Service, a
//     device by the advertised address — or not at all, in which case the
//     project's journal says why. Silence is never the outcome.
//
// What it is not: a way onto the network. A run with no network — a
// .cloop/sandbox.yaml that names no grant, firewall rules that reach nothing,
// a `network: none` executor — gets no session, because there is no route to
// the proxy to give it. And a .cloop/sandbox.yaml that *names* a grant the hub
// cannot serve is refused, with a 409 and the remedy, rather than started
// without the egress its author asked for.

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/fwpolicy"
	"github.com/blechschmidt/cloop/pkg/netfilter"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/sandbox"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// The session keepalive's pacing, the same as the secret lease's: check every
// tick, renew when the deadline is within the margin. Vars so tests can run it
// in milliseconds.
var (
	egressKeepaliveTick   = time.Minute
	egressKeepaliveMargin = 5 * time.Minute
)

// egressRun identifies the run a session is issued for.
type egressRun struct {
	// runID is the execution's id, the one its dispatch rows carry.
	runID string
	// identity is who started the run, "" for an internal dispatch.
	identity string
}

// egressUnservableError reports a .cloop/sandbox.yaml that names an egress
// grant the hub cannot serve to this run. Rendered as a 409 by jsonWorkloadErr:
// the request is well formed, and what conflicts is the repo's spec with what
// the hub can deliver.
type egressUnservableError struct {
	ProjectPath string
	GrantID     string
	ExecutorID  string
	Reason      string
	Remedy      string
}

// Error implements error.
func (e *egressUnservableError) Error() string {
	return fmt.Sprintf("sandbox: %s names the egress grant %q, which this hub cannot serve to a run of %s "+
		"on executor %s: %s. %s", sandbox.FileName, e.GrantID, e.ProjectPath, e.ExecutorID, e.Reason, e.Remediation())
}

// Remediation is the "what to do about it" half.
func (e *egressUnservableError) Remediation() string {
	if e.Remedy != "" {
		return e.Remedy
	}
	return "Fix the hub's executors.egress section, or remove capabilities.network from " + sandbox.FileName +
		" to run without egress."
}

// runEgress is one run's proxy session.
type runEgress struct {
	svc        *egressProxyService
	sess       *egressbroker.Session
	grantID    string
	workDir    string
	executorID string
	route      executor.EgressProxyRoute

	mu    sync.Mutex
	alive func(context.Context) bool

	stopKeepalive func()
	once          sync.Once
}

// liveEgress is every run session this hub holds open.
var liveEgress = &egressRegistry{all: make(map[*runEgress]string)}

// egressRegistry indexes open run sessions by the handle of the workload
// holding them. A session is in it from redemption, before it has a handle,
// so a hub stopping between the two still closes it.
type egressRegistry struct {
	mu  sync.Mutex
	all map[*runEgress]string
}

func (r *egressRegistry) add(egr *runEgress) {
	r.mu.Lock()
	r.all[egr] = ""
	r.mu.Unlock()
}

func (r *egressRegistry) bind(egr *runEgress, handleID string) {
	r.mu.Lock()
	if _, ok := r.all[egr]; ok {
		r.all[egr] = handleID
	}
	r.mu.Unlock()
}

func (r *egressRegistry) remove(egr *runEgress) {
	r.mu.Lock()
	delete(r.all, egr)
	r.mu.Unlock()
}

// byHandle returns the session the workload with handleID holds, or nil.
func (r *egressRegistry) byHandle(handleID string) *runEgress {
	if handleID == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for egr, h := range r.all {
		if h == handleID {
			return egr
		}
	}
	return nil
}

// idsForHandle returns the ids of the sessions the workload with handleID
// holds, sorted: what a run's owner row names, so the process adopting the run
// restores them (Task 20383).
func (r *egressRegistry) idsForHandle(handleID string) []string {
	if handleID == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for egr, h := range r.all {
		if h == handleID && egr.sess != nil {
			out = append(out, egr.sess.ID)
		}
	}
	sort.Strings(out)
	return out
}

// snapshot returns every open session.
func (r *egressRegistry) snapshot() []*runEgress {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*runEgress, 0, len(r.all))
	for egr := range r.all {
		out = append(out, egr)
	}
	return out
}

// closeRunEgress closes the session the workload with handleID holds, if any.
func closeRunEgress(handleID, reason string) {
	liveEgress.byHandle(handleID).close(reason)
}

// closeAllRunEgress closes every session this hub holds.
func closeAllRunEgress(reason string) {
	for _, egr := range liveEgress.snapshot() {
		egr.close(reason)
	}
}

// suspendAllRunEgress suspends every durable session this hub holds and closes
// the rest — what a hub stopping gracefully does, so the process that adopts
// each run restores its session with its counters rather than finding it
// closed (Task 20383).
func suspendAllRunEgress(reason string) {
	for _, egr := range liveEgress.snapshot() {
		egr.suspend(reason)
	}
}

// applyEgressSession redeems a proxy session for a run whose policy project
// holds an active egress grant, and puts it in spec: the proxy variables in
// Env, declared sensitive, and the route in EgressProxy.
//
// It runs after the sandbox and the firewall have shaped spec, because both
// decide whether the run has a network at all and the firewall decides what a
// route to the proxy has to get through. resolved is the project's sandbox
// spec; a grant it names is the one redeemed, and one that cannot be served is
// a refusal. With no grant named, a project that holds none gets nothing and
// no journal row — there was nothing to give — and one that holds a grant this
// run cannot use gets a journal row saying why.
//
// The returned session is nil when none was issued. Otherwise the caller owns
// it: bind it to the workload once started, and close it on every path that
// does not start one.
func applyEgressSession(spec executor.Spec, ex executor.Executor, workDir string,
	resolved *sandbox.Resolved, run egressRun) (executor.Spec, *runEgress, error) {
	if ex == nil {
		return spec, nil, nil
	}
	named := ""
	if resolved.Present() {
		named = strings.TrimSpace(resolved.Spec.Capabilities.Network)
	}
	requester := secretbroker.Requester{
		ExecutorID: ex.ID(),
		// A feature holds its parent project's grants and never its own path,
		// exactly as for the secret lease (features.go).
		ProjectID: policyProjectPath(workDir),
		RunID:     run.runID,
	}

	// refuse turns a reason this run gets no session into the outcome: a
	// refusal when the sandbox spec named the grant, a journal row when the
	// project merely holds one.
	refuse := func(grantID, reason, remedy string) (executor.Spec, *runEgress, error) {
		if named != "" {
			return spec, nil, &egressUnservableError{ProjectPath: workDir, GrantID: named,
				ExecutorID: ex.ID(), Reason: reason, Remedy: remedy}
		}
		msg := fmt.Sprintf("egress: this project holds the egress grant %s, but this run on executor %s "+
			"gets no proxy session: %s", grantID, ex.ID(), reason)
		if remedy != "" {
			msg += ". " + remedy
		}
		logEgress(workDir, msg)
		return spec, nil, nil
	}

	svc := activeEgressProxy()
	match, lookupErr := matchingEgressGrant(svc, requester, named)
	if lookupErr != nil {
		if named != "" {
			return refuse(named, "its grants could not be read: "+lookupErr.Error(), "")
		}
		// No row: a hub whose grant store cannot be read cannot say whether
		// this project holds a grant, and a row on every run saying so would
		// bury the one that matters. The hub's log has it.
		fmt.Fprintf(os.Stderr, "ui: egress: read grants for %s: %v\n", workDir, lookupErr)
		return spec, nil, nil
	}
	grant := match.active
	if grant == nil {
		if match.inactive == nil {
			// No grant was ever aimed at this run: nothing was expected, so
			// nothing is said.
			return spec, nil, nil
		}
		// One was, and it is spent. Asked for anyway when the hub hosts the
		// proxy, so the broker's own denial lands in the trail and the
		// refusal metrics — the same record a direct redemption would make.
		if svc != nil {
			ctx, cancel := egressProxyContext()
			_, _ = svc.broker.Redeem(ctx, egressbroker.RedeemRequest{Requester: requester,
				TaskID: run.runID, RunID: run.runID, Actor: egressActor(run), GrantID: match.inactive.ID})
			cancel()
		}
		return refuse(match.inactive.ID, "the grant is no longer active — "+match.inactive.DenyReason(time.Now()),
			"Ask an operator to issue it again.")
	}
	if svc == nil {
		return refuse(grant.ID, egressProxyUnavailable(), egressProxyRemedy())
	}
	if spec.DisableNetwork {
		return refuse(grant.ID, "the run has no network — its "+sandbox.FileName+" names no egress grant, or "+
			"the firewall rules that apply to it reach nothing — so there is no route to the proxy",
			"Name the grant in capabilities.network, or let the firewall rules reach something.")
	}
	if !ex.Capabilities().NetworkEgress {
		return refuse(grant.ID, "the executor gives its sandboxes no network, so there is no route to the proxy",
			"Bind the project to an executor whose sandboxes have a network (an --internal bridge is enough).")
	}
	route, why, remedy := svc.routeFor(ex, spec)
	if why != "" {
		return refuse(grant.ID, why, remedy)
	}

	ctx, cancel := egressProxyContext()
	defer cancel()
	red, err := svc.broker.Redeem(ctx, egressbroker.RedeemRequest{
		Requester: requester,
		TaskID:    run.runID,
		RunID:     run.runID,
		Actor:     egressActor(run),
		GrantID:   grant.ID,
		Endpoint:  route.String(),
		NoProxy:   hubEndpointHosts(),
		// Recorded with its counters, so the process that adopts the run
		// after this one stops restores it against the same quota (Task
		// 20383).
		Durable: leaseHolderID() != "",
	})
	if err != nil {
		return refuse(grant.ID, "the egress broker refused a session: "+secretbroker.RedactString(err.Error()), "")
	}

	spec = withEgressEnv(spec, ex, red)
	r := route
	spec.EgressProxy = &r

	egr := &runEgress{
		svc: svc, sess: red.Session, grantID: grant.ID, workDir: workDir,
		executorID: ex.ID(), route: route,
	}
	liveEgress.add(egr)
	egr.startKeepalive()
	logEgress(workDir, fmt.Sprintf("egress: proxy session %s issued under the grant %s (%s) for run %s on "+
		"executor %s; the sandbox reaches the proxy at %s, and the session is renewed while the run lives",
		red.Session.ID, grant.ID, red.Session.Grant.Summary(), run.runID, ex.ID(), route))
	return spec, egr, nil
}

// egressActor is who a session is issued to: the run's user, or the hub for
// a dispatch nobody started.
func egressActor(run egressRun) string {
	if run.identity != "" {
		return run.identity
	}
	return "ui"
}

// egressMatch is what the grants aimed at one run are: the active one it
// would be redeemed under, and otherwise the newest that was aimed at it and
// is spent — revoked, or expired.
type egressMatch struct {
	active   *egressbroker.Grant
	inactive *egressbroker.Grant
}

// matchingEgressGrant finds the grants aimed at a requester: the named one, or
// the newest that matches — the same choice the broker makes. With no hosted
// proxy they are read through a broker opened for the purpose, only to decide
// whether a refusal or a journal row is owed.
func matchingEgressGrant(svc *egressProxyService, req secretbroker.Requester, named string) (egressMatch, error) {
	var (
		grants []egressbroker.Grant
		err    error
	)
	if svc != nil {
		grants, err = svc.broker.ListGrants(egressbroker.GrantFilter{})
	} else {
		grants, err = readEgressGrants(controlPlaneDir())
	}
	if err != nil {
		return egressMatch{}, err
	}
	now := time.Now()
	var m egressMatch
	for i := range grants {
		g := grants[i]
		if named != "" && g.ID != named {
			continue
		}
		if !g.Subject.Matches(req) {
			continue
		}
		if g.Active(now) {
			m.active = &g
			return m, nil
		}
		if m.inactive == nil {
			m.inactive = &g
		}
	}
	return m, nil
}

// readEgressGrants lists the egress grants in the control plane at dir, for a
// hub that hosts no proxy. Only the egress store is opened — not the secret
// broker, whose key would be derived on every dispatch for nothing — and a
// control plane with no database yet has no grants.
func readEgressGrants(dir string) ([]egressbroker.Grant, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, nil
	}
	path := state.DBPath(dir)
	if _, err := os.Stat(path); err != nil {
		return nil, nil
	}
	db, err := statedb.Open(path)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	store, err := secretstore.NewEgressStore(db)
	if err != nil {
		return nil, err
	}
	return store.ListGrants()
}

// routeFor chooses how a workload on ex reaches this proxy, or says why it
// cannot — the reason first, then the remedy.
func (s *egressProxyService) routeFor(ex executor.Executor, spec executor.Spec) (executor.EgressProxyRoute, string, string) {
	port := s.bound.Port
	switch ex.Kind() {
	case executor.KindLocalProcess:
		// The workload is a process on this host: the bound address is its
		// own.
		return executor.EgressProxyRoute{Host: s.boundHost(), Port: port}, "", ""

	case executor.KindContainer:
		return executor.ContainerEgressRoute(s.bound)

	case executor.KindKubernetes:
		route, why, remedy := s.advertisedRoute("Pods", executor.EgressRemedyPods)
		if why != "" {
			return route, why, remedy
		}
		// A Pod's NetworkPolicy is built from the executor's egress_filter and
		// the stored rules, and cloop does not add the proxy to it: on a
		// cluster the proxy is a Service, which a NetworkPolicy cannot name.
		// So the policy must already open it, and is proven to here.
		rules := spec.EgressRules
		if rules == nil {
			rules = executor.PostureOf(ex).Config
		}
		if why := proxyBlockedBy(rules, route); why != "" {
			return executor.EgressProxyRoute{}, why, fmt.Sprintf("Open %s in executor %s's "+
				"executors.kubernetes.egress_filter (cidrs and ports), or advertise an address it allows.",
				route, ex.ID())
		}
		return route, "", ""

	case executor.KindRemoteAgent, executor.KindVirtual:
		route, why, remedy := s.advertisedRoute("a device", executor.EgressRemedyDevices)
		if why != "" {
			return route, why, remedy
		}
		// The device installs a firewall for this workload — the stored rule
		// sets, or a virtual executor's own — and opens the route in it from
		// the Spec. An agent too old to know the field would install the
		// rules without it.
		pos := executor.PostureOf(ex)
		firewalled := spec.EgressRules != nil || (pos.Own != nil && pos.Own.HasDestination())
		if pos.Own != nil && !pos.Own.HasDestination() && spec.EgressRules == nil {
			return executor.EgressProxyRoute{}, fmt.Sprintf("%s gives this run no network, so there is no route "+
				"to the proxy", pos.OwnName), "Give the device's sandboxes a network."
		}
		if firewalled {
			if v := agentProtocolOf(ex); v > 0 && !remote.SupportsEgressProxy(v) {
				return executor.EgressProxyRoute{},
					executor.ProtocolShortfall("The device's agent", v, remote.MinEgressProxyVersion,
						"to open the hub's egress proxy in this run's firewall"),
					executor.AgentUpgradePath(v, remote.MinEgressProxyVersion)
			}
			if _, ok := route.Addr(); !ok {
				return executor.EgressProxyRoute{}, fmt.Sprintf("this run is confined by a firewall on the device, "+
						"which opens addresses, and the proxy is advertised by name (%s)", route),
					"Set executors.egress.advertise_addr to an address, not a name."
			}
		}
		return route, "", ""
	}
	return executor.EgressProxyRoute{}, fmt.Sprintf("executor kind %q has no route to the hub's egress proxy",
		ex.Kind()), ""
}

// advertisedRoute is the configured advertise_addr as a route, for executors
// on other machines — or why it cannot be one. who names them for messages.
func (s *egressProxyService) advertisedRoute(who, unsetRemedy string) (executor.EgressProxyRoute, string, string) {
	route, why := executor.AdvertisedEgressRoute(s.advertised, s.bound.String(), who)
	if why != "" {
		return executor.EgressProxyRoute{}, why, unsetRemedy
	}
	return route, "", ""
}

// proxyBlockedBy says why rules would drop a workload's connection to route,
// or "" when they let it through — proven with the compiled policy's own
// semantics, the same netfilter.Evaluate the drivers' rulesets are tested
// against. nil rules filter nothing.
func proxyBlockedBy(rules *executor.FirewallRules, route executor.EgressProxyRoute) string {
	if rules == nil {
		return ""
	}
	addr, ok := route.Addr()
	if !ok {
		return fmt.Sprintf("the sandbox's network is filtered by addresses, and the proxy is advertised by name (%s), "+
			"which a filter cannot be shown to allow", route)
	}
	if !rules.HasDestination() {
		return "the firewall rules for this run reach nothing"
	}
	in, err := fwpolicy.Input(*rules)
	if err != nil {
		return "the firewall rules for this run are unreadable: " + err.Error()
	}
	policy, err := netfilter.Compile(in)
	if err != nil {
		return "the firewall rules for this run do not compile: " + err.Error()
	}
	if v, why := policy.WireOnly().Evaluate(addr, uint16(route.Port), netfilter.ProtoTCP); v != netfilter.VerdictAllow {
		return fmt.Sprintf("the firewall rules for this run drop the proxy at %s (%s)", route, why)
	}
	return ""
}

// agentProtocolOf is the protocol the agent behind a remote or virtual
// executor negotiated, or 0 when there is none to ask.
func agentProtocolOf(ex executor.Executor) int {
	if v, ok := ex.(*remote.Virtual); ok {
		return v.Parent().ProtocolVersion()
	}
	if p, ok := ex.(interface{ ProtocolVersion() int }); ok {
		return p.ProtocolVersion()
	}
	return 0
}

// hubEndpointHosts are hosts a sandbox reaches directly rather than through
// the egress proxy: the hub's own git proxy and Kubernetes access monitor,
// which a grant does not name and should not have to. Without them git and
// kubectl, which honour HTTPS_PROXY, would send the hub's own endpoints to the
// egress proxy and be refused.
func hubEndpointHosts() []string {
	var out []string
	for _, base := range []string{activeGitProxy().BaseURL(), activeKubeGuard().BaseURL()} {
		if u, err := url.Parse(base); err == nil && u.Hostname() != "" {
			out = append(out, u.Hostname())
		}
	}
	return out
}

// withEgressEnv puts a session's variables into spec.Env, replacing any of the
// same names the environment already carried, and declares the ones holding
// the credential sensitive (redact.EnvKey) — so the executor scrubs them from
// the output it captures, the workload scrubs them from its own, and the
// dispatched spec is stored without them.
func withEgressEnv(spec executor.Spec, ex executor.Executor, red *egressbroker.Redemption) executor.Spec {
	base := spec.Env
	if base == nil && !executor.IsolatesFromHost(ex) {
		// nil means "inherit" on the host driver, and an Env that only held
		// these would strip PATH and HOME from the harness (see applyLease).
		base = os.Environ()
	}
	set := red.Env()
	declared := map[string]bool{}
	out := make([]string, 0, len(base)+len(set)+1)
	for _, kv := range base {
		name, value, _ := strings.Cut(kv, "=")
		if name == redact.EnvKey {
			for _, n := range strings.Split(value, ",") {
				if n = strings.TrimSpace(n); n != "" {
					declared[n] = true
				}
			}
			continue
		}
		if _, replaced := set[name]; replaced {
			continue
		}
		out = append(out, kv)
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, k+"="+set[k])
	}
	for _, k := range egressbroker.ProxyEnvKeys {
		declared[k] = true
	}
	names := make([]string, 0, len(declared))
	for n := range declared {
		names = append(names, n)
	}
	sort.Strings(names)
	spec.Env = append(out, redact.EnvKey+"="+strings.Join(names, ","))
	return spec
}

// bindHandle records the workload holding the session, and how to ask whether
// it is still running: the keepalive renews only a session whose workload is.
func (r *runEgress) bindHandle(ex executor.Executor, handleID string) {
	if r == nil {
		return
	}
	liveEgress.bind(r, handleID)
	r.mu.Lock()
	r.alive = func(ctx context.Context) bool {
		st, err := ex.Status(ctx, handleID)
		if err != nil {
			// A device between reconnects reports unknown; the supervisor's
			// failover decides it is gone, and the run's end closes this.
			return !errors.Is(err, executor.ErrHandleNotFound)
		}
		return !st.State.Terminal()
	}
	r.mu.Unlock()
}

// close ends the session for reason and journals it once. Nil-safe and
// idempotent, so every path that might end a run can call it.
func (r *runEgress) close(reason string) {
	if r == nil {
		return
	}
	r.once.Do(func() {
		// The keepalive first, so it does not read the close below as a
		// revocation and journal it a second time.
		if r.stopKeepalive != nil {
			r.stopKeepalive()
		}
		liveEgress.remove(r)
		if r.sess.Closed() {
			// Ended underneath the run — revoked, expired — and journaled
			// by the keepalive when it was.
			return
		}
		r.svc.broker.CloseSession(r.sess.ID, reason)
		r.journalEnd()
	})
}

// suspend stops serving the session without ending it: its counters are
// checkpointed, its sockets close and its record stays open for the process
// that adopts the run. A session with no record is closed instead — nothing
// could restore it, and its journal would otherwise never say it ended.
// Nil-safe; shares close's once, so a session is either suspended or closed
// here, never both.
func (r *runEgress) suspend(reason string) {
	if r == nil {
		return
	}
	if r.sess == nil || !r.sess.Durable() {
		r.close(reason)
		return
	}
	r.once.Do(func() {
		if r.stopKeepalive != nil {
			r.stopKeepalive()
		}
		liveEgress.remove(r)
		if r.sess.Closed() {
			return
		}
		r.svc.broker.SuspendSession(r.sess.ID, reason)
		logEgress(r.workDir, fmt.Sprintf("egress: proxy session %s suspended — %s; %d request(s), %s up, %s down "+
			"so far, which the hub process that adopts the run counts on from", r.sess.ID, reason, r.sess.Requests(),
			egressByteCount(r.sess.BytesUp()), egressByteCount(r.sess.BytesDown())))
	})
}

// journalEnd writes the session's last row on the project's journal.
func (r *runEgress) journalEnd() {
	s := r.sess
	msg := fmt.Sprintf("egress: proxy session %s closed — %s; %d request(s), %s up, %s down",
		s.ID, s.CloseReason(), s.Requests(), egressByteCount(s.BytesUp()), egressByteCount(s.BytesDown()))
	if n := s.TunnelsCut(); n > 0 {
		msg += fmt.Sprintf("; %d live tunnel(s) were cut", n)
	}
	logEgress(r.workDir, msg)
}

// egressByteCount renders bytes a session moved. egressbroker.FormatBytes is
// the quota spelling, in which zero means unlimited; here zero is zero.
func egressByteCount(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// startKeepalive renews the session while its run lives and ends it the
// moment its grant stops authorising it. Started once, by applyEgressSession.
func (r *runEgress) startKeepalive() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	r.stopKeepalive = func() {
		cancel()
		<-done
	}
	go func() {
		defer close(done)
		defer recoverGoroutine("egress session keepalive: " + r.sess.ID)
		r.keepalive(ctx)
	}()
}

// keepalive is the loop startKeepalive runs.
func (r *runEgress) keepalive(ctx context.Context) {
	t := time.NewTicker(egressKeepaliveTick)
	defer t.Stop()
	broker, id := r.svc.broker, r.sess.ID
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.sess.Done():
			// Closed underneath the run: its grant revoked in the dashboard
			// (the broker that holds the session closes it there and then,
			// tunnels and all), its TTL run out unrenewed, or the hub stopping.
			if ctx.Err() == nil {
				r.journalEnd()
			}
			return
		case now := <-t.C:
			// The counters, written into the session's record (Task 20383):
			// what a process restoring the session after this one dies counts
			// on from, so a SIGKILL loses at most a tick of traffic against
			// the quota.
			broker.CheckpointSession(id)
			// The grant, re-read every tick: a revocation made where this
			// broker did not see it — `cloop egress revoke`, another hub
			// member — lands within a tick rather than at the session's TTL.
			if err := broker.RecheckSession(id); err != nil {
				if ctx.Err() != nil || r.sess.Closed() {
					continue // the Done case reports it
				}
				broker.CloseSession(id, egressEndReason(err))
				continue
			}
			if r.sess.ExpiresAt().Sub(now) > egressKeepaliveMargin {
				continue
			}
			r.mu.Lock()
			alive := r.alive
			r.mu.Unlock()
			if alive != nil && !alive(ctx) {
				// Finished, or gone from its executor: the run's end closes
				// the session; renewing it now would only widen the window in
				// which a lost workload keeps a way out.
				continue
			}
			if _, err := broker.ExtendSession(ctx, id); err != nil {
				if ctx.Err() != nil {
					return
				}
				if egressRenewalIsFinal(err) && !r.sess.Closed() {
					broker.CloseSession(id, egressEndReason(err))
				}
				// Anything else is retried next tick, several times before
				// the margin runs out.
			}
		}
	}
}

// egressRenewalIsFinal reports whether a refused renewal will be refused
// again.
func egressRenewalIsFinal(err error) bool {
	for _, final := range []error{
		egressbroker.ErrGrantRevoked, egressbroker.ErrGrantExpired,
		egressbroker.ErrNoGrant, egressbroker.ErrSessionExpired,
	} {
		if errors.Is(err, final) {
			return true
		}
	}
	return false
}

// egressEndReason renders why a session's grant no longer authorises it, for
// its close row and the journal.
func egressEndReason(err error) string {
	switch {
	case errors.Is(err, egressbroker.ErrGrantRevoked):
		return "its egress grant was revoked"
	case errors.Is(err, egressbroker.ErrGrantExpired):
		return "its egress grant expired"
	case errors.Is(err, egressbroker.ErrNoGrant):
		return "its egress grant no longer authorises this run"
	}
	return "its egress grant could not be confirmed: " + err.Error()
}

// logEgress appends one row to the project's journal.
func logEgress(workDir, msg string) {
	state.LogEvent(workDir, state.EventRow{
		Type:    state.EventEgress,
		Step:    state.NoStep,
		Message: msg,
	})
}
