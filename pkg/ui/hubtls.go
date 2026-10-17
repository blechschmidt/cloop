package ui

// hubtls.go issues the credential monitors' certificates from the hub's own CA
// when their section says tls: auto (Task 20409), and follows a rotation of
// that CA online (Task 20438). See pkg/hubca for the CA itself, for who
// replaces a leaf when, and for the rotation's steps.
//
// Five things live here:
//
//   - the control plane's CAs as this process knows them (hubCA): opened, and
//     on a fresh control plane minted, once per process under the same KEK
//     registry as every brokered secret, and re-read every minute — sooner
//     when the cluster bus says another process took a rotation step — so a
//     member hands new dispatches the CAs a stage added, signs with the CA an
//     activation made active, and stops trusting the one a retirement took
//     out;
//   - a monitor's certificate (startMonitorCertificate): a hubca.Server whose
//     GetCertificate the listener asks per handshake, refreshed on the same
//     tick so a member serves the leaf the leader issued;
//   - the leader's duty (watchMonitorCertificates, and the tick right after
//     an activation), which renews both monitors' leaves well before they
//     expire and reissues them from a newly active CA;
//   - what each dispatch is told to trust (applyGitProxyTrust, the kube
//     guard's kubeconfigs, labelHubCATrust), read once per dispatch and
//     recorded on its spec, so an activation can tell which running runs
//     would stop verifying the monitors;
//   - an emergency rotation's cut: the proxy sessions of the runs it named,
//     ended by every member that holds them.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/hubca"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	// monitorCertRefreshInterval is how often each member re-reads the CAs
	// and the monitors' stored leaves. The leader renews two days before
	// expiry, so a minute is far more often than renewal needs; it is what
	// makes a rotation step reach every member within a minute when the bus
	// cannot carry the news (a standalone hub, a step taken by the CLI while
	// the bus was pruned).
	monitorCertRefreshInterval = time.Minute
	// monitorCertRenewInterval is how often the leader checks whether a leaf
	// is due.
	monitorCertRenewInterval = 10 * time.Minute
	// busTopicHubCA carries "a rotation step was taken": every member
	// re-reads its CAs at once rather than at its next tick.
	busTopicHubCA = hubca.BusTopic
	// hubCAMemberRowTTL is how long a stopped member's report is kept.
	hubCAMemberRowTTL = 24 * time.Hour
	// hubCAEmergencyWindow bounds how long after an emergency rotation a
	// member starting up still ends the sessions it named: a session it
	// restores later than that was minted before the hub's restart and is
	// already gone, or belongs to a run long over.
	hubCAEmergencyWindow = 24 * time.Hour
)

// hubCA is a control plane's CAs as this process knows them, what they are
// stored and sealed with, and the monitors issuing from them.
type hubCA struct {
	dir     string
	db      *statedb.DB
	store   *hubca.Store
	keyring *secretbroker.Keyring
	trust   *hubca.Trust

	mu       sync.Mutex
	monitors map[hubca.Monitor]*monitorCert
	stop     context.CancelFunc
	kick     chan struct{}
	// lastErr is the last refresh failure reported, so one is said once.
	lastErr string
	// lastGen is the set of CAs the last tick acted on: a change is judged
	// against it rather than against Refresh's answer, since a leaf's own
	// refresh may have read the change first.
	lastGen string
	// cut remembers the emergency rotations whose runs this process has
	// already cut off.
	cut map[string]bool
}

var (
	hubCAMu sync.Mutex
	// hubCAs caches the opened CAs per control-plane directory: both monitors
	// share one keyring derivation, one database handle and one refresher,
	// held for the process's life like the proxies' audit handles.
	hubCAs = map[string]*hubCA{}
)

// openHubCA returns the control plane's CAs, minting the first one the first
// time any hub process asks for it.
func openHubCA(dir string) (*hubCA, error) {
	hubCAMu.Lock()
	defer hubCAMu.Unlock()
	if c := hubCAs[dir]; c != nil {
		return c, nil
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return nil, fmt.Errorf("open the control plane's database for the hub CA: %w", err)
	}
	db = db.AsControlPlane()
	fail := func(err error) (*hubCA, error) {
		_ = db.Close()
		return nil, err
	}
	ks, err := secretstore.New(db)
	if err != nil {
		return fail(err)
	}
	kr, err := secretbroker.OpenKeyring(ks, secretbroker.WithKeyringActor("hub"))
	if err != nil {
		if errors.Is(err, secretbroker.ErrNoKey) {
			return fail(hubca.ErrNoKey)
		}
		return fail(fmt.Errorf("open the sealing keys the hub CA is kept under: %w", err))
	}
	store, err := hubca.NewStore(db)
	if err != nil {
		return fail(err)
	}
	tr, err := hubca.OpenTrust(store, kr, hubCAOptions(db))
	if err != nil {
		return fail(err)
	}
	c := &hubCA{dir: dir, db: db, store: store, keyring: kr, trust: tr,
		monitors: map[hubca.Monitor]*monitorCert{}, kick: make(chan struct{}, 1), cut: map[string]bool{}}
	hubCAs[dir] = c
	return c, nil
}

// processHubCA is the CAs this process's credential monitors issue from, or
// nil when no monitor here runs under tls: auto.
func processHubCA() *hubCA {
	if gp := activeGitProxy(); gp != nil && gp.certs != nil {
		return gp.certs.ca
	}
	if kg := activeKubeGuard(); kg != nil && kg.certs != nil {
		return kg.certs.ca
	}
	hubCAMu.Lock()
	defer hubCAMu.Unlock()
	return hubCAs[controlPlaneDir()]
}

// kickHubCA asks every refresher in this process to re-read its CAs now: the
// cluster bus said a rotation step was taken.
func kickHubCA() {
	hubCAMu.Lock()
	defer hubCAMu.Unlock()
	for _, c := range hubCAs {
		select {
		case c.kick <- struct{}{}:
		default:
		}
	}
}

// onBusHubCA is the bus subscription.
func onBusHubCA(hubcluster.Event) { kickHubCA() }

// hubCAOptions is how this hub process issues: under its own name, with every
// certificate it mints or issues, and every rotation step it takes, written to
// the control plane's audit trail. A CA minted twice for one control plane is
// the row an operator needs, because every sandbox trusts the first.
func hubCAOptions(db *statedb.DB) hubca.Options {
	actor := monitorCertActor()
	return hubca.Options{Actor: actor, Audit: func(i hubca.Issued) {
		var action auditaction.Action = auditaction.ActionHubCALeafIssued
		entity := i.Serial
		payload := map[string]any{"serial": i.Serial, "not_after": i.NotAfter.UTC().Format(time.RFC3339)}
		if i.CA {
			action = auditaction.ActionHubCAMinted
			payload["fingerprint"] = i.Fingerprint
			fmt.Fprintf(os.Stderr, "ui: minted the hub CA %s (sha256 %s), valid until %s\n",
				i.Serial, i.Fingerprint, payload["not_after"])
		} else {
			payload["monitor"] = string(i.Monitor)
			payload["names"] = i.Names
			payload["issuer"] = i.Issuer
			payload["reason"] = i.Reason
			if i.Replaced != "" {
				payload["replaced"] = i.Replaced
			}
			hubmetrics.HubCALeavesIssued.Inc(string(i.Monitor), i.Reason)
		}
		appendHubCAAudit(db, actor, action, entity, payload)
	}, Rotation: func(e hubca.RotationEvent) { auditRotationStep(db, actor, e, "dashboard") }}
}

// auditRotationStep writes a rotation step this process took to the trail.
func auditRotationStep(db *statedb.DB, actor string, e hubca.RotationEvent, via string) {
	switch e.Step {
	case hubca.StepStage:
		appendHubCAAudit(db, actor, auditaction.ActionHubCARotationStaged, e.RotationID, e.Payload(via))
	case hubca.StepActivate:
		appendHubCAAudit(db, actor, auditaction.ActionHubCARotationActivated, e.RotationID, e.Payload(via))
	case hubca.StepRetirePrevious:
		appendHubCAAudit(db, actor, auditaction.ActionHubCAPreviousRetired, e.RotationID, e.Payload(via))
	case hubca.StepAbandon:
		appendHubCAAudit(db, actor, auditaction.ActionHubCARotationAbandoned, e.RotationID, e.Payload(via))
	case hubca.StepEmergency:
		appendHubCAAudit(db, actor, auditaction.ActionHubCAEmergencyRotated, e.RotationID, e.Payload(via))
	}
}

// appendHubCAAudit writes one hub_ca row; a write that fails is said on
// stderr and recorded as a gap by the audit layer.
func appendHubCAAudit(db *statedb.DB, actor string, action auditaction.Action, entity string, payload map[string]any) {
	blob, err := json.Marshal(payload)
	if err != nil {
		blob = []byte(`{}`)
	}
	if err := db.AppendAuditEvent(&statedb.AuditEvent{
		Timestamp: time.Now().UTC(), Actor: actor, EventType: string(action),
		EntityType: "hub_ca", EntityID: entity, Payload: string(blob),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "ui: %s for %s not written to the audit trail: %v\n", action, entity, err)
	}
}

// monitorCertActor names this hub process on the rows it issues.
func monitorCertActor() string {
	if n := currentCluster(); n != nil {
		return n.ID()
	}
	host, _ := os.Hostname()
	return fmt.Sprintf("%s/%d", strings.TrimSpace(host), os.Getpid())
}

// processLeads reports whether this process does the work one member does:
// the cluster leader, or a hub with no cluster.
func processLeads() bool {
	n := currentCluster()
	return n == nil || n.IsLeader()
}

// register adds a monitor's certificate to the refresher, starting it with
// the first.
func (c *hubCA) register(mc *monitorCert) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.monitors[mc.srv.Monitor()] = mc
	if c.stop == nil {
		ctx, cancel := context.WithCancel(context.Background())
		c.stop = cancel
		go c.run(ctx)
	}
}

// unregister drops a monitor's certificate, stopping the refresher with the
// last.
func (c *hubCA) unregister(mc *monitorCert) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.monitors[mc.srv.Monitor()] == mc {
		delete(c.monitors, mc.srv.Monitor())
	}
	if len(c.monitors) == 0 && c.stop != nil {
		c.stop()
		c.stop = nil
		// Nothing here serves a leaf or hands out the CAs any more: a rotation
		// has nothing of this member to wait for.
		_ = c.trust.Withdraw(processInstanceID())
	}
}

func (c *hubCA) servers() []*hubca.Server {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*hubca.Server, 0, len(c.monitors))
	for _, m := range hubca.Monitors() {
		if mc := c.monitors[m]; mc != nil {
			out = append(out, mc.srv)
		}
	}
	return out
}

// run refreshes until ctx ends: every monitorCertRefreshInterval, and when
// kicked.
func (c *hubCA) run(ctx context.Context) {
	defer recoverGoroutine("hub CA refresh")
	t := time.NewTicker(monitorCertRefreshInterval)
	defer t.Stop()
	c.tick()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-c.kick:
		}
		c.tick()
	}
}

// tick is one refresh: the CAs, then each monitor's leaf — reissued at once
// by the leader when the active CA changed — then what this member serves,
// on record for the next step to read.
func (c *hubCA) tick() {
	_, err := c.trust.Refresh()
	c.report(err)
	gen := c.trust.State().Generation()
	c.mu.Lock()
	changed := c.lastGen != "" && gen != c.lastGen
	c.lastGen = gen
	c.mu.Unlock()
	leads := processLeads()
	reissued := false
	for _, srv := range c.servers() {
		var (
			issued bool
			serr   error
		)
		if changed && leads {
			issued, serr = srv.Renew()
		} else {
			issued, serr = srv.Refresh()
		}
		reissued = reissued || issued
		c.report(serr)
	}
	if changed {
		hubmetrics.HubCATrustAdoptions.Inc()
		st := c.trust.State()
		fmt.Fprintf(os.Stderr, "ui: the hub CAs changed (%s): new sandboxes trust %s, leaves come from %s\n",
			st.Phase(), strings.Join(shortSerials(st.Serials()), ", "), shortSerial(st.Active.Serial))
		if leads {
			// A monitor no process here runs still has a stored leaf, which a
			// retirement waits on: the leader reissues that too.
			issued, err := hubca.ReissueLeaves(c.store, c.keyring, hubCAOptions(c.db))
			c.report(err)
			reissued = reissued || len(issued) > 0
		}
	}
	if reissued && leads {
		// A member that has not ticked yet learns of the reissued leaf now.
		publishHubCAStep("leaves")
	}
	c.applyEmergencyCut()
	if id := processInstanceID(); id != "" {
		if err := c.trust.Report(id, c.servers()...); err != nil {
			c.report(fmt.Errorf("record what this member serves: %w", err))
		}
		if leads {
			_, _ = c.db.PruneHubCAMembers(time.Now().Add(-hubCAMemberRowTTL))
		}
	}
}

// report says a refresh failure once per distinct message.
func (c *hubCA) report(err error) {
	if err == nil {
		return
	}
	c.mu.Lock()
	same := c.lastErr == err.Error()
	c.lastErr = err.Error()
	c.mu.Unlock()
	if !same {
		fmt.Fprintf(os.Stderr, "ui: the hub CA could not be refreshed: %v\n", err)
	}
}

// applyEmergencyCut ends this process's proxy sessions of the runs a recent
// emergency rotation named, once per rotation, and of any run on record whose
// dispatch was not given the CA that is active now.
//
// Only the latest rotation counts: a later one has moved what "the CA that is
// active now" means, and its runs were never handed the emergency's CA.
func (c *hubCA) applyEmergencyCut() {
	rows, err := c.db.ListHubCARotations(1)
	if err != nil {
		return
	}
	for _, r := range rows {
		if !r.Emergency || r.State != statedb.HubCARotationRetired || time.Since(r.EndedAt) > hubCAEmergencyWindow {
			continue
		}
		c.mu.Lock()
		done := c.cut[r.ID]
		c.cut[r.ID] = true
		c.mu.Unlock()
		if done {
			continue
		}
		runs := map[string]bool{}
		for _, id := range r.CutRuns {
			runs[id] = true
		}
		// A run dispatched between the step and this member's adoption of it
		// was given only the replaced CAs too.
		if live, err := hubca.RunningRuns(c.db); err == nil {
			for _, run := range live {
				if run.ID != "" && run.Breaks(r.ToSerial) {
					runs[run.ID] = true
				}
			}
		}
		ended := endRunProxySessions(runs, "the hub CA was replaced in an emergency (rotation "+r.ID+
			"); this run trusted only the replaced CA")
		names := make([]string, 0, len(runs))
		for id := range runs {
			names = append(names, id)
		}
		sort.Strings(names)
		appendHubCAAudit(c.db, monitorCertActor(), auditaction.ActionHubCASessionsEnded, r.ID, map[string]any{
			"rotation": r.ID, "member": processInstanceID(), "runs": names,
			"git_proxy": ended[hubmetrics.HubCAProxyGit], "kube_guard": ended[hubmetrics.HubCAProxyKube],
			"model_relay": ended[hubmetrics.HubCAProxyRelay],
		})
		if total := ended[hubmetrics.HubCAProxyGit] + ended[hubmetrics.HubCAProxyKube] + ended[hubmetrics.HubCAProxyRelay]; total > 0 {
			fmt.Fprintf(os.Stderr, "ui: ended %d proxy session(s) of %d run(s) that trusted only the hub CA an "+
				"emergency rotation replaced: %s\n", total, len(names), strings.Join(names, ", "))
		}
	}
}

// endRunProxySessions ends this process's git proxy, Kubernetes monitor and
// model relay sessions whose run is in runs, and counts them by proxy.
func endRunProxySessions(runs map[string]bool, reason string) map[string]int {
	out := map[string]int{}
	if len(runs) == 0 {
		return out
	}
	if gp := activeGitProxy(); gp != nil && gp.reg != nil {
		for _, s := range gp.reg.Sessions() {
			if s.RunID != "" && runs[s.RunID] {
				gp.reg.Close(s.ID, reason)
				out[hubmetrics.HubCAProxyGit]++
			}
		}
	}
	if kg := activeKubeGuard(); kg != nil && kg.reg != nil {
		for _, s := range kg.reg.Sessions() {
			if s.RunID != "" && runs[s.RunID] {
				kg.reg.Close(s.ID, reason)
				out[hubmetrics.HubCAProxyKube]++
			}
		}
	}
	if mr := activeModelRelay(); mr != nil && mr.reg != nil {
		for _, s := range mr.reg.Sessions() {
			if s.RunID != "" && runs[s.RunID] {
				if err := mr.reg.Close(s.ID, reason); err == nil {
					out[hubmetrics.HubCAProxyRelay]++
				}
			}
		}
	}
	for proxy, n := range out {
		hubmetrics.HubCASessionsEnded.Add(float64(n), proxy)
	}
	return out
}

// publishHubCAStep tells every member a rotation step was taken: they
// re-read their CAs now rather than at their next tick.
func publishHubCAStep(step string) {
	if n := currentCluster(); n != nil {
		n.Publish(busTopicHubCA, step, map[string]string{"step": step})
	}
}

func shortSerial(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func shortSerials(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = shortSerial(s)
	}
	return out
}

// monitorCert is one monitor's auto-issued certificate as its listener serves
// it.
type monitorCert struct {
	ca  *hubCA
	srv *hubca.Server
}

// startMonitorCertificate settles monitor m's leaf for the names sandboxes
// reach it at — baseURL's host, and the listen address's when it names one —
// and keeps it current until close.
func startMonitorCertificate(m hubca.Monitor, dir, baseURL, listenAddr string) (*monitorCert, error) {
	c, err := openHubCA(dir)
	if err != nil {
		return nil, err
	}
	want, err := hubca.SANsFor(baseURL, listenAddr)
	if err != nil {
		return nil, err
	}
	srv, err := hubca.NewServer(hubca.ServerConfig{
		Monitor: m, Store: c.store, Sealer: c.keyring, Trust: c.trust, Want: want,
		Options: hubCAOptions(c.db),
		Logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "ui: "+format+"\n", args...)
		},
	})
	if err != nil {
		return nil, err
	}
	mc := &monitorCert{ca: c, srv: srv}
	c.register(mc)
	return mc, nil
}

// close stops keeping the certificate current. Nil-safe.
func (mc *monitorCert) close() {
	if mc != nil && mc.ca != nil {
		mc.ca.unregister(mc)
	}
}

// renew is the leader's half: replace the leaf when it is due. Nil-safe.
func (mc *monitorCert) renew() {
	if mc == nil {
		return
	}
	if _, err := mc.srv.Renew(); err != nil {
		fmt.Fprintf(os.Stderr, "ui: the %s's certificate could not be renewed: %v\n", mc.srv.Monitor().Label(), err)
	}
}

// caPEM is what sandboxes are told to trust now: every CA the control plane
// trusts, the active one first. Nil-safe.
func (mc *monitorCert) caPEM() []byte {
	if mc == nil {
		return nil
	}
	return mc.srv.CAPEM()
}

// watchMonitorCertificates renews the monitors' auto-issued leaves for as long
// as this hub leads: one member renews, every member serves the result. A
// leader duty, so two members never race to replace the same leaf on a timer —
// though the store's compare-and-swap would settle them if they did.
func (s *Server) watchMonitorCertificates(ctx context.Context) {
	defer recoverGoroutine("monitor certificate renewal")
	renewMonitorCertificates()
	t := time.NewTicker(monitorCertRenewInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			renewMonitorCertificates()
		}
	}
}

// renewMonitorCertificates renews whichever running monitors issue their own
// certificate.
func renewMonitorCertificates() {
	if gp := activeGitProxy(); gp != nil {
		gp.certs.renew()
	}
	if kg := activeKubeGuard(); kg != nil {
		kg.certs.renew()
	}
}

// SandboxGitCA is what a dispatched workload's git is told to trust: the hub's
// CAs — one, or two while the CA is being rotated — for the proxy's URL and
// nothing else. Nil when the proxy is not running or serves an operator's
// certificate, which the sandbox image trusts or not as before.
func (s *gitProxyService) SandboxGitCA() *executor.GitCA {
	if s == nil || s.certs == nil {
		return nil
	}
	u, err := executor.NormalizeGitCAURL(s.baseURL)
	if err != nil {
		return nil
	}
	return &executor.GitCA{URLs: []string{u}, PEM: s.certs.caPEM()}
}

// applyGitProxyTrust gives spec the hub's CAs for the proxy's URL when the
// running proxy serves a certificate the hub issued (Task 20409): every driver
// then makes the workload's git trust them there and nowhere else. Attached to
// every dispatch rather than only those holding a GitHub grant, because the
// workspace fetch a driver makes at Start may go through the proxy too, and a
// CA certificate costs a sandbox nothing it could misuse; a driver that cannot
// deliver it refuses only the workloads that would talk to the proxy.
func applyGitProxyTrust(spec executor.Spec) executor.Spec {
	if ca := activeGitProxy().SandboxGitCA(); ca != nil {
		spec.GitCA = ca
	}
	return spec
}

// kubeTrust remembers, per run, the hub CAs the kubeconfig the kube guard
// minted for it carries, until the run's dispatch records them
// (labelHubCATrust). An entry a dispatch never collected — it failed before —
// is dropped after kubeTrustTTL.
var kubeTrust = struct {
	sync.Mutex
	m map[string]kubeTrustEntry
}{m: map[string]kubeTrustEntry{}}

type kubeTrustEntry struct {
	serials []string
	at      time.Time
}

const kubeTrustTTL = 10 * time.Minute

func rememberKubeTrust(runID string, serials []string) {
	if runID == "" {
		return
	}
	kubeTrust.Lock()
	defer kubeTrust.Unlock()
	now := time.Now()
	for k, v := range kubeTrust.m {
		if now.Sub(v.at) > kubeTrustTTL {
			delete(kubeTrust.m, k)
		}
	}
	kubeTrust.m[runID] = kubeTrustEntry{serials: append([]string(nil), serials...), at: now}
}

func takeKubeTrust(runID string) ([]string, bool) {
	kubeTrust.Lock()
	defer kubeTrust.Unlock()
	e, ok := kubeTrust.m[runID]
	delete(kubeTrust.m, runID)
	return e.serials, ok
}

// kubeGuardBundle is the bundle a kubeconfig minted now carries, and the
// serials in it: the hub's CAs under tls: auto, nil otherwise (the registry's
// static bundle applies).
func (s *kubeGuardService) kubeGuardBundle() ([]byte, []string) {
	if s == nil || s.certs == nil {
		return nil, nil
	}
	snap := s.certs.srv.Trust().Snapshot()
	return snap.Bundle, snap.Serials
}

// labelHubCATrust records on spec which of the hub's CAs the dispatch was
// told to trust, and on which paths (executor.LabelHubCATrust and
// LabelHubCAUses, Task 20438) — the record a CA rotation reads, from the
// executor session the spec is stored in, to tell which running runs an
// activation would break. Called last among the steps that hand a sandbox the
// hub's CA: the git proxy's trust, the model relay's Node trust, and the
// lease, whose kubeconfig the kube guard minted.
//
// It also hands an agent too old to take two CAs for Node (before protocol
// v25) the active one alone, while a rotation has two: that run then trusts
// only the active CA, and is recorded so.
func labelHubCATrust(spec executor.Spec, ex executor.Executor) executor.Spec {
	labels := make(map[string]string, len(spec.Labels)+2)
	for k, v := range spec.Labels {
		labels[k] = v
	}
	spec.Labels = labels
	runID := labels[executor.LabelRunID]
	kube, kubeUsed := takeKubeTrust(runID)

	c := processHubCA()
	if c == nil && !kubeUsed && spec.GitCA == nil {
		// This member holds none of the hub's CAs: say so, rather than leave
		// the record absent — absent reads as a build from before rotation.
		labels[executor.LabelHubCATrust] = ""
		labels[executor.LabelHubCAUses] = ""
		return spec
	}
	if spec.GitCA != nil && spec.GitCA.Node && spec.GitCA.CertCount() > 1 {
		if v := agentProtocolOf(ex); v > 0 && !remote.SupportsNodeCABundle(v) {
			reduced := spec.GitCA.Clone()
			reduced.PEM = hubca.FirstPEM(reduced.PEM)
			spec.GitCA = reduced
		}
	}

	var trusted []string
	have := false
	var uses []string
	if spec.GitCA != nil {
		trusted, have = hubca.BundleSerials(spec.GitCA.PEM), true
		if len(spec.GitCA.URLs) > 0 {
			uses = append(uses, hubca.UseGitProxy)
		}
		if spec.GitCA.Node {
			uses = append(uses, hubca.UseNode)
		}
	}
	if kubeUsed {
		if have {
			trusted = intersect(trusted, kube)
		} else {
			trusted, have = kube, true
		}
		uses = append(uses, hubca.UseKubeGuard)
	}
	if !have && c != nil {
		// Given none of them, the run would be given what this member hands
		// out now: recorded, so an activation knows it was dispatched since.
		trusted = c.trust.Serials()
	}
	labels[executor.LabelHubCATrust] = hubca.Label(trusted)
	labels[executor.LabelHubCAUses] = strings.Join(uses, ",")
	return spec
}

func intersect(a, b []string) []string {
	in := map[string]bool{}
	for _, s := range b {
		in[s] = true
	}
	var out []string
	for _, s := range a {
		if in[s] {
			out = append(out, s)
		}
	}
	return out
}
