package hubca_test

// Rotating the hub CA online (Task 20438): what sandboxes are told to trust at
// each step, which CA signs, members agreeing before a step, the runs an
// activation would break, and the retired CA's key gone from the file.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/hubca"
	"github.com/blechschmidt/cloop/pkg/kms"
	"github.com/blechschmidt/cloop/pkg/kms/kmstest"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// env is a rotation's environment over the fixture: every member that has
// not left counts as alive, and runs are read from the executor sessions.
func (f *fixture) env(actor string) hubca.Env {
	return hubca.Env{Store: f.store, Sealer: f.keyring, Options: f.opts(actor)}
}

func (f *fixture) trust(t *testing.T, actor string) *hubca.Trust {
	t.Helper()
	tr, err := hubca.OpenTrust(f.store, f.keyring, f.opts(actor))
	if err != nil {
		t.Fatalf("open trust: %v", err)
	}
	return tr
}

func (f *fixture) trustServer(t *testing.T, tr *hubca.Trust, actor string, m hubca.Monitor, want ...string) *hubca.Server {
	t.Helper()
	srv, err := hubca.NewServer(hubca.ServerConfig{Monitor: m, Store: f.store, Sealer: f.keyring, Trust: tr,
		Want: want, Options: f.opts(actor)})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return srv
}

// join records a live hub member; rotates says whether its build advertises
// rotation.
func (f *fixture) join(t *testing.T, id string, rotates bool) {
	t.Helper()
	meta := "{}"
	if rotates {
		meta = `{"` + hubca.EndpointRotation + `":"1"}`
	}
	if err := f.db.JoinHubMember(statedb.HubMemberRow{InstanceID: id, Hostname: "host-" + id, PID: 100,
		Version: "test", Meta: meta}); err != nil {
		t.Fatal(err)
	}
}

// dispatch records a running dispatch the way the hub's supervisor does: its
// executor session, its spec's labels saying what it was told to trust. A nil
// trust records nothing — a build from before rotation.
func (f *fixture) dispatch(t *testing.T, runID string, started time.Time, trust []string, uses ...string) {
	t.Helper()
	labels := map[string]string{executor.LabelRunID: runID}
	if trust != nil {
		labels[executor.LabelHubCATrust] = hubca.Label(trust)
		labels[executor.LabelHubCAUses] = strings.Join(uses, ",")
	}
	spec, err := json.Marshal(executor.Spec{Argv: []string{"claude"}, Labels: labels})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.OpenExecutorSession(statedb.ExecutorSessionRow{ID: "sess_" + runID, ExecutorID: "ex_1",
		HandleID: "h_" + runID, ProjectPath: "/srv/" + runID, TaskID: 1, ClaimToken: "tok_" + runID,
		StartedAt: started, SpecJSON: string(spec)}); err != nil {
		t.Fatal(err)
	}
}

func certs(t *testing.T, bundle []byte) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	rest := bundle
	for {
		var der []byte
		der, rest = firstDER(rest)
		if der == nil {
			return out
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
}

func serialsOf(t *testing.T, bundle []byte) string {
	t.Helper()
	var s []string
	for _, c := range certs(t, bundle) {
		s = append(s, hubca.Serial(c))
	}
	if got := strings.Join(hubca.BundleSerials(bundle), ","); got != strings.Join(s, ",") {
		t.Fatalf("BundleSerials = %s, want %s", got, strings.Join(s, ","))
	}
	return strings.Join(s, ",")
}

func verifies(leaf *x509.Certificate, bundle []byte, name string, at time.Time) error {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(bundle)
	_, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: name, CurrentTime: at})
	return err
}

// TestTheBundleAtEachStep follows one member through a whole rotation and
// checks, after each step, what a sandbox dispatched then is told to trust,
// which CA signs the leaf the monitor serves, and that a sandbox dispatched at
// any earlier step still verifies it while it should.
func TestTheBundleAtEachStep(t *testing.T) {
	f := newFixture(t)
	f.join(t, "hub_a", true)
	tr := f.trust(t, "hub_a")
	srv := f.trustServer(t, tr, "hub_a", hubca.GitProxy, "hub.internal")
	ca1 := tr.State().Active.Serial

	// Steady: one CA, which signs.
	steady := tr.Bundle()
	if got := serialsOf(t, steady); got != ca1 || tr.State().Phase() != hubca.PhaseSteady {
		t.Fatalf("steady bundle %s, phase %s", got, tr.State().Phase())
	}

	// Stage: both CAs, the active one first; the leaf still from CA1.
	staged, err := hubca.Stage(f.env("operator"), hubca.StageRequest{})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	ca2 := staged.CA.Serial
	if changed, err := tr.Refresh(); err != nil || !changed {
		t.Fatalf("a member's refresh did not see the stage: changed=%v err=%v", changed, err)
	}
	during := tr.Bundle()
	if got := serialsOf(t, during); got != ca1+","+ca2 || tr.State().Phase() != hubca.PhaseStaged {
		t.Fatalf("staged bundle %s, phase %s", got, tr.State().Phase())
	}
	if !strings.HasSuffix(string(during), "\n") || bytes.Count(during, []byte("BEGIN CERTIFICATE")) != 2 {
		t.Fatalf("staged bundle is not two PEM blocks: %q", during)
	}
	if issued, err := srv.Renew(); err != nil || issued {
		t.Fatalf("a stage made the leader reissue: issued=%v err=%v", issued, err)
	}
	if err := srv.Current().Cert.CheckSignatureFrom(certs(t, steady)[0]); err != nil {
		t.Fatal("the leaf no longer comes from CA1 while CA2 is only staged")
	}

	// Activate: both still trusted, CA2 first; the leader reissues from CA2.
	if _, err := hubca.Activate(f.env("operator"), hubca.ActivateRequest{}); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if _, err := tr.Refresh(); err != nil {
		t.Fatal(err)
	}
	activated := tr.Bundle()
	if got := serialsOf(t, activated); got != ca2+","+ca1 || tr.State().Phase() != hubca.PhaseActivated {
		t.Fatalf("activated bundle %s, phase %s", got, tr.State().Phase())
	}
	if tr.Authority().Serial() != ca2 {
		t.Fatalf("the member signs with %s after the activation, want %s", tr.Authority().Serial(), ca2)
	}
	if issued, err := srv.Renew(); err != nil || !issued {
		t.Fatalf("the leader did not reissue after the activation: issued=%v err=%v", issued, err)
	}
	leaf := srv.Current().Cert
	now := f.clock.now()
	if err := verifies(leaf, during, "hub.internal", now); err != nil {
		t.Fatalf("a sandbox dispatched during the stage refuses the new leaf: %v", err)
	}
	if err := verifies(leaf, steady, "hub.internal", now); err == nil {
		t.Fatal("a sandbox dispatched before the stage verified a leaf from CA2: it was never given CA2")
	}

	// Retire: CA2 alone.
	if err := tr.Report("hub_a", srv); err != nil {
		t.Fatal(err)
	}
	if _, err := hubca.RetirePrevious(f.env("operator")); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if _, err := tr.Refresh(); err != nil {
		t.Fatal(err)
	}
	if got := serialsOf(t, tr.Bundle()); got != ca2 || tr.State().Phase() != hubca.PhaseSteady {
		t.Fatalf("bundle after retirement %s, phase %s", got, tr.State().Phase())
	}
	if err := verifies(leaf, tr.Bundle(), "hub.internal", now); err != nil {
		t.Fatalf("a sandbox dispatched after the retirement refuses the leaf: %v", err)
	}
	if _, err := f.db.GetHubTLS(statedb.HubCAPrevious); !errors.Is(err, statedb.ErrHubTLSNotFound) {
		t.Fatalf("CA1's row survived retirement: %v", err)
	}
}

// TestAStagedCAIsNameConstrained: the CA a rotation mints permits the names
// the monitors are reached at — every stored leaf's, and those asked for —
// and nothing else, so a certificate it signed for another host fails every
// verifier, including Node, which trusts it for every host.
func TestAStagedCAIsNameConstrained(t *testing.T) {
	f := newFixture(t)
	tr := f.trust(t, "hub_a")
	f.trustServer(t, tr, "hub_a", hubca.GitProxy, "hub.internal", "10.0.0.5")
	f.trustServer(t, tr, "hub_a", hubca.KubeGuard, "kube.internal")

	staged, err := hubca.Stage(f.env("operator"), hubca.StageRequest{Names: []string{"new-hub.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(staged.CA.Names, ","); got != "10.0.0.5,hub.internal,kube.internal,new-hub.example.com" {
		t.Fatalf("the staged CA permits %s", got)
	}
	ca := staged.CA.Cert
	if !ca.PermittedDNSDomainsCritical {
		t.Error("the name constraints are not critical")
	}
	// A leaf signed with the staged CA's key for another host. The test signs
	// it the way an attacker holding the key would.
	key := stagedKey(t, f, staged.CA.Serial)
	for _, tc := range []struct {
		name string
		dns  []string
		ips  []net.IP
		ok   bool
	}{
		{"a permitted name", []string{"hub.internal"}, nil, true},
		{"a name beneath a permitted one", []string{"git.new-hub.example.com"}, nil, true},
		{"a permitted address", nil, []net.IP{net.ParseIP("10.0.0.5")}, true},
		{"api.anthropic.com", []string{"api.anthropic.com"}, nil, false},
		{"github.com", []string{"github.com"}, nil, false},
		{"another address", nil, []net.IP{net.ParseIP("10.0.0.6")}, false},
		{"an IPv6 address", nil, []net.IP{net.ParseIP("::1")}, false},
	} {
		leaf := signLeaf(t, ca, key, f.clock.now(), tc.dns, tc.ips)
		pool := x509.NewCertPool()
		pool.AddCert(ca)
		_, err := leaf.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: f.clock.now()})
		if (err == nil) != tc.ok {
			t.Errorf("%s: verify err = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}

	// Without constraints, as an operator may ask.
	if _, err := hubca.Abort(f.env("operator"), "test"); err != nil {
		t.Fatal(err)
	}
	free, err := hubca.Stage(f.env("operator"), hubca.StageRequest{NoNameConstraints: true})
	if err != nil {
		t.Fatal(err)
	}
	if hubca.Constrained(free.CA.Cert) {
		t.Fatal("--no-name-constraints minted a constrained CA")
	}
}

// TestAConstrainedCAIssuesOnlyWhatItPermits: a member reached at a name the
// active CA does not permit is served a leaf without it, and told why, rather
// than a leaf that fails every sandbox's check or none at all.
func TestAConstrainedCAIssuesOnlyWhatItPermits(t *testing.T) {
	f := newFixture(t)
	tr := f.trust(t, "hub_a")
	f.trustServer(t, tr, "hub_a", hubca.GitProxy, "hub.internal")
	if _, err := hubca.Stage(f.env("op"), hubca.StageRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := hubca.Activate(f.env("op"), hubca.ActivateRequest{}); err != nil {
		t.Fatal(err)
	}
	srv := f.trustServer(t, tr, "hub_b", hubca.GitProxy, "hub.internal", "moved.example.com")
	if got := strings.Join(srv.Current().SANs(), ","); got != "hub.internal" {
		t.Fatalf("leaf names %s", got)
	}
	if got := strings.Join(srv.Refused(), ","); got != "moved.example.com" {
		t.Fatalf("Refused = %s", got)
	}
}

// TestMembersAgreeBeforeAStep is the cluster's half: a member that has not
// adopted the stage holds an activation back, one that predates rotation
// holds it back for good, and once every member reports the stage the
// activation goes ahead; the retirement then waits for every member to serve
// the leader's new leaf.
func TestMembersAgreeBeforeAStep(t *testing.T) {
	f := newFixture(t)
	f.join(t, "hub_a", true)
	f.join(t, "hub_b", true)
	a := f.trust(t, "hub_a")
	b := f.trust(t, "hub_b")
	leader := f.trustServer(t, a, "hub_a", hubca.GitProxy, "hub.internal")
	follower := f.trustServer(t, b, "hub_b", hubca.GitProxy, "hub.internal")
	for _, m := range []struct {
		tr  *hubca.Trust
		id  string
		srv *hubca.Server
	}{{a, "hub_a", leader}, {b, "hub_b", follower}} {
		if err := m.tr.Report(m.id, m.srv); err != nil {
			t.Fatal(err)
		}
	}

	staged, err := hubca.Stage(f.env("op"), hubca.StageRequest{})
	if err != nil {
		t.Fatal(err)
	}
	// Member a sees the stage at once; b's refresh has not run yet.
	if _, err := a.Refresh(); err != nil {
		t.Fatal(err)
	}
	if err := a.Report("hub_a", leader); err != nil {
		t.Fatal(err)
	}
	_, err = hubca.Activate(f.env("op"), hubca.ActivateRequest{Force: true})
	var me *hubca.MembersError
	if !errors.As(err, &me) || len(me.Members) != 1 || me.Members[0].ID != "hub_b" ||
		!strings.Contains(me.Error(), "does not yet hand dispatches hub CA "+staged.CA.Serial[:12]) {
		t.Fatalf("activation with a member behind: %v", err)
	}
	st, err := hubca.ReadStatus(f.env("op"))
	if err != nil || st.Ready || !strings.Contains(st.NextStep, "hub_b") {
		t.Fatalf("status with a member behind: ready=%v next=%q err=%v", st.Ready, st.NextStep, err)
	}

	// A member whose build predates rotation: no flag gets past it.
	f.join(t, "hub_old", false)
	_, err = hubca.Activate(f.env("op"), hubca.ActivateRequest{Force: true})
	if !errors.As(err, &me) || !me.Old || !strings.Contains(err.Error(), "predates CA rotation") {
		t.Fatalf("activation beside a member that predates rotation: %v", err)
	}
	if err := f.db.LeaveHubMember("hub_old", time.Now()); err != nil {
		t.Fatal(err)
	}

	// b catches up; the members agree, and the activation goes ahead.
	if _, err := b.Refresh(); err != nil {
		t.Fatal(err)
	}
	if err := b.Report("hub_b", follower); err != nil {
		t.Fatal(err)
	}
	if _, err := hubca.Activate(f.env("op"), hubca.ActivateRequest{}); err != nil {
		t.Fatalf("activation once every member agrees: %v", err)
	}

	// The leader reissues; the follower keeps the CA1 leaf until it re-reads
	// the store, and the retirement waits for it.
	if issued, err := leader.Renew(); err != nil || !issued {
		t.Fatalf("leader renew: %v %v", issued, err)
	}
	_ = a.Report("hub_a", leader)
	if _, err := b.Refresh(); err != nil {
		t.Fatal(err)
	}
	_ = b.Report("hub_b", follower)
	if _, err := hubca.RetirePrevious(f.env("op")); err == nil || !strings.Contains(err.Error(), "hub_b") {
		t.Fatalf("retirement while a member serves the previous CA's leaf: %v", err)
	}
	if issued, err := follower.Refresh(); err != nil || issued {
		t.Fatalf("the follower issued a leaf of its own: issued=%v err=%v", issued, err)
	}
	if follower.Current().Serial != leader.Current().Serial {
		t.Fatal("the follower did not adopt the leader's leaf")
	}
	_ = b.Report("hub_b", follower)
	if _, err := hubca.RetirePrevious(f.env("op")); err != nil {
		t.Fatalf("retirement once every member serves the new leaf: %v", err)
	}
	for _, tr := range []*hubca.Trust{a, b} {
		if _, err := tr.Refresh(); err != nil || tr.State().Phase() != hubca.PhaseSteady {
			t.Fatalf("a member after retirement: phase %s, %v", tr.State().Phase(), err)
		}
	}
}

// TestAFollowerWaitsForTheLeaderThenStopsWaiting: right after an activation a
// follower serves the previous CA's leaf, which every sandbox dispatched
// since the stage trusts; once ActivationGrace passes with no leaf from the
// leader, it issues one itself.
func TestAFollowerWaitsForTheLeaderThenStopsWaiting(t *testing.T) {
	f := newFixture(t)
	tr := f.trust(t, "hub_b")
	srv := f.trustServer(t, tr, "hub_b", hubca.KubeGuard, "kube.internal")
	first := srv.Current().Serial
	if _, err := hubca.Stage(f.env("op"), hubca.StageRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := hubca.Activate(f.env("op"), hubca.ActivateRequest{}); err != nil {
		t.Fatal(err)
	}
	if issued, err := srv.Refresh(); err != nil || issued || srv.Current().Serial != first {
		t.Fatalf("a follower replaced the leaf at once: issued=%v err=%v", issued, err)
	}
	f.clock.advance(hubca.ActivationGrace + time.Minute)
	issued, err := srv.Refresh()
	if err != nil || !issued {
		t.Fatalf("a follower kept the previous CA's leaf past the grace: issued=%v err=%v", issued, err)
	}
	if srv.Current().Cert.CheckSignatureFrom(tr.State().Active.Cert) != nil {
		t.Fatal("the follower's leaf is not from the new CA")
	}
}

// TestAnActivationWaitsForRunsDispatchedBeforeTheStage: a run that was told
// to trust only CA1 holds the activation back, named; so does one whose build
// recorded nothing. A run given CA2 too, or none of the hub's CAs, does not.
// Forced, the activation names the runs it breaks.
func TestAnActivationWaitsForRunsDispatchedBeforeTheStage(t *testing.T) {
	f := newFixture(t)
	tr := f.trust(t, "hub_a")
	f.trustServer(t, tr, "hub_a", hubca.GitProxy, "hub.internal")
	ca1 := tr.State().Active.Serial
	before := f.clock.now().Add(-time.Hour)
	f.dispatch(t, "run_old", before, []string{ca1}, hubca.UseGitProxy)
	f.dispatch(t, "run_unrecorded", before, nil)
	f.dispatch(t, "run_unaffected", before, []string{}) // given no hub CA at all

	staged, err := hubca.Stage(f.env("op"), hubca.StageRequest{})
	if err != nil {
		t.Fatal(err)
	}
	f.dispatch(t, "run_new", f.clock.now(), []string{ca1, staged.CA.Serial}, hubca.UseGitProxy, hubca.UseKubeGuard)

	_, err = hubca.Activate(f.env("op"), hubca.ActivateRequest{})
	var re *hubca.RunsError
	if !errors.As(err, &re) {
		t.Fatalf("activation with older runs running: %v", err)
	}
	var names []string
	for _, r := range re.Runs {
		names = append(names, r.Name())
	}
	if got := strings.Join(names, ","); got != "run_old,run_unrecorded" {
		t.Fatalf("activation blocked by %s, want run_old,run_unrecorded", got)
	}
	if !strings.Contains(err.Error(), "run run_old of /srv/run_old (task 1) on executor ex_1") {
		t.Errorf("the refusal does not name the run: %v", err)
	}
	st, err := hubca.ReadStatus(f.env("op"))
	if err != nil || st.Ready || len(st.Blocking) != 2 || st.Running != 4 {
		t.Fatalf("status: ready=%v blocking=%d running=%d err=%v", st.Ready, len(st.Blocking), st.Running, err)
	}

	res, err := hubca.Activate(f.env("op"), hubca.ActivateRequest{Force: true})
	if err != nil {
		t.Fatalf("forced activation: %v", err)
	}
	if got := strings.Join(res.Rotation.Forced, ","); got != "run_old,run_unrecorded" {
		t.Fatalf("forced past %s", got)
	}
	rot, err := f.db.GetHubCARotation(res.Rotation.ID)
	if err != nil || strings.Join(rot.Forced, ",") != "run_old,run_unrecorded" {
		t.Fatalf("the journal does not name the broken runs: %+v %v", rot, err)
	}
}

// TestRetirementWaitsForTheLeadersLeaf: retiring the previous CA while a
// stored leaf still comes from it would leave the monitors serving a
// certificate no new sandbox trusts.
func TestRetirementWaitsForTheLeadersLeaf(t *testing.T) {
	f := newFixture(t)
	tr := f.trust(t, "hub_a")
	srv := f.trustServer(t, tr, "hub_a", hubca.GitProxy, "hub.internal")
	if _, err := hubca.Stage(f.env("op"), hubca.StageRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := hubca.Activate(f.env("op"), hubca.ActivateRequest{}); err != nil {
		t.Fatal(err)
	}
	// A member serves the git proxy: its leader reissues, the step waits.
	f.join(t, "hub_a", true)
	if err := tr.Report("hub_a", srv); err != nil {
		t.Fatal(err)
	}
	if _, err := hubca.RetirePrevious(f.env("op")); !errors.Is(err, hubca.ErrLeavesBehind) {
		t.Fatalf("retirement with the previous CA's leaf stored: %v", err)
	}
	if _, err := srv.Renew(); err != nil {
		t.Fatal(err)
	}
	if err := tr.Report("hub_a", srv); err != nil {
		t.Fatal(err)
	}
	if _, err := hubca.RetirePrevious(f.env("op")); err != nil {
		t.Fatalf("retirement after the leader reissued: %v", err)
	}
}

// TestRetirementReissuesALeafNobodyServes: a monitor turned off after its leaf
// was issued — or a hub that is down — has no leader to reissue it, so the
// retirement does, rather than wait for ever.
func TestRetirementReissuesALeafNobodyServes(t *testing.T) {
	f := newFixture(t)
	tr := f.trust(t, "hub_a")
	f.trustServer(t, tr, "hub_a", hubca.KubeGuard, "kube.internal")
	if _, err := hubca.Stage(f.env("op"), hubca.StageRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := hubca.Activate(f.env("op"), hubca.ActivateRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := hubca.RetirePrevious(f.env("op")); err != nil {
		t.Fatalf("retirement with no member serving the monitor: %v", err)
	}
	st, err := hubca.ReadStatus(f.env("op"))
	if err != nil || len(st.Leaves) != 1 || st.Leaves[0].Issuer != st.Active.Serial {
		t.Fatalf("the stored leaf after the retirement: %+v %v", st.Leaves, err)
	}
}

// TestTheRetiredCAsKeyIsDestroyedInTheDatabaseFile: the CA's key is sealed in
// the control-plane database, and retirement is what makes a copy of that
// database stop holding it. After a full rotation — through which key rotation
// also rewrapped it — neither of the old CA's envelopes is anywhere in the
// file, and the new CA's is.
func TestTheRetiredCAsKeyIsDestroyedInTheDatabaseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	f := fixtureOn(t, db, passphrase)
	tr := f.trust(t, "hub_a")
	srv := f.trustServer(t, tr, "hub_a", hubca.GitProxy, "hub.internal")
	first, err := db.GetHubTLS(statedb.HubCAActive)
	if err != nil {
		t.Fatal(err)
	}
	// A key rotation rewraps CA1: the row it frees carries the first envelope.
	ks, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	rot, err := secretbroker.NewRotator(f.keyring, ks, f.store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.keyring.AddKey("test"); err != nil {
		t.Fatal(err)
	}
	if _, err := rot.Rotate(t.Context(), secretbroker.RotateOptions{Actor: "test"}); err != nil {
		t.Fatal(err)
	}
	rewrapped, err := db.GetHubTLS(statedb.HubCAActive)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(rewrapped.WrappedDEK, first.WrappedDEK) {
		t.Fatal("the key rotation did not rewrap the CA")
	}

	if _, err := hubca.Stage(f.env("op"), hubca.StageRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := hubca.Activate(f.env("op"), hubca.ActivateRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Renew(); err != nil {
		t.Fatal(err)
	}
	if _, err := hubca.RetirePrevious(f.env("op")); err != nil {
		t.Fatal(err)
	}
	live, err := db.GetHubTLS(statedb.HubCAActive)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for what, b := range map[string][]byte{
		"CA1's first sealed key": first.KeySealed, "CA1's first wrapped data key": first.WrappedDEK,
		"CA1's rewrapped sealed key": rewrapped.KeySealed, "CA1's rewrapped data key": rewrapped.WrappedDEK,
	} {
		if bytes.Contains(data, b) {
			t.Errorf("%s is still in the database file after retirement", what)
		}
	}
	if !bytes.Contains(data, live.KeySealed) {
		t.Error("CA2's sealed key is not in the file: the scan is not reading what it should")
	}
}

// TestKeyRotationRewrapsTheStagedCA: a staged CA is sealed exactly as the
// active one, so `cloop hub key rotate` carries it onto the new KEK, and
// retirement of the old KEK waits for it.
func TestKeyRotationRewrapsTheStagedCA(t *testing.T) {
	f := newFixture(t)
	tr := f.trust(t, "hub_a")
	f.trustServer(t, tr, "hub_a", hubca.GitProxy, "hub.internal")
	if _, err := hubca.Stage(f.env("op"), hubca.StageRequest{}); err != nil {
		t.Fatal(err)
	}
	oldKey := f.keyring.PrimaryID()
	ks, err := secretstore.New(f.db)
	if err != nil {
		t.Fatal(err)
	}
	rot, err := secretbroker.NewRotator(f.keyring, ks, f.store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.keyring.AddKey("test"); err != nil {
		t.Fatal(err)
	}
	if err := rot.RetireKey(oldKey); err == nil {
		t.Fatal("retired a KEK that still seals the staged CA")
	}
	if _, err := rot.Rotate(t.Context(), secretbroker.RotateOptions{Actor: "test"}); err != nil {
		t.Fatal(err)
	}
	counts, err := f.store.CountSealedByKey()
	if err != nil {
		t.Fatal(err)
	}
	if counts[oldKey] != 0 || counts[f.keyring.PrimaryID()] != 3 {
		t.Fatalf("after rotation the hub_tls keys are sealed %v (old %s)", counts, oldKey)
	}
	if err := rot.RetireKey(oldKey); err != nil {
		t.Fatal(err)
	}
	// The staged CA, rewrapped, still opens when it is activated.
	if _, err := hubca.Activate(f.env("op"), hubca.ActivateRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Refresh(); err != nil {
		t.Fatalf("the rewrapped staged CA does not open once active: %v", err)
	}
}

// TestAStagedCAIsHeldByTheKMSWhenTheStoreIs: with secrets.kms the staged CA's
// key is sealed under the KMS-held KEK, like every other key, so the database
// and CLOOP_SECRET_KEY without the KMS do not open it.
func TestAStagedCAIsHeldByTheKMSWhenTheStoreIs(t *testing.T) {
	t.Cleanup(secretbroker.ForgetOpenedKeys)
	plugin := kmstest.StartPlugin(t)
	prov, err := kms.Open(config.KMSConfig{Provider: config.KMSProviderKMSv2,
		KMSv2: config.KMSv2Config{Endpoint: plugin.Endpoint()}})
	if err != nil {
		t.Fatal(err)
	}
	defer prov.Close()
	f := newFixture(t)
	ks, err := secretstore.New(f.db)
	if err != nil {
		t.Fatal(err)
	}
	// The fixture's passphrase keyring minted the first CA; the store then
	// moves onto the KMS, as `cloop hub key rotate --retire-previous` would
	// after a change of root.
	tr := f.trust(t, "hub_a")
	f.trustServer(t, tr, "hub_a", hubca.GitProxy, "hub.internal")
	kr, err := secretbroker.OpenKeyring(ks, secretbroker.WithKeyringRootSet(secretbroker.KMSRoot(prov),
		secretbroker.PassphraseRoot(passphrase)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kr.AddKey("test"); err != nil {
		t.Fatalf("mint a KMS-held key: %v", err)
	}
	env := hubca.Env{Store: f.store, Sealer: kr, Options: f.opts("op")}
	staged, err := hubca.Stage(env, hubca.StageRequest{})
	if err != nil {
		t.Fatal(err)
	}
	row, err := f.db.GetHubTLS(statedb.HubCANext)
	if err != nil {
		t.Fatal(err)
	}
	keks, err := f.db.ListKEKs()
	if err != nil {
		t.Fatal(err)
	}
	wrap := ""
	for _, k := range keks {
		if k.ID == row.KeyID {
			wrap = k.Wrap
		}
	}
	if wrap != "kms" {
		t.Fatalf("the staged CA %s is sealed under %s, wrapped %q; want a KMS-held key", staged.CA.Serial, row.KeyID, wrap)
	}
	// The database and the passphrase, without the KMS, cannot open it.
	secretbroker.ForgetOpenedKeys()
	ro, err := secretbroker.OpenKeyring(ks, secretbroker.WithKeyringPassphrase(passphrase), secretbroker.WithoutKeyCreation())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hubca.Activate(hubca.Env{Store: f.store, Sealer: ro, Options: f.opts("op")}, hubca.ActivateRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := hubca.OpenAuthority(f.store, ro, f.opts("thief")); err == nil {
		t.Fatal("the passphrase alone opened a KMS-held CA key")
	}
	if _, err := hubca.OpenAuthority(f.store, kr, f.opts("hub")); err != nil {
		t.Fatalf("the KMS-held keyring does not open the CA it sealed: %v", err)
	}
}

// TestAnEmergencyReplacesEveryCAAndCutsTheRunsThatTrustThem: --now, from the
// middle of an ordinary rotation, abandons the staged CA (its key sits in the
// same database), mints a fresh one, reissues every leaf from it, retires the
// old CA and names every run that trusted only the replaced ones.
func TestAnEmergencyReplacesEveryCAAndCutsTheRunsThatTrustThem(t *testing.T) {
	f := newFixture(t)
	f.join(t, "hub_a", true)
	tr := f.trust(t, "hub_a")
	gp := f.trustServer(t, tr, "hub_a", hubca.GitProxy, "hub.internal")
	kg := f.trustServer(t, tr, "hub_a", hubca.KubeGuard, "kube.internal")
	ca1 := tr.State().Active.Serial
	staged, err := hubca.Stage(f.env("op"), hubca.StageRequest{})
	if err != nil {
		t.Fatal(err)
	}
	f.dispatch(t, "run_before", f.clock.now().Add(-time.Hour), []string{ca1}, hubca.UseGitProxy)
	f.dispatch(t, "run_during", f.clock.now(), []string{ca1, staged.CA.Serial}, hubca.UseKubeGuard)
	f.dispatch(t, "run_free", f.clock.now(), []string{})

	res, err := hubca.Emergency(f.env("incident"), hubca.StageRequest{})
	if err != nil {
		t.Fatalf("emergency: %v", err)
	}
	if strings.Join(res.Replaced, ",") != ca1+","+staged.CA.Serial {
		t.Fatalf("replaced %v", res.Replaced)
	}
	var cut []string
	for _, r := range res.Cut {
		cut = append(cut, r.Name())
	}
	if got := strings.Join(cut, ","); got != "run_before,run_during" {
		t.Fatalf("cut %s, want run_before,run_during", got)
	}
	if res.Rotation.State != statedb.HubCARotationRetired || !res.Rotation.Emergency ||
		strings.Join(res.Rotation.CutRuns, ",") != "run_before,run_during" {
		t.Fatalf("journal: %+v", res.Rotation)
	}
	st, err := hubca.ReadState(f.store)
	if err != nil || st.Phase() != hubca.PhaseSteady || st.Active.Serial != res.CA.Serial {
		t.Fatalf("after the emergency: %+v %v", st, err)
	}
	if len(res.Leaves) != 2 {
		t.Fatalf("reissued %d leaves, want both monitors'", len(res.Leaves))
	}
	// Every member serves the new leaves at its next refresh, and only a
	// sandbox given the new CA verifies them.
	for _, srv := range []*hubca.Server{gp, kg} {
		if _, err := srv.Refresh(); err != nil {
			t.Fatal(err)
		}
		leaf := srv.Current().Cert
		if leaf.CheckSignatureFrom(res.CA.Cert) != nil {
			t.Fatalf("the %s serves a leaf from a replaced CA", srv.Monitor().Label())
		}
		if err := verifies(leaf, staged.CA.PEM, leaf.DNSNames[0], f.clock.now()); err == nil {
			t.Fatal("a sandbox given only the abandoned staged CA verified the emergency's leaf")
		}
	}
	// The abandoned rotation is on the record too.
	hist, _ := f.db.ListHubCARotations(10)
	var states []string
	for _, h := range hist {
		states = append(states, h.State)
	}
	if !strings.Contains(strings.Join(states, ","), statedb.HubCARotationAbandoned) {
		t.Fatalf("history %v does not record the abandoned stage", states)
	}
}

// TestAbortDestroysTheStagedCA: an operator who staged by mistake takes it
// back; nothing that trusted it breaks, since every such dispatch trusts the
// active CA too.
func TestAbortDestroysTheStagedCA(t *testing.T) {
	f := newFixture(t)
	tr := f.trust(t, "hub_a")
	f.trustServer(t, tr, "hub_a", hubca.GitProxy, "hub.internal")
	staged, err := hubca.Stage(f.env("op"), hubca.StageRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hubca.Stage(f.env("op"), hubca.StageRequest{}); !errors.Is(err, hubca.ErrWrongPhase) {
		t.Fatalf("a second stage: %v", err)
	}
	rot, err := hubca.Abort(f.env("op"), "staged by mistake")
	if err != nil || rot.State != statedb.HubCARotationAbandoned || rot.ToSerial != staged.CA.Serial {
		t.Fatalf("abort: %+v %v", rot, err)
	}
	if _, err := tr.Refresh(); err != nil || tr.State().Phase() != hubca.PhaseSteady {
		t.Fatalf("after abort: %s %v", tr.State().Phase(), err)
	}
	if _, err := hubca.Activate(f.env("op"), hubca.ActivateRequest{}); !errors.Is(err, hubca.ErrWrongPhase) {
		t.Fatalf("activating after an abort: %v", err)
	}
}

// TestNothingToRotateBeforeTheFirstCA: a hub that never ran a monitor under
// tls: auto has no CA, and says so rather than minting one to rotate.
func TestNothingToRotateBeforeTheFirstCA(t *testing.T) {
	f := newFixture(t)
	if _, err := hubca.Stage(f.env("op"), hubca.StageRequest{}); !errors.Is(err, hubca.ErrNoCA) {
		t.Fatalf("stage with no CA: %v", err)
	}
	st, err := hubca.ReadStatus(f.env("op"))
	if err != nil || st.Phase != hubca.PhaseNone {
		t.Fatalf("status with no CA: %+v %v", st, err)
	}
	if rows, _ := f.db.ListHubTLS(); len(rows) != 0 {
		t.Fatalf("a status minted something: %d rows", len(rows))
	}
}

// stagedKey opens the staged CA's key the way the hub does, for a test that
// signs with it as an attacker who held it would.
func stagedKey(t *testing.T, f *fixture, serial string) *ecdsa.PrivateKey {
	t.Helper()
	k, err := hubca.OpenStagedKeyForTest(f.store, f.keyring, serial)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func signLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, at time.Time, dns []string, ips []net.IP) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: dns, IPAddresses: ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// firstDER returns the first PEM block's bytes and the rest.
func firstDER(b []byte) ([]byte, []byte) {
	block, rest := pem.Decode(b)
	if block == nil {
		return nil, b
	}
	return block.Bytes, rest
}
