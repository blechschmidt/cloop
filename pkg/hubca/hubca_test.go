package hubca_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/hometest"
	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/hubca"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func TestMain(m *testing.M) { os.Exit(hometest.Isolate(m)) }

const passphrase = "hubca-test-passphrase"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type fixture struct {
	db      *statedb.DB
	store   *hubca.Store
	keyring *secretbroker.Keyring
	clock   *clock
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db := statedbtest.Open(t)
	return fixtureOn(t, db, passphrase)
}

func fixtureOn(t *testing.T, db *statedb.DB, pass string) *fixture {
	t.Helper()
	ks, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	kr, err := secretbroker.OpenKeyring(ks, secretbroker.WithKeyringPassphrase(pass))
	if err != nil {
		t.Fatalf("open keyring: %v", err)
	}
	st, err := hubca.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{db: db, store: st, keyring: kr,
		clock: &clock{t: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)}}
}

func (f *fixture) opts(actor string) hubca.Options {
	return hubca.Options{Now: f.clock.now, Actor: actor}
}

func (f *fixture) authority(t *testing.T) *hubca.Authority {
	t.Helper()
	ca, err := hubca.OpenAuthority(f.store, f.keyring, f.opts("member-a"))
	if err != nil {
		t.Fatalf("open authority: %v", err)
	}
	return ca
}

func (f *fixture) server(t *testing.T, ca *hubca.Authority, m hubca.Monitor, want ...string) *hubca.Server {
	t.Helper()
	srv, err := hubca.NewServer(hubca.ServerConfig{
		Monitor: m, Store: f.store, Sealer: f.keyring, Authority: ca, Want: want, Options: f.opts("member-a"),
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return srv
}

func poolOf(t *testing.T, pemBytes []byte) *x509.CertPool {
	t.Helper()
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(pemBytes) {
		t.Fatal("CA PEM does not parse")
	}
	return p
}

// TestOpeningTheCAAdoptsTheStoredOne: the CA is the trust every sandbox
// holds, so a second open — another member, a restart — must get the same one,
// and opening never replaces it: only a rotation does (Task 20438), after
// which an open adopts the CA the rotation made active.
func TestOpeningTheCAAdoptsTheStoredOne(t *testing.T) {
	f := newFixture(t)
	first := f.authority(t)
	second := f.authority(t)
	if first.Serial() != second.Serial() {
		t.Fatalf("a second open minted another CA: %s then %s", first.Serial(), second.Serial())
	}
	defer func() {
		env := hubca.Env{Store: f.store, Sealer: f.keyring, Options: f.opts("operator")}
		staged, err := hubca.Stage(env, hubca.StageRequest{NoNameConstraints: true})
		if err != nil {
			t.Fatal(err)
		}
		if again := f.authority(t); again.Serial() != first.Serial() {
			t.Fatalf("an open after a stage adopted %s, want the still-active %s", again.Serial(), first.Serial())
		}
		if _, err := hubca.Activate(env, hubca.ActivateRequest{}); err != nil {
			t.Fatal(err)
		}
		if again := f.authority(t); again.Serial() != staged.CA.Serial {
			t.Fatalf("an open after the activation adopted %s, want the activated %s", again.Serial(), staged.CA.Serial)
		}
	}()
	if !first.Certificate().IsCA || first.Certificate().MaxPathLen != 0 || !first.Certificate().MaxPathLenZero {
		t.Errorf("the CA can sign subordinate CAs: IsCA=%v MaxPathLen=%d", first.Certificate().IsCA,
			first.Certificate().MaxPathLen)
	}
	if left := first.Certificate().NotAfter.Sub(f.clock.now()); left < 9*365*24*time.Hour {
		t.Errorf("the CA lives %s; a short-lived CA is one every sandbox stops trusting at once", left)
	}
}

// TestConcurrentMembersAgreeOnOneCA: two hub processes starting together each
// find no CA. The one whose insert loses must adopt the winner's.
func TestConcurrentMembersAgreeOnOneCA(t *testing.T) {
	f := newFixture(t)
	const n = 6
	serials := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ca, err := hubca.OpenAuthority(f.store, f.keyring, f.opts("member"))
			if err != nil {
				t.Errorf("open authority %d: %v", i, err)
				return
			}
			serials[i] = ca.Serial()
		}(i)
	}
	wg.Wait()
	for _, s := range serials[1:] {
		if s != serials[0] {
			t.Fatalf("members disagree on the CA: %v", serials)
		}
	}
}

// TestThePrivateKeysAreSealed: the hub_tls rows hold envelopes, never a key.
func TestThePrivateKeysAreSealed(t *testing.T) {
	f := newFixture(t)
	ca := f.authority(t)
	f.server(t, ca, hubca.GitProxy, "hub.internal")
	rows, err := f.db.ListHubTLS()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("want the CA and one leaf, got %d rows", len(rows))
	}
	for _, r := range rows {
		for _, field := range [][]byte{[]byte(r.CertPEM), r.KeySealed, r.WrappedDEK} {
			if bytes.Contains(field, []byte("PRIVATE KEY")) {
				t.Errorf("row %s holds a PEM private key", r.ID)
			}
		}
		if r.KeyID == "" || len(r.KeySealed) == 0 {
			t.Errorf("row %s has no sealed key", r.ID)
		}
	}
	// And another passphrase cannot open them: the keyring refuses before
	// any row is read.
	ks, err := secretstore.New(f.db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secretbroker.OpenKeyring(ks, secretbroker.WithKeyringPassphrase("a-different-passphrase")); err == nil {
		t.Fatal("a keyring opened under the wrong passphrase")
	}
}

// TestNoKeyMeansNoCA: tls: auto needs CLOOP_SECRET_KEY, and says so.
func TestNoKeyMeansNoCA(t *testing.T) {
	db := statedbtest.Open(t)
	ks, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(secretbroker.EnvPassphraseKey, "")
	_, err = secretbroker.OpenKeyring(ks)
	if err == nil {
		t.Fatal("a keyring opened with no passphrase")
	}
	if !strings.Contains(err.Error(), "CLOOP_SECRET_KEY") {
		t.Errorf("error does not name the variable: %v", err)
	}
}

// TestASealedKeyMovedToAnotherRowDoesNotOpen: the envelope is bound to its
// row and serial, so copying the CA's onto the leaf's row cannot make the
// listener serve with the CA's key, nor the reverse.
func TestASealedKeyMovedToAnotherRowDoesNotOpen(t *testing.T) {
	f := newFixture(t)
	ca := f.authority(t)
	f.server(t, ca, hubca.GitProxy, "hub.internal")
	caRow, err := f.db.GetHubTLS("ca")
	if err != nil {
		t.Fatal(err)
	}
	leafRow, err := f.db.GetHubTLS("leaf:git_proxy")
	if err != nil {
		t.Fatal(err)
	}
	moved := caRow
	moved.KeyID, moved.WrappedDEK, moved.KeySealed = leafRow.KeyID, leafRow.WrappedDEK, leafRow.KeySealed
	if ok, err := f.db.ReplaceHubTLS(moved, caRow.Serial); err != nil || !ok {
		t.Fatalf("plant: ok=%v err=%v", ok, err)
	}
	if _, err := hubca.OpenAuthority(f.store, f.keyring, f.opts("x")); err == nil {
		t.Fatal("the CA row opened with the leaf's sealed key")
	}
}

func TestSANsFor(t *testing.T) {
	cases := []struct {
		base, listen string
		want         string
	}{
		{"https://hub.internal:8443", "0.0.0.0:8443", "hub.internal"},
		{"https://Hub.Example.COM:8443", ":8443", "hub.example.com"},
		{"https://hub.internal:8443", "10.0.0.5:8443", "10.0.0.5,hub.internal"},
		{"https://127.0.0.1:40123", "", "127.0.0.1"},
		{"https://[::1]:8443", "[::]:8443", "::1"},
		{"https://hub.internal", "hub.internal:8443", "hub.internal"},
	}
	for _, c := range cases {
		got, err := hubca.SANsFor(c.base, c.listen)
		if err != nil {
			t.Errorf("SANsFor(%q, %q): %v", c.base, c.listen, err)
			continue
		}
		if strings.Join(got, ",") != c.want {
			t.Errorf("SANsFor(%q, %q) = %v, want %s", c.base, c.listen, got, c.want)
		}
	}
	if _, err := hubca.NormalizeSANs([]string{"*.example.com"}); err == nil {
		t.Error("a wildcard name was accepted")
	}
}

// TestTheLeafVerifiesForItsNamesOnly: a client trusting the CA accepts the
// leaf for the advertised host and refuses it for any other.
func TestTheLeafVerifiesForItsNamesOnly(t *testing.T) {
	f := newFixture(t)
	ca := f.authority(t)
	srv := f.server(t, ca, hubca.GitProxy, "hub.internal", "127.0.0.1")
	leaf := srv.Current().Cert
	opts := x509.VerifyOptions{Roots: poolOf(t, ca.CertPEM()), CurrentTime: f.clock.now(), DNSName: "hub.internal"}
	if _, err := leaf.Verify(opts); err != nil {
		t.Fatalf("the leaf does not verify for its own name: %v", err)
	}
	opts.DNSName = "github.com"
	if _, err := leaf.Verify(opts); err == nil {
		t.Fatal("the leaf verified for a name it does not carry")
	}
	if leaf.IsCA {
		t.Error("the leaf is a CA")
	}
	if left := leaf.NotAfter.Sub(f.clock.now()); left > hubca.LeafLifetime || left < hubca.LeafLifetime-time.Minute {
		t.Errorf("the leaf lives %s, want %s", left, hubca.LeafLifetime)
	}
}

// TestRenewalOverlapsAndAMemberPicksItUp is the rotation property: the leader
// replaces the leaf with two days left; a second member's refresh serves the
// new one; and a client trusting the CA accepts both, so nothing a running
// sandbox holds is invalidated by the swap.
func TestRenewalOverlapsAndAMemberPicksItUp(t *testing.T) {
	f := newFixture(t)
	ca := f.authority(t)
	leader := f.server(t, ca, hubca.GitProxy, "hub.internal")
	follower, err := hubca.NewServer(hubca.ServerConfig{
		Monitor: hubca.GitProxy, Store: f.store, Sealer: f.keyring, Authority: ca,
		Want: []string{"hub.internal"}, Options: f.opts("member-b"),
	})
	if err != nil {
		t.Fatal(err)
	}
	first := leader.Current()
	if follower.Current().Serial != first.Serial {
		t.Fatal("a second member started with its own leaf instead of the stored one")
	}

	// A day in: nothing to do.
	f.clock.advance(23 * time.Hour)
	if issued, err := leader.Renew(); err != nil || issued {
		t.Fatalf("renewed with %s left: issued=%v err=%v", first.Cert.NotAfter.Sub(f.clock.now()), issued, err)
	}
	// Past the renewal point: the leader replaces it.
	f.clock.advance(2 * time.Hour)
	issued, err := leader.Renew()
	if err != nil || !issued {
		t.Fatalf("no renewal with %s left: issued=%v err=%v", first.Cert.NotAfter.Sub(f.clock.now()), issued, err)
	}
	second := leader.Current()
	if second.Serial == first.Serial {
		t.Fatal("renewal kept the same certificate")
	}
	// The follower is still serving the first leaf until it refreshes, and
	// its refresh does not issue a third: it adopts the leader's.
	if follower.Current().Serial != first.Serial {
		t.Fatal("the follower changed leaf without refreshing")
	}
	if issued, err := follower.Refresh(); err != nil || issued {
		t.Fatalf("follower refresh: issued=%v err=%v", issued, err)
	}
	if follower.Current().Serial != second.Serial {
		t.Fatal("the follower did not adopt the renewed leaf")
	}
	// Both leaves verify against the CA right now: the overlap a push in
	// flight relies on.
	roots := poolOf(t, ca.CertPEM())
	for _, l := range []*hubca.Leaf{first, second} {
		if _, err := l.Cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: f.clock.now(), DNSName: "hub.internal"}); err != nil {
			t.Errorf("leaf %s does not verify during the overlap: %v", l.Serial, err)
		}
	}
}

// TestAFollowerRenewsOnlyInAnEmergency: a member that is not the leader
// replaces a leaf itself only when it is about to lapse.
func TestAFollowerRenewsOnlyInAnEmergency(t *testing.T) {
	f := newFixture(t)
	ca := f.authority(t)
	srv := f.server(t, ca, hubca.KubeGuard, "hub.internal")
	first := srv.Current().Serial
	f.clock.advance(hubca.LeafLifetime - hubca.EmergencyWithin - time.Hour)
	if issued, err := srv.Refresh(); err != nil || issued {
		t.Fatalf("follower renewed with hours to spare: issued=%v err=%v", issued, err)
	}
	f.clock.advance(90 * time.Minute)
	issued, err := srv.Refresh()
	if err != nil || !issued || srv.Current().Serial == first {
		t.Fatalf("follower did not renew a leaf about to lapse: issued=%v err=%v", issued, err)
	}
}

// TestAMemberWithAnotherNameKeepsTheFirstMembersName: names are merged, so two
// members cannot take turns issuing a leaf that leaves the other's out.
func TestAMemberWithAnotherNameKeepsTheFirstMembersName(t *testing.T) {
	f := newFixture(t)
	ca := f.authority(t)
	a := f.server(t, ca, hubca.GitProxy, "hub-a.internal")
	b, err := hubca.NewServer(hubca.ServerConfig{
		Monitor: hubca.GitProxy, Store: f.store, Sealer: f.keyring, Authority: ca,
		Want: []string{"hub-b.internal"}, Options: f.opts("member-b"),
	})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(b.Current().SANs(), ",")
	if got != "hub-a.internal,hub-b.internal" {
		t.Fatalf("second member's leaf names %s", got)
	}
	if issued, err := a.Refresh(); err != nil || issued {
		t.Fatalf("first member re-issued over a leaf that covers it: issued=%v err=%v", issued, err)
	}
	if !hubca.Covers(a.Current().Cert, []string{"hub-a.internal"}) {
		t.Fatal("first member serves a leaf without its name")
	}
}

// TestConcurrentRenewalsLeaveOneLeaf: two members renewing at the same moment
// store one leaf, and both end up serving it.
func TestConcurrentRenewalsLeaveOneLeaf(t *testing.T) {
	f := newFixture(t)
	ca := f.authority(t)
	var servers []*hubca.Server
	for i := 0; i < 4; i++ {
		servers = append(servers, f.server(t, ca, hubca.GitProxy, "hub.internal"))
	}
	f.clock.advance(hubca.LeafLifetime - hubca.RenewWithin + time.Minute)
	var wg sync.WaitGroup
	for _, s := range servers {
		wg.Add(1)
		go func(s *hubca.Server) {
			defer wg.Done()
			if _, err := s.Renew(); err != nil {
				t.Errorf("renew: %v", err)
			}
		}(s)
	}
	wg.Wait()
	row, err := f.db.GetHubTLS("leaf:git_proxy")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range servers {
		if _, err := s.Refresh(); err != nil {
			t.Fatal(err)
		}
		if s.Current().Serial != row.Serial {
			t.Errorf("a member serves %s, the store holds %s", s.Current().Serial, row.Serial)
		}
	}
}

// TestAHandshakeAcrossARenewal drives real TLS: a connection opened before the
// leaf is replaced keeps working, and a new one verifies the new leaf against
// the same CA — what a sandbox's git sees when the leader renews mid-push.
func TestAHandshakeAcrossARenewal(t *testing.T) {
	f := newFixture(t)
	// Real time here, because the TLS stack verifies against the wall clock:
	// the first leaf is issued 25 hours ago, so it is due for renewal now and
	// both it and its successor are valid at this moment.
	f.clock = &clock{t: time.Now().UTC().Add(-25 * time.Hour)}
	ca := f.authority(t)
	srv := f.server(t, ca, hubca.GitProxy, "127.0.0.1")
	tlsCfg, err := srv.TLSConfig("1.2")
	if err != nil {
		t.Fatal(err)
	}
	// The production shape — tls.NewListener over the config, no static
	// Certificates — rather than httptest's StartTLS, which installs a
	// certificate of its own that a connection without SNI would be handed.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = hs.Serve(tls.NewListener(ln, tlsCfg)) }()
	defer hs.Close()
	ts := struct{ URL string }{URL: "https://" + ln.Addr().String()}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: poolOf(t, ca.CertPEM())}}}
	get := func() string {
		t.Helper()
		resp, err := client.Get(ts.URL)
		if err != nil {
			t.Fatalf("GET through the leaf: %v", err)
		}
		// Read to the end, or the transport will not reuse the connection.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.TLS.PeerCertificates[0].SerialNumber.Text(16)
	}
	before := get()

	f.clock.advance(25 * time.Hour)
	if issued, err := srv.Renew(); err != nil || !issued {
		t.Fatalf("renew: issued=%v err=%v", issued, err)
	}
	// The kept-alive connection still answers.
	if before2 := get(); before2 != before {
		t.Fatalf("the open connection changed certificate: %s then %s", before, before2)
	}
	// A fresh connection gets the new leaf, trusted by the same CA.
	client.CloseIdleConnections()
	after := get()
	if after == before {
		t.Fatal("a new connection was still handed the replaced leaf")
	}
	// And a client trusting only the system roots refuses it.
	plain := &http.Client{Transport: &http.Transport{}}
	if resp, err := plain.Get(ts.URL); err == nil {
		resp.Body.Close()
		t.Fatal("a client without the hub CA accepted the leaf")
	}
}

// TestKeyRotationRewrapsTheCA: `cloop hub key rotate` must carry the CA and
// leaf keys onto the new KEK, and retirement must refuse while they are not.
func TestKeyRotationRewrapsTheCA(t *testing.T) {
	f := newFixture(t)
	ca := f.authority(t)
	f.server(t, ca, hubca.GitProxy, "hub.internal")
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
		t.Fatalf("add key: %v", err)
	}
	if err := rot.RetireKey(oldKey); err == nil {
		t.Fatal("retired a KEK that still seals the hub CA")
	}
	if _, err := rot.Rotate(context.Background(), secretbroker.RotateOptions{Actor: "test"}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	counts, err := f.store.CountSealedByKey()
	if err != nil {
		t.Fatal(err)
	}
	if counts[oldKey] != 0 || counts[f.keyring.PrimaryID()] != 2 {
		t.Fatalf("after rotation the keys are sealed %v (old %s)", counts, oldKey)
	}
	if err := rot.RetireKey(oldKey); err != nil {
		t.Fatalf("retire after rotation: %v", err)
	}
	// The CA still opens, and still signs.
	again, err := hubca.OpenAuthority(f.store, f.keyring, f.opts("x"))
	if err != nil {
		t.Fatalf("the CA does not open after rotation: %v", err)
	}
	if again.Serial() != ca.Serial() {
		t.Fatal("rotation replaced the CA")
	}
	f.clock.advance(hubca.LeafLifetime)
	if _, err := hubca.NewServer(hubca.ServerConfig{Monitor: hubca.GitProxy, Store: f.store, Sealer: f.keyring,
		Authority: again, Want: []string{"hub.internal"}, Options: f.opts("x")}); err != nil {
		t.Fatalf("the rotated CA cannot issue: %v", err)
	}
}
