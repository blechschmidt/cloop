package ui

// hubtls.go issues the credential monitors' certificates from the hub's own CA
// when their section says tls: auto (Task 20409). See pkg/hubca for the CA
// itself and for who replaces a leaf when.
//
// Three things live here:
//
//   - the CA, opened (and on a fresh control plane minted) once per control
//     plane per process, under the same KEK registry as every brokered secret;
//   - a monitor's certificate (startMonitorCertificate): a hubca.Server whose
//     GetCertificate the listener asks per handshake, and a goroutine that
//     re-reads the stored leaf every minute so a member serves the leaf the
//     leader renewed;
//   - the leader's duty (watchMonitorCertificates), which renews both
//     monitors' leaves well before they expire.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/hubca"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	// monitorCertRefreshInterval is how often each member re-reads a
	// monitor's stored leaf. The leader renews two days before expiry, so a
	// minute is far more often than needed for correctness; it is chosen so
	// a renewal is visible on every member before anyone reads the log.
	monitorCertRefreshInterval = time.Minute
	// monitorCertRenewInterval is how often the leader checks whether a leaf
	// is due.
	monitorCertRenewInterval = 10 * time.Minute
)

// hubCA is a control plane's opened CA and what it is stored and sealed with.
type hubCA struct {
	db      *statedb.DB
	store   *hubca.Store
	keyring *secretbroker.Keyring
	ca      *hubca.Authority
}

var (
	hubCAMu sync.Mutex
	// hubCAs caches the opened CA per control-plane directory: both monitors
	// share one keyring derivation and one database handle, held for the
	// process's life like the proxies' audit handles.
	hubCAs = map[string]*hubCA{}
)

// openHubCA returns the control plane's CA, minting it the first time any hub
// process asks for it.
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
	ca, err := hubca.OpenAuthority(store, kr, hubCAOptions(db))
	if err != nil {
		return fail(err)
	}
	c := &hubCA{db: db, store: store, keyring: kr, ca: ca}
	hubCAs[dir] = c
	return c, nil
}

// hubCAOptions is how this hub process issues: under its own name, with every
// certificate it mints or issues written to the control plane's audit trail
// (hub_ca.minted, hub_ca.leaf_issued). A CA minted twice for one control plane
// is the row an operator needs, because every sandbox trusts the first.
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
			if i.Replaced != "" {
				payload["replaced"] = i.Replaced
			}
		}
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
	}}
}

// monitorCertActor names this hub process on the rows it issues.
func monitorCertActor() string {
	if n := currentCluster(); n != nil {
		return n.ID()
	}
	host, _ := os.Hostname()
	return fmt.Sprintf("%s/%d", strings.TrimSpace(host), os.Getpid())
}

// monitorCert is one monitor's auto-issued certificate as its listener serves
// it, and the goroutine keeping it current.
type monitorCert struct {
	srv  *hubca.Server
	stop context.CancelFunc
}

// startMonitorCertificate settles monitor m's leaf for the names sandboxes
// reach it at — baseURL's host, and the listen address's when it names one —
// and keeps re-reading it until Close.
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
		Monitor: m, Store: c.store, Sealer: c.keyring, Authority: c.ca, Want: want,
		Options: hubCAOptions(c.db),
		Logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "ui: "+format+"\n", args...)
		},
	})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	mc := &monitorCert{srv: srv, stop: cancel}
	go mc.refresh(ctx)
	return mc, nil
}

// refresh re-reads the stored leaf until ctx ends, so this member serves the
// one the leader renewed. A failure is reported once per distinct message:
// the listener keeps serving the leaf it has.
func (mc *monitorCert) refresh(ctx context.Context) {
	defer recoverGoroutine("monitor certificate refresh")
	t := time.NewTicker(monitorCertRefreshInterval)
	defer t.Stop()
	var last string
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, err := mc.srv.Refresh()
			msg := ""
			if err != nil {
				msg = err.Error()
			}
			if msg != last && msg != "" {
				fmt.Fprintf(os.Stderr, "ui: the %s's certificate could not be refreshed: %v\n",
					mc.srv.Monitor().Label(), err)
			}
			last = msg
		}
	}
}

// close stops the refresh. Nil-safe.
func (mc *monitorCert) close() {
	if mc != nil && mc.stop != nil {
		mc.stop()
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

// caPEM is the CA certificate sandboxes are told to trust. Nil-safe.
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
// CA, for the proxy's URL and nothing else. Nil when the proxy is not running
// or serves an operator's certificate, which the sandbox image trusts or not
// as before.
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

// applyGitProxyTrust gives spec the hub's CA for the proxy's URL when the
// running proxy serves a certificate the hub issued (Task 20409): every driver
// then makes the workload's git trust it there and nowhere else. Attached to
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
