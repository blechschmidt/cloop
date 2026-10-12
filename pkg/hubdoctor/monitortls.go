package hubdoctor

// Certificates the hub issues its credential monitors itself (tls: auto, Task
// 20409), and the forge credentials a strict hub without a git proxy hands into
// sandboxes.
//
// Under tls: auto there is no certificate file to load, so the question
// proxyTLS asks — "will the listener's key pair load?" — has two others in its
// place: can the hub open the CA it signs with (it needs the sealing key), and
// is the leaf it is serving still good for the names sandboxes reach it at?
// The second is read from the control-plane database, where the CA and the
// leaves live; the leader renews a leaf with two days to spare, so a leaf with
// less than one left means renewal has stopped, and a leaf that does not name
// the advertise URL's host is one every sandbox's TLS check refuses.

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/hubca"
	"github.com/blechschmidt/cloop/pkg/rootkey"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// caExpiryWarning is how far ahead of the hub CA's expiry the doctor starts to
// say so. Replacing the CA changes what every sandbox trusts, so it is planned
// work rather than a renewal.
const caExpiryWarning = 365 * 24 * time.Hour

// autoMonitorTLS checks a monitor running under tls: auto and reports whether
// it will start.
func autoMonitorTLS(dir string, m hubca.Monitor, check, title string, ep proxyEndpoint, listenAddr,
	refusal string, now time.Time, add addFn) bool {

	section := m.ConfigKey()
	if key, _ := rootkey.Current(); key == "" {
		add(Finding{
			Check: check, Title: title, Severity: SeverityFail,
			Message: fmt.Sprintf("%s.tls is auto, which issues the certificate from the hub's own CA, "+
				"and the CA's private key is sealed under %s — which is not set here, so the %s will "+
				"not start and %s", section, secretbroker.EnvPassphraseKey, m.Label(), refusal),
			Remediation: "Give the hub its key (" + rootkey.EnvKeyFile + ", the systemd credential " +
				rootkey.Credential + ", or " + rootkey.EnvKey + "; `cloop hub bootstrap` writes one), or give " +
				section + " a cert_file and key_file instead",
		})
		return false
	}

	notYet := Finding{
		Check: check, Title: title, Severity: SeverityPass,
		Message: fmt.Sprintf("tls: auto; the hub mints its CA and issues the %s's certificate the first "+
			"time it starts, and tells every sandbox to trust that CA for %s only", m.Label(), ep.base),
	}
	store, closeStore, err := openHubTLSStore(dir)
	if errors.Is(err, hubca.ErrNotMinted) {
		add(notYet)
		return true
	}
	if err != nil {
		// checkStorage reports the database; this is only what it costs.
		add(Finding{
			Check: check, Title: title, Severity: SeverityWarn,
			Message:     fmt.Sprintf("the certificate the hub issued the %s could not be read: %v", m.Label(), err),
			Remediation: "See the storage findings; the certificate lives in the control-plane database",
		})
		return true
	}
	defer closeStore()

	caCert, _, err := readCA(store)
	if errors.Is(err, hubca.ErrNotMinted) {
		add(notYet)
		return true
	}
	if err != nil {
		add(Finding{
			Check: check, Title: title, Severity: SeverityFail,
			Message: fmt.Sprintf("the hub CA in the control-plane database is unreadable: %v — the %s "+
				"will not start, so %s", err, m.Label(), refusal),
			Remediation: "Restore the database from a backup taken before the damage; a new CA would " +
				"have to be minted and every running sandbox would stop trusting the proxy",
		})
		return false
	}
	switch left := caCert.NotAfter.Sub(now); {
	case left <= 0:
		add(Finding{
			Check: check, Title: title, Severity: SeverityFail,
			Message: fmt.Sprintf("the hub CA expired at %s, so the %s will not start and %s",
				caCert.NotAfter.UTC().Format(time.RFC3339), m.Label(), refusal),
			Remediation: "Give " + section + " a cert_file and key_file while a new hub CA is planned",
		})
		return false
	case left < caExpiryWarning:
		add(Finding{
			Check: "hubca.expiry", Title: "Hub certificate authority", Severity: SeverityWarn,
			Message: fmt.Sprintf("the hub CA expires at %s; every sandbox trusts it for the monitors' URLs, "+
				"so replacing it is planned work, not a renewal", caCert.NotAfter.UTC().Format(time.RFC3339)),
			Remediation: "Plan the replacement before then",
		})
	}

	leaf, err := store.ReadLeaf(m)
	if errors.Is(err, hubca.ErrNotMinted) {
		add(notYet)
		return true
	}
	if err != nil {
		add(Finding{
			Check: check, Title: title, Severity: SeverityFail,
			Message: fmt.Sprintf("the %s's certificate in the control-plane database is unreadable: %v",
				m.Label(), err),
			Remediation: "Restart the hub: it issues a new certificate when the stored one cannot be used",
		})
		return false
	}

	details := map[string]any{
		"serial":    leaf.Cert.SerialNumber.Text(16),
		"not_after": leaf.Cert.NotAfter.UTC().Format(time.RFC3339),
		"names":     leaf.SANs,
		"issued_by": leaf.IssuedBy,
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, verr := leaf.Cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); verr != nil {
		add(Finding{
			Check: check, Title: title, Severity: SeverityFail,
			Message: fmt.Sprintf("the certificate the %s serves does not verify against the hub CA: %v — "+
				"sandboxes trust only that CA for the %s, so %s", m.Label(), verr, m.Label(), refusal),
			Remediation: "Restart the hub, which replaces a leaf that does not verify; if this persists, " +
				"its log names why renewal fails",
			Details: details,
		})
		return true
	}
	if left := leaf.Cert.NotAfter.Sub(now); left < hubca.NearExpiry {
		add(Finding{
			Check: check, Title: title, Severity: SeverityFail,
			Message: fmt.Sprintf("the certificate the %s serves expires at %s, in %s; the cluster leader "+
				"renews it %s before expiry, so renewal has stopped", m.Label(),
				leaf.Cert.NotAfter.UTC().Format(time.RFC3339), left.Round(time.Minute), hubca.RenewWithin),
			Remediation: "Check the hub's log for \"could not be renewed\"; restarting the hub issues a fresh one",
			Details:     details,
		})
		return true
	}
	if want, werr := hubca.SANsFor(ep.base, listenAddr); werr == nil {
		if missing := hubca.Missing(leaf.Cert, want); len(missing) > 0 {
			add(Finding{
				Check: check, Title: title, Severity: SeverityFail,
				Message: fmt.Sprintf("the certificate the %s serves names %s but not %s, which sandboxes "+
					"reach it at (%s) — every sandbox's TLS check would refuse it", m.Label(),
					strings.Join(leaf.SANs, ", "), strings.Join(missing, ", "), ep.base),
				Remediation: "Restart the hub after changing " + section + ".advertise_url: it issues a " +
					"certificate for the names it is configured with at start",
				Details: details,
			})
			return true
		}
	}
	add(Finding{
		Check: check, Title: title, Severity: SeverityPass,
		Message: fmt.Sprintf("tls: auto; serving a certificate from the hub CA for %s, valid until %s; "+
			"sandboxes trust the CA for %s only", strings.Join(leaf.SANs, ", "),
			leaf.Cert.NotAfter.UTC().Format(time.RFC3339), ep.base),
		Details: details,
	})
	return true
}

// openHubTLSStore opens the control plane's hub_tls rows for reading. A
// control plane with no database yet has no rows, which is what a store over
// an empty database reports.
func openHubTLSStore(dir string) (*hubca.Store, func(), error) {
	dbPath := state.DBPath(dir)
	if _, err := os.Stat(dbPath); err != nil {
		return nil, nil, fmt.Errorf("%w: no database yet", hubca.ErrNotMinted)
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, nil, err
	}
	store, err := hubca.NewStore(db)
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	return store, func() { _ = db.Close() }, nil
}

// readCA is Store.ReadCA, tolerating the store openHubTLSStore could not open.
func readCA(store *hubca.Store) (*x509.Certificate, []byte, error) {
	if store == nil {
		return nil, nil, hubca.ErrNotMinted
	}
	return store.ReadCA()
}

// forgeGrant is one active GitHub grant, named for an operator.
type forgeGrant struct {
	secret  string
	kind    secretbroker.Kind
	subject string
}

func (g forgeGrant) String() string {
	return fmt.Sprintf("%s (%s) to %s", g.secret, g.kind, g.subject)
}

// checkForgeCredentials names the GitHub grants a strict hub with no git proxy
// delivers into sandboxes as the credential itself (Task 20409).
//
// A hub that set allow_host_process: false has said no run may execute beside
// its credentials; delivering a PAT or an App installation token into the
// sandbox puts the credential beside the run instead, where a workload can use
// it against the REST API or push wherever it reaches. The git proxy is what
// keeps it on the hub, and with tls: auto it needs no certificate files.
func checkForgeCredentials(dir string, cfg *config.Config, add addFn) {
	if cfg.Executors.GitProxy.Enabled || cfg.Executors.HostProcessAllowed() {
		return
	}
	grants, _ := activeForgeGrants(dir)
	if len(grants) == 0 {
		return
	}
	names := make([]string, 0, len(grants))
	for _, g := range grants {
		names = append(names, g.String())
	}
	sort.Strings(names)
	shown := names
	if len(shown) > 10 {
		shown = append(append([]string(nil), shown[:10]...), fmt.Sprintf("and %d more", len(names)-10))
	}
	add(Finding{
		Check:    "gitproxy.forge_credentials",
		Title:    "Forge credentials in sandboxes",
		Severity: SeverityWarn,
		Message: fmt.Sprintf("host execution is off, but executors.git_proxy is too, so %d GitHub grant(s) "+
			"are delivered into sandboxes as the credential itself, usable against GitHub's API and for "+
			"any push the token reaches: %s", len(grants), strings.Join(shown, "; ")),
		Remediation: "Enable executors.git_proxy with tls: auto and an advertise_url your executors reach " +
			"(`cloop hub bootstrap` writes one), so the token stays on the hub and sandboxes hold a " +
			"session worth one grant's repositories and branches. See docs/architecture/git-proxy.md",
		Details: map[string]any{"grants": names},
	})
}

// activeForgeGrants lists the active GitHub grants with their secrets' names
// and subjects. known is false when the store exists and could not be read.
func activeForgeGrants(dir string) (grants []forgeGrant, known bool) {
	dbPath := state.DBPath(dir)
	if _, err := os.Stat(dbPath); err != nil {
		return nil, true
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, false
	}
	defer func() { _ = db.Close() }()
	store, err := secretstore.New(db)
	if err != nil {
		return nil, false
	}
	secrets, err := store.ListSecrets()
	if err != nil {
		return nil, false
	}
	type named struct {
		name string
		kind secretbroker.Kind
	}
	byID := make(map[string]named, len(secrets))
	for _, s := range secrets {
		byID[s.ID] = named{name: s.Name, kind: s.Kind}
	}
	all, err := store.ListGrants()
	if err != nil {
		return nil, false
	}
	now := time.Now()
	for _, g := range all {
		s := byID[g.SecretID]
		if !g.Active(now) || (s.kind != secretbroker.KindGitHubPAT && s.kind != secretbroker.KindGitHubApp) {
			continue
		}
		grants = append(grants, forgeGrant{secret: s.name, kind: s.kind, subject: g.Subject.String()})
	}
	return grants, true
}
