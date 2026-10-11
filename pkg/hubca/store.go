package hubca

// store.go keeps the CA and the leaves in the control-plane database, with
// every private key sealed under the hub's KEK registry.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Sealer is the part of a *secretbroker.Keyring this package uses.
type Sealer interface {
	SealFor(aad string, plaintext []byte) (secretbroker.Envelope, error)
	OpenEnvelope(aad string, env secretbroker.Envelope) ([]byte, error)
}

// Store is the hub_tls table. It is also the secretbroker.SealedSet through
// which `cloop hub key rotate` rewraps the keys it holds.
type Store struct {
	db *statedb.DB
}

// NewStore adapts a control-plane database. Which database matters: the CA
// belongs to the hub, and a project's state.db is written by whoever can push
// to that project.
func NewStore(db *statedb.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("hubca: nil database")
	}
	return &Store{db: db}, nil
}

// rowAAD binds a sealed key to its row and its certificate's serial, so an
// envelope moved onto another row — or onto the same row's next certificate —
// does not open.
func rowAAD(id, serial string) string {
	return secretbroker.AADFor(secretbroker.SetHubTLS, id+"/"+serial)
}

// SealedSetName identifies the set in rotation reports.
func (s *Store) SealedSetName() string { return secretbroker.SetHubTLS }

// CountSealedByKey groups the rows by the key sealing them.
func (s *Store) CountSealedByKey() (map[string]int, error) { return s.db.CountHubTLSByKey() }

// ListSealedNotUnder returns rows sealed under another key.
func (s *Store) ListSealedNotUnder(keyID string, limit int) ([]secretbroker.SealedRow, error) {
	rows, err := s.db.ListHubTLSNotUnderKey(keyID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]secretbroker.SealedRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, secretbroker.SealedRow{
			ID:  r.ID,
			AAD: rowAAD(r.ID, r.Serial),
			Env: secretbroker.Envelope{KeyID: r.KeyID, WrappedDEK: r.WrappedDEK, Ciphertext: r.KeySealed},
		})
	}
	return out, nil
}

// ReplaceSealed swaps a row's key envelope under compare-and-swap.
func (s *Store) ReplaceSealed(id string, expect, next secretbroker.Envelope) (bool, error) {
	return s.db.ReplaceHubTLSSealed(id,
		statedb.SealedRow{KeyID: expect.KeyID, WrappedDEK: expect.WrappedDEK, Ciphertext: expect.Ciphertext},
		statedb.SealedRow{KeyID: next.KeyID, WrappedDEK: next.WrappedDEK, Ciphertext: next.Ciphertext})
}

var _ secretbroker.SealedSet = (*Store)(nil)

// sealKey seals a private key for a row.
func sealKey(sealer Sealer, id, serial string, key *ecdsa.PrivateKey) (secretbroker.Envelope, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return secretbroker.Envelope{}, fmt.Errorf("hubca: encode the key for %s: %w", id, err)
	}
	defer wipe(der)
	env, err := sealer.SealFor(rowAAD(id, serial), der)
	if err != nil {
		return secretbroker.Envelope{}, sealError(id, err)
	}
	return env, nil
}

// openKey opens a row's sealed private key and checks it belongs to cert.
func openKey(sealer Sealer, row statedb.HubTLSRow, cert *x509.Certificate) (crypto.Signer, error) {
	der, err := sealer.OpenEnvelope(rowAAD(row.ID, row.Serial),
		secretbroker.Envelope{KeyID: row.KeyID, WrappedDEK: row.WrappedDEK, Ciphertext: row.KeySealed})
	if err != nil {
		return nil, sealError(row.ID, err)
	}
	defer wipe(der)
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("hubca: the sealed key of %s does not parse: %w", row.ID, err)
	}
	key, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("hubca: the sealed key of %s cannot sign", row.ID)
	}
	if !matchesKey(cert, key) {
		return nil, fmt.Errorf("hubca: the sealed key of %s is not the key of its certificate", row.ID)
	}
	return key, nil
}

// sealError names the remedy for a key that cannot be sealed or opened.
func sealError(id string, err error) error {
	if errors.Is(err, secretbroker.ErrNoKey) {
		return fmt.Errorf("%w (%s)", ErrNoKey, id)
	}
	return fmt.Errorf("hubca: the private key of %s: %w", id, err)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Options adjusts an operation.
type Options struct {
	// Now is the clock; nil uses time.Now.
	Now func() time.Time
	// Actor names the hub process issuing, for the row's issued_by.
	Actor string
	// Audit receives one record per certificate this process minted or
	// issued — never one it adopted from another process. Nil drops them.
	Audit func(Issued)
}

// Issued describes a certificate this process put in the store: the CA, or a
// monitor's leaf. Certificates only — nothing here is secret.
type Issued struct {
	// CA is true for the CA itself, false for a monitor's leaf.
	CA bool
	// Monitor is the leaf's monitor; empty for the CA.
	Monitor Monitor
	Serial  string
	// Fingerprint is the SHA-256 of the certificate's DER, in hex: what an
	// operator compares against the PEM a sandbox was given.
	Fingerprint string
	Names       []string
	NotAfter    time.Time
	// Replaced is the serial of the leaf this one replaced, if any.
	Replaced string
}

func (o Options) audit(i Issued) {
	if o.Audit != nil {
		o.Audit(i)
	}
}

func certFingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now().UTC()
	}
	return time.Now().UTC()
}

// ReadCA returns the CA certificate the control plane holds, without opening
// its key — what `cloop hub doctor` reads. ErrNotMinted when there is none.
func (s *Store) ReadCA() (*x509.Certificate, []byte, error) {
	row, err := s.db.GetHubTLS(caRowID)
	if errors.Is(err, statedb.ErrHubTLSNotFound) {
		return nil, nil, ErrNotMinted
	}
	if err != nil {
		return nil, nil, err
	}
	cert, err := ParseCertPEM([]byte(row.CertPEM))
	if err != nil {
		return nil, nil, fmt.Errorf("hubca: the hub CA certificate: %w", err)
	}
	return cert, []byte(row.CertPEM), nil
}

// LeafInfo is what can be read about a monitor's leaf without opening its key.
type LeafInfo struct {
	Monitor  Monitor
	Cert     *x509.Certificate
	SANs     []string
	Issuer   string
	IssuedBy string
	IssuedAt time.Time
}

// ReadLeaf returns a monitor's current leaf, without its key. ErrNotMinted
// when none has been issued.
func (s *Store) ReadLeaf(m Monitor) (LeafInfo, error) {
	row, err := s.db.GetHubTLS(m.rowID())
	if errors.Is(err, statedb.ErrHubTLSNotFound) {
		return LeafInfo{}, ErrNotMinted
	}
	if err != nil {
		return LeafInfo{}, err
	}
	cert, err := ParseCertPEM([]byte(row.CertPEM))
	if err != nil {
		return LeafInfo{}, fmt.Errorf("hubca: the %s's certificate: %w", m.Label(), err)
	}
	return LeafInfo{Monitor: m, Cert: cert, SANs: certSANs(cert), Issuer: row.Issuer,
		IssuedBy: row.IssuedBy, IssuedAt: row.IssuedAt}, nil
}

// ErrNotMinted is returned for a CA or a leaf that does not exist yet: a hub
// that has never started a monitor in auto mode.
var ErrNotMinted = errors.New("hubca: not issued yet")

// OpenAuthority returns the hub's CA, minting it on the first call any hub
// process makes against this control plane.
//
// Two processes minting at the same moment cannot both win: the insert is ON
// CONFLICT DO NOTHING, and the loser opens the winner's CA instead of its own.
// A CA that exists is never replaced here — every sandbox already given it
// would refuse its successor.
func OpenAuthority(s *Store, sealer Sealer, o Options) (*Authority, error) {
	if s == nil || sealer == nil {
		return nil, errors.New("hubca: a store and a sealer are required")
	}
	row, err := s.db.GetHubTLS(caRowID)
	if errors.Is(err, statedb.ErrHubTLSNotFound) {
		now := o.now()
		cert, certPEM, key, merr := mintCA(now)
		if merr != nil {
			return nil, merr
		}
		serial := serialHex(cert.SerialNumber)
		env, serr := sealKey(sealer, caRowID, serial, key)
		if serr != nil {
			return nil, serr
		}
		inserted, ierr := s.db.InsertHubTLS(statedb.HubTLSRow{
			ID: caRowID, Kind: "ca", Serial: serial, CertPEM: string(certPEM),
			KeyID: env.KeyID, WrappedDEK: env.WrappedDEK, KeySealed: env.Ciphertext,
			NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, IssuedAt: now, IssuedBy: o.Actor,
		})
		if ierr != nil {
			return nil, fmt.Errorf("hubca: store the hub CA: %w", ierr)
		}
		if inserted {
			o.audit(Issued{CA: true, Serial: serial, Fingerprint: certFingerprint(cert), NotAfter: cert.NotAfter})
			return &Authority{cert: cert, certPEM: certPEM, signer: key}, nil
		}
		// Another process minted first. Its CA is the hub's.
		row, err = s.db.GetHubTLS(caRowID)
	}
	if err != nil {
		return nil, fmt.Errorf("hubca: read the hub CA: %w", err)
	}
	return openAuthorityRow(sealer, row, o.now())
}

func openAuthorityRow(sealer Sealer, row statedb.HubTLSRow, now time.Time) (*Authority, error) {
	cert, err := ParseCertPEM([]byte(row.CertPEM))
	if err != nil {
		return nil, fmt.Errorf("hubca: the hub CA certificate: %w", err)
	}
	if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("hubca: the stored hub CA certificate is not a CA certificate")
	}
	if serialHex(cert.SerialNumber) != strings.ToLower(row.Serial) {
		return nil, errors.New("hubca: the stored hub CA's serial is not its certificate's")
	}
	if now.After(cert.NotAfter) {
		return nil, fmt.Errorf("hubca: the hub CA expired at %s; every sandbox has stopped trusting it, "+
			"so no certificate it signs would verify", cert.NotAfter.UTC().Format(time.RFC3339))
	}
	key, err := openKey(sealer, row, cert)
	if err != nil {
		return nil, err
	}
	return &Authority{cert: cert, certPEM: []byte(row.CertPEM), signer: key}, nil
}

// Leaf is a monitor's serving certificate, opened.
type Leaf struct {
	Monitor  Monitor
	Serial   string
	Cert     *x509.Certificate
	CertPEM  []byte
	IssuedBy string
	pair     tls.Certificate
}

// SANs lists the names the leaf carries.
func (l *Leaf) SANs() []string { return certSANs(l.Cert) }

// usable reports whether the leaf may keep serving want for at least margin
// beyond now: it chains to ca, carries every name, and is valid that long.
func (l *Leaf) usable(ca *Authority, want []string, now time.Time, margin time.Duration) bool {
	if l == nil || l.Cert == nil {
		return false
	}
	if now.Before(l.Cert.NotBefore) || !now.Add(margin).Before(l.Cert.NotAfter) {
		return false
	}
	if !Covers(l.Cert, want) {
		return false
	}
	_, err := l.Cert.Verify(x509.VerifyOptions{
		Roots:       ca.pool(),
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err == nil
}

// loadLeaf reads and opens a monitor's stored leaf. A missing one is (nil, "",
// nil); an unreadable one is returned with its serial so it can be replaced.
func loadLeaf(s *Store, sealer Sealer, m Monitor) (*Leaf, string, error) {
	row, err := s.db.GetHubTLS(m.rowID())
	if errors.Is(err, statedb.ErrHubTLSNotFound) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	cert, err := ParseCertPEM([]byte(row.CertPEM))
	if err != nil {
		return nil, row.Serial, fmt.Errorf("hubca: the %s's stored certificate: %w", m.Label(), err)
	}
	key, err := openKey(sealer, row, cert)
	if err != nil {
		return nil, row.Serial, err
	}
	return &Leaf{
		Monitor: m, Serial: row.Serial, Cert: cert, CertPEM: []byte(row.CertPEM),
		IssuedBy: row.IssuedBy, pair: tlsPair(cert, key),
	}, row.Serial, nil
}

// issueLeaf signs and stores a new leaf for m, replacing the row whose serial
// is replace ("" for none). It reports whether it was stored; false means
// another process stored one first, which the caller re-reads.
func issueLeaf(s *Store, sealer Sealer, ca *Authority, m Monitor, sans []string, replace string, o Options) (*Leaf, bool, error) {
	now := o.now()
	cert, certPEM, key, err := ca.issue(m, sans, now)
	if err != nil {
		return nil, false, err
	}
	serial := serialHex(cert.SerialNumber)
	env, err := sealKey(sealer, m.rowID(), serial, key)
	if err != nil {
		return nil, false, err
	}
	row := statedb.HubTLSRow{
		ID: m.rowID(), Kind: "leaf", Serial: serial, Issuer: ca.Serial(), CertPEM: string(certPEM),
		KeyID: env.KeyID, WrappedDEK: env.WrappedDEK, KeySealed: env.Ciphertext,
		SANs: certSANs(cert), NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, IssuedAt: now, IssuedBy: o.Actor,
	}
	var stored bool
	if replace == "" {
		stored, err = s.db.InsertHubTLS(row)
	} else {
		stored, err = s.db.ReplaceHubTLS(row, replace)
	}
	if err != nil {
		return nil, false, fmt.Errorf("hubca: store the %s's certificate: %w", m.Label(), err)
	}
	if stored {
		o.audit(Issued{Monitor: m, Serial: serial, Fingerprint: certFingerprint(cert), Names: certSANs(cert),
			NotAfter: cert.NotAfter, Replaced: replace})
	}
	return &Leaf{
		Monitor: m, Serial: serial, Cert: cert, CertPEM: certPEM, IssuedBy: o.Actor,
		pair: tlsPair(cert, key),
	}, stored, nil
}
