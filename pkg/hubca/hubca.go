// Package hubca is the hub's own certificate authority, and the short-lived
// certificates it issues its two credential monitors (Task 20409).
//
// # Why the hub has one
//
// The git interception proxy and the Kubernetes access monitor exist so that a
// forge token and a cluster credential stay on the hub: the sandbox holds a
// session token instead, and a process it does not control decides every push
// and every API request. That token rides every request, so both listeners
// speak TLS — and until this package, their certificate was a pair of files
// the operator supplied. A self-signed pair needed its CA in every sandbox
// image, a public one needed a name the sandbox could reach and a CA would
// sign, and so most hubs ran neither and delivered the PAT itself into the
// sandbox. The security property was one the operator had to finish building.
//
// With `tls: auto` on a monitor's section the hub builds it. A CA is minted
// once per control plane, its private key sealed under the hub's KEK registry
// (envelope encryption, the same as every brokered secret) and kept in the
// control-plane database, never as a loose file. So every hub-cluster member
// serves the same identity, a database backup carries it, and `cloop hub key
// rotate` rewraps it. Each monitor's serving certificate is a leaf issued from
// that CA for the names sandboxes reach it at — the advertise URL's host and
// the listen address's — valid for LeafLifetime and replaced by the cluster
// leader when less than RenewWithin remains.
//
// # What a sandbox trusts
//
// The CA, never the leaf, and only for the monitor's URL. The CA certificate
// travels to each sandbox (pkg/executor.GitCA) and git is told to trust it
// through http.<advertise_url>.sslCAInfo — not GIT_SSL_CAINFO, which replaces
// the trust store — so another https host whose certificate this CA signed is
// still verified against the image's own store and refused. A kubeconfig
// carries the CA as its cluster's certificate-authority-data. Because the
// sandbox trusts the CA, a leaf can be replaced under a running workload: a
// push in flight keeps its connection, and the next one verifies the new leaf
// against the same CA.
//
// The CA's private key is opened only in the hub process, to sign leaves. It
// is in no Spec, no lease, no start frame and no log.
//
// # Replacing the CA
//
// A CA's key that may have leaked — a backup taken with the root key, a
// misused KMS identity, a departed operator — is replaced online, in three
// steps an operator takes with `cloop hub ca rotate` (rotate.go, Task 20438):
// stage a second CA, which every sandbox dispatched from then on trusts beside
// the first; activate it once no run dispatched before the stage is still
// running, when the cluster leader reissues every leaf from it; and retire the
// first, whose sealed key is destroyed. A process's view of which CAs exist,
// which one signs and which ones a sandbox is told to trust is a Trust
// (trust.go), re-read every minute and whenever another process takes a step.
//
// A CA minted by a rotation carries X.509 name constraints for the names the
// monitors are reached at, so even a verifier that trusts it more widely than
// git's per-URL setting does — Node.js, which trusts it for every host — would
// refuse a certificate it signed for any other host.
package hubca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 5280 §4.2.1.2 key identifier, not a signature
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Monitor names a listener whose certificate the hub issues.
type Monitor string

const (
	// GitProxy is the git interception proxy (executors.git_proxy).
	GitProxy Monitor = "git_proxy"
	// KubeGuard is the Kubernetes access monitor (executors.kube_guard).
	KubeGuard Monitor = "kube_guard"
)

// Monitors lists every monitor the hub issues for, in a stable order.
func Monitors() []Monitor { return []Monitor{GitProxy, KubeGuard} }

// Valid reports whether m is a monitor this package issues for.
func (m Monitor) Valid() bool { return m == GitProxy || m == KubeGuard }

// Label is how a message names the monitor.
func (m Monitor) Label() string {
	switch m {
	case GitProxy:
		return "git proxy"
	case KubeGuard:
		return "Kubernetes access monitor"
	}
	return string(m)
}

// ConfigKey is the configuration section the monitor is configured by.
func (m Monitor) ConfigKey() string { return "executors." + string(m) }

// rowID is the monitor's leaf row in hub_tls.
func (m Monitor) rowID() string { return "leaf:" + string(m) }

// caRowID is the CA's row in hub_tls.
const caRowID = "ca"

const (
	// CALifetime is how long the CA is valid. Long, because a CA that
	// expires is one every sandbox stops trusting at once, and replacing it
	// is a change to every workload's trust rather than to one listener's
	// certificate. Leaves are what is short-lived.
	CALifetime = 10 * 365 * 24 * time.Hour
	// LeafLifetime is how long a monitor's certificate is valid.
	LeafLifetime = 72 * time.Hour
	// RenewWithin: a leaf with less than this left is replaced. The 48-hour
	// overlap is what a renewal that failed has to be noticed and fixed in
	// before anything stops verifying.
	RenewWithin = 48 * time.Hour
	// NearExpiry is when `cloop hub doctor` fails a leaf: renewal should have
	// replaced it a day before this.
	NearExpiry = 24 * time.Hour
	// EmergencyWithin: a hub process that is not the cluster leader replaces
	// a leaf itself only this close to its expiry — a leader that has been
	// gone for two days, or a cluster whose leader cannot sign.
	EmergencyWithin = time.Hour
	// backdate starts every certificate's validity this far in the past, so a
	// sandbox whose clock runs behind the hub's still accepts a new leaf.
	backdate = time.Hour
	// MaxSANs bounds the names one leaf carries.
	MaxSANs = 16
)

// ErrNoKey is returned when the hub has no sealing key to keep the CA under.
var ErrNoKey = errors.New("hubca: the hub's certificate authority needs CLOOP_SECRET_KEY (or its key file, " +
	"CLOOP_SECRET_KEY_FILE), which its private key is sealed under")

// Authority is the hub's CA, opened for signing.
type Authority struct {
	cert    *x509.Certificate
	certPEM []byte
	signer  crypto.Signer
}

// Certificate returns the CA certificate.
func (a *Authority) Certificate() *x509.Certificate { return a.cert }

// CertPEM returns a copy of the CA certificate, PEM-encoded. Public.
func (a *Authority) CertPEM() []byte { return append([]byte(nil), a.certPEM...) }

// Serial is the CA's serial in lowercase hex.
func (a *Authority) Serial() string { return serialHex(a.cert.SerialNumber) }

// pool is a cert pool holding only the CA.
func (a *Authority) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(a.cert)
	return p
}

// newSerial returns a random positive 128-bit serial, the size RFC 5280 allows
// and CA/B Forum practice expects to be unpredictable.
func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, fmt.Errorf("hubca: draw a serial: %w", err)
		}
		if n.Sign() > 0 {
			return n, nil
		}
	}
}

func serialHex(n *big.Int) string {
	if n == nil {
		return ""
	}
	return strings.ToLower(hex.EncodeToString(n.Bytes()))
}

// keyIdentifier is the RFC 5280 method-1 identifier of a public key.
func keyIdentifier(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, err
	}
	sum := sha1.Sum(spki.PublicKey.Bytes) //nolint:gosec // identifier, not a signature
	return sum[:], nil
}

// mintCA creates a new CA certificate and key. names, when there are any,
// become the CA's name constraints (constrain).
func mintCA(now time.Time, names []string) (*x509.Certificate, []byte, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("hubca: generate the CA key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	ski, err := keyIdentifier(&key.PublicKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("hubca: CA key identifier: %w", err)
	}
	short := serialHex(serial)
	if len(short) > 8 {
		short = short[:8]
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"cloop"},
			CommonName:   "cloop hub CA " + short,
		},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(CALifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// It signs leaves and nothing that signs: a CA one level deep cannot
		// be used to mint a subordinate the hub never sees.
		MaxPathLen:     0,
		MaxPathLenZero: true,
		SubjectKeyId:   ski,
	}
	if len(names) > 0 {
		if err := constrain(tmpl, names); err != nil {
			return nil, nil, nil, err
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("hubca: sign the CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("hubca: parse the CA certificate: %w", err)
	}
	return cert, pemCert(der), key, nil
}

// issue signs a leaf for m covering sans.
func (a *Authority) issue(m Monitor, sans []string, now time.Time) (*x509.Certificate, []byte, *ecdsa.PrivateKey, error) {
	if !m.Valid() {
		return nil, nil, nil, fmt.Errorf("hubca: %q is not a monitor this hub issues for", m)
	}
	dns, ips, err := splitSANs(sans)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(dns)+len(ips) == 0 {
		return nil, nil, nil, fmt.Errorf("hubca: the %s's certificate would name nothing a sandbox could reach it at", m.Label())
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("hubca: generate the %s's key: %w", m.Label(), err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	notAfter := now.Add(LeafLifetime)
	if notAfter.After(a.cert.NotAfter) {
		// A leaf that outlives its CA would stop verifying with the CA anyway;
		// saying so in the certificate keeps doctor's arithmetic honest.
		notAfter = a.cert.NotAfter
	}
	// The common name is the first DNS name, and a leaf that names addresses
	// only has none: a verifier that finds no DNS name in the leaf checks its
	// common name against the CA's DNS name constraints instead — GnuTLS, the
	// TLS library of Debian's and Ubuntu's git, whatever the name looks like —
	// and a CA constrained to addresses permits no DNS name at all.
	cn := ""
	if len(dns) > 0 {
		cn = dns[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization:       []string{"cloop"},
			OrganizationalUnit: []string{m.Label()},
			CommonName:         cn,
		},
		NotBefore:             now.Add(-backdate),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dns,
		IPAddresses:           ips,
		AuthorityKeyId:        a.cert.SubjectKeyId,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.signer)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("hubca: sign the %s's certificate: %w", m.Label(), err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("hubca: parse the %s's certificate: %w", m.Label(), err)
	}
	return cert, pemCert(der), key, nil
}

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// ParseCertPEM decodes exactly one certificate from PEM.
func ParseCertPEM(b []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("hubca: no PEM certificate")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("hubca: more than one PEM block where one certificate was expected")
	}
	return x509.ParseCertificate(block.Bytes)
}

// SANsFor returns the names a monitor's certificate must carry: the host of
// advertiseBase — the https URL sandboxes are pointed at — and the host of
// listenAddr when it names one, rather than every interface.
//
// The listen address is there for the sandbox that shares the hub's network
// namespace and dials it directly, and for a hub whose advertise URL is the
// bound address; an unspecified bind (":8443", "0.0.0.0:8443") names nothing
// a client could dial, so it adds nothing.
func SANsFor(advertiseBase, listenAddr string) ([]string, error) {
	var out []string
	if s := strings.TrimSpace(advertiseBase); s != "" {
		u, err := url.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("hubca: advertise URL %q: %w", s, err)
		}
		h := u.Hostname()
		if h == "" {
			return nil, fmt.Errorf("hubca: advertise URL %q names no host", s)
		}
		out = append(out, h)
	}
	if s := strings.TrimSpace(listenAddr); s != "" {
		host, _, err := net.SplitHostPort(s)
		if err != nil {
			return nil, fmt.Errorf("hubca: listen address %q: %w", s, err)
		}
		if host != "" {
			if ip, perr := netip.ParseAddr(host); perr != nil || !ip.IsUnspecified() {
				out = append(out, host)
			}
		}
	}
	return NormalizeSANs(out)
}

// NormalizeSANs validates, lowercases, de-duplicates and sorts names.
func NormalizeSANs(in []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, raw := range in {
		s := strings.ToLower(strings.TrimSpace(raw))
		s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
		if s == "" {
			continue
		}
		if ip, err := netip.ParseAddr(s); err == nil {
			s = ip.Unmap().String()
		} else if !validDNSName(s) {
			return nil, fmt.Errorf("hubca: %q is neither an IP address nor a DNS name a certificate can carry", raw)
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out, nil
}

// validDNSName accepts the hostnames a sandbox can be pointed at: letters,
// digits, hyphens and dots, no wildcard, no empty label, at most 253 bytes.
func validDNSName(s string) bool {
	if len(s) == 0 || len(s) > 253 || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

func splitSANs(sans []string) (dns []string, ips []net.IP, err error) {
	norm, err := NormalizeSANs(sans)
	if err != nil {
		return nil, nil, err
	}
	for _, s := range norm {
		if ip, perr := netip.ParseAddr(s); perr == nil {
			ips = append(ips, net.IP(ip.AsSlice()))
			continue
		}
		dns = append(dns, s)
	}
	return dns, ips, nil
}

// certSANs lists the names a certificate carries, normalized.
func certSANs(c *x509.Certificate) []string {
	var raw []string
	raw = append(raw, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		raw = append(raw, ip.String())
	}
	out, err := NormalizeSANs(raw)
	if err != nil {
		return raw
	}
	return out
}

// Covers reports whether a certificate carries every one of want's names.
func Covers(c *x509.Certificate, want []string) bool {
	if c == nil {
		return false
	}
	have := map[string]bool{}
	for _, s := range certSANs(c) {
		have[s] = true
	}
	norm, err := NormalizeSANs(want)
	if err != nil {
		return false
	}
	for _, s := range norm {
		if !have[s] {
			return false
		}
	}
	return true
}

// Missing returns want's names a certificate does not carry.
func Missing(c *x509.Certificate, want []string) []string {
	have := map[string]bool{}
	if c != nil {
		for _, s := range certSANs(c) {
			have[s] = true
		}
	}
	norm, _ := NormalizeSANs(want)
	var out []string
	for _, s := range norm {
		if !have[s] {
			out = append(out, s)
		}
	}
	return out
}

// union merges two name lists, falling back to want alone past MaxSANs.
func union(have, want []string) []string {
	merged, err := NormalizeSANs(append(append([]string(nil), have...), want...))
	if err != nil || len(merged) > MaxSANs {
		w, _ := NormalizeSANs(want)
		return w
	}
	return merged
}

// tlsPair builds what a listener serves from a leaf and its key.
func tlsPair(cert *x509.Certificate, key crypto.Signer) tls.Certificate {
	return tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	}
}

// matchesKey reports whether key is the private half of cert's public key.
func matchesKey(cert *x509.Certificate, key crypto.Signer) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	pub, ok := key.Public().(equaler)
	return ok && pub.Equal(cert.PublicKey)
}

// pemFirst returns the first PEM block of b, encoded again, and the rest.
func pemFirst(b []byte) ([]byte, []byte) {
	block, rest := pem.Decode(b)
	if block == nil {
		return nil, b
	}
	return pem.EncodeToMemory(block), rest
}

// Serial is a certificate's serial as the hub records it: lowercase hex of
// its big-endian bytes, the form hub_tls, the trust labels and the audit
// trail use. (big.Int's Text(16) drops a leading zero nibble, so it is not.)
func Serial(c *x509.Certificate) string {
	if c == nil {
		return ""
	}
	return serialHex(c.SerialNumber)
}

// BundleSerials lists the serials of the certificates in a PEM bundle, in
// order; a block that does not parse is skipped.
func BundleSerials(bundle []byte) []string {
	var out []string
	rest := bundle
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			return out
		}
		rest = r
		if block.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			out = append(out, Serial(c))
		}
	}
}

// FirstPEM is the first certificate of a PEM bundle, PEM-encoded: the active
// CA, which State.Bundle puts first.
func FirstPEM(bundle []byte) []byte {
	first, _ := pemFirst(bundle)
	return first
}
