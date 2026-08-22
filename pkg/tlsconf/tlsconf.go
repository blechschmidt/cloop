// Package tlsconf centralises cloop's transport-security decisions: the
// server-side TLS parameters for `cloop ui` / `cloop serve`, and the SPKI
// pinning primitives the executor agent uses to decide whether the TLS peer
// that answered DNS is really its control plane.
//
// Why one package rather than a tls.Config per caller: the hub, the REST API
// server and the agent must agree on what "acceptable transport" means. When
// each site builds its own tls.Config, the weakest one becomes the deployment's
// real floor, and nothing fails loudly when they drift apart. Everything here
// is deliberately small and pure so tests/security can assert on it directly.
//
// Pinning is SPKI-based, not certificate-based, on purpose. A pin over the
// Subject Public Key Info survives certificate renewal — the near-universal
// operational event — as long as the operator reuses the key, so a fleet of
// enrolled edge devices does not all break on the day a 90-day certificate
// rolls over. Pinning the whole certificate would turn every renewal into a
// fleet-wide re-enrollment. (This mirrors RFC 7469's choice for the same
// reason.)
//
// Pinning here is *additive*: it runs through tls.Config.VerifyPeerCertificate,
// which the Go runtime only calls after the normal chain/hostname verification
// has already succeeded. This package never sets InsecureSkipVerify and no
// caller should: "the pin matches" must mean "a valid certificate that also
// matches the pin", never "an invalid certificate we decided to accept".
package tlsconf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/atomicfile"
)

// PinPrefix is the algorithm tag every pin carries. It is spelled out rather
// than implied so a future second hash can be added without silently
// reinterpreting pins already deployed on edge devices.
const PinPrefix = "sha256:"

// File modes for generated key material. The private key is 0600 because it
// is the server's identity; the certificate is 0644 because it is public by
// construction and agents/operators need to read it to compute a pin.
const (
	KeyFileMode  os.FileMode = 0o600
	CertFileMode os.FileMode = 0o644
)

// ErrPinMismatch is returned by the VerifyPeerCertificate closure when the
// peer presented a valid certificate whose SPKI is not in the pin set. It is
// distinct from a generic handshake failure because the operator response is
// different: a mismatch means either the certificate was rotated to a new key
// (re-pin) or something is impersonating the control plane (investigate).
var ErrPinMismatch = errors.New("tlsconf: server public key does not match any configured pin")

// ErrNoPin is returned when a pin string cannot be parsed.
var ErrNoPin = errors.New("tlsconf: malformed pin")

// ---------------------------------------------------------------------------
// Protocol parameters
// ---------------------------------------------------------------------------

// ParseMinVersion converts a config value into a tls.Version constant.
//
// Accepted: "" (default), "1.2"/"tls1.2"/"tls12", "1.3"/"tls1.3"/"tls13".
// TLS 1.0 and 1.1 are rejected rather than accepted-with-a-warning: they have
// no safe configuration left, and an operator who wrote "1.0" into a config
// file needs to find out at startup, not from a pentest report.
func ParseMinVersion(s string) (uint16, error) {
	norm := strings.ToLower(strings.TrimSpace(s))
	norm = strings.TrimPrefix(norm, "tls")
	norm = strings.TrimPrefix(norm, "v")
	switch norm {
	case "":
		return tls.VersionTLS12, nil
	case "1.2", "12":
		return tls.VersionTLS12, nil
	case "1.3", "13":
		return tls.VersionTLS13, nil
	case "1.0", "10", "1.1", "11":
		return 0, fmt.Errorf("tlsconf: TLS %s is not supported; the minimum is 1.2", norm)
	default:
		return 0, fmt.Errorf("tlsconf: unrecognised TLS version %q (want 1.2 or 1.3)", s)
	}
}

// VersionName renders a tls.Version constant for logs and error messages.
func VersionName(v uint16) string {
	switch v {
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// CipherSuites returns the TLS 1.2 suites cloop offers, in preference order.
//
// Only AEAD suites with forward secrecy are listed: ECDHE key agreement plus
// AES-GCM or ChaCha20-Poly1305. Everything Go still supports for
// compatibility — CBC-mode suites (Lucky13, and a long tail of padding-oracle
// variants), static RSA key exchange (no forward secrecy, so one key
// compromise retroactively decrypts every recorded session) — is excluded.
//
// TLS 1.3 suites are deliberately absent: Go does not allow configuring them,
// and all three are AEAD-with-forward-secrecy by design.
func CipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
}

// ServerConfig loads a key pair and returns the tls.Config that `cloop ui`
// and `cloop serve` serve with.
//
// Both paths are required together: a certificate with no key (or the reverse)
// is a half-finished configuration, and starting in plaintext because one line
// of YAML was missing is exactly the silent downgrade this whole task exists
// to remove.
func ServerConfig(certFile, keyFile, minVersion string) (*tls.Config, error) {
	certFile, keyFile = strings.TrimSpace(certFile), strings.TrimSpace(keyFile)
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("tlsconf: both a certificate and a key are required (got cert=%q key=%q)",
			certFile, keyFile)
	}
	min, err := ParseMinVersion(minVersion)
	if err != nil {
		return nil, err
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("tlsconf: load key pair (cert=%s key=%s): %w", certFile, keyFile, err)
	}
	if warn := CheckKeyPermissions(keyFile); warn != "" {
		// Not fatal: refusing to start because of a permission bit would take
		// a working deployment down for a problem the operator can fix
		// without downtime. Loud, though — a world-readable server key is a
		// full impersonation of the control plane.
		fmt.Fprintf(os.Stderr, "warning: %s\n", warn)
	}
	return &tls.Config{
		Certificates:             []tls.Certificate{pair},
		MinVersion:               min,
		CipherSuites:             CipherSuites(),
		PreferServerCipherSuites: true,
		NextProtos:               []string{"h2", "http/1.1"},
	}, nil
}

// CheckKeyPermissions reports a warning string when a private key is readable
// by anyone but its owner, or "" when the mode is acceptable. Windows has no
// comparable bits, so it is skipped there.
func CheckKeyPermissions(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Sprintf("TLS private key %s has permissions %#o — it should be %#o (owner-only)",
			path, perm, KeyFileMode)
	}
	return ""
}

// ---------------------------------------------------------------------------
// SPKI pinning
// ---------------------------------------------------------------------------

// Fingerprint returns the pin for a certificate: "sha256:" followed by the
// base64 of SHA-256 over the DER-encoded SubjectPublicKeyInfo.
func Fingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	return FingerprintSPKI(cert.RawSubjectPublicKeyInfo)
}

// FingerprintSPKI computes a pin from a raw DER SubjectPublicKeyInfo.
func FingerprintSPKI(spki []byte) string {
	sum := sha256.Sum256(spki)
	return PinPrefix + base64.StdEncoding.EncodeToString(sum[:])
}

// ParsePin decodes a pin string into its raw 32-byte digest.
//
// Both standard and URL-safe base64 are accepted, with or without padding,
// because pins travel through shells, YAML files and QR codes on their way to
// an edge device and get mangled in predictable ways. The "sha256:" prefix is
// optional on input so a bare digest pasted from another tool still works; it
// is always present on output.
func ParsePin(pin string) ([]byte, error) {
	s := strings.TrimSpace(pin)
	if s == "" {
		return nil, fmt.Errorf("%w: empty", ErrNoPin)
	}
	if idx := strings.Index(s, ":"); idx >= 0 {
		alg := strings.ToLower(s[:idx])
		if alg != "sha256" {
			return nil, fmt.Errorf("%w: unsupported hash %q (want sha256)", ErrNoPin, s[:idx])
		}
		s = s[idx+1:]
	}
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if raw, err := enc.DecodeString(s); err == nil && len(raw) == sha256.Size {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("%w: %q is not a base64 SHA-256 digest", ErrNoPin, pin)
}

// PinSet is a parsed, comparable collection of acceptable server keys.
//
// More than one pin is supported so a certificate rotation onto a *new* key
// can be staged: publish both pins, roll the server, then retire the old one.
// Without that, any key rotation is a flag day across the whole fleet.
type PinSet struct {
	digests [][sha256.Size]byte
}

// ParsePinSet parses a comma- or whitespace-separated list of pins. An empty
// input yields an empty (disabled) set rather than an error, so callers can
// pass an unset flag straight through.
func ParsePinSet(s string) (PinSet, error) {
	var set PinSet
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	for _, f := range fields {
		raw, err := ParsePin(f)
		if err != nil {
			return PinSet{}, err
		}
		var d [sha256.Size]byte
		copy(d[:], raw)
		set.digests = append(set.digests, d)
	}
	// A non-empty input that yielded no pins — "," or a lone newline — is a
	// typo, not a request to disable pinning. Returning an empty set here
	// would connect unpinned and report "no pin" to an operator who believes
	// they passed one.
	if strings.TrimSpace(s) != "" && len(set.digests) == 0 {
		return PinSet{}, fmt.Errorf("%w: %q contains no pins", ErrNoPin, s)
	}
	return set, nil
}

// Empty reports whether pinning is disabled for this set.
func (p PinSet) Empty() bool { return len(p.digests) == 0 }

// Len returns how many distinct keys this set accepts.
func (p PinSet) Len() int { return len(p.digests) }

// Matches reports whether cert's public key is pinned by this set.
func (p PinSet) Matches(cert *x509.Certificate) bool {
	if cert == nil || p.Empty() {
		return false
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	for _, d := range p.digests {
		// Pins are public values, so a constant-time compare buys nothing
		// here; an attacker who can time this already knows the pin.
		if d == sum {
			return true
		}
	}
	return false
}

// String renders the set for logs and error messages.
func (p PinSet) String() string {
	out := make([]string, 0, len(p.digests))
	for _, d := range p.digests {
		out = append(out, PinPrefix+base64.StdEncoding.EncodeToString(d[:]))
	}
	return strings.Join(out, ",")
}

// VerifyPeerCertificate returns a callback for tls.Config of the same name, or
// nil when the set is empty (pinning disabled — normal PKI verification only).
//
// The callback checks the *leaf*, which is rawCerts[0] by TLS wire order. Go
// invokes it only after the standard chain and hostname checks have passed, so
// a match here means "valid certificate AND the expected key", never "invalid
// certificate we waved through".
func (p PinSet) VerifyPeerCertificate() func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if p.Empty() {
		return nil
	}
	set := p
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("%w: peer presented no certificate", ErrPinMismatch)
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("tlsconf: parse peer certificate: %w", err)
		}
		if set.Matches(leaf) {
			return nil
		}
		return fmt.Errorf("%w: peer key is %s, expected one of %s (subject %q)",
			ErrPinMismatch, Fingerprint(leaf), set.String(), leaf.Subject.CommonName)
	}
}

// PinFromCertFile computes the pin of the leaf certificate in a PEM file.
//
// The leaf is the first CERTIFICATE block, matching how tls.LoadX509KeyPair
// and every fullchain.pem in the wild are ordered: leaf first, then
// intermediates. Pinning an intermediate would be a defensible different
// policy, but silently picking one because it happened to sort first is not.
func PinFromCertFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("tlsconf: read certificate %s: %w", path, err)
	}
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("tlsconf: parse certificate in %s: %w", path, err)
		}
		return Fingerprint(cert), nil
	}
	return "", fmt.Errorf("tlsconf: no CERTIFICATE block in %s", path)
}

// ---------------------------------------------------------------------------
// Development certificate generation
// ---------------------------------------------------------------------------

// SelfSignedOptions parameterises GenerateSelfSigned.
type SelfSignedOptions struct {
	// Hosts are the DNS names and IP addresses the certificate is valid for.
	// Empty defaults to localhost plus the loopback addresses.
	Hosts []string
	// ValidFor is the certificate lifetime. Zero uses DefaultSelfSignedTTL.
	ValidFor time.Duration
	// Organization appears in the subject. Empty uses "cloop (development)".
	Organization string
	// Now overrides the clock for tests.
	Now func() time.Time
}

// DefaultSelfSignedTTL bounds a generated development certificate.
//
// One year rather than ten: a self-signed certificate that outlives the
// experiment it was made for is how "temporary" dev TLS ends up terminating
// production traffic. An expiry inside the horizon of the person who ran the
// command is the cheapest available forcing function.
const DefaultSelfSignedTTL = 365 * 24 * time.Hour

// GenerateSelfSigned writes a fresh P-256 key pair and self-signed certificate
// to certPath/keyPath and returns the certificate's pin.
//
// This exists for development and for air-gapped labs, not for the public
// Internet: a self-signed certificate is not trusted by any agent's root store,
// so the device must be given the certificate explicitly (see the agent's
// --ca-file). Both files are written through pkg/atomicfile, so a crash
// mid-write can never leave a certificate that does not match its key — and
// the key is 0600 from the moment it exists, never briefly world-readable.
func GenerateSelfSigned(certPath, keyPath string, opts SelfSignedOptions) (pin string, err error) {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	ttl := opts.ValidFor
	if ttl <= 0 {
		ttl = DefaultSelfSignedTTL
	}
	org := strings.TrimSpace(opts.Organization)
	if org == "" {
		org = "cloop (development)"
	}
	hosts := opts.Hosts
	if len(hosts) == 0 {
		hosts = []string{"localhost", "127.0.0.1", "::1"}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("tlsconf: generate key: %w", err)
	}

	serialMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialMax)
	if err != nil {
		return "", fmt.Errorf("tlsconf: generate serial: %w", err)
	}

	start := now().Add(-1 * time.Hour) // tolerate modest clock skew on edge devices
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{org}, CommonName: hosts[0]},
		NotBefore:             start,
		NotAfter:              start.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		// Self-signed leaves must be their own CA or Go's verifier rejects
		// them even when the operator has explicitly added them as a root
		// (CheckSignatureFrom refuses a non-CA parent).
		//
		// That makes the constraints below load-bearing. The obvious operator
		// shortcut is to install this certificate into the system trust store
		// rather than pass --ca-file — at which point an unconstrained CA
		// would let the hub's serving key mint a trusted certificate for any
		// domain on that machine. MaxPathLen 0 stops it signing further CAs,
		// and the name constraints added below confine it to the hosts it was
		// generated for.
		IsCA:           true,
		MaxPathLen:     0,
		MaxPathLenZero: true,
	}
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			continue
		}
		tmpl.DNSNames = append(tmpl.DNSNames, h)
	}
	// Confine the CA to exactly the names it serves. A verifier that honours
	// name constraints will refuse any certificate this key signs for anything
	// else, so installing it as a root cannot become a wildcard.
	tmpl.PermittedDNSDomainsCritical = true
	tmpl.PermittedDNSDomains = append(tmpl.PermittedDNSDomains, tmpl.DNSNames...)
	for _, ip := range tmpl.IPAddresses {
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		tmpl.PermittedIPRanges = append(tmpl.PermittedIPRanges,
			&net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return "", fmt.Errorf("tlsconf: create certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("tlsconf: marshal key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	for _, dir := range []string{filepath.Dir(certPath), filepath.Dir(keyPath)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", fmt.Errorf("tlsconf: create %s: %w", dir, err)
		}
	}
	// Key first: if the certificate write fails, a stray key is inert, whereas
	// a stray certificate with no key looks like a usable configuration.
	if err := atomicfile.Write(keyPath, keyPEM, KeyFileMode); err != nil {
		return "", fmt.Errorf("tlsconf: write key: %w", err)
	}
	if err := atomicfile.Write(certPath, certPEM, CertFileMode); err != nil {
		return "", fmt.Errorf("tlsconf: write certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", fmt.Errorf("tlsconf: parse generated certificate: %w", err)
	}
	return Fingerprint(cert), nil
}
