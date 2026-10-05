package secretbrokertest

// tlsca.go is a throwaway certificate authority (Task 20383), for tests whose
// processes must verify one another: a hub process that reaches a forge
// answering as github.com through a CONNECT proxy, a sandbox's git trusting
// the hub's git proxy. Everything it issues dies with the test.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CA issues leaf certificates for loopback test servers.
type CA struct {
	// CertPEM is the CA certificate, for a trust store.
	CertPEM []byte
	// CertFile is CertPEM written to a file, for SSL_CERT_FILE, GIT_SSL_CAINFO
	// or a config's ca_file.
	CertFile string

	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	dir  string
}

// NewCA returns a CA valid for a day.
func NewCA(t testing.TB) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "cloop test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ca := &CA{CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert: cert, key: key, dir: t.TempDir()}
	ca.CertFile = filepath.Join(ca.dir, "ca.pem")
	if err := os.WriteFile(ca.CertFile, ca.CertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	return ca
}

// Leaf is an issued certificate and its key.
type Leaf struct {
	TLS      tls.Certificate
	CertFile string
	KeyFile  string
}

// Issue returns a server certificate for hosts — names and IP literals —
// signed by the CA, also written to files for a config's cert_file/key_file.
func (ca *CA) Issue(t testing.TB, hosts ...string) Leaf {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: hosts[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	leaf := Leaf{TLS: pair, CertFile: filepath.Join(dir, "cert.pem"), KeyFile: filepath.Join(dir, "key.pem")}
	if err := os.WriteFile(leaf.CertFile, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leaf.KeyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return leaf
}

// Pool returns a cert pool trusting the CA.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.cert)
	return p
}
