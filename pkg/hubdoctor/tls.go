package hubdoctor

// Transport checks: is the certificate this hub serves one that will still
// work tomorrow, and for the name people actually use?
//
// Certificate problems are the class of failure that is invisible right up
// until it is total. An expiring certificate is fine, fine, fine, and then
// every enrolled edge device in the fleet stops reconnecting at once; a SAN
// that omits the external hostname works for whoever generated it on localhost
// and for nobody else. Both are trivially detectable in advance and neither is
// detectable *at* the moment they break, because by then the hub is unreachable
// by the tools that would tell you why.
//
// What the checks do NOT do is dial the hub. A doctor run happens on the host,
// often before the listener is up, and "connect to yourself and inspect the
// handshake" answers a question about the proxy in front rather than about the
// material configured here. Reading the files is the narrower and more useful
// answer: it is the same material `cloop ui` will load.

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// certExpiryWarning is how long before expiry a certificate becomes a warning.
// Thirty days is the usual renewal window for an ACME-issued certificate, so
// crossing it means automated renewal has already had a chance and did not
// take it.
const certExpiryWarning = 30 * 24 * time.Hour

func checkTLS(cfg *config.Config, opts Options, add addFn) {
	certFile := strings.TrimSpace(cfg.UI.TLS.CertFile)
	keyFile := strings.TrimSpace(cfg.UI.TLS.KeyFile)
	external := strings.TrimSpace(cfg.UI.ExternalURL)

	if certFile == "" && keyFile == "" {
		checkProxyTermination(external, add)
		return
	}
	// A half-configuration is refused at startup, so a hub in this state
	// never boots. Reporting it here is what turns "the service will not
	// start" into "you set one of two required fields".
	if err := cfg.UI.TLS.Validate(); err != nil {
		add(Finding{
			Check: "tls.material", Title: "TLS material", Severity: SeverityFail,
			Message:     err.Error(),
			Remediation: "Set both ui.tls.cert_file and ui.tls.key_file, or neither",
		})
		return
	}

	// LoadX509KeyPair is the same call the server makes, so a pass here means
	// the server will get past this point too — including the check that the
	// private key actually belongs to the leaf certificate, which is a
	// mismatch no amount of reading the two files separately would catch.
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		add(Finding{
			Check: "tls.material", Title: "TLS material", Severity: SeverityFail,
			Message:     fmt.Sprintf("certificate and key could not be loaded as a pair: %v", err),
			Remediation: "Regenerate with `cloop hub tls-init --force`, or point ui.tls at a matching pair",
		})
		return
	}
	add(Finding{
		Check: "tls.material", Title: "TLS material", Severity: SeverityPass,
		Message: fmt.Sprintf("%s and its key load as a matching pair", certFile),
	})

	if msg := tlsconf.CheckKeyPermissions(keyFile); msg != "" {
		add(Finding{
			Check: "tls.key_permissions", Title: "Private key permissions", Severity: SeverityWarn,
			Message:     msg,
			Remediation: fmt.Sprintf("Run: chmod 600 %s", keyFile),
		})
	} else {
		add(Finding{
			Check: "tls.key_permissions", Title: "Private key permissions", Severity: SeverityPass,
			Message: "the private key is not group- or world-readable",
		})
	}

	chain := parseChain(certFile)
	if len(chain) == 0 {
		// LoadX509KeyPair succeeded, so this only happens if the file
		// changed underneath us. Report rather than assume.
		add(Finding{
			Check: "tls.chain", Title: "Certificate chain", Severity: SeverityWarn,
			Message:     "the certificate file contains no PEM CERTIFICATE block that could be re-read",
			Remediation: "Confirm " + certFile + " is a PEM chain with the leaf first",
		})
		return
	}
	leaf := chain[0]
	checkChain(chain, certFile, add)
	checkExpiry(leaf, opts.now(), add)
	checkSANs(leaf, external, add)
	checkMinVersion(cfg.UI.TLS.MinVersion, add)
}

// checkProxyTermination handles the no-certificate case, which is a correct
// configuration behind a proxy and a broken one otherwise.
//
// The X-Forwarded-Proto note is the part worth surfacing: without it every
// session cookie a proxied hub issues is missing the Secure attribute, and the
// symptom of that is not an error anywhere — it is a cookie that a downgrade
// attack can replay.
func checkProxyTermination(external string, add addFn) {
	if external == "" {
		add(Finding{
			Check: "tls.termination", Title: "TLS termination", Severity: SeverityWarn,
			Message: "no ui.tls certificate and no ui.external_url: this hub serves plaintext " +
				"and does not know whether something in front of it does not",
			Remediation: "Run `cloop hub tls-init` for a development certificate, or set ui.external_url " +
				"if a proxy terminates TLS",
		})
		return
	}
	u, err := url.Parse(external)
	if err != nil || u.Host == "" {
		add(Finding{
			Check: "tls.termination", Title: "TLS termination", Severity: SeverityFail,
			Message:     fmt.Sprintf("ui.external_url %q is not a URL, so the transport could not be assessed", external),
			Remediation: "Set ui.external_url to e.g. https://cloop.example.com",
		})
		return
	}
	if strings.EqualFold(u.Scheme, "https") {
		add(Finding{
			Check: "tls.termination", Title: "TLS termination", Severity: SeverityPass,
			Message: "no certificate here; TLS is expected to terminate at a proxy in front of " + u.Host,
			Details: map[string]any{
				"requires": "the proxy MUST set X-Forwarded-Proto: https, or session cookies lose the Secure attribute",
			},
		})
		return
	}
	if isLoopbackHost(u.Hostname()) {
		add(Finding{
			Check: "tls.termination", Title: "TLS termination", Severity: SeverityPass,
			Message: "plaintext to loopback only",
		})
		return
	}
	add(Finding{
		Check: "tls.termination", Title: "TLS termination", Severity: SeverityFail,
		Message: fmt.Sprintf("ui.external_url is %s: sessions, enrollment tokens and API tokens "+
			"cross the network in the clear", external),
		Remediation: "Terminate TLS at a proxy and change ui.external_url to https://, or set ui.tls",
	})
}

// parseChain reads every CERTIFICATE block from a PEM file, leaf first.
func parseChain(path string) []*x509.Certificate {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []*x509.Certificate
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
			continue
		}
		out = append(out, cert)
	}
	return out
}

// checkChain reports whether intermediates were shipped, and whether they are
// in the order TLS requires.
//
// A missing intermediate is the classic "works in my browser, fails in curl and
// in every Go client" bug: browsers cache intermediates from previous sites and
// paper over it, while an executor agent dialling in for the first time has
// nothing cached and simply cannot build a path.
func checkChain(chain []*x509.Certificate, certFile string, add addFn) {
	leaf := chain[0]
	if len(chain) == 1 {
		if isSelfSigned(leaf) {
			add(Finding{
				Check: "tls.chain", Title: "Certificate chain", Severity: SeverityWarn,
				Message: "self-signed: no system trust store accepts this certificate, so every " +
					"agent must be given it explicitly",
				Remediation: "Distribute it with `cloop executor agent --ca-file`, or install a CA-issued " +
					"certificate for production",
			})
			return
		}
		add(Finding{
			Check: "tls.chain", Title: "Certificate chain", Severity: SeverityWarn,
			Message: "only the leaf certificate is present; clients with no cached intermediate " +
				"will fail to build a trust path",
			Remediation: "Append the issuing intermediate(s) to " + certFile + " (leaf first)",
		})
		return
	}
	for i := 0; i < len(chain)-1; i++ {
		// RawIssuer/RawSubject rather than the pkix.Name strings: DN equality
		// is defined over the encoded bytes, and two DNs that render
		// identically can still be different names.
		if !bytes.Equal(chain[i].RawIssuer, chain[i+1].RawSubject) {
			add(Finding{
				Check: "tls.chain", Title: "Certificate chain", Severity: SeverityFail,
				Message: fmt.Sprintf("chain is out of order at position %d: %q is not issued by %q",
					i, chain[i].Subject.CommonName, chain[i+1].Subject.CommonName),
				Remediation: "Reorder " + certFile + " so each certificate is followed by its issuer, leaf first",
			})
			return
		}
	}
	add(Finding{
		Check: "tls.chain", Title: "Certificate chain", Severity: SeverityPass,
		Message: fmt.Sprintf("%d certificate(s), each followed by its issuer", len(chain)),
	})
}

func isSelfSigned(c *x509.Certificate) bool {
	return c.Issuer.String() == c.Subject.String()
}

// checkExpiry reports validity against the injected clock.
func checkExpiry(leaf *x509.Certificate, now time.Time, add addFn) {
	switch {
	case now.Before(leaf.NotBefore):
		add(Finding{
			Check: "tls.expiry", Title: "Certificate validity", Severity: SeverityFail,
			Message: fmt.Sprintf("not valid until %s — every TLS handshake will be rejected until then",
				leaf.NotBefore.Format(time.RFC3339)),
			Remediation: "Check this host's clock, or reissue the certificate",
		})
	case now.After(leaf.NotAfter):
		add(Finding{
			Check: "tls.expiry", Title: "Certificate validity", Severity: SeverityFail,
			Message: fmt.Sprintf("expired %s ago (on %s); no client will connect",
				now.Sub(leaf.NotAfter).Round(time.Hour), leaf.NotAfter.Format("2006-01-02")),
			Remediation: "Renew the certificate, or regenerate with `cloop hub tls-init --force`",
		})
	case leaf.NotAfter.Sub(now) < certExpiryWarning:
		add(Finding{
			Check: "tls.expiry", Title: "Certificate validity", Severity: SeverityWarn,
			Message: fmt.Sprintf("expires in %s (on %s); enrolled agents stop reconnecting at that moment",
				leaf.NotAfter.Sub(now).Round(time.Hour), leaf.NotAfter.Format("2006-01-02")),
			Remediation: "Renew now. Reusing the same key keeps the SPKI pin valid and needs no re-enrollment",
		})
	default:
		add(Finding{
			Check: "tls.expiry", Title: "Certificate validity", Severity: SeverityPass,
			Message: fmt.Sprintf("valid for another %d day(s), until %s",
				int(leaf.NotAfter.Sub(now).Hours()/24), leaf.NotAfter.Format("2006-01-02")),
		})
	}
}

// checkSANs verifies the certificate covers the hostname operators and agents
// actually use — which is ui.external_url, not whatever was on the machine when
// the certificate was generated.
func checkSANs(leaf *x509.Certificate, external string, add addFn) {
	names := append([]string{}, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		names = append(names, ip.String())
	}
	if len(names) == 0 {
		add(Finding{
			Check: "tls.san", Title: "Certificate names", Severity: SeverityFail,
			Message: "the certificate has no subjectAltName; Go and every modern browser reject " +
				"a certificate matched only by its common name",
			Remediation: "Reissue with SANs, e.g. `cloop hub tls-init --host <your-host> --force`",
		})
		return
	}
	if external == "" {
		add(Finding{
			Check: "tls.san", Title: "Certificate names", Severity: SeverityWarn,
			Message: "valid for " + strings.Join(names, ", ") +
				", but ui.external_url is unset so the name that matters could not be checked",
			Remediation: "Set ui.external_url to the URL a browser types",
		})
		return
	}
	u, err := url.Parse(external)
	if err != nil || u.Host == "" {
		add(Finding{
			Check: "tls.san", Title: "Certificate names", Severity: SeverityWarn,
			Message:     fmt.Sprintf("ui.external_url %q is not a URL, so the SAN list could not be checked", external),
			Remediation: "Set ui.external_url to e.g. https://cloop.example.com",
		})
		return
	}
	host := u.Hostname()
	if err := leaf.VerifyHostname(host); err != nil {
		add(Finding{
			Check: "tls.san", Title: "Certificate names", Severity: SeverityFail,
			Message: fmt.Sprintf("the certificate is not valid for %q (it covers %s), so browsers and "+
				"agents will reject it", host, strings.Join(names, ", ")),
			Remediation: fmt.Sprintf("Reissue including that name: `cloop hub tls-init --host %s --force`", host),
		})
		return
	}
	add(Finding{
		Check: "tls.san", Title: "Certificate names", Severity: SeverityPass,
		Message: fmt.Sprintf("valid for %s (%s)", host, strings.Join(names, ", ")),
	})
}

// checkMinVersion reports the negotiated floor. ParseMinVersion rejects 1.0 and
// 1.1 outright, so an invalid value is a hub that will not start.
func checkMinVersion(raw string, add addFn) {
	v, err := tlsconf.ParseMinVersion(raw)
	if err != nil {
		add(Finding{
			Check: "tls.min_version", Title: "TLS floor", Severity: SeverityFail,
			Message:     err.Error(),
			Remediation: `Set ui.tls.min_version to "1.2" or "1.3"`,
		})
		return
	}
	label := "1.2"
	sev := SeverityPass
	if v >= tls.VersionTLS13 {
		label = "1.3"
	}
	add(Finding{
		Check: "tls.min_version", Title: "TLS floor", Severity: sev,
		Message: "minimum negotiated version is TLS " + label,
	})
}

// hostPort is a small helper for registry probes elsewhere in the package; it
// lives here because it is about network addressing, not about certificates.
func hostPort(host string, defaultPort string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, defaultPort)
}
