package hubca

// names.go gives a CA X.509 name constraints for the names the credential
// monitors are reached at (Task 20438).
//
// git trusts the hub's CA for the proxy's URL only (http.<url>.sslCAInfo), and
// a kubeconfig's certificate-authority-data for its one server, so neither
// lets the CA vouch for another host. Node.js does: NODE_EXTRA_CA_CERTS adds
// the CA to its trust for every connection the harness makes, which is how a
// relayed run verifies the model relay (Task 20435). A name-constrained CA
// keeps that wider trust honest — Go, OpenSSL (and so Node and curl) and
// GnuTLS refuse a certificate the CA signed for a name outside its permitted
// subtrees, so whoever holds its key can no longer present one for
// api.anthropic.com to a relayed harness, or for github.com to anything.
//
// The cost is the advertise URL. The constraints are part of the CA's
// certificate, so a monitor moved to a host they do not permit cannot be
// served from it: the leaf it would be issued fails every sandbox's check.
// Changing an advertise URL to a new host is therefore a CA rotation — stage
// with the new name as well as the old ones, wait for the runs dispatched
// before, activate, then move the URL. Only a CA a rotation mints is
// constrained; the one a control plane mints at its first start predates any
// list of names an operator has confirmed.

import (
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// noDNSName is the one DNS subtree a CA constrained to addresses alone
// permits: under the reserved .invalid top-level domain (RFC 6761), which no
// leaf the hub issues names. A constraint section with no DNS subtree at all
// would leave DNS names unconstrained.
const noDNSName = "invalid"

// noIPRange is, likewise, the one address range a CA constrained to DNS names
// alone permits: 0.0.0.0/32, which no monitor listens at.
var noIPRange = &net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(32, 32)}

// constrain gives a CA template name constraints permitting names and nothing
// else, marked critical as RFC 5280 requires.
func constrain(tmpl *x509.Certificate, names []string) error {
	dns, ips, err := splitSANs(names)
	if err != nil {
		return err
	}
	if len(dns)+len(ips) == 0 {
		return fmt.Errorf("hubca: name constraints need at least one name")
	}
	tmpl.PermittedDNSDomainsCritical = true
	tmpl.PermittedDNSDomains = dns
	if len(dns) == 0 {
		tmpl.PermittedDNSDomains = []string{noDNSName}
	}
	for _, ip := range ips {
		bits := 8 * len(ip)
		tmpl.PermittedIPRanges = append(tmpl.PermittedIPRanges, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	if len(ips) == 0 {
		tmpl.PermittedIPRanges = []*net.IPNet{noIPRange}
	}
	return nil
}

// Constrained reports whether a CA certificate carries name constraints.
func Constrained(c *x509.Certificate) bool {
	return c != nil && (len(c.PermittedDNSDomains) > 0 || len(c.PermittedIPRanges) > 0 ||
		len(c.ExcludedDNSDomains) > 0 || len(c.ExcludedIPRanges) > 0)
}

// ConstraintNames lists the names a CA's constraints permit, as an operator
// gave them; nil for a CA without constraints.
func ConstraintNames(c *x509.Certificate) []string {
	if !Constrained(c) {
		return nil
	}
	var out []string
	for _, d := range c.PermittedDNSDomains {
		if d != noDNSName {
			out = append(out, d)
		}
	}
	for _, r := range c.PermittedIPRanges {
		if r == nil || r.String() == noIPRange.String() {
			continue
		}
		if ones, bits := r.Mask.Size(); ones == bits {
			out = append(out, r.IP.String())
			continue
		}
		out = append(out, r.String())
	}
	norm, err := NormalizeSANs(out)
	if err != nil {
		return out
	}
	return norm
}

// Permitted splits names into those a CA certificate may vouch for and those
// its name constraints refuse. A CA without constraints permits every name.
func Permitted(c *x509.Certificate, names []string) (ok, refused []string) {
	norm, err := NormalizeSANs(names)
	if err != nil {
		return nil, names
	}
	if !Constrained(c) {
		return norm, nil
	}
	for _, n := range norm {
		if permits(c, n) {
			ok = append(ok, n)
		} else {
			refused = append(refused, n)
		}
	}
	return ok, refused
}

// permits applies a CA's constraints to one normalized name the way RFC 5280
// verifiers do for the subtrees cloop writes: a DNS name is permitted by a
// subtree equal to it or an ancestor of it, an address by a range holding it;
// a name of a kind the CA has no permitted subtree for is unconstrained.
func permits(c *x509.Certificate, name string) bool {
	if ip, err := netip.ParseAddr(name); err == nil {
		for _, r := range c.ExcludedIPRanges {
			if r.Contains(net.IP(ip.AsSlice())) {
				return false
			}
		}
		if len(c.PermittedIPRanges) == 0 {
			return true
		}
		addr := net.IP(ip.AsSlice())
		for _, r := range c.PermittedIPRanges {
			// A range of the other family never permits an address.
			if len(r.IP) == len(addr) && r.Contains(addr) {
				return true
			}
		}
		return false
	}
	for _, d := range c.ExcludedDNSDomains {
		if domainMatch(name, d) {
			return false
		}
	}
	if len(c.PermittedDNSDomains) == 0 {
		return true
	}
	for _, d := range c.PermittedDNSDomains {
		if domainMatch(name, d) {
			return true
		}
	}
	return false
}

// domainMatch is RFC 5280's dNSName subtree rule for the constraints cloop
// writes: the name itself, or any name beneath it.
func domainMatch(name, constraint string) bool {
	c := strings.ToLower(strings.TrimSuffix(constraint, "."))
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	if strings.HasPrefix(c, ".") {
		return strings.HasSuffix(n, c)
	}
	return n == c || strings.HasSuffix(n, "."+c)
}
