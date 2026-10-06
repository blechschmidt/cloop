package hubdoctor

// The git proxy and the Kubernetes monitor are started the same way, by
// startGitProxy and startKubeGuard in pkg/ui: load the TLS material through
// tlsconf.ServerConfig, bind listen_addr, take the base sandboxes are pointed
// at from <pkg>.AdvertisedBaseURL, and hand it to <pkg>.NewRegistry, whose
// NormalizeBaseURL refuses what no sandbox can use. Any refusal leaves the
// section enabled and the listener absent, and the hub then refuses the work
// that needed it rather than hand the credential over.
//
// These helpers run those functions, in that order, so the doctor's verdict on
// "would it start, and where would it point sandboxes" is the hub's verdict.
// They used to be restated here: an os.Stat in place of loading the key pair —
// which passed a certificate and key from different pairs — and a substring
// match in place of parsing the advertised host (Task 20387).

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// proxyTLS reports whether the TLS material a proxy section names loads the
// way its listener loads it. section is the config key ("executors.git_proxy"),
// refusal says what the hub does when the listener does not start.
func proxyTLS(check, title, section, certFile, keyFile, minVersion, refusal string, add addFn) bool {
	_, permWarning, err := tlsconf.LoadServerConfig(certFile, keyFile, minVersion)
	if err != nil {
		add(Finding{
			Check: check, Title: title, Severity: SeverityFail,
			Message: fmt.Sprintf("the listener will not start: %v — %s is enabled, so %s",
				err, section, refusal),
			Remediation: fmt.Sprintf("Point %s.cert_file and key_file at a matching pair (`cloop hub bootstrap` "+
				"generates one) with a supported min_tls_version, or set enabled: false", section),
		})
		return false
	}
	if permWarning != "" {
		add(Finding{
			Check: check, Title: title, Severity: SeverityWarn,
			Message:     permWarning,
			Remediation: "Run: chmod 600 " + strings.TrimSpace(keyFile),
		})
	}
	return true
}

// proxyEndpoint is the base a starting proxy points sandboxes at.
type proxyEndpoint struct {
	// base is the URL sandboxes are given, as the registry normalises it.
	base string
	// host is base's host, for judging whether a sandbox can reach it.
	host string
	// fromBind reports that advertise_url is unset and base is the bound
	// address, the hub's fallback.
	fromBind bool
	// ephemeral reports that the bound port is chosen at startup, so base
	// carries no port a doctor run can know or dial.
	ephemeral bool
}

// resolveProxyEndpoint computes the base the hub would advertise, with the
// subsystem's own functions: advertised is <pkg>.AdvertisedBaseURL, normalize
// <pkg>.NormalizeBaseURL, defaultListen <pkg>.DefaultListenAddr.
//
// With advertise_url unset the hub advertises its bound address, which the
// doctor cannot bind to find out. It resolves listen_addr instead — an IP
// literal, or a host name when it may make network requests — which yields the
// same address except for a port chosen at startup.
func resolveProxyEndpoint(advertise, listen, defaultListen string, offline bool,
	advertised func(string, net.Addr) (string, error), normalize func(string) (string, error)) (proxyEndpoint, error) {
	if strings.TrimSpace(advertise) != "" {
		raw, err := advertised(advertise, nil)
		if err != nil {
			return proxyEndpoint{}, err
		}
		base, err := normalize(raw)
		if err != nil {
			return proxyEndpoint{}, err
		}
		return proxyEndpoint{base: base, host: hostOf(base)}, nil
	}

	addr := strings.TrimSpace(listen)
	if addr == "" {
		addr = defaultListen
	}
	bound, err := boundAddr(addr, offline)
	if err != nil {
		return proxyEndpoint{}, err
	}
	raw, err := advertised("", bound)
	if err != nil {
		return proxyEndpoint{}, err
	}
	ep := proxyEndpoint{base: raw, host: hostOf(raw), fromBind: true, ephemeral: bound.Port == 0}
	if !ep.ephemeral {
		// A port chosen at startup is filled in before the registry sees
		// the base; one written into listen_addr is checked as written.
		if ep.base, err = normalize(raw); err != nil {
			return proxyEndpoint{}, err
		}
	}
	return ep, nil
}

// boundAddr is the address net.Listen would bind for addr. A host name is
// resolved only when the run may make network requests.
func boundAddr(addr string, offline bool) (*net.TCPAddr, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("listen_addr %q is not host:port: %w", addr, err)
	}
	if host != "" && net.ParseIP(host) == nil && offline {
		return nil, fmt.Errorf("listen_addr %q names a host, which --offline does not resolve", addr)
	}
	tcp, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen_addr %q: %w", addr, err)
	}
	return tcp, nil
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// onlyThisHost reports whether a sandbox handed host reaches this machine and
// nothing else: a loopback name or address by the rule the hub's own endpoint
// checks use (tlsconf.IsLoopbackHost), or the unspecified address, which a
// sandbox told to dial dials itself.
func onlyThisHost(host string) bool {
	if tlsconf.IsLoopbackHost(host) {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsUnspecified()
}

// proxyLabels names one proxy's findings and settings in prose.
type proxyLabels struct {
	advertiseCheck, advertiseTitle string
	reachCheck, reachTitle         string
	what                           string // "the git proxy"
	key                            string // "executors.git_proxy.advertise_url"
	consequence                    string // what a sandbox that cannot reach it sees
	example                        string // a URL a sandbox can typically reach
}

// reportProxyEndpoint says whether the base a proxy points sandboxes at is one
// they could use, and dials it. resolveErr is resolveProxyEndpoint's failure
// to determine the bound address, if any. likely says something on this hub
// would use the proxy from another network namespace, which is what turns a
// loopback address from fine into broken.
func reportProxyEndpoint(ctx context.Context, opts Options, ep proxyEndpoint, resolveErr error,
	likely bool, l proxyLabels, add addFn) {
	if resolveErr != nil {
		add(Finding{
			Check: l.advertiseCheck, Title: l.advertiseTitle, Severity: SeverityWarn,
			Message: fmt.Sprintf("%s is not set, and the address sandboxes would be pointed at instead "+
				"could not be determined: %v", l.key, resolveErr),
			Remediation: fmt.Sprintf("Set %s to a URL the sandbox can reach, such as %s", l.key, l.example),
		})
		return
	}

	shown := ep.base
	if ep.ephemeral {
		shown = "https://" + ep.host + " on a port chosen at startup"
	}
	switch {
	case ep.fromBind && onlyThisHost(ep.host) && likely:
		add(Finding{
			Check: l.advertiseCheck, Title: l.advertiseTitle, Severity: SeverityWarn,
			Message: fmt.Sprintf("not set, so sandboxes are pointed at the bound address, %s — reachable "+
				"only by a sandbox that shares the hub's network namespace; for a Pod or an edge device %s",
				shown, l.consequence),
			Remediation: fmt.Sprintf("Set %s to a URL the sandbox can reach (a Service name for "+
				"Kubernetes, a hub address the edge device routes to)", l.key),
		})
	case !ep.fromBind && onlyThisHost(ep.host) && likely:
		add(Finding{
			Check: l.advertiseCheck, Title: l.advertiseTitle, Severity: SeverityWarn,
			Message: fmt.Sprintf("advertises %s, which names this machine only — for a Pod or an edge "+
				"device %s", shown, l.consequence),
			Remediation: fmt.Sprintf("Set %s to an address reachable from the sandbox's network, not "+
				"from the hub's", l.key),
		})
	}

	// Dialling it is separate from judging it, and reported separately, because
	// the two answer different questions: the judgement asks whether the value
	// is the kind of address a sandbox could use, this asks whether anything is
	// actually there. A loopback URL fails the first and passes the second,
	// which is exactly the combination worth seeing spelled out.
	if ep.ephemeral {
		return // no port to dial until the hub has bound one
	}
	target, err := dialTarget(ep.base)
	if err != nil {
		add(Finding{
			Check: l.reachCheck, Title: l.reachTitle, Severity: SeverityWarn,
			Message: fmt.Sprintf("%s %q could not be turned into an address to dial: %v",
				l.key, ep.base, err),
			Remediation: fmt.Sprintf("Set %s to an absolute URL such as %s", l.key, l.example),
		})
		return
	}
	add(reachFinding(l.reachCheck, l.reachTitle, l.what, l.key, probeReach(ctx, opts, target), opts))
}
