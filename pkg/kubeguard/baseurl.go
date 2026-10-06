package kubeguard

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// NormalizeBaseURL checks the base a sandbox's kubeconfig names as its server
// and returns it as scheme://host[:port]. It is the rule NewRegistry applies,
// exported so that config validation and `cloop hub doctor` ask it rather than
// restate it (Task 20387). The config's copy refused a path that this one
// let through; there is one rule now.
//
// It becomes the `server:` field of a kubeconfig, so it must be a bare base:
// kubectl appends "/api/v1/..." to it, and a path, query or fragment here
// would produce requests nothing serves.
//
// It must be https: the bearer token rides an Authorization header on every
// request, and a loopback listener is no exception, since a sandbox is by
// construction something that may share a host with whatever else is
// listening on loopback. The host must name a host — "https://:8444" has a
// non-empty Host and nowhere to dial — and a port must be one a client can
// dial.
func NormalizeBaseURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("kubeguard: base url is empty")
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("kubeguard: base url %q: %w", s, err)
	}
	switch {
	case u.Scheme != "https":
		return "", fmt.Errorf("kubeguard: base url must be https (got %q)", s)
	case u.Hostname() == "":
		return "", fmt.Errorf("kubeguard: base url has no host (got %q)", s)
	case !dialablePort(u.Port()):
		return "", fmt.Errorf("kubeguard: base url port %q is not a TCP port", u.Port())
	case u.User != nil:
		return "", errors.New("kubeguard: base url must not embed credentials")
	case strings.Trim(u.Path, "/") != "" || u.RawQuery != "" || u.Fragment != "":
		return "", fmt.Errorf("kubeguard: base url must be a bare base with no path, query or fragment (got %q)", s)
	}
	return u.Scheme + "://" + u.Host, nil
}

// dialablePort reports whether p, a URL's port, is absent or 1–65535.
func dialablePort(p string) bool {
	if p == "" {
		return true
	}
	n, err := strconv.Atoi(p)
	return err == nil && n >= 1 && n <= 65535
}

// DefaultListenAddr is where a hub binds the Kubernetes monitor when listen_addr is
// unset: loopback, on a port chosen at startup.
const DefaultListenAddr = "127.0.0.1:0"

// AdvertisedBaseURL is the base a hub points sandboxes at for a monitor bound
// to bound: advertise_url when it is set, otherwise the bound address itself —
// with an unspecified bind named as 127.0.0.1, because 0.0.0.0 is a bind
// address and never a destination. The result is what NewRegistry is given,
// and so is still subject to NormalizeBaseURL.
//
// The bound address is only correct when the sandbox shares the hub's network
// namespace. Falling back to it rather than refusing keeps the single-host
// case working with no configuration, and a wrong choice surfaces immediately
// as a kubectl that cannot connect rather than as a credential going somewhere
// it should not.
func AdvertisedBaseURL(advertise string, bound net.Addr) (string, error) {
	if s := strings.TrimSpace(advertise); s != "" {
		u, err := url.Parse(s)
		if err != nil {
			return "", fmt.Errorf("kubernetes monitor advertise_url %q: %w", s, err)
		}
		return strings.TrimSuffix(u.String(), "/"), nil
	}
	tcp, ok := bound.(*net.TCPAddr)
	if !ok {
		return "", fmt.Errorf("kubernetes monitor listener is not TCP (%T), so no URL can be "+
			"advertised; set executors.kube_guard.advertise_url", bound)
	}
	host := tcp.IP.String()
	if tcp.IP == nil || tcp.IP.IsUnspecified() {
		host = "127.0.0.1"
	}
	return "https://" + net.JoinHostPort(host, fmt.Sprint(tcp.Port)), nil
}
