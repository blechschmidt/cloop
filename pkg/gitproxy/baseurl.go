package gitproxy

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// NormalizeBaseURL checks the public base a sandbox clones from and returns it
// as scheme://host[:port]. It is the rule NewRegistry applies, exported so
// that config validation and `cloop hub doctor` ask it rather than restate it
// (Task 20387): three copies of one rule were three chances to disagree about
// which advertise_url starts a proxy.
//
// https is required for the same reason pkg/executor requires it of a
// workspace repo: the sandbox presents its session token as an Authorization
// header on every request, and over cleartext that token is published rather
// than delivered. A loopback proxy is not an exception — a sandbox is, by
// construction, something that might be sharing the host.
//
// The host must name a host, not merely be non-empty: "https://:8443" has a
// Host of ":8443", and every sandbox handed it would dial nowhere. A port must
// be one a client can dial.
func NormalizeBaseURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("gitproxy: base URL is empty")
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("gitproxy: base URL %q is not a URL: %w", s, err)
	}
	switch {
	case u.Scheme != "https":
		return "", fmt.Errorf("gitproxy: base URL must be https, got scheme %q", u.Scheme)
	case u.Hostname() == "":
		return "", errors.New("gitproxy: base URL has no host")
	case !dialablePort(u.Port()):
		return "", fmt.Errorf("gitproxy: base URL port %q is not a TCP port", u.Port())
	case u.User != nil:
		return "", errors.New("gitproxy: base URL must not embed credentials")
	case strings.Trim(u.Path, "/") != "":
		return "", fmt.Errorf("gitproxy: base URL must have no path, got %q", u.Path)
	case u.RawQuery != "" || u.Fragment != "":
		return "", errors.New("gitproxy: base URL must not carry a query or fragment")
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

// DefaultListenAddr is where a hub binds the git proxy when listen_addr is
// unset: loopback, on a port chosen at startup.
const DefaultListenAddr = "127.0.0.1:0"

// AdvertisedBaseURL is the base a hub points sandboxes at for a proxy bound to
// bound: advertise_url when it is set, otherwise the bound address itself —
// with an unspecified bind named as 127.0.0.1, because 0.0.0.0 is a bind
// address and never a destination. The result is what NewRegistry is given,
// and so is still subject to NormalizeBaseURL.
//
// The bound address is only correct when the sandbox shares the hub's network
// namespace, which is why an operator running containers, Pods or edge devices
// sets advertise_url. Falling back to it anyway — rather than refusing — keeps
// the single-host case working with no configuration, and a wrong choice here
// surfaces as a fetch that cannot connect rather than as a credential going
// somewhere it should not.
func AdvertisedBaseURL(advertise string, bound net.Addr) (string, error) {
	if s := strings.TrimSpace(advertise); s != "" {
		u, err := url.Parse(s)
		if err != nil {
			return "", fmt.Errorf("git proxy advertise_url %q: %w", s, err)
		}
		return strings.TrimSuffix(u.String(), "/"), nil
	}
	tcp, ok := bound.(*net.TCPAddr)
	if !ok {
		return "", fmt.Errorf("git proxy listener is not TCP (%T), so no URL can be advertised; "+
			"set executors.git_proxy.advertise_url", bound)
	}
	host := tcp.IP.String()
	if tcp.IP == nil || tcp.IP.IsUnspecified() {
		// Naming loopback is the honest reading of "wherever this hub is",
		// and an operator whose sandboxes are elsewhere has to say where.
		host = "127.0.0.1"
	}
	return "https://" + net.JoinHostPort(host, fmt.Sprint(tcp.Port)), nil
}
