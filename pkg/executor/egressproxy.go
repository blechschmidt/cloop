package executor

// egressproxy.go is the contract between the hub that hosts the egress proxy
// and the drivers that place the workloads it brokers for (Task 20378).
//
// The proxy session itself — the credential, the grant it stands on, the
// quotas — is the hub's business and reaches the workload as environment
// variables. What the hub cannot do from where it stands is make the address
// in those variables reachable: a container joins a bridge whose gateway only
// the engine knows, and a sandbox behind a firewall reaches nothing the
// firewall does not name. So the Spec carries the route, and the driver that
// builds the sandbox network finishes the job.

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// EgressProxyRoute is how one workload reaches the hub's egress proxy.
type EgressProxyRoute struct {
	// Host is the host the workload's proxy variables name: a name the driver
	// pins (Gateway), or the address or name the workload dials as it is.
	Host string `json:"host"`
	// Port is the proxy's port.
	Port int `json:"port"`
	// Gateway asks the driver to resolve Host to the gateway of the network
	// the sandbox joins, and to pin that resolution inside the sandbox.
	//
	// It is how a container on the hub's own engine reaches a proxy that
	// listens on every host interface: the host is at the gateway address of
	// whichever bridge the sandbox lands on, and on an --internal bridge that
	// address is the only one off the sandbox it can route to at all.
	Gateway bool `json:"gateway,omitempty"`
}

// Validate checks the route's shape. It is called by Spec.Validate, so a
// route arriving at a driver — possibly over the wire from another machine —
// is checked where it is used rather than trusted from the sender.
func (r EgressProxyRoute) Validate() error {
	host := strings.TrimSpace(r.Host)
	if host == "" {
		return fmt.Errorf("%w: egress_proxy.host is empty", ErrInvalidSpec)
	}
	if r.Port < 1 || r.Port > 65535 {
		return fmt.Errorf("%w: egress_proxy.port %d is not a port (1-65535)", ErrInvalidSpec, r.Port)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		if r.Gateway {
			// A pin maps a *name* to the gateway; pinning an address literal
			// would mean an /etc/hosts line that resolves nothing.
			return fmt.Errorf("%w: egress_proxy.host %q is an address, so there is no name to pin "+
				"to the gateway", ErrInvalidSpec, host)
		}
		return nil
	}
	if !validRouteHostname(host) {
		return fmt.Errorf("%w: egress_proxy.host %q is neither an address nor a host name", ErrInvalidSpec, host)
	}
	return nil
}

// Addr returns the route's host as an address, when it is one.
func (r EgressProxyRoute) Addr() (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(r.Host))
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// String renders the route as host:port, for messages.
func (r EgressProxyRoute) String() string {
	return net.JoinHostPort(strings.TrimSpace(r.Host), fmt.Sprint(r.Port))
}

// validRouteHostname is the RFC 1123 host name shape: dot-separated labels of
// letters, digits and hyphens, none starting or ending with a hyphen. The name
// ends up in a runtime's --add-host flag and in /etc/hosts, so nothing else may.
func validRouteHostname(h string) bool {
	if len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(h, "."), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
			default:
				return false
			}
		}
	}
	return true
}
