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
	"strconv"
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

// The routing rules below decide how a workload of each kind reaches the
// hub's egress proxy. They were methods of the hub's proxy service until Task
// 20387 moved them here, so that `cloop hub doctor` reports the route the hub
// will choose — by calling these — rather than its own guess at one. The
// doctor's guess had already drifted: it accepted a loopback advertise_addr on
// a Kubernetes hub that was not in strict mode, and recommended a Service name
// the hub refuses.

// EgressGatewayHost is the name a container sandbox's proxy URL uses for the
// hub. The container driver pins it to the gateway of whichever bridge the
// sandbox joins; podman already resolves it to the host in every container.
const EgressGatewayHost = "host.containers.internal"

// EgressAdvertised resolves executors.egress.advertise_addr against the port
// the proxy is bound to: a bare host, or a port of 0, takes the bound port,
// which is what lets an operator bind an ephemeral port and still advertise a
// name. "" when advertise is unset.
func EgressAdvertised(advertise string, boundPort int) (string, error) {
	a := strings.TrimSpace(advertise)
	if a == "" {
		return "", nil
	}
	host, port, err := net.SplitHostPort(a)
	if err != nil {
		host, port = strings.Trim(a, "[]"), ""
	}
	if host == "" {
		return "", fmt.Errorf("executors.egress.advertise_addr %q names no host", a)
	}
	if port == "" || port == "0" {
		port = fmt.Sprint(boundPort)
	}
	return net.JoinHostPort(host, port), nil
}

// ContainerEgressRoute is how a container sandbox on the hub's own engine
// reaches a proxy bound to bound — or why it cannot, the reason first, then
// the remedy.
func ContainerEgressRoute(bound *net.TCPAddr) (route EgressProxyRoute, why, remedy string) {
	ip := bound.IP
	switch {
	case ip != nil && ip.IsLoopback():
		return EgressProxyRoute{}, fmt.Sprintf("executors.egress.listen_addr binds %s, a loopback "+
				"address no container sandbox can reach", bound),
			fmt.Sprintf("Bind executors.egress.listen_addr to 0.0.0.0:%d — the per-session credential is what "+
				"protects the proxy, on every interface — so sandboxes reach it at their bridge's gateway.", bound.Port)
	case ip == nil || ip.IsUnspecified():
		// Every host interface, so the gateway of whichever bridge the
		// sandbox joins — an --internal one included — answers.
		return EgressProxyRoute{Host: EgressGatewayHost, Port: bound.Port, Gateway: true}, "", ""
	default:
		// One host address: reachable from a bridge with a route off it,
		// and from an --internal bridge only if it is that bridge's own
		// gateway. The driver opens it in a ruleset either way.
		return EgressProxyRoute{Host: ip.String(), Port: bound.Port}, "", ""
	}
}

// The remedies for an AdvertisedEgressRoute refusal, by who it refuses.
const (
	EgressRemedyPods = "Set executors.egress.advertise_addr to the address Pods reach the hub's proxy at — its " +
		"Service's cluster IP and port; a name is refused, since a Pod's NetworkPolicy opens addresses."
	EgressRemedyDevices = "Set executors.egress.advertise_addr to an address the device reaches the hub at, " +
		"with the proxy's port."
)

// AdvertisedEgressRoute is advertised — EgressAdvertised's result — as the
// route a workload on another machine is given, or why it cannot be one. who
// names those workloads in the reason ("Pods", "a device"), and bound is the
// proxy's bound address, named when nothing is advertised.
func AdvertisedEgressRoute(advertised, bound, who string) (EgressProxyRoute, string) {
	if advertised == "" {
		return EgressProxyRoute{}, fmt.Sprintf("executors.egress.advertise_addr is not set, and the "+
			"proxy's bound address %s is not one %s can reach", bound, who)
	}
	host, portStr, err := net.SplitHostPort(advertised)
	if err != nil {
		return EgressProxyRoute{}, fmt.Sprintf("executors.egress.advertise_addr %q is not host:port", advertised)
	}
	port, _ := strconv.Atoi(portStr)
	if local := HubLocalHost(host); local != "" {
		return EgressProxyRoute{}, fmt.Sprintf("executors.egress.advertise_addr names %s, %s, which %s "+
			"cannot reach", host, local, who)
	}
	route := EgressProxyRoute{Host: host, Port: port}
	if err := route.Validate(); err != nil {
		return EgressProxyRoute{}, err.Error()
	}
	return route, ""
}

// HubLocalHost says why a host only means something on the hub's own machine
// or network, or "" when it may be reachable from elsewhere.
//
// A device cannot be asked whether it can reach an address before the run
// starts, so this is a judgement — and it errs on the side of saying so: an
// address it lets through that the device cannot reach fails the run's first
// request, which the journal row at dispatch names.
func HubLocalHost(host string) string {
	h := strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	switch {
	case h == "localhost" || strings.HasSuffix(h, ".localhost"):
		return "the loopback name"
	case h == EgressGatewayHost || h == "host.docker.internal":
		return "a container runtime's name for its own host"
	case strings.HasSuffix(h, ".svc") || strings.HasSuffix(h, ".cluster.local"):
		return "a Kubernetes cluster-internal name"
	}
	if a, err := netip.ParseAddr(h); err == nil {
		a = a.Unmap()
		switch {
		case a.IsLoopback():
			return "a loopback address"
		case a.IsUnspecified():
			return "the unspecified address"
		case a.IsLinkLocalUnicast():
			return "a link-local address"
		}
	}
	return ""
}
