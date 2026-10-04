package container

// egressproxy.go makes the hub's egress proxy reachable from a sandbox that
// was given a session for it (Task 20378).
//
// The hub decides whether a workload gets a session and puts the session's URL
// in its environment. What the hub cannot see is the network the sandbox lands
// on: which bridge, and so which gateway address the host answers on — on an
// --internal bridge the only address off the sandbox it can route to at all.
// So the Spec carries a route (executor.EgressProxyRoute) and this driver
// finishes it: it pins the route's name to the gateway of the bridge the
// sandbox joins, and, when that bridge carries a ruleset, opens exactly the
// proxy's address and port in it (provisionNetwork).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// networkIPAM is the part of a network's description that names its gateway.
// docker and podman disagree on the shape exactly as they do on the rest of
// it (see networkInspection), so both are decoded:
//
//	docker  {"IPAM": {"Config": [{"Subnet": "172.19.0.0/16", "Gateway": "172.19.0.1"}]}}
//	podman  {"subnets": [{"subnet": "10.88.0.0/16", "gateway": "10.88.0.1"}]}
type networkIPAM struct {
	IPAM *struct {
		Config []struct {
			Gateway string `json:"Gateway"`
		} `json:"Config"`
	} `json:"IPAM"`
	Subnets []struct {
		Gateway string `json:"gateway"`
	} `json:"subnets"`
}

// networkGateway returns the IPv4 gateway of a runtime network: the address
// the host answers on for sandboxes attached to it.
//
// IPv4 only, deliberately. Both runtimes give every bridge an IPv4 gateway,
// --add-host takes an IPv6 one in a different spelling on each, and a proxy
// listening on every interface answers on both.
func (e *Executor) networkGateway(ctx context.Context, name string) (netip.Addr, error) {
	if err := validateNetworkName(name); err != nil {
		return netip.Addr{}, err
	}
	res, err := runCLITimeout(ctx, e.rt, shortCmdTimeout, "network", "inspect", name, "--format", "{{json .}}")
	if err != nil {
		return netip.Addr{}, err
	}
	if res.ExitCode != 0 {
		return netip.Addr{}, fmt.Errorf("container: network %s does not exist", name)
	}
	gw, err := gatewayFromInspection([]byte(strings.TrimSpace(firstLine(res.Stdout))))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("container: %s's description of network %s: %w", e.rt.Name, name, err)
	}
	return gw, nil
}

// gatewayFromInspection reads the IPv4 gateway out of `network inspect
// --format '{{json .}}'` output from either runtime.
func gatewayFromInspection(payload []byte) (netip.Addr, error) {
	var got networkIPAM
	if err := json.Unmarshal(payload, &got); err != nil {
		return netip.Addr{}, fmt.Errorf("unreadable: %w", err)
	}
	var candidates []string
	if got.IPAM != nil {
		for _, c := range got.IPAM.Config {
			candidates = append(candidates, c.Gateway)
		}
	}
	for _, s := range got.Subnets {
		candidates = append(candidates, s.Gateway)
	}
	for _, c := range candidates {
		if a, err := netip.ParseAddr(strings.TrimSpace(c)); err == nil && a.Unmap().Is4() {
			return a.Unmap(), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("it reports no IPv4 gateway, so a sandbox on it has no address at " +
		"which to reach the hub's egress proxy")
}

// proxyEndpoint resolves the address and port a ruleset on network must open
// for route, and the network's gateway when the route is pinned to it.
//
// A route that names the proxy by address opens that address. One that names
// it by host name cannot be opened at all — a packet filter matches addresses,
// and resolving the name here would pin it silently, the hazard parseEndpoint
// refuses for the same reason — so it is refused, naming the fix.
func (e *Executor) proxyEndpoint(ctx context.Context, network string, route executor.EgressProxyRoute) (netip.AddrPort, netip.Addr, error) {
	if route.Gateway {
		gw, err := e.networkGateway(ctx, network)
		if err != nil {
			return netip.AddrPort{}, netip.Addr{}, err
		}
		return netip.AddrPortFrom(gw, uint16(route.Port)), gw, nil
	}
	if a, ok := route.Addr(); ok {
		return netip.AddrPortFrom(a, uint16(route.Port)), netip.Addr{}, nil
	}
	return netip.AddrPort{}, netip.Addr{}, fmt.Errorf("%w: executor %s filters its sandboxes' egress and so can "+
		"only open an address, but the hub's egress proxy is advertised to this workload by name (%s); set "+
		"executors.egress.advertise_addr on the hub to an address the device reaches it at",
		executor.ErrUnsupported, e.id, route)
}

// routeEgressProxy pins a gateway route's name inside the sandbox, so the
// proxy URL in its environment resolves to the bridge's gateway.
//
// gw is the gateway if provisioning already looked it up; otherwise the
// network the request joins is asked. A rootless engine is left alone: its
// networks live in a namespace of their own whose gateway is not a host
// address, and podman already resolves host.containers.internal to the host
// in every rootless container.
func (e *Executor) routeEgressProxy(ctx context.Context, req *runRequest, route executor.EgressProxyRoute, gw netip.Addr) error {
	if !route.Gateway || req.Network == NetworkNone {
		return nil
	}
	if e.rootless() {
		return nil
	}
	if !gw.IsValid() {
		var err error
		if gw, err = e.networkGateway(ctx, req.Network); err != nil {
			return err
		}
	}
	pin := strings.TrimSpace(route.Host) + ":" + gw.String()
	if err := validateAddHost(pin); err != nil {
		return err
	}
	// First, so it wins: /etc/hosts resolves to the first matching line, and
	// an operator's allow_hosts entry for the same name must not redirect the
	// proxy URL the hub issued.
	req.AddHosts = append([]string{pin}, req.AddHosts...)
	return nil
}
