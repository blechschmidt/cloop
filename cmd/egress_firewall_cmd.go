// IP-layer egress firewalling (Task 20186).
//
// `cloop egress firewall` shows what a grant becomes at layer 3, and lets an
// operator ask whether one address and port would get through.
//
// It exists because the two enforcement points answer different questions and
// an operator has to be able to see both. `cloop egress test` asks the proxy
// "may I connect to this URL", which is the L7 answer and depends on the
// workload choosing to use the proxy. This asks the packet filter "would this
// packet leave", which is the answer that binds a workload that does not.
//
// The rendered output is the same text the driver installs — pkg/netfilter
// has one compiler and the backends render it — so an operator debugging a
// sandbox can diff what they see here against `nft list table inet
// cloop_sbx_<id>` on the host and against `kubectl get netpol -o yaml` in a
// cluster.

package cmd

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/netfilter"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	egressFirewallGrantFlag    string
	egressFirewallFormatFlag   string
	egressFirewallTableFlag    string
	egressFirewallBridgeFlag   string
	egressFirewallBrokerFlag   string
	egressFirewallResolverFlag []string
	egressFirewallCheckFlag    string
	egressFirewallInternetFlag bool
	egressFirewallCIDRsFlag    []string
	egressFirewallPortsFlag    []int
)

var egressFirewallCmd = &cobra.Command{
	Use:   "firewall",
	Short: "Render the IP-layer filter a grant compiles to",
	Long: `Render the packet filter an egress authorisation compiles to.

The egress broker is an HTTP proxy: it enforces the host allowlist, but only
for a workload that chooses to use it. The IP-layer filter is what binds one
that does not — a harness opening a raw socket, or anything that is not HTTP.

With --grant, the authorisation is read from a stored grant. Otherwise it is
built from --cidrs, --ports, --internet, --broker and --resolver, which is how
an operator previews a configuration before writing it into config.yaml.

Formats:
  nft             an nft(8) script for the sandbox's own network namespace
  nft-bridge      an nft(8) script filtering one bridge from the host side
  networkpolicy   a Kubernetes NetworkPolicy object
  rules           the compiled rules, one per line

Examples:
  # What would this grant actually enforce at layer 3?
  cloop egress firewall --grant egress_a1b2c3

  # Preview a configuration before writing it
  cloop egress firewall --cidrs 10.8.0.0/24 --ports 6443 --format rules

  # Would a packet to the metadata service get out?
  cloop egress firewall --internet --ports 443 --check 169.254.169.254:80`,
	RunE: runEgressFirewall,
	Args: cobra.NoArgs,
}

func runEgressFirewall(cmd *cobra.Command, _ []string) error {
	in, source, err := egressFirewallInput()
	if err != nil {
		return err
	}
	policy, err := netfilter.Compile(in)
	if err != nil {
		return err
	}

	if egressFirewallCheckFlag != "" {
		return egressFirewallCheck(policy, egressFirewallCheckFlag)
	}

	switch strings.ToLower(strings.TrimSpace(egressFirewallFormatFlag)) {
	case "", "nft":
		out, err := netfilter.RenderNftables(policy, netfilter.NftablesOptions{Table: egressFirewallTableFlag})
		if err != nil {
			return err
		}
		fmt.Print(out)
	case "nft-bridge":
		if egressFirewallBridgeFlag == "" {
			return fmt.Errorf("--format nft-bridge needs --bridge (the sandbox network's host interface, e.g. br-8e9671342cdf)")
		}
		out, err := netfilter.RenderNftables(policy, netfilter.NftablesOptions{
			Table:  egressFirewallTableFlag,
			Bridge: egressFirewallBridgeFlag,
		})
		if err != nil {
			return err
		}
		fmt.Print(out)
	case "networkpolicy":
		// An nft identifier and a Kubernetes object name have different
		// grammars: nft takes underscores, DNS-1123 does not. Translating
		// rather than erroring means one --table flag serves both formats.
		np, err := netfilter.RenderNetworkPolicy(policy, netfilter.NetworkPolicyOptions{
			Name:            strings.ReplaceAll(egressFirewallTableFlag, "_", "-"),
			Namespace:       "cloop",
			PodSelector:     map[string]string{"cloop.dev/handle-id": "<handle>"},
			AllowClusterDNS: true,
		})
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(np); err != nil {
			return err
		}
	case "rules":
		egressFirewallPrintRules(policy, source)
	default:
		return fmt.Errorf("unknown --format %q (want nft, nft-bridge, networkpolicy or rules)", egressFirewallFormatFlag)
	}
	return nil
}

// egressFirewallInput builds the authorisation, from a stored grant or from
// flags.
func egressFirewallInput() (netfilter.Input, string, error) {
	var in netfilter.Input
	source := "flags"

	if egressFirewallGrantFlag != "" {
		g, err := loadEgressGrant(egressFirewallGrantFlag)
		if err != nil {
			return in, "", err
		}
		source = "grant " + g.ID
		for _, c := range g.CIDRs {
			p, perr := netip.ParsePrefix(c)
			if perr != nil {
				return in, "", fmt.Errorf("grant %s carries an unparseable CIDR %q: %w", g.ID, c, perr)
			}
			in.AllowCIDRs = append(in.AllowCIDRs, p)
		}
		for _, p := range g.Ports {
			in.AllowPorts = append(in.AllowPorts, uint16(p))
		}
		// A host allowlist has no layer-3 form, so it becomes the public
		// Internet — and Compile attaches the warning that says so. This is
		// the single most useful thing this command reports.
		if len(g.Hosts) > 0 {
			in.AllowPublicInternet = true
			in.HostPatterns = g.Hosts
		}
	} else {
		for _, c := range egressFirewallCIDRsFlag {
			p, err := netip.ParsePrefix(strings.TrimSpace(c))
			if err != nil {
				return in, "", fmt.Errorf("--cidrs %q is not a prefix: %w", c, err)
			}
			in.AllowCIDRs = append(in.AllowCIDRs, p)
		}
		for _, p := range egressFirewallPortsFlag {
			if p <= 0 || p > 65535 {
				return in, "", fmt.Errorf("--ports %d is out of range", p)
			}
			in.AllowPorts = append(in.AllowPorts, uint16(p))
		}
		in.AllowPublicInternet = egressFirewallInternetFlag
	}

	if egressFirewallBrokerFlag != "" {
		ap, err := netip.ParseAddrPort(strings.TrimSpace(egressFirewallBrokerFlag))
		if err != nil {
			return in, "", fmt.Errorf("--broker %q must be an address:port literal: %w", egressFirewallBrokerFlag, err)
		}
		in.Brokers = append(in.Brokers, ap)
	}
	for _, r := range egressFirewallResolverFlag {
		r = strings.TrimSpace(r)
		ap, err := netip.ParseAddrPort(r)
		if err != nil {
			a, aerr := netip.ParseAddr(r)
			if aerr != nil {
				return in, "", fmt.Errorf("--resolver %q must be an address or address:port literal", r)
			}
			ap = netip.AddrPortFrom(a, 53)
		}
		in.Resolvers = append(in.Resolvers, ap)
	}
	return in, source, nil
}

// loadEgressGrant fetches one grant by ID from the project's store.
func loadEgressGrant(id string) (egressbroker.Grant, error) {
	broker, cleanup, err := openEgressBroker()
	if err != nil {
		return egressbroker.Grant{}, err
	}
	defer cleanup()

	grants, err := broker.ListGrants(egressbroker.GrantFilter{})
	if err != nil {
		return egressbroker.Grant{}, fmt.Errorf("listing egress grants: %w", err)
	}
	for _, g := range grants {
		if g.ID == id {
			return g, nil
		}
	}
	return egressbroker.Grant{}, fmt.Errorf("no egress grant %q (run `cloop egress list --all`)", id)
}

// egressFirewallCheck answers the one-address question.
//
// The exit status carries the verdict so the command composes into a script:
// 0 when the packet would leave, 1 when it would be dropped. An operator
// automating "is this sandbox still confined" should not have to parse prose.
func egressFirewallCheck(p netfilter.Policy, target string) error {
	proto := netfilter.ProtoTCP
	spec := strings.TrimSpace(target)
	if rest, ok := strings.CutSuffix(strings.ToLower(spec), "/udp"); ok {
		proto, spec = netfilter.ProtoUDP, rest
	} else if rest, ok := strings.CutSuffix(strings.ToLower(spec), "/tcp"); ok {
		spec = rest
	}

	ap, err := netip.ParseAddrPort(spec)
	if err != nil {
		return fmt.Errorf("--check %q must be an address:port literal, optionally suffixed /tcp or /udp "+
			"(a packet filter matches addresses, not names)", target)
	}

	verdict, reason := p.WireOnly().Evaluate(ap.Addr(), ap.Port(), proto)
	if verdict == netfilter.VerdictAllow {
		fmt.Printf("%s %s %s/%s — %s\n", color.GreenString("ALLOW"), ap.Addr(), ap.String(), proto, reason)
		return nil
	}
	fmt.Printf("%s %s %s/%s — %s\n", color.RedString("DROP "), ap.Addr(), ap.String(), proto, reason)
	os.Exit(1)
	return nil
}

// egressFirewallPrintRules renders the compiled rules for a human.
func egressFirewallPrintRules(p netfilter.Policy, source string) {
	fmt.Printf("%s  mode %s, %d rules, from %s\n\n",
		color.New(color.Bold).Sprint("IP-layer egress filter"), p.Mode, len(p.Rules), source)

	for _, w := range p.Warnings {
		fmt.Printf("%s %s\n\n", color.YellowString("warning:"), w)
	}
	for _, r := range p.Rules {
		verdict := color.GreenString("allow")
		if r.Verdict == netfilter.VerdictDrop {
			verdict = color.RedString("drop ")
		}
		scope := ""
		if r.Scope == netfilter.ScopeLocal {
			scope = color.New(color.Faint).Sprint(" [namespace-local]")
		}
		line := fmt.Sprintf("  %s  %-22s", verdict, r.Prefix)
		if r.Proto != netfilter.ProtoAny {
			line += fmt.Sprintf(" %-3s", r.Proto)
		} else {
			line += "    "
		}
		if len(r.Ports) > 0 {
			ports := make([]string, len(r.Ports))
			for i, pt := range r.Ports {
				ports[i] = fmt.Sprint(pt)
			}
			line += fmt.Sprintf(" %-12s", strings.Join(ports, ","))
		} else {
			line += fmt.Sprintf(" %-12s", "any")
		}
		fmt.Printf("%s %s%s\n", line, color.New(color.Faint).Sprint(r.Reason), scope)
	}
	fmt.Printf("  %s  %-22s %-3s %-12s %s\n",
		color.RedString("drop "), "everything else", "", "", color.New(color.Faint).Sprint("default deny"))
}

func init() {
	f := egressFirewallCmd.Flags()
	f.StringVar(&egressFirewallGrantFlag, "grant", "", "compile a stored grant by ID")
	f.StringVar(&egressFirewallFormatFlag, "format", "rules", "nft, nft-bridge, networkpolicy or rules")
	f.StringVar(&egressFirewallTableFlag, "table", "cloop_sbx_preview", "nft table / NetworkPolicy name")
	f.StringVar(&egressFirewallBridgeFlag, "bridge", "", "host interface to filter (--format nft-bridge)")
	f.StringVar(&egressFirewallBrokerFlag, "broker", "", "egress proxy endpoint the sandbox may reach (address:port)")
	f.StringSliceVar(&egressFirewallResolverFlag, "resolver", nil, "DNS server the sandbox may query directly")
	f.StringVar(&egressFirewallCheckFlag, "check", "", "report the verdict for one address:port and exit 1 if dropped")
	f.BoolVar(&egressFirewallInternetFlag, "internet", false, "allow every public address on --ports")
	f.StringSliceVar(&egressFirewallCIDRsFlag, "cidrs", nil, "address ranges the sandbox may reach directly")
	f.IntSliceVar(&egressFirewallPortsFlag, "ports", nil, "destination ports")

	egressCmd.AddCommand(egressFirewallCmd)
}
