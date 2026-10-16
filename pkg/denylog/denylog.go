// Package denylog reads what a sandbox's firewall refused and reports it per
// run (Task 20437).
//
// A sandbox's IP firewall (pkg/netfilter) used to end in a silent drop, so a
// blocked connection looked like an outage: the workload waited out a TCP
// timeout, the harness retried for minutes, and nothing said which address had
// been refused by which rule. The ruleset now refuses instead, and every deny
// path logs — rate-limited, to an NFLOG group — under a prefix naming the rule
// set's fingerprint and the rule. This package is the other end of that log:
//
//   - nflog_linux.go binds the group over a netlink socket in this process. It
//     needs CAP_NET_ADMIN and AF_NETLINK, which is exactly what installing the
//     ruleset needs (the agent's --packet-filter grant), and no child process:
//     the capability never leaves the process that holds it (pkg/caps).
//   - parse.go and headers.go read the kernel's messages: the prefix, the
//     input interface, and the IPv4/IPv6 and TCP/UDP headers of the packet.
//     Addresses and ports are all that survive; the rule's snaplen means the
//     kernel copies little more, and nothing past the ports is read.
//   - monitor.go attributes each packet to its run by the sandbox's bridge and
//     source address, and aggregate.go counts it, per run, by destination,
//     port, protocol and rule — capped, so a hostile workload cannot make the
//     process do unbounded work.
//
// What becomes of a batch is the process's business, through its Sink: an
// executor agent sends it to the hub over its session, and the hub's own
// container executor hands it to the hub directly.
package denylog

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/blechschmidt/cloop/pkg/netfilter"
)

// Caps on what one process holds. Every one of them is reached only by a
// workload doing something no developer's task does — spraying addresses,
// ports or protocols at its firewall — and each turns that into a count.
const (
	// MaxEntriesPerRun bounds the distinct (destination, port, protocol,
	// rule) a run's aggregate itemises. Past it, the entry seen least — the
	// smallest count, then the longest ago — makes room, and what it had not
	// yet reported is counted as unitemised.
	MaxEntriesPerRun = 64
	// MaxRuns bounds the runs one process tracks at once: far more sandboxes
	// than a host runs, and a ceiling on the memory a confused caller could
	// make the monitor hold.
	MaxRuns = 4096
	// maxPending bounds the observations held for an address no run has
	// claimed yet — the instant between a container starting and the driver
	// learning its address.
	maxPending = 256
)

// Proto names an IP protocol the way an entry carries it.
type Proto uint8

// The protocols an entry names. Anything else is "other": the number of an
// exotic protocol is not worth an unbounded label.
const (
	ProtoICMP    Proto = 1
	ProtoTCP     Proto = 6
	ProtoUDP     Proto = 17
	ProtoICMPv6  Proto = 58
	ProtoSCTP    Proto = 132
	ProtoUDPLite Proto = 136
)

// String renders the protocol for an entry.
func (p Proto) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMP:
		return "icmp"
	case ProtoICMPv6:
		return "icmpv6"
	case ProtoSCTP:
		return "sctp"
	case ProtoUDPLite:
		return "udplite"
	default:
		return "other"
	}
}

// HasPorts reports whether packets of this protocol carry a destination port.
func (p Proto) HasPorts() bool {
	switch p {
	case ProtoTCP, ProtoUDP, ProtoSCTP, ProtoUDPLite:
		return true
	}
	return false
}

// ProtoNames lists every value Entry.Proto may take.
var ProtoNames = []string{"tcp", "udp", "icmp", "icmpv6", "sctp", "udplite", "other"}

// Entry is one aggregated refusal: every packet a run sent to one destination
// and port, over one protocol, that one rule denied.
type Entry struct {
	// Dst is the address the sandbox tried to reach.
	Dst netip.Addr `json:"dst"`
	// Port is its destination port; 0 for a protocol without ports, or a
	// packet whose transport header did not fit in what the kernel copied.
	Port uint16 `json:"port,omitempty"`
	// Proto is one of ProtoNames.
	Proto string `json:"proto"`
	// Rule is the deny path's tag (pkg/netfilter: "default", "deny:<prefix>",
	// "meta:<prefix>", "block:<prefix>", "xlat:<prefix>").
	Rule string `json:"rule"`
	// Count is how many packets this report adds — a delta, so a batch that
	// arrives twice cannot be mistaken for one that arrived once, and a
	// report that never arrives loses only its own share.
	Count uint64 `json:"count"`
	// First and Last bound when they were seen.
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
}

// Batch is what a flush reports for one run.
type Batch struct {
	// Fingerprint is the rule set the run's sandbox was filtered by, as the
	// prefixes named it.
	Fingerprint string `json:"fingerprint,omitempty"`
	// Entries are the itemised refusals since the last report.
	Entries []Entry `json:"entries,omitempty"`
	// Unitemised counts refusals since the last report that no entry holds:
	// those of entries that made room for others before they were reported.
	Unitemised uint64 `json:"unitemised,omitempty"`
	// Final says the run is over and nothing more will be reported for it.
	Final bool `json:"final,omitempty"`
}

// Empty reports whether the batch carries nothing to record.
func (b Batch) Empty() bool { return len(b.Entries) == 0 && b.Unitemised == 0 }

// Total is the number of refusals the batch reports.
func (b Batch) Total() uint64 {
	t := b.Unitemised
	for _, e := range b.Entries {
		t += e.Count
	}
	return t
}

// maxCount bounds one entry's delta. A kernel rate limit of ten a second per
// rule cannot get anywhere near it in any flush interval; a report claiming
// more is not from this package.
const maxCount = 1 << 40

// Validate checks a batch that arrived from somewhere else — a device's frame
// — before anything is recorded from it: bounded, canonical, and naming only
// rules and protocols this package writes. It does not trust the sender's
// clock; Clamp does that.
func (b Batch) Validate() error {
	if len(b.Entries) > MaxEntriesPerRun {
		return fmt.Errorf("denylog: %d entries in one report, the most a run itemises is %d",
			len(b.Entries), MaxEntriesPerRun)
	}
	if b.Fingerprint != "" && !isHex12(b.Fingerprint) {
		return fmt.Errorf("denylog: fingerprint %q is not twelve lowercase hex digits", b.Fingerprint)
	}
	if b.Unitemised > maxCount {
		return fmt.Errorf("denylog: %d unitemised refusals is past any rate the kernel logs at", b.Unitemised)
	}
	seen := make(map[string]bool, len(b.Entries))
	for i, e := range b.Entries {
		if err := e.validate(); err != nil {
			return fmt.Errorf("denylog: entries[%d]: %w", i, err)
		}
		k := e.key()
		if seen[k] {
			return fmt.Errorf("denylog: entries[%d] repeats %s", i, k)
		}
		seen[k] = true
	}
	return nil
}

func (e Entry) validate() error {
	if !e.Dst.IsValid() || e.Dst.Zone() != "" || e.Dst.Is4In6() {
		return errors.New("destination is not a plain address")
	}
	if !knownProto(e.Proto) {
		return fmt.Errorf("protocol %q is not one an entry names", e.Proto)
	}
	if e.Port != 0 && !protoHasPorts(e.Proto) {
		return fmt.Errorf("%s carries no ports, but the entry names port %d", e.Proto, e.Port)
	}
	if !ValidRule(e.Rule) {
		return fmt.Errorf("rule %q is not a deny path", e.Rule)
	}
	if e.Count == 0 || e.Count > maxCount {
		return fmt.Errorf("count %d is out of range", e.Count)
	}
	if e.First.IsZero() || e.Last.IsZero() || e.Last.Before(e.First) {
		return errors.New("first and last seen do not bound an interval")
	}
	return nil
}

// Clamp keeps a reported interval inside [lo, hi]: a device's clock is not the
// hub's, and a time from a skewed or hostile one must not sort a refusal into
// a task that was never running or out of a project's recent list.
func (e *Entry) Clamp(lo, hi time.Time) {
	clamp := func(t time.Time) time.Time {
		if t.Before(lo) {
			return lo
		}
		if t.After(hi) {
			return hi
		}
		return t
	}
	e.First, e.Last = clamp(e.First), clamp(e.Last)
}

func (e Entry) key() string {
	return e.Dst.String() + "|" + strconv.Itoa(int(e.Port)) + "|" + e.Proto + "|" + e.Rule
}

// Describe renders the destination as an operator types it: 203.0.113.7:443/tcp,
// [2001:db8::7]:443/tcp, 203.0.113.7/icmp.
func (e Entry) Describe() string {
	if e.Port == 0 {
		return e.Dst.String() + "/" + e.Proto
	}
	return netip.AddrPortFrom(e.Dst, e.Port).String() + "/" + e.Proto
}

func knownProto(s string) bool {
	for _, p := range ProtoNames {
		if p == s {
			return true
		}
	}
	return false
}

func protoHasPorts(s string) bool {
	switch s {
	case "tcp", "udp", "sctp", "udplite":
		return true
	}
	return false
}

// ValidRule reports whether s is a deny-path tag pkg/netfilter writes.
func ValidRule(s string) bool {
	_, _, ok := netfilter.ParseTag(s)
	return ok
}

// RuleKind is a tag's kind: "default", "deny", "meta", "block" or "xlat".
func RuleKind(rule string) string {
	kind, _, _ := netfilter.ParseTag(rule)
	return kind
}

// RulePrefix is the range a tag names, or the zero prefix for "default".
func RulePrefix(rule string) netip.Prefix {
	_, p, _ := netfilter.ParseTag(rule)
	return p
}

// ParsePrefix splits a log prefix "cloop:<fingerprint>:<tag>".
func ParsePrefix(s string) (fingerprint, rule string, ok bool) {
	return netfilter.ParseLogPrefix(s)
}

func isHex12(s string) bool {
	if len(s) != 12 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
