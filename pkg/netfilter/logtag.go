package netfilter

// logtag.go names each deny path for the packet log (Task 20437).
//
// A refused connection used to leave no trace a developer could find: the
// workload waited out a timeout, and nothing said which address was refused by
// which rule. Every deny path in a rendered ruleset now carries a rate-limited
// `log ... group N` statement ahead of its verdict, and the prefix that
// statement hands the kernel's NFLOG group is the whole of what a reader learns
// about the rule. So the prefix is a small grammar rather than prose:
//
//	cloop:<fingerprint>:<tag>
//
// where the fingerprint is the rule set's (pkg/fwpolicy.Fingerprint — the same
// digest the sandbox's bridge and table are named after) and the tag is one of
//
//	default            the implicit final deny: nothing allowed the packet
//	deny:<prefix>      an entry of a deny list
//	meta:<prefix>      a cloud metadata service
//	block:<prefix>     the rest of the hard-block set: private, loopback, ...
//	xlat:<prefix>      an IPv6 translation prefix no allow waives
//
// Nothing in a prefix is a sentence. Which level's allowlist did not name the
// address, whose deny list did — those are the hub's to say, because only the
// hub knows the levels a run was composed from (pkg/fwpolicy.Explain).

import (
	"fmt"
	"net/netip"
	"strings"
)

// Tag kinds, the part of a tag before its prefix.
const (
	// TagDefault is the implicit final deny. It carries no prefix: nothing
	// matched, which is the point.
	TagDefault = "default"
	// TagKindDeny is a deny-list entry.
	TagKindDeny = "deny"
	// TagKindMetadata is a cloud metadata service, whether the block set
	// dropped it or an allow that contained it was carved.
	TagKindMetadata = "meta"
	// TagKindBlock is the rest of the hard-block set.
	TagKindBlock = "block"
	// TagKindTranslation is an IPv6 translation prefix.
	TagKindTranslation = "xlat"
)

// LogPrefixMarker begins every prefix cloop logs under. A reader drops
// anything else that arrives in its group.
const LogPrefixMarker = "cloop:"

// nfLogPrefixMax is the longest prefix the kernel keeps: NF_LOG_PREFIXLEN is
// 128 bytes with the terminator, and nft refuses a longer one outright, which
// would fail the whole transaction.
const nfLogPrefixMax = 127

// LogOptions turns on the packet log for a rendered ruleset.
type LogOptions struct {
	// Group is the NFLOG group the process that installs the ruleset reads.
	Group uint16
	// Fingerprint identifies the rule set in every prefix: twelve lowercase
	// hex digits, as pkg/fwpolicy.Fingerprint renders it.
	Fingerprint string
}

// Rate limits for the log statements, per deny path.
//
// The log is how a developer learns what was blocked, not an accounting of
// every packet: a refused TCP connect costs one log line, and a workload that
// sprays a range is reported as a count, not a stream. The limit is per rule —
// one bucket for each deny path in each chain — and what it bounds is the work
// a hostile workload can make the host do: at most this rate, per path, ever
// crosses into the reader's process. A packet over the limit is still denied;
// the limit gates the log statement, not the verdict.
const (
	logLimits = "limit rate 10/second burst 20 packets"
	logSnap   = 80
)

// LogSnaplen is how much of a logged packet the kernel copies to the reader:
// enough for an IPv4 header with options and the ports behind it, or an IPv6
// header and a few extension headers. The reader parses addresses and ports
// out of it and keeps nothing else; bounding it in the rule means even a
// process that binds the group asking for whole packets gets no payload.
const LogSnaplen = logSnap

func denyTag(kind string, p netip.Prefix) string { return kind + ":" + p.String() }

// LogPrefix builds the prefix a deny path logs under.
func LogPrefix(fingerprint, tag string) (string, error) {
	if !validFingerprint(fingerprint) {
		return "", fmt.Errorf("netfilter: log fingerprint %q is not twelve lowercase hex digits", fingerprint)
	}
	if _, _, ok := ParseTag(tag); !ok {
		return "", fmt.Errorf("netfilter: %q is not a deny-path tag", tag)
	}
	out := LogPrefixMarker + fingerprint + ":" + tag
	if len(out) > nfLogPrefixMax {
		return "", fmt.Errorf("netfilter: log prefix %q is longer than the kernel's %d bytes", out, nfLogPrefixMax)
	}
	return out, nil
}

// ParseLogPrefix splits a prefix LogPrefix built. It accepts nothing else: the
// prefix arrives from the kernel, but the group it arrived in is a number any
// process holding CAP_NET_ADMIN could log to as well.
func ParseLogPrefix(s string) (fingerprint, tag string, ok bool) {
	rest, found := strings.CutPrefix(s, LogPrefixMarker)
	if !found || len(s) > nfLogPrefixMax {
		return "", "", false
	}
	fingerprint, tag, found = strings.Cut(rest, ":")
	if !found || !validFingerprint(fingerprint) {
		return "", "", false
	}
	if _, _, ok := ParseTag(tag); !ok {
		return "", "", false
	}
	return fingerprint, tag, true
}

// ParseTag splits a deny-path tag into its kind and prefix. TagDefault has no
// prefix and comes back with a zero one.
func ParseTag(tag string) (kind string, prefix netip.Prefix, ok bool) {
	if tag == TagDefault {
		return TagDefault, netip.Prefix{}, true
	}
	kind, raw, found := strings.Cut(tag, ":")
	if !found {
		return "", netip.Prefix{}, false
	}
	switch kind {
	case TagKindDeny, TagKindMetadata, TagKindBlock, TagKindTranslation:
	default:
		return "", netip.Prefix{}, false
	}
	p, err := netip.ParsePrefix(raw)
	if err != nil || p != p.Masked() || p.String() != raw {
		// Canonical only: a tag is something this package wrote, and a
		// second spelling of one would aggregate as a second rule.
		return "", netip.Prefix{}, false
	}
	return kind, p, true
}

func validFingerprint(s string) bool {
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

// logRule renders the log statement for one deny path: the rule's match, a
// rate limit, and the log to the group. The verdict follows on its own line,
// so a packet over the limit is denied all the same.
func logRule(match, fingerprint, tag string, opts *LogOptions) (string, bool) {
	prefix, err := LogPrefix(fingerprint, tag)
	if err != nil {
		return "", false
	}
	var b strings.Builder
	if match != "" {
		b.WriteString(match + " ")
	}
	// The prefix is quoted by hand: LogPrefix admits only [0-9a-z:./], so
	// there is nothing in it to escape, and %q's Go escaping is not nft's.
	fmt.Fprintf(&b, "%s log prefix \"%s\" group %d snaplen %d", logLimits, prefix, opts.Group, logSnap)
	return b.String(), true
}
