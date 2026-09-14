package hubdoctor

// Reachability probes for the two addresses a hub hands *out* rather than
// binds: executors.git_proxy.advertise_url and executors.egress.advertise_addr.
//
// # Why these two need a probe when nothing else here does
//
// Every other address in the config is one the hub uses itself, so it is
// wrong loudly: a bad listen_addr fails to bind, a bad issuer fails discovery.
// These two are different. They are written into a sandbox's environment and
// consumed on the far side of a network boundary — in a Pod, on an edge
// device — and the hub never dials them, so a value that is wrong for the
// sandbox is indistinguishable from one that is right. The failure shows up as
// a clone that hangs or a proxy that refuses, attributed to the project that
// happened to run first.
//
// # What a probe from here can and cannot prove
//
// It cannot prove the interesting thing. The question is "will a sandbox, on
// its own network, reach this", and the hub is not on that network. A
// Kubernetes Service name is *supposed* to fail to resolve here; a hub behind
// NAT may reach its own advertised address by a path no edge device has.
//
// So the probe is scoped to what a dial genuinely settles, and the severities
// follow from that:
//
//   - It answered. Something is listening and the address is well-formed.
//     Pass, with the caveat stated in the message rather than implied.
//   - Refused. The address resolves and routes from here and nothing is
//     listening on it. Usually the proxy is not started yet — a doctor run is
//     often a pre-flight — so: warn, never fail.
//   - It did not resolve, or timed out. Inconclusive, and the most common
//     *correct* configuration on Kubernetes lands exactly here. Warn, and say
//     which reading applies.
//
// Nothing in this file returns SeverityFail. A check that cannot see the
// network it is judging has not earned the right to fail a deployment, and a
// gate that goes red on a correct Service name is a gate an operator turns off
// — taking the real failures with it.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// DefaultDialTimeout bounds one reachability dial.
//
// Shorter than DefaultProbeTimeout because the outcomes differ in cost: an
// HTTP probe against a cold IdP is worth waiting ten seconds for, while a TCP
// dial that has not completed in three seconds is reported as inconclusive
// anyway — so waiting longer buys a slower command and the same finding.
const DefaultDialTimeout = 3 * time.Second

// dialTimeout bounds a reachability dial, honouring an explicit --timeout.
func (o Options) dialTimeout() time.Duration {
	if o.Timeout > 0 {
		return o.Timeout
	}
	return DefaultDialTimeout
}

// dial opens a TCP connection, using the injected dialer when tests supply one.
func (o Options) dial(ctx context.Context, addr string) (net.Conn, error) {
	if o.DialContext != nil {
		return o.DialContext(ctx, "tcp", addr)
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
}

// reachOutcome is what a dial settled.
type reachOutcome int

const (
	reachSkipped  reachOutcome = iota // --offline, or nothing to dial
	reachOK                           // something accepted the connection
	reachRefused                      // resolved and routed; nothing listening
	reachUnproven                     // no resolution, no route, or a timeout
)

// reachResult carries the outcome and the error that produced it.
type reachResult struct {
	Outcome reachOutcome
	Addr    string
	Err     error
}

// probeReach dials addr ("host:port") and classifies the result.
//
// The classification is deliberately coarse. Distinguishing "no such host"
// from "no route" would make the message a little more specific and the
// remediation no different, because both have the same two readings — wrong
// value, or a value correct only from somewhere else.
func probeReach(ctx context.Context, opts Options, addr string) reachResult {
	if opts.Offline || strings.TrimSpace(addr) == "" {
		return reachResult{Outcome: reachSkipped, Addr: addr}
	}
	ctx, cancel := context.WithTimeout(ctx, opts.dialTimeout())
	defer cancel()

	conn, err := opts.dial(ctx, addr)
	if err == nil {
		_ = conn.Close()
		return reachResult{Outcome: reachOK, Addr: addr}
	}

	// ECONNREFUSED is the one error that proves the packet arrived: something
	// on the far end answered, even if only to say no. Everything else —
	// timeouts, DNS, unreachable networks — leaves the question open.
	if errors.Is(err, context.DeadlineExceeded) {
		return reachResult{Outcome: reachUnproven, Addr: addr, Err: err}
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return reachResult{Outcome: reachUnproven, Addr: addr, Err: err}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return reachResult{Outcome: reachUnproven, Addr: addr, Err: err}
	}
	if strings.Contains(err.Error(), "connection refused") {
		return reachResult{Outcome: reachRefused, Addr: addr, Err: err}
	}
	return reachResult{Outcome: reachUnproven, Addr: addr, Err: err}
}

// dialTarget derives the "host:port" to dial from an advertised URL.
//
// A URL without an explicit port is dialled on its scheme's default, which is
// what a sandbox's git or HTTP client would do with the same string — the
// point being to probe what the sandbox will actually contact, not what the
// config literally says.
func dialTarget(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("not a URL: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("names no host")
	}
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			return "", fmt.Errorf("scheme %q has no default port; write the port explicitly", u.Scheme)
		}
	}
	return net.JoinHostPort(host, port), nil
}

// addrTarget normalises an advertised "host:port" for dialling.
//
// A bare host is legitimate in config — the egress broker appends the
// listener's port — but there is nothing to dial without one, so it is
// reported as unprobeable rather than guessed at.
func addrTarget(raw string) (string, error) {
	a := strings.TrimSpace(raw)
	if a == "" {
		return "", fmt.Errorf("is empty")
	}
	host, port, err := net.SplitHostPort(a)
	if err != nil {
		return "", fmt.Errorf("carries no port, so there is nothing to dial " +
			"(the broker appends the listener's port at run time)")
	}
	if host == "" {
		return "", fmt.Errorf("names no host")
	}
	return net.JoinHostPort(host, port), nil
}

// reachFinding renders a probe result as the finding for one advertised
// address.
//
// check is the finding id, what names the setting in prose ("git proxy"), and
// key is the config key an operator would edit.
func reachFinding(check, title, what, key string, res reachResult, opts Options) Finding {
	switch res.Outcome {
	case reachOK:
		return Finding{
			Check:    check,
			Title:    title,
			Severity: SeverityPass,
			Message: fmt.Sprintf("%s answers at %s from the hub; a sandbox on a different "+
				"network still resolves and routes it independently", what, res.Addr),
			Details: map[string]any{"dialed": res.Addr},
		}
	case reachRefused:
		return Finding{
			Check:    check,
			Title:    title,
			Severity: SeverityWarn,
			Message: fmt.Sprintf("%s at %s resolves and routes from the hub but nothing is "+
				"listening — a sandbox handed this address gets the same refusal", what, res.Addr),
			Remediation: fmt.Sprintf("Start the hub — a refusal is expected when `cloop hub doctor` "+
				"runs as a pre-flight against a stopped hub — or correct %s", key),
			Details: map[string]any{"dialed": res.Addr, "error": res.Err.Error()},
		}
	case reachUnproven:
		return Finding{
			Check:    check,
			Title:    title,
			Severity: SeverityWarn,
			Message: fmt.Sprintf("%s at %s could not be reached from the hub: %v — which is correct "+
				"when the address is meant to resolve only inside the sandbox's network (a Kubernetes "+
				"Service name), and a misconfiguration otherwise", what, res.Addr, res.Err),
			Remediation: fmt.Sprintf("Confirm %s resolves from a sandbox — `kubectl run -it --rm probe "+
				"--image=busybox -- nc -vz %s` from the executor's namespace, or the same from an "+
				"enrolled edge device", key, strings.Replace(res.Addr, ":", " ", 1)),
			Details: map[string]any{"dialed": res.Addr, "error": res.Err.Error()},
		}
	default:
		reason := "--offline was requested"
		if !opts.Offline {
			reason = "there was no address to dial"
		}
		return Finding{
			Check:    check,
			Title:    title,
			Severity: SeverityWarn,
			Message: fmt.Sprintf("%s was not probed because %s, so whether a sandbox can reach it "+
				"is unknown", what, reason),
			Remediation: fmt.Sprintf("Re-run `cloop hub doctor` without --offline to probe %s", key),
		}
	}
}
