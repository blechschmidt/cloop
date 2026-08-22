package secretbroker

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Decision is the outcome recorded for every brokered operation.
type Decision string

const (
	// DecisionAllow: the operation succeeded and credentials were (or will
	// be) delivered.
	DecisionAllow Decision = "allow"
	// DecisionDeny: the operation was refused. The Reason says why.
	DecisionDeny Decision = "deny"
)

// Action names the brokered operation an audit event describes.
type Action string

const (
	ActionMint        Action = "secret.mint"
	ActionDeleteSec   Action = "secret.delete"
	ActionGrant       Action = "secret.grant"
	ActionRevoke      Action = "secret.revoke"
	ActionLease       Action = "secret.lease"
	ActionRenew       Action = "secret.renew"
	ActionRelease     Action = "secret.release"
	ActionAccessCheck Action = "secret.access_check"

	// Egress actions come from pkg/egressbroker, which brokers the hub's
	// Internet connection as a fourth grantable resource alongside GitHub
	// repositories, PATs, and Kubernetes clusters.
	//
	// They share this audit trail rather than opening a second one on
	// purpose: "what did this executor reach, and with whose authority" is
	// one question, and answering it from two hash chains that can disagree
	// about ordering would be strictly worse than answering it from one.
	ActionEgressGrant   Action = "egress.grant"
	ActionEgressRevoke  Action = "egress.revoke"
	ActionEgressRedeem  Action = "egress.redeem"
	ActionEgressConnect Action = "egress.connect"
	ActionEgressRequest Action = "egress.request"
	ActionEgressClose   Action = "egress.close"
)

// Event is one audit record. Every field on it is metadata about a
// credential: which one, for whom, under what constraints, and what was
// decided. None of them is, or may become, the credential itself.
//
// This is enforced rather than asserted: Event has no field capable of
// carrying a payload, and Redact scrubs the free-text Reason before the
// event leaves the package, because Reason is built from error strings and
// an error string is the one place a payload could plausibly get spliced in.
type Event struct {
	Time     time.Time `json:"time"`
	Action   Action    `json:"action"`
	Decision Decision  `json:"decision"`
	// Actor is who asked: an OIDC subject, "cli", "ui", or an executor ID.
	Actor string `json:"actor,omitempty"`
	// Subject is the grant subject the operation concerned, rendered in
	// the CLI's "--to" syntax.
	Subject string `json:"subject,omitempty"`
	// SecretID and SecretName identify the credential. The name is a
	// handle chosen by an operator, never the value.
	SecretID   string `json:"secret_id,omitempty"`
	SecretName string `json:"secret_name,omitempty"`
	Kind       Kind   `json:"kind,omitempty"`
	GrantID    string `json:"grant_id,omitempty"`
	LeaseID    string `json:"lease_id,omitempty"`
	ExecutorID string `json:"executor_id,omitempty"`
	ProjectID  string `json:"project_id,omitempty"`
	// Constraints is the allowlist summary that applied to the decision.
	Constraints string `json:"constraints,omitempty"`
	// ExpiresAt is the TTL stamp of the grant or lease involved.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	// Reason explains a denial, or annotates an allow ("2 grants matched").
	Reason string `json:"reason,omitempty"`

	// TaskID is the unit of work the decision was made for. Populated by
	// the egress broker, which knows it; the secret broker's leases are
	// per-executor rather than per-task and leave it empty.
	TaskID string `json:"task_id,omitempty"`
	// Host and Port name an egress destination. They are a hostname and a
	// port and nothing else — deliberately not a URL, because a URL has a
	// path and a query, and those are request contents rather than access
	// metadata.
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
	// BytesUp and BytesDown are the session's transfer totals at the time of
	// the decision, from the workload's point of view.
	BytesUp   int64 `json:"bytes_up,omitempty"`
	BytesDown int64 `json:"bytes_down,omitempty"`
}

// Auditor receives brokered-operation events. Implementations must not block
// the broker: an audit sink that is slow or down must not stop a workload
// from starting, so the production adapter writes best-effort and swallows
// its own errors, exactly as pkg/statedb's audit emitters do.
type Auditor interface {
	Audit(ev Event)
}

// AuditorFunc adapts a function to the Auditor interface.
type AuditorFunc func(Event)

// Audit implements Auditor.
func (f AuditorFunc) Audit(ev Event) {
	if f != nil {
		f(ev)
	}
}

// nopAuditor drops events. Used when no auditor is configured, so the broker
// never has to nil-check at a call site.
type nopAuditor struct{}

func (nopAuditor) Audit(Event) {}

// redactionMarker replaces anything scrubbed out of an audit reason.
const redactionMarker = "[redacted]"

// Redact returns a copy of ev safe to persist.
//
// It scrubs the Reason of anything that pattern-matches a credential. That
// may look like belt-and-braces given that no code path deliberately puts a
// payload in a Reason — and it is. The reason to do it anyway is that Reason
// is assembled from wrapped errors, and error wrapping is exactly how a
// payload leaks: someone one day writes fmt.Errorf("bad token %q: %w", tok,
// err) three packages down, and the audit log quietly becomes the place the
// credential is stored in plaintext forever. Scrubbing at the boundary means
// that mistake degrades to an unhelpful log line instead of a breach.
//
// Auditors must call this (the broker calls it on every emission), and the
// storage adapter calls it again on the way in.
func Redact(ev Event) Event {
	ev.Reason = RedactString(ev.Reason)
	return ev
}

// credentialPrefixes are the leading substrings of well-known credential
// formats. A token in a string is replaced from its prefix to the next
// whitespace or quote.
var credentialPrefixes = []string{
	"ghp_", "ghs_", "gho_", "ghu_", "ghr_", "github_pat_",
	"sk-ant-", "sk-proj-", "sk-",
	"AKIA", "ASIA",
	"AIzaSy",
	"xoxb-", "xoxp-", "xoxa-", "xoxs-",
	"eyJhbGciO", // JWT header, base64 of {"alg":"
	"-----BEGIN",
}

// RedactString removes credential-shaped substrings from s.
//
// Two classes are handled: known token prefixes, and URL userinfo
// ("https://user:password@host"), which is how an egress_proxy secret would
// leak if its URL ended up in an error message.
func RedactString(s string) string {
	if s == "" {
		return s
	}
	out := redactURLCredentials(s)
	for _, prefix := range credentialPrefixes {
		out = redactPrefixed(out, prefix)
	}
	return out
}

// redactPrefixed replaces every run starting with prefix and ending at the
// next delimiter. Matching is case-sensitive because every prefix above has
// a fixed case, and lowering the haystack would corrupt the surviving text.
func redactPrefixed(s, prefix string) string {
	var b strings.Builder
	for {
		i := strings.Index(s, prefix)
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i])
		b.WriteString(redactionMarker)
		rest := s[i+len(prefix):]
		// Consume to the next delimiter: the credential body.
		end := strings.IndexAny(rest, " \t\n\r\"'`,;)]}")
		if end < 0 {
			return b.String()
		}
		s = rest[end:]
	}
}

// redactURLCredentials rewrites "scheme://user:pass@host" to
// "scheme://[redacted]@host". The password is the sensitive half, but the
// username in a proxy URL is often a token too, so both go.
func redactURLCredentials(s string) string {
	var b strings.Builder
	rest := s
	for {
		i := strings.Index(rest, "://")
		if i < 0 {
			b.WriteString(rest)
			return b.String()
		}
		b.WriteString(rest[:i+3])
		rest = rest[i+3:]
		// The authority ends at the first '/', '?', '#', or whitespace.
		authEnd := strings.IndexAny(rest, "/?# \t\n\r\"'")
		if authEnd < 0 {
			authEnd = len(rest)
		}
		authority := rest[:authEnd]
		if at := strings.LastIndex(authority, "@"); at >= 0 {
			b.WriteString(redactionMarker)
			b.WriteString(authority[at:])
		} else {
			b.WriteString(authority)
		}
		rest = rest[authEnd:]
	}
}

// emit redacts and forwards an event, stamping the time if unset.
func (b *Broker) emit(ev Event) {
	if ev.Time.IsZero() {
		ev.Time = b.now()
	}
	b.auditor.Audit(Redact(ev))
}

// denyf emits a denial event and returns the corresponding error. Pairing
// the two in one call is what keeps "denied but not logged" from being
// expressible: there is no path that returns a denial without emitting one.
func (b *Broker) denyf(ev Event, err error, format string, args ...any) error {
	reason := fmt.Sprintf(format, args...)
	ev.Decision = DecisionDeny
	ev.Reason = reason
	b.emit(ev)
	return wrapf(err, "%s", reason)
}

// denyErr emits a denial for an error that already carries its own sentinel
// and message, and returns it unchanged.
//
// It exists because denyf would wrap the sentinel around text that already
// contains it, producing "invalid constraint: … : invalid constraint: …" in
// the operator's terminal. Same guarantee as denyf: there is no way to
// return the denial without logging it.
func (b *Broker) denyErr(ev Event, err error) error {
	ev.Decision = DecisionDeny
	ev.Reason = err.Error()
	b.emit(ev)
	return err
}

// wrapf wraps a sentinel with formatted detail.
func wrapf(err error, format string, args ...any) error {
	return fmt.Errorf("%w: %s", err, fmt.Sprintf(format, args...))
}

// Fields renders an event as sorted key=value pairs, for text log sinks.
func (ev Event) Fields() string {
	kv := map[string]string{
		"action":   string(ev.Action),
		"decision": string(ev.Decision),
	}
	put := func(k, v string) {
		if v != "" {
			kv[k] = v
		}
	}
	put("actor", ev.Actor)
	put("subject", ev.Subject)
	put("secret_id", ev.SecretID)
	put("secret", ev.SecretName)
	put("kind", string(ev.Kind))
	put("grant_id", ev.GrantID)
	put("lease_id", ev.LeaseID)
	put("executor", ev.ExecutorID)
	put("project", ev.ProjectID)
	put("constraints", ev.Constraints)
	put("reason", ev.Reason)
	put("task", ev.TaskID)
	put("host", ev.Host)
	if ev.Port != 0 {
		kv["port"] = strconv.Itoa(ev.Port)
	}
	if ev.BytesUp != 0 {
		kv["bytes_up"] = strconv.FormatInt(ev.BytesUp, 10)
	}
	if ev.BytesDown != 0 {
		kv["bytes_down"] = strconv.FormatInt(ev.BytesDown, 10)
	}
	if !ev.ExpiresAt.IsZero() {
		kv["expires_at"] = ev.ExpiresAt.UTC().Format(time.RFC3339)
	}

	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+kv[k])
	}
	return strings.Join(parts, " ")
}
