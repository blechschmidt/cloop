package secretbroker

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/redact"
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

	// Lease revocation actions (Task 20178). These are separate from
	// ActionRelease because releasing a lease and revoking one answer
	// different questions. A release is the ordinary end of a workload's
	// credential lifetime; a revocation is somebody deciding, mid-run, that
	// an executor may no longer hold something it already has.
	//
	// All three exist because a revocation is not one event. It is sent,
	// and then it either lands or it does not, possibly minutes later when
	// an offline device reconnects. Collapsing them into one row would make
	// the trail claim a credential was withdrawn at a moment when it
	// demonstrably still worked.
	ActionLeaseRevokeSent   Action = "lease.revoke_sent"
	ActionLeaseRevokeAcked  Action = "lease.revoke_acked"
	ActionLeaseRevokeFailed Action = "lease.revoke_failed"

	// ActionAppTokenDestroy records a GitHub App installation token being
	// destroyed at GitHub (Task 20254).
	//
	// It is deliberately not ActionRevoke. A github_app token is destroyed on
	// every ordinary lease release, so folding these rows into `secret.revoke`
	// would make "how many grants did an operator withdraw" a number dominated
	// by routine task teardown — and the one question the revoke series exists
	// to answer would stop having an answer.
	//
	// It is also not ActionRelease, for the reason the lease.revoke_* family is
	// separate from it: a release says a workload finished with a credential,
	// while this says a credential stopped existing. When the DELETE fails the
	// first is still true and the second is not, and an incident response needs
	// to be able to tell those apart.
	ActionAppTokenDestroy Action = "github_app.token_destroy"

	// Self-service request actions (Task 20271).
	//
	// Separate from the secret.grant family rather than folded into it, because
	// a request and a grant are different facts and a reviewer needs to tell
	// them apart. secret.grant answers "what authority exists"; these answer
	// "who asked, who decided, and how long it took" — and the gap between a
	// request and its approval is the number that tells an operator whether the
	// request path is actually being used or routed around.
	//
	// secret.request_expire is its own action, not a flavour of deny, for the
	// reason RequestExpired is its own state: denied is an answer and expired is
	// the absence of one, and a trail that conflated them would hide a queue
	// nobody is working.
	ActionRequestOpen     Action = "secret.request"
	ActionRequestApprove  Action = "secret.request_approve"
	ActionRequestDeny     Action = "secret.request_deny"
	ActionRequestWithdraw Action = "secret.request_withdraw"
	ActionRequestExpire   Action = "secret.request_expire"

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
	// RequestID is the access request an event concerns (Task 20271). Present
	// on the request family above, and on nothing else: a grant minted directly
	// has no request behind it, and leaving the field empty is what makes
	// "which grants came through review" answerable from the trail.
	RequestID  string `json:"request_id,omitempty"`
	LeaseID    string `json:"lease_id,omitempty"`
	ExecutorID string `json:"executor_id,omitempty"`
	ProjectID  string `json:"project_id,omitempty"`
	// RunID names the execution a lease was issued to (Task 20282). It is what
	// makes "which credentials did this task hold" answerable exactly: a task
	// id may run many times and unions every attempt's leases, whereas a run id
	// names the one execution that spent them.
	//
	// Populated for dispatch-time leases. Empty for grant and mint events,
	// which are operator actions with no execution behind them.
	RunID string `json:"run_id,omitempty"`
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

// redactionMarker replaces anything scrubbed out of an audit reason. It is
// redact.Marker, so a reason reads the same whichever layer caught the value.
const redactionMarker = redact.Marker

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

// RedactString removes credential-shaped substrings from s.
//
// The shapes are pkg/redact's registry — GitHub tokens in both forms, cloop's
// own tokens, cloud and model-provider keys, JWTs, PEM private keys, kubeconfig
// credentials, Authorization values and URL userinfo — so an audit reason is
// scrubbed of exactly what cloop audit would report in it. This package keeps
// only its replacement: every credential becomes "[redacted]", with whatever
// identified it ("Bearer ", a URL's host) left readable around the marker.
//
// It used to carry its own prefix list, scrubbing from a prefix to the next
// delimiter. That knew none of cloop's own prefixes, turned "risk-free" into
// "ri[redacted]" on the bare "sk-", and removed only the "-----BEGIN" of a
// private key while the key itself went into the log.
func RedactString(s string) string {
	if s == "" {
		return s
	}
	mark := func(redact.Match) string { return redactionMarker }
	if len(s) <= maxReasonBytes+reasonScanMargin {
		return redact.ScrubFunc(s, mark)
	}
	s = redact.ScrubFunc(clipUTF8(s, maxReasonBytes+reasonScanMargin), mark)
	return clipUTF8(s, maxReasonBytes) + reasonTruncated
}

// maxReasonBytes is how much of a long reason RedactString keeps. A reason is
// a sentence for a person, but it quotes text a stranger chose — a secret
// reference from a request body, a URI the egress proxy refused — and it is
// scrubbed twice on its way to the store, so unbounded, both the cost of the
// scrubbing and the size of the row were the stranger's to pick.
//
// reasonScanMargin is read past the cut before it is made, so a credential the
// cut would halve is scrubbed whole; and a reason already cut is short enough
// not to be cut again, which keeps the store's second pass from changing it.
const (
	maxReasonBytes   = 8 << 10
	reasonScanMargin = 4 << 10
	reasonTruncated  = "…[truncated]"
)

// clipUTF8 returns at most the first n bytes of s, cut on a rune boundary.
func clipUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
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
	put("request_id", ev.RequestID)
	put("lease_id", ev.LeaseID)
	put("executor", ev.ExecutorID)
	put("project", ev.ProjectID)
	put("run_id", ev.RunID)
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
