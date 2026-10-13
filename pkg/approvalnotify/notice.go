// Package approvalnotify tells the people who can decide a grant request or
// approve an API token that one is waiting on them (Task 20427).
//
// Two decisions wait on an administrator — a self-service grant request (Task
// 20271) and an API token a role policy suspends until it is approved (Task
// 20422) — and before this package nothing reached the people who could make
// them: a request lapsed after three days unless an approver happened to open
// the Secrets tab. The hub's leader now records a notice for every moment worth
// telling — a request filed, twelve hours from lapsing, decided, withdrawn or
// lapsed; a token that started waiting — and posts each to the webhooks in
// notifications.webhooks.
//
// Three properties shape it:
//
//   - Once per cluster. Notices are found by a scan of the control plane's
//     own rows, so every path that changes a request — the dashboard, `cloop
//     hub grant`, an offboarding — is seen, and each is recorded under a unique
//     key, so however many passes or members notice a moment it is sent once.
//     Only the leader scans and sends.
//   - Nothing secret leaves. A notice carries identities, the secret's name and
//     kind, the subject, deadlines and a link to the dashboard. Not the
//     requester's justification (free text, kept for the dashboard), not a
//     decision note, and nothing credential-shaped: every string is run
//     through the credential-pattern scrubber (pkg/redact) before it is
//     rendered.
//   - Nowhere it was not sent. The client posts https only, follows no
//     redirect, uses no proxy, and checks the address it actually dials:
//     loopback, private and link-local receivers only when the webhook's
//     allow_addresses names them, cloud metadata services never.
package approvalnotify

import (
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// EventTest is a message sent from Settings to check a webhook. It is never
// recorded as a notice.
const EventTest = "test"

// Notice is one thing worth telling approvers, as recorded in the outbox.
//
// It holds what a message may say and nothing else. There is no field for a
// justification, a note, constraints or anything a credential could ride in,
// so a renderer cannot leak one by mistake.
type Notice struct {
	Event string    `json:"event"`
	At    time.Time `json:"at"`

	// The grant request, for request.* events.
	RequestID   string `json:"request_id,omitempty"`
	RequestedBy string `json:"requested_by,omitempty"`
	SecretName  string `json:"secret_name,omitempty"`
	SecretKind  string `json:"secret_kind,omitempty"`
	Subject     string `json:"subject,omitempty"`
	DecidedBy   string `json:"decided_by,omitempty"`

	// The API token, for token.waiting.
	TokenID   string   `json:"token_id,omitempty"`
	TokenName string   `json:"token_name,omitempty"`
	Roles     []string `json:"roles,omitempty"`
	CreatedBy string   `json:"created_by,omitempty"`

	// Deadline is when the request lapses undecided, or the token expires;
	// zero for a token that never expires.
	Deadline time.Time `json:"deadline,omitempty"`
}

// Key is the notice's outbox key: the event and what it is about. Unique, so a
// moment noticed twice is recorded once.
func (n Notice) Key() string {
	id := n.RequestID
	if strings.HasPrefix(n.Event, "token.") {
		id = n.TokenID
	}
	return n.Event + ":" + id
}

// TokenInfo is an API token waiting for an administrator's approval, as the
// hub describes it: never its hash, never its secret.
type TokenInfo struct {
	ID        string
	Name      string
	Roles     []string
	CreatedBy string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Snapshot is what the scan looks at: the control plane's requests and the
// tokens waiting on an approval.
type Snapshot struct {
	// Requests is every access request; RequestsKnown is false when they
	// could not be read (no secret broker on this hub), so the scan and the
	// staleness check know an absence means nothing.
	Requests      []secretbroker.AccessRequest
	RequestsKnown bool

	// Waiting is the tokens a role policy this hub enforces suspends until
	// approved — empty, and TokensKnown true, on a hub enforcing none.
	Waiting     []TokenInfo
	TokensKnown bool
}

// Scan returns every notice the snapshot supports at now. Decisions and lapses
// are reported from since on, so a webhook configured today is not told about
// last month's decisions; what is still waiting is reported whenever it is
// seen, because it is still actionable. The caller records each by Key, so a
// notice found again is not sent again.
func Scan(snap Snapshot, since, now time.Time) []Notice {
	var out []Notice
	for _, r := range snap.Requests {
		base := requestNotice(r)
		switch {
		case r.Pending(now):
			filed := base
			filed.Event, filed.At = config.NotifyEventRequestFiled, r.CreatedAt
			out = append(out, filed)
			if remindAt, ok := reminderTime(r); ok && !now.Before(remindAt) {
				rem := base
				rem.Event, rem.At = config.NotifyEventRequestReminder, remindAt
				out = append(out, rem)
			}
		case r.State == secretbroker.RequestApproved, r.State == secretbroker.RequestDenied,
			r.State == secretbroker.RequestWithdrawn:
			if r.DecidedAt.IsZero() || r.DecidedAt.Before(since) {
				continue
			}
			d := base
			d.At, d.DecidedBy = r.DecidedAt, r.DecidedBy
			switch r.State {
			case secretbroker.RequestApproved:
				d.Event = config.NotifyEventRequestApproved
			case secretbroker.RequestDenied:
				d.Event = config.NotifyEventRequestDenied
			default:
				d.Event = config.NotifyEventRequestWithdrawn
			}
			out = append(out, d)
		case r.State == secretbroker.RequestExpired, r.State == secretbroker.RequestPending:
			// Pending past its deadline is lapsed whether or not a sweep has
			// moved the row yet, as the broker reads it.
			if r.ExpiresAt.IsZero() || r.ExpiresAt.Before(since) {
				continue
			}
			l := base
			l.Event, l.At = config.NotifyEventRequestLapsed, r.ExpiresAt
			out = append(out, l)
		}
	}
	for _, t := range snap.Waiting {
		out = append(out, Notice{
			Event: config.NotifyEventTokenWaiting, At: now,
			TokenID: t.ID, TokenName: t.Name, Roles: append([]string(nil), t.Roles...),
			CreatedBy: t.CreatedBy, Deadline: t.ExpiresAt,
		})
	}
	return out
}

// reminderTime is when a request's reminder is due: NotificationReminderLead
// before it lapses. A request asked to wait less than that has none — the
// notice that it was filed already named its deadline.
func reminderTime(r secretbroker.AccessRequest) (time.Time, bool) {
	if r.ExpiresAt.IsZero() {
		return time.Time{}, false
	}
	at := r.ExpiresAt.Add(-config.NotificationReminderLead)
	if r.CreatedAt.After(at) {
		return time.Time{}, false
	}
	return at, true
}

// requestNotice copies what a message may say about a request.
func requestNotice(r secretbroker.AccessRequest) Notice {
	return Notice{
		RequestID:   r.ID,
		RequestedBy: r.RequestedBy,
		SecretName:  r.SecretName,
		SecretKind:  string(r.Kind),
		Subject:     r.Subject.String(),
		Deadline:    r.ExpiresAt,
	}
}

// Superseded reports whether a notice that something is waiting no longer
// describes the world: the request was decided, withdrawn or lapsed, or the
// token approved or revoked, before the notice could be sent. Telling an
// approver to act on something already settled is worse than saying nothing.
func Superseded(n Notice, snap Snapshot, now time.Time) bool {
	switch n.Event {
	case config.NotifyEventRequestFiled, config.NotifyEventRequestReminder:
		if !snap.RequestsKnown {
			return false
		}
		for _, r := range snap.Requests {
			if r.ID == n.RequestID {
				return !r.Pending(now)
			}
		}
		return true
	case config.NotifyEventTokenWaiting:
		if !snap.TokensKnown {
			return false
		}
		for _, t := range snap.Waiting {
			if t.ID == n.TokenID {
				return false
			}
		}
		return true
	}
	return false
}
