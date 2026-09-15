package kubeguard

// event.go defines what the monitor writes down.
//
// The audit rows are the reason a monitor is worth more than a narrower
// credential: a kubeconfig that cannot reach kube-system produces silence
// when something tries, while this produces a row naming who tried, what they
// asked for, and why it was refused.
//
// Every field here is an identifier, a resource name, a namespace or a
// reason. There is no field that can hold credential material or object
// content, which is what makes an Event safe to write into a table an
// operator exports to a SIEM.

import (
	"fmt"
	"strings"
	"time"
)

// EventKind classifies an audit row.
type EventKind string

const (
	EventSessionMinted EventKind = "session_minted"
	EventSessionClosed EventKind = "session_closed"
	// EventRequestDenied is the row that matters. It is the only place a
	// sandbox's attempt to write to, or read outside, its granted scope is
	// recorded, and nothing else in cloop would record it.
	EventRequestDenied EventKind = "request_denied"
	// EventRequestAllowed is sampled rather than written per request; see
	// Registry.OnEvent's contract in session.go.
	EventRequestAllowed EventKind = "request_allowed"
	// EventRejected covers refusals that happen before a session is
	// identified: no credential, an unknown token, an expired session.
	EventRejected EventKind = "rejected"
)

// Event is one audit row.
type Event struct {
	Kind      EventKind
	SessionID string
	// Cluster is the API server endpoint the session is pinned to, so a fleet
	// with several clusters can be read apart. It is a URL, never a
	// credential.
	Cluster string
	// Context is the kubeconfig context the session was minted from.
	Context string
	// Verb, Resource, Namespace and Name describe the request. Empty on
	// session lifecycle rows.
	Verb      string
	Resource  string
	Namespace string
	Name      string
	// Reason classifies a denial, for metrics.
	Reason DenyReason

	ProjectID  string
	TaskID     string
	ExecutorID string
	Actor      string
	GrantID    string
	LeaseID    string

	Detail string
	At     time.Time
}

// String renders the event for a log line.
func (e Event) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s session=%s", e.Kind, orNone(e.SessionID))
	if e.Cluster != "" {
		fmt.Fprintf(&b, " cluster=%s", e.Cluster)
	}
	if e.Verb != "" {
		fmt.Fprintf(&b, " verb=%s", e.Verb)
	}
	if e.Resource != "" {
		fmt.Fprintf(&b, " resource=%s", e.Resource)
	}
	if e.Namespace != "" {
		fmt.Fprintf(&b, " namespace=%s", e.Namespace)
	}
	if e.Name != "" {
		fmt.Fprintf(&b, " name=%s", e.Name)
	}
	if e.Reason != "" {
		fmt.Fprintf(&b, " reason=%s", e.Reason)
	}
	if e.ProjectID != "" {
		fmt.Fprintf(&b, " project=%s", e.ProjectID)
	}
	if e.Detail != "" {
		fmt.Fprintf(&b, " detail=%q", e.Detail)
	}
	return b.String()
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(none)"
	}
	return s
}

// eventFor builds the request-shaped fields of an event from a parsed
// request, so the allowed and denied paths cannot describe the same request
// differently.
func (s *Session) eventFor(kind EventKind, r APIRequest) Event {
	e := Event{
		Kind:       kind,
		SessionID:  s.ID,
		Cluster:    s.ClusterURL,
		Context:    s.ContextName,
		Verb:       r.Verb,
		Namespace:  r.Namespace,
		Name:       r.Name,
		ProjectID:  s.ProjectID,
		TaskID:     s.TaskID,
		ExecutorID: s.ExecutorID,
		Actor:      s.Actor,
		GrantID:    s.GrantID,
		LeaseID:    s.LeaseID,
	}
	if r.IsResource {
		e.Resource = r.ResourceString()
	} else {
		e.Resource = r.Path
	}
	return e
}
