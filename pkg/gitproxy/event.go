package gitproxy

import (
	"fmt"
	"strings"
	"time"
)

// EventKind names what happened.
type EventKind string

const (
	// EventSessionMinted records a session coming into existence.
	EventSessionMinted EventKind = "session_minted"
	// EventSessionClosed records one going away, by revocation or expiry.
	EventSessionClosed EventKind = "session_closed"
	// EventSessionRenewed records a session's deadline moved by Renew.
	EventSessionRenewed EventKind = "session_renewed"
	// EventPushAllowed records a push whose every command passed policy — and,
	// unless the push scan is off, whose pack carried none of the run's
	// credentials. It is emitted before the forge's verdict is forwarded, so
	// it describes what was authorised, not what the remote ultimately
	// accepted.
	EventPushAllowed EventKind = "push_allowed"
	// EventPushDenied records a push refused by policy. This is the row that
	// matters: it is the evidence that the boundary held, and the only place a
	// sandbox's attempt to reach a protected branch is written down.
	EventPushDenied EventKind = "push_denied"
	// EventPushSecretRefused records a push refused because it carries a
	// credential the session's run was given (Task 20436). Its Findings name
	// the objects and the grant and secret each value came from — never the
	// value.
	EventPushSecretRefused EventKind = "push_secret_refused"
	// EventFetch records a read through the proxy.
	EventFetch EventKind = "fetch"
	// EventRejected records a request refused before policy ran at all —
	// unauthenticated, wrong repository, malformed, or a route this proxy does
	// not serve.
	EventRejected EventKind = "rejected"
)

// Event is one observation for the compliance trail.
//
// It carries no credential and no object content: the fields are IDs, ref
// names and reasons, all of which are safe to write to a log an operator
// reads. The audit value is in the refusals — a push_denied naming
// refs/heads/main is a sandbox that tried, and nothing else in the system
// would have recorded it.
type Event struct {
	Kind      EventKind `json:"kind"`
	SessionID string    `json:"session_id,omitempty"`
	RepoPath  string    `json:"repo_path,omitempty"`
	ProjectID string    `json:"project_id,omitempty"`
	TaskID    string    `json:"task_id,omitempty"`
	Actor     string    `json:"actor,omitempty"`
	// RunID is the run the session serves, on a push_secret_refused row: what
	// the hub files the refusal in the run's history by.
	RunID string `json:"run_id,omitempty"`
	// Refs are the ref names the request touched, with any of the run's
	// credentials a name carries taken out.
	Refs []string `json:"refs,omitempty"`
	// Detail is a human-readable reason or summary.
	Detail string `json:"detail,omitempty"`
	// Findings are where a push_secret_refused push carries a credential.
	Findings []ScanFinding `json:"findings,omitempty"`
	// Scan is set on a push the scan refused (Task 20436): ScanResultSecret
	// on a push_secret_refused row, ScanResultLimit or ScanResultUnreadable
	// on a push_denied one.
	Scan string    `json:"scan,omitempty"`
	At   time.Time `json:"at"`
}

// String renders the event as one log line.
func (e Event) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "gitproxy %s", e.Kind)
	if e.SessionID != "" {
		fmt.Fprintf(&b, " session=%s", e.SessionID)
	}
	if e.RepoPath != "" {
		fmt.Fprintf(&b, " repo=%s", e.RepoPath)
	}
	if e.ProjectID != "" {
		fmt.Fprintf(&b, " project=%s", e.ProjectID)
	}
	if e.TaskID != "" {
		fmt.Fprintf(&b, " task=%s", e.TaskID)
	}
	if len(e.Refs) > 0 {
		fmt.Fprintf(&b, " refs=%s", strings.Join(e.Refs, ","))
	}
	if e.Detail != "" {
		fmt.Fprintf(&b, " detail=%q", e.Detail)
	}
	return b.String()
}

// refNames pulls the ref names out of a command list for an Event.
func refNames(cmds []RefUpdate) []string {
	out := make([]string, 0, len(cmds))
	for _, c := range cmds {
		out = append(out, c.Ref)
	}
	return out
}
