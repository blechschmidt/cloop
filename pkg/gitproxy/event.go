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
	// EventPushAllowed records a push whose every command passed policy. It is
	// emitted before forwarding, so it describes what was authorised, not what
	// the remote ultimately accepted.
	EventPushAllowed EventKind = "push_allowed"
	// EventPushDenied records a push refused by policy. This is the row that
	// matters: it is the evidence that the boundary held, and the only place a
	// sandbox's attempt to reach a protected branch is written down.
	EventPushDenied EventKind = "push_denied"
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
	// Refs are the ref names the request touched.
	Refs []string `json:"refs,omitempty"`
	// Detail is a human-readable reason or summary.
	Detail string    `json:"detail,omitempty"`
	At     time.Time `json:"at"`
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
