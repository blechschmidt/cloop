package pm

// quarantine.go is the data model for a task the control plane suspects of
// taking down the nodes that run it (Task 20391).
//
// Executor failover moves a run off a node that stopped answering onto another
// one. When the node died *because of* the run — a fork bomb, a workload that
// exhausts memory, one that panics the kernel — the failover hands the next
// node the same fate. executors.failover.max_attempts bounds how far one run
// carries it. The quarantine is the other half: a task that two or more
// distinct nodes went down under is marked, and it is not run again — not by
// the next dispatch, not by --retry-failed, not by an automatic resume — until
// somebody resets it on purpose.
//
// The mark is evidence, not proof. A fleet whose nodes fail for unrelated
// reasons can put two losses on an innocent task, which is why it is a
// suspicion that a person clears with one reset, rather than a deletion.

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// QuarantineNodeKiller is TaskQuarantine.Kind for a task two or more distinct
// executors went unreachable under.
const QuarantineNodeKiller = "node_killer"

// NodeKillerThreshold is how many distinct executors must have gone
// unreachable while a task was running before it is suspected of taking them
// down. One lost node is a flaky node; two different ones under the same task
// are a pattern.
const NodeKillerThreshold = 2

// NodeLoss is one executor that went unreachable while a task was running on
// it.
type NodeLoss struct {
	// ExecutorID is the executor that went unreachable.
	ExecutorID string `json:"executor_id"`
	// LostAt is when it was found unreachable.
	LostAt time.Time `json:"lost_at"`
	// SessionID is the executor session that was lost with it.
	SessionID string `json:"session_id,omitempty"`
	// Attempt is that session's attempt number: 1 for the original dispatch.
	Attempt int `json:"attempt,omitempty"`
}

// TaskQuarantine marks a task that runs again only after an explicit reset.
type TaskQuarantine struct {
	// Kind is what the task is suspected of; QuarantineNodeKiller.
	Kind string `json:"kind"`
	// Reason is one sentence naming the nodes.
	Reason string `json:"reason,omitempty"`
	// Nodes are the losses behind the mark, oldest first.
	Nodes []NodeLoss `json:"nodes,omitempty"`
	// MarkedAt is when the task was marked.
	MarkedAt time.Time `json:"marked_at"`
	// MarkedBy is what marked it, e.g. "failover".
	MarkedBy string `json:"marked_by,omitempty"`
}

// Quarantined reports whether t is held back until an explicit reset.
func (t *Task) Quarantined() bool { return t != nil && t.Quarantine != nil }

// DistinctNodes returns the distinct executors in losses, in the order each
// first went down.
func DistinctNodes(losses []NodeLoss) []string {
	seen := make(map[string]bool, len(losses))
	var out []string
	for _, l := range SortNodeLosses(losses) {
		if l.ExecutorID == "" || seen[l.ExecutorID] {
			continue
		}
		seen[l.ExecutorID] = true
		out = append(out, l.ExecutorID)
	}
	return out
}

// SuspectedNodeKiller reports whether losses make a task a suspected node
// killer: NodeKillerThreshold or more distinct executors.
func SuspectedNodeKiller(losses []NodeLoss) bool {
	return len(DistinctNodes(losses)) >= NodeKillerThreshold
}

// SortNodeLosses returns a copy of losses ordered by when each node went down.
func SortNodeLosses(losses []NodeLoss) []NodeLoss {
	out := append([]NodeLoss(nil), losses...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].LostAt.Before(out[j].LostAt) })
	return out
}

// DescribeNodeLosses renders losses as "sgx (unreachable 2026-10-06T12:00:01Z),
// edge-2 (unreachable 2026-10-06T12:03:10Z)", oldest first — the form every
// reason, journal row and listing uses, so an operator can grep one for the
// others.
func DescribeNodeLosses(losses []NodeLoss) string {
	parts := make([]string, 0, len(losses))
	for _, l := range SortNodeLosses(losses) {
		when := "at an unrecorded time"
		if !l.LostAt.IsZero() {
			when = l.LostAt.UTC().Format(time.RFC3339)
		}
		parts = append(parts, fmt.Sprintf("%s (unreachable %s)", l.ExecutorID, when))
	}
	return strings.Join(parts, ", ")
}
