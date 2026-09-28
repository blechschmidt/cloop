package ui

// cluster_handles.go scopes durable workload handles to the hub member that
// dispatched them (Task 20354).
//
// executor_handles is how a restarted hub finds the containers, Pods and host
// processes its predecessor was running (Task 20191): every driver rehydrates
// from it at construction and adopts what it finds. With one hub that is
// exactly right. With several it is a hazard — a member starting up would
// adopt its peers' live workloads, and two members streaming, settling and
// (for Kubernetes) renewing leases for the same Pod is two owners for one
// run.
//
// So every row a member writes carries its member id, and the store a member's
// drivers read from hides rows a *live* peer wrote. Rows of a dead member stay
// visible, which is what makes adoption after a crash work: the member that
// re-attaches this store once the owner is judged dead finds them. Rows with
// no id — written before clustering — are visible to all, which is the
// pre-cluster behaviour.
//
// Remote-agent rows are never hidden. They belong to the agent, not to a
// member: the agent's workload is reachable from whichever member it is
// connected to, and the member it reconnects to after a move must adopt them
// or refuse the agent's resume offer and terminate a healthy run.

import (
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// handleMetaInstance is the HandleRecord.Meta key naming the member that
// wrote the row. Meta is stored verbatim; the value is an opaque member id.
const handleMetaInstance = "hub_instance"

// clusterHandleStore is a member-scoped view of a HandleStore.
type clusterHandleStore struct {
	inner executor.HandleStore
	node  *hubcluster.Node
}

// scopeHandleStore wraps store for node, or returns it unchanged for a
// standalone hub.
func scopeHandleStore(store executor.HandleStore, node *hubcluster.Node) executor.HandleStore {
	if store == nil || node == nil {
		return store
	}
	if _, already := store.(*clusterHandleStore); already {
		return store
	}
	return &clusterHandleStore{inner: store, node: node}
}

// PutHandle stamps the row with this member.
func (c *clusterHandleStore) PutHandle(rec executor.HandleRecord) error {
	meta := make(map[string]string, len(rec.Meta)+1)
	for k, v := range rec.Meta {
		meta[k] = v
	}
	meta[handleMetaInstance] = c.node.ID()
	rec.Meta = meta
	return c.inner.PutHandle(rec)
}

// ListHandles returns the rows this member may adopt.
func (c *clusterHandleStore) ListHandles(executorID string) ([]executor.HandleRecord, error) {
	rows, err := c.inner.ListHandles(executorID)
	if err != nil {
		return nil, err
	}
	out := rows[:0:0]
	for _, r := range rows {
		if !c.trackedByLivePeer(r) {
			out = append(out, r)
		}
	}
	return out, nil
}

// ListForeignHandles returns the rows a live peer tracks.
func (c *clusterHandleStore) ListForeignHandles(executorID string) ([]executor.HandleRecord, error) {
	rows, err := c.inner.ListHandles(executorID)
	if err != nil {
		return nil, err
	}
	var out []executor.HandleRecord
	for _, r := range rows {
		if c.trackedByLivePeer(r) {
			out = append(out, r)
		}
	}
	return out, nil
}

// DeleteHandle removes a row. Only rows ListHandles returned ever reach a
// driver, so a member can only delete what it owns or adopted.
func (c *clusterHandleStore) DeleteHandle(handleID string) error {
	return c.inner.DeleteHandle(handleID)
}

// trackedByLivePeer reports whether r belongs to another live member.
func (c *clusterHandleStore) trackedByLivePeer(r executor.HandleRecord) bool {
	if strings.TrimSpace(r.Driver) == executor.KindRemoteAgent {
		return false
	}
	owner := strings.TrimSpace(r.Meta[handleMetaInstance])
	if owner == "" || owner == c.node.ID() {
		return false
	}
	return c.node.IsAlive(owner)
}

// clusterScopedHandleStore returns the member-scoped handle store for the
// control plane at dir, or nil — the reconcile package's default — for a
// standalone hub. Opened for the process's life, like the default store.
func clusterScopedHandleStore(dir string, node *hubcluster.Node) executor.HandleStore {
	if node == nil || strings.TrimSpace(dir) == "" {
		return nil
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: open handle store for the hub cluster: %v\n", err)
		return nil
	}
	store, err := executorstore.NewHandles(db)
	if err != nil {
		_ = db.Close()
		fmt.Fprintf(os.Stderr, "ui: open handle store for the hub cluster: %v\n", err)
		return nil
	}
	return scopeHandleStore(store, node)
}

// clusterSweepGate decides which executor sweeps this process runs. The
// startup sweep only while no other member serves; the periodic orphan sweep
// only on the leader. See reconcile.Options.SweepGate.
func clusterSweepGate(node *hubcluster.Node) func(periodic bool) bool {
	if node == nil {
		return nil
	}
	return func(periodic bool) bool {
		if periodic {
			return node.IsLeader()
		}
		return !node.HasPeers()
	}
}

// clusterProbeFilter decides which executors this process's supervisor
// probes: an edge agent (or a sub-executor of one) by the member holding its
// socket — or by the leader when nobody does, which is when it really is
// unreachable — and every other executor by the leader alone. See
// executor.WithProbeFilter.
func clusterProbeFilter(node *hubcluster.Node) func(executor.Executor) bool {
	if node == nil {
		return nil
	}
	return func(ex executor.Executor) bool {
		agent := ""
		if v, ok := ex.(interface{ ParentID() string }); ok {
			agent = strings.TrimSpace(v.ParentID())
		} else if ex.Kind() == executor.KindRemoteAgent {
			agent = ex.ID()
		}
		if agent == "" {
			return node.IsLeader()
		}
		o, found, err := node.Lookup(ownerAgent, agent)
		if err == nil && found && o.Alive {
			return o.Self
		}
		return node.IsLeader()
	}
}
