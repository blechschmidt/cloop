package ui

// proxy_session_store.go records the hub's proxy sessions durably (Task
// 20383) through pkg/sessionrecord: the git proxy's and the Kubernetes
// monitor's lease-path sessions and every run's egress session, written as
// this process — the holder leaseHolderID names, the cluster member id the
// run's lease is recorded under — so the process that adopts a run after this
// one stops can restore them.

import (
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/kubeguard"
	"github.com/blechschmidt/cloop/pkg/sessionrecord"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// sessionHolderID is the holder this process writes session records as, read
// on every write: tests play two processes by changing leaseHolderID.
func sessionHolderID() string { return leaseHolderID() }

// logSessionStoreErr reports a record write that failed. The session still
// works; what is lost is that its end or renewal is known to a successor.
func logSessionStoreErr(kind, id, what string, err error) {
	fmt.Fprintf(os.Stderr, "ui: %s session %s: %s: %v\n", kind, id, what, err)
}

func newGitSessionStore(db *statedb.DB) gitproxy.SessionStore {
	return sessionrecord.NewGitStore(db, sessionHolderID, logSessionStoreErr)
}

func newKubeSessionStore(db *statedb.DB) kubeguard.SessionStore {
	return sessionrecord.NewKubeStore(db, sessionHolderID, logSessionStoreErr)
}

func newEgressSessionStore(db *statedb.DB) egressbroker.SessionStore {
	return sessionrecord.NewEgressStore(db, sessionHolderID, logSessionStoreErr)
}

// durableSession reports whether a session standing on leaseID is recorded:
// the lease must be one this process records, which takes a holder id — the
// same condition brokerOptions applies to the lease itself.
func durableSession(leaseID string) bool {
	return leaseID != "" && leaseHolderID() != ""
}
