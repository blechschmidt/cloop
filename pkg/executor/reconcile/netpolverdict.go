package reconcile

// netpolverdict.go persists what the NetworkPolicy enforcement probe found, and
// hands it back to the driver at startup.
//
// # Why the split
//
// The driver cannot store this itself: pkg/executor/kubernetes must not import
// pkg/statedb — it is imported *by* pkg/config, and a driver that needed a
// database open to answer "what are your capabilities" could not be constructed
// by a config validator. And statedb cannot hold the type, because it would
// then import the driver. So the driver owns the shape of a verdict
// (kubernetes.ProbeVerdict, JSON), and this package — which already imports
// both, and is already where a config file becomes a registry of live executors
// — owns getting it to and from disk.
//
// # Why the hub's database and not the cluster
//
// A verdict is a claim about a cluster, so an in-cluster ConfigMap is the
// tempting home: it would be visible to every hub pointed at that namespace.
// It was rejected because it would make this feature's *storage* require RBAC
// the executor does not otherwise hold — configmaps: [get create update] — and
// a security capability that fails closed when its bookkeeping is unauthorised
// would train operators to widen the executor's Role to make a warning go away.
// The hub's own database needs no new permission on anyone else's system, and
// the claim it makes is the honest one: *this hub* proved it, on this date.

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// netpolVerdictKeyPrefix namespaces one record per executor inside the hub
// metadata table. Per executor and not per cluster because two executors can
// point at different namespaces of the same cluster with different credentials,
// and a NetworkPolicy is namespaced: a verdict from one is not evidence for the
// other. kubernetes.ProbeVerdict records the executor id too, so a record that
// is somehow read under the wrong key is still rejected at resolution time.
const netpolVerdictKeyPrefix = "executor.netpol_verdict."

// NetworkPolicyVerdictKey is the hub-meta key holding one executor's verdict.
func NetworkPolicyVerdictKey(executorID string) string {
	return netpolVerdictKeyPrefix + strings.TrimSpace(executorID)
}

// LoadNetworkPolicyVerdictFromDir opens dir's control-plane database, reads one
// executor's verdict and closes it again.
//
// Its own short-lived handle rather than one borrowed from the credential
// source, because the two have different lifetimes and different owners: the
// source's database is held for the process's life by the driver, and an
// in-cluster hub has no broker at all — reading through it would silently lose
// the verdict on exactly the deployment most likely to have one.
//
// A database that cannot be opened yields the zero verdict and no error. The
// field's only effect is to grant a capability, so an unreadable record costs a
// refusal that names the probe command; failing startup over it would turn a
// narrow degradation into an outage.
func LoadNetworkPolicyVerdictFromDir(dir, executorID string) (kubernetes.ProbeVerdict, error) {
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return kubernetes.ProbeVerdict{}, nil
	}
	defer db.Close()
	return LoadNetworkPolicyVerdict(db, executorID)
}

// LoadNetworkPolicyVerdict reads the recorded verdict for one executor.
//
// A missing record is not an error — it is the state every deployment starts
// in, and it resolves to "unverified", which fails closed. A record that will
// not parse is also not an error: it is treated as missing, for the same
// reason. The alternative is a hub that refuses to start because a field it
// uses to *deny* a capability is corrupt, and denying is what a zero value
// already does.
func LoadNetworkPolicyVerdict(db *statedb.DB, executorID string) (kubernetes.ProbeVerdict, error) {
	if db == nil || strings.TrimSpace(executorID) == "" {
		return kubernetes.ProbeVerdict{}, nil
	}
	raw, ok, err := db.HubMeta(NetworkPolicyVerdictKey(executorID))
	if err != nil {
		return kubernetes.ProbeVerdict{}, fmt.Errorf("read NetworkPolicy verdict for %s: %w", executorID, err)
	}
	if !ok || strings.TrimSpace(raw) == "" {
		return kubernetes.ProbeVerdict{}, nil
	}
	var v kubernetes.ProbeVerdict
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return kubernetes.ProbeVerdict{}, nil
	}
	return v, nil
}

// SaveNetworkPolicyVerdict records a probe result for one executor.
//
// It refuses a verdict with no timestamp. ProbeVerdict.Recorded() is what tells
// every reader "a probe actually ran", so writing a zero-valued one would store
// a record that reads as evidence and is not — and, because an unrecorded
// verdict resolves to unverified, it would also be indistinguishable from
// having written nothing while looking like a successful save.
func SaveNetworkPolicyVerdict(db *statedb.DB, executorID string, v kubernetes.ProbeVerdict) error {
	if db == nil {
		return fmt.Errorf("save NetworkPolicy verdict: no control-plane database")
	}
	id := strings.TrimSpace(executorID)
	if id == "" {
		return fmt.Errorf("save NetworkPolicy verdict: no executor id")
	}
	if !v.Recorded() {
		return fmt.Errorf("save NetworkPolicy verdict for %s: the verdict has no observation time, "+
			"so it is not a probe result", id)
	}
	if v.ExecutorID == "" {
		v.ExecutorID = id
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("save NetworkPolicy verdict for %s: %w", id, err)
	}
	if err := db.SetHubMeta(NetworkPolicyVerdictKey(id), string(raw)); err != nil {
		return fmt.Errorf("save NetworkPolicy verdict for %s: %w", id, err)
	}
	return nil
}

// ForgetNetworkPolicyVerdict removes a recorded verdict.
//
// It exists so that an operator who has changed CNI can invalidate the record
// without waiting for it to expire, and so that a test can return the hub to
// the unverified state without knowing how the record is stored.
func ForgetNetworkPolicyVerdict(db *statedb.DB, executorID string) error {
	if db == nil {
		return nil
	}
	id := strings.TrimSpace(executorID)
	if id == "" {
		return nil
	}
	if err := db.DeleteHubMeta(NetworkPolicyVerdictKey(id)); err != nil {
		return fmt.Errorf("forget NetworkPolicy verdict for %s: %w", id, err)
	}
	return nil
}
