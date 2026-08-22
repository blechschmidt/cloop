// Secret-lease plumbing for the Web UI (Task 20159).
//
// Before the broker, the orchestrator read the whole flat secret store and
// put every entry in the environment of every workload. This file replaces
// that at the UI's two spawn points: a workload now gets a lease — only the
// grants whose subject matches its executor and project, each minimized
// against its own constraints — materialised into a tmpfs directory that is
// wiped when the workload exits.
//
// Failure policy is deliberate and asymmetric:
//
//   - No CLOOP_SECRET_KEY, no broker tables, no grants: the workload starts
//     with no brokered credentials. This is the pre-broker status quo for an
//     install that has not adopted the broker, and failing the run would
//     make upgrading cloop break every project that never had secrets.
//   - A broker that exists but denies a specific grant: the denial is
//     audited and that credential is absent. The run continues, because a
//     revoked GitHub token should not stop a task that does not need GitHub.
//
// What never happens is a widening: there is no path here that falls back to
// the old "inject everything" behaviour when the broker is unavailable.

package ui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// leaseTimeout bounds how long acquiring credentials may delay a start.
// A workload that cannot get its lease promptly starts without it rather
// than hanging an HTTP handler.
const leaseTimeout = 10 * time.Second

// liveLeases tracks the leases this hub has issued and still holds open, so
// GET /api/leases can answer "which executor is holding which credential
// right now" and POST /api/leases/{id}/revoke can take it away (Task 20171).
//
// A registry is needed because Broker.leases is per-instance and every spawn
// builds its own broker over the control-plane database. Asking a freshly
// constructed broker to list leases would truthfully report none, which is
// the worst possible answer for a panel whose job is to show outstanding
// access.
//
// It holds only leases this process issued and has not yet wiped. That is
// the honest scope: a lease's materials live in a tmpfs directory this
// process owns, so a lease it does not hold is one it could not revoke
// either, and listing it would offer a button that does nothing.
var liveLeases = &leaseRegistry{active: make(map[string]*secretLease)}

// leaseRegistry is a concurrent set of open leases keyed by lease ID.
type leaseRegistry struct {
	mu     sync.Mutex
	active map[string]*secretLease
}

// add records an open lease. Called once per successful materialisation.
func (lr *leaseRegistry) add(sl *secretLease) {
	if sl == nil || sl.lease == nil {
		return
	}
	lr.mu.Lock()
	lr.active[sl.lease.ID] = sl
	lr.mu.Unlock()
}

// remove forgets a lease without wiping it. Close calls this; callers that
// want the credentials gone want revoke instead.
func (lr *leaseRegistry) remove(id string) {
	lr.mu.Lock()
	delete(lr.active, id)
	lr.mu.Unlock()
}

// snapshot returns the currently open leases, newest first.
func (lr *leaseRegistry) snapshot() []*secretLease {
	lr.mu.Lock()
	out := make([]*secretLease, 0, len(lr.active))
	for _, sl := range lr.active {
		out = append(out, sl)
	}
	lr.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		return out[i].lease.IssuedAt.After(out[j].lease.IssuedAt)
	})
	return out
}

// revoke wipes one lease's credential directory and releases it, reporting
// whether the lease was open here.
//
// The lease is dropped from the map *before* Close runs. Close calls remove
// itself, and holding the mutex across it would deadlock; doing it in this
// order also means a second concurrent revoke of the same ID reports false
// rather than racing to wipe the same directory twice.
func (lr *leaseRegistry) revoke(id string) (*secretLease, bool) {
	lr.mu.Lock()
	sl, ok := lr.active[id]
	delete(lr.active, id)
	lr.mu.Unlock()
	if !ok {
		return nil, false
	}
	sl.Close()
	return sl, true
}

// secretLease couples a lease to the mount holding its files, so a caller
// has one thing to close.
type secretLease struct {
	broker *secretbroker.Broker
	lease  *secretbroker.Lease
	mount  *secretbroker.Mount
	closer func()

	once sync.Once
}

// Env returns the environment additions for the workload, or nil.
func (sl *secretLease) Env() []string {
	if sl == nil || sl.mount == nil {
		return nil
	}
	return sl.mount.Env()
}

// Bindings projects the mount's per-grant attribution onto the driver-facing
// executor.SecretBinding, so the executor that receives this spec can take one
// credential back mid-run instead of only at exit.
//
// The TTL rides along. A driver that loses contact with the control plane can
// then expire the material locally rather than holding it indefinitely, which
// is the difference between a lease TTL that binds the whole system and one
// that binds only the hub.
func (sl *secretLease) Bindings() []executor.SecretBinding {
	if sl == nil || sl.lease == nil || sl.mount == nil {
		return nil
	}
	raw := sl.mount.Bindings()
	out := make([]executor.SecretBinding, 0, len(raw))
	for _, b := range raw {
		out = append(out, executor.SecretBinding{
			LeaseID:    sl.lease.ID,
			GrantID:    b.GrantID,
			SecretName: b.SecretName,
			Kind:       string(b.Kind),
			EnvKeys:    b.EnvKeys,
			Files:      b.Files,
			Dir:        b.Dir,
			Egress:     b.Kind == secretbroker.KindEgressProxy,
			ExpiresAt:  sl.lease.ExpiresAt,
		})
	}
	return out
}

// ExecutorID returns the executor this lease was issued to, or "".
func (sl *secretLease) ExecutorID() string {
	if sl == nil || sl.lease == nil {
		return ""
	}
	return sl.lease.ExecutorID
}

// Close wipes the credential directory and releases the lease. Idempotent,
// so it is safe both in a defer and on an explicit early return.
func (sl *secretLease) Close() {
	if sl == nil {
		return
	}
	sl.once.Do(func() {
		if sl.lease != nil {
			liveLeases.remove(sl.lease.ID)
		}
		if sl.mount != nil {
			if err := sl.mount.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "ui: wipe secret lease: %v\n", err)
			}
		}
		if sl.broker != nil && sl.lease != nil {
			sl.broker.Release(sl.lease.ID)
		}
		if sl.closer != nil {
			sl.closer()
		}
	})
}

// acquireSecretLease leases and materialises the credentials for a workload.
//
// It returns nil (not an error) when there is nothing to deliver, so callers
// can treat "no secrets" and "broker not configured" identically: both mean
// "start the workload with its ordinary environment".
func acquireSecretLease(controlPlaneDir, workDir, executorID string) *secretLease {
	broker, closeDB, err := openUIBroker(controlPlaneDir)
	if err != nil {
		// Not configured is the common case and is not worth a log line on
		// every run; a genuine failure is.
		if !isBrokerUnconfigured(err) {
			fmt.Fprintf(os.Stderr, "ui: secret broker unavailable: %v\n", err)
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), leaseTimeout)
	defer cancel()

	lease, err := broker.LeaseFor(ctx, secretbroker.Requester{
		ExecutorID: executorID,
		ProjectID:  workDir,
	}, "ui")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: lease secrets for %s: %v\n", workDir, err)
		closeDB()
		return nil
	}
	if lease.Empty() {
		broker.Release(lease.ID)
		closeDB()
		return nil
	}

	mount, err := lease.Materialize("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: materialize secret lease: %v\n", err)
		broker.Release(lease.ID)
		closeDB()
		return nil
	}
	sl := &secretLease{broker: broker, lease: lease, mount: mount, closer: closeDB}
	// Registered only once the credentials actually exist on disk: every
	// earlier return path has already released the lease, and a registry
	// entry for one of those would offer a revoke button for a lease that
	// was never held.
	liveLeases.add(sl)
	return sl
}

// openUIBroker builds a broker over the control plane's database.
//
// Grants live in the control plane's own database rather than each project's,
// for the same reason executor bindings do (see lookupProjectExecutor): a
// project pinned to a remote executor may have no readable local .cloop
// directory, and a tenant must not be able to grant itself credentials by
// writing to a database it owns.
func openUIBroker(controlPlaneDir string) (*secretbroker.Broker, func(), error) {
	if controlPlaneDir == "" {
		return nil, nil, fmt.Errorf("no control plane directory")
	}
	dbPath := state.DBPath(controlPlaneDir)
	if _, err := os.Stat(dbPath); err != nil {
		return nil, nil, fmt.Errorf("no state database: %w", err)
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, nil, err
	}
	store, err := secretstore.New(db)
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	broker, err := secretbroker.New(store, secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	return broker, func() { _ = db.Close() }, nil
}

// isBrokerUnconfigured reports whether the broker simply is not set up on
// this install, as opposed to being set up and broken. A missing state
// database or an unset CLOOP_SECRET_KEY are the ordinary "not adopted yet"
// states and should not produce a log line on every run.
func isBrokerUnconfigured(err error) bool {
	if err == nil {
		return false
	}
	return os.IsNotExist(err) ||
		errors.Is(err, os.ErrNotExist) ||
		errors.Is(err, secretbroker.ErrNoKey)
}

// applyLease appends a lease's environment to a spec.
//
// Spec.Env nil means "inherit the control plane's environment", which is the
// behaviour every existing UI spawn relies on. Adding lease variables means
// we must now materialise that inheritance explicitly, or the workload would
// lose everything it used to get from the server's environment.
func applyLease(spec executor.Spec, sl *secretLease) executor.Spec {
	env := sl.Env()
	if len(env) == 0 {
		return spec
	}
	// Attribution travels with the material. Without it the executor sees an
	// environment it cannot take anything back out of, and a revocation could
	// only ever kill the workload — see pkg/executor.SecretBinding.
	spec.Secrets = append(spec.Secrets, sl.Bindings()...)

	base := spec.Env
	if base == nil {
		base = os.Environ()
	}
	merged := make([]string, 0, len(base)+len(env))
	merged = append(merged, base...)
	merged = append(merged, env...)
	spec.Env = merged
	return spec
}
