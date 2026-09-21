package ui

// The loop that acts on the fleet auto-update policy (Task 20331).
//
// pkg/executor/autoupdate holds the decision and none of the doing, so that the
// restraint rules — never interrupt running work, never take the fleet down at
// once, never touch a cordoned device — can be tested exhaustively without a
// network. This file is the other half: it gathers the fleet's current shape,
// hands it to Plan, and sends the requests Plan asked for.
//
// It lives beside startExecutorSupervisor because it needs exactly what the
// supervisor already has — a control-plane database and a live view of which
// devices are healthy — and because the two have the same lifetime. A sweep
// that outlived fleet supervision would be deciding from health records nobody
// was refreshing.

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/autoupdate"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// autoUpdateInterval is how often the fleet is reconsidered.
//
// Minutes rather than seconds. Nothing here is urgent — a device being an hour
// out of date is the normal state of a fleet — and a short interval would mean
// a device that fails to upgrade is asked again almost immediately, turning a
// broken release into a restart loop across the whole estate.
const autoUpdateInterval = 5 * time.Minute

// autoUpdateGrace is how long a device asked to upgrade is presumed to still be
// upgrading.
//
// It is what makes MaxInFlight mean anything: the hub has no completion signal
// to wait for, because a successful upgrade kills the session that would have
// carried it (see pkg/executor/remote/upgrade.go). So a device that has been
// asked holds its slot for this long, and after that the sweep is free to
// reconsider it — which is also the retry path for an upgrade that silently
// failed to take.
const autoUpdateGrace = 15 * time.Minute

// autoUpdater tracks which devices have been asked recently.
type autoUpdater struct {
	db *statedb.DB
	sv *executor.Supervisor

	mu     sync.Mutex
	asked  map[string]time.Time
	nowFn  func() time.Time
	sendFn func(context.Context, *remote.Executor, remote.UpgradeRequest) (remote.UpgradeOutcome, error)
}

func newAutoUpdater(db *statedb.DB, sv *executor.Supervisor) *autoUpdater {
	return &autoUpdater{
		db:    db,
		sv:    sv,
		asked: map[string]time.Time{},
		nowFn: time.Now,
		sendFn: func(ctx context.Context, ex *remote.Executor, req remote.UpgradeRequest) (
			remote.UpgradeOutcome, error,
		) {
			return ex.RequestUpgrade(ctx, req)
		},
	}
}

// run sweeps until ctx is cancelled.
func (a *autoUpdater) run(ctx context.Context) {
	t := time.NewTicker(autoUpdateInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.sweepOnce(ctx)
		}
	}
}

// sweepOnce reads the policy, plans, and sends.
//
// A disabled policy returns before the fleet is even enumerated: the
// overwhelmingly common case is that this feature is off, and it should cost
// one query rather than a walk of every executor.
func (a *autoUpdater) sweepOnce(ctx context.Context) {
	stored, err := statedb.AutoUpdatePolicyFor(a.db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: auto-update: read policy: %v\n", err)
		return
	}
	if !stored.Policy.Enabled {
		return
	}

	devices, live := a.fleet()
	for _, v := range autoupdate.Plan(stored.Policy, hubVersion(), devices) {
		if !v.Upgrade {
			continue
		}
		ex := live[v.Device.ID]
		if ex == nil {
			continue
		}
		a.markAsked(v.Device.ID)

		reqCtx, cancel := context.WithTimeout(ctx, upgradeRequestTimeout)
		outcome, err := a.sendFn(reqCtx, ex, remote.UpgradeRequest{
			TargetVersion: stored.Policy.Resolve(hubVersion()).TargetVersion,
			Reason:        "fleet auto-update policy",
		})
		cancel()

		name := v.Device.Name
		if name == "" {
			name = v.Device.ID
		}
		switch {
		case err != nil:
			// The slot stays held. A device that could not be reached is not a
			// device to hammer on the next tick, and the grace window is the
			// backoff.
			fmt.Fprintf(os.Stderr, "ui: auto-update: %s: %v\n", name, err)
		case !outcome.Accepted:
			// Released immediately: a refusal is a decision, not a restart in
			// progress, and holding a slot for it would stall the rollout
			// behind a device that is never going to move.
			a.clearAsked(v.Device.ID)
			fmt.Fprintf(os.Stderr, "ui: auto-update: %s\n", outcome.Summary(name))
		default:
			// No broadcast from here. The device is about to drop its session
			// and reconnect on the new build, and both of those already reach
			// the panel as ordinary executor events — pushing a third would
			// need a Server reference this loop has no other use for.
			fmt.Fprintf(os.Stderr, "ui: auto-update: %s\n", outcome.Summary(name))
		}
	}
}

// fleet snapshots every remote device as the planner needs to see it.
//
// Only remote agents are returned. Container and Kubernetes executors run the
// control plane's own binary and have no separate build to move, so including
// them would produce verdicts about machines this feature cannot act on.
func (a *autoUpdater) fleet() ([]autoupdate.Device, map[string]*remote.Executor) {
	var devices []autoupdate.Device
	live := map[string]*remote.Executor{}

	for _, ex := range executor.List() {
		rex, ok := ex.(*remote.Executor)
		if !ok {
			continue
		}
		id := rex.ID()
		d := autoupdate.Device{
			ID:              id,
			Name:            rex.Name(),
			Version:         rex.AgentVersion(),
			ProtocolVersion: rex.ProtocolVersion(),
			Online:          rex.Connected(),
			Busy:            len(rex.Handles()) > 0,
			Upgrading:       a.recentlyAsked(id),
		}
		if a.sv != nil {
			h := a.sv.Health(id)
			d.AdminHeld = h.State.AdminHeld()
		}
		devices = append(devices, d)
		live[id] = rex
	}
	return devices, live
}

func (a *autoUpdater) markAsked(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asked[id] = a.nowFn()
}

func (a *autoUpdater) clearAsked(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.asked, id)
}

func (a *autoUpdater) recentlyAsked(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	at, ok := a.asked[id]
	if !ok {
		return false
	}
	if a.nowFn().Sub(at) > autoUpdateGrace {
		delete(a.asked, id)
		return false
	}
	return true
}
