package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/blechschmidt/cloop/pkg/denylog"
	"github.com/blechschmidt/cloop/pkg/executor/container"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// denials.go is the device half of Task 20437: what this device's sandbox
// firewalls refused, sent to the hub for the run it belongs to.
//
// The agent's container drivers install each sandbox's ruleset with log
// statements to an NFLOG group this process binds (pkg/denylog), using the
// CAP_NET_ADMIN its packet-filter grant already gives it — in this process,
// never a child, which inherits nothing (pkg/caps). The monitor aggregates per
// workload and hands each batch here, keyed by the inner driver's handle; this
// file maps that to the hub's handle and sends a denials frame on the live
// session. A batch that cannot go out now stays in the monitor and goes with
// the next flush.

// errNotConnected is a batch held for the next session.
var errNotConnected = errors.New("agent: no session to report refusals on")

// denialSendTimeout bounds one frame write from the monitor's goroutine.
const denialSendTimeout = 10 * time.Second

// sendDenials is the monitor's sink in an agent.
func (a *Agent) sendDenials(r denylog.Run, b denylog.Batch) error {
	wl := a.workloadByLocal(r.ID)
	if wl == nil {
		// Not a workload this agent dispatched — nothing would know it.
		return nil
	}
	sess := a.currentSession()
	if sess == nil {
		return errNotConnected
	}
	if !remote.SupportsDenialLog(sess.version) {
		// A hub too old to take the frame; the refusals stay on the device's
		// side of the link, which is where they were before v24.
		return nil
	}
	frame, err := sess.frame(remote.TypeDenials, "", wl.handleID, remote.DenialsPayload{Batch: b})
	if err != nil {
		return fmt.Errorf("agent: encode refusals of %s: %w", wl.handleID, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), denialSendTimeout)
	defer cancel()
	return sess.write(ctx, frame)
}

// workloadByLocal finds a workload by its inner driver's handle.
func (a *Agent) workloadByLocal(localID string) *workload {
	// Copied out first: no workload lock is taken under the agent's.
	a.mu.Lock()
	wls := make([]*workload, 0, len(a.workloads))
	for _, wl := range a.workloads {
		wls = append(wls, wl)
	}
	a.mu.Unlock()
	for _, wl := range wls {
		wl.mu.Lock()
		match := wl.localID == localID
		wl.mu.Unlock()
		if match {
			return wl
		}
	}
	return nil
}

// flushFinalDenials sends a finished workload's last refusals, ahead of its
// terminal status: the frame that closes the run's stream on the hub must not
// overtake them. A failure is not the status's to wait on — the next attempt
// at the status flushes again.
func (a *Agent) flushFinalDenials(ctx context.Context, wl *workload) {
	wl.mu.Lock()
	local := wl.localID
	wl.mu.Unlock()
	if local == "" {
		return
	}
	if err := container.FlushDenials(ctx, local); err != nil && !errors.Is(err, errNotConnected) {
		a.cfg.logf("workload %s: report its last refusals: %v", wl.handleID, err)
	}
}

// denialLogCapability is what the hello says about the packet log: read when
// the packet filter works, since the group is bound with the same capability.
func denialLogCapability(packetFilter bool) (bool, string) {
	if !packetFilter {
		return false, "this device installs no sandbox firewall, so it has nothing to report"
	}
	if _, err := denylog.Shared(); err != nil {
		return false, err.Error()
	}
	return true, ""
}
