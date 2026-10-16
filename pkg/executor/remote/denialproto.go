package remote

// denialproto.go carries what a device's sandbox firewalls refused to the hub
// (Task 20437, protocol v24).
//
// A sandbox's firewall on a device refuses a blocked connection and logs it,
// rate-limited, to an NFLOG group the agent reads (pkg/denylog). The agent
// aggregates per workload — by destination, port, protocol and rule, capped —
// and sends a denials frame for the workload every few seconds while it has
// something new, and once more, final, just before the workload's terminal
// status. The hub records each batch on the run it belongs to: its history,
// its task's Network section, the project's recently blocked list.
//
// A device is hostile until proven otherwise, so the hub takes a batch only
// for a handle it dispatched to that device, only while the handle is live,
// at a bounded rate per handle, and only after Validate: bounded, canonical,
// naming only deny paths and protocols the agent's own code writes. Nothing in
// a batch is more than an address, a port and a count.

import (
	"fmt"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/denylog"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
)

// TypeDenials (agent → control plane) reports one workload's refusals since
// the last report. Unsolicited, scoped to the workload's handle. Added in v24.
const TypeDenials FrameType = "denials"

// MinDenialLogVersion is the first version whose agents read their sandboxes'
// packet log and report what it refused (Task 20437).
//
// Neither a placement rule nor a refusal: an older agent's sandbox firewall is
// as strict as ever, it only cannot say what it refused. So the hub sends it
// nothing new and dispatches to it as before, and where a run's refusals would
// be shown it says the device's agent is too old to report them — and how to
// fix that — instead of an empty list that would read as "nothing was blocked".
// The rule that is enforced runs the other way: an agent sends the frame only
// on a session that negotiated v24.
const MinDenialLogVersion = 24

// SupportsDenialLog reports whether an agent speaking this version reports
// its sandboxes' refusals.
func SupportsDenialLog(version int) bool { return version >= MinDenialLogVersion }

// DenialsPayload is one workload's batch.
type DenialsPayload struct {
	denylog.Batch
}

// DecodeDenials decodes and validates a denials frame.
func DecodeDenials(f Frame) (DenialsPayload, error) {
	var p DenialsPayload
	if err := decodePayload(f, &p); err != nil {
		return p, err
	}
	if err := p.Validate(); err != nil {
		return DenialsPayload{}, fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	return p, nil
}

// denialFrameBurst and denialFrameEvery bound how often one handle's reports
// are taken: a device flushes a live workload every two seconds and once more
// at its end, so this admits that with room to spare and turns a device that
// floods frames into dropped reports rather than a database write per frame.
const (
	denialFrameBurst = 5
	denialFrameEvery = 500 * time.Millisecond
)

// denialLimiter is one session's per-handle token buckets.
type denialLimiter struct {
	mu      sync.Mutex
	buckets map[string]*denialBucket
}

type denialBucket struct {
	tokens float64
	at     time.Time
}

func (l *denialLimiter) allow(handle string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buckets == nil {
		l.buckets = map[string]*denialBucket{}
	}
	b := l.buckets[handle]
	if b == nil {
		if len(l.buckets) >= denylog.MaxRuns {
			// Only handles this executor dispatched reach here, so this is a
			// ceiling on a confused hub, not on a device.
			for k := range l.buckets {
				delete(l.buckets, k)
			}
		}
		b = &denialBucket{tokens: denialFrameBurst, at: now}
		l.buckets[handle] = b
	}
	b.tokens += now.Sub(b.at).Seconds() / denialFrameEvery.Seconds()
	if b.tokens > denialFrameBurst {
		b.tokens = denialFrameBurst
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *denialLimiter) forget(handle string) {
	l.mu.Lock()
	delete(l.buckets, handle)
	l.mu.Unlock()
}

// applyDenials hands a device's batch for one of its live handles to the hub.
func (e *Executor) applyDenials(handleID string, p DenialsPayload) error {
	hs, err := e.lookup(handleID)
	if err != nil {
		return err
	}
	hs.mu.Lock()
	closed := hs.closed
	hs.mu.Unlock()
	if closed {
		hubmetrics.FirewallDenialReportsDropped.Inc("late")
		return fmt.Errorf("%w: handle %s already reported its final status", ErrProtocol, handleID)
	}
	if !executor.ReportDenials(e.id, handleID, p.Batch) {
		hubmetrics.FirewallDenialReportsDropped.Inc("no_sink")
	}
	return nil
}

// DenialLogStatus says whether this device reports what its sandbox firewalls
// refuse, and if not, the sentence shown in place of the list — the upgrade
// for an agent below v24, the agent's own reason for one that could not bind
// its packet log.
func (e *Executor) DenialLogStatus() (bool, string) {
	sess := e.currentSession()
	if sess == nil {
		return false, fmt.Sprintf("%s is not connected; what its sandbox firewalls refuse is reported while it is",
			e.subject())
	}
	if v := sess.Version(); !SupportsDenialLog(v) {
		return false, executor.NeedsProtocol(e.subject(), v, MinDenialLogVersion,
			"to report what its sandbox firewalls refuse", "")
	}
	caps := e.AgentCapabilities()
	if !caps.DenialLog {
		why := caps.DenialLogIssue
		if why == "" {
			why = "it reads no packet log"
		}
		return false, fmt.Sprintf("%s does not report what its sandbox firewalls refuse: %s", e.subject(), why)
	}
	return true, ""
}

// DenialLogStatus is the parent device's: a virtual executor's sandboxes are
// the device's, and so is their packet log.
func (v *Virtual) DenialLogStatus() (bool, string) { return v.parent.DenialLogStatus() }
