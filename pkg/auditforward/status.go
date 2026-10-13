package auditforward

// status.go: how far each configured sink has got, read from the databases
// rather than from a running forwarder — for `cloop hub audit forward status`
// and `cloop hub doctor`, which run beside the hub, not in it.
//
// Every chain is opened read-only: a diagnostic must neither migrate a
// project's database nor create one where it found none.

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Report is one configured sink as the databases say it stands.
type Report struct {
	Sink   config.AuditForwardSink
	Chains []ChainReport
}

// ChainReport is the sink's position in one chain.
type ChainReport struct {
	Cursor statedb.AuditForwardCursor
	// HeadID is the chain's newest row; Backlog how many rows after the
	// cursor the sink has not acknowledged; PendingSince the oldest of
	// those's timestamp, zero when there are none.
	HeadID       int64
	Backlog      int64
	PendingSince time.Time
	// Err is set when the chain could not be read.
	Err error
}

// Lag is the age of the oldest row the sink has not acknowledged in any
// chain; zero when it is caught up.
func (r Report) Lag(now time.Time) time.Duration {
	var oldest time.Time
	for _, c := range r.Chains {
		if !c.PendingSince.IsZero() && (oldest.IsZero() || c.PendingSince.Before(oldest)) {
			oldest = c.PendingSince
		}
	}
	if oldest.IsZero() || now.Before(oldest) {
		return 0
	}
	return now.Sub(oldest)
}

// Backlog is the rows the sink has not acknowledged, across chains.
func (r Report) Backlog() int64 {
	var n int64
	for _, c := range r.Chains {
		n += c.Backlog
	}
	return n
}

// Delivered is the rows the sink has acknowledged, across chains.
func (r Report) Delivered() int64 {
	var n int64
	for _, c := range r.Chains {
		n += c.Cursor.Delivered
	}
	return n
}

// LastDelivery is when the sink last acknowledged a batch; zero when it never
// has.
func (r Report) LastDelivery() time.Time {
	var t time.Time
	for _, c := range r.Chains {
		if c.Cursor.AckedAt.After(t) {
			t = c.Cursor.AckedAt
		}
	}
	return t
}

// LastError is the newest failure any of the sink's cursors records.
func (r Report) LastError() (string, time.Time) {
	var (
		msg string
		at  time.Time
	)
	for _, c := range r.Chains {
		if c.Cursor.LastError != "" && c.Cursor.LastErrorAt.After(at) {
			msg, at = c.Cursor.LastError, c.Cursor.LastErrorAt
		}
	}
	return msg, at
}

// Status reports every configured sink, from the cursors in the control plane
// at cpPath and the head of each chain they name. A sink the forwarder has not
// started has no chains.
func Status(cpPath string, cfg config.AuditForwardConfig) ([]Report, error) {
	conn, err := statedb.OpenConn(cpPath, statedb.ReadOnly)
	if err != nil {
		return nil, fmt.Errorf("open the control plane read-only: %w", err)
	}
	cursors, err := statedb.ReadAuditForwardCursors(conn)
	conn.Close() //nolint:errcheck
	if err != nil {
		return nil, err
	}
	bySink := map[string][]statedb.AuditForwardCursor{}
	for _, c := range cursors {
		if !c.Retired() {
			bySink[c.Sink] = append(bySink[c.Sink], c)
		}
	}
	heads := map[string]chainHead{}
	out := make([]Report, 0, len(cfg.Sinks))
	for _, s := range cfg.Sinks {
		r := Report{Sink: s}
		for _, c := range bySink[s.Name] {
			cr := ChainReport{Cursor: c}
			h, ok := heads[c.Chain]
			if !ok {
				h = readHead(c.Chain)
				heads[c.Chain] = h
			}
			cr.Err, cr.HeadID = h.err, h.lastID
			if h.err == nil && h.lastID > c.AckedID {
				cr.Backlog = h.lastID - max(c.AckedID, h.firstID-1)
				cr.PendingSince = pendingSince(c.Chain, c.AckedID)
			}
			r.Chains = append(r.Chains, cr)
		}
		sort.Slice(r.Chains, func(i, j int) bool { return r.Chains[i].Cursor.Chain < r.Chains[j].Cursor.Chain })
		out = append(out, r)
	}
	return out, nil
}

type chainHead struct {
	firstID, lastID int64
	err             error
}

func readHead(path string) chainHead {
	if _, err := os.Stat(path); err != nil {
		return chainHead{err: err}
	}
	conn, err := statedb.OpenConn(path, statedb.ReadOnly)
	if err != nil {
		return chainHead{err: err}
	}
	defer conn.Close()
	h, err := statedb.ReadAuditHead(conn)
	if err != nil {
		return chainHead{err: err}
	}
	return chainHead{firstID: h.FirstID, lastID: h.LastID}
}

func pendingSince(path string, afterID int64) time.Time {
	conn, err := statedb.OpenConn(path, statedb.ReadOnly)
	if err != nil {
		return time.Time{}
	}
	defer conn.Close()
	ev, ok, err := statedb.ReadAuditRowAfter(conn, afterID)
	if err != nil || !ok {
		return time.Time{}
	}
	return ev.Timestamp
}

// IsSinkRepair reports whether a load repair is a sink the loader refused.
func IsSinkRepair(r config.LoadRepair) bool {
	return r.SwitchedOff != "" && strings.HasPrefix(r.SwitchedOff, "audit.forward.sinks")
}

// Unhealthy says what is wrong with a sink, or "" when nothing is: no cursor
// yet — the hub has not run with it — rows waiting and nothing ever
// acknowledged, or the oldest waiting row older than maxLag.
func Unhealthy(r Report, maxLag time.Duration, now time.Time) string {
	errSuffix := ""
	if msg, _ := r.LastError(); msg != "" {
		errSuffix = "; last error: " + msg
	}
	backlog, lag := r.Backlog(), r.Lag(now)
	switch {
	case len(r.Chains) == 0:
		return "has never delivered: it has no cursors, so no hub has forwarded to it yet"
	case backlog > 0 && r.LastDelivery().IsZero():
		return fmt.Sprintf("has never delivered: %d row(s) waiting%s", backlog, errSuffix)
	case lag > maxLag:
		return fmt.Sprintf("lags %s behind, beyond audit.forward.max_lag (%s): %d row(s) waiting%s",
			lag.Round(time.Second), maxLag, backlog, errSuffix)
	}
	return ""
}
