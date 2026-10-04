package remote

// refreshproto.go rewrites credential files a running workload already holds on
// a device (Task 20375, protocol v17).
//
// A GitHub App installation token works for an hour. The hub re-mints it before
// then (pkg/secretbroker/apprefresh.go) and, for a workload on a device, sends
// the new token file here: the agent rewrites it in place in the lease directory
// it created at start, which the workload's git reads through its credential
// helper on every call. In container mode that directory is bind-mounted into
// the sandbox whole, so the rename is what the workload sees next.
//
// # Older agents
//
// An agent below v17 has no handler for the frame — it would log it as unknown
// and never answer — so the hub does not send it. Nor does it refuse the
// dispatch: a run that needs GitHub for less than an hour works exactly as it
// did, and one that needs it longer loses it at the hour, as it always did.
// The report says Unsupported and names the upgrade, and the hub journals it on
// the project.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

const (
	// TypeSecretRefresh (control plane → agent) replaces credential files a
	// lease already delivered to running workloads. Added in v17.
	TypeSecretRefresh FrameType = "secret_refresh"
	// TypeSecretRefreshed (agent → control plane) reports what was rewritten.
	TypeSecretRefreshed FrameType = "secret_refreshed"
)

// MinSecretRefreshVersion is the first version whose agents rewrite a running
// workload's credential files on request.
//
// Not a placement rule: see the file comment.
const MinSecretRefreshVersion = 17

// SupportsSecretRefresh reports whether an agent speaking this protocol version
// handles the secret_refresh frame.
func SupportsSecretRefresh(version int) bool { return version >= MinSecretRefreshVersion }

// secretRefreshTimeout bounds one refresh round trip. Rewriting a file or three
// in a tmpfs is instant; the bound is for a link that is not.
const secretRefreshTimeout = 20 * time.Second

// SecretRefreshPayload is the refresh request on the wire.
type SecretRefreshPayload struct {
	LeaseID string `json:"lease_id"`
	// Files carry the replacements, attributed and named exactly as the start
	// frame's SecretFiles were: Dir is the directory the hub declared, which
	// the agent maps onto the one it actually created.
	Files  []SecretFile `json:"files"`
	Reason string       `json:"reason,omitempty"`
}

// String redacts the content, as SecretFile's does.
func (p SecretRefreshPayload) String() string {
	names := make([]string, 0, len(p.Files))
	for _, f := range p.Files {
		names = append(names, f.String())
	}
	return fmt.Sprintf("secret refresh for lease %s: %s", p.LeaseID, strings.Join(names, ", "))
}

// GoString mirrors String.
func (p SecretRefreshPayload) GoString() string { return p.String() }

// Request converts the wire form into what a driver consumes.
func (p SecretRefreshPayload) Request() executor.SecretRefreshRequest {
	files := make([]executor.SecretFile, 0, len(p.Files))
	for _, f := range p.Files {
		files = append(files, f.Executor())
	}
	return executor.SecretRefreshRequest{LeaseID: p.LeaseID, Files: files, Reason: p.Reason}
}

// SecretRefreshedPayload is the agent's report.
type SecretRefreshedPayload = executor.SecretRefreshReport

// NewSecretRefreshPayload converts a driver-facing request into the wire form.
func NewSecretRefreshPayload(req executor.SecretRefreshRequest) SecretRefreshPayload {
	files := make([]SecretFile, 0, len(req.Files))
	for _, f := range req.Files {
		wf := NewSecretFile(f)
		if wf.LeaseID == "" {
			wf.LeaseID = req.LeaseID
		}
		files = append(files, wf)
	}
	return SecretRefreshPayload{LeaseID: req.LeaseID, Files: files, Reason: req.Reason}
}

// DecodeSecretRefresh decodes and validates a refresh request. Validated here,
// on receipt, for the reason a start frame's files are: the frame crossed a
// process boundary from a party this device does not trust with a write
// anywhere but its own lease directories.
func DecodeSecretRefresh(f Frame) (SecretRefreshPayload, error) {
	var p SecretRefreshPayload
	if err := decodePayload(f, &p); err != nil {
		return p, err
	}
	if strings.TrimSpace(p.LeaseID) == "" {
		return p, fmt.Errorf("%w: secret_refresh frame has no lease_id", ErrProtocol)
	}
	if len(p.Files) == 0 {
		return p, fmt.Errorf("%w: secret_refresh frame carries no files", ErrProtocol)
	}
	for i, file := range p.Files {
		if file.LeaseID != "" && file.LeaseID != p.LeaseID {
			return p, fmt.Errorf("%w: secret_refresh file %d belongs to lease %s, not %s",
				ErrProtocol, i, file.LeaseID, p.LeaseID)
		}
	}
	if err := ValidateSecretFiles(p.Files); err != nil {
		return p, err
	}
	return p, nil
}

// DecodeSecretRefreshed decodes the agent's report.
func DecodeSecretRefreshed(f Frame) (SecretRefreshedPayload, error) {
	var p SecretRefreshedPayload
	err := decodePayload(f, &p)
	return p, err
}

// refreshSecretFiles sends one refresh and waits for the agent's report.
func (s *Session) refreshSecretFiles(ctx context.Context, p SecretRefreshPayload) (SecretRefreshedPayload, error) {
	if !SupportsSecretRefresh(s.version) {
		return SecretRefreshedPayload{}, fmt.Errorf("%w: %s", ErrProtocol,
			executor.NeedsProtocol("agent "+s.agentID, s.version, MinSecretRefreshVersion,
				"to replace a credential file in a running workload", ""))
	}
	if err := ValidateSecretFiles(p.Files); err != nil {
		return SecretRefreshedPayload{}, err
	}
	frame, err := s.frame(TypeSecretRefresh, newCorrelationID(), "", p)
	if err != nil {
		return SecretRefreshedPayload{}, err
	}
	reply, err := s.request(ctx, frame, TypeSecretRefreshed)
	if err != nil {
		return SecretRefreshedPayload{}, err
	}
	return DecodeSecretRefreshed(reply)
}

// SupportsSecretRefresh reports whether a refresh issued now would reach the
// device: it is connected, and its agent speaks v17.
func (e *Executor) SupportsSecretRefresh() bool {
	sess := e.currentSession()
	return sess != nil && SupportsSecretRefresh(sess.Version())
}

// SecretRefreshShortfall explains why a refresh would not reach the device, or
// returns "" when it would.
func (e *Executor) SecretRefreshShortfall() string {
	sess := e.currentSession()
	if sess == nil {
		return fmt.Sprintf("agent %s (%s) is not connected", e.id, e.name)
	}
	if !SupportsSecretRefresh(sess.Version()) {
		return executor.NeedsProtocol("Its agent", sess.Version(), MinSecretRefreshVersion,
			"to replace a credential file in a running workload", "")
	}
	return ""
}

// RefreshSecretFiles implements executor.SecretRefresher: it sends req to the
// device and reports what the agent rewrote. The new content joins the hub-side
// redaction of every workload holding the lease first, because the log stream
// that carries a workload's output to the hub is scrubbed here, not on the
// device.
func (e *Executor) RefreshSecretFiles(ctx context.Context, req executor.SecretRefreshRequest) executor.SecretRefreshReport {
	out := executor.SecretRefreshReport{LeaseID: strings.TrimSpace(req.LeaseID)}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := req.Validate(); err != nil {
		out.Error = err.Error()
		return out
	}
	held := e.leases.Handles(executor.RevokeRequest{LeaseID: out.LeaseID})
	if len(held) == 0 && !e.leases.Holds(out.LeaseID) {
		return out
	}
	out.Known = true
	values := req.Values()
	handles := make([]string, 0, len(held))
	for id := range held {
		handles = append(handles, id)
	}
	sort.Strings(handles)
	for _, id := range handles {
		if hs, err := e.lookup(id); err == nil && hs.bus != nil {
			hs.bus.AddRedactions(values...)
		}
	}

	sess := e.currentSession()
	if sess == nil {
		out.Error = fmt.Sprintf("%v: agent %s (%s) is not connected; the refresh is retried while the "+
			"run's lease is kept alive", ErrAgentUnreachable, e.id, e.name)
		return out
	}
	if !SupportsSecretRefresh(sess.Version()) {
		out.Unsupported = true
		out.Error = executor.NeedsProtocol("Agent "+e.id, sess.Version(), MinSecretRefreshVersion,
			"to replace a credential file in a running workload", "")
		return out
	}

	rctx, cancel := context.WithTimeout(ctx, secretRefreshTimeout)
	defer cancel()
	ack, err := sess.refreshSecretFiles(rctx, NewSecretRefreshPayload(req))
	if err != nil {
		out.Error = err.Error()
		return out
	}
	// The agent's report is the answer: it is the machine holding the files.
	ack.LeaseID = out.LeaseID
	return ack
}

// RefreshResult is one executor's answer to a lease refresh.
type RefreshResult struct {
	ExecutorID string                       `json:"executor_id"`
	Report     executor.SecretRefreshReport `json:"report"`
}

// RefreshLease sends req to every connected agent holding the lease and
// reports each answer. Nil when no agent holds it — the ordinary case for a
// lease held by a hub-local executor.
func (h *Hub) RefreshLease(ctx context.Context, req executor.SecretRefreshRequest) []RefreshResult {
	leaseID := strings.TrimSpace(req.LeaseID)
	if leaseID == "" {
		return nil
	}
	var holders []*Executor
	for _, ex := range h.Executors() {
		if ex.HoldsLease(leaseID) {
			holders = append(holders, ex)
		}
	}
	out := make([]RefreshResult, len(holders))
	done := make(chan struct{}, len(holders))
	for i, ex := range holders {
		go func(i int, ex *Executor) {
			defer func() { done <- struct{}{} }()
			defer func() {
				if r := recover(); r != nil {
					out[i] = RefreshResult{ExecutorID: ex.ID(), Report: executor.SecretRefreshReport{
						LeaseID: leaseID, Known: true, Error: fmt.Sprintf("panic refreshing lease: %v", r),
					}}
				}
			}()
			out[i] = RefreshResult{ExecutorID: ex.ID(), Report: ex.RefreshSecretFiles(ctx, req)}
		}(i, ex)
	}
	for range holders {
		<-done
	}
	for _, res := range out {
		h.opts.logf("remote: refresh lease %s on %s: %d file(s)%s",
			leaseID, res.ExecutorID, res.Report.FilesRewritten, errSuffix(res.Report.Error))
	}
	return out
}

var _ executor.SecretRefresher = (*Executor)(nil)
