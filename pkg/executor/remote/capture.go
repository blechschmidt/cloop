package remote

// capture.go is the control plane's half of a capture request (Task 20495):
// it asks a device for a project's working copy, assembles the answer under
// the same rules write-back's assembly follows (writeback.go, returns.go), and
// hands it to the caller, who writes it into the hub's move store and lets go
// of it.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
)

// ErrCaptureUnsupported reports a device that cannot answer a capture: an
// agent too old to be asked. Its message names the upgrade.
var ErrCaptureUnsupported = errors.New("remote: this device cannot capture a project's working copy")

// ErrCaptureRefused reports a capture the device would not, or could not,
// answer; the error carries its reason.
var ErrCaptureRefused = errors.New("remote: the device did not capture the working copy")

// ErrCaptureBusy reports a device answering another capture.
var ErrCaptureBusy = errors.New("remote: the device is answering another capture")

// CaptureTimeout bounds one capture on the device: a large repository's
// bundle over an edge uplink.
const CaptureTimeout = 30 * time.Minute

// captureRetention is how long a verified answer nobody collected is kept.
const captureRetention = 10 * time.Minute

// CaptureRequest is what the hub asks a device for.
type CaptureRequest struct {
	// Mode is CaptureInspect or CaptureFull.
	Mode string
	// MoveID names the hidden refs a capture writes.
	MoveID string
	// WorkDir is the project's working copy under the agent's trees root:
	// executor.DeviceWorkDir of the project's path.
	WorkDir  string
	Features []CaptureFeature
	// Tenant is, for a pool's runner, the tenant its volume must hold.
	Tenant string
	// Limits caps each part; a zero document cap takes
	// MaxCaptureDocumentBytes.
	Limits CaptureLimits
}

// capturePart is one part as it arrives.
type capturePart struct {
	chunks [][]byte
	size   int64
	sum    hash.Hash
}

// captureAssembly is one capture's answer, in flight or held for the caller.
type captureAssembly struct {
	id      string
	session *Session
	limits  CaptureLimits
	parts   map[string]*capturePart
	// held is what the assembly counts against the executor's budget.
	held int64
	// closed: the result arrived, or the capture was cancelled, failed or
	// dropped. Nothing is accepted after.
	closed   bool
	closedAt time.Time
	// failed says why the answer is not usable, once it is not.
	failed string
	// verified: the result arrived and every part matched it.
	verified bool
	result   *CaptureResultPayload
	// cancelSent: the device was told to stop.
	cancelSent bool
	// abort ends the caller's wait: the assembly failed or was dropped, and
	// no answer the device still sends would be accepted.
	abort context.CancelFunc
}

// captureSet is an executor's captures. Its zero value is ready.
type captureSet struct {
	mu sync.Mutex
	m  map[string]*captureAssembly
}

// dropLocked lets go of an assembly's bytes and gives them back to the
// budget, recording why. c.mu must be held.
func (e *Executor) dropCaptureLocked(a *captureAssembly, why string) {
	if a == nil {
		return
	}
	if !a.closed {
		a.closed, a.closedAt = true, e.opts.now()
	}
	if why != "" && a.failed == "" && !a.verified {
		a.failed = why
	}
	e.budget.release(e.id, a.held)
	a.parts, a.held = nil, 0
	if a.abort != nil && !a.verified {
		a.abort()
	}
}

// releaseCapture lets go of one capture and forgets it.
func (e *Executor) releaseCapture(id, why string) {
	e.captures.mu.Lock()
	defer e.captures.mu.Unlock()
	if a := e.captures.m[id]; a != nil {
		e.dropCaptureLocked(a, why)
		delete(e.captures.m, id)
	}
}

// dropCaptures lets go of every capture this executor holds: its agent was
// revoked or deregistered, and nothing it sent is landed afterwards.
func (e *Executor) dropCaptures(why string) {
	e.captures.mu.Lock()
	defer e.captures.mu.Unlock()
	for id, a := range e.captures.m {
		e.dropCaptureLocked(a, why)
		delete(e.captures.m, id)
	}
}

// dropSessionCaptures lets go of the captures still in flight on a session
// that ended: an answer is never resumed on another one. One already verified
// stays for its caller.
func (e *Executor) dropSessionCaptures(sess *Session, why string) {
	e.captures.mu.Lock()
	defer e.captures.mu.Unlock()
	for _, a := range e.captures.m {
		if a.session == sess && !a.verified {
			e.dropCaptureLocked(a, why)
		}
	}
}

// releaseStaleCaptures lets go of verified answers nobody collected within
// captureRetention. Run on each heartbeat, as releaseUncollected is.
func (e *Executor) releaseStaleCaptures() {
	now := e.opts.now()
	e.captures.mu.Lock()
	defer e.captures.mu.Unlock()
	for id, a := range e.captures.m {
		if a.closed && !a.closedAt.IsZero() && now.Sub(a.closedAt) >= captureRetention {
			e.dropCaptureLocked(a, fmt.Sprintf("the hub let go of it after %s with nobody collecting it", captureRetention))
			delete(e.captures.m, id)
		}
	}
}

// PinnedCaptureBytes reports what this executor's captures hold, for tests
// and diagnostics.
func (e *Executor) PinnedCaptureBytes() int64 {
	e.captures.mu.Lock()
	defer e.captures.mu.Unlock()
	var n int64
	for _, a := range e.captures.m {
		n += a.held
	}
	return n
}

// appendCaptureChunk accepts one slice of a capture's answer. Every refusal
// comes before anything is allocated for it, and the first one fails the
// capture: a part with a hole is not a smaller part.
func (e *Executor) appendCaptureChunk(sess *Session, id string, p CaptureChunkPayload) error {
	e.captures.mu.Lock()
	defer e.captures.mu.Unlock()
	a := e.captures.m[id]
	if a == nil {
		refuseFrame(hubmetrics.WriteBackRefusedNotRequested)
		return fmt.Errorf("%w: no capture %s was asked of this agent", ErrProtocol, id)
	}
	if a.session != sess {
		refuseFrame(hubmetrics.WriteBackRefusedNotRequested)
		return fmt.Errorf("%w: capture %s was asked on another session", ErrProtocol, id)
	}
	if a.closed {
		refuseFrame(hubmetrics.WriteBackRefusedLate)
		return fmt.Errorf("%w: capture %s already closed, so no more of it is accepted", ErrProtocol, id)
	}
	fail := func(reason string) error {
		e.dropCaptureLocked(a, reason)
		return fmt.Errorf("%w: capture %s: %s", ErrProtocol, id, reason)
	}
	limit, _ := a.limits.of(p.Part)
	if limit <= 0 {
		refuseFrame(hubmetrics.WriteBackRefusedNotRequested)
		return fail(fmt.Sprintf("the request asked for no %s", p.Part))
	}
	part := a.parts[p.Part]
	if part == nil {
		part = &capturePart{sum: sha256.New()}
		a.parts[p.Part] = part
	}
	if p.Offset != part.size {
		return fail(fmt.Sprintf("a %s chunk at offset %d, where %d bytes had arrived", p.Part, p.Offset, part.size))
	}
	if p.End() > limit {
		refuseFrame(hubmetrics.WriteBackRefusedOverCap)
		return fail(fmt.Sprintf("the %s exceeded the %d-byte cap the request set", p.Part, limit))
	}
	cost := int64(len(p.Data)) + ResultChunkOverhead
	if refused := e.budget.reserve(e.id, cost); refused != nil {
		refuseFrame(refused.metricReason())
		return fail(refused.reason("this capture", e.id))
	}
	// A copy the size of what arrived, never the decoded slice: see
	// appendResultChunk.
	data := append([]byte(nil), p.Data...)
	part.chunks = append(part.chunks, data)
	part.size += int64(len(data))
	part.sum.Write(data)
	a.held += cost
	return nil
}

// applyCaptureResult closes a capture's answer, checking every part against
// what the device reported.
func (e *Executor) applyCaptureResult(sess *Session, id string, p CaptureResultPayload) error {
	e.captures.mu.Lock()
	defer e.captures.mu.Unlock()
	a := e.captures.m[id]
	if a == nil {
		return fmt.Errorf("%w: no capture %s was asked of this agent", ErrProtocol, id)
	}
	if a.session != sess {
		return fmt.Errorf("%w: capture %s was asked on another session", ErrProtocol, id)
	}
	if a.closed {
		refuseFrame(hubmetrics.WriteBackRefusedLate)
		return fmt.Errorf("%w: capture %s already closed", ErrProtocol, id)
	}
	res := p
	a.result = &res
	if p.Error != "" || p.Code != "" {
		e.dropCaptureLocked(a, "")
		return nil
	}
	if a.failed != "" {
		e.dropCaptureLocked(a, "")
		return nil
	}
	reported := map[string]CapturePartDigest{}
	for _, d := range p.Parts {
		reported[d.Part] = d
	}
	for name := range a.parts {
		if _, ok := reported[name]; !ok {
			e.dropCaptureLocked(a, fmt.Sprintf("the device sent a %s it did not report", name))
			return nil
		}
	}
	for name, d := range reported {
		part := a.parts[name]
		var size int64
		got := hex.EncodeToString(sha256.New().Sum(nil))
		if part != nil {
			size, got = part.size, hex.EncodeToString(part.sum.Sum(nil))
		}
		if limit, _ := a.limits.of(name); d.Bytes > limit {
			e.dropCaptureLocked(a, fmt.Sprintf("the device reported a %d-byte %s, past the %d-byte cap", d.Bytes, name, limit))
			return nil
		}
		if size != d.Bytes {
			e.dropCaptureLocked(a, fmt.Sprintf("the device reported a %d-byte %s and %d bytes arrived", d.Bytes, name, size))
			return nil
		}
		if got != d.SHA256 {
			e.dropCaptureLocked(a, fmt.Sprintf("the assembled %s's digest does not match the one the device reported", name))
			return nil
		}
	}
	if _, ok := reported[CapturePartDocument]; !ok {
		e.dropCaptureLocked(a, "the device reported no document")
		return nil
	}
	a.closed, a.closedAt, a.verified = true, e.opts.now(), true
	// The waiter reads the verified answer however its result frame was
	// addressed: one sent under another correlation ID must not leave it
	// waiting out CaptureTimeout for an answer already here.
	if a.abort != nil {
		a.abort()
	}
	return nil
}

// Captured is a verified answer, held for the caller until Release.
type Captured struct {
	e  *Executor
	id string
	a  *captureAssembly
}

// Has reports whether the answer holds part.
func (c *Captured) Has(part string) bool {
	c.e.captures.mu.Lock()
	defer c.e.captures.mu.Unlock()
	if c.a.parts == nil {
		return false
	}
	_, ok := c.a.parts[part]
	return ok
}

// Size reports a part's size; zero when the answer holds none of it.
func (c *Captured) Size(part string) int64 {
	c.e.captures.mu.Lock()
	defer c.e.captures.mu.Unlock()
	if p := c.a.parts[part]; p != nil {
		return p.size
	}
	return 0
}

// WriteTo writes part to w. An answer let go of — released, or dropped
// because its executor was revoked — writes nothing and says why.
func (c *Captured) WriteTo(part string, w io.Writer) (int64, error) {
	c.e.captures.mu.Lock()
	if c.a.parts == nil {
		why := c.a.failed
		c.e.captures.mu.Unlock()
		if why == "" {
			why = "it was released"
		}
		return 0, fmt.Errorf("%w: the capture is no longer held: %s", executor.ErrWriteBackUnavailable, why)
	}
	p := c.a.parts[part]
	var chunks [][]byte
	if p != nil {
		chunks = append(chunks, p.chunks...)
	}
	c.e.captures.mu.Unlock()
	var n int64
	for _, ch := range chunks {
		m, err := w.Write(ch)
		n += int64(m)
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// Release lets go of the answer and gives its bytes back to the budget.
func (c *Captured) Release() {
	if c != nil && c.e != nil {
		c.e.releaseCapture(c.id, "")
	}
}

// CaptureProject asks the device for a project's working copy and waits for
// the answer. The caller must Release what it returns.
func (e *Executor) CaptureProject(ctx context.Context, req CaptureRequest) (*Captured, error) {
	return e.captureProject(ctx, req, e.subject())
}

func (e *Executor) captureProject(ctx context.Context, req CaptureRequest, subject string) (*Captured, error) {
	sess := e.currentSession()
	if sess == nil {
		return nil, fmt.Errorf("%w: %s (%s) is not connected, so its working copy cannot be captured",
			ErrAgentUnreachable, e.id, e.name)
	}
	if v := sess.Version(); !SupportsProjectCapture(v) {
		return nil, fmt.Errorf("%w: %s", ErrCaptureUnsupported, CaptureUpgradeNeeded(subject, v))
	}
	id, err := randomString(12)
	if err != nil {
		return nil, fmt.Errorf("remote: mint a capture id: %w", err)
	}
	id = "cap-" + strings.NewReplacer("+", "-", "/", "_", "=", "").Replace(id)
	if req.Limits.Document <= 0 {
		req.Limits.Document = MaxCaptureDocumentBytes
	}
	payload := CaptureRequestPayload{
		CaptureID: id, Mode: req.Mode, MoveID: req.MoveID, WorkDir: req.WorkDir,
		Features: req.Features, Tenant: req.Tenant, Limits: req.Limits,
	}
	if err := payload.Check(); err != nil {
		return nil, fmt.Errorf("remote: capture request: %w", err)
	}
	rctx, cancel := context.WithTimeout(ctx, CaptureTimeout)
	defer cancel()
	// The read loop wakes this wait once the answer is settled (abort). That
	// ends wait only, never rctx, which the request is written under: ending
	// a write's context before the write has returned closes the device's
	// whole session (requestUntil), and a refusal can be read and handled
	// before the writer has returned.
	wait, wake := context.WithCancel(rctx)
	defer wake()
	a := &captureAssembly{id: id, session: sess, limits: req.Limits, parts: map[string]*capturePart{}, abort: wake}
	e.captures.mu.Lock()
	if e.captures.m == nil {
		e.captures.m = map[string]*captureAssembly{}
	}
	e.captures.m[id] = a
	e.captures.mu.Unlock()
	keep := false
	defer func() {
		if !keep {
			e.releaseCapture(id, "")
		}
	}()

	frame, err := sess.frame(TypeCaptureReq, newCorrelationID(), id, payload)
	if err != nil {
		return nil, fmt.Errorf("remote: build capture request for %s: %w", e.id, err)
	}
	_, reqErr := sess.requestUntil(rctx, wait, frame, TypeCaptureResult)
	// What the read loop recorded decides, whatever ended the wait: the
	// result (applied before it was delivered), a failure that aborted the
	// wait, or neither.
	e.captures.mu.Lock()
	result, failed, verified := a.result, a.failed, a.verified
	e.captures.mu.Unlock()
	switch {
	case verified:
		keep = true
		return &Captured{e: e, id: id, a: a}, nil
	case result != nil && result.Code == CaptureCodeBusy:
		return nil, fmt.Errorf("%w: %s", ErrCaptureBusy, result.Error)
	case result != nil && (result.Error != "" || result.Code != ""):
		return nil, fmt.Errorf("%w: %s", ErrCaptureRefused, nonEmptyText(result.Error, result.Code))
	case failed != "":
		e.cancelCapture(sess, id, failed)
		return nil, fmt.Errorf("%w: %s", executor.ErrWriteBackUnavailable, failed)
	case reqErr != nil:
		e.cancelCapture(sess, id, "the hub stopped waiting: "+reqErr.Error())
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("remote: ask %s (%s) for the working copy: %w", e.id, e.name, reqErr)
	default:
		return nil, fmt.Errorf("%w: the capture's answer was not verified", executor.ErrWriteBackUnavailable)
	}
}

// cancelCapture tells the device to stop a capture, once.
func (e *Executor) cancelCapture(sess *Session, id, reason string) {
	e.captures.mu.Lock()
	a := e.captures.m[id]
	send := a != nil && !a.cancelSent && !a.verified
	if a != nil {
		a.cancelSent = true
	}
	e.captures.mu.Unlock()
	if !send || sess == nil {
		return
	}
	f, err := sess.frame(TypeCaptureCancel, "", id, CaptureCancelPayload{Reason: clipCaptureText(reason)})
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), WriteTimeout)
	defer cancel()
	_ = sess.write(ctx, f)
}

// failedCapture tells the device to stop a capture the hub has failed.
func (s *Session) failedCapture(id, reason string) {
	if s.ex != nil {
		s.ex.cancelCapture(s, id, reason)
	}
}

// CaptureUpgradeNeeded is the sentence a device too old to capture is refused
// with, naming the upgrade.
func CaptureUpgradeNeeded(subject string, have int) string {
	return executor.NeedsProtocol(subject, have, MinProjectCaptureVersion,
		"to capture a project's working copy for a move", "")
}

// CaptureProject asks a virtual executor's device for the project's working
// copy: a device and its virtual executors keep one working copy.
func (v *Virtual) CaptureProject(ctx context.Context, req CaptureRequest) (*Captured, error) {
	return v.parent.captureProject(ctx, req, fmt.Sprintf("virtual executor %s's device %s", v.id, v.parent.subject()))
}

// CaptureVersion reports the protocol the device's session speaks, and
// whether it is connected at all.
func (e *Executor) CaptureVersion() (int, bool) {
	sess := e.currentSession()
	if sess == nil {
		return 0, false
	}
	return sess.Version(), true
}

// CaptureVersion reports the protocol the virtual executor's device speaks.
func (v *Virtual) CaptureVersion() (int, bool) { return v.parent.CaptureVersion() }

// CaptureParts lists the parts an answer holds, for diagnostics.
func (c *Captured) CaptureParts() []string {
	c.e.captures.mu.Lock()
	defer c.e.captures.mu.Unlock()
	var out []string
	for name := range c.a.parts {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func nonEmptyText(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
