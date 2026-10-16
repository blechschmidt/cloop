package gitproxy

// pushgate.go forwards a push to the forge while it is scanned, and decides
// before the forge can commit anything (Task 20436).
//
// The scan runs on its own goroutine, reading the sandbox's body; the forge's
// request reads the pipe the scan writes into. Bytes reach the pipe only once
// the scan has consumed them (packSource), and the pack's checksum only once
// the scan has finished clean. A refusal closes the pipe with an error instead,
// which aborts the forge's request mid-body — over HTTP/1.1 the connection
// closes before the chunked body's terminator, over HTTP/2 the stream is reset
// — so the forge holds an incomplete pack, which receive-pack refuses to
// unpack, and no ref moves. The scan then reads the rest of the sandbox's body
// so its git reads the refusal rather than a broken pipe.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/hubmetrics"
)

// errPushScanRefused is what the forge's request body fails with when a push
// is refused. It never reaches the sandbox.
var errPushScanRefused = errors.New("gitproxy: push refused by its scan; the forge's request is abandoned")

// Results a scan is counted under (cloop_gitproxy_push_scans_total).
const (
	ScanResultClean      = "clean"
	ScanResultSecret     = "secret"
	ScanResultLimit      = "limit"
	ScanResultUnreadable = "unreadable"
	ScanResultIncomplete = "incomplete"
	ScanResultUnscanned  = "unscanned"
)

// ScanResults is every result label, for tests that hold the docs to the set.
var ScanResults = []string{
	ScanResultClean, ScanResultSecret, ScanResultLimit, ScanResultUnreadable,
	ScanResultIncomplete, ScanResultUnscanned,
}

// scanOutcome is what a scan decided.
type scanOutcome struct {
	findings []ScanFinding
	err      *scanError
	inflated int64
	objects  uint32
	work     time.Duration
}

// refused reports whether the push is refused: it carries a credential, or
// the scan could not finish for a reason the push itself caused.
func (o scanOutcome) refused() bool {
	if len(o.findings) > 0 {
		return true
	}
	return o.err != nil && (o.err.stop == stopLimit || o.err.stop == stopUnreadable)
}

func (o scanOutcome) result() string {
	switch {
	case len(o.findings) > 0:
		return ScanResultSecret
	case o.err == nil:
		return ScanResultClean
	case o.err.stop == stopLimit:
		return ScanResultLimit
	case o.err.stop == stopUnreadable:
		return ScanResultUnreadable
	default:
		return ScanResultIncomplete
	}
}

// pushGate joins the scan's goroutine to the forge's request.
//
// The bytes the scan hands on go through a bounded queue to a goroutine of
// their own that writes them into the pipe the forge's request reads, so the
// scan inflates the next objects while the transport is still sending the
// last ones: a push then takes about as long as the slower of the two, not
// their sum.
type pushGate struct {
	pr *io.PipeReader
	pw *io.PipeWriter
	// refused: the push will be refused, and nothing more reaches the forge.
	// upstreamGone: nothing reads the pipe any more, and the scan should
	// stop.
	refused      atomic.Bool
	upstreamGone atomic.Bool
	// complete: the scan ended clean and handed on its last bytes, so the
	// pump may end the forge's body once it has written them.
	complete atomic.Bool

	queue chan []byte
	free  chan []byte
	// sent is closed when the pump has written or dropped everything queued.
	sent       chan struct{}
	finishOnce sync.Once
	done       chan struct{}
	out        scanOutcome
}

// pushGateQueue bounds the bytes queued for the forge: 64 buffers of the
// source's 64 KiB.
const pushGateQueue = 64

func newPushGate() *pushGate {
	pr, pw := io.Pipe()
	g := &pushGate{
		pr: pr, pw: pw,
		queue: make(chan []byte, pushGateQueue),
		free:  make(chan []byte, pushGateQueue+2),
		sent:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	go g.pump()
	return g
}

// pump writes queued bytes into the pipe until the queue closes, then ends
// the forge's body: cleanly when the scan said so, with an error otherwise.
func (g *pushGate) pump() {
	defer close(g.sent)
	for b := range g.queue {
		if !g.refused.Load() && !g.upstreamGone.Load() {
			if _, err := g.pw.Write(b); err != nil && !g.refused.Load() {
				g.upstreamGone.Store(true)
			}
		}
		select {
		case g.free <- b[:cap(b)]:
		default:
		}
	}
	if g.complete.Load() && !g.refused.Load() && !g.upstreamGone.Load() {
		_ = g.pw.Close()
		return
	}
	_ = g.pw.CloseWithError(errPushScanRefused)
}

// tee hands consumed bytes to the forge's request. It copies them, because
// the source reuses its buffer, and blocks while the queue is full.
func (g *pushGate) tee(b []byte) error {
	for len(b) > 0 {
		if g.refused.Load() {
			return nil
		}
		if g.upstreamGone.Load() {
			return &scanError{stop: stopUpstream, msg: "the forge stopped reading the push"}
		}
		var buf []byte
		select {
		case buf = <-g.free:
		default:
			buf = make([]byte, scanSourceBuffer)
		}
		n := copy(buf, b)
		b = b[n:]
		g.queue <- buf[:n]
	}
	return nil
}

// refuse abandons the forge's request at once, whatever is still queued.
func (g *pushGate) refuse() {
	if g.refused.CompareAndSwap(false, true) {
		_ = g.pw.CloseWithError(errPushScanRefused)
	}
}

// finish ends the queue, once; complete says the scan ended clean. It waits
// for the pump to have written or dropped everything queued.
func (g *pushGate) finish(complete bool) {
	g.finishOnce.Do(func() {
		g.complete.Store(complete)
		close(g.queue)
	})
	<-g.sent
}

// abandonUpstream is for the handler: nothing will read the forge's side.
func (g *pushGate) abandonUpstream() {
	g.upstreamGone.Store(true)
	_ = g.pr.CloseWithError(errPushScanRefused)
}

// upstreamBody is the forge request's body. Its Close reaches the pipe, which
// is the point: http.NewRequest gives a body that is no io.ReadCloser a Close
// that does nothing, and a transport that stops reading — the forge answered
// early and dropped the connection — would then close a body that never told
// the pipe, leaving the scan blocked on a write nobody reads, and the push's
// handler waiting on the scan.
type upstreamBody struct {
	io.Reader
	pipe *io.PipeReader
}

func (b upstreamBody) Close() error { return b.pipe.CloseWithError(errPushScanRefused) }

// runPushScan scans what follows the command section and forwards it, then
// records its outcome on g and closes g.done. maxBytes bounds what it reads
// from the sandbox.
func runPushScan(g *pushGate, rest io.Reader, head *ReceivePack, m *matcher, mode ScanMode,
	limits ScanLimits, maxBytes int64, idle func()) {

	defer close(g.done)
	// Everything below runs on a goroutine of its own, where a panic would
	// take the hub down rather than one request: whatever fails, the push is
	// refused and the forge's request abandoned.
	defer func() {
		if r := recover(); r != nil {
			g.out = scanOutcome{err: unreadable("the proxy failed reading it (%v)", r)}
			g.refuse()
			g.finish(false)
		}
	}()
	src := newPackSource(rest, g.tee)
	src.idle = idle
	src.limit = maxBytes
	sc := newPackScanner(src, head.hashLen(), m, mode == ScanShapes, limits)
	sc.onRefuse = g.refuse

	err := func() (err error) {
		// The pack is the sandbox's to write, and this parser reads it on a
		// goroutine of its own, where a panic would take the hub down with
		// it. A parser fault is a pack the proxy cannot read, and refused.
		defer func() {
			if r := recover(); r != nil {
				err = unreadable("the proxy failed reading it (%v)", r)
			}
		}()
		return sc.scan(head)
	}()

	var se *scanError
	if err != nil && !errors.As(err, &se) {
		se = &scanError{stop: stopUnreadable, msg: err.Error(), err: err}
	}
	out := scanOutcome{err: se, inflated: sc.inflated, objects: sc.objects, work: sc.work()}
	out.findings = sc.report()

	switch {
	case !out.refused() && se == nil:
		// Clean: the checksum goes upstream, and the pack is whole.
		rerr := src.release()
		g.finish(rerr == nil)
		if rerr != nil || g.upstreamGone.Load() {
			if !errors.As(rerr, &se) {
				se = &scanError{stop: stopUpstream, msg: "the forge stopped reading the push", err: rerr}
			}
			out.err = se
		}
	case out.refused():
		g.refuse()
		// The sandbox's git is still sending; let it finish, so it reads
		// the refusal rather than a reset connection.
		src.drain()
		g.finish(false)
	default:
		// The sandbox's body failed or the forge stopped reading: neither
		// end can be told anything, and the forge must not get a pack.
		g.refuse()
		g.finish(false)
	}
	g.out = out
}

// hashLen is the object id width the push uses: SHA-256 when its object names
// are 64 hex digits.
func (r *ReceivePack) hashLen() int {
	if r != nil {
		for _, c := range r.Commands {
			if len(c.New) == 64 || len(c.Old) == 64 {
				return 32
			}
		}
	}
	return 20
}

// scanPushAndForward forwards a push whose commands policy allowed, scanning
// what it carries on the way.
func (p *Proxy) scanPushAndForward(w http.ResponseWriter, r *http.Request, sess *Session, head *ReceivePack,
	raw []byte, rest io.Reader, scan PushScan, m *matcher) {

	// At most a couple of scans per session at once: one sandbox pushing in
	// parallel gets its scans in turn rather than every core of the hub.
	release, err := sess.acquireScan(r.Context())
	if err != nil {
		return
	}
	defer release()

	g := newPushGate()
	rc := http.NewResponseController(w)
	idle := func() { _ = rc.SetReadDeadline(time.Now().Add(pushScanIdleReadDeadline)) }
	go runPushScan(g, rest, head, m, scan.Mode, scan.Limits, sess.Policy.MaxPackBytes, idle)

	up, err := p.upstreamRequest(r, sess, "/"+receivePackService,
		upstreamBody{Reader: io.MultiReader(bytes.NewReader(raw), g.pr), pipe: g.pr})
	switch {
	case err != nil:
		g.abandonUpstream()
	case up.StatusCode >= http.StatusBadRequest:
		// The forge has answered, and refused, before taking the pack: it
		// will do nothing with the rest, so stop feeding it.
		g.abandonUpstream()
	}
	<-g.done
	_ = rc.SetReadDeadline(time.Time{})
	out := g.out

	hubmetrics.GitProxyPushScans.Inc(out.result())
	hubmetrics.GitProxyPushScanBytes.Add(float64(out.inflated))
	hubmetrics.GitProxyPushScanSeconds.Observe(out.work.Seconds())

	if out.refused() {
		if up != nil {
			_ = up.Body.Close()
		}
		sess.denied.Add(1)
		hubmetrics.GitProxyPushes.Inc(hubmetrics.ResultDenied)
		p.refuseScanned(w, r, sess, head, out, m)
		return
	}
	if err != nil {
		p.upstreamFailed(w, r, sess, err)
		return
	}
	if out.err != nil {
		// The sandbox's git went away mid-push, or the forge stopped reading
		// it — answering early, say, with an error of its own. Either way the
		// scan did not finish and the forge holds no complete pack: the push
		// is neither allowed nor refused, and the row says what happened.
		p.reg.emit(Event{
			Kind: EventRejected, SessionID: sess.ID, RepoPath: requestRepo(r, sess),
			ProjectID: sess.ProjectID, TaskID: sess.TaskID, Actor: sess.Actor,
			Refs: m.redactAll(refNames(head.Commands)), Detail: "push not completed: " + out.err.msg, At: p.reg.now(),
		})
		if out.err.stop == stopUpstream {
			// What the forge said, if anything, is the sandbox's to read.
			p.forward(w, r, sess, up, receiveResultMediaType)
			return
		}
		_ = up.Body.Close()
		return
	}
	hubmetrics.GitProxyPushes.Inc(hubmetrics.ResultAllowed)
	detail := m.redact(summarize(head.Commands)) + fmt.Sprintf(
		"; scanned %d objects (%s inflated) for the run's credentials and found none",
		out.objects, humanBytes(out.inflated))
	p.emitPush(r, sess, EventPushAllowed, m.redactAll(refNames(head.Commands)), detail)
	sess.pushes.Add(1)
	p.forward(w, r, sess, up, receiveResultMediaType)
}

// refuseScanned answers a push its scan refused, in git's own vocabulary, and
// records why.
func (p *Proxy) refuseScanned(w http.ResponseWriter, r *http.Request, sess *Session, head *ReceivePack,
	out scanOutcome, m *matcher) {

	refs := m.redactAll(refNames(head.Commands))
	var (
		lines  []string
		reason string
	)
	if len(out.findings) > 0 {
		lines = append(lines, "cloop git proxy refused this push: it carries a credential this run was given.")
		for _, f := range out.findings {
			lines = append(lines, "- "+f.summary())
		}
		lines = append(lines,
			"Take the value out of these objects and rewrite the commits that carry it "+
				"(git commit --amend, git rebase -i), then push again.",
			"No ref was updated, and the forge never received a complete pack. The value itself "+
				"is never shown, logged or recorded.")
		first := out.findings[0]
		reason = "carries a credential this run was given: " +
			ScanSecret{Grant: first.Grant, Secret: first.Secret, Field: first.Field}.describe()
		p.reg.emit(Event{
			Kind: EventPushSecretRefused, SessionID: sess.ID, RepoPath: requestRepo(r, sess),
			ProjectID: sess.ProjectID, TaskID: sess.TaskID, Actor: sess.Actor, RunID: sess.RunID,
			Refs: refs, Detail: findingsDetail(out.findings), Findings: out.findings,
			Scan: ScanResultSecret, At: p.reg.now(),
		})
		hubmetrics.GitProxyDenials.Inc(string(DenySecretInPush))
	} else {
		var how string
		denial := DenyUnreadablePack
		if out.err.stop == stopLimit {
			denial = DenyScanLimit
			how = "its objects could not be scanned within the proxy's limits: " + out.err.msg +
				", so it cannot say the push carries no credential."
			if out.err.setting != "" {
				how += " Split the push, or have an operator raise " + out.err.setting + "."
			}
		} else {
			how = "the proxy could not read its pack: " + out.err.msg +
				", so it cannot say the push carries no credential."
		}
		lines = append(lines, "cloop git proxy refused this push: "+how, "No ref was updated.")
		reason = "not scanned: " + out.err.msg
		p.reg.emit(Event{
			Kind: EventPushDenied, SessionID: sess.ID, RepoPath: requestRepo(r, sess),
			ProjectID: sess.ProjectID, TaskID: sess.TaskID, Actor: sess.Actor, RunID: sess.RunID,
			Refs: refs, Detail: "push scan: " + how, Scan: out.result(), At: p.reg.now(),
		})
		hubmetrics.GitProxyDenials.Inc(string(denial))
	}

	if !head.WantsReportStatus() {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, strings.Join(lines, "\n")+"\n")
		return
	}
	var report strings.Builder
	report.WriteString("unpack ok\n")
	for _, c := range head.Commands {
		fmt.Fprintf(&report, "ng %s %s\n", c.Ref, oneLine(reason))
	}
	w.Header().Set("Content-Type", receiveResultMediaType)
	w.Header().Set("Cache-Control", "no-cache, max-age=0, must-revalidate")
	w.WriteHeader(http.StatusOK)
	o := newFlushWriter(w)
	if head.WantsSideband() {
		for _, line := range lines {
			_ = writeSideband(o, sidebandProgress, []byte(line+"\n"))
		}
		_ = writeSideband(o, sidebandData, []byte(reportPackets(report.String())))
		_ = writeFlush(o)
		return
	}
	_, _ = o.Write([]byte(reportPackets(report.String())))
}

// findingsDetail is the audit row's detail for a refusal: every finding, by
// object and provenance, never by value.
func findingsDetail(fs []ScanFinding) string {
	parts := make([]string, 0, len(fs))
	for _, f := range fs {
		parts = append(parts, f.summary())
	}
	return "carries a credential the run was given: " + strings.Join(parts, "; ")
}

// redactAll applies redact to each string.
func (m *matcher) redactAll(ss []string) []string {
	if m == nil {
		return ss
	}
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = m.redact(s)
	}
	return out
}

// humanBytes renders a byte count for a detail line.
func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
