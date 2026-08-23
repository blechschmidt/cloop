// Package gitproxy is a git smart-HTTP interception proxy that runs outside the
// sandbox and decides, per ref, what a sandbox is allowed to push.
//
// # The hole it closes
//
// pkg/executor already requires every write-back branch to live under "cloop/",
// and pkg/writeback re-verifies the branch after the fact. Both of those checks
// run in code the sandbox itself executes or in code that inspects the result
// after the push has already landed. Neither is a boundary. A workload that
// ignores the SDK and runs `git push --force origin HEAD:main` with the
// credential it was handed reaches main, and the first anyone hears of it is
// the force-push notification.
//
// The credential is the reason. In push mode the hub leases a GitHub PAT and
// delivers it *into* the sandbox, because that is where git runs. Everything
// downstream of that delivery is advisory: the sandbox holds an authority
// scoped to whole repositories and is asked politely to use a fraction of it.
//
// # The inversion
//
// This proxy moves git's authenticated leg out of the sandbox. The sandbox's
// remote is rewritten to point here, and it authenticates with an ephemeral
// session token that is worth nothing anywhere else. The proxy holds the real
// credential, parses the receive-pack command list before forwarding a byte of
// it, checks every ref update against the session's policy, and only then
// presents the credential upstream.
//
//	sandbox ──session token──▶ gitproxy ──PAT──▶ github.com
//	                             │
//	                        Policy.Decide per ref
//
// So "push to whitelisted branches only" stops being a convention the sandbox
// is trusted to honour and becomes a property of the network path. A sandbox
// that tries refs/heads/main gets a refusal in git's own vocabulary and an
// audit row; a sandbox that leaks its token leaks the right to push to
// refs/heads/cloop/** for the rest of the task, and nothing else.
//
// # What it does not decide
//
// Whether an update is a fast-forward. That needs the object graph, which the
// proxy does not have and would have to index a pack to get. Fast-forward
// enforcement belongs to the forge, where the graph already is — GitHub branch
// protection, or receive.denyNonFastForwards. This package is deliberately
// explicit about the boundary rather than implying a check it cannot make: what
// it enforces is *which refs* a sandbox may touch and *in which direction*
// (create, update, delete), which is exactly what stops a sandbox reaching a
// branch a human owns.
//
// Signed pushes are refused outright. See ParseReceivePack.
//
// # Transport
//
// Serve() takes a listener, so TLS is the caller's to configure through
// pkg/tlsconf. The base URL must be https: the sandbox presents its session
// token as an Authorization header on every request, and a sandbox is by
// construction something that may be sharing a host with whatever else is
// listening on loopback.
package gitproxy

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Content types git uses for the smart protocol.
const (
	uploadPackService  = "git-upload-pack"
	receivePackService = "git-receive-pack"

	advertiseContentType   = "application/x-%s-advertisement"
	resultContentType      = "application/x-%s-result"
	receiveResultMediaType = "application/x-git-receive-pack-result"
)

// Tunables for the upstream leg.
const (
	// defaultDialTimeout bounds connecting to the forge.
	defaultDialTimeout = 15 * time.Second
	// defaultResponseHeaderTimeout bounds how long the forge may take to start
	// replying. There is deliberately no overall client timeout: a large push
	// is legitimately slow, and the request context already dies when the
	// sandbox hangs up.
	defaultResponseHeaderTimeout = 60 * time.Second
	// shutdownGrace bounds Close() waiting for in-flight requests.
	shutdownGrace = 30 * time.Second
)

// Proxy serves the git smart-HTTP protocol for the sessions in a Registry.
//
// The zero value is not usable; call New.
type Proxy struct {
	reg    *Registry
	client *http.Client

	mu       sync.Mutex
	srv      *http.Server
	listener net.Listener
	closed   bool
}

// Options tunes the upstream leg.
type Options struct {
	// Transport carries the proxy's requests to the forge. nil gets a
	// hardened default. It exists so an operator whose forge sits behind a
	// private CA can supply one — the same case pkg/tlsconf exists for — and
	// so a test can point the upstream leg at a self-signed fixture without
	// weakening the default.
	Transport http.RoundTripper
}

// New returns a proxy over reg.
func New(reg *Registry, opts Options) (*Proxy, error) {
	if reg == nil {
		return nil, errors.New("gitproxy: nil registry")
	}
	if _, err := normalizeBaseURL(reg.BaseURL); err != nil {
		return nil, err
	}
	rt := opts.Transport
	if rt == nil {
		rt = &http.Transport{
			DialContext:           (&net.Dialer{Timeout: defaultDialTimeout}).DialContext,
			TLSHandshakeTimeout:   defaultDialTimeout,
			ResponseHeaderTimeout: defaultResponseHeaderTimeout,
			ForceAttemptHTTP2:     true,
			Proxy:                 http.ProxyFromEnvironment,
		}
	}
	return &Proxy{
		reg: reg,
		client: &http.Client{
			Transport: rt,
			// Refuse redirects. A forge that 302s a receive-pack elsewhere
			// would be a forge redirecting the hub's credential to a host the
			// session was never scoped to.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Registry returns the session registry the proxy serves.
func (p *Proxy) Registry() *Registry { return p.reg }

// Serve accepts connections on ln until Close. The caller supplies the
// listener, so a TLS listener from pkg/tlsconf drops straight in.
func (p *Proxy) Serve(ln net.Listener) error {
	srv := &http.Server{
		Handler:           p,
		ReadHeaderTimeout: 30 * time.Second,
		// No WriteTimeout: a clone of a large repository legitimately takes
		// longer than any fixed ceiling worth setting, and the request context
		// already ends when the peer goes away.
		IdleTimeout: 2 * time.Minute,
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return errors.New("gitproxy: proxy is closed")
	}
	p.srv = srv
	p.listener = ln
	p.mu.Unlock()

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Addr returns the address the proxy is listening on, or "".
func (p *Proxy) Addr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener == nil {
		return ""
	}
	return p.listener.Addr().String()
}

// Close stops serving and waits briefly for in-flight requests.
func (p *Proxy) Close() error {
	p.mu.Lock()
	srv := p.srv
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()

	if srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	return srv.Shutdown(ctx)
}

// ServeHTTP implements the git smart-HTTP routes.
//
// Everything outside those routes is a 404. The dumb-HTTP protocol in
// particular is not served: it reads objects and packs straight out of the
// repository, which would let a sandbox fetch by path and bypass every check
// below.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	repoPath, endpoint, ok := splitGitPath(r.URL.Path)
	if !ok {
		p.reject(w, r, http.StatusNotFound, "", "not a git smart-HTTP endpoint")
		return
	}

	sess, err := p.authenticate(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="cloop git proxy"`)
		p.reject(w, r, http.StatusUnauthorized, repoPath, err.Error())
		return
	}
	if !strings.EqualFold(repoPath, sess.RepoPath) {
		p.rejectSession(w, r, sess, http.StatusForbidden,
			fmt.Sprintf("session is scoped to %s, not %s", sess.RepoPath, repoPath))
		return
	}

	switch {
	case endpoint == "info/refs" && r.Method == http.MethodGet:
		p.handleAdvertise(w, r, sess)
	case endpoint == receivePackService && r.Method == http.MethodPost:
		p.handleReceivePack(w, r, sess)
	case endpoint == uploadPackService && r.Method == http.MethodPost:
		p.handleUploadPack(w, r, sess)
	default:
		p.rejectSession(w, r, sess, http.StatusNotFound,
			fmt.Sprintf("%s %s is not a route this proxy serves", r.Method, endpoint))
	}
}

// splitGitPath splits "/owner/name/info/refs" into "owner/name" and
// "info/refs". A trailing ".git" on the repository is tolerated because git
// users habitually append it.
func splitGitPath(p string) (repo, endpoint string, ok bool) {
	trimmed := strings.Trim(p, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 {
		return "", "", false
	}
	// The endpoint is either the last segment (git-upload-pack,
	// git-receive-pack) or the last two (info/refs).
	switch {
	case len(parts) >= 4 && parts[len(parts)-2] == "info" && parts[len(parts)-1] == "refs":
		endpoint = "info/refs"
		parts = parts[:len(parts)-2]
	case parts[len(parts)-1] == uploadPackService, parts[len(parts)-1] == receivePackService:
		endpoint = parts[len(parts)-1]
		parts = parts[:len(parts)-1]
	default:
		return "", "", false
	}
	if len(parts) != 2 {
		// Exactly owner/name. Anything else is not a repository this proxy
		// serves, and accepting a deeper path would let a request address a
		// URL the session's pin was never compared against.
		return "", "", false
	}
	owner, name := parts[0], strings.TrimSuffix(parts[1], ".git")
	if owner == "" || name == "" || owner == "." || owner == ".." || name == "." || name == ".." {
		return "", "", false
	}
	return owner + "/" + name, endpoint, true
}

// authenticate resolves the session from the request's basic credential.
func (p *Proxy) authenticate(r *http.Request) (*Session, error) {
	id, token, ok := r.BasicAuth()
	if !ok || id == "" || token == "" {
		return nil, fmt.Errorf("%w: no basic credential", ErrUnauthenticated)
	}
	return p.reg.Authenticate(id, token)
}

// --- ref advertisement -------------------------------------------------------

// handleAdvertise proxies GET /info/refs.
//
// The advertisement is forwarded unmodified. Filtering it to the allowed refs
// is tempting and wrong: a receive-pack client treats every advertised ref as
// an object it need not send, so hiding refs/heads/main makes the sandbox
// re-send the entire history reachable from it on every push. The allowlist is
// enforced on the command list, where it costs nothing and cannot be worked
// around by a client that skipped discovery.
func (p *Proxy) handleAdvertise(w http.ResponseWriter, r *http.Request, sess *Session) {
	service := r.URL.Query().Get("service")
	switch service {
	case receivePackService:
		if !sess.Policy.canWrite() {
			p.rejectSession(w, r, sess, http.StatusForbidden, "this session may not push")
			return
		}
	case uploadPackService:
		if !sess.Policy.AllowFetch {
			p.rejectSession(w, r, sess, http.StatusForbidden, "this session may not fetch")
			return
		}
	default:
		// No service parameter means the dumb protocol. Refusing it is what
		// keeps this proxy's surface to the two endpoints below.
		p.rejectSession(w, r, sess, http.StatusForbidden,
			fmt.Sprintf("unsupported service %q; only the smart protocol is proxied", service))
		return
	}

	up, err := p.upstreamRequest(r, sess, "/info/refs?service="+service, nil)
	if err != nil {
		p.rejectSession(w, r, sess, http.StatusBadGateway, err.Error())
		return
	}
	p.forward(w, r, sess, up, fmt.Sprintf(advertiseContentType, service))
}

// --- push --------------------------------------------------------------------

// handleReceivePack is the interception point.
func (p *Proxy) handleReceivePack(w http.ResponseWriter, r *http.Request, sess *Session) {
	pol := sess.Policy
	if !pol.canWrite() {
		p.rejectSession(w, r, sess, http.StatusForbidden, "this session may not push")
		return
	}

	body, err := requestBody(w, r, pol.MaxPackBytes)
	if err != nil {
		p.rejectSession(w, r, sess, http.StatusBadRequest, err.Error())
		return
	}
	if closer, ok := body.(io.Closer); ok {
		defer closer.Close()
	}

	head, replay, err := ParseReceivePack(body)
	if err != nil {
		sess.denied.Add(1)
		status := http.StatusBadRequest
		if errors.Is(err, errPushCert) {
			status = http.StatusForbidden
		}
		p.rejectSession(w, r, sess, status, err.Error())
		return
	}

	if len(head.Commands) == 0 {
		// git sends a flush-only body to probe. Nothing is authorised and
		// nothing is forwarded.
		w.Header().Set("Content-Type", receiveResultMediaType)
		w.WriteHeader(http.StatusOK)
		return
	}

	if len(head.Commands) > pol.MaxCommands {
		sess.denied.Add(1)
		p.emitPush(sess, EventPushDenied, head.Commands,
			fmt.Sprintf("%d ref updates exceeds the %d this session allows", len(head.Commands), pol.MaxCommands))
		p.refuse(w, r, sess, head, nil,
			fmt.Sprintf("push carries %d ref updates; this session allows %d", len(head.Commands), pol.MaxCommands))
		return
	}

	decisions, allowed := pol.DecideAll(head.Commands)
	if !allowed {
		sess.denied.Add(1)
		var refused []string
		for _, d := range decisions {
			if !d.Allowed() {
				refused = append(refused, d.Update.Ref+": "+d.Reason())
			}
		}
		p.emitPush(sess, EventPushDenied, head.Commands, strings.Join(refused, "; "))
		p.refuse(w, r, sess, head, decisions, "")
		return
	}

	p.emitPush(sess, EventPushAllowed, head.Commands, summarize(head.Commands))

	up, err := p.upstreamRequest(r, sess, "/"+receivePackService, replay)
	if err != nil {
		p.rejectSession(w, r, sess, http.StatusBadGateway, err.Error())
		return
	}
	sess.pushes.Add(1)
	p.forward(w, r, sess, up, receiveResultMediaType)
}

// handleUploadPack proxies a fetch.
func (p *Proxy) handleUploadPack(w http.ResponseWriter, r *http.Request, sess *Session) {
	if !sess.Policy.AllowFetch {
		p.rejectSession(w, r, sess, http.StatusForbidden, "this session may not fetch")
		return
	}
	body, err := requestBody(w, r, sess.Policy.MaxPackBytes)
	if err != nil {
		p.rejectSession(w, r, sess, http.StatusBadRequest, err.Error())
		return
	}
	if closer, ok := body.(io.Closer); ok {
		defer closer.Close()
	}
	up, err := p.upstreamRequest(r, sess, "/"+uploadPackService, body)
	if err != nil {
		p.rejectSession(w, r, sess, http.StatusBadGateway, err.Error())
		return
	}
	sess.fetches.Add(1)
	p.reg.emit(Event{
		Kind: EventFetch, SessionID: sess.ID, RepoPath: sess.RepoPath,
		ProjectID: sess.ProjectID, TaskID: sess.TaskID, Actor: sess.Actor,
		At: p.reg.now(),
	})
	p.forward(w, r, sess, up, fmt.Sprintf(resultContentType, uploadPackService))
}

// canWrite reports whether a policy permits any push at all.
func (p Policy) canWrite() bool { return p.AllowCreate || p.AllowUpdate || p.AllowDelete }

// requestBody applies the size cap and transparently decompresses a gzipped
// body, which is what git sends for anything past a few kilobytes.
func requestBody(w http.ResponseWriter, r *http.Request, maxBytes int64) (io.Reader, error) {
	var body io.Reader = r.Body
	if maxBytes > 0 {
		body = http.MaxBytesReader(w, r.Body, maxBytes)
	}
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(body)
		if err != nil {
			return nil, fmt.Errorf("body claims gzip encoding but does not decompress: %w", err)
		}
		return zr, nil
	}
	return body, nil
}

// --- upstream ----------------------------------------------------------------

// upstreamRequest builds and sends the forge-side request.
//
// This is the only place the real credential is attached, and it is attached to
// a URL derived from the session rather than from anything the sandbox sent —
// so a request cannot steer the credential at a host of its choosing.
func (p *Proxy) upstreamRequest(r *http.Request, sess *Session, suffix string, body io.Reader) (*http.Response, error) {
	target := strings.TrimSuffix(sess.Upstream, ".git") + ".git" + suffix
	method := http.MethodGet
	if body != nil {
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(r.Context(), method, target, body)
	if err != nil {
		return nil, fmt.Errorf("building upstream request: %w", err)
	}
	if body != nil {
		// Unknown length: the replay reader concatenates a buffer and a stream,
		// and a gzipped body was decompressed on the way in, so neither the
		// client's Content-Length nor its Content-Encoding still describes what
		// goes out. Only when there *is* a body: net/http refuses to send a
		// request whose ContentLength is non-zero while Body is nil, so setting
		// this on the body-less GET of /info/refs fails every clone, fetch and
		// push at the ref advertisement.
		req.ContentLength = -1
	}

	for _, h := range []string{"Content-Type", "Accept", "Git-Protocol"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	req.Header.Set("User-Agent", "cloop-gitproxy")
	if auth := sess.credential.authorization(); auth != "" {
		req.Header.Set("Authorization", auth)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upstream request failed: %w", scrub(err, sess))
	}
	return resp, nil
}

// forward streams the upstream response back to the sandbox.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, sess *Session, up *http.Response, fallbackType string) {
	defer up.Body.Close()

	ct := up.Header.Get("Content-Type")
	if ct == "" {
		ct = fallbackType
	}
	w.Header().Set("Content-Type", ct)
	// Git caches nothing here and neither should anything in between.
	w.Header().Set("Cache-Control", "no-cache, max-age=0, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	if v := up.Header.Get("Content-Encoding"); v != "" {
		w.Header().Set("Content-Encoding", v)
	}
	// Every other upstream header is dropped rather than relayed. A forge's
	// Set-Cookie or WWW-Authenticate reaching the sandbox would be the hub's
	// session with the forge leaking one hop further than it should.

	status := up.StatusCode
	if status >= 400 {
		// Upstream refused. Pass the status through so git reports something
		// truthful, but do not pass the body: a forge's error page can quote
		// the request back, and the request carried the hub's credential.
		w.WriteHeader(status)
		fmt.Fprintf(w, "cloop git proxy: upstream returned %s\n", up.Status)
		return
	}
	w.WriteHeader(status)

	n, err := io.Copy(newFlushWriter(w), up.Body)
	sess.bytesDown.Add(n)
	if err != nil && !errors.Is(err, context.Canceled) {
		// The status line is already out, so there is nowhere to report this
		// except the audit trail.
		p.reg.emit(Event{
			Kind: EventRejected, SessionID: sess.ID, RepoPath: sess.RepoPath,
			ProjectID: sess.ProjectID, TaskID: sess.TaskID,
			Detail: "upstream stream ended early: " + scrub(err, sess).Error(),
			At:     p.reg.now(),
		})
	}
}

// scrub keeps a session's upstream credential out of an error surfaced to the
// sandbox. url.Error quotes the request URL, which never contains the
// credential here — but an error built elsewhere might, and the cost of being
// certain is one string replacement.
func scrub(err error, sess *Session) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if pw := strings.TrimSpace(sess.credential.Password); pw != "" && strings.Contains(msg, pw) {
		msg = strings.ReplaceAll(msg, pw, "[redacted]")
		return errors.New(msg)
	}
	return err
}

// flushWriter pushes each chunk out as it arrives. Git's side-band progress is
// useless if it is buffered until the pack finishes.
type flushWriter struct {
	w io.Writer
	f http.Flusher
}

func newFlushWriter(w http.ResponseWriter) io.Writer {
	f, ok := w.(http.Flusher)
	if !ok {
		return w
	}
	return &flushWriter{w: w, f: f}
}

func (fw *flushWriter) Write(b []byte) (int, error) {
	n, err := fw.w.Write(b)
	if n > 0 {
		fw.f.Flush()
	}
	return n, err
}

// --- refusal -----------------------------------------------------------------

// refuse tells the client its push was rejected, in whichever dialect it can
// understand.
//
// A client that asked for report-status gets a per-ref "ng" line and exits
// non-zero having printed the reason next to the branch name — the difference
// between "remote rejected refs/heads/main: not in this session's branch
// allowlist" and a bare HTTP 403, which git renders as an unexplained failure.
// A client that did not ask has no channel for a report, so it is refused at
// the HTTP layer instead; answering 200 with a report it will not read would be
// a refused push that git calls a success.
func (p *Proxy) refuse(w http.ResponseWriter, r *http.Request, sess *Session, head *ReceivePack, decisions []Decision, global string) {
	if !head.WantsReportStatus() {
		msg := global
		if msg == "" {
			for _, d := range decisions {
				if !d.Allowed() {
					msg = d.Update.Ref + ": " + d.Reason()
					break
				}
			}
		}
		p.rejectSession(w, r, sess, http.StatusForbidden, msg)
		return
	}

	var report strings.Builder
	report.WriteString("unpack ok\n")
	if global != "" {
		for _, c := range head.Commands {
			fmt.Fprintf(&report, "ng %s %s\n", c.Ref, oneLine(global))
		}
	} else {
		for _, d := range decisions {
			if d.Allowed() {
				// Refused as a unit: a command that would have passed on its
				// own is still not applied, and saying "ok" for it would tell
				// the client a ref moved when nothing did.
				fmt.Fprintf(&report, "ng %s %s\n", d.Update.Ref, "push refused as a whole because another ref was denied")
				continue
			}
			fmt.Fprintf(&report, "ng %s %s\n", d.Update.Ref, oneLine(d.Reason()))
		}
	}

	w.Header().Set("Content-Type", receiveResultMediaType)
	w.Header().Set("Cache-Control", "no-cache, max-age=0, must-revalidate")
	w.WriteHeader(http.StatusOK)

	out := newFlushWriter(w)
	if head.WantsSideband() {
		// Channel 2 is progress, which git prints prefixed with "remote:" —
		// the only way to get a full explanation in front of the user, since
		// "ng" reasons are truncated to one line next to the ref.
		_ = writeSideband(out, sidebandProgress,
			[]byte("cloop git proxy refused this push: "+oneLine(refusalSummary(global, decisions))+"\n"))
		_ = writeSideband(out, sidebandData, []byte(reportPackets(report.String())))
		_ = writeFlush(out)
		return
	}
	_, _ = out.Write([]byte(reportPackets(report.String())))
}

// reportPackets frames each report line as its own pkt-line and terminates the
// section, which is the shape git's status parser expects.
func reportPackets(report string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimSuffix(report, "\n"), "\n") {
		_ = writePkt(&b, []byte(line+"\n"))
	}
	_ = writeFlush(&b)
	return b.String()
}

func refusalSummary(global string, decisions []Decision) string {
	if global != "" {
		return global
	}
	var parts []string
	for _, d := range decisions {
		if !d.Allowed() {
			parts = append(parts, d.Update.Ref+" ("+d.Reason()+")")
		}
	}
	return strings.Join(parts, ", ")
}

func oneLine(s string) string {
	return elide(strings.Join(strings.Fields(s), " "))
}

// reject answers a request that never reached a session.
func (p *Proxy) reject(w http.ResponseWriter, r *http.Request, status int, repoPath, detail string) {
	p.reg.emit(Event{
		Kind: EventRejected, RepoPath: repoPath, Detail: detail, At: p.reg.now(),
	})
	http.Error(w, "cloop git proxy: "+oneLine(detail), status)
}

// rejectSession answers a request that authenticated but was refused.
func (p *Proxy) rejectSession(w http.ResponseWriter, r *http.Request, sess *Session, status int, detail string) {
	p.reg.emit(Event{
		Kind: EventRejected, SessionID: sess.ID, RepoPath: sess.RepoPath,
		ProjectID: sess.ProjectID, TaskID: sess.TaskID, Actor: sess.Actor,
		Detail: detail, At: p.reg.now(),
	})
	http.Error(w, "cloop git proxy: "+oneLine(detail), status)
}

func (p *Proxy) emitPush(sess *Session, kind EventKind, cmds []RefUpdate, detail string) {
	p.reg.emit(Event{
		Kind: kind, SessionID: sess.ID, RepoPath: sess.RepoPath,
		ProjectID: sess.ProjectID, TaskID: sess.TaskID, Actor: sess.Actor,
		Refs: refNames(cmds), Detail: detail, At: p.reg.now(),
	})
}

func summarize(cmds []RefUpdate) string {
	parts := make([]string, 0, len(cmds))
	for _, c := range cmds {
		parts = append(parts, c.String())
	}
	return strings.Join(parts, ", ")
}
