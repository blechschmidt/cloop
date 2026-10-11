package ui

// The static admin token, retired at runtime (Task 20406).
//
// --token / CLOOP_UI_TOKEN is the deployment's own secret: a request
// presenting it is an administrator outside RBAC, and it never expires. Until
// this file the only way to stop a hub honouring it was to edit the Secret and
// restart every member, and nothing it had opened — a dashboard stream, a
// sandbox terminal — ended even then.
//
// # One verdict
//
// checkStaticToken is the only code that compares a presented credential with
// the token, and both authentication gates — authMiddleware for a token-only
// hub, oidcGate for one with single sign-on — act on its verdict. Two copies of
// the comparison are how a fix lands in one gate and not the other;
// tests/arch keeps it one.
//
// # Retired, never absent
//
// Retiring adds the token's fingerprint to retired_static_tokens. A member
// refuses a retired token at once when the retirement was its own, within a
// bus poll when another member or `cloop hub token static retire` announced
// it, and within ReportInterval when nothing reached it; a member that starts
// reads the table before it serves. The refusal is a 401 saying when and by
// whom the token was retired and what to use instead, and it does not count
// toward the per-IP guess lockout: presenting a retired token is not guessing.
//
// The token stays configured. s.staticToken is never cleared, so
// staticTokenConfigured keeps answering true, which is what keeps a token-only
// hub closed — an empty token opens it, and decides the loopback-only bind
// (pkg/exposure) — after its only credential was retired. Such a hub then
// admits API tokens and nothing else, which is why retiring that credential
// with no admin API token in existence is refused unless forced.
//
// Retirement is per fingerprint, so a new value deployed in place of the old
// one is admitted: that is the rotation path. The retired value is refused
// wherever it is presented, including to a hub that has since rotated.
//
// # What it opened
//
// A stream records that the static token opened it (admitStaticToken), and
// credentialEnded now asks whether that token is retired: a retirement ends
// every dashboard socket, event stream and sandbox terminal it opened, on
// every member, with credential_ended and 1008 static_token_retired.
//
// # Last use
//
// Each member keeps the token's last use — time and client address — and the
// refusals of retired tokens in memory, and flushes them to static_token_use
// every ReportInterval and when it stops, never once per request. The Settings
// card, `cloop hub token static status` and `cloop hub doctor` read it from
// there.

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/statictoken"
)

// staticTokenRefreshNS is how old the retired set may get before a reader
// asks for a fresh one, in nanoseconds: statictoken.ReportInterval, so a
// member the bus never reached still refuses a retired token within a minute.
// Atomic so a test can change it while another server's goroutines read it.
var staticTokenRefreshNS atomic.Int64

func init() { staticTokenRefreshNS.Store(int64(statictoken.ReportInterval)) }

// staticTokenGuard is what a hub knows about its static token besides the
// value.
type staticTokenGuard struct {
	// retired is the last retired set read, nil until the first read
	// succeeds. Replaced whole, so a reader never sees half a reload.
	retired atomic.Pointer[retiredStaticTokens]
	// loadMu runs one reload at a time; refreshing marks a background one.
	loadMu     sync.Mutex
	refreshing atomic.Bool
	// failedAt is when the last read failed (unix nanoseconds), so a set that
	// has never been read is not re-read by every request while the database
	// will not answer; loadWarned is when a failed read was last logged.
	failedAt   atomic.Int64
	loadWarned atomic.Int64

	// fpOnce computes the configured token's fingerprint, which never
	// changes: the token is set when the Server is built.
	fpOnce sync.Once
	fp     string

	// useMu guards the use and refusals seen since the last flush, and the
	// latest use this process ever saw.
	useMu    sync.Mutex
	pending  staticTokenSeen
	latest   staticTokenSeen
	refused  map[string]*staticTokenRefusals
	warnedAt map[string]time.Time
}

// retiredStaticTokens is one read of retired_static_tokens.
type retiredStaticTokens struct {
	byFingerprint map[string]statedb.RetiredStaticTokenRow
	readAt        time.Time
}

// staticTokenSeen is one admitted use: when, and from which client address.
type staticTokenSeen struct {
	at time.Time
	ip string
}

// staticTokenRefusals counts the requests refused because a token is
// retired, and the latest of them.
type staticTokenRefusals struct {
	n    int64
	last staticTokenSeen
}

// staticTokenVerdict is what a request's static-token credential amounts to.
type staticTokenVerdict struct {
	// presented: the request carries a value the static token is compared
	// with — an Authorization: Bearer header, or a non-empty ?token=.
	presented bool
	// admitted: one of them is this hub's static token, and it is live.
	admitted bool
	// retired: one of them is a retired static token — this hub's own, or a
	// value retired before it was rotated away — and none was admitted.
	retired *statedb.RetiredStaticTokenRow
	// unverifiable: one of them is this hub's static token, and whether it
	// is retired cannot be told, because the retired set has never been
	// read. Refused: an administrator credential that may have been retired
	// is not admitted on a guess.
	unverifiable bool
}

// staticTokenConfigured reports whether this hub has a static token at all,
// retired or not. A retired token is configured: answering false here would
// open a token-only hub and widen where it binds.
func (s *Server) staticTokenConfigured() bool {
	return s.staticToken != ""
}

// staticTokenAccepted reports whether a request presenting this hub's static
// token would be admitted: one is configured and it is not retired. For what
// the dashboard tells people only — an authentication or bind decision reads
// staticTokenConfigured, because a retired token is still configured.
func (s *Server) staticTokenAccepted() bool {
	if !s.staticTokenConfigured() {
		return false
	}
	_, retired := s.ownStaticTokenRetirement()
	return !retired
}

// staticTokenFingerprint is the configured token's fingerprint, or "" when
// none is configured.
func (s *Server) staticTokenFingerprint() string {
	s.staticTok.fpOnce.Do(func() {
		if s.staticToken != "" {
			s.staticTok.fp = statictoken.Fingerprint(s.staticToken)
		}
	})
	return s.staticTok.fp
}

// checkStaticToken decides whether r carries the static token and whether
// that token is still live. Both forms are read — the Authorization header,
// and ?token= for an EventSource, which cannot set one — and judged alike, so
// a retired token is refused exactly the same way in either.
//
// The comparison with the configured value is constant-time. A value that is
// not it is looked up among the retired fingerprints only when there are any,
// and by its fingerprint: the lookup can reveal nothing about a secret beyond
// whether the caller already holds one that was retired.
func (s *Server) checkStaticToken(r *http.Request) staticTokenVerdict {
	var v staticTokenVerdict
	var values [2]string
	n := 0
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		values[n] = strings.TrimPrefix(auth, "Bearer ")
		n++
	}
	if q := r.URL.Query().Get("token"); q != "" {
		values[n] = q
		n++
	}
	if n == 0 {
		return v
	}
	v.presented = true
	retired, loadErr := s.retiredStaticTokenSet()
	own := s.staticToken
	for _, value := range values[:n] {
		if own != "" && subtle.ConstantTimeCompare([]byte(value), []byte(own)) == 1 {
			switch rec, isRetired := retired[s.staticTokenFingerprint()]; {
			case loadErr != nil:
				v.unverifiable = true
			case isRetired:
				rec := rec
				v.retired = &rec
			default:
				v.admitted = true
			}
			continue
		}
		if len(retired) > 0 {
			if rec, isRetired := retired[statictoken.Fingerprint(value)]; isRetired {
				v.retired = &rec
			}
		}
	}
	if v.admitted {
		v.retired, v.unverifiable = nil, false
	}
	return v
}

// staticTokenRetryAfter is how long a set that has never been read waits after
// a failed read before a request asks again. Meanwhile the static token is
// refused as unverifiable, quickly, rather than each request waiting out the
// database's busy timeout.
const staticTokenRetryAfter = 2 * time.Second

// retiredStaticTokenSet returns the retired set, reading it first if it has
// never been read, and starting a background re-read once the copy in hand is
// older than staticTokenRefreshNS. An error means no copy exists at all.
func (s *Server) retiredStaticTokenSet() (map[string]statedb.RetiredStaticTokenRow, error) {
	if snap := s.staticTok.retired.Load(); snap != nil {
		if time.Since(snap.readAt) > time.Duration(staticTokenRefreshNS.Load()) {
			s.refreshRetiredStaticTokensAsync()
		}
		return snap.byFingerprint, nil
	}
	if at := s.staticTok.failedAt.Load(); at != 0 && time.Since(time.Unix(0, at)) < staticTokenRetryAfter {
		return nil, errors.New("the retired static tokens could not be read")
	}
	if err := s.reloadRetiredStaticTokens(); err != nil {
		return nil, err
	}
	if snap := s.staticTok.retired.Load(); snap != nil {
		return snap.byFingerprint, nil
	}
	return nil, errors.New("the retired static tokens could not be read")
}

// ownStaticTokenRetirement returns the retirement of this hub's own token,
// when it is retired. A set that cannot be read reports it live: this is
// asked of streams the token already opened, which the request path admitted
// only after a read succeeded.
func (s *Server) ownStaticTokenRetirement() (statedb.RetiredStaticTokenRow, bool) {
	fp := s.staticTokenFingerprint()
	if fp == "" {
		return statedb.RetiredStaticTokenRow{}, false
	}
	set, err := s.retiredStaticTokenSet()
	if err != nil {
		return statedb.RetiredStaticTokenRow{}, false
	}
	rec, ok := set[fp]
	return rec, ok
}

// ownStaticTokenRetiredIn reports whether snap retires this hub's own token,
// reading nothing.
func (s *Server) ownStaticTokenRetiredIn(snap *retiredStaticTokens) bool {
	fp := s.staticTokenFingerprint()
	if snap == nil || fp == "" {
		return false
	}
	_, ok := snap.byFingerprint[fp]
	return ok
}

// reloadRetiredStaticTokens reads retired_static_tokens now. A failure keeps
// the copy in hand: a retirement once seen is never forgotten because the
// database was briefly busy.
func (s *Server) reloadRetiredStaticTokens() error {
	asked := time.Now()
	g := &s.staticTok
	g.loadMu.Lock()
	defer g.loadMu.Unlock()
	// Read by somebody else while this caller waited for the lock.
	if snap := g.retired.Load(); snap != nil && !snap.readAt.Before(asked) {
		return nil
	}
	rows, err := s.readRetiredStaticTokens()
	if err != nil {
		now := time.Now()
		g.failedAt.Store(now.UnixNano())
		if last := g.loadWarned.Load(); last == 0 || now.Sub(time.Unix(0, last)) >= staticTokenWarnEvery {
			g.loadWarned.Store(now.UnixNano())
			s.log().Warn(logger.EventAuthz, 0, "static token: read the retired tokens",
				map[string]interface{}{"error": err.Error()})
		}
		return err
	}
	g.failedAt.Store(0)
	set := make(map[string]statedb.RetiredStaticTokenRow, len(rows))
	for _, row := range rows {
		set[row.Fingerprint] = row
	}
	g.retired.Store(&retiredStaticTokens{byFingerprint: set, readAt: time.Now()})
	return nil
}

// refreshRetiredStaticTokensAsync re-reads the set off the request path. One
// at a time; a reader meanwhile answers from the copy in hand.
func (s *Server) refreshRetiredStaticTokensAsync() {
	if !s.staticTok.refreshing.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer s.staticTok.refreshing.Store(false)
		defer recoverGoroutine("static token refresh")
		_ = s.reloadRetiredStaticTokens()
	}()
}

// readRetiredStaticTokens reads the table from the control plane. A hub
// directory with no state database has retired nothing: retirements are
// written into that same file.
func (s *Server) readRetiredStaticTokens() ([]statedb.RetiredStaticTokenRow, error) {
	db, err := s.existingControlPlane()
	if err != nil || db == nil {
		return nil, err
	}
	defer db.Close()
	return db.ListRetiredStaticTokens()
}

// existingControlPlane opens the control-plane database, or returns nil, nil
// when there is none — it never creates one.
func (s *Server) existingControlPlane() (*statedb.DB, error) {
	path := state.DBPath(s.WorkDir)
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat the control-plane database: %w", err)
	}
	db, err := statedb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open the control-plane database: %w", err)
	}
	return db.AsControlPlane(), nil
}

// ── what a request presenting a retired token is told ───────────────────────

// staticTokenRetiredCode marks a 401 for a retired static token, beside the
// error sentence, for a client that acts on it rather than showing it.
const staticTokenRetiredCode = "static_token_retired"

// refuseStaticToken answers a request whose static token is retired, or
// cannot be verified. Neither counts toward the guess lockout.
func (s *Server) refuseStaticToken(w http.ResponseWriter, v staticTokenVerdict, ip string) {
	sso := s.oidcEnabled()
	if sso {
		setSignInHint(w)
	}
	if v.retired == nil {
		jsonErr(w, "the static token cannot be verified right now: this hub could not read which static "+
			"tokens are retired. Try again shortly, or use a scoped API token.", http.StatusServiceUnavailable)
		return
	}
	s.noteStaticTokenRefused(v.retired.Fingerprint, ip)
	at := v.retired.RetiredAt.UTC().Format(time.RFC3339)
	instead := statictoken.Instead(sso)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": fmt.Sprintf("This static token was retired on %s by %s and is no longer accepted. %s",
			at, v.retired.RetiredBy, instead),
		"code":       staticTokenRetiredCode,
		"retired_at": at,
		"retired_by": v.retired.RetiredBy,
		"instead":    instead,
	})
}

// ── last use ────────────────────────────────────────────────────────────────

// noteStaticTokenUse records an admitted request, in memory.
func (s *Server) noteStaticTokenUse(ip string) {
	seen := staticTokenSeen{at: time.Now(), ip: ip}
	g := &s.staticTok
	g.useMu.Lock()
	g.pending, g.latest = seen, seen
	g.useMu.Unlock()
}

// staticTokenWarnEvery bounds the log line a retired token's refusal writes,
// per fingerprint: a client retrying in a loop must not fill the log, and the
// count is flushed either way.
const staticTokenWarnEvery = time.Minute

// noteStaticTokenRefused records a request refused because the token with
// fingerprint fp is retired, in memory, and says so in the log at most once a
// minute per token. After a suspected leak, who is still presenting it is the
// question.
func (s *Server) noteStaticTokenRefused(fp, ip string) {
	now := time.Now()
	g := &s.staticTok
	g.useMu.Lock()
	if g.refused == nil {
		g.refused = map[string]*staticTokenRefusals{}
	}
	r := g.refused[fp]
	if r == nil {
		r = &staticTokenRefusals{}
		g.refused[fp] = r
	}
	r.n++
	r.last = staticTokenSeen{at: now, ip: ip}
	if g.warnedAt == nil {
		g.warnedAt = map[string]time.Time{}
	}
	warn := now.Sub(g.warnedAt[fp]) >= staticTokenWarnEvery
	if warn {
		g.warnedAt[fp] = now
	}
	g.useMu.Unlock()
	if warn {
		s.log().Warn(logger.EventAuthz, 0, "refused a retired static token",
			map[string]interface{}{"fingerprint": statictoken.Short(fp), "ip": ip})
	}
}

// latestStaticTokenUse is the latest admitted use this process saw.
func (s *Server) latestStaticTokenUse() staticTokenSeen {
	g := &s.staticTok
	g.useMu.Lock()
	defer g.useMu.Unlock()
	return g.latest
}

// flushStaticTokenUse writes what this process saw since its last flush to
// static_token_use: that it holds its token, the latest use, and the
// refusals. What could not be written is kept for the next flush.
func (s *Server) flushStaticTokenUse(now time.Time) error {
	g := &s.staticTok
	g.useMu.Lock()
	used, refused := g.pending, g.refused
	g.pending, g.refused = staticTokenSeen{}, nil
	g.useMu.Unlock()

	own := s.staticTokenFingerprint()
	byFP := map[string]*statedb.StaticTokenUseReport{}
	report := func(fp string) *statedb.StaticTokenUseReport {
		if rep := byFP[fp]; rep != nil {
			return rep
		}
		rep := &statedb.StaticTokenUseReport{Fingerprint: fp, At: now}
		byFP[fp] = rep
		return rep
	}
	if own != "" {
		rep := report(own)
		rep.Held, rep.HeldBy, rep.SSO = true, s.hubInstanceID(), s.oidcEnabled()
		rep.UsedAt, rep.UsedIP = used.at, used.ip
	}
	for fp, r := range refused {
		rep := report(fp)
		rep.Refused, rep.RefusedAt, rep.RefusedIP = r.n, r.last.at, r.last.ip
	}
	if len(byFP) == 0 {
		return nil
	}
	reports := make([]statedb.StaticTokenUseReport, 0, len(byFP))
	for _, rep := range byFP {
		reports = append(reports, *rep)
	}

	db, err := s.existingControlPlane()
	if err == nil && db != nil {
		err = db.ReportStaticTokenUse(reports)
		db.Close()
	}
	if err != nil {
		// Put it back, merged with whatever arrived meanwhile.
		g.useMu.Lock()
		if g.pending.at.IsZero() {
			g.pending = used
		}
		if len(refused) > 0 {
			if g.refused == nil {
				g.refused = map[string]*staticTokenRefusals{}
			}
			for fp, r := range refused {
				cur := g.refused[fp]
				if cur == nil {
					g.refused[fp] = r
					continue
				}
				cur.n += r.n
				if r.last.at.After(cur.last.at) {
					cur.last = r.last
				}
			}
		}
		g.useMu.Unlock()
		return err
	}
	return nil
}

// ── the member's own loop ───────────────────────────────────────────────────

// startStaticTokenGuard reads the retired set before the hub serves, says so
// when its own token is retired, reports that it holds the token, and keeps
// both current every ReportInterval while ctx lives. A hub with no static
// token has nothing to report; it reads the set when a request needs it.
func (s *Server) startStaticTokenGuard(ctxDone <-chan struct{}) {
	if !s.staticTokenConfigured() {
		return
	}
	if err := s.reloadRetiredStaticTokens(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not read the retired static tokens (%v) — the static token is "+
			"refused until they can be read\n", err)
	} else if rec, retired := s.ownStaticTokenRetirement(); retired {
		fmt.Fprintf(os.Stderr, "warning: the static token this hub was given (fingerprint %s) was retired on %s by %s "+
			"and is refused. Deploy a new value or remove --token / CLOOP_UI_TOKEN.\n",
			statictoken.Short(rec.Fingerprint), rec.RetiredAt.UTC().Format(time.RFC3339), rec.RetiredBy)
	}
	if err := s.flushStaticTokenUse(time.Now()); err != nil {
		s.log().Warn(logger.EventAuthz, 0, "static token: report use", map[string]interface{}{"error": err.Error()})
	}
	go s.watchStaticToken(ctxDone)
}

// watchStaticToken re-reads the retired set and flushes the last use every
// ReportInterval. A retirement it finds that nothing announced to this member
// ends the streams the token opened here at once, rather than at each
// stream's own keepalive.
func (s *Server) watchStaticToken(done <-chan struct{}) {
	defer recoverGoroutine("static token watcher")
	t := time.NewTicker(statictoken.ReportInterval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			wasRetired := s.ownStaticTokenRetiredIn(s.staticTok.retired.Load())
			if err := s.reloadRetiredStaticTokens(); err == nil {
				if s.ownStaticTokenRetiredIn(s.staticTok.retired.Load()) && !wasRetired {
					s.recheckStaticTokenStreams()
				}
			}
			if err := s.flushStaticTokenUse(time.Now()); err != nil {
				s.log().Warn(logger.EventAuthz, 0, "static token: report use",
					map[string]interface{}{"error": err.Error()})
			}
		}
	}
}

// ── a retirement made elsewhere ─────────────────────────────────────────────

// onStaticTokenRetired is the bus notice another member, or the CLI, posts
// after retiring a static token: re-read the set now, then end what a retired
// token opened here.
func (s *Server) onStaticTokenRetired() {
	_ = s.reloadRetiredStaticTokens()
	s.recheckStaticTokenStreams()
}

// AnnounceStaticTokenRetired posts the bus notice a hub member publishes after
// retiring a static token, for a writer that is not a member: `cloop hub token
// static retire`. Every member reading the bus re-reads the retired set and
// closes the streams and terminals the token opened there within its poll
// interval. A failure is the caller's to report, never fatal to the
// retirement, which has already happened: a member that misses the notice
// refuses the token at its next re-read, within ReportInterval.
func AnnounceStaticTokenRetired(db *statedb.DB, origin, fingerprint string) error {
	return appendInvalidations(db, origin, invalidateStaticToken,
		[]any{map[string]string{"fingerprint": fingerprint}})
}
