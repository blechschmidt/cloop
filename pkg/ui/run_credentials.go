package ui

// run_credentials.go: a run's credentials open its run's routes and no other
// (Task 20499).
//
// Every credential the hub mints for a run — and the two it mints for an
// executor pool — is good at one entry point: a knowledge session token at the
// run-scoped knowledge search, a model relay token at the relay, a git proxy
// session at the git proxy, and so on (docs/security/model.md, "What a run's
// credentials reach"). Each of those authenticates the credential itself and
// reads the run's project off it. None of them is a credential of the
// dashboard, so authMiddleware never admitted one; but it answered one the way
// it answers a mistyped password — 401, counted toward the address's lockout,
// recorded nowhere — or, on a hub without sign-in, served the request as if
// the credential were not there.
//
// A run presenting its credential to the dashboard is a run asking for
// something its credential was never for: a sandboxed agent probing the hub's
// API with the token it was given, most likely. So it is refused for what it
// is: 403, saying which credential it was and what it opens, before anything
// else reads the request — the same answer on a hub with single sign-on, one
// with a static token and one with neither — and recorded as
// run.credential_refused, with the run and project the credential belongs to
// when it is a live one the hub can name.
//
// Recognised by shape, the documented prefixes in docs/reference/
// credential-patterns.md: a value that merely looks like one is refused the
// same way, which tells its sender nothing about whether a real one exists,
// and could never have been admitted anyway.

import (
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/claudeproxy"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/knowledgerun"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// runCredentialKind is one kind of credential the hub mints for a run or a
// pool, which opens one entry point of the hub and no dashboard route.
type runCredentialKind struct {
	// name is the kind as the audit trail names it.
	name string
	// prefix is how a presented value is recognised.
	prefix string
	// label says what it is, for the refusal.
	label string
	// opens is the one place it is accepted.
	opens string
	// session is the proxy_sessions kind a live one is recorded under, ""
	// when it is not recorded there or names no session in its value.
	session string
	// sessionID returns the session id a value names, "" for none.
	sessionID func(token string) string
}

// runCredentialKinds is every kind. tests/arch/runcredentials_test.go keeps it
// in step with the entry points that authenticate them.
var runCredentialKinds = []runCredentialKind{
	{
		name: "knowledge_session", prefix: knowledgerun.TokenPrefix,
		label:   "a run's knowledge session token",
		opens:   "the run-scoped knowledge search under " + knowledgerun.MountPath,
		session: statedb.ProxySessionKnowledge, sessionID: idAfterPrefix(knowledgerun.TokenPrefix),
	},
	{
		name: "model_relay_session", prefix: redact.RelayTokenPrefix,
		label:   "a sandboxed run's model relay token",
		opens:   "the model relay under " + modelRelayMount,
		session: statedb.ProxySessionModel, sessionID: idAfterPrefix(redact.RelayTokenPrefix),
	},
	{
		name: "ci_relay_session", prefix: claudeproxy.TokenPrefix,
		label: "a CI job's relay session token",
		opens: "the CI relay under /api/ci/anthropic/",
	},
	{
		name: "git_proxy_session", prefix: redact.GitProxyTokenPrefix,
		label: "a run's git proxy session password",
		opens: "the hub's git proxy",
	},
	{
		name: "kube_guard_session", prefix: redact.KubeGuardTokenPrefix,
		label:   "a run's Kubernetes access monitor token",
		opens:   "the hub's Kubernetes access monitor",
		session: statedb.ProxySessionKube, sessionID: idWithPrefix(redact.KubeGuardTokenPrefix),
	},
	{
		name: "egress_session", prefix: redact.EgressTokenPrefix,
		label: "a run's egress proxy password",
		opens: "the hub's egress proxy",
	},
	{
		name: "pool_controller", prefix: executorpool.CredentialPrefix,
		label: "an executor pool controller's credential",
		opens: "the executor pool controller's routes under /api/pool-controller/",
	},
	{
		name: "runner_token", prefix: remote.RunnerTokenMarker,
		label: "an executor pool runner's enrollment token",
		opens: executorConnectPath,
	},
	{
		name: "runner_credential", prefix: remote.RunnerCredentialMarker,
		label: "an executor pool runner's credential",
		opens: executorConnectPath,
	},
}

// idAfterPrefix reads <prefix><id>.<secret>: the id, without the prefix.
func idAfterPrefix(prefix string) func(string) string {
	return func(token string) string {
		rest, ok := strings.CutPrefix(token, prefix)
		if !ok {
			return ""
		}
		id, secret, ok := strings.Cut(rest, ".")
		if !ok || id == "" || secret == "" || len(id) > 128 {
			return ""
		}
		return id
	}
}

// idWithPrefix reads <prefix><raw>.<secret> whose session id is
// <prefix><raw>, as the Kubernetes monitor's is (Task 20454).
func idWithPrefix(prefix string) func(string) string {
	after := idAfterPrefix(prefix)
	return func(token string) string {
		if id := after(token); id != "" {
			return prefix + id
		}
		return ""
	}
}

// presentedRunCredential is a run credential a request carries, by kind, with
// the value it carried.
type presentedRunCredential struct {
	kind  runCredentialKind
	value string
	// via says where in the request it was: authorization, x-api-key,
	// proxy-authorization or query.
	via string
}

// runCredentialIn returns the run credential r presents, if any: as a bearer
// token or under any other scheme, either half of a basic credential (the git
// proxy's and the egress proxy's form), an X-Api-Key (an Anthropic client's
// form), a Proxy-Authorization, or the ?token= an EventSource sends the
// dashboard's static token in — in any of a header's values.
func runCredentialIn(r *http.Request) (presentedRunCredential, bool) {
	check := func(value, via string) (presentedRunCredential, bool) {
		value = strings.TrimSpace(value)
		if value == "" {
			return presentedRunCredential{}, false
		}
		for _, k := range runCredentialKinds {
			if strings.HasPrefix(value, k.prefix) {
				return presentedRunCredential{kind: k, value: value, via: via}, true
			}
		}
		return presentedRunCredential{}, false
	}
	fromAuthorization := func(header, via string) (presentedRunCredential, bool) {
		fields := strings.Fields(header)
		if len(fields) == 0 {
			return presentedRunCredential{}, false
		}
		if len(fields) == 2 && strings.EqualFold(fields[0], "basic") {
			for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
				if raw, err := enc.DecodeString(fields[1]); err == nil {
					user, pass, _ := strings.Cut(string(raw), ":")
					if c, ok := check(pass, via); ok {
						return c, true
					}
					if c, ok := check(user, via); ok {
						return c, true
					}
				}
			}
		}
		// Whatever the scheme, or none: a credential is a credential.
		for _, f := range fields {
			if c, ok := check(f, via); ok {
				return c, true
			}
		}
		return presentedRunCredential{}, false
	}
	for _, h := range []struct{ name, via string }{
		{"Authorization", "authorization"}, {"Proxy-Authorization", "proxy-authorization"},
	} {
		for _, v := range r.Header.Values(h.name) {
			if c, ok := fromAuthorization(v, h.via); ok {
				return c, true
			}
		}
	}
	for _, v := range r.Header.Values("X-Api-Key") {
		if c, ok := check(v, "x-api-key"); ok {
			return c, true
		}
	}
	for _, v := range r.URL.Query()["token"] {
		if c, ok := check(v, "query"); ok {
			return c, true
		}
	}
	return presentedRunCredential{}, false
}

// refuseRunCredential answers a dashboard request that presented a run
// credential: 403, saying what the credential is and where it is good, and a
// run.credential_refused row.
func (s *Server) refuseRunCredential(w http.ResponseWriter, r *http.Request, c presentedRunCredential) {
	s.recordRunCredentialRefusal(r, c)
	apierror.WriteError(w, apierror.Newf(apierror.CodeForbidden,
		"refused: this request carries %s, which the hub minted to open %s and nothing else. No route of the "+
			"dashboard's API takes it, whatever project the request names.", c.kind.label, c.kind.opens).
		WithDetails(map[string]any{"reason": "run_credential", "credential": c.kind.name}))
}

// Bounds on the rows refusals write. A run that probes the dashboard's API
// with its credential would otherwise turn every request into a write. Each
// credential gets a burst and a steady rate of its own, and a hub process a
// ceiling a minute — one for refusals of a live session the hub recorded and a
// smaller one for every other value, so values made up to look like a
// credential cannot spend what a real run's refusals are written from. A
// refusal past a bound is counted, and the next row written for that
// credential says how many were not; refusals of credentials the limiter had
// no room to track are counted for the next row written at all.
var (
	runCredentialAuditBurst          = 64.0
	runCredentialAuditPerSecond      = 1.0
	runCredentialAuditPerMinute      = 600
	runCredentialUnverifiedPerMinute = 120
	// runCredentialTracked bounds how many credentials the limiter keeps a
	// bucket for; past it, a credential it has no bucket for is counted, not
	// written.
	runCredentialTracked = 4096
)

// runCredentialAuditLimiter is the rate at which refusals are recorded.
var runCredentialAuditLimiter = struct {
	mu         sync.Mutex
	buckets    map[string]*runCredentialBucket
	window     time.Time
	verified   int // rows written this window for live sessions
	unverified int // and for every other value
	// untracked counts refusals of credentials no bucket could be kept for.
	untracked int
}{buckets: map[string]*runCredentialBucket{}}

type runCredentialBucket struct {
	tokens     float64
	last       time.Time
	suppressed int
}

// takeRunCredentialToken takes a refusal of the credential keyed key from its
// own bucket. It reports false — and counts the refusal — when the bucket is
// spent, and tracked false when the limiter has no room for a new bucket: such
// a refusal is written only if it turns out to be a live session's, from that
// budget, so a table filled with made-up values cannot lock a real run's
// refusals out.
func takeRunCredentialToken(key string, now time.Time) (ok, tracked bool) {
	l := &runCredentialAuditLimiter
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= runCredentialTracked {
			for k, old := range l.buckets {
				if now.Sub(old.last) > time.Minute {
					l.untracked += old.suppressed
					delete(l.buckets, k)
				}
			}
		}
		if len(l.buckets) >= runCredentialTracked {
			return true, false
		}
		b = &runCredentialBucket{tokens: runCredentialAuditBurst, last: now}
		l.buckets[key] = b
	}
	b.tokens = min(runCredentialAuditBurst, b.tokens+now.Sub(b.last).Seconds()*runCredentialAuditPerSecond)
	b.last = now
	if b.tokens < 1 {
		b.suppressed++
		return false, true
	}
	b.tokens--
	return true, true
}

// countUntracked counts a refusal that is not written and has no bucket to
// be counted in.
func countUntracked() {
	l := &runCredentialAuditLimiter
	l.mu.Lock()
	l.untracked++
	l.mu.Unlock()
}

// admitRunCredentialRow reports whether a refusal of the credential keyed key
// may be written now — within this minute's ceiling for its kind, verified or
// not — with how many of its refusals, and of untracked credentials, were not
// written since the last row that said so.
func admitRunCredentialRow(key string, verified bool, now time.Time) (ok bool, suppressed, untracked int) {
	l := &runCredentialAuditLimiter
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.window) >= time.Minute || now.Before(l.window) {
		l.window, l.verified, l.unverified = now, 0, 0
	}
	b := l.buckets[key]
	if verified && l.verified >= runCredentialAuditPerMinute || !verified && l.unverified >= runCredentialUnverifiedPerMinute {
		if b != nil {
			b.suppressed++
		} else {
			l.untracked++
		}
		return false, 0, 0
	}
	if verified {
		l.verified++
	} else {
		l.unverified++
	}
	if b != nil {
		suppressed, b.suppressed = b.suppressed, 0
	}
	untracked, l.untracked = l.untracked, 0
	return true, suppressed, untracked
}

// recordRunCredentialRefusal writes the refusal to the control plane's audit
// trail, naming the run and project the credential belongs to when it is a
// live session the hub recorded. The value is never written: the session id
// a value names is public, its secret half is not.
func (s *Server) recordRunCredentialRefusal(r *http.Request, c presentedRunCredential) {
	id := ""
	if c.kind.sessionID != nil {
		id = c.kind.sessionID(c.value)
	}
	// One credential is one bucket: a value naming no session is keyed by
	// its hash.
	key := c.kind.name + "|" + id
	if id == "" {
		key = c.kind.name + "|" + tokenSHA256(c.value)
	}
	now := time.Now()
	ok, tracked := takeRunCredentialToken(key, now)
	if !ok {
		return
	}
	if !tracked && (c.kind.session == "" || id == "") {
		// No bucket, and nothing the hub could verify it as: counted.
		countUntracked()
		return
	}
	// The hub's own database only, and only when it exists, as for every
	// refusal recorded before authentication (recordRefusal).
	if strings.TrimSpace(s.WorkDir) == "" {
		return
	}
	if _, err := os.Stat(state.DBPath(s.WorkDir)); err != nil {
		return
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		s.log().Warn(logger.EventAuthz, 0, "run credential refusal audit: open control plane",
			map[string]interface{}{"error": err.Error()})
		return
	}
	defer db.Close()
	row, live := liveRunSession(db, c, id)
	if !tracked && !live {
		countUntracked()
		return
	}
	ok, suppressed, untracked := admitRunCredentialRow(key, live, now)
	if !ok {
		return
	}
	payload := map[string]any{
		"kind":   c.kind.name,
		"via":    c.via,
		"method": r.Method,
		"path":   truncate(r.URL.Path, 512),
		"ip":     s.clientIP(r),
		"opens":  c.kind.opens,
	}
	if id != "" {
		payload["session_id"] = id
	}
	if v := strings.TrimSpace(r.URL.Query().Get("project_idx")); v != "" {
		payload["project_idx"] = truncate(v, 32)
	}
	if ua := r.UserAgent(); ua != "" {
		payload["user_agent"] = truncate(ua, 256)
	}
	if suppressed > 0 {
		payload["suppressed"] = suppressed
	}
	if untracked > 0 {
		payload["untracked"] = untracked
	}
	actor := "run credential " + c.kind.name
	if live {
		payload["verified"] = true
		payload["project"] = row.ProjectID
		if row.RunID != "" {
			payload["run_id"] = row.RunID
		}
		if row.ExecutorID != "" {
			payload["executor_id"] = row.ExecutorID
		}
		actor = runKnowledgeActor(row)
	}
	s.log().Warn(logger.EventAuthz, 0, "refused a run's credential presented to the dashboard's API",
		map[string]interface{}{"credential": c.kind.name, "method": r.Method, "path": r.URL.Path,
			"ip": payload["ip"], "verified": live})
	if err := db.AppendAuditEvent(&statedb.AuditEvent{
		Actor:      actor,
		EventType:  string(auditaction.ActionRunCredentialRefused),
		EntityType: "request",
		EntityID:   r.Method + " " + truncate(r.URL.Path, 200),
		Payload:    statedb.MarshalAuditPayload(payload),
	}); err != nil {
		s.log().Warn(logger.EventAuthz, 0, "run credential refusal audit: append",
			map[string]interface{}{"error": err.Error()})
		return
	}
	s.broadcastAuditAppend(string(auditaction.ActionRunCredentialRefused))
}

// liveRunSession returns the recorded session a presented credential is, when
// it is one: open, unexpired, and the value's hash the one recorded. Only then
// does a refusal name a run and a project, so a made-up value naming a real
// session's id cannot put a refusal on that run's account.
func liveRunSession(db *statedb.DB, c presentedRunCredential, id string) (statedb.ProxySessionRow, bool) {
	if c.kind.session == "" || id == "" {
		return statedb.ProxySessionRow{}, false
	}
	row, err := db.GetProxySession(c.kind.session, id)
	if err != nil {
		return statedb.ProxySessionRow{}, false
	}
	if subtle.ConstantTimeCompare([]byte(tokenSHA256(c.value)), []byte(row.TokenSHA256)) != 1 ||
		!row.Open() || !time.Now().Before(row.ExpiresAt) {
		return statedb.ProxySessionRow{}, false
	}
	return row, true
}
