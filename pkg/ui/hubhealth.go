package ui

// hubhealth.go is Settings → Hub health (Task 20434): the hub doctor's checks,
// run by the hub on itself.
//
// pkg/hubdoctor holds some eighty checks of a hosted control plane — a hub CA
// nearing expiry, audit forwarding falling behind, edge devices lagging, an API
// token waiting for approval — and until this file they ran only as `cloop hub
// doctor`, in a shell on the hub host, in the hub's directory, with both of its
// configuration files in reach. An administrator of a Helm or compose
// deployment, or one without a shell there, never saw them, and nothing told
// anybody when one started failing.
//
// GET /api/hub/health runs them in this process instead (hubdoctor.Live):
// against this hub's directory and the configuration it runs under, overlay
// included, with this hub's port — the listener checks are about the process
// that answers, which is why the report names the cluster member it came from.
// What a run must not do inside a serving hub is hubdoctor's to keep out — no
// step that starts a workload, each step bounded and its panic recovered — and
// this file's to answer for it where the shell's doctor would ask from
// outside (hubHealthSelf): how the listener admits requests, the KMS clients
// the hub pinned, what its executor supervisor last recorded.
//
// A report is computed at most once at a time and served for hubHealthTTL, or
// until the configuration files change, whichever comes first; the heaviest
// checks are made less often still (hubdoctor's liveEvery). The dashboard asks
// again when the hub says the report changed (the hub_health broadcast, which
// carries nothing), on reconnect, and when the report it last saw expires by
// the hub's clock — no timer of its own beyond that and a retry after a
// failed read.
//
// Everything a check wrote passes through two redactions before it leaves:
// the exact credential values this hub's configuration and environment hold,
// and pkg/redact's registry of credential shapes — a password in an issuer's
// URL, a token in an error string from three packages down. The page renders
// what is left as text.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/hubdoctor"
	"github.com/blechschmidt/cloop/pkg/kms"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/rootkey"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

const (
	// hubHealthTTL is how long a report is served before the next request
	// computes another. Long enough that a dashboard left open costs the hub
	// one run a minute, short enough that a certificate expiring or a disk
	// filling shows within one.
	hubHealthTTL = time.Minute

	// hubHealthRerunFloor is how fresh a report may be before "Run the checks
	// again" is answered from it rather than with a new run: the button
	// dials whatever the checks dial, and pressing it twice is not a reason
	// to do that twice.
	hubHealthRerunFloor = 10 * time.Second

	// hubHealthProbeTimeout bounds each network probe a check makes. Half the
	// CLI's default: a dashboard's report should come back in seconds, and a
	// check that needs longer to reach its issuer has found something to say.
	hubHealthProbeTimeout = 5 * time.Second

	// hubHealthWatchEvery is how often the hub looks at its configuration
	// files' size and modification time, to tell dashboards a report no longer
	// describes them.
	hubHealthWatchEvery = 3 * time.Second

	// hubHealthDocsBase is the runbook page that explains each group of
	// checks, on the published documentation site.
	hubHealthDocsBase = "https://blechschmidt.github.io/cloop/docs/operations/runbook/"
)

// hubHealthState is one process's report cache. The zero value is ready.
type hubHealthState struct {
	live hubdoctor.Live

	mu sync.Mutex
	// report is the last one computed, and print the fingerprint of the
	// configuration files it was computed under.
	report *hubHealthReport
	print  string
	// summary says what the last report found, to tell whether the next one
	// changed anything a dashboard shows.
	summary string
	// nudged is the configuration fingerprint dashboards were last told about.
	nudged string
	// inflight is the run under way, which concurrent requests wait for.
	inflight *hubHealthCall

	// Test knobs, set before the server starts: the per-check deadline, the
	// cache's lifetime and checks added to the hub's own.
	checkTimeout time.Duration
	ttl          time.Duration
	extra        []hubdoctor.Check
}

// hubHealthCall is one run that requests wait on.
type hubHealthCall struct {
	done   chan struct{}
	report *hubHealthReport
}

// hubHealthReport is the response of GET /api/hub/health.
type hubHealthReport struct {
	// Member is the hub process that ran the checks.
	Member    hubHealthMember `json:"member"`
	CheckedAt time.Time       `json:"checked_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	// ServedAt is when this response left the hub, so a page times the
	// report's expiry by the hub's clock rather than its own.
	ServedAt   time.Time `json:"served_at"`
	DurationMS int64     `json:"duration_ms"`
	// Config names the files the configuration was read from.
	Config     hubHealthConfig `json:"config"`
	StrictMode bool            `json:"strict_mode"`
	Counts     hubHealthCounts `json:"counts"`
	// Failing is the number of failed checks: what the header shows.
	Failing  int                    `json:"failing"`
	Findings []hubHealthFinding     `json:"findings,omitempty"`
	Steps    []hubdoctor.StepResult `json:"steps,omitempty"`
	// NotRun is what the dashboard leaves to `cloop hub doctor` on the host.
	NotRun []hubHealthNotRun `json:"not_run,omitempty"`
}

type hubHealthMember struct {
	ID        string `json:"id"`
	Hostname  string `json:"hostname,omitempty"`
	Port      int    `json:"port,omitempty"`
	Clustered bool   `json:"clustered"`
	Leader    bool   `json:"leader"`
}

type hubHealthConfig struct {
	Files []string `json:"files"`
	// Error is why the configuration could not be loaded, when it could not.
	Error string `json:"error,omitempty"`
}

type hubHealthCounts struct {
	Pass int `json:"pass"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
}

// hubHealthFinding is a hubdoctor.Finding as it leaves the hub: redacted, and
// with the documentation anchor of its group.
type hubHealthFinding struct {
	Check       string         `json:"check"`
	Title       string         `json:"title"`
	Severity    string         `json:"severity"`
	Message     string         `json:"message"`
	Remediation string         `json:"remediation,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
	Docs        string         `json:"docs"`
	// AsOf is when a check made less often than reports are last ran; zero
	// is now.
	AsOf time.Time `json:"as_of,omitzero"`
}

type hubHealthNotRun struct {
	Check   string `json:"check"`
	Why     string `json:"why"`
	Command string `json:"command"`
}

// hubHealthRoutes is the report's route.
func (s *Server) hubHealthRoutes() []routeSpec {
	return []routeSpec{
		// config.write at global scope, as the hub-wide Settings around it
		// are: a report spells out the configuration's weak points, and the
		// people who need it are the ones who may change it. Through the
		// route gate, so authz.Enforced decides what the permission means.
		{Pattern: "GET /api/hub/health", Handler: s.handleHubHealth, Perm: authz.PermConfigWrite, Scope: scopeGlobal},
	}
}

// handleHubHealth answers with this member's report: the cached one while it
// is fresh, otherwise a new run. ?summary=1 leaves the findings out — what
// the header needs — and ?fresh=1 asks for a new run unless the cached one is
// seconds old.
//
// GET /api/hub/health
func (s *Server) handleHubHealth(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	out := *s.hubHealthReport(q.Get("fresh") == "1")
	out.ServedAt = time.Now().UTC()
	if q.Get("summary") == "1" {
		out.Findings, out.Steps, out.NotRun = nil, nil, nil
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonOK(w, &out)
}

// hubHealthReport returns a report no older than the cache allows, computing
// one if needed. One run at a time: a request that arrives during one waits
// for it rather than starting another.
func (s *Server) hubHealthReport(fresh bool) *hubHealthReport {
	h := &s.hubHealth
	fp := s.hubConfigFingerprint()
	for {
		h.mu.Lock()
		if rep := h.report; rep != nil && h.print == fp {
			now := time.Now()
			if now.Before(rep.ExpiresAt) && !(fresh && now.Sub(rep.CheckedAt) >= hubHealthRerunFloor) {
				h.mu.Unlock()
				return rep
			}
		}
		if c := h.inflight; c != nil {
			h.mu.Unlock()
			<-c.done
			if c.report != nil {
				return c.report
			}
			continue // that run died; this request makes the next one
		}
		c := &hubHealthCall{done: make(chan struct{})}
		h.inflight = c
		h.mu.Unlock()
		return s.runHubHealth(c, fp, fresh)
	}
}

// runHubHealth makes one run and publishes it to the cache, telling
// dashboards when it found something the last one did not.
func (s *Server) runHubHealth(c *hubHealthCall, fp string, fresh bool) (rep *hubHealthReport) {
	h := &s.hubHealth
	defer func() {
		h.mu.Lock()
		h.inflight = nil
		changed := false
		if rep != nil {
			sum := hubHealthSummary(rep)
			changed = h.report != nil && sum != h.summary
			h.report, h.print, h.summary = rep, fp, sum
			if h.nudged == "" {
				h.nudged = fp
			}
		}
		h.mu.Unlock()
		c.report = rep
		close(c.done)
		if changed {
			// Carries nothing: who may see a report is decided where it is
			// read. Every member's dashboards, since a load balancer may send
			// any of them here for the next read.
			s.broadcastToAll(wsMessage{Type: "hub_health", Data: json.RawMessage(`{}`)})
		}
	}()

	start := time.Now()
	cfg, cfgErr := s.loadHubConfig()
	files := []string{config.ConfigPath(s.WorkDir)}
	if overlay := s.hubConfigOverlay(); overlay != "" {
		files = append(files, overlay)
	}
	scrub := hubHealthScrub{set: redact.New(hubSecretValues(cfg, files, os.Environ())...)}
	lr := h.live.Run(context.Background(), s.WorkDir, cfg, hubdoctor.LiveOptions{
		Options: hubdoctor.Options{
			Timeout: hubHealthProbeTimeout,
			Port:    s.Port,
			Self:    s.hubHealthSelf(),
		},
		CheckTimeout: h.checkTimeout,
		Extra:        h.extra,
		Generation:   fp,
		Fresh:        fresh,
		OnPanic: func(step string, v any, stack []byte) {
			s.log().Error(logger.EventHealthCheck, 0, "a hub health check panicked", map[string]interface{}{
				"step": step, "panic": scrub.text(fmt.Sprint(v)), "stack": scrub.text(string(stack)),
			})
		},
	})
	ttl := h.ttl
	if ttl <= 0 {
		ttl = hubHealthTTL
	}
	end := time.Now()
	// Built aside and published whole: a report that failed half-way must
	// not be cached as though it were one.
	out := &hubHealthReport{
		Member:     s.hubHealthMember(),
		CheckedAt:  start.UTC(),
		ExpiresAt:  end.Add(ttl).UTC(),
		DurationMS: end.Sub(start).Milliseconds(),
		Config:     hubHealthConfig{Files: s.hubConfigFiles()},
		StrictMode: lr.StrictMode,
	}
	if cfgErr != nil {
		// Scrubbed whole, then cut: cut first, a credential across the cut
		// would leave its first half behind.
		out.Config.Error = truncateRunes(scrub.text(cfgErr.Error()), 400)
	}
	for _, f := range lr.Findings {
		hf := hubHealthFinding{
			Check:       hubHealthCheckID(f.Check),
			Title:       scrub.text(f.Title),
			Severity:    string(f.Severity),
			Message:     scrub.text(f.Message),
			Remediation: scrub.text(f.Remediation),
			Details:     scrub.details(f.Details),
			AsOf:        f.AsOf,
		}
		hf.Docs = hubHealthDocsURL(hf.Check)
		switch f.Severity {
		case hubdoctor.SeverityFail:
			out.Counts.Fail++
		case hubdoctor.SeverityWarn:
			out.Counts.Warn++
		default:
			hf.Severity = string(hubdoctor.SeverityPass)
			out.Counts.Pass++
		}
		out.Findings = append(out.Findings, hf)
	}
	out.Failing = out.Counts.Fail
	for _, st := range lr.Steps {
		st.Title, st.Panic = scrub.text(st.Title), scrub.text(st.Panic)
		st.ID = hubHealthCheckID(st.ID)
		out.Steps = append(out.Steps, st)
	}
	for _, n := range lr.NotRun {
		out.NotRun = append(out.NotRun, hubHealthNotRun{Check: n.Check, Why: n.Why,
			Command: fmt.Sprintf("cloop hub doctor %s --port %d", n.Flag, s.Port)})
	}
	return out
}

// hubHealthSelf is what this process knows about itself that the doctor would
// otherwise ask from outside: how its listener admits a request, the KMS
// roots it pinned, and what its supervisor last saw of each executor.
func (s *Server) hubHealthSelf() *hubdoctor.Self {
	return &hubdoctor.Self{
		SSO:         s.OIDC != nil,
		StaticToken: s.staticTokenConfigured(),
		TLS:         strings.TrimSpace(s.TLSCertFile) != "",
		KMS:         s.hubKMSRoots,
		Probe:       s.hubHealthProbe(s.recordedExecutorHealth()),
	}
}

// hubKMSRoots are the roots `cloop ui` resolved and pinned for every keyring
// this process opens, with the providers it handed the server.
func (s *Server) hubKMSRoots() (kms.Roots, bool) {
	cur, prev, ok := secretbroker.PinnedRoots()
	if !ok {
		return kms.Roots{}, false
	}
	roots := kms.Roots{Current: cur, Previous: prev}
	if s.kms != nil {
		roots.Providers = append(roots.Providers, s.kms.providers...)
	}
	return roots, true
}

// recordedExecutorHealth is the executor supervisor's last word on each
// executor, by id: one read per report, of rows every member shares.
func (s *Server) recordedExecutorHealth() map[string]executor.Health {
	db, closeDB, err := s.openControlPlaneDB()
	if err != nil {
		return nil
	}
	defer closeDB()
	sched, err := executorstore.NewScheduler(db)
	if err != nil {
		return nil
	}
	hs, err := sched.ListHealth()
	if err != nil {
		return nil
	}
	out := make(map[string]executor.Health, len(hs))
	for _, h := range hs {
		out[h.ExecutorID] = h
	}
	return out
}

// hubHealthProbe answers the doctor's liveness question for one executor
// without probing it again: from the supervisor's record (the member that
// probes each executor is the one that should, and every member reads the
// same row), or — for a device another member holds and the supervisor has
// not recorded — from the cluster's ownership. Only an executor nobody has
// probed yet is asked, once.
func (s *Server) hubHealthProbe(recorded map[string]executor.Health) func(context.Context, executor.Executor) (string, error) {
	return func(ctx context.Context, ex executor.Executor) (string, error) {
		if h, ok := recorded[ex.ID()]; ok && !h.LastProbe.IsZero() {
			source := "as the hub's supervisor last probed it, at " + h.LastProbe.UTC().Format(time.RFC3339)
			if h.ConsecutiveFailures > 0 || h.State == executor.NodeUnreachable {
				reason := strings.TrimSpace(h.Reason)
				if reason == "" {
					reason = fmt.Sprintf("%d consecutive failed probe(s)", h.ConsecutiveFailures)
				}
				return source, errors.New(reason)
			}
			return source, nil
		}
		if member, held := s.agentHeldByPeer(ex); held {
			return "connected to hub member " + member, nil
		}
		return "probed now: the hub's supervisor has not recorded it yet", ex.HealthCheck(ctx)
	}
}

// hubHealthSummary is what a dashboard shows of a report: each check that did
// not pass, by severity and title. A new report with the same summary changed
// nothing worth telling anyone about.
func hubHealthSummary(rep *hubHealthReport) string {
	var b strings.Builder
	for _, f := range rep.Findings {
		if f.Severity != string(hubdoctor.SeverityPass) {
			fmt.Fprintf(&b, "%s\x00%s\x00%s\n", f.Severity, f.Check, f.Title)
		}
	}
	return b.String()
}

// hubHealthMember names this process among the hub's members.
func (s *Server) hubHealthMember() hubHealthMember {
	m := hubHealthMember{ID: s.hubInstanceID(), Port: s.Port, Leader: s.isLeader()}
	if n := s.clusterNode(); n != nil {
		m.Clustered = true
		m.Hostname = n.Self().Hostname
	}
	if m.Hostname == "" {
		m.Hostname, _ = os.Hostname()
	}
	if m.ID == "" {
		m.ID = "standalone"
	}
	return m
}

// hubConfigFiles names the files this hub's configuration is read from,
// relative to its directory.
func (s *Server) hubConfigFiles() []string {
	files := []string{".cloop/config.yaml"}
	if s.hubConfigOverlay() != "" {
		files = append(files, fmt.Sprintf(".cloop/config.ui-%d.yaml", s.Port))
	}
	return files
}

// hubConfigFingerprint changes whenever one of this hub's configuration files
// is written, created or removed.
func (s *Server) hubConfigFingerprint() string {
	var b strings.Builder
	paths := []string{config.ConfigPath(s.WorkDir)}
	if s.Port > 0 {
		paths = append(paths, config.UIInstanceConfigPath(s.WorkDir, s.Port))
	}
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			b.WriteString("-;")
			continue
		}
		fmt.Fprintf(&b, "%d:%d;", fi.Size(), fi.ModTime().UnixNano())
	}
	return b.String()
}

// watchHubHealthConfig tells this member's dashboards to ask again when the
// configuration a report was computed under changes, so a saved setting —
// from the Settings tab, from another member, or from an editor on the host —
// shows without waiting out the report's minute.
func (s *Server) watchHubHealthConfig(ctx context.Context) {
	defer recoverGoroutine("watchHubHealthConfig")
	t := time.NewTicker(hubHealthWatchEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.hubHealthConfigTick()
	}
}

// hubHealthConfigTick is one look at the configuration files. It says so once
// per change, and only while there is a report it makes stale.
func (s *Server) hubHealthConfigTick() {
	h := &s.hubHealth
	fp := s.hubConfigFingerprint()
	h.mu.Lock()
	stale := h.report != nil && h.print != fp && h.nudged != fp
	if stale {
		h.nudged = fp
	}
	h.mu.Unlock()
	if stale {
		s.deliverToAll(wsMessage{Type: "hub_health", Data: json.RawMessage(`{}`)})
	}
}

// urlCredentials is the userinfo credential of raw when it is a URL that has
// one: its password, or a username long enough to be a token presented as one.
func urlCredentials(raw string) []string {
	if !strings.Contains(raw, "://") || !strings.Contains(raw, "@") {
		return nil
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.User == nil {
		return nil
	}
	if pw, ok := u.User.Password(); ok {
		return redact.Values([]byte(pw))
	}
	if name := u.User.Username(); len(name) >= 20 {
		return []string{name}
	}
	return nil
}

// ── Documentation anchors ───────────────────────────────────────────────────

// hubHealthDocAnchors maps a check id's group to its row in the runbook's
// table of `cloop hub doctor` checks. The longest matching prefix wins.
// TestHubHealthDocAnchorsExist holds every anchor to the page and every check
// id the doctor emits to an entry.
var hubHealthDocAnchors = []struct{ prefix, anchor string }{
	{"doctor.", "hub-health-in-the-dashboard"},
	{"policy.", "doctor-policy"},
	{"config.", "doctor-config"},
	{"oidc.", "doctor-oidc"},
	{"tls.", "doctor-tls"},
	{"ui.", "doctor-ui"},
	{"secret_key.", "doctor-secret_key"},
	{"secrets.", "doctor-secret_key"},
	{"rbac.", "doctor-rbac"},
	{"api_tokens.", "doctor-rbac"},
	{"scim.", "doctor-scim"},
	{"offboard.", "doctor-offboard"},
	{"images.", "doctor-images"},
	{"executors.", "doctor-executors"},
	{"runs.", "doctor-runs"},
	{"firewall.", "doctor-firewall"},
	{"gitproxy.", "doctor-gitproxy"},
	{"hubca.", "doctor-gitproxy"},
	{"kubeguard.", "doctor-kubeguard"},
	{"egress.", "doctor-egress"},
	{"projects.", "doctor-projects"},
	{"storage.", "doctor-storage"},
	{"statedb.", "doctor-storage"},
	{"retention.", "doctor-retention"},
	{"audit.", "doctor-audit"},
	{"quotas.", "doctor-quotas"},
	{"budget.", "doctor-quotas"},
	{"smoke.", "dispatch-health-cloop-hub-doctor---smoke"},
}

// hubHealthDocsFallback is the section itself, for a check no group names.
const hubHealthDocsFallback = "configuration-health-cloop-hub-doctor"

// hubHealthDocsURL is where check is explained.
func hubHealthDocsURL(check string) string {
	anchor, best := hubHealthDocsFallback, 0
	for _, d := range hubHealthDocAnchors {
		if strings.HasPrefix(check, d.prefix) && len(d.prefix) > best {
			anchor, best = d.anchor, len(d.prefix)
		}
	}
	return hubHealthDocsBase + "#" + anchor
}

// hubHealthCheckID keeps a check id to the characters ids are made of. The
// hub's own are constants; this is for a check added from elsewhere.
func hubHealthCheckID(id string) string {
	return checkIDJunk.ReplaceAllString(id, "_")
}

var checkIDJunk = regexp.MustCompile(`[^a-z0-9_.\-]`)

// ── Redaction ───────────────────────────────────────────────────────────────

// hubHealthScrub removes credentials from what a check wrote: the exact
// values in set first, then anything the credential-shape registry
// recognises in what is left.
type hubHealthScrub struct{ set *redact.Set }

func (sc hubHealthScrub) text(s string) string {
	if s == "" {
		return s
	}
	return redact.Scrub(sc.set.String(s))
}

// details scrubs a finding's details, whatever they hold, by way of the JSON
// they are sent as: every string in it, keys included, at any depth.
func (sc hubHealthScrub) details(d map[string]any) map[string]any {
	if len(d) == 0 {
		return nil
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return map[string]any{"details": "could not be rendered"}
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return map[string]any{"details": "could not be rendered"}
	}
	out, _ := sc.value(generic).(map[string]any)
	return out
}

func (sc hubHealthScrub) value(v any) any {
	switch x := v.(type) {
	case string:
		return sc.text(x)
	case []any:
		for i := range x {
			x[i] = sc.value(x[i])
		}
		return x
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[sc.text(k)] = sc.value(e)
		}
		return out
	default:
		return x
	}
}

// hubSecretValues lists every credential the hub's configuration and
// environment hold by value.
//
// The checks name settings, not secrets, but they quote what they read — an
// issuer, a webhook, an error from a library that echoes its input — and a
// credential with no recognisable shape gets past the registry. These are the
// ones the hub knows outright.
//
// The configuration is read twice: as loaded, which carries what came from
// the environment (an OIDC client secret supplied as one), and as the files
// say, which still carry a section loading switched off — whose URL is exactly
// what the finding about switching it off quotes.
func hubSecretValues(cfg *config.Config, files []string, environ []string) []string {
	var out []string
	for _, kv := range environ {
		name, value, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if secretEnvName(name) {
			out = append(out, redact.Values([]byte(value))...)
		}
		// HTTPS_PROXY=https://user:pass@proxy is a credential under a name
		// that is not.
		out = append(out, urlCredentials(value)...)
	}
	// The root key wherever it was read from: a file or a systemd credential
	// is not in the environment.
	if roots, err := rootkey.Resolve(); err == nil {
		out = append(out, redact.Values([]byte(roots.Current.Value))...)
		out = append(out, redact.Values([]byte(roots.Previous.Value))...)
	}
	var docs [][]byte
	if cfg != nil {
		if raw, err := yaml.Marshal(cfg); err == nil {
			docs = append(docs, raw)
		}
	}
	for _, f := range files {
		if raw, err := os.ReadFile(f); err == nil {
			docs = append(docs, raw)
		}
	}
	for _, raw := range docs {
		var tree any
		if yaml.Unmarshal(raw, &tree) == nil {
			collectConfigSecrets(tree, nil, &out)
		}
	}
	return out
}

var (
	// secretEnvWord and secretEnvKey are the variable names that hold a
	// credential: CLOOP_SECRET_KEY, ANTHROPIC_API_KEY, GITHUB_TOKEN, a
	// *_PASSWORD. notSecretEnv are the ones that only point at one.
	secretEnvWord = regexp.MustCompile(`(?i)(SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE)`)
	secretEnvKey  = regexp.MustCompile(`(?i)(^|_)(KEY|PAT|PASS)(_|$)`)
	notSecretEnv  = regexp.MustCompile(`(?i)_(FILE|PATH|DIR|DIRECTORY|NAME|ID|URL|ENDPOINT|HOST|PORT|TYPE)$`)
	// secretHeader is a header whose value is a credential, not a content
	// type or an accept list.
	secretHeader = regexp.MustCompile(`(?i)(auth|token|secret|key|cookie|signature|password|session)`)
)

func secretEnvName(name string) bool {
	return !notSecretEnv.MatchString(name) && (secretEnvWord.MatchString(name) || secretEnvKey.MatchString(name))
}

// secretConfigKeys are the configuration keys whose value is the credential
// itself, rather than the name of a secret in the store or a file holding
// one: the OIDC client secret, provider API keys, the GitHub and relay
// tokens, a webhook's signing secret.
var secretConfigKeys = map[string]bool{
	"api_key": true, "groq_api_key": true, "client_secret": true, "token": true,
	"upstream_auth_token": true, "secret": true, "password": true,
}

// collectConfigSecrets walks a configuration as YAML sees it. Besides the
// keys above, a webhook's URL is its credential (Slack's carries the secret
// in its path), so is an Authorization-like header a webhook is configured to
// send, and so is the password in any URL: a check that quotes the URL is
// redacted by the registry, but an error that quotes the password alone is
// not.
func collectConfigSecrets(v any, path []string, out *[]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			collectConfigSecrets(e, append(path[:len(path):len(path)], k), out)
		}
	case []any:
		for _, e := range x {
			collectConfigSecrets(e, path, out)
		}
	case string:
		if len(path) == 0 {
			return
		}
		*out = append(*out, urlCredentials(x)...)
		key := strings.ToLower(path[len(path)-1])
		joined := strings.ToLower(strings.Join(path, "."))
		webhook := strings.Contains(key, "webhook") || (key == "url" && strings.Contains(joined, "webhook"))
		if secretConfigKeys[key] || webhook ||
			(len(path) > 1 && strings.EqualFold(path[len(path)-2], "headers") && secretHeader.MatchString(key)) {
			*out = append(*out, redact.Values([]byte(x))...)
		}
		if u, err := url.Parse(strings.TrimSpace(x)); webhook && err == nil && len(u.Path) > 1 {
			// An error quotes the request it made: the path is the secret.
			*out = append(*out, u.Path, u.EscapedPath())
		}
	}
}
