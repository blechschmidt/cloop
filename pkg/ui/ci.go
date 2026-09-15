package ui

// ci.go runs the CI/CD federation service alongside the hub (Task 20278).
//
// It is the third monitor in the same family as gitproxy.go and kubeguard.go —
// take custody of a credential, hand out something narrower that points at a
// thing which reads every request — applied to the credential CI actually
// wants, which is Claude.
//
// # Why this one is not on its own listener
//
// The git and Kubernetes monitors serve sandboxes, which run wherever the hub
// put them and can be told any address. This one serves GitHub's runners,
// which are on the internet and reach the hub the same way a browser does. A
// second listener would mean a second public port, a second certificate and a
// second thing to get through a corporate firewall, to serve traffic the
// existing one already terminates. So the exchange and the relay are routes on
// the main mux, carved out of hub authentication because their credential is
// the request itself: a pipeline presents a forge-signed assertion, and later
// a session token this hub minted, and has no cloop session to present.
//
// # What turning it on changes
//
// Two routes begin answering, and nothing else. With ui.ci.enabled false they
// refuse, whatever rules are stored — which is the switch an operator reaches
// for when a pipeline is misbehaving and they want it to stop now rather than
// after they have finished reading the allowlist.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/ciauth"
	"github.com/blechschmidt/cloop/pkg/claudeproxy"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// ciMountPath is where the Anthropic relay lives. It is the value a pipeline
// sets ANTHROPIC_BASE_URL to, with the hub's external URL in front.
const ciMountPath = "/api/ci/anthropic"

// ciExchangePath is where a pipeline trades its OIDC token for a session.
const ciExchangePath = "/api/ci/token"

// ciReapInterval is how often lapsed sessions are swept. Expiry is enforced at
// authentication regardless, so this is hygiene.
const ciReapInterval = 5 * time.Minute

// ciService is the running federation service: the token verifier, the session
// registry, and the relay that serves them.
//
// One is built per Server and rebuilt when the settings change, rather than
// living in a package global the way the git and Kubernetes monitors do. Those
// two are reached by executor code that has no Server to ask; this one is
// reached only from handlers, and a global would be one more thing a pkg/ui
// test mutates for every other test in the package.
type ciService struct {
	verifier *ciauth.Verifier
	reg      *claudeproxy.Registry
	proxy    *claudeproxy.Proxy

	// models is the hub-wide default allowlist a rule inherits when it names
	// none.
	models []string

	// upstream describes what the relay talks to, for the settings panel.
	// It never contains the credential.
	upstream string

	// fingerprint is the config this service was built from. It lives on the
	// service rather than beside the pointer so that one atomic load answers
	// both "is there a service" and "is it still current" — reading them
	// separately is a data race, and the losing read is the one that decides
	// whether to tear down every live session.
	fingerprint string

	// auditDB is held open for the service's lifetime rather than opened per
	// event. A relay emits one event per request, and opening a second
	// connection to a SQLite file this process already has open produces
	// SQLITE_BUSY under any concurrency at all — which showed up as audit
	// rows silently missing while the request they described succeeded. Nil
	// when the database could not be opened; the sink then writes to stderr
	// rather than dropping the decision on the floor.
	auditDB *statedb.DB

	stopReaping context.CancelFunc
}

// ciState is the per-Server holder. It is a separate struct so Server gains one
// field rather than four.
type ciState struct {
	mu  sync.Mutex
	svc atomic.Pointer[ciService]

	// lastErr is the most recent build failure, surfaced by the settings
	// panel. A hub whose CI service failed to build must say so: the
	// alternative is an operator reading "enabled: true" while every pipeline
	// gets a 503.
	lastErr atomic.Pointer[string]
}

// loadHubConfig reads this hub's own configuration.
//
// Deliberately re-read rather than cached: the settings panel writes
// config.yaml, and a CI service built from a snapshot taken at boot would keep
// federating under a policy an operator has already changed.
func (s *Server) loadHubConfig() (*config.Config, error) {
	return config.Load(s.WorkDir)
}

// ciEnabled reports whether CI federation is configured on.
func (s *Server) ciEnabled() bool {
	cfg, err := s.loadHubConfig()
	if err != nil || cfg == nil {
		return false
	}
	return cfg.UI.CI.Enabled
}

// ciSvc returns the live service, building it if needed.
//
// A build failure is recorded and returned; it is not cached as a permanent
// verdict, because the usual cause is a missing Anthropic credential and the
// usual fix is to add one — which should take effect on the next request, not
// on the next restart.
func (s *Server) ciSvc() (*ciService, error) {
	cfg, err := s.loadHubConfig()
	if err != nil {
		return nil, fmt.Errorf("load hub config: %w", err)
	}
	if cfg == nil || !cfg.UI.CI.Enabled {
		return nil, ciauth.ErrDisabled
	}

	fingerprint := ciFingerprint(cfg)
	if svc := s.ci.svc.Load(); svc != nil && svc.fingerprint == fingerprint {
		return svc, nil
	}

	s.ci.mu.Lock()
	defer s.ci.mu.Unlock()
	// Re-check under the lock: two concurrent exchanges on a cold hub would
	// otherwise build two services, and the loser's sessions would be minted
	// into a registry nothing serves.
	if svc := s.ci.svc.Load(); svc != nil && svc.fingerprint == fingerprint {
		return svc, nil
	}

	svc, err := s.buildCIService(cfg)
	if err != nil {
		msg := err.Error()
		s.ci.lastErr.Store(&msg)
		return nil, err
	}
	s.ci.lastErr.Store(nil)
	// Replacing the service replaces the registry, so every session minted
	// under the old configuration stops working. That is the intent: a
	// settings change that left already-minted sessions relaying under the
	// old policy would be a settings change that did not happen.
	if old := s.ci.svc.Swap(svc); old != nil {
		old.shutdown("configuration changed")
	}
	return svc, nil
}

// ciFingerprint summarises the config fields that require a rebuild. Fields
// absent from it — the exchange-log bound, for instance — are read live.
func ciFingerprint(cfg *config.Config) string {
	c := cfg.UI.CI
	return strings.Join([]string{
		fmt.Sprint(c.Enabled), c.Issuer, c.Audience, fmt.Sprint(c.ClockSkew()),
		strings.Join(c.Models(), ","), c.UpstreamBaseURL,
		// The credentials are fingerprinted by length, not by value: a
		// rotated key must rebuild the relay, and a config fingerprint is
		// not a place to put a secret even in a process-local string.
		fmt.Sprint(len(c.UpstreamAuthToken)), fmt.Sprint(len(cfg.Anthropic.APIKey)),
		cfg.UI.ExternalURL,
	}, "|")
}

// buildCIService constructs the verifier, registry and relay.
func (s *Server) buildCIService(cfg *config.Config) (*ciService, error) {
	c := cfg.UI.CI

	issuer := strings.TrimSpace(c.Issuer)
	if issuer == "" {
		issuer = ciauth.GitHubActionsIssuer
	}
	audience := strings.TrimSpace(c.Audience)
	if audience == "" {
		audience = ciauth.DefaultAudience
	}
	verifier, err := ciauth.NewVerifier(ciauth.VerifierConfig{
		Issuer:    issuer,
		Audience:  audience,
		ClockSkew: time.Duration(c.ClockSkew()) * time.Second,
	})
	if err != nil {
		return nil, err
	}

	upstream := claudeproxy.Upstream{BaseURL: strings.TrimSpace(c.UpstreamBaseURL)}
	if tok := strings.TrimSpace(c.UpstreamAuthToken); tok != "" {
		upstream.AuthToken = tok
	} else {
		// The ordinary case: relay with the credential the rest of cloop
		// already uses, configured in one place. An operator who has not set
		// one gets a specific error rather than a 502 from the relay.
		upstream.APIKey = strings.TrimSpace(cfg.Anthropic.APIKey)
	}
	if err := upstream.Validate(); err != nil {
		if errors.Is(err, claudeproxy.ErrNoUpstream) {
			return nil, errors.New("CI federation is enabled but this hub has no Anthropic " +
				"credential to relay with — set anthropic.api_key, or ui.ci.upstream_auth_token")
		}
		return nil, err
	}

	var auditDB *statedb.DB
	if db, dbErr := statedb.Open(state.DBPath(s.WorkDir)); dbErr == nil {
		// s.WorkDir is the hub's own directory. A CI pipeline authenticates to
		// the hub, not to a project, so its sessions and relayed calls are
		// fleet facts even when the job they run is about one repository.
		auditDB = db.AsControlPlane()
	} else {
		fmt.Fprintf(os.Stderr,
			"ui: CI relay decisions will go to stderr, not the audit trail: %v\n", dbErr)
	}

	reg := claudeproxy.NewRegistry(strings.TrimSuffix(cfg.UI.ExternalURL, "/") + ciMountPath)
	reg.OnEvent = ciAuditSink(auditDB)

	px, err := claudeproxy.New(reg, claudeproxy.Options{
		Upstream:   upstream,
		PathPrefix: ciMountPath,
	})
	if err != nil {
		return nil, err
	}

	reapCtx, stop := context.WithCancel(context.Background())
	svc := &ciService{
		verifier:    verifier,
		reg:         reg,
		proxy:       px,
		models:      c.Models(),
		upstream:    upstream.Redacted(),
		fingerprint: ciFingerprint(cfg),
		auditDB:     auditDB,
		stopReaping: stop,
	}
	go svc.reap(reapCtx)
	return svc, nil
}

// reap sweeps lapsed sessions until the service is replaced or the hub stops.
func (svc *ciService) reap(ctx context.Context) {
	t := time.NewTicker(ciReapInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			svc.reg.ReapExpired()
		}
	}
}

// shutdown revokes every session and stops the reaper.
func (svc *ciService) shutdown(reason string) {
	if svc == nil {
		return
	}
	if svc.stopReaping != nil {
		svc.stopReaping()
	}
	// Sessions are closed before the audit handle, so the closing events
	// reach the trail rather than stderr.
	svc.reg.CloseAll(reason)
	if svc.auditDB != nil {
		_ = svc.auditDB.Close()
	}
}

// closeCI tears the service down. Called from the hub's shutdown path.
func (s *Server) closeCI() {
	if old := s.ci.svc.Swap(nil); old != nil {
		old.shutdown("hub shutting down")
	}
}

// ciBaseURL is what a pipeline should set ANTHROPIC_BASE_URL to.
//
// The configured external URL wins, because it is what the operator says this
// deployment is called and is the only answer that survives a reverse proxy.
// Falling back to the request's own host is what makes the feature work on a
// hub nobody has configured an external URL for — a development hub, or one
// reached directly — instead of handing the pipeline an unusable empty string.
func (s *Server) ciBaseURL(r *http.Request) string {
	if ext := strings.TrimSpace(s.ExternalURL); ext != "" {
		return strings.TrimSuffix(ext, "/") + ciMountPath
	}
	scheme := "https"
	if r.TLS == nil {
		// X-Forwarded-Proto is honoured because the common deployment puts a
		// TLS-terminating proxy in front; without it every such hub would
		// advertise http:// and the pipeline would refuse or downgrade.
		if fwd := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); fwd != "" {
			scheme = strings.ToLower(fwd)
		} else {
			scheme = "http"
		}
	}
	host := r.Host
	if fwd := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); fwd != "" {
		host = fwd
	}
	return scheme + "://" + host + ciMountPath
}

// isCIFederationEndpoint reports whether a request is one of the two the CI
// feature answers without a hub session.
//
// It is deliberately narrow: one exact path for the exchange, restricted to
// POST, and the relay subtree. Both authenticate internally — the exchange
// against the forge's signing keys, the relay against a session token this hub
// minted — and both refuse outright when the feature is off. Everything else
// under /api/ci/ is ordinary RBAC-gated configuration and must keep failing
// closed.
func isCIFederationEndpoint(r *http.Request) bool {
	p := r.URL.Path
	if p == ciExchangePath {
		return r.Method == http.MethodPost
	}
	return p == ciMountPath || strings.HasPrefix(p, ciMountPath+"/")
}

// ciAuditSink writes relay decisions to the hub's audit trail.
//
// Failures are reported to stderr rather than returned: the sink runs on the
// request goroutine, and a pipeline's Claude call must not fail because an
// audit row could not be written. What must not happen is the write failing
// silently — a refusal nobody recorded is a refusal nobody can review.
func ciAuditSink(db *statedb.DB) func(claudeproxy.Event) {
	if db == nil {
		return func(e claudeproxy.Event) {
			fmt.Fprintf(os.Stderr, "ci relay: %s %s %s %s\n",
				e.Kind, e.Repository, e.Model, e.Detail)
		}
	}
	return func(e claudeproxy.Event) {
		if err := appendCIAuditEvent(db, e); err != nil {
			fmt.Fprintf(os.Stderr, "ui: ci relay audit: %v (event: %s %s)\n",
				err, e.Kind, e.Repository)
		}
	}
}

// appendCIAuditEvent writes one decision. The event type carries no credential
// by construction: pkg/claudeproxy.Event has no field that could hold a prompt,
// a completion or a token.
func appendCIAuditEvent(db *statedb.DB, e claudeproxy.Event) error {
	payload, err := json.Marshal(e)
	if err != nil {
		payload = []byte(`{}`)
	}
	actor := e.Repository
	if actor == "" {
		actor = "ci-pipeline"
	}
	at := e.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	return db.AppendAuditEvent(&statedb.AuditEvent{
		Timestamp:  at,
		Actor:      actor,
		EventType:  string(e.Kind),
		EntityType: "ci_session",
		EntityID:   e.SessionID,
		Payload:    string(payload),
	})
}

// newCIRuleID mints an identifier for a rule or an exchange record.
//
// Random rather than sequential: rule ids appear in audit payloads and in the
// exchange log, and a monotonic counter would let anyone who sees one infer
// how many rules a hub has and in what order they were written.
func newCIRuleID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read randomness: %w", err)
	}
	return hex.EncodeToString(b), nil
}
