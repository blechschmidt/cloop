package ui

// kubeshare.go is the hub's half of a Kubernetes share (Task 20416; the share
// itself is pkg/kubeshare, and its terminal half `cloop remote kube`).
//
// A share reaches the hub as an ordinary kubeconfig secret, minted through
// POST /api/secrets as the dashboard mints one, with metadata saying it is a
// share. Everything after that is here:
//
//   - at upload, the time fields of that metadata are taken from the token
//     itself rather than from whoever sent them, and a share that asks to be
//     renewed by the hub is refused unless this hub runs the Kubernetes access
//     monitor — the only thing that keeps the renewal permission the hub's;
//   - one member renews every hub-renewed share at half its token's life
//     (watchKubeShareRenewals), with the token the share already holds;
//   - every member hands the renewed token to its own live monitor sessions
//     (watchKubeGuardUpstreams), so a run dispatched before the renewal keeps
//     working after the token it started with has expired;
//   - POST /api/secrets/{id}/renew renews one now, or takes a token its owner
//     minted from their terminal (`cloop remote kube renew`), checked with the
//     cluster first.
//
// Nothing here runs a credential plugin or reads a file a kubeconfig names. The
// kubeconfig the hub holds is static, and pkg/kubeshare parses it with the
// hub's own parser, which refuses anything else.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/kubeshare"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

const (
	// kubeShareRenewInterval is how often the leader looks for shares due a
	// renewal. A share is due at half its token's life, and the shortest
	// token is ten minutes, so a minute leaves four attempts in the shortest
	// window there is.
	kubeShareRenewInterval = time.Minute
	// kubeShareRenewTimeout bounds one renewal: one TokenRequest.
	kubeShareRenewTimeout = 45 * time.Second
	// kubeGuardSyncInterval is how often a member checks its live monitor
	// sessions against the shares behind them. The token a session holds
	// stays valid for half its life after a renewal, so a minute is ample.
	kubeGuardSyncInterval = time.Minute
	// kubeShareActor is who a scheduled renewal is attributed to.
	kubeShareActor = "hub"
)

// kubeShareState is a member's memory of share renewals.
type kubeShareState struct {
	mu sync.Mutex
	// failed is the last failure each share's renewal reported, by secret
	// id, so each distinct cause is audited once rather than once a minute.
	failed map[string]string
	// applied is, per live monitor session, the token issue time of the
	// share renewal it last took up.
	applied map[string]string
}

// newFailure records msg as secretID's latest failure and reports whether it
// differs from the previous one.
func (st *kubeShareState) newFailure(secretID, msg string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.failed == nil {
		st.failed = map[string]string{}
	}
	if st.failed[secretID] == msg {
		return false
	}
	st.failed[secretID] = msg
	return true
}

func (st *kubeShareState) succeeded(secretID string) {
	st.mu.Lock()
	delete(st.failed, secretID)
	st.mu.Unlock()
}

func (st *kubeShareState) appliedFor(sessionID string) string {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.applied[sessionID]
}

func (st *kubeShareState) setApplied(sessionID, marker string) {
	st.mu.Lock()
	if st.applied == nil {
		st.applied = map[string]string{}
	}
	st.applied[sessionID] = marker
	st.mu.Unlock()
}

// keepApplied forgets the sessions that are no longer live.
func (st *kubeShareState) keepApplied(live map[string]bool) {
	st.mu.Lock()
	for id := range st.applied {
		if !live[id] {
			delete(st.applied, id)
		}
	}
	st.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Renewal
// ---------------------------------------------------------------------------

// watchKubeShareRenewals renews hub-renewed shares as they come due, until ctx
// ends. A leader duty: a renewal is one TokenRequest per share, and two
// members making it would mint two tokens for one.
func (s *Server) watchKubeShareRenewals(ctx context.Context) {
	defer recoverGoroutine("kubernetes share renewal")
	t := time.NewTicker(kubeShareRenewInterval)
	defer t.Stop()
	for {
		s.renewDueKubeShares(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// renewDueKubeShares renews every hub-renewed share whose token is past half
// its life, and returns how many it renewed.
func (s *Server) renewDueKubeShares(ctx context.Context, now time.Time) int {
	bs, err := openBrokersAt(s.WorkDir)
	if err != nil {
		return 0
	}
	defer bs.close()
	if bs.secret == nil {
		return 0
	}
	secrets, err := bs.secret.ListSecrets()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: kubernetes share renewal: list secrets: %v\n", err)
		return 0
	}
	renewed := 0
	for _, sec := range secrets {
		if sec.Kind != secretbroker.KindKubeconfig {
			continue
		}
		share, ok := kubeshare.FromMetadata(sec.Metadata)
		if !ok || share.Renewal != kubeshare.RenewalHub || share.Lapsed || !share.Due(now) {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		rctx, cancel := context.WithTimeout(ctx, kubeShareRenewTimeout)
		_, err := s.renewKubeShare(rctx, bs.secret, sec, kubeShareActor, now)
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "ui: kubernetes share %s not renewed: %v\n", sec.Name, err)
			continue
		}
		renewed++
	}
	if renewed > 0 {
		s.syncKubeGuardUpstreams()
		s.broadcastSecretsUpdate("secret_renewed", "")
	}
	return renewed
}

// renewKubeShare mints a share's next token with the one it holds and stores it
// in place. A failure is written to the share's metadata, where `cloop remote
// kube list` shows it, and to the audit trail once per distinct cause.
func (s *Server) renewKubeShare(ctx context.Context, b *secretbroker.Broker, sec secretbroker.Secret,
	actor string, now time.Time) (secretbroker.Secret, error) {
	share, _ := kubeshare.FromMetadata(sec.Metadata)
	updated, err := b.RenewSecret(ctx, secretbroker.RenewSecretRequest{
		Ref: sec.ID, Kind: secretbroker.KindKubeconfig, Actor: actor,
		AuditFailure: func(err error) bool { return s.kubeShares.newFailure(sec.ID, err.Error()) },
		Renew: func(ctx context.Context, cur secretbroker.Secret, plaintext []byte) (secretbroker.RenewedPayload, error) {
			r, err := kubeshare.Renew(ctx, plaintext, now)
			if err != nil {
				return secretbroker.RenewedPayload{}, err
			}
			meta := cloneMetadata(cur.Metadata)
			kubeshare.RecordRenewal(meta, r.Claims, actor, now)
			return secretbroker.RenewedPayload{
				Payload:   r.Kubeconfig,
				Metadata:  meta,
				ExpiresAt: r.Claims.ExpiresAt,
				Reason: fmt.Sprintf("Kubernetes share: ServiceAccount %s/%s minted its next token with its own "+
					"self-renewal Role; valid until %s, replacing one valid until %s",
					r.Claims.Namespace, r.Claims.ServiceAccount, r.Claims.ExpiresAt.Format(time.RFC3339),
					r.Previous.ExpiresAt.Format(time.RFC3339)),
			}, nil
		},
	})
	if err != nil {
		// Losing a race to another renewal is not a failure of this share:
		// the one that won holds a token at least as new.
		if !errors.Is(err, secretbroker.ErrSecretChanged) {
			s.recordKubeShareFailure(b, sec, share, err, now)
		}
		return sec, err
	}
	s.kubeShares.succeeded(sec.ID)
	return updated, nil
}

// recordKubeShareFailure writes a failed renewal into the share's metadata
// when it says something the metadata does not already.
func (s *Server) recordKubeShareFailure(b *secretbroker.Broker, sec secretbroker.Secret, share kubeshare.Share,
	cause error, now time.Time) {
	lapsed := kubeshare.Lapsed(cause)
	msg := kubeshare.FailureText(secretbroker.RedactString(cause.Error()))
	if sec.Metadata[kubeshare.MetaRenewError] == msg && (!lapsed || share.Lapsed) {
		return
	}
	if _, err := b.UpdateSecretMetadata(sec.ID, func(m map[string]string) {
		kubeshare.RecordFailure(m, msg, now, lapsed)
	}); err != nil && !errors.Is(err, secretbroker.ErrSecretChanged) {
		fmt.Fprintf(os.Stderr, "ui: record the failed renewal of kubernetes share %s: %v\n", sec.Name, err)
	}
}

// adoptKubeShareToken stores a token the share's owner minted, after the
// cluster has confirmed it is the share's own ServiceAccount's.
func (s *Server) adoptKubeShareToken(ctx context.Context, b *secretbroker.Broker, sec secretbroker.Secret,
	token, actor string, now time.Time) (secretbroker.Secret, bool, error) {
	verified := false
	updated, err := b.RenewSecret(ctx, secretbroker.RenewSecretRequest{
		Ref: sec.ID, Kind: secretbroker.KindKubeconfig, Actor: actor,
		Renew: func(ctx context.Context, cur secretbroker.Secret, plaintext []byte) (secretbroker.RenewedPayload, error) {
			r, err := kubeshare.Adopt(ctx, plaintext, token, now)
			if err != nil {
				return secretbroker.RenewedPayload{}, err
			}
			verified = r.Verified
			meta := cloneMetadata(cur.Metadata)
			kubeshare.RecordRenewal(meta, r.Claims, actor, now)
			how := "confirmed with the cluster"
			if !r.Verified {
				how = "not confirmed with the cluster, which does not answer SelfSubjectReview"
			}
			return secretbroker.RenewedPayload{
				Payload:   r.Kubeconfig,
				Metadata:  meta,
				ExpiresAt: r.Claims.ExpiresAt,
				Reason: fmt.Sprintf("Kubernetes share: a token for ServiceAccount %s/%s minted by its owner from the "+
					"terminal (cloop remote kube renew), %s; valid until %s", r.Claims.Namespace,
					r.Claims.ServiceAccount, how, r.Claims.ExpiresAt.Format(time.RFC3339)),
			}, nil
		},
	})
	if err != nil {
		return sec, false, err
	}
	s.kubeShares.succeeded(sec.ID)
	return updated, verified, nil
}

func cloneMetadata(m map[string]string) map[string]string {
	out := make(map[string]string, len(m)+4)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ---------------------------------------------------------------------------
// Live monitor sessions
// ---------------------------------------------------------------------------

// watchKubeGuardUpstreams keeps this member's monitor sessions on the token
// their share holds now. Every member runs it: a session lives in the registry
// of the member that minted it, while the renewal may have been made by
// another.
func (s *Server) watchKubeGuardUpstreams(ctx context.Context) {
	defer recoverGoroutine("kubernetes monitor session renewal")
	t := time.NewTicker(kubeGuardSyncInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.syncKubeGuardUpstreams()
		}
	}
}

// syncKubeGuardUpstreams gives every live monitor session standing on a
// Kubernetes share the token the share holds now, when that changed since the
// session last took one up. It returns how many sessions it updated.
//
// The kubeconfig is re-derived the way a restored session's is — from the
// lease's grant, through the lease's own broker, which re-checks the grant —
// and the monitor accepts it only if nothing but the credential changed.
func (s *Server) syncKubeGuardUpstreams() int {
	svc := activeKubeGuard()
	if svc == nil || svc.reg == nil {
		return 0
	}
	live := map[string]bool{}
	type liveSession struct{ id, leaseID, grantID string }
	var sessions []liveSession
	for _, sess := range svc.reg.Sessions() {
		if sess.Closed() || sess.LeaseID == "" || sess.GrantID == "" {
			continue
		}
		live[sess.ID] = true
		sessions = append(sessions, liveSession{sess.ID, sess.LeaseID, sess.GrantID})
	}
	defer s.kubeShares.keepApplied(live)
	if len(sessions) == 0 {
		return 0
	}

	bs, err := openBrokersAt(s.WorkDir)
	if err != nil {
		return 0
	}
	defer bs.close()
	if bs.secret == nil {
		return 0
	}
	grants, err := bs.secret.ListGrants(secretbroker.GrantFilter{})
	if err != nil {
		return 0
	}
	secretOf := make(map[string]string, len(grants))
	for _, g := range grants {
		secretOf[g.ID] = g.SecretID
	}
	secrets, err := bs.secret.ListSecrets()
	if err != nil {
		return 0
	}
	byID := make(map[string]secretbroker.Secret, len(secrets))
	for _, sec := range secrets {
		byID[sec.ID] = sec
	}

	updated := 0
	for _, sess := range sessions {
		sec, ok := byID[secretOf[sess.grantID]]
		if !ok || sec.Kind != secretbroker.KindKubeconfig || !kubeshare.IsShare(sec.Metadata) {
			continue
		}
		marker := sec.Metadata[kubeshare.MetaIssuedAt]
		if marker != "" && s.kubeShares.appliedFor(sess.id) == marker {
			continue
		}
		sl := liveLeases.get(sess.leaseID)
		if sl == nil || sl.broker == nil {
			continue
		}
		doc, err := sl.broker.KubeconfigUpstream(sess.leaseID, sess.grantID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ui: kubernetes monitor session %s: re-derive its share %s: %v\n", sess.id, sec.Name, err)
			continue
		}
		changed, err := svc.reg.UpdateUpstream(sess.id, doc)
		for i := range doc {
			doc[i] = 0
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "ui: kubernetes monitor session %s: take up the renewed token of %s: %v\n",
				sess.id, sec.Name, err)
			continue
		}
		s.kubeShares.setApplied(sess.id, marker)
		if changed {
			updated++
		}
	}
	return updated
}

// ---------------------------------------------------------------------------
// Upload
// ---------------------------------------------------------------------------

// shareIDPattern is what kubeshare.NewID produces, and all a share id may be.
var shareIDPattern = regexp.MustCompile(`^[a-z0-9]{4,16}$`)

// hubOwnedShareKeys are written by the hub alone; a client's values for them
// are dropped at upload.
var hubOwnedShareKeys = []string{
	kubeshare.MetaIssuedAt, kubeshare.MetaExpiresAt, kubeshare.MetaRenewedAt, kubeshare.MetaRenewedBy,
	kubeshare.MetaRenewals, kubeshare.MetaRenewError, kubeshare.MetaRenewErrorAt, kubeshare.MetaRenewState,
}

// prepareKubeShare checks a share's payload and settles its metadata: the
// token's ServiceAccount and lifetime come from the token, the server from the
// kubeconfig, and hub renewal only on a hub whose monitor would keep the
// renewal permission out of every sandbox.
func prepareKubeShare(meta map[string]string, payload []byte, now time.Time) (map[string]string, error) {
	rc, claims, err := kubeshare.Inspect(payload)
	if err != nil {
		return nil, fmt.Errorf("a Kubernetes share holds a static kubeconfig with one ServiceAccount token: %v", err)
	}
	if !now.Before(claims.ExpiresAt) {
		return nil, fmt.Errorf("the share's token expired at %s", claims.ExpiresAt.Format(time.RFC3339))
	}
	if claims.Lifetime() > kubeshare.MaxTTL+time.Minute {
		return nil, fmt.Errorf("the share's token lives %s; a share holds tokens for at most %s",
			claims.Lifetime().Round(time.Minute), kubeshare.ShortDuration(kubeshare.MaxTTL))
	}
	out := cloneMetadata(meta)
	for _, k := range hubOwnedShareKeys {
		delete(out, k)
	}
	if !shareIDPattern.MatchString(strings.TrimSpace(out[kubeshare.MetaShare])) {
		return nil, fmt.Errorf("%s %q is not a share id", kubeshare.MetaShare, out[kubeshare.MetaShare])
	}
	switch kubeshare.Renewal(strings.TrimSpace(out[kubeshare.MetaRenewal])) {
	case kubeshare.RenewalHub:
		if !kubeGuardRequired.Load() {
			return nil, errors.New("this hub does not run the Kubernetes access monitor " +
				"(executors.kube_guard), and a share the hub renews needs it: its ServiceAccount may create " +
				"tokens for itself, and only the monitor keeps that out of every sandbox. Share it with " +
				"--renewal manual and renew it from your terminal")
		}
	case kubeshare.RenewalManual, "":
		out[kubeshare.MetaRenewal] = string(kubeshare.RenewalManual)
	default:
		return nil, fmt.Errorf("%s %q: want %s or %s", kubeshare.MetaRenewal, out[kubeshare.MetaRenewal],
			kubeshare.RenewalHub, kubeshare.RenewalManual)
	}
	kubeshare.RecordToken(out, claims)
	out[kubeshare.MetaServer] = rc.Server
	return out, nil
}

// kubeGuardView tells a client whether this hub runs the Kubernetes access
// monitor: whether a kubeconfig it delivers reaches the sandbox as a monitor
// session, and so whether it renews a Kubernetes share itself.
type kubeGuardView struct {
	// Enabled is executors.kube_guard.enabled: every kubeconfig is delivered
	// through the monitor, or not at all.
	Enabled bool `json:"enabled"`
	// Running is whether the monitor is serving on this hub process.
	Running bool `json:"running"`
}

func currentKubeGuardView() kubeGuardView {
	return kubeGuardView{Enabled: kubeGuardRequired.Load(), Running: activeKubeGuard() != nil}
}

// ---------------------------------------------------------------------------
// POST /api/secrets/{id}/renew
// ---------------------------------------------------------------------------

// renewSecretRequest is the POST /api/secrets/{id}/renew body. With no token
// the hub renews the share itself, now; with one, it takes the token its owner
// minted. The token is a credential and is never logged or echoed.
type renewSecretRequest struct {
	Token string `json:"token,omitempty"`
}

// kubeShareView is a share as the renew route reports it. No credential.
type kubeShareView struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	Renewal        string     `json:"renewal"`
	ServiceAccount string     `json:"service_account"`
	Namespaces     string     `json:"namespaces"`
	Access         string     `json:"access"`
	Server         string     `json:"server"`
	IssuedAt       time.Time  `json:"issued_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
	RenewedAt      *time.Time `json:"renewed_at,omitempty"`
	RenewedBy      string     `json:"renewed_by,omitempty"`
	Renewals       int        `json:"renewals"`
	// Verified is whether the cluster confirmed a pushed token's identity.
	Verified bool `json:"verified,omitempty"`
	// Sessions is how many live monitor sessions on this hub process took up
	// the new token at once.
	Sessions int `json:"sessions"`
}

func viewKubeShare(sec secretbroker.Secret) kubeShareView {
	sh, _ := kubeshare.FromMetadata(sec.Metadata)
	v := kubeShareView{
		ID: sec.ID, Name: sec.Name, Renewal: string(sh.Renewal),
		ServiceAccount: sh.Namespace + "/" + sh.ServiceAccount, Namespaces: sh.SharedNamespaces(),
		Access: string(sh.Access), Server: sh.Server, IssuedAt: sh.IssuedAt, ExpiresAt: sh.ExpiresAt,
		RenewedBy: sh.RenewedBy, Renewals: sh.Renewals,
	}
	if !sh.RenewedAt.IsZero() {
		at := sh.RenewedAt
		v.RenewedAt = &at
	}
	return v
}

// handleSecretRenew serves POST /api/secrets/{id}/renew (Task 20416).
//
// Who may: the owner of a personal share, or a holder of secret.grant for a
// shared one — the same people who may delete it. An administrator can delete
// a colleague's personal share but not put a credential into it.
func (s *Server) handleSecretRenew(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "secret id is required"))
		return
	}
	var req renewSecretRequest
	if !decodeSecretsBody(w, r, &req) {
		return
	}
	bs, ok := s.openBrokersOr(w)
	if !ok {
		return
	}
	defer bs.close()
	if !bs.requireSecretBroker(w) {
		return
	}
	viewer := s.secretViewer(r)
	target, err := bs.secret.DescribeSecretFor(id, viewer)
	if err != nil {
		writeBrokerError(w, err, "renew secret")
		return
	}
	switch {
	case target.Personal() && !target.OwnedBy(viewer.Identity):
		apierror.WriteError(w, apierror.New(apierror.CodeForbidden,
			"only its owner may renew a personal Kubernetes share; an administrator may delete it"))
		return
	case !target.Personal() && !s.holdsSharedSecretWrite(r):
		denySharedSecret(w, authz.PermSecretGrant, "renewing one")
		return
	}
	share, isShare := kubeshare.FromMetadata(target.Metadata)
	if target.Kind != secretbroker.KindKubeconfig || !isShare {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			fmt.Sprintf("%s is not a Kubernetes share; only a share made with `cloop remote kube share` renews", target.Name)))
		return
	}

	now := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), kubeShareRenewTimeout)
	defer cancel()
	actor := s.auditActor(r)
	var (
		updated  secretbroker.Secret
		verified bool
	)
	if strings.TrimSpace(req.Token) == "" {
		switch {
		case share.Renewal != kubeshare.RenewalHub:
			apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, fmt.Sprintf(
				"%s is renewed from its owner's terminal, not by the hub: run `cloop remote kube renew %s`",
				target.Name, target.Name)))
			return
		case share.Lapsed || share.Expired(now):
			apierror.WriteError(w, apierror.New(apierror.CodeConflict, fmt.Sprintf(
				"%s's token has expired, so nothing the hub holds can mint its next one; its owner can, with "+
					"`cloop remote kube renew %s`", target.Name, target.Name)))
			return
		}
		updated, err = s.renewKubeShare(ctx, bs.secret, target, actor, now)
	} else {
		updated, verified, err = s.adoptKubeShareToken(ctx, bs.secret, target, strings.TrimSpace(req.Token), actor, now)
	}
	if err != nil {
		writeKubeShareRenewError(w, err)
		return
	}
	view := viewKubeShare(updated)
	view.Verified = verified
	view.Sessions = s.syncKubeGuardUpstreams()
	s.broadcastAuditAppend(string(secretbroker.ActionRenew))
	s.broadcastSecretsUpdate("secret_renewed", updated.ID)
	jsonOK(w, view)
}

// writeKubeShareRenewError answers a failed renewal with what it means.
func writeKubeShareRenewError(w http.ResponseWriter, err error) {
	msg := secretbroker.RedactString(err.Error())
	switch {
	case errors.Is(err, kubeshare.ErrWrongToken), errors.Is(err, kubeshare.ErrNotServiceAccountToken):
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, msg))
	case errors.Is(err, secretbroker.ErrSecretChanged), kubeshare.Lapsed(err):
		apierror.WriteError(w, apierror.New(apierror.CodeConflict, msg))
	case errors.Is(err, context.DeadlineExceeded):
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, "the cluster did not answer in time: "+msg))
	default:
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, msg))
	}
}
