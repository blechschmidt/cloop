package secretbroker

// apprefresh.go keeps a GitHub App installation token working for as long as
// the run holding it (Task 20375).
//
// # The hour
//
// A github_app grant is delivered as an installation token minted at dispatch,
// and GitHub stops honouring that token an hour later. Task 20349 made a run's
// lease live as long as the run (Broker.Extend), but extending a lease extends
// nothing at GitHub, so a run still using git more than an hour after dispatch
// lost GitHub there — through the git proxy, whose session presented the dead
// token upstream, and without it, in the sandbox's own token file.
//
// # What a refresh is
//
// Each App token a lease carries lives in a slot (appTokenSlot). A refresh
// re-mints the slot's token and swaps it in:
//
//   - at the scope the first token was minted at, replayed verbatim — the same
//     installation, the same repositories by ID, the same permissions — and
//     held to the permissions GitHub granted the first time, so a refresh can
//     never come back wider than the token it replaces (appTokenScope);
//   - only while the authority behind it holds: the grant is re-read and must
//     still be active and still issued to the requester, its secret must still
//     exist and name the same installation, and the lease must not have been
//     released;
//   - with the superseded token destroyed at GitHub once nothing presents it any
//     more — when a proxy session's in-flight requests drain, or a grace period
//     after a sandbox's token file was rewritten (appTokenRetireGrace).
//
// Who asks depends on where the token is. Under the git proxy the session that
// presents it upstream asks, from its request path, when the token is within
// AppTokenRefreshWindow of its end (the guard hands it the slot's refresher).
// Without the proxy the token is a file in the sandbox, and the hub's lease
// keepalive asks (RefreshLeaseFiles) and delivers the new file through the
// executor.
//
// # When it is refused
//
// A refresh the broker or GitHub refuses — the grant revoked or expired, the
// lease released, the installation suspended or gone, a repository no longer in
// the installation — ends the grant's access the way a revocation does: the
// slot stops refreshing, every token it holds is destroyed at GitHub, and the
// refusal is a denied secret.renew row. The proxy session presenting it is
// closed by the caller. A sandbox's token file is left as a grant revocation
// leaves it — holding a token GitHub no longer honours — and the hub journals
// why; taking the file itself away is the lease's revocation, as ever. A
// failure that may pass — GitHub unreachable, busy or rate-limiting — is a
// denied row too, and is retried while the token held still works.

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// AppTokenRefreshWindow is how much of an installation token's life may remain
// when it is re-minted.
//
// Ten minutes leaves room for several attempts — a proxy session tries again
// after appTokenRefreshBackoff, the lease keepalive every minute — before a
// failing refresh lets the token lapse, and stays clear of appTokenMinLifetime,
// the floor below which a freshly minted token is refused outright.
const AppTokenRefreshWindow = 10 * time.Minute

// appTokenRetireGrace is how long a superseded token keeps working after its
// replacement reached a sandbox's file, before it is destroyed at GitHub.
//
// git reads its credential once per process and reuses it for every request
// that process makes, so a fetch that started a moment before the file was
// rewritten still presents the old token on its next request. Destroying the
// old token the instant the file changed would fail exactly that fetch. Two
// minutes outlasts the request sequence of any one git invocation, whose long
// transfers are single requests authenticated when they begin.
const appTokenRetireGrace = 2 * time.Minute

// appTokenSlot is one GitHub App installation token a lease holds, kept
// current by refresh.
//
// The fields above mu's are fixed when the slot is made; the rest are guarded
// by the owning Broker's mu, because Release, Revoke and DeleteSecret reach a
// slot through Broker.minted under that lock.
type appTokenSlot struct {
	grantID    string
	secretID   string
	secretName string
	// requester and actor are the lease's, so a refresh re-checks the grant
	// against the subject the lease was issued to and audits as its holder.
	requester Requester
	actor     string
	scope     appTokenScope
	// guarded: a git proxy session presents this token upstream, and refreshes
	// it on its own request path. The lease keepalive leaves it alone.
	guarded bool
	// envExported: a "*" allowlist also exported the token as GITHUB_TOKEN and
	// GH_TOKEN, which no refresh can reach inside a running process. The
	// superseded token is left to lapse at its hour rather than destroyed, so
	// the variables keep working as long as they did before refresh existed.
	envExported bool

	// sem makes refreshes of one slot single-flight: a caller waits for the
	// refresh in progress rather than minting a second token beside it.
	sem chan struct{}

	// Guarded by Broker.mu.
	leaseID string
	// sessionID is the git proxy session presenting a guarded token, named on
	// its refresh rows so the two trails join.
	sessionID string
	current   appToken
	// retiring holds superseded tokens still live at GitHub.
	retiring []retiringToken
	// delivered: the workload holds current. False from a refresh of an
	// unguarded token until its file is rewritten; the keepalive re-delivers
	// until it is.
	delivered bool
	// abandoned: the material this token was minted for was never delivered
	// (its guard failed, say), so the token is only ever destroyed.
	abandoned bool
	// ended: the lease was released, the grant revoked, or a refresh refused.
	// Nothing refreshes an ended slot, and its tokens have been destroyed.
	ended bool
}

// retiringToken is a superseded token awaiting destruction.
type retiringToken struct {
	appToken
	// retireAfter is when the keepalive may destroy it. Zero until the token
	// replacing it reached the sandbox; a proxy session retires its own.
	retireAfter time.Time
}

func newAppTokenSlot() *appTokenSlot {
	return &appTokenSlot{sem: make(chan struct{}, 1)}
}

// tokens returns every credential the slot holds at GitHub. Callers hold
// Broker.mu.
func (s *appTokenSlot) tokens() []appToken {
	out := make([]appToken, 0, 1+len(s.retiring))
	if s.current.token != "" {
		out = append(out, s.current)
	}
	for _, r := range s.retiring {
		out = append(out, r.appToken)
	}
	return out
}

// end marks the slot finished and returns the tokens to destroy. Callers hold
// Broker.mu.
func (s *appTokenSlot) end() []appToken {
	if s.ended {
		return nil
	}
	s.ended = true
	out := s.tokens()
	s.retiring = nil
	return out
}

// AppTokenRefresh is a re-minted installation token.
type AppTokenRefresh struct {
	// Token is the credential, for the hub's own use: a proxy session presents
	// it upstream. Never logged, never delivered to a sandbox by this type.
	Token string
	// ExpiresAt is when GitHub stops honouring Token.
	ExpiresAt time.Time
	// Retire destroys the token this one superseded, at GitHub. Nil when no
	// new token was minted — another caller had already refreshed, and Token is
	// the one it minted. Idempotent, safe after the lease was released, and
	// never blocks longer than appRevokeTimeout.
	Retire func()
}

// String redacts the token so a %v on a refresh cannot log a credential.
func (r AppTokenRefresh) String() string {
	return fmt.Sprintf("installation token (%d bytes, expires %s) [redacted]",
		len(r.Token), r.ExpiresAt.UTC().Format(time.RFC3339))
}

// GoString mirrors String.
func (r AppTokenRefresh) GoString() string { return r.String() }

// RefreshAppToken re-mints the installation token leaseID holds for grantID and
// returns it. held is the token the caller presents now; when the slot's token
// is no longer that one, another caller refreshed first and its token comes
// back with no Retire, unminted.
//
// It is the workspace path's refresh (pkg/executor/gitcreds): a pinned git
// proxy session presents the token its inner lease carries. A lease path
// session is handed its refresher by the guard instead (GitGuardRequest), and a
// sandbox's token file is refreshed by RefreshLeaseFiles.
func (b *Broker) RefreshAppToken(ctx context.Context, leaseID, grantID, held string) (AppTokenRefresh, error) {
	slot := b.findSlot(leaseID, grantID)
	if slot == nil {
		ev := Event{Action: ActionRenew, LeaseID: leaseID, GrantID: grantID, Kind: KindGitHubApp}
		return AppTokenRefresh{}, b.denyf(ev, ErrRefreshRefused,
			"lease %s holds no github_app token for grant %s (released, or never issued here)", leaseID, grantID)
	}
	return b.refreshSlot(ctx, slot, held)
}

// findSlot returns the slot leaseID holds for grantID, or nil.
func (b *Broker) findSlot(leaseID, grantID string) *appTokenSlot {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, slot := range b.minted[strings.TrimSpace(leaseID)] {
		if slot.grantID == strings.TrimSpace(grantID) && !slot.abandoned {
			return slot
		}
	}
	return nil
}

// slotRefresher is what a guard's session calls to refresh slot.
func (b *Broker) slotRefresher(slot *appTokenSlot) func(context.Context, string) (AppTokenRefresh, error) {
	return func(ctx context.Context, held string) (AppTokenRefresh, error) {
		return b.refreshSlot(ctx, slot, held)
	}
}

// refreshSlot re-mints slot's token. See the file comment for the rules.
func (b *Broker) refreshSlot(ctx context.Context, slot *appTokenSlot, held string) (AppTokenRefresh, error) {
	if err := ctx.Err(); err != nil {
		return AppTokenRefresh{}, err
	}
	// Single flight. Waiting is bounded by the caller's context: a session's
	// request gives up with its client rather than queueing behind GitHub.
	select {
	case slot.sem <- struct{}{}:
	case <-ctx.Done():
		return AppTokenRefresh{}, ctx.Err()
	}
	defer func() { <-slot.sem }()

	b.mu.Lock()
	ev := b.slotEvent(slot)
	if slot.ended || slot.abandoned {
		b.mu.Unlock()
		return AppTokenRefresh{}, b.denyf(ev, ErrRefreshRefused,
			"github app token for grant %s: the lease holding it was released", slot.grantID)
	}
	if held != "" && !sameToken(slot.current.token, held) {
		// Someone else refreshed while this caller waited: theirs is the token.
		cur := slot.current
		b.mu.Unlock()
		return AppTokenRefresh{Token: cur.token, ExpiresAt: cur.expiresAt}, nil
	}
	previous := slot.current
	b.mu.Unlock()

	cred, final, cause := b.refreshAuthority(slot)
	if cause != nil {
		if final {
			return AppTokenRefresh{}, b.refuseRefresh(ctx, slot, ev, cause)
		}
		// The store or the keyring could not answer just now. That says
		// nothing about the grant, so the token held keeps working and the
		// caller asks again.
		return AppTokenRefresh{}, b.denyf(ev, ErrGitHubAppMint,
			"github app token for grant %s could not be re-minted (will retry; the current token "+
				"expires %s): %v", slot.grantID, previous.expiresAt.UTC().Format(time.RFC3339), cause)
	}

	tok, err := b.appMinter.remint(ctx, cred, slot.scope)
	if err != nil {
		if errors.Is(err, ErrGitHubAppRefused) {
			return AppTokenRefresh{}, b.refuseRefresh(ctx, slot, ev, err)
		}
		// GitHub unreachable, slow or rate limiting. The token held keeps
		// working until its own expiry, and the caller tries again.
		return AppTokenRefresh{}, b.denyf(ev, ErrGitHubAppMint,
			"github app token for grant %s could not be re-minted (will retry; the current token "+
				"expires %s): %v", slot.grantID, previous.expiresAt.UTC().Format(time.RFC3339), err)
	}

	fresh := appToken{
		grantID:    slot.grantID,
		secretID:   slot.secretID,
		secretName: slot.secretName,
		baseURL:    slot.scope.baseURL,
		token:      tok.Token,
		expiresAt:  tok.ExpiresAt,
	}
	b.mu.Lock()
	if slot.ended {
		// Released, or revoked, while GitHub was minting. The new token belongs
		// to nothing; destroy it rather than let it live out its hour.
		b.mu.Unlock()
		b.destroyAppTokens(ctx, []appToken{fresh}, "lease released during a refresh")
		return AppTokenRefresh{}, b.denyf(ev, ErrRefreshRefused,
			"github app token for grant %s: the lease holding it was released during the refresh", slot.grantID)
	}
	if previous.token != "" {
		slot.retiring = append(slot.retiring, retiringToken{appToken: previous})
	}
	slot.current = fresh
	slot.delivered = slot.guarded
	sessionID := slot.sessionID
	b.mu.Unlock()

	ev.Decision = DecisionAllow
	ev.ExpiresAt = tok.ExpiresAt
	ev.Reason = fmt.Sprintf("github app installation %d token re-minted at its original scope (%s, %s), "+
		"expires %s", slot.scope.installationID, slot.scope.summary, describePermissions(slot.scope.permissions),
		tok.ExpiresAt.UTC().Format(time.RFC3339))
	if sessionID != "" {
		ev.Reason += "; presented upstream by git proxy session " + sessionID
	} else {
		ev.Reason += "; the sandbox's token file is rewritten with it"
	}
	b.emit(ev)

	retire := func() {}
	if previous.token != "" {
		retire = b.retirer(slot, previous.token)
	}
	return AppTokenRefresh{Token: tok.Token, ExpiresAt: tok.ExpiresAt, Retire: retire}, nil
}

// slotEvent is the audit row a refresh of slot starts from. Callers hold mu.
func (b *Broker) slotEvent(slot *appTokenSlot) Event {
	return Event{
		Action:     ActionRenew,
		Actor:      slot.actor,
		LeaseID:    slot.leaseID,
		GrantID:    slot.grantID,
		SecretID:   slot.secretID,
		SecretName: slot.secretName,
		Kind:       KindGitHubApp,
		ExecutorID: slot.requester.ExecutorID,
		ProjectID:  slot.requester.ProjectID,
		RunID:      slot.requester.RunID,
	}
}

// refreshAuthority re-reads what a refresh stands on and opens the App
// credential, or returns why the token must not be renewed now. final reports
// whether that answer will stand: a grant that is gone, revoked, expired or
// reissued, a secret that is gone or changed kind, a payload that no longer
// parses. A store or keyring that failed to answer is not final — a busy
// database says nothing about the grant.
func (b *Broker) refreshAuthority(slot *appTokenSlot) (cred *AppCredential, final bool, cause error) {
	now := b.now()
	g, err := b.store.GetGrant(slot.grantID)
	if err != nil {
		if errors.Is(err, ErrGrantNotFound) {
			return nil, true, fmt.Errorf("%w: grant %s is gone", ErrGrantNotFound, slot.grantID)
		}
		return nil, false, fmt.Errorf("read grant %s: %w", slot.grantID, err)
	}
	if reason := g.DenyReason(now); reason != "" {
		sentinel := ErrGrantExpired
		if !g.RevokedAt.IsZero() {
			sentinel = ErrGrantRevoked
		}
		return nil, true, fmt.Errorf("%w: grant %s: %s", sentinel, g.ID, reason)
	}
	if !g.Subject.Matches(slot.requester) {
		return nil, true, fmt.Errorf("%w: grant %s is no longer issued to this lease's holder", ErrInvalidGrant, g.ID)
	}
	if g.SecretID != slot.secretID {
		return nil, true, fmt.Errorf("%w: grant %s now points at another secret", ErrInvalidGrant, g.ID)
	}
	s, err := b.store.GetSecret(slot.secretID)
	if err != nil {
		if errors.Is(err, ErrSecretNotFound) {
			return nil, true, fmt.Errorf("%w: secret %s behind grant %s is gone", ErrSecretNotFound, slot.secretID, g.ID)
		}
		return nil, false, fmt.Errorf("read secret %s: %w", slot.secretID, err)
	}
	if s.Kind != KindGitHubApp {
		return nil, true, fmt.Errorf("%w: secret %s is no longer a github_app secret", ErrInvalidSecret, s.Name)
	}
	plaintext, err := b.seal.OpenEnvelope(AADFor(SetSecrets, s.ID), s.Envelope())
	if err != nil {
		return nil, false, fmt.Errorf("%w: open payload for %s: %w", ErrSealFailed, s.Name, err)
	}
	defer zero(plaintext)
	parsed, err := ParseGitHubApp(plaintext)
	if err != nil {
		return nil, true, err
	}
	return parsed, false, nil
}

// refuseRefresh ends slot after a final refusal: no further refresh, every token
// destroyed at GitHub, and a denied secret.renew row naming the cause. The
// returned error wraps ErrRefreshRefused and the cause.
func (b *Broker) refuseRefresh(ctx context.Context, slot *appTokenSlot, ev Event, cause error) error {
	b.mu.Lock()
	doomed := slot.end()
	b.mu.Unlock()
	reason := fmt.Sprintf("github app token for grant %s will not be renewed, so its access ends: %v",
		slot.grantID, cause)
	b.destroyAppTokens(ctx, doomed, "refresh refused")
	err := fmt.Errorf("%w: %w", ErrRefreshRefused, cause)
	ev.Decision = DecisionDeny
	ev.Reason = reason
	b.emit(ev)
	return err
}

// retirer returns the function that destroys one superseded token of slot.
func (b *Broker) retirer(slot *appTokenSlot, token string) func() {
	return func() { b.retireToken(context.Background(), slot, token, "superseded by a refreshed token") }
}

// retireToken destroys a superseded token now, if slot still holds it. A token
// the slot no longer holds was destroyed with the lease, or already retired.
func (b *Broker) retireToken(ctx context.Context, slot *appTokenSlot, token, reason string) {
	b.mu.Lock()
	var doomed []appToken
	kept := slot.retiring[:0:0]
	for _, r := range slot.retiring {
		if sameToken(r.token, token) {
			doomed = append(doomed, r.appToken)
			continue
		}
		kept = append(kept, r)
	}
	slot.retiring = kept
	b.mu.Unlock()
	b.destroyAppTokens(ctx, doomed, reason)
}

// RetireSuperseded destroys the superseded tokens of leaseID whose grace has
// passed: replaced in the sandbox's token file at least appTokenRetireGrace
// ago. It is the no-proxy half of retirement, called by the hub's lease
// keepalive; a proxy session retires its own when its requests drain.
//
// A superseded token that has simply expired is forgotten without a call to
// GitHub, and so is one whose grant exported it into the environment (see
// envExported) once it lapses.
func (b *Broker) RetireSuperseded(ctx context.Context, leaseID string) {
	now := b.now()
	var doomed []appToken
	b.mu.Lock()
	for _, slot := range b.minted[leaseID] {
		if slot.guarded {
			continue
		}
		kept := slot.retiring[:0:0]
		for _, r := range slot.retiring {
			switch {
			case !now.Before(r.expiresAt):
				// Dead at GitHub already; nothing to destroy.
			case slot.envExported || r.retireAfter.IsZero() || now.Before(r.retireAfter):
				kept = append(kept, r)
			default:
				doomed = append(doomed, r.appToken)
			}
		}
		slot.retiring = kept
	}
	b.mu.Unlock()
	b.destroyAppTokens(ctx, doomed, "superseded by a refreshed token")
}

// ---------------------------------------------------------------------------
// Refreshing a sandbox's token file
// ---------------------------------------------------------------------------

// LeaseFileRefresh is new content for token files a lease already delivered:
// what the hub's keepalive hands the executor holding the lease.
type LeaseFileRefresh struct {
	LeaseID string
	// Files are the token files to rewrite in place, named as the lease
	// rendered them. Dir is empty: the caller knows where the lease landed.
	Files []DeliveredFile
	// Refused names the grants whose refresh was refused. Their tokens are
	// already destroyed at GitHub, so the files the workload holds name dead
	// tokens, as after a grant revocation; the caller reports why.
	Refused []RefusedRefresh
	// Pending reports grants whose refresh failed for a reason that may pass.
	// Their current token still works; the next call tries again.
	Pending []string
	// Summary is audit-safe: which grants, which files, until when.
	Summary string

	b     *Broker
	slots []*appTokenSlot
	// tokens are the credentials Files carry, by slot, so Delivered marks
	// exactly what was delivered even if a refresh lands in between.
	tokens []string
}

// RefusedRefresh is one grant a refresh ended.
type RefusedRefresh struct {
	GrantID    string
	SecretName string
	Reason     string
}

// Empty reports whether there is nothing to deliver or report.
func (r *LeaseFileRefresh) Empty() bool {
	return r == nil || (len(r.Files) == 0 && len(r.Refused) == 0 && len(r.Pending) == 0)
}

// Delivered records that every file reached the workload. The tokens they
// replaced may be destroyed appTokenRetireGrace from now — unless eventual,
// when the files went to something that delivers them later (the kubelet
// syncing a Secret volume): the workload may still read the old token after
// any grace this side could choose, so the superseded token is left to lapse
// at its own expiry instead.
func (r *LeaseFileRefresh) Delivered(eventual bool) {
	if r == nil || r.b == nil {
		return
	}
	now := r.b.now()
	r.b.mu.Lock()
	defer r.b.mu.Unlock()
	for i, slot := range r.slots {
		if slot.ended || !sameToken(slot.current.token, r.tokens[i]) {
			continue
		}
		slot.delivered = true
		for j := range slot.retiring {
			if !slot.retiring[j].retireAfter.IsZero() {
				continue
			}
			if eventual {
				slot.retiring[j].retireAfter = slot.retiring[j].expiresAt
				continue
			}
			slot.retiring[j].retireAfter = now.Add(appTokenRetireGrace)
		}
	}
}

// AppTokensDue reports whether RefreshLeaseFiles has anything to do for
// leaseID: an App token delivered as a file is within AppTokenRefreshWindow of
// its end, or was refreshed and has not reached the workload yet. It mints
// nothing, so the keepalive can ask on every tick — and ask where the new file
// would go before a token is minted for a workload that cannot receive it.
func (b *Broker) AppTokensDue(leaseID string) bool {
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, slot := range b.minted[strings.TrimSpace(leaseID)] {
		if slot.guarded || slot.abandoned || slot.ended {
			continue
		}
		if slot.current.expiresAt.Sub(now) <= AppTokenRefreshWindow || !slot.delivered {
			return true
		}
	}
	return false
}

// HeldAppTokenExpiry is when the first GitHub App token file leaseID's
// workload holds stops working at GitHub. After a refresh that has not reached
// the workload yet, that is the token it still reads, not the one waiting to
// replace it. Zero when the lease holds none, or only tokens already past their
// hour.
func (b *Broker) HeldAppTokenExpiry(leaseID string) time.Time {
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	var earliest time.Time
	for _, slot := range b.minted[strings.TrimSpace(leaseID)] {
		if slot.guarded || slot.abandoned || slot.ended {
			continue
		}
		held := slot.current.expiresAt
		if !slot.delivered {
			// The oldest token no delivery has superseded yet. Gone from
			// retiring once it lapsed, which leaves nothing to report.
			held = time.Time{}
			for _, r := range slot.retiring {
				if r.retireAfter.IsZero() {
					held = r.expiresAt
					break
				}
			}
		}
		if held.IsZero() || !now.Before(held) {
			continue
		}
		if earliest.IsZero() || held.Before(earliest) {
			earliest = held
		}
	}
	return earliest
}

// HoldsFileAppTokens reports whether leaseID carries a GitHub App token the
// workload holds as a file — the only kind the keepalive refreshes.
func (b *Broker) HoldsFileAppTokens(leaseID string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, slot := range b.minted[strings.TrimSpace(leaseID)] {
		if !slot.guarded && !slot.abandoned && !slot.ended {
			return true
		}
	}
	return false
}

// Close zeroes the file contents.
func (r *LeaseFileRefresh) Close() {
	if r == nil {
		return
	}
	for i := range r.Files {
		zero(r.Files[i].Content)
		r.Files[i].Content = nil
	}
	r.tokens = nil
}

// RefreshLeaseFiles re-mints every App token lease delivered as a file that is
// within AppTokenRefreshWindow of its end, and returns the files to rewrite —
// together with any token refreshed earlier whose file has not reached the
// workload yet. Nil when there is nothing to do, which is the common case and
// costs one map lookup.
//
// Guarded tokens are skipped: their proxy session refreshes them. So is a
// lease with no App material.
func (b *Broker) RefreshLeaseFiles(ctx context.Context, lease *Lease) (*LeaseFileRefresh, error) {
	if lease == nil || strings.TrimSpace(lease.ID) == "" {
		return nil, wrapf(ErrLeaseNotFound, "nil lease")
	}
	now := b.now()
	b.mu.Lock()
	var candidates []*appTokenSlot
	for _, slot := range b.minted[lease.ID] {
		if slot.guarded || slot.abandoned || slot.ended {
			continue
		}
		if slot.current.expiresAt.Sub(now) <= AppTokenRefreshWindow || !slot.delivered {
			candidates = append(candidates, slot)
		}
	}
	b.mu.Unlock()
	if len(candidates) == 0 {
		return nil, nil
	}

	out := &LeaseFileRefresh{LeaseID: lease.ID, b: b}
	names := tokenFileNames(lease.Materials)
	var parts []string
	for _, slot := range candidates {
		b.mu.Lock()
		due := slot.current.expiresAt.Sub(now) <= AppTokenRefreshWindow
		held := slot.current.token
		b.mu.Unlock()
		if due {
			if _, err := b.refreshSlot(ctx, slot, held); err != nil {
				if errors.Is(err, ErrRefreshRefused) {
					out.Refused = append(out.Refused, RefusedRefresh{
						GrantID: slot.grantID, SecretName: slot.secretName, Reason: err.Error(),
					})
				} else {
					out.Pending = append(out.Pending, slot.grantID)
				}
				continue
			}
		}
		name, ok := names[slot.grantID]
		if !ok {
			// The lease delivered no token file for this grant — guarded after
			// all, or a material shape this function does not know. Nothing
			// in the sandbox to rewrite.
			continue
		}
		b.mu.Lock()
		cur := slot.current
		ended := slot.ended
		b.mu.Unlock()
		if ended || cur.token == "" {
			continue
		}
		out.Files = append(out.Files, DeliveredFile{
			GrantID:    slot.grantID,
			SecretName: slot.secretName,
			Kind:       KindGitHubApp,
			Name:       name,
			Mode:       0o600,
			Content:    []byte(cur.token + "\n"),
		})
		out.slots = append(out.slots, slot)
		out.tokens = append(out.tokens, cur.token)
		parts = append(parts, fmt.Sprintf("%s (grant %s, %s, expires %s)", name, slot.grantID,
			slot.scope.summary, cur.expiresAt.UTC().Format(time.RFC3339)))
	}
	sort.Strings(parts)
	out.Summary = strings.Join(parts, "; ")
	if out.Empty() {
		return nil, nil
	}
	return out, nil
}

// tokenFileNames maps each unguarded GitHub material's grant to the name its
// token file has in the rendered lease: "github-token" for the first, suffixed
// for the rest (githubmulti.go), exactly as render named them at dispatch.
func tokenFileNames(materials []Material) map[string]string {
	out := map[string]string{}
	coalesced, err := coalesceGitHub(materials)
	if err != nil {
		return out
	}
	for _, m := range coalesced {
		if m.Kind != KindGitHubApp {
			continue
		}
		for _, f := range m.Files {
			if f.Name == tokenFileName || strings.HasPrefix(f.Name, tokenFileName+"-") {
				out[m.GrantID] = f.Name
				break
			}
		}
	}
	return out
}

// describePermissions renders a permission request for an audit row.
func describePermissions(perms map[string]string) string {
	if perms == nil {
		return "the installation's permissions"
	}
	parts := make([]string, 0, len(perms))
	for scope, level := range perms {
		parts = append(parts, scope+":"+level)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// sameToken compares two credentials in constant time. Every comparison here
// is between tokens this process minted, not against anything a caller
// supplied blind — but a comparison of credential values is written one way
// throughout the hub, and that is the way.
func sameToken(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
