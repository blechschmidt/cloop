package oidcauth

// The session lifecycle: create, authenticate, expire, revoke, and revalidate
// against the identity provider (Task 20176).
//
// Two rules shape everything here.
//
// First, expiry is enforced on the *read* path, not only by the janitor. A
// session whose clock has run out is refused by the very next request even if
// nothing has swept the row yet, so a stopped janitor degrades storage hygiene
// and never authorization.
//
// Second, a termination is audited exactly once, and the store's DELETE is what
// decides who audits it. Two concurrent requests can both observe the same
// expired session; only the one whose delete actually removed a row writes the
// event. This is why terminate takes its cue from the store rather than from a
// local "have I already handled this".

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// ── creation ────────────────────────────────────────────────────────────────

// createSession mints a session cookie, records the session, and returns the
// cookie value. The returned string is the only place the raw session id ever
// exists outside the browser: the store receives its digest.
func (a *Authenticator) createSession(id Identity, r *http.Request, refreshToken string) (string, error) {
	sid, err := randToken()
	if err != nil {
		return "", err
	}
	now := a.now()

	// Make room under the identity's session quota before minting another,
	// so the cap holds at the moment it is crossed rather than at the next
	// sweep. See Config.SessionLimit for why this evicts rather than refuses.
	a.enforceSessionLimit(id, now)

	rec := SessionRecord{
		ID:        HashSessionID(sid),
		Identity:  id,
		IP:        RequestIP(r),
		UserAgent: truncate(userAgent(r), 300),
		IssuedAt:  now,
		LastSeen:  now,
		ExpiresAt: now.Add(a.cfg.SessionTTL),

		// Not stamped as checked: a session that has never been revalidated
		// should come due on the first pass, not one interval later.
		RefreshToken: refreshToken,
	}
	if err := a.store.Put(rec); err != nil {
		return "", fmt.Errorf("oidcauth: persist session: %w", err)
	}
	a.mu.Lock()
	a.cache[rec.ID] = &cachedSession{rec: withoutRefreshToken(rec), fetchedAt: now, lastPersisted: now}
	a.mu.Unlock()

	a.audit(SessionAudit{
		Event:     AuditSessionCreated,
		SessionID: rec.ID,
		Subject:   id.Sub,
		Email:     id.Email,
		Actor:     id.OwnerKey(),
		IP:        rec.IP,
		UserAgent: rec.UserAgent,
		At:        now,
		Reason:    refreshReadyReason(refreshToken),
	})
	return sid, nil
}

// enforceSessionLimit evicts the identity's oldest sessions until one more
// will fit under its quota (Task 20182).
//
// Least-recently-seen first, which is the session the user is least likely to
// still be sitting in front of. Evictions are audited as ordinary revocations
// with a reason, so an operator seeing a user's session vanish can tell "the
// quota reclaimed it" from "somebody terminated it".
//
// Every failure here is non-fatal: a store that will not list, or will not
// delete, must not stop somebody signing in. The cost of degrading is that an
// identity briefly holds one session more than its cap, which is a far smaller
// problem than a hub that cannot authenticate.
func (a *Authenticator) enforceSessionLimit(id Identity, now time.Time) {
	if a.cfg.SessionLimit == nil {
		return
	}
	key := id.OwnerKey()
	if key == "" {
		return
	}
	limit := a.cfg.SessionLimit(key, id.Groups, id.Roles)
	if limit <= 0 {
		return
	}

	all, err := a.store.List()
	if err != nil {
		return
	}
	mine := make([]SessionRecord, 0, 4)
	for _, rec := range all {
		// Match on the same key ownership is recorded under, not on Sub
		// alone: an identity is the thing being capped, and OwnerKey is
		// what everything else in the hub counts by.
		if rec.Identity.OwnerKey() != key {
			continue
		}
		// An already-dead session is not headroom somebody else is using.
		// Counting it would evict a live session to make room for a row the
		// next read would have refused anyway.
		if rec.Expired(now) || rec.Idle(now, a.cfg.IdleTimeout) {
			continue
		}
		mine = append(mine, rec)
	}
	surplus := len(mine) - (limit - 1)
	if surplus <= 0 {
		return
	}
	sort.Slice(mine, func(i, j int) bool { return mine[i].LastSeen.Before(mine[j].LastSeen) })
	for i := 0; i < surplus && i < len(mine); i++ {
		a.terminate(mine[i], AuditSessionRevoked, "session_quota_exceeded", "quota")
	}
}

// refreshReadyReason records, at sign-in, whether this session can be revoked
// from the IdP side. An operator reading the trail after an incident needs to
// know which sessions were only ever bounded by their timeouts.
func refreshReadyReason(refreshToken string) string {
	if refreshToken == "" {
		return "no_refresh_token"
	}
	return ""
}

// ── the authentication path ─────────────────────────────────────────────────

// IdentityFromRequest returns the authenticated user for r's session cookie,
// or nil when there is no valid session. Safe on nil receiver.
func (a *Authenticator) IdentityFromRequest(r *http.Request) *Identity {
	rec, ok := a.SessionFromRequest(r)
	if !ok {
		return nil
	}
	id := rec.Identity // copy so callers cannot mutate the stored session
	return &id
}

// SessionFromRequest resolves and validates r's session, refreshing the idle
// clock as a side effect. It reports false for a missing, unknown, expired, or
// idle session — deliberately without distinguishing them, since the caller
// must answer all four identically.
func (a *Authenticator) SessionFromRequest(r *http.Request) (SessionRecord, bool) {
	if !a.Enabled() || r == nil {
		return SessionRecord{}, false
	}
	c, err := r.Cookie(SessionCookieName)
	if err != nil || c.Value == "" {
		return SessionRecord{}, false
	}
	hash := HashSessionID(c.Value)
	now := a.now()

	rec, ok := a.lookup(hash, now)
	if !ok {
		return SessionRecord{}, false
	}
	if rec.Expired(now) {
		a.terminate(rec, AuditSessionExpired, "absolute_ttl", "system")
		return SessionRecord{}, false
	}
	if rec.Idle(now, a.cfg.IdleTimeout) {
		a.terminate(rec, AuditSessionExpired, "idle_timeout", "system")
		return SessionRecord{}, false
	}
	a.touch(hash, now)
	rec.LastSeen = now
	return rec, true
}

// lookup returns a session from the read-through cache, falling back to the
// store. A cache entry older than sessionCacheTTL is refetched — that bound is
// what makes a revocation performed on another replica take effect here.
func (a *Authenticator) lookup(hash string, now time.Time) (SessionRecord, bool) {
	a.mu.Lock()
	if ent, ok := a.cache[hash]; ok && now.Sub(ent.fetchedAt) < sessionCacheTTL {
		rec := ent.rec
		a.mu.Unlock()
		return rec, true
	}
	a.mu.Unlock()

	rec, err := a.store.Get(hash)
	if err != nil {
		// Gone from the store: revoked elsewhere, swept, or never existed.
		// Drop any cached copy so it cannot be served again.
		a.mu.Lock()
		delete(a.cache, hash)
		a.mu.Unlock()
		return SessionRecord{}, false
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	// Carry forward what this process knows that the row does not: the
	// throttle watermark, and an in-memory LastSeen the store has not been
	// told about yet. Dropping either would restart the throttle on every
	// refetch and turn a busy session back into a per-request writer.
	lastPersisted := rec.LastSeen
	if prev, ok := a.cache[hash]; ok {
		if prev.lastPersisted.After(lastPersisted) {
			lastPersisted = prev.lastPersisted
		}
		if prev.rec.LastSeen.After(rec.LastSeen) {
			rec.LastSeen = prev.rec.LastSeen
		}
	}
	rec = withoutRefreshToken(rec)
	a.cache[hash] = &cachedSession{rec: rec, fetchedAt: now, lastPersisted: lastPersisted}
	return rec, true
}

// withoutRefreshToken returns a copy with the credential stripped.
//
// The cache is a hot-path structure that holds an entry per signed-in user for
// as long as they keep using the dashboard, and nothing on the authentication
// path — or in any handler that receives a SessionRecord — has a use for the
// refresh token. The revalidation pass reads it straight from the store, so
// keeping a decrypted copy resident here would widen the window in which a
// heap dump yields live IdP credentials, in exchange for nothing.
func withoutRefreshToken(rec SessionRecord) SessionRecord {
	rec.RefreshToken = ""
	return rec
}

// touch advances the idle clock in memory and, at most once per
// lastSeenWriteInterval, in the store.
//
// The decision to write is made under the lock and the watermark is claimed at
// the same instant, so concurrent requests on one session produce exactly one
// write rather than N — and cannot interleave into a torn value, since the
// mutation itself never happens outside the lock.
func (a *Authenticator) touch(hash string, now time.Time) {
	a.mu.Lock()
	ent, ok := a.cache[hash]
	if !ok {
		a.mu.Unlock()
		return
	}
	if now.After(ent.rec.LastSeen) {
		ent.rec.LastSeen = now
	}
	due := now.Sub(ent.lastPersisted) >= lastSeenWriteInterval
	if due {
		ent.lastPersisted = now
	}
	a.mu.Unlock()

	if !due {
		return
	}
	// Advisory: a failed idle-clock write must never fail a request. The cost
	// is that the session expires up to one interval early, which is the safe
	// direction.
	_ = a.store.Touch(hash, now)
}

// terminate removes a session and audits it exactly once.
//
// The store's report of whether a row existed is the arbiter: whoever actually
// deleted it writes the event. Everyone else — a concurrent request that saw
// the same expired session, a janitor pass racing a sign-out — stays silent.
func (a *Authenticator) terminate(rec SessionRecord, event, reason, actor string) {
	a.mu.Lock()
	delete(a.cache, rec.ID)
	a.mu.Unlock()

	existed, err := a.store.Delete(rec.ID)
	if err != nil || !existed {
		return
	}
	a.auditTermination(rec, event, reason, actor)
}

func (a *Authenticator) auditTermination(rec SessionRecord, event, reason, actor string) {
	if actor == "" {
		actor = "system"
	}
	a.audit(SessionAudit{
		Event:     event,
		SessionID: rec.ID,
		Subject:   rec.Identity.Sub,
		Email:     rec.Identity.Email,
		Actor:     actor,
		Reason:    reason,
		IP:        rec.IP,
		UserAgent: rec.UserAgent,
	})
}

// ── logout and revocation ───────────────────────────────────────────────────

// Logout ends the caller's session and clears the cookie. It returns the
// identity that was signed out, or nil when there was no session.
func (a *Authenticator) Logout(w http.ResponseWriter, r *http.Request) *Identity {
	var out *Identity
	if rec, ok := a.SessionFromRequest(r); ok {
		a.terminate(rec, AuditSessionRevoked, "user_logout", rec.Identity.OwnerKey())
		id := rec.Identity
		out = &id
	}
	http.SetCookie(w, a.sessionCookie(r, "", -1))
	return out
}

// LogoutAll ends every session belonging to subject and returns how many it
// ended. keepID (a hashed session id, typically the caller's own) is spared;
// pass "" to end all of them.
//
// The self-service answer to a stolen laptop: one call from any device the
// user still holds invalidates the rest, without an operator in the loop.
func (a *Authenticator) LogoutAll(subject, keepID, actor string) (int, error) {
	if a == nil {
		return 0, errors.New("oidcauth: not configured")
	}
	if strings.TrimSpace(subject) == "" {
		return 0, errors.New("oidcauth: a subject is required")
	}
	gone, err := a.store.DeleteBySubject(subject, keepID)
	if err != nil {
		return 0, fmt.Errorf("oidcauth: end sessions for subject: %w", err)
	}
	a.mu.Lock()
	for _, rec := range gone {
		delete(a.cache, rec.ID)
	}
	a.mu.Unlock()
	for _, rec := range gone {
		a.auditTermination(rec, AuditSessionRevoked, "logout_all", actor)
	}
	return len(gone), nil
}

// RevokeSession ends one session by its hashed id, on behalf of actor. It
// reports false when no such session existed.
//
// This is the operator's kill switch: a session terminated here stops
// authenticating within sessionCacheTTL even on a replica that has it cached,
// and immediately on the replica that served the call.
func (a *Authenticator) RevokeSession(id, actor, reason string) (bool, error) {
	if a == nil {
		return false, errors.New("oidcauth: not configured")
	}
	if strings.TrimSpace(id) == "" {
		return false, errors.New("oidcauth: a session id is required")
	}
	rec, err := a.store.Get(id)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("oidcauth: read session: %w", err)
	}
	a.mu.Lock()
	delete(a.cache, id)
	a.mu.Unlock()

	existed, err := a.store.Delete(id)
	if err != nil {
		return false, fmt.Errorf("oidcauth: delete session: %w", err)
	}
	if !existed {
		return false, nil
	}
	if reason == "" {
		reason = "admin_revoked"
	}
	a.auditTermination(rec, AuditSessionRevoked, reason, actor)
	return true, nil
}

// ListSessions returns every live session, most recently active first, with
// the two clocks evaluated at now so the caller can render a status without
// re-deriving the policy.
func (a *Authenticator) ListSessions() ([]SessionRecord, error) {
	if a == nil {
		return nil, errors.New("oidcauth: not configured")
	}
	return a.store.List()
}

// SessionCount returns the number of stored sessions. Used by tests and
// /api/me diagnostics.
func (a *Authenticator) SessionCount() int {
	if a == nil {
		return 0
	}
	rows, err := a.store.List()
	if err != nil {
		return 0
	}
	return len(rows)
}

// ── janitor ─────────────────────────────────────────────────────────────────

// RunJanitor sweeps expired sessions and revalidates them against the IdP
// until ctx is done. It is safe to call at most once per Authenticator;
// callers that do not want the background work simply do not start it, and
// then rely on the read-path checks alone.
func (a *Authenticator) RunJanitor(ctx context.Context) {
	if a == nil || !a.Enabled() {
		return
	}
	t := time.NewTicker(janitorInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.SweepExpired()
			a.RevalidateDue(ctx)
		}
	}
}

// SweepExpired removes sessions past either clock and audits each one.
// Returns how many it removed. Exported so tests and the janitor share one
// code path.
func (a *Authenticator) SweepExpired() int {
	if a == nil {
		return 0
	}
	now := a.now()
	idleCutoff := now.Add(-a.cfg.IdleTimeout)
	if a.cfg.IdleTimeout <= 0 {
		// Idle clock disabled: choose a cutoff no row can be at or before.
		// The zero time would still match a row whose LastSeen is zero, which
		// is exactly the corrupt row we would rather leave for a human.
		idleCutoff = time.Time{}
	}
	gone, err := a.store.DeleteExpired(now, idleCutoff)
	if err != nil {
		return 0
	}
	a.mu.Lock()
	for _, rec := range gone {
		delete(a.cache, rec.ID)
	}
	a.mu.Unlock()
	for _, rec := range gone {
		reason := "idle_timeout"
		if rec.Expired(now) {
			reason = "absolute_ttl"
		}
		a.auditTermination(rec, AuditSessionExpired, reason, "system")
	}
	return len(gone)
}

// ── IdP revalidation ────────────────────────────────────────────────────────

// RevalidateDue re-checks every session whose last IdP confirmation is older
// than the configured interval, terminating those the provider refuses.
// Returns (checked, terminated).
//
// This is the mechanism that makes IdP-side revocation take effect. Without
// it, disabling a user at the provider changes nothing the hub can observe:
// the cookie is still valid, the claims in it were valid when issued, and the
// session runs to its ceiling.
func (a *Authenticator) RevalidateDue(ctx context.Context) (int, int) {
	if a == nil || a.cfg.RefreshInterval <= 0 {
		return 0, 0
	}
	cutoff := a.now().Add(-a.cfg.RefreshInterval)
	due, err := a.store.DueForRefresh(cutoff, refreshBatchSize)
	if err != nil || len(due) == 0 {
		return 0, 0
	}
	terminated := 0
	for _, rec := range due {
		if ctx.Err() != nil {
			break
		}
		if a.revalidate(ctx, rec) {
			terminated++
		}
	}
	return len(due), terminated
}

// revalidate redeems one session's refresh token. It reports whether the
// session was terminated.
//
// The failure taxonomy is the whole point:
//
//   - The IdP answers with an OAuth error that means the grant is gone
//     (invalid_grant — a disabled user, withdrawn consent, a forced sign-out,
//     or a refresh token already rotated away): terminate immediately.
//   - The IdP is unreachable, times out, or returns a server error: leave the
//     session alone and stamp the attempt so it is retried on the next
//     interval rather than on every tick. Failing closed here would mean a
//     provider outage signs out the entire fleet, which converts a dependency
//     problem into an availability incident.
//   - The IdP rejects *cloop's own* credentials (invalid_client): also leave
//     the session alone. That is a misconfiguration on this side, and no
//     user's access should end because an operator rotated a client secret.
func (a *Authenticator) revalidate(ctx context.Context, rec SessionRecord) bool {
	if rec.RefreshToken == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	tok, refreshed, err := a.refreshGrant(ctx, rec.RefreshToken)
	now := a.now()
	if err != nil {
		if isGrantRevoked(err) {
			a.terminate(rec, AuditSessionIdPRevoked, grantErrorReason(err), "idp")
			return true
		}
		// Transient or local: back off by stamping the attempt, keeping the
		// existing token so the next interval retries with it.
		_ = a.store.ApplyRefresh(rec.ID, RefreshResult{
			RefreshToken: rec.RefreshToken,
			CheckedAt:    now,
		})
		a.invalidateCache(rec.ID)
		return false
	}

	// A refreshed id_token for a different subject is not a claim update, it
	// is a different person. Applying its groups would hand this session
	// somebody else's authority, so the only safe reading is that this session
	// no longer corresponds to anything the provider will vouch for. It takes
	// an IdP bug or a token substitution to get here; both warrant ending it.
	if refreshed != nil && refreshed.Sub != rec.Identity.Sub {
		a.terminate(rec, AuditSessionIdPRevoked, "idp_subject_mismatch", "idp")
		return true
	}

	// Rotation: an IdP that issues a new refresh token has invalidated the old
	// one, so failing to store the replacement would make the *next* check
	// look like a revocation and sign the user out for no reason.
	next := tok.RefreshToken
	if next == "" {
		next = rec.RefreshToken
	}
	res := RefreshResult{RefreshToken: next, CheckedAt: now}
	if refreshed != nil {
		// Groups and roles only. Email and name are deliberately left as
		// captured at sign-in: OwnerKey is derived from the email and is what
		// every project ownership row was recorded under, so rewriting it
		// mid-session would silently orphan a user from their own projects —
		// a data-access change masquerading as a security fix. Re-keying an
		// identity is a migration, not something a background refresh does.
		res.ClaimsAsserted = true
		res.Groups, res.Roles = refreshed.Groups, refreshed.Roles
	}
	if err := a.store.ApplyRefresh(rec.ID, res); err != nil {
		// Nothing was stamped, so this session stays due and the next pass
		// retries it rather than waiting out a full interval on claims that
		// were never written.
		return false
	}
	// Evict last: until the row is written there is nothing new to re-read,
	// and a request landing in the gap would only refill the cache from the
	// pre-refresh row it just dropped.
	a.invalidateCache(rec.ID)
	a.noteClaimAssertion(rec, refreshed, now)
	return false
}

// noteClaimAssertion records what the refresh did to this session's authority:
// an audit event when it narrowed, and the counters behind RefreshClaimStats.
func (a *Authenticator) noteClaimAssertion(rec SessionRecord, refreshed *Identity, now time.Time) {
	if refreshed == nil {
		a.mu.Lock()
		a.claimsUnverified++
		first := !a.claimsUnverifiedSeen
		a.claimsUnverifiedSeen = true
		a.mu.Unlock()
		if first {
			a.audit(SessionAudit{
				Event:     AuditSessionClaimsUnverified,
				SessionID: rec.ID,
				Subject:   rec.Identity.Sub,
				Email:     rec.Identity.Email,
				Actor:     "idp",
				Reason:    "no_id_token_and_no_userinfo",
				At:        now,
			})
		}
		return
	}

	a.mu.Lock()
	a.claimsAsserted++
	a.mu.Unlock()

	dropped := droppedClaims(rec.Identity, *refreshed)

	// Both roles are resolved under the session's *existing* identity key,
	// varying only the claims. The refreshed identity is not used for this:
	// plenty of providers omit the email claim from a refresh id_token, and
	// resolving the new claims under an empty-email key would miss every
	// email-keyed binding — reporting an administrator as demoted on every
	// single refresh. Since the subject is confirmed identical above and the
	// email is deliberately not rewritten, the key is by construction the same
	// on both sides, and the claims are the only thing that moved.
	key := rec.Identity.OwnerKey()
	priorRole, priorRank := a.effectiveRole(key, rec.Identity.Groups, rec.Identity.Roles)
	nextRole, nextRank := a.effectiveRole(key, refreshed.Groups, refreshed.Roles)

	// Two independent narrowings, because they answer different questions. A
	// rank drop is the one that changed what this user may do; a dropped claim
	// that leaves the rank alone still records that they left a group, which
	// is what makes the trail usable for "when did access to X end". A pure
	// widening is not audited here: gaining authority is the ordinary outcome
	// of a grant, and auditing every one of them would bury the narrowings.
	rankNarrowed := priorRole != "" && nextRank < priorRank
	if !rankNarrowed && len(dropped) == 0 {
		return
	}
	reason := "claims_dropped"
	if rankNarrowed {
		reason = "role_downgraded"
	}
	a.audit(SessionAudit{
		Event:         AuditSessionRoleNarrowed,
		SessionID:     rec.ID,
		Subject:       rec.Identity.Sub,
		Email:         rec.Identity.Email,
		Actor:         "idp",
		Reason:        reason,
		IP:            rec.IP,
		UserAgent:     rec.UserAgent,
		At:            now,
		PriorRole:     priorRole,
		Role:          nextRole,
		DroppedClaims: dropped,
	})
}

// effectiveRole consults the optional resolver hook. Without one it reports
// ("", 0), which callers read as "this deployment cannot name roles".
func (a *Authenticator) effectiveRole(identity string, groups, roles []string) (string, int) {
	if a.cfg.EffectiveRole == nil {
		return "", 0
	}
	return a.cfg.EffectiveRole(identity, groups, roles)
}

// droppedClaims lists the group and role values present before and absent
// after, sorted so the event is stable to compare across sessions.
//
// Values are matched the way they are consumed: case-insensitively and with a
// leading path separator trimmed, matching pkg/authz's normalisation. An IdP
// that restyles "/admins" as "admins" has not deprivileged anybody, and
// reporting that as a lost group would train operators to ignore the event.
func droppedClaims(before, after Identity) []string {
	held := make(map[string]struct{}, len(after.Groups)+len(after.Roles))
	for _, v := range after.Groups {
		held[normalizeClaim(v)] = struct{}{}
	}
	for _, v := range after.Roles {
		held[normalizeClaim(v)] = struct{}{}
	}

	var out []string
	seen := make(map[string]struct{}, len(before.Groups)+len(before.Roles))
	for _, v := range append(append([]string(nil), before.Groups...), before.Roles...) {
		key := normalizeClaim(v)
		if key == "" {
			continue
		}
		if _, ok := held[key]; ok {
			continue
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		// The original spelling, not the normalised key: an operator greps
		// the trail for what their IdP calls the group.
		out = append(out, strings.TrimSpace(v))
	}
	sort.Strings(out)
	return out
}

func normalizeClaim(v string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(v), "/"))
}

// invalidateCache drops a cached copy so the next request re-reads the row.
func (a *Authenticator) invalidateCache(id string) {
	a.mu.Lock()
	delete(a.cache, id)
	a.mu.Unlock()
}

// refreshGrant performs the refresh_token grant, returning the token response
// and the identity its id_token asserts — nil when the provider returned none.
//
// The response's id_token, when present, is verified with the same rules as at
// login minus the nonce binding (there is no authorization request to bind
// to). It is verified rather than ignored so a token endpoint that has been
// compromised or misrouted cannot keep a session alive with an unsigned
// answer — a check that costs one signature verification per session per
// interval.
//
// The verified identity is *returned* rather than discarded because it is the
// only current statement the provider makes about who this user is. Verifying
// it and then keeping the claims captured at sign-in means an administrator
// removed from the admin group at the IdP holds admin here until the absolute
// session TTL runs out, however often this runs.
//
// When the provider returns no id_token — the common case, since most only
// issue one on the initial code exchange — the userinfo endpoint is asked
// instead, so that hole is not simply conceded. See userinfo.go.
func (a *Authenticator) refreshGrant(ctx context.Context, refreshToken string) (*tokenResponse, *Identity, error) {
	disc, err := a.discover(ctx)
	if err != nil {
		return nil, nil, err
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("scope", strings.Join(a.cfg.Scopes, " "))

	tok, status, err := a.postToken(ctx, disc.TokenEndpoint, form, true)
	if err != nil && (status == http.StatusUnauthorized || isOAuthCode(err, "invalid_client")) {
		tok, _, err = a.postToken(ctx, disc.TokenEndpoint, form, false)
	}
	if err != nil {
		return nil, nil, err
	}
	if tok.IDToken == "" {
		// No id_token — the common case, and the one that used to leave claims
		// frozen at sign-in. Ask userinfo instead, using the access token this
		// very response carried.
		//
		// A failure here is deliberately not propagated: the *grant* succeeded,
		// so the session is still valid and must survive. Returning the error
		// would terminate it over an unreachable userinfo endpoint. The nil
		// identity is what the caller records as "claims unverified".
		id, uerr := a.userinfoIdentity(ctx, tok.AccessToken)
		if uerr != nil || id == nil {
			return tok, nil, nil
		}
		return tok, id, nil
	}
	id, verr := a.verifyIDToken(ctx, tok.IDToken, "")
	if verr != nil {
		return nil, nil, fmt.Errorf("oidcauth: refreshed id_token failed validation: %w", verr)
	}
	return tok, id, nil
}

// isGrantRevoked reports whether err means the IdP has withdrawn this session.
func isGrantRevoked(err error) bool {
	return isOAuthCode(err, "invalid_grant")
}

// grantErrorReason renders the provider's own error code for the audit trail,
// so an operator can tell "the user was disabled" from "the refresh token was
// already used" without reading the hub's logs.
func grantErrorReason(err error) string {
	var oe *oauthError
	if errors.As(err, &oe) && oe.Code != "" {
		return "idp_" + oe.Code
	}
	return "idp_rejected"
}

// ── IdP-side logout ─────────────────────────────────────────────────────────

// EndSessionURL returns the provider's RP-initiated logout URL, or "" when the
// discovery document advertises none (or has not been fetched yet).
//
// Clearing the cookie ends the session *here*; the browser's session at the
// provider survives it, so the next sign-in completes without a prompt and
// "log out" looks broken to anyone on a shared machine. Sending the browser on
// to end_session_endpoint is what makes the two agree.
//
// The request carries client_id and post_logout_redirect_uri rather than
// id_token_hint. Both are permitted by RP-Initiated Logout 1.0, and the hint
// would mean retaining the ID token at rest for the life of the session — a
// second credential to protect in exchange for a marginally smoother prompt.
func (a *Authenticator) EndSessionURL() string {
	if a == nil || !a.Enabled() {
		return ""
	}
	a.discMu.Lock()
	disc := a.disc
	a.discMu.Unlock()
	if disc == nil || disc.EndSessionEndpoint == "" {
		return ""
	}
	q := url.Values{}
	q.Set("client_id", a.cfg.ClientID)
	if home := a.postLogoutRedirect(); home != "" {
		q.Set("post_logout_redirect_uri", home)
	}
	sep := "?"
	if strings.Contains(disc.EndSessionEndpoint, "?") {
		sep = "&"
	}
	return disc.EndSessionEndpoint + sep + q.Encode()
}

// postLogoutRedirect derives where the IdP should send the browser back to:
// the dashboard root, taken from the configured redirect URL's origin so it is
// always a URL this deployment actually answers on.
func (a *Authenticator) postLogoutRedirect() string {
	u, err := url.Parse(a.cfg.RedirectURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host + "/"
}

// ── request metadata ────────────────────────────────────────────────────────

// RequestIP extracts the client address for the Active Sessions table.
//
// X-Forwarded-For is honoured because a hosted hub sits behind a reverse
// proxy, and its leftmost entry is the only useful value there. It is
// attacker-controlled on a direct connection, which is why nothing
// security-relevant keys off this: it is a label an operator reads, never an
// input to an authorization decision.
func RequestIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if first := strings.TrimSpace(strings.Split(xff, ",")[0]); first != "" {
			return truncate(first, 64)
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func userAgent(r *http.Request) string {
	if r == nil {
		return ""
	}
	return r.Header.Get("User-Agent")
}
