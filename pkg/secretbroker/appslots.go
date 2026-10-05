package secretbroker

// appslots.go: what a taken-over lease needs to keep feeding its run (Task
// 20383).
//
// Task 20382 made a lease outlive the hub process that issued it: the process
// adopting the lease's run takes the lease over. But a lease is a record of
// grants, and what the run actually spends lived in the stopped process's
// memory — the GitHub App tokens it minted, and the slots that re-mint them
// before GitHub's hour ends (apprefresh.go), and the credentials its git proxy
// and Kubernetes monitor sessions present upstream. This file is how the
// process that took the lease over gets them back.
//
// App token slots are recorded with the lease: the scope each token was minted
// at — installation, repository ids, the permissions asked for and the ones
// GitHub granted — the lease file a token delivered without the proxy lives in,
// and when the token held now expires. Never the token. Restore takes the
// slots over with the lease and rebuilds them holding no token; the next
// refresh mints one at the recorded scope, which is checked against the grant
// first so it can only come back as narrow as the grant allows now, and never
// wider than the token it replaces.
//
// A proxy session's upstream credential is re-derived on demand
// (GitHubUpstream, KubeconfigUpstream): a PAT or kubeconfig is opened from the
// grant's secret, an App token is minted at once at its slot's recorded scope.
// Each re-checks the grant, so a grant revoked or expired while no process held
// the lease refuses — the restored session is never served.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/hubmetrics"
)

// AppSlotRecord is the durable account of one GitHub App token a lease holds.
// It names what the token was minted for and never carries the token.
type AppSlotRecord struct {
	LeaseID    string
	GrantID    string
	Holder     string
	SecretID   string
	SecretName string

	BaseURL        string
	InstallationID int64
	// RepositoryIDs is nil for an installation-wide token.
	RepositoryIDs []int64
	// Permissions is what the first mint asked for; nil asked for every
	// permission the installation has.
	Permissions map[string]string
	// Granted is what GitHub answered the first mint with.
	Granted map[string]string
	// Summary names what the token reaches, audit-safe.
	Summary string

	// Guarded: a git proxy session presents the token, named by SessionID.
	Guarded     bool
	SessionID   string
	EnvExported bool
	// FileName is the lease file an unguarded token is delivered in.
	FileName string
	// TokenExpiresAt is when the token the workload or session holds stops
	// working at GitHub.
	TokenExpiresAt time.Time
}

// AppSlotStore persists AppSlotRecords. Optional, like LeaseStore: a broker
// whose store does not implement it keeps its slots in memory only. Every
// write after the insert is fenced on the holder.
type AppSlotStore interface {
	PutAppSlot(r AppSlotRecord) error
	ListAppSlots(leaseID string) ([]AppSlotRecord, error)
	// UpdateAppSlot rewrites a slot's guarded flag, session, export flag and
	// held-token expiry if r.Holder holds it.
	UpdateAppSlot(r AppSlotRecord) (bool, error)
	TakeAppSlots(leaseID, from, holder string) (int, error)
	DeleteAppSlots(leaseID, holder string) (int, error)
	DeleteAppSlot(leaseID, grantID, holder string) (bool, error)
}

// appSlotStore returns the store's AppSlotStore when this broker keeps lease
// records — a slot is recorded only for a lease that is.
func (b *Broker) appSlotStore() (AppSlotStore, bool) {
	if b.leaseHolder == "" {
		return nil, false
	}
	ss, ok := b.store.(AppSlotStore)
	return ss, ok
}

// slotRecord renders slot for its store. Callers hold b.mu.
func (b *Broker) slotRecord(slot *appTokenSlot) AppSlotRecord {
	return AppSlotRecord{
		LeaseID:        slot.leaseID,
		GrantID:        slot.grantID,
		Holder:         b.leaseHolder,
		SecretID:       slot.secretID,
		SecretName:     slot.secretName,
		BaseURL:        slot.scope.baseURL,
		InstallationID: slot.scope.installationID,
		RepositoryIDs:  append([]int64(nil), slot.scope.repositoryIDs...),
		Permissions:    copyPermissions(slot.scope.permissions),
		Granted:        copyPermissions(slot.scope.granted),
		Summary:        slot.scope.summary,
		Guarded:        slot.guarded,
		SessionID:      slot.sessionID,
		EnvExported:    slot.envExported,
		FileName:       slot.fileName,
		TokenExpiresAt: slot.heldExpiry(),
	}
}

// heldExpiry is when the token the workload or session holds now stops
// working: the current one, or — after a refresh that has not reached a
// sandbox's file yet — the one the file still holds. Callers hold b.mu.
func (s *appTokenSlot) heldExpiry() time.Time {
	if s.guarded || s.delivered {
		return s.current.expiresAt
	}
	for _, r := range s.retiring {
		if r.retireAfter.IsZero() {
			return r.expiresAt
		}
	}
	return s.current.expiresAt
}

// recordSlots writes the slots of a lease that was just recorded. A failure
// costs the slots their survival: the lease's own row says so.
func (b *Broker) recordSlots(slots []*appTokenSlot, names map[string]string) error {
	ss, ok := b.appSlotStore()
	if !ok || len(slots) == 0 {
		return nil
	}
	var recs []AppSlotRecord
	b.mu.Lock()
	for _, slot := range slots {
		if slot.abandoned || slot.ended {
			continue
		}
		if !slot.guarded {
			slot.fileName = names[slot.grantID]
		}
		recs = append(recs, b.slotRecord(slot))
	}
	b.mu.Unlock()
	var errs []error
	for _, r := range recs {
		if err := ss.PutAppSlot(r); err != nil {
			errs = append(errs, fmt.Errorf("app token slot %s/%s: %w", r.LeaseID, r.GrantID, err))
		}
	}
	return errors.Join(errs...)
}

// recordSlotState rewrites a slot's record after its token or its holder
// changed. Best-effort: what a failure loses is a successor's knowledge of the
// newer expiry, and a successor that re-mints early loses nothing.
func (b *Broker) recordSlotState(slot *appTokenSlot) {
	ss, ok := b.appSlotStore()
	if !ok || slot == nil {
		return
	}
	b.mu.Lock()
	if slot.ended || slot.abandoned || slot.leaseID == "" {
		b.mu.Unlock()
		return
	}
	rec := b.slotRecord(slot)
	b.mu.Unlock()
	_, _ = ss.UpdateAppSlot(rec)
}

// forgetSlotRecords deletes the records of slots that ended, fenced on this
// broker's holder: a lease another process took over keeps its slots.
func (b *Broker) forgetSlotRecords(leaseID string, grantIDs ...string) {
	ss, ok := b.appSlotStore()
	if !ok || strings.TrimSpace(leaseID) == "" {
		return
	}
	if len(grantIDs) == 0 {
		_, _ = ss.DeleteAppSlots(leaseID, b.leaseHolder)
		return
	}
	for _, g := range grantIDs {
		_, _ = ss.DeleteAppSlot(leaseID, g, b.leaseHolder)
	}
}

// restoreSlots takes over the App token slots of a lease Restore took over,
// and rebuilds them holding no token: a guarded slot is re-minted when its
// proxy session is restored (GitHubUpstream), a file slot when the keepalive
// finds it due — on the token's own recorded expiry, which is when the file in
// the workload stops working.
//
// A slot whose recorded scope is wider than its grant allows now is not
// rebuilt: its record goes, a denied secret.renew row says why, and nothing
// renews that token — the workload's copy works until its hour. Its repository
// ids are held to the grant when it is first re-minted (confirmScope).
//
// A store that cannot take over or read the records just now refuses nothing:
// the lease is marked, and retryPendingSlots tries again before a slot of it
// is needed. Callers hold slotRestoreMu.
func (b *Broker) restoreSlots(ev Event, rec LeaseRecord, from string) error {
	ss, ok := b.appSlotStore()
	if !ok {
		return nil
	}
	pending := func(from string, err error) error {
		b.mu.Lock()
		if st, ok := b.leases[rec.ID]; ok {
			st.slotsPending = &pendingSlots{ev: ev, rec: rec, from: from}
		}
		b.mu.Unlock()
		_ = b.denyf(ev, ErrGitHubAppMint,
			"the github app token slots of lease %s could not be taken over yet (will retry before a token "+
				"of it is needed): %v", rec.ID, err)
		return err
	}
	if from != b.leaseHolder {
		if _, err := ss.TakeAppSlots(rec.ID, from, b.leaseHolder); err != nil {
			return pending(from, err)
		}
	}
	rows, err := ss.ListAppSlots(rec.ID)
	if err != nil {
		return pending(b.leaseHolder, err)
	}
	b.mu.Lock()
	if st, ok := b.leases[rec.ID]; ok {
		st.slotsPending = nil
	}
	b.mu.Unlock()
	var slots []*appTokenSlot
	for _, r := range rows {
		if r.Holder != b.leaseHolder {
			continue
		}
		slotEv := ev
		slotEv.GrantID, slotEv.SecretID, slotEv.SecretName, slotEv.Kind = r.GrantID, r.SecretID, r.SecretName, KindGitHubApp
		if !slices.Contains(rec.GrantIDs, r.GrantID) {
			_, _ = ss.DeleteAppSlot(rec.ID, r.GrantID, b.leaseHolder)
			continue
		}
		if why := b.slotScopeWider(r); why != "" {
			_, _ = ss.DeleteAppSlot(rec.ID, r.GrantID, b.leaseHolder)
			hubmetrics.SessionRestores.Inc(hubmetrics.RestoreKindAppToken, hubmetrics.RestoreRefused)
			_ = b.denyf(slotEv, ErrRefreshRefused,
				"the github app token of grant %s is not renewed by the hub process that took lease %s over: %s",
				r.GrantID, rec.ID, why)
			continue
		}
		slot := newAppTokenSlot()
		slot.leaseID = rec.ID
		slot.grantID = r.GrantID
		slot.secretID = r.SecretID
		slot.secretName = r.SecretName
		slot.requester = rec.Requester
		slot.actor = rec.Actor
		slot.scope = appTokenScope{
			baseURL:        r.BaseURL,
			installationID: r.InstallationID,
			repositoryIDs:  append([]int64(nil), r.RepositoryIDs...),
			permissions:    copyPermissions(r.Permissions),
			granted:        copyPermissions(r.Granted),
			summary:        r.Summary,
		}
		slot.guarded = r.Guarded
		slot.sessionID = r.SessionID
		slot.envExported = r.EnvExported
		slot.fileName = r.FileName
		// The token itself stayed with the process that minted it. What is
		// known is when the workload's copy dies, which is what decides when
		// a file slot is due.
		slot.current = appToken{grantID: r.GrantID, secretID: r.SecretID, secretName: r.SecretName,
			baseURL: r.BaseURL, expiresAt: r.TokenExpiresAt}
		slot.delivered = true
		slot.restored = true
		slots = append(slots, slot)
		hubmetrics.SessionRestores.Inc(hubmetrics.RestoreKindAppToken, hubmetrics.RestoreRestored)
	}
	if len(slots) == 0 {
		return nil
	}
	b.mu.Lock()
	b.minted[rec.ID] = append(b.minted[rec.ID], slots...)
	b.mu.Unlock()
	return nil
}

// pendingSlots is a slot restore to try again: the lease record it was for,
// the audit row it started from, and the holder the records are taken from.
type pendingSlots struct {
	ev   Event
	rec  LeaseRecord
	from string
}

// retryPendingSlots restores the App-token slots of leaseID that Restore could
// not, if there are any. Nil once there is nothing left to restore.
func (b *Broker) retryPendingSlots(leaseID string) error {
	b.slotRestoreMu.Lock()
	defer b.slotRestoreMu.Unlock()
	b.mu.Lock()
	var p *pendingSlots
	if st, ok := b.leases[leaseID]; ok {
		p = st.slotsPending
	}
	b.mu.Unlock()
	if p == nil {
		return nil
	}
	return b.restoreSlots(p.ev, p.rec, p.from)
}

// slotScopeWider reports how a recorded slot's scope exceeds what its grant
// allows now, or "". The record was read back from a database, and a refresh
// replays it verbatim: this is what keeps an edited record from minting a
// token the grant never authorised.
func (b *Broker) slotScopeWider(r AppSlotRecord) string {
	g, err := b.store.GetGrant(r.GrantID)
	if err != nil {
		return "its grant can no longer be read"
	}
	if g.SecretID != r.SecretID {
		return "its grant now points at another secret"
	}
	if r.InstallationID <= 0 {
		return "the record names no installation"
	}
	perms, err := GitHubAppPermissions(g.Constraints)
	if err != nil {
		return "its grant's permissions no longer parse: " + err.Error()
	}
	if perms != nil {
		if r.Permissions == nil {
			return "the recorded token asked for every permission the installation has, and the grant names " +
				describePermissions(perms)
		}
		var wider []string
		for scope, level := range r.Permissions {
			if have, ok := perms[scope]; !ok || permissionRank(level) > permissionRank(have) {
				wider = append(wider, scope+":"+level)
			}
		}
		if len(wider) > 0 {
			sort.Strings(wider)
			return "the recorded scope asks for " + strings.Join(wider, ", ") + ", beyond the grant's " +
				describePermissions(perms)
		}
	}
	if len(r.RepositoryIDs) == 0 && !allowsAllRepos(g.Constraints.Repos) {
		return "the recorded token was installation-wide, and the grant names repositories"
	}
	return ""
}

// UpstreamGitHub is the credential a restored git proxy session presents
// upstream: a PAT, or an App token minted for it now.
type UpstreamGitHub struct {
	// Token is the credential, for the proxy's own use. Never logged, never
	// delivered to a sandbox by this type.
	Token string
	// ExpiresAt is when GitHub stops honouring an App token; zero for a PAT.
	ExpiresAt time.Time
	// Refresh re-mints an App token at its recorded scope; nil for a PAT.
	Refresh func(ctx context.Context, held string) (AppTokenRefresh, error)
}

// String redacts the token.
func (u UpstreamGitHub) String() string {
	return fmt.Sprintf("github upstream credential (%d bytes, expires %s) [redacted]",
		len(u.Token), u.ExpiresAt.UTC().Format(time.RFC3339))
}

// GoString mirrors String.
func (u UpstreamGitHub) GoString() string { return u.String() }

// GitHubUpstream re-derives the credential a git proxy session standing on
// grantID of leaseID presents upstream, for the hub process that took the
// lease over (Restore) and is restoring the session. sessionID names it, for
// the audit row of a re-minted App token.
//
// The grant is re-checked first. A PAT is opened from the grant's secret; an
// App token is minted at once at the slot's recorded scope — the token the
// stopped process minted is out of reach — and kept alive by the returned
// refresher, as a minted session's is.
func (b *Broker) GitHubUpstream(ctx context.Context, leaseID, grantID, sessionID string) (UpstreamGitHub, error) {
	g, s, err := b.heldGrant(leaseID, grantID)
	if err != nil {
		return UpstreamGitHub{}, err
	}
	switch s.Kind {
	case KindGitHubPAT:
		plaintext, err := b.seal.OpenEnvelope(AADFor(SetSecrets, s.ID), s.Envelope())
		if err != nil {
			return UpstreamGitHub{}, fmt.Errorf("%w: open payload for %s: %w", ErrSealFailed, s.Name, err)
		}
		token := strings.TrimSpace(string(plaintext))
		zero(plaintext)
		if token == "" {
			return UpstreamGitHub{}, wrapf(ErrMalformedPayload, "github secret %s is empty", s.Name)
		}
		return UpstreamGitHub{Token: token}, nil
	case KindGitHubApp:
		if err := b.retryPendingSlots(leaseID); err != nil {
			// Not a refusal: the store did not answer, and the caller tries
			// again.
			return UpstreamGitHub{}, fmt.Errorf("the github app token slots of lease %s could not be read yet: %w",
				leaseID, err)
		}
		slot := b.findSlot(leaseID, g.ID)
		if slot == nil {
			return UpstreamGitHub{}, wrapf(ErrRefreshRefused,
				"lease %s holds no recorded github app token slot for grant %s, so no token can be minted at "+
					"the scope the session was given", leaseID, g.ID)
		}
		b.mu.Lock()
		guarded := slot.guarded
		if guarded && sessionID != "" {
			slot.sessionID = sessionID
		}
		b.mu.Unlock()
		if !guarded {
			// The token was delivered into the workload's files, not held by
			// a session; the keepalive renews it there.
			return UpstreamGitHub{}, wrapf(ErrRefreshRefused,
				"grant %s's github app token reached lease %s as a file, not through a git proxy session", g.ID, leaseID)
		}
		got, err := b.refreshSlot(ctx, slot, "")
		if err != nil {
			return UpstreamGitHub{}, err
		}
		if got.Retire != nil {
			// A token an earlier attempt minted for this session, which no
			// session presents: the session is restored only once, with this
			// one.
			got.Retire()
		}
		return UpstreamGitHub{Token: got.Token, ExpiresAt: got.ExpiresAt, Refresh: b.slotRefresher(slot)}, nil
	default:
		return UpstreamGitHub{}, wrapf(ErrInvalidKind, "grant %s carries a %s secret, not a GitHub credential", g.ID, s.Kind)
	}
}

// KubeconfigUpstream re-derives the cluster credential a Kubernetes monitor
// session standing on grantID of leaseID spends: the grant's kubeconfig,
// minimised to its constraints exactly as the guard was given it at mint. The
// grant is re-checked first. The caller zeroes the returned document once it
// has parsed it.
func (b *Broker) KubeconfigUpstream(leaseID, grantID string) ([]byte, error) {
	g, s, err := b.heldGrant(leaseID, grantID)
	if err != nil {
		return nil, err
	}
	if s.Kind != KindKubeconfig {
		return nil, wrapf(ErrInvalidKind, "grant %s carries a %s secret, not a kubeconfig", g.ID, s.Kind)
	}
	plaintext, err := b.seal.OpenEnvelope(AADFor(SetSecrets, s.ID), s.Envelope())
	if err != nil {
		return nil, fmt.Errorf("%w: open payload for %s: %w", ErrSealFailed, s.Name, err)
	}
	defer zero(plaintext)
	return MinimizeKubeconfig(plaintext, g.Constraints)
}

// heldGrant returns a grant of a lease this broker holds, and its secret, after
// the checks Extend makes: not revoked or expired, still issued to the lease's
// requester, its secret still there. A refusal is a denied secret.renew row.
func (b *Broker) heldGrant(leaseID, grantID string) (Grant, Secret, error) {
	ev := Event{Action: ActionRenew, LeaseID: leaseID, GrantID: grantID}
	b.mu.Lock()
	st, ok := b.leases[leaseID]
	var (
		requester Requester
		carried   bool
	)
	if ok {
		requester = st.requester
		ev.Actor = st.actor
		carried = slices.Contains(st.grantIDs, grantID)
	}
	b.mu.Unlock()
	if !ok {
		return Grant{}, Secret{}, b.denyf(ev, ErrLeaseNotFound,
			"lease %s is not held by this hub process, so nothing standing on it can be re-derived", leaseID)
	}
	ev.ExecutorID, ev.ProjectID, ev.RunID = requester.ExecutorID, requester.ProjectID, requester.RunID
	if !carried {
		return Grant{}, Secret{}, b.denyf(ev, ErrInvalidGrant, "lease %s does not carry grant %s", leaseID, grantID)
	}
	if _, err := b.recheckGrants(ev, leaseID, requester, []string{grantID}, b.now()); err != nil {
		return Grant{}, Secret{}, err
	}
	g, err := b.store.GetGrant(grantID)
	if err != nil {
		return Grant{}, Secret{}, b.denyf(ev, ErrGrantNotFound, "grant %s: %v", grantID, err)
	}
	s, err := b.store.GetSecret(g.SecretID)
	if err != nil {
		return Grant{}, Secret{}, b.denyf(ev, ErrSecretNotFound, "secret %s of grant %s: %v", g.SecretID, grantID, err)
	}
	return g, s, nil
}

// SuspendLeaseTokens lets go of the App tokens a lease holds without ending the
// lease, for a process that stops serving it: shutting down gracefully, or
// handing it to the process that adopted its run. A token a proxy session
// presented is destroyed at GitHub — the session is suspended with it, and
// whoever restores the session mints its own. A token in a workload's file is
// left alone: the workload is still using it, and the new holder replaces it
// before it expires. So is a file token a refresh superseded whose successor
// the workload has not confirmed receiving: its file may still hold it, so it
// lapses at its hour rather than being destroyed under the workload. The
// slots' records stay, for the new holder.
func (b *Broker) SuspendLeaseTokens(leaseID, reason string) {
	var doomed []appToken
	b.mu.Lock()
	for _, slot := range b.minted[leaseID] {
		if slot.guarded {
			doomed = append(doomed, slot.end()...)
			continue
		}
		slot.ended = true
		slot.retiring = nil
	}
	delete(b.minted, leaseID)
	b.mu.Unlock()
	if reason == "" {
		reason = "lease handed to another hub process"
	}
	b.destroyAppTokens(context.Background(), doomed, reason)
}

// appSlotScope is how a slot's scope is written into its record's JSON. Kept
// beside the record so the two cannot drift; pkg/secretstore owns the column.
type appSlotScope struct {
	BaseURL        string  `json:"base_url"`
	InstallationID int64   `json:"installation_id"`
	RepositoryIDs  []int64 `json:"repository_ids,omitempty"`
	// Not omitempty: a nil map asked for every permission, and must not read
	// back as an empty one, or the other way round.
	Permissions map[string]string `json:"permissions"`
	Granted     map[string]string `json:"granted"`
	Summary     string            `json:"summary,omitempty"`
}

// MarshalAppSlotScope renders a record's scope for storage.
func MarshalAppSlotScope(r AppSlotRecord) (string, error) {
	b, err := json.Marshal(appSlotScope{
		BaseURL: r.BaseURL, InstallationID: r.InstallationID, RepositoryIDs: r.RepositoryIDs,
		Permissions: r.Permissions, Granted: r.Granted, Summary: r.Summary,
	})
	return string(b), err
}

// UnmarshalAppSlotScope reads a stored scope back into r.
func UnmarshalAppSlotScope(raw string, r *AppSlotRecord) error {
	var s appSlotScope
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return err
	}
	r.BaseURL, r.InstallationID, r.RepositoryIDs = s.BaseURL, s.InstallationID, s.RepositoryIDs
	r.Permissions, r.Granted, r.Summary = s.Permissions, s.Granted, s.Summary
	return nil
}

// HeldGrant returns a grant of a lease this broker holds, after the checks
// Extend makes: not revoked or expired, still issued to the lease's requester,
// its secret still there. A refusal is a denied secret.renew row. It is what a
// process restoring a proxy session reads the grant's current constraints from,
// to hold the session's recorded scope to them (Task 20383).
func (b *Broker) HeldGrant(leaseID, grantID string) (Grant, error) {
	g, _, err := b.heldGrant(leaseID, grantID)
	return g, err
}
