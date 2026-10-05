package secretbroker

// appslots_test.go covers what a taken-over lease brings with it (Task
// 20383): its GitHub App token slots, recorded without their tokens and
// rebuilt by the process that takes the lease over — re-minted at the recorded
// scope, never wider than the grant allows now — and the PAT and kubeconfig a
// restored proxy session presents, re-derived through the broker.

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// ── memStore's AppSlotStore half ─────────────────────────────────────────────

var _ AppSlotStore = (*memStore)(nil)

func (m *memStore) PutAppSlot(r AppSlotRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.appSlots[[2]string{r.LeaseID, r.GrantID}] = r
	return nil
}

func (m *memStore) ListAppSlots(leaseID string) ([]AppSlotRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.slotErr != nil {
		return nil, m.slotErr
	}
	var out []AppSlotRecord
	for k, r := range m.appSlots {
		if leaseID == "" || k[0] == leaseID {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *memStore) UpdateAppSlot(r AppSlotRecord) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := [2]string{r.LeaseID, r.GrantID}
	cur, ok := m.appSlots[k]
	if !ok || cur.Holder != r.Holder {
		return false, nil
	}
	cur.Guarded, cur.SessionID, cur.EnvExported, cur.TokenExpiresAt = r.Guarded, r.SessionID, r.EnvExported, r.TokenExpiresAt
	cur.BaseURL, cur.InstallationID, cur.RepositoryIDs = r.BaseURL, r.InstallationID, r.RepositoryIDs
	cur.Permissions, cur.Granted, cur.Summary = r.Permissions, r.Granted, r.Summary
	m.appSlots[k] = cur
	return true, nil
}

func (m *memStore) TakeAppSlots(leaseID, from, holder string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.slotErr != nil {
		return 0, m.slotErr
	}
	n := 0
	for k, r := range m.appSlots {
		if k[0] == leaseID && r.Holder == from {
			r.Holder = holder
			m.appSlots[k] = r
			n++
		}
	}
	return n, nil
}

func (m *memStore) DeleteAppSlots(leaseID, holder string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k, r := range m.appSlots {
		if k[0] == leaseID && r.Holder == holder {
			delete(m.appSlots, k)
			n++
		}
	}
	return n, nil
}

func (m *memStore) DeleteAppSlot(leaseID, grantID, holder string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := [2]string{leaseID, grantID}
	if r, ok := m.appSlots[k]; ok && r.Holder == holder {
		delete(m.appSlots, k)
		return true, nil
	}
	return false, nil
}

func (m *memStore) slotRecord(leaseID, grantID string) (AppSlotRecord, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.appSlots[[2]string{leaseID, grantID}]
	return r, ok
}

func (m *memStore) slotCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.appSlots)
}

// ── fixture ──────────────────────────────────────────────────────────────────

// slotWorld is one control plane shared by several hub processes: a store, a
// clock, a fake GitHub, and a github_app grant to /srv/app for acme/api.
type slotWorld struct {
	setup *Broker
	store *memStore
	clock *fakeClock
	gh    *fakeGitHub
	grant Grant
}

func newSlotWorld(t *testing.T, repos, perms []string) *slotWorld {
	t.Helper()
	setup, store, _, clock := newTestBroker(t)
	gh := newFakeGitHub(InstallationRepo{ID: 1, FullName: "acme/api"}, InstallationRepo{ID: 2, FullName: "acme/web"})
	gh.clock = clock.Now
	setup.appMinter = newGitHubAppMinter(gh, clock.Now)
	sec, err := setup.Mint(context.Background(), MintRequest{
		Name: "app", Kind: KindGitHubApp, Payload: appPayloadJSON(t), Actor: "test",
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	g := grantTo(t, setup, sec.ID, "project:/srv/app", Constraints{Repos: repos, Permissions: perms}, 24*time.Hour)
	return &slotWorld{setup: setup, store: store, clock: clock, gh: gh, grant: g}
}

// process is a hub process over the world: a broker keeping lease records as
// holder, minting through the world's GitHub, guarded by guard if set.
func (w *slotWorld) process(t *testing.T, holder string, guard GitGuard) (*Broker, *recordingAuditor) {
	t.Helper()
	b, auditor := holderBroker(t, w.store, w.clock, holder)
	b.appMinter = newGitHubAppMinter(w.gh, w.clock.Now)
	b.GitGuard = guard
	return b, auditor
}

func (w *slotWorld) lease(t *testing.T, b *Broker) *Lease {
	t.Helper()
	lease, err := b.LeaseFor(context.Background(), Requester{ExecutorID: "dev1", ProjectID: "/srv/app", RunID: "run_1"}, "ui")
	if err != nil || len(lease.Materials) != 1 {
		t.Fatalf("LeaseFor = %+v, %v", lease, err)
	}
	return lease
}

// scoped returns the mint requests that delivered a token, without the
// metadata:read discovery tokens.
func (w *slotWorld) scoped() []InstallationTokenRequest {
	w.gh.mu.Lock()
	defer w.gh.mu.Unlock()
	var out []InstallationTokenRequest
	for _, c := range w.gh.creates {
		if len(c.Permissions) == 1 && c.Permissions["metadata"] == "read" {
			continue
		}
		out = append(out, c)
	}
	return out
}

func (w *slotWorld) live(token string) bool {
	w.gh.mu.Lock()
	defer w.gh.mu.Unlock()
	return w.gh.live[token]
}

// fileToken returns the token a lease's material put in its token file.
func fileToken(t *testing.T, lease *Lease) string {
	t.Helper()
	for _, m := range lease.Materials {
		for _, f := range m.Files {
			if f.Name == tokenFileName {
				return strings.TrimSpace(string(f.Content))
			}
		}
	}
	t.Fatal("the lease delivered no token file")
	return ""
}

// ── tests ────────────────────────────────────────────────────────────────────

// TestAppTokenSlotsAreRecordedWithTheirLease: the scope, the file and the
// expiry are written beside the lease record; the token is not.
func TestAppTokenSlotsAreRecordedWithTheirLease(t *testing.T) {
	w := newSlotWorld(t, []string{"acme/api"}, []string{"contents:write"})
	a, _ := w.process(t, "hub_a", nil)
	lease := w.lease(t, a)
	token := fileToken(t, lease)

	rec, ok := w.store.slotRecord(lease.ID, w.grant.ID)
	if !ok {
		t.Fatal("the lease's App token slot was not recorded")
	}
	if rec.Holder != "hub_a" || rec.InstallationID != 67890 || !reflect.DeepEqual(rec.RepositoryIDs, []int64{1}) ||
		rec.Permissions["contents"] != "write" || rec.FileName != tokenFileName || rec.Guarded ||
		rec.TokenExpiresAt.IsZero() || rec.Summary != "acme/api" {
		t.Fatalf("slot record = %+v", rec)
	}
	raw, _ := json.Marshal(rec)
	if strings.Contains(string(raw), token) {
		t.Fatalf("the slot record carries the token: %s", raw)
	}

	// A broker that keeps no lease records keeps no slots either.
	before := w.store.slotCount()
	if _, err := w.setup.LeaseFor(context.Background(), Requester{ExecutorID: "dev1", ProjectID: "/srv/app"}, "cli"); err != nil {
		t.Fatal(err)
	}
	if w.store.slotCount() != before {
		t.Fatal("a broker without lease records recorded a slot")
	}
}

// TestRestoredFileSlotRefreshesPastItsHour is the no-proxy half of item 4: the
// process that took the lease over keeps the workload's token file alive past
// GitHub's hour, minting at the recorded scope.
func TestRestoredFileSlotRefreshesPastItsHour(t *testing.T) {
	w := newSlotWorld(t, []string{"acme/*"}, []string{"contents:write"})
	a, _ := w.process(t, "hub_a", nil)
	lease := w.lease(t, a)
	first := fileToken(t, lease)
	firstScope := w.scoped()[0]
	// The installation gains a repository the glob would match now: a refresh
	// re-derived from the grant would widen; one replayed from the record
	// does not.
	w.gh.mu.Lock()
	w.gh.repos = append(w.gh.repos, InstallationRepo{ID: 3, FullName: "acme/new"})
	w.gh.mu.Unlock()

	w.clock.advance(5 * time.Minute)
	b, auditB := w.process(t, "hub_b", nil)
	taken, err := b.Restore(context.Background(), lease.ID)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if !b.HoldsFileAppTokens(lease.ID) {
		t.Fatal("the taken-over lease holds no App token file to keep alive")
	}
	if b.AppTokensDue(lease.ID) {
		t.Fatal("a token with most of its hour left is due at once")
	}
	if rec, _ := w.store.slotRecord(lease.ID, w.grant.ID); rec.Holder != "hub_b" {
		t.Fatalf("slot record holder after the takeover = %q", rec.Holder)
	}

	refreshFile := func(label string) string {
		t.Helper()
		if !b.AppTokensDue(lease.ID) {
			t.Fatalf("%s: not due", label)
		}
		fr, err := b.RefreshLeaseFiles(context.Background(), taken)
		if err != nil || fr == nil || len(fr.Files) != 1 {
			t.Fatalf("%s: RefreshLeaseFiles = %+v, %v", label, fr, err)
		}
		if fr.Files[0].Name != tokenFileName {
			t.Fatalf("%s: file %q, want the one the lease rendered", label, fr.Files[0].Name)
		}
		tok := strings.TrimSpace(string(fr.Files[0].Content))
		fr.Delivered(false)
		fr.Close()
		return tok
	}

	// Five minutes before the first token's hour runs out.
	w.clock.advance(50 * time.Minute)
	second := refreshFile("first refresh")
	if second == first || !w.live(second) {
		t.Fatalf("the refreshed token is %q (live %v)", second, w.live(second))
	}
	creates := w.scoped()
	last := creates[len(creates)-1]
	if !reflect.DeepEqual(last.RepositoryIDs, firstScope.RepositoryIDs) || !reflect.DeepEqual(last.Permissions, firstScope.Permissions) ||
		last.InstallationID != firstScope.InstallationID {
		t.Fatalf("re-minted at %+v, first minted at %+v", last, firstScope)
	}
	if rec, _ := w.store.slotRecord(lease.ID, w.grant.ID); !rec.TokenExpiresAt.After(w.clock.Now().Add(50 * time.Minute)) {
		t.Fatalf("the record still names the first token's expiry: %s", rec.TokenExpiresAt)
	}
	var takenOverRow bool
	for _, ev := range auditB.byAction(ActionRenew) {
		if ev.Decision == DecisionAllow && strings.Contains(ev.Reason, "took the lease over") {
			takenOverRow = true
		}
	}
	if !takenOverRow {
		t.Fatalf("no renew row says who re-minted: %+v", auditB.byAction(ActionRenew))
	}

	// And past the second token's hour too: the slot is a slot like any other.
	w.clock.advance(time.Hour - 5*time.Minute)
	third := refreshFile("second refresh")
	if third == second || !w.live(third) {
		t.Fatal("the second refresh did not mint a new token")
	}
	w.clock.advance(appTokenRetireGrace + time.Second)
	b.RetireSuperseded(context.Background(), lease.ID)
	if w.live(second) {
		t.Fatal("the superseded token the new holder minted was not destroyed after its grace")
	}

	// Its release ends the tokens it minted and the records with them.
	b.Release(lease.ID)
	if w.live(third) {
		t.Fatal("the release left the new holder's token live")
	}
	if _, ok := w.store.slotRecord(lease.ID, w.grant.ID); ok {
		t.Fatal("the slot record outlived its lease")
	}
}

// TestRestoredGuardedSlotIsMintedForItsSession is the proxy half: a session's
// upstream App token is minted at once at the recorded scope, and comes with a
// refresher.
func TestRestoredGuardedSlotIsMintedForItsSession(t *testing.T) {
	w := newSlotWorld(t, []string{"acme/api"}, []string{"contents:write"})
	a, _ := w.process(t, "hub_a", workingGuard())
	lease := w.lease(t, a)
	rec, ok := w.store.slotRecord(lease.ID, w.grant.ID)
	if !ok || !rec.Guarded || rec.SessionID != "sess-abc" || rec.FileName != "" {
		t.Fatalf("guarded slot record = %+v, %v", rec, ok)
	}
	firstScope := w.scoped()[0]

	b, _ := w.process(t, "hub_b", workingGuard())
	if _, err := b.Restore(context.Background(), lease.ID); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if b.HoldsFileAppTokens(lease.ID) {
		t.Fatal("a guarded slot is treated as a file the keepalive must refresh")
	}
	up, err := b.GitHubUpstream(context.Background(), lease.ID, w.grant.ID, "sess-abc")
	if err != nil {
		t.Fatalf("GitHubUpstream: %v", err)
	}
	if !w.live(up.Token) || up.Refresh == nil || up.ExpiresAt.Sub(w.clock.Now()) < 55*time.Minute {
		t.Fatalf("upstream = %v (live %v)", up, w.live(up.Token))
	}
	last := w.scoped()[len(w.scoped())-1]
	if !reflect.DeepEqual(last.RepositoryIDs, firstScope.RepositoryIDs) || !reflect.DeepEqual(last.Permissions, firstScope.Permissions) {
		t.Fatalf("re-minted at %+v, first at %+v", last, firstScope)
	}
	if strings.Contains(up.String(), up.Token) || strings.Contains(fmtGo(up), up.Token) {
		t.Fatal("UpstreamGitHub renders its token")
	}

	// The session renews past the hour through the refresher it was given.
	w.clock.advance(55 * time.Minute)
	next, err := up.Refresh(context.Background(), up.Token)
	if err != nil || next.Token == up.Token || !w.live(next.Token) {
		t.Fatalf("refresh = %v, %v", next, err)
	}
	next.Retire()
	if w.live(up.Token) {
		t.Fatal("the superseded session token was not destroyed")
	}
}

// TestRestoreDropsASlotWiderThanItsGrant: a record read back from the
// database cannot mint what the grant does not allow.
func TestRestoreDropsASlotWiderThanItsGrant(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tamper func(*AppSlotRecord)
		why    string
	}{
		{"a permission the grant never named", func(r *AppSlotRecord) {
			r.Permissions = map[string]string{"contents": "write", "administration": "write"}
		}, "administration:write"},
		{"every permission", func(r *AppSlotRecord) { r.Permissions = nil }, "every permission"},
		{"installation-wide", func(r *AppSlotRecord) { r.RepositoryIDs = nil }, "installation-wide"},
		{"a higher level", func(r *AppSlotRecord) { r.Permissions = map[string]string{"contents": "admin"} }, "contents:admin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newSlotWorld(t, []string{"acme/api"}, []string{"contents:write"})
			a, _ := w.process(t, "hub_a", nil)
			lease := w.lease(t, a)
			rec, _ := w.store.slotRecord(lease.ID, w.grant.ID)
			tc.tamper(&rec)
			_ = w.store.PutAppSlot(rec)

			b, auditB := w.process(t, "hub_b", nil)
			if _, err := b.Restore(context.Background(), lease.ID); err != nil {
				t.Fatalf("Restore: %v", err)
			}
			if b.HoldsFileAppTokens(lease.ID) {
				t.Fatal("a slot wider than its grant was rebuilt")
			}
			if _, ok := w.store.slotRecord(lease.ID, w.grant.ID); ok {
				t.Fatal("the refused slot's record was kept")
			}
			var denied bool
			for _, ev := range auditB.byAction(ActionRenew) {
				if ev.Decision == DecisionDeny && strings.Contains(ev.Reason, tc.why) {
					denied = true
				}
			}
			if !denied {
				t.Fatalf("no denied row names %q: %+v", tc.why, auditB.byAction(ActionRenew))
			}
		})
	}
}

// TestLosingTheRaceForALeaseTakesNoSlots: of two processes adopting the run,
// the one that lost the lease rebuilds nothing.
func TestLosingTheRaceForALeaseTakesNoSlots(t *testing.T) {
	w := newSlotWorld(t, []string{"acme/api"}, []string{"contents:write"})
	a, _ := w.process(t, "hub_a", nil)
	lease := w.lease(t, a)
	b, _ := w.process(t, "hub_b", nil)
	c, _ := w.process(t, "hub_c", nil)
	// Both read the record while hub_a holds it; hub_b's takeover lands
	// between hub_c's read and its conditional write.
	w.store.beforeTake = func() {
		if _, err := b.Restore(context.Background(), lease.ID); err != nil {
			t.Errorf("first Restore: %v", err)
		}
	}
	if _, err := c.Restore(context.Background(), lease.ID); !errors.Is(err, ErrLeaseMoved) {
		t.Fatalf("second Restore = %v, want ErrLeaseMoved", err)
	}
	if !b.HoldsFileAppTokens(lease.ID) {
		t.Fatal("the winner did not rebuild the slot")
	}
	if c.HoldsFileAppTokens(lease.ID) {
		t.Fatal("the process that lost the lease rebuilt its slots")
	}
	if rec, _ := w.store.slotRecord(lease.ID, w.grant.ID); rec.Holder != "hub_b" {
		t.Fatalf("slot holder = %q, want the winner", rec.Holder)
	}
	if _, err := c.GitHubUpstream(context.Background(), lease.ID, w.grant.ID, ""); !errors.Is(err, ErrLeaseNotFound) {
		t.Fatalf("the loser re-derived a credential: %v", err)
	}
}

// TestSlotRecordsEndWithTheirGrantOrLease: revocation, release and the
// janitor's retirement all take the slot records with them.
func TestSlotRecordsEndWithTheirGrantOrLease(t *testing.T) {
	t.Run("revoked grant", func(t *testing.T) {
		w := newSlotWorld(t, []string{"acme/api"}, []string{"contents:read"})
		a, _ := w.process(t, "hub_a", nil)
		lease := w.lease(t, a)
		if err := a.Revoke(context.Background(), w.grant.ID, "admin"); err != nil {
			t.Fatal(err)
		}
		if _, ok := w.store.slotRecord(lease.ID, w.grant.ID); ok {
			t.Fatal("a revoked grant's slot record survived")
		}
	})
	t.Run("retired by another process", func(t *testing.T) {
		w := newSlotWorld(t, []string{"acme/api"}, []string{"contents:read"})
		a, _ := w.process(t, "hub_a", nil)
		lease := w.lease(t, a)
		janitor, _ := w.process(t, "hub_leader", nil)
		rec, err := janitor.LeaseRecordFor(lease.ID)
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := janitor.RetireRecord(rec, "lapsed"); err != nil || !ok {
			t.Fatalf("RetireRecord = %v, %v", ok, err)
		}
		if _, ok := w.store.slotRecord(lease.ID, w.grant.ID); ok {
			t.Fatal("a retired lease's slot record survived")
		}
	})
}

// TestUpstreamCredentialsAreReDerivedFromTheGrant covers the PAT and kubeconfig
// halves: opened from the grant's secret by the process holding the lease, and
// refused once the grant is revoked.
func TestUpstreamCredentialsAreReDerivedFromTheGrant(t *testing.T) {
	setup, store, _, clock := newTestBroker(t)
	ctx := context.Background()
	pat, err := setup.Mint(ctx, MintRequest{Name: "pat", Kind: KindGitHubPAT, Payload: []byte("ghp_" + strings.Repeat("A", 36)), Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	patGrant := grantTo(t, setup, pat.ID, "project:/srv/app", Constraints{Repos: []string{"acme/*"}}, 24*time.Hour)
	kc, err := setup.Mint(ctx, MintRequest{Name: "kube", Kind: KindKubeconfig, Payload: []byte(threeContextKubeconfig), Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	kubeGrant := grantTo(t, setup, kc.ID, "project:/srv/app", Constraints{Contexts: []string{"prod"}}, 24*time.Hour)

	a, _ := holderBroker(t, store, clock, "hub_a")
	lease, err := a.LeaseFor(ctx, Requester{ExecutorID: "dev1", ProjectID: "/srv/app"}, "ui")
	if err != nil || len(lease.Materials) != 2 {
		t.Fatalf("lease = %+v, %v", lease, err)
	}
	b, _ := holderBroker(t, store, clock, "hub_b")
	if _, err := b.GitHubUpstream(ctx, lease.ID, patGrant.ID, ""); !errors.Is(err, ErrLeaseNotFound) {
		t.Fatalf("before the takeover = %v, want ErrLeaseNotFound", err)
	}
	if _, err := b.Restore(ctx, lease.ID); err != nil {
		t.Fatal(err)
	}
	up, err := b.GitHubUpstream(ctx, lease.ID, patGrant.ID, "")
	if err != nil || up.Token != "ghp_"+strings.Repeat("A", 36) || up.Refresh != nil || !up.ExpiresAt.IsZero() {
		t.Fatalf("PAT upstream = %v, %v", up, err)
	}
	doc, err := b.KubeconfigUpstream(lease.ID, kubeGrant.ID)
	if err != nil {
		t.Fatalf("KubeconfigUpstream: %v", err)
	}
	if !strings.Contains(string(doc), "prod.example.test") || strings.Contains(string(doc), "staging.example.test") {
		t.Fatalf("the re-derived kubeconfig is not minimised to the grant:\n%s", doc)
	}
	if _, err := b.KubeconfigUpstream(lease.ID, patGrant.ID); !errors.Is(err, ErrInvalidKind) {
		t.Fatalf("a PAT grant as a kubeconfig = %v", err)
	}
	if _, err := b.GitHubUpstream(ctx, lease.ID, "grant_not_in_lease", ""); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("a grant the lease does not carry = %v", err)
	}

	if err := setup.Revoke(ctx, patGrant.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.GitHubUpstream(ctx, lease.ID, patGrant.ID, ""); !errors.Is(err, ErrGrantRevoked) {
		t.Fatalf("after the revocation = %v, want ErrGrantRevoked", err)
	}
}

func fmtGo(v any) string {
	if g, ok := v.(interface{ GoString() string }); ok {
		return g.GoString()
	}
	return ""
}

// TestRestoredSlotIsHeldToItsGrantsRepositories: a refresh replays a slot's
// repository ids, and a restored slot's came from a record another process
// wrote. Before its first token is minted they are held to what the grant
// admits in the installation now — an id the grant never admitted is dropped,
// and a record naming none it admits is refused — because a token delivered
// into a workload's file answers to no proxy's allowlist.
func TestRestoredSlotIsHeldToItsGrantsRepositories(t *testing.T) {
	takeOver := func(t *testing.T, ids []int64) (*slotWorld, *Broker, *recordingAuditor, *Lease) {
		t.Helper()
		w := newSlotWorld(t, []string{"acme/api"}, []string{"contents:write"})
		a, _ := w.process(t, "hub_a", nil)
		lease := w.lease(t, a)
		// Edited underneath the broker while no process held the lease.
		rec, _ := w.store.slotRecord(lease.ID, w.grant.ID)
		rec.RepositoryIDs, rec.Summary = ids, "acme/api|acme/web"
		if err := w.store.PutAppSlot(rec); err != nil {
			t.Fatal(err)
		}
		b, audit := w.process(t, "hub_b", nil)
		taken, err := b.Restore(context.Background(), lease.ID)
		if err != nil {
			t.Fatalf("Restore: %v", err)
		}
		w.clock.advance(55 * time.Minute)
		return w, b, audit, taken
	}

	t.Run("an id the grant never admitted is dropped", func(t *testing.T) {
		w, b, audit, taken := takeOver(t, []int64{1, 2})
		fr, err := b.RefreshLeaseFiles(context.Background(), taken)
		if err != nil || fr == nil || len(fr.Files) != 1 {
			t.Fatalf("RefreshLeaseFiles = %+v, %v", fr, err)
		}
		fr.Delivered(false)
		fr.Close()
		creates := w.scoped()
		if last := creates[len(creates)-1]; !reflect.DeepEqual(last.RepositoryIDs, []int64{1}) {
			t.Fatalf("re-minted for repositories %v, want only the grant's [1]", last.RepositoryIDs)
		}
		if rec, _ := w.store.slotRecord(taken.ID, w.grant.ID); !reflect.DeepEqual(rec.RepositoryIDs, []int64{1}) ||
			rec.Summary != "acme/api" {
			t.Fatalf("the record was not narrowed with the slot: %+v", rec)
		}
		var said bool
		for _, ev := range audit.byAction(ActionRenew) {
			if ev.Decision == DecisionAllow && strings.Contains(ev.Reason, "does not admit now dropped") {
				said = true
			}
		}
		if !said {
			t.Fatalf("no renew row says a repository was dropped: %+v", audit.byAction(ActionRenew))
		}
	})
	t.Run("none admitted is refused", func(t *testing.T) {
		w, b, _, taken := takeOver(t, []int64{2})
		before := len(w.scoped())
		fr, err := b.RefreshLeaseFiles(context.Background(), taken)
		if err != nil || fr == nil || len(fr.Refused) != 1 || len(fr.Files) != 0 {
			t.Fatalf("RefreshLeaseFiles = %+v, %v; want the grant's token refused", fr, err)
		}
		fr.Close()
		if len(w.scoped()) != before {
			t.Fatal("a token was minted for repositories the grant does not admit")
		}
	})
}

// TestSlotRestoreRetriesAfterAStoreError: a takeover that cannot read the
// lease's slot records refuses nothing — the lease is taken, and the slots are
// restored as soon as the store answers, before any of them is needed.
func TestSlotRestoreRetriesAfterAStoreError(t *testing.T) {
	w := newSlotWorld(t, []string{"acme/api"}, []string{"contents:write"})
	a, _ := w.process(t, "hub_a", nil)
	lease := w.lease(t, a)
	b, _ := w.process(t, "hub_b", nil)

	w.store.mu.Lock()
	w.store.slotErr = errors.New("database is locked")
	w.store.mu.Unlock()
	taken, err := b.Restore(context.Background(), lease.ID)
	if err != nil {
		t.Fatalf("Restore with the slot records unreadable = %v", err)
	}
	w.clock.advance(55 * time.Minute)
	if !b.HoldsFileAppTokens(lease.ID) {
		t.Fatal("the keepalive was told the lease holds no token file while its slots could not be read")
	}
	if _, err := b.RefreshLeaseFiles(context.Background(), taken); err == nil || errors.Is(err, ErrRefreshRefused) {
		t.Fatalf("RefreshLeaseFiles with the slots unread = %v, want a retryable error", err)
	}
	if _, err := b.GitHubUpstream(context.Background(), lease.ID, w.grant.ID, ""); err == nil ||
		errors.Is(err, ErrRefreshRefused) {
		t.Fatalf("GitHubUpstream with the slots unread = %v, want a retryable error", err)
	}

	w.store.mu.Lock()
	w.store.slotErr = nil
	w.store.mu.Unlock()
	if !b.AppTokensDue(lease.ID) {
		t.Fatal("the restored slot is not due once the store answers")
	}
	fr, err := b.RefreshLeaseFiles(context.Background(), taken)
	if err != nil || fr == nil || len(fr.Files) != 1 {
		t.Fatalf("RefreshLeaseFiles once the store answers = %+v, %v", fr, err)
	}
	fr.Close()
	if rec, _ := w.store.slotRecord(lease.ID, w.grant.ID); rec.Holder != "hub_b" {
		t.Fatalf("slot holder = %q, want the process that took the lease over", rec.Holder)
	}
}
