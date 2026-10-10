package secretbroker

// Tombstones, reasons on revocation and deletion, the offboarding withdrawal
// and the keyless broker (Task 20400).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// The memStore half of TombstoneStore.

func (m *memStore) DeleteSecretTombstoned(id string, t Tombstone) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.secrets[id]; !ok {
		return fmt.Errorf("%w: %s", ErrSecretNotFound, id)
	}
	delete(m.secrets, id)
	t.SecretID = id
	m.tombstones[id] = t
	return nil
}

func (m *memStore) GetTombstone(secretID string) (Tombstone, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tombstones[secretID]
	if !ok {
		return Tombstone{}, fmt.Errorf("%w: no tombstone for %s", ErrSecretNotFound, secretID)
	}
	return t, nil
}

// The memStore half of CausedRevoker.
func (m *memStore) RevokeGrantWithCause(id string, at time.Time, cause RevocationCause) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[id]
	if !ok {
		return wrapf(ErrGrantNotFound, "%s", id)
	}
	if !g.RevokedAt.IsZero() {
		return nil // idempotent; the original timestamp and cause stand
	}
	g.RevokedAt, g.RevokedCause = at.UTC(), cause
	m.grants[id] = g
	return nil
}

// noTombstones hides the tombstone and cause halves, standing in for a store
// that predates them: the methods below shadow the promoted ones with different
// signatures, so the type satisfies neither TombstoneStore nor CausedRevoker.
type noTombstones struct{ *memStore }

func (noTombstones) DeleteSecretTombstoned() {}
func (noTombstones) RevokeGrantWithCause()   {}

// grantPersonal hands a personal secret to a project, as its owner.
func grantPersonal(t *testing.T, b *Broker, ref, owner, project string) Grant {
	t.Helper()
	g, err := b.Grant(context.Background(), GrantRequest{
		SecretRef:   ref,
		Subject:     Subject{Type: SubjectProject, Value: project},
		Constraints: Constraints{Repos: []string{"corp/app"}},
		TTL:         time.Hour,
		Actor:       owner,
		Viewer:      Viewer{Identity: owner},
	})
	if err != nil {
		t.Fatalf("grant %s to %s: %v", ref, project, err)
	}
	return g
}

// TestDeletingAPersonalSecretAtOffboardingLeavesATombstone: the reason lands on
// the audit row and the tombstone, the cause on the tombstone, and every grant
// over the secret is revoked with it.
func TestDeletingAPersonalSecretAtOffboardingLeavesATombstone(t *testing.T) {
	b, store, audit, clock := newTestBroker(t)
	sec := mintPersonal(t, b, "alice-pat", "alice@corp", "ghp_aliceaaaaaaaaaaaaaaaaaaaaaaaa")
	g := grantPersonal(t, b, "alice-pat", "alice@corp", "/srv/shared")

	if err := b.DeleteSecretBecause(context.Background(), sec.ID, "root@corp", CauseOffboarded, "left the company, HR-882"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetSecret(sec.ID); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("the secret survived: %v", err)
	}
	tomb, ok := b.Tombstone(sec.ID)
	if !ok {
		t.Fatal("no tombstone was recorded")
	}
	if tomb.Name != "alice-pat" || tomb.Owner != "alice@corp" || tomb.Cause != CauseOffboarded ||
		tomb.DeletedBy != "root@corp" || tomb.Reason != "left the company, HR-882" || !tomb.DeletedAt.Equal(clock.Now()) {
		t.Fatalf("tombstone = %+v", tomb)
	}
	if got, _ := store.GetGrant(g.ID); got.RevokedAt.IsZero() {
		t.Fatal("the grant over the deleted secret is still live")
	}
	dels := audit.byAction(ActionDeleteSec)
	if len(dels) != 1 || !strings.Contains(dels[0].Reason, "owner offboarded: left the company") {
		t.Fatalf("secret.delete rows = %+v, want one carrying the offboarding reason", dels)
	}
}

// TestTombstoneDescriptionLeavesTheReasonOut: the description goes to the
// people who lost the credential, and the deleter's reason — for an
// offboarding, often an HR matter — is not theirs to read.
func TestTombstoneDescriptionLeavesTheReasonOut(t *testing.T) {
	tomb := Tombstone{Name: "alice-pat", Kind: KindGitHubPAT, Owner: "alice@corp", Cause: CauseOffboarded,
		DeletedAt: time.Date(2026, 10, 10, 7, 0, 0, 0, time.UTC), DeletedBy: "root@corp",
		Reason: "terminated for cause, case 77"}
	got := tomb.Describe()
	for _, want := range []string{`github_pat "alice-pat"`, "alice@corp", "2026-10-10", "offboarded"} {
		if !strings.Contains(got, want) {
			t.Errorf("description %q lacks %q", got, want)
		}
	}
	if strings.Contains(got, "terminated") || strings.Contains(got, "case 77") {
		t.Fatalf("description %q carries the deleter's reason", got)
	}
}

// TestALeaseRefusesADeletedPersonalCredentialByName is the next run of a shared
// project that had been granted a colleague's personal credential. It must be
// told which credential it lost and why — not "secret not found", and not a
// bare "grant revoked" that names nothing.
func TestALeaseRefusesADeletedPersonalCredentialByName(t *testing.T) {
	b, _, audit, clock := newTestBroker(t)
	sec := mintPersonal(t, b, "alice-pat", "alice@corp", "ghp_aliceaaaaaaaaaaaaaaaaaaaaaaaa")
	g := grantPersonal(t, b, "alice-pat", "alice@corp", "/srv/shared")
	if err := b.DeleteSecretBecause(context.Background(), sec.ID, "root@corp", CauseOffboarded, "left"); err != nil {
		t.Fatal(err)
	}
	clock.advance(time.Minute)

	lease, err := b.Lease(context.Background(), "edge-1", "/srv/shared")
	if err != nil {
		t.Fatal(err)
	}
	if !lease.Empty() {
		t.Fatalf("the deleted credential was delivered: %+v", lease.Materials)
	}
	if len(lease.Refused) != 1 {
		t.Fatalf("refused = %+v, want the one deleted credential", lease.Refused)
	}
	rc := lease.Refused[0]
	if rc.GrantID != g.ID || rc.SecretName != "alice-pat" || rc.Owner != "alice@corp" || rc.Kind != KindGitHubPAT {
		t.Fatalf("refusal = %+v", rc)
	}
	for _, want := range []string{"alice-pat", "alice@corp", "offboarded", "grant this project a credential"} {
		if !strings.Contains(rc.Reason, want) {
			t.Errorf("refusal %q lacks %q", rc.Reason, want)
		}
	}
	if strings.Contains(rc.Reason, "secret not found") || strings.Contains(rc.Reason, sec.ID) {
		t.Errorf("refusal %q is the bare form it replaces", rc.Reason)
	}

	var denied []Event
	for _, ev := range audit.byAction(ActionLease) {
		if ev.Decision == DecisionDeny && ev.GrantID == g.ID {
			denied = append(denied, ev)
		}
	}
	if len(denied) != 1 || denied[0].SecretName != "alice-pat" || !strings.Contains(denied[0].Reason, "alice-pat") {
		t.Fatalf("lease denial rows = %+v, want one naming the deleted secret", denied)
	}
}

// TestARefusalIsHandedBackOnlyForWhatTheDeletionTook: a grant somebody had
// revoked before the secret went lost nothing to the deletion, and is not put
// in front of the project — though its audit row still names the secret.
func TestARefusalIsHandedBackOnlyForWhatTheDeletionTook(t *testing.T) {
	b, _, audit, clock := newTestBroker(t)
	sec := mintPersonal(t, b, "alice-pat", "alice@corp", "ghp_aliceaaaaaaaaaaaaaaaaaaaaaaaa")
	old := grantPersonal(t, b, "alice-pat", "alice@corp", "/srv/shared")
	if err := b.Revoke(context.Background(), old.ID, "alice@corp"); err != nil {
		t.Fatal(err)
	}
	clock.advance(time.Hour)
	if err := b.DeleteSecretBecause(context.Background(), sec.ID, "root@corp", CauseOffboarded, "left"); err != nil {
		t.Fatal(err)
	}

	lease, err := b.Lease(context.Background(), "edge-1", "/srv/shared")
	if err != nil {
		t.Fatal(err)
	}
	if len(lease.Refused) != 0 {
		t.Fatalf("a grant revoked before the deletion was handed back: %+v", lease.Refused)
	}
	var named bool
	for _, ev := range audit.byAction(ActionLease) {
		if ev.GrantID == old.ID && ev.SecretName == "alice-pat" {
			named = true
		}
	}
	if !named {
		t.Fatal("the audit row for the old grant does not name the secret")
	}
}

// TestAStoreWithoutTombstonesStillDeletes: the extension is optional.
func TestAStoreWithoutTombstonesStillDeletes(t *testing.T) {
	store := newMemStore()
	cipher, err := NewCipherWithKey(testKey)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(noTombstones{store}, WithCipher(cipher))
	if err != nil {
		t.Fatal(err)
	}
	sec := mintPersonal(t, b, "alice-pat", "alice@corp", "ghp_aliceaaaaaaaaaaaaaaaaaaaaaaaa")
	if err := b.DeleteSecretBecause(context.Background(), sec.ID, "root@corp", CauseOffboarded, "left"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetSecret(sec.ID); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("the secret survived: %v", err)
	}
	if _, ok := b.Tombstone(sec.ID); ok {
		t.Fatal("a store without tombstones reported one")
	}
}

// TestRevokeBecauseRecordsTheReason.
func TestRevokeBecauseRecordsTheReason(t *testing.T) {
	b, _, audit, _ := newTestBroker(t)
	mintPersonal(t, b, "alice-pat", "alice@corp", "ghp_aliceaaaaaaaaaaaaaaaaaaaaaaaa")
	g := grantPersonal(t, b, "alice-pat", "alice@corp", "/srv/shared")
	if err := b.RevokeBecause(context.Background(), g.ID, "root@corp", "owner offboarded: left"); err != nil {
		t.Fatal(err)
	}
	revs := audit.byAction(ActionRevoke)
	if len(revs) != 1 || revs[0].Reason != "owner offboarded: left" || revs[0].Decision != DecisionAllow {
		t.Fatalf("secret.revoke rows = %+v", revs)
	}
}

// TestWithdrawRequestOnOffboard: the one withdrawal its requester does not
// make. It moves a pending request to withdrawn under the offboarding actor,
// with the reason in the note, and leaves a decided one alone.
func TestWithdrawRequestOnOffboard(t *testing.T) {
	b, store, audit, _ := newTestBroker(t)
	mintGitHub(t, b, "fleet-deploy", "ghp_sharedshared")
	req, err := b.RequestAccess(context.Background(), AccessRequestInput{
		SecretRef: "fleet-deploy", Subject: Subject{Type: SubjectProject, Value: "/srv/alice"},
		Constraints: Constraints{Repos: []string{"corp/app"}}, Justification: "deploys",
		Actor: "alice@corp",
	})
	if err != nil {
		t.Fatal(err)
	}
	// The ordinary path refuses anyone but the requester.
	if _, err := b.WithdrawRequest(context.Background(), req.ID, "root@corp"); !errors.Is(err, ErrNotRequester) {
		t.Fatalf("WithdrawRequest by an admin: %v, want ErrNotRequester", err)
	}

	got, err := b.WithdrawRequestOnOffboard(context.Background(), req.ID, "root@corp", "left the company")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != RequestWithdrawn || got.DecidedBy != "root@corp" ||
		got.DecisionNote != "withdrawn when alice@corp was offboarded" {
		t.Fatalf("withdrawn request = %+v", got)
	}
	if stored, _ := store.GetAccessRequest(req.ID); stored.State != RequestWithdrawn {
		t.Fatalf("stored state = %s", stored.State)
	}
	// The reason is the audit row's, which only admins read — not the note's,
	// which everyone who reviews requests does.
	rows := audit.byAction(ActionRequestWithdraw)
	if len(rows) == 0 || !strings.Contains(rows[len(rows)-1].Reason, "offboarded: left the company") {
		t.Fatalf("secret.request_withdraw rows = %+v", rows)
	}
	if _, err := b.WithdrawRequestOnOffboard(context.Background(), req.ID, "root@corp", "again"); !errors.Is(err, ErrRequestNotPending) {
		t.Fatalf("withdrawing a decided request: %v, want ErrRequestNotPending", err)
	}
}

// TestAKeylessBrokerAdministersButCannotSeal: what offboarding from a shell
// without CLOOP_SECRET_KEY needs, and nothing more.
func TestAKeylessBrokerAdministersButCannotSeal(t *testing.T) {
	keyed, store, _, _ := newTestBroker(t)
	sec := mintPersonal(t, keyed, "alice-pat", "alice@corp", "ghp_aliceaaaaaaaaaaaaaaaaaaaaaaaa")
	g := grantPersonal(t, keyed, "alice-pat", "alice@corp", "/srv/shared")

	t.Setenv(EnvPassphraseKey, "")
	b, err := New(store, WithoutKey())
	if err != nil {
		t.Fatalf("a keyless broker must build without CLOOP_SECRET_KEY: %v", err)
	}
	if secrets, err := b.ListSecrets(); err != nil || len(secrets) != 1 {
		t.Fatalf("list: %v %v", secrets, err)
	}
	if err := b.RevokeBecause(context.Background(), g.ID, "cli:root", "offboarded"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := b.DeleteSecretBecause(context.Background(), sec.ID, "cli:root", CauseOffboarded, "left"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	// Mint reports a seal failure, naming the missing key, and stores nothing.
	_, err = b.Mint(context.Background(), MintRequest{Name: "x", Kind: KindEnv, Payload: []byte("v"), Actor: "a"})
	if !errors.Is(err, ErrSealFailed) || !strings.Contains(err.Error(), EnvPassphraseKey) {
		t.Fatalf("mint on a keyless broker: %v, want a seal failure naming %s", err, EnvPassphraseKey)
	}
	if secrets, _ := b.ListSecrets(); len(secrets) != 0 {
		t.Fatalf("a keyless broker stored %+v", secrets)
	}
}

// TestAGrantWithdrawnAtOffboardingIsNamedWhenTheSecretGoesLater is a legal hold
// lifted days after the offboarding: the grant was revoked then, with its
// cause, and the secret is destroyed now. The project's next lease still names
// what it lost — the cause is on the grant, not inferred from timestamps.
func TestAGrantWithdrawnAtOffboardingIsNamedWhenTheSecretGoesLater(t *testing.T) {
	b, _, _, clock := newTestBroker(t)
	sec := mintPersonal(t, b, "alice-pat", "alice@corp", "ghp_aliceaaaaaaaaaaaaaaaaaaaaaaaa")
	g := grantPersonal(t, b, "alice-pat", "alice@corp", "/srv/shared")
	if err := b.RevokeWithCause(context.Background(), g.ID, "root@corp", RevokedOwnerOffboarded, "left"); err != nil {
		t.Fatal(err)
	}
	clock.advance(72 * time.Hour)
	if err := b.DeleteSecretBecause(context.Background(), sec.ID, "root@corp", CauseOffboarded, "hold lifted"); err != nil {
		t.Fatal(err)
	}
	lease, err := b.Lease(context.Background(), "edge-1", "/srv/shared")
	if err != nil {
		t.Fatal(err)
	}
	if len(lease.Refused) != 1 || lease.Refused[0].SecretName != "alice-pat" ||
		!strings.Contains(lease.Refused[0].Reason, "offboarded") {
		t.Fatalf("refused = %+v, want alice-pat named three days after its grant was withdrawn", lease.Refused)
	}
}

// TestALegalHoldStillTellsTheProject: the secret is kept, so there is no
// tombstone, and the grant over it was withdrawn when its owner left. The
// project is told by name all the same.
func TestALegalHoldStillTellsTheProject(t *testing.T) {
	b, store, _, _ := newTestBroker(t)
	sec := mintPersonal(t, b, "alice-pat", "alice@corp", "ghp_aliceaaaaaaaaaaaaaaaaaaaaaaaa")
	g := grantPersonal(t, b, "alice-pat", "alice@corp", "/srv/shared")
	if err := b.RevokeWithCause(context.Background(), g.ID, "root@corp", RevokedOwnerOffboarded, "left, legal hold"); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.GetGrant(g.ID); got.RevokedCause != RevokedOwnerOffboarded {
		t.Fatalf("revoked cause = %q, want %q", got.RevokedCause, RevokedOwnerOffboarded)
	}
	if _, err := store.GetSecret(sec.ID); err != nil {
		t.Fatalf("the held secret is gone: %v", err)
	}
	lease, err := b.Lease(context.Background(), "edge-1", "/srv/shared")
	if err != nil {
		t.Fatal(err)
	}
	if len(lease.Refused) != 1 {
		t.Fatalf("refused = %+v, want the withdrawn grant named", lease.Refused)
	}
	rc := lease.Refused[0]
	for _, want := range []string{`github_pat "alice-pat"`, "alice@corp", "withdrawn", "offboarded"} {
		if !strings.Contains(rc.Reason, want) {
			t.Errorf("refusal %q lacks %q", rc.Reason, want)
		}
	}
	if strings.Contains(rc.Reason, "legal hold") {
		t.Errorf("refusal %q carries the revoker's reason", rc.Reason)
	}
}

// TestAnExpiredGrantOverADeletedSecretIsNotHandedBack: a grant that had simply
// lapsed lost nothing to the deletion, and is not put in front of the project
// on every run.
func TestAnExpiredGrantOverADeletedSecretIsNotHandedBack(t *testing.T) {
	b, _, audit, clock := newTestBroker(t)
	sec := mintPersonal(t, b, "alice-pat", "alice@corp", "ghp_aliceaaaaaaaaaaaaaaaaaaaaaaaa")
	g := grantPersonal(t, b, "alice-pat", "alice@corp", "/srv/shared")
	clock.advance(2 * time.Hour) // the grant's hour runs out
	if err := b.DeleteSecretBecause(context.Background(), sec.ID, "root@corp", CauseOffboarded, "left"); err != nil {
		t.Fatal(err)
	}
	lease, err := b.Lease(context.Background(), "edge-1", "/srv/shared")
	if err != nil {
		t.Fatal(err)
	}
	if len(lease.Refused) != 0 {
		t.Fatalf("an expired grant was handed back: %+v", lease.Refused)
	}
	var named bool
	for _, ev := range audit.byAction(ActionLease) {
		if ev.GrantID == g.ID && ev.SecretName == "alice-pat" {
			named = true
		}
	}
	if !named {
		t.Fatal("the expired grant's audit row does not name the deleted secret")
	}
}
