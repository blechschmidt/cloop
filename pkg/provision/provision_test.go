package provision

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/hometest"
	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/offboard"
	"github.com/blechschmidt/cloop/pkg/rolestore"
	"github.com/blechschmidt/cloop/pkg/scim"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// pkg/offboard reaches pkg/multiui, which owns ~/.cloop/projects.json.
func TestMain(m *testing.M) { os.Exit(hometest.Isolate(m)) }

const (
	aliceEmail = "alice@example.com"
	aliceSub   = "sub-alice"
	aliceOID   = "6f9a0c3e-6c1b-4b7e-9d36-0a5b5c3f1e01"
	bobEmail   = "bob@example.com"
	bobSub     = "sub-bob"
	testBase   = "https://hub.example.com/scim/v2"
	entra      = "entra"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

// ── fakes ───────────────────────────────────────────────────────────────────

type fakeLeases struct {
	mu       sync.Mutex
	live     []offboard.LeaseRef
	released []string
}

func (l *fakeLeases) LiveLeases() []offboard.LeaseRef {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]offboard.LeaseRef(nil), l.live...)
}

func (l *fakeLeases) Release(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.released = append(l.released, id)
	kept := l.live[:0]
	for _, x := range l.live {
		if x.ID != id {
			kept = append(kept, x)
		}
	}
	l.live = kept
}

type fakeTasks struct {
	mu      sync.Mutex
	running map[string][]offboard.TaskRef
	stopped []string
}

func (t *fakeTasks) Running(path string) ([]offboard.TaskRef, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]offboard.TaskRef(nil), t.running[path]...), nil
}

func (t *fakeTasks) Stop(ref offboard.TaskRef, actor, reason string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopped = append(t.stopped, ref.ProjectPath)
	delete(t.running, ref.ProjectPath)
	return nil
}

type fakeHub struct {
	mu       sync.Mutex
	leases   *fakeLeases
	tasks    *fakeTasks
	projects []multiui.ProjectEntry
	severed  []Severance
	changed  int
}

func (h *fakeHub) Collaborators(db *statedb.DB) offboard.Options {
	secrets, _ := offboard.StoreSecrets(db)
	return offboard.Options{
		Leases: h.leases, Tasks: h.tasks, Projects: offboard.RegistryProjects(h.projects), Secrets: secrets,
	}
}

func (h *fakeHub) Severed(v Severance) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.severed = append(h.severed, v)
}

func (h *fakeHub) DirectoryChanged() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.changed++
}

// ── the world ───────────────────────────────────────────────────────────────

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// world is a hub with alice — whom the identity provider is about to
// deactivate — and bob, who stays, and everything each holds.
type world struct {
	t      *testing.T
	db     *statedb.DB
	svc    *Service
	hub    *fakeHub
	dir    *Directory
	clk    *clock
	broker *secretbroker.Broker
	mgr    *apitoken.Manager

	aliceToken, aliceGlasses, bobToken string
	aliceSecret                        secretbroker.Secret
	aliceGrant, bobGrant               secretbroker.Grant
}

func newWorld(t *testing.T, claim MatchClaim) *world {
	t.Helper()
	db := statedbtest.Open(t)
	clk := &clock{t: time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)}
	w := &world{t: t, db: db, clk: clk}
	w.hub = &fakeHub{
		leases: &fakeLeases{live: []offboard.LeaseRef{
			{ID: "lease-alice", ProjectID: "/srv/alice", ExecutorID: "edge-1"},
			{ID: "lease-bob", ProjectID: "/srv/bob", ExecutorID: "edge-1"},
		}},
		tasks: &fakeTasks{running: map[string][]offboard.TaskRef{
			"/srv/alice": {{ProjectPath: "/srv/alice", ID: 7, Title: "train", Status: "in_progress"}},
			"/srv/bob":   {{ProjectPath: "/srv/bob", ID: 3, Title: "lint", Status: "in_progress"}},
		}},
		projects: []multiui.ProjectEntry{
			{Name: "alice", Path: "/srv/alice", Owner: aliceEmail},
			{Name: "bob", Path: "/srv/bob", Owner: bobEmail},
		},
	}

	// Sessions: alice in a browser and a terminal, bob in a browser.
	w.putSession("s-alice", aliceSub, aliceEmail, aliceEmail, aliceOID)
	w.putSession("s-alice-cli", aliceSub, aliceEmail, aliceEmail, aliceOID)
	w.putSession("s-bob", bobSub, bobEmail, bobEmail, "")

	store, err := apitoken.NewSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if w.mgr, err = apitoken.NewManager(store); err != nil {
		t.Fatal(err)
	}
	w.aliceToken = w.mint("alice-ci", "", &apitoken.Owner{Sub: aliceSub, Email: aliceEmail})
	w.aliceGlasses = w.mint("alice-glasses", apitoken.KindGlasses, &apitoken.Owner{Sub: aliceSub, Email: aliceEmail})
	w.bobToken = w.mint("bob-ci", "", &apitoken.Owner{Sub: bobSub, Email: bobEmail})

	sstore, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := secretbroker.NewCipherWithKey(testKey)
	if err != nil {
		t.Fatal(err)
	}
	w.broker, err = secretbroker.New(sstore, secretbroker.WithCipher(cipher),
		secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	w.aliceSecret, err = w.broker.Mint(ctx, secretbroker.MintRequest{Name: "alice-pat", Kind: secretbroker.KindGitHubPAT,
		Payload: []byte("ghp_ALICEALICEALICEALICEALICEALICE0000"), Actor: "seed", Owner: aliceEmail, Personal: true})
	if err != nil {
		t.Fatal(err)
	}
	bobSecret, err := w.broker.Mint(ctx, secretbroker.MintRequest{Name: "bob-pat", Kind: secretbroker.KindGitHubPAT,
		Payload: []byte("ghp_BOBBOBBOBBOBBOBBOBBOBBOBBOBBOB0000"), Actor: "seed", Owner: bobEmail, Personal: true})
	if err != nil {
		t.Fatal(err)
	}
	grant := func(sec secretbroker.Secret, project, as string) secretbroker.Grant {
		g, err := w.broker.Grant(ctx, secretbroker.GrantRequest{SecretRef: sec.ID,
			Subject:     secretbroker.Subject{Type: secretbroker.SubjectProject, Value: project},
			Constraints: secretbroker.Constraints{Repos: []string{"corp/app"}}, TTL: 24 * time.Hour,
			Actor: as, Viewer: secretbroker.Viewer{Identity: as}})
		if err != nil {
			t.Fatalf("grant: %v", err)
		}
		return g
	}
	// alice's PAT granted to a project bob runs: the colleague's run that
	// spends a deactivated person's credential.
	w.aliceGrant = grant(w.aliceSecret, "/srv/bob", aliceEmail)
	w.bobGrant = grant(bobSecret, "/srv/bob", bobEmail)

	if w.dir, err = NewDirectory(db, claim, WithDirectoryClock(clk.now)); err != nil {
		t.Fatal(err)
	}
	w.svc = &Service{DB: db, Config: Config{MatchClaim: claim}, Directory: w.dir, Hub: w.hub, Now: clk.now}
	return w
}

func (w *world) putSession(id, sub, email, username, oid string) {
	w.t.Helper()
	now := time.Now()
	if err := w.db.PutSession(statedb.SessionRow{ID: id, Subject: sub, Email: email, OwnerKey: email,
		Username: username, OID: oid, IssuedAt: now, LastSeen: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) mint(name, kind string, owner *apitoken.Owner) string {
	w.t.Helper()
	m, err := w.mgr.Mint(apitoken.MintOptions{Name: name, Roles: []string{"operator"}, Kind: kind, Owner: owner,
		ExpiresAt: time.Now().Add(24 * time.Hour)})
	if err != nil {
		w.t.Fatal(err)
	}
	return m.Plaintext
}

var actor = Actor{CredentialID: "c1", Name: entra}

func (w *world) create(body string) map[string]any {
	w.t.Helper()
	res, err := w.svc.CreateUser(context.Background(), actor, []byte(body), testBase)
	if err != nil {
		w.t.Fatalf("CreateUser: %v", err)
	}
	if res.Status != http.StatusCreated {
		w.t.Fatalf("CreateUser status %d", res.Status)
	}
	return res.Resource
}

func (w *world) patch(id, body string) (Result, error) {
	w.t.Helper()
	return w.svc.PatchUser(context.Background(), actor, id, []byte(body), "", testBase)
}

func (w *world) mustPatch(id, body string) Result {
	w.t.Helper()
	res, err := w.patch(id, body)
	if err != nil {
		w.t.Fatalf("PatchUser: %v", err)
	}
	return res
}

func (w *world) tokenErr(raw string) error {
	w.t.Helper()
	_, err := w.mgr.Verify(raw)
	return err
}

func (w *world) denies() map[string]statedb.RoleBindingRow {
	w.t.Helper()
	rows, err := w.db.ListRoleBindings()
	if err != nil {
		w.t.Fatal(err)
	}
	out := map[string]statedb.RoleBindingRow{}
	for _, r := range rows {
		if r.Effect == statedb.RoleEffectDeny {
			out[r.Claim+"="+r.Value] = r
		}
	}
	return out
}

// secretExists reports whether a broker secret is still stored.
func (w *world) secretExists(id string) bool {
	w.t.Helper()
	all, err := w.broker.ListSecrets()
	if err != nil {
		w.t.Fatal(err)
	}
	for _, s := range all {
		if s.ID == id {
			return true
		}
	}
	return false
}

func (w *world) grant(id string) secretbroker.Grant {
	w.t.Helper()
	gs, err := w.broker.ListGrants(secretbroker.GrantFilter{})
	if err != nil {
		w.t.Fatal(err)
	}
	for _, g := range gs {
		if g.ID == id {
			return g
		}
	}
	w.t.Fatalf("grant %s not found", id)
	return secretbroker.Grant{}
}

func (w *world) sessionIDs() []string {
	w.t.Helper()
	rows, err := w.db.ListSessions()
	if err != nil {
		w.t.Fatal(err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.ID)
	}
	sort.Strings(out)
	return out
}

func (w *world) audit(action string) []map[string]any {
	w.t.Helper()
	evs, _, err := w.db.ListAuditEvents(statedb.AuditFilter{EventType: action, Limit: 100})
	if err != nil {
		w.t.Fatal(err)
	}
	var out []map[string]any
	for _, ev := range evs {
		var p map[string]any
		_ = json.Unmarshal([]byte(ev.Payload), &p)
		p["_actor"] = ev.Actor
		out = append(out, p)
	}
	return out
}

const aliceUser = `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"alice@example.com",
	"externalId":"` + aliceOID + `","active":true,
	"emails":[{"primary":true,"type":"work","value":"alice@example.com"}],
	"name":{"givenName":"Alice","familyName":"Example"}}`

const entraDisable = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
	"Operations":[{"op":"Replace","path":"active","value":"False"}]}`

const entraEnable = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
	"Operations":[{"op":"Replace","path":"active","value":"True"}]}`

// ── credentials ─────────────────────────────────────────────────────────────

func TestCredentialLifecycle(t *testing.T) {
	db := statedbtest.Open(t)
	clk := &clock{t: time.Now()}
	v := &Verifier{DB: db, Now: clk.now}
	ac := AdminContext{Actor: "cli:root", Reason: "set up provisioning", Via: "cli"}

	if _, err := MintCredential(db, "not a name!", ac, clk.now()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a malformed name was accepted: %v", err)
	}
	m, err := MintCredential(db, entra, ac, clk.now())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(m.Plaintext, CredentialPrefix) {
		t.Fatalf("plaintext %q lacks the prefix", m.Plaintext)
	}
	if _, err := MintCredential(db, entra, ac, clk.now()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a second live credential with one name was accepted: %v", err)
	}
	got, err := v.Verify(m.Plaintext)
	if err != nil || got.Actor.Label() != "scim:entra" || got.Previous {
		t.Fatalf("Verify = %+v, %v", got, err)
	}
	// Nothing stored can be presented: the row holds an HMAC, not the secret.
	row, _ := db.GetSCIMCredential(m.Row.ID)
	if strings.Contains(row.SecretHash, strings.TrimPrefix(m.Plaintext, CredentialPrefix+m.Row.ID+"_")) {
		t.Fatal("the secret is stored in the clear")
	}
	wrong := m.Plaintext[:len(m.Plaintext)-1] + "0"
	if wrong == m.Plaintext {
		wrong = m.Plaintext[:len(m.Plaintext)-1] + "1"
	}
	for _, bad := range []string{"", "cloop_pat_0123456789abcdef_" + strings.Repeat("a", 64), wrong} {
		if _, err := v.Verify(bad); err == nil {
			t.Fatalf("Verify(%.20q) succeeded", bad)
		}
	}

	// Rotation with a grace period: both secrets work until it ends.
	rot, err := RotateCredential(db, entra, time.Hour, ac, clk.now())
	if err != nil {
		t.Fatal(err)
	}
	if rot.Row.ID != m.Row.ID {
		t.Fatal("rotation changed the credential's id")
	}
	if got, err := v.Verify(m.Plaintext); err != nil || !got.Previous {
		t.Fatalf("the replaced secret is refused inside its grace: %+v %v", got, err)
	}
	if _, err := v.Verify(rot.Plaintext); err != nil {
		t.Fatalf("the new secret is refused: %v", err)
	}
	clk.advance(61 * time.Minute)
	if _, err := v.Verify(m.Plaintext); !errors.Is(err, ErrBadCredential) {
		t.Fatalf("the replaced secret outlived its grace: %v", err)
	}
	// Rotation without one ends the old secret at once.
	rot2, err := RotateCredential(db, m.Row.ID, 0, ac, clk.now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(rot.Plaintext); !errors.Is(err, ErrBadCredential) {
		t.Fatalf("a rotation without grace left the old secret working: %v", err)
	}
	if _, err := RotateCredential(db, entra, MaxGrace+time.Hour, ac, clk.now()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an over-long grace was accepted: %v", err)
	}

	// Revocation ends both secrets: the current one is told it was revoked,
	// and the one a rotation replaced is no longer a secret of anything.
	rot3, err := RotateCredential(db, entra, time.Hour, ac, clk.now())
	if err != nil {
		t.Fatal(err)
	}
	if _, revoked, err := RevokeCredential(db, entra, ac, clk.now()); err != nil || !revoked {
		t.Fatalf("RevokeCredential: %v %v", revoked, err)
	}
	if _, err := v.Verify(rot3.Plaintext); !errors.Is(err, ErrRevoked) {
		t.Fatalf("a revoked credential: %v", err)
	}
	if _, err := v.Verify(rot2.Plaintext); err == nil {
		t.Fatal("a revoked credential's previous secret still works")
	}
	if _, revoked, err := RevokeCredential(db, m.Row.ID, ac, clk.now()); err != nil || revoked {
		t.Fatalf("a second revocation: %v %v", revoked, err)
	}
	// The name is free again.
	if _, err := MintCredential(db, entra, ac, clk.now()); err != nil {
		t.Fatalf("the name of a revoked credential cannot be reused: %v", err)
	}
	for _, action := range []string{"scim.credential_create", "scim.credential_rotate", "scim.credential_revoke"} {
		evs, _, _ := db.ListAuditEvents(statedb.AuditFilter{EventType: action, Limit: 10})
		if len(evs) == 0 {
			t.Errorf("no %s row", action)
		}
		for _, ev := range evs {
			if strings.Contains(ev.Payload, CredentialPrefix) {
				t.Errorf("%s carries a credential: %s", action, ev.Payload)
			}
		}
	}
}

// ── deactivation ────────────────────────────────────────────────────────────

// TestDeactivationSuspendsInOneTransaction is the headline: Entra's PATCH
// with active "False" severs everything alice can use, suspends the grants
// over her personal secrets, and keeps what she stored.
func TestDeactivationSuspendsInOneTransaction(t *testing.T) {
	w := newWorld(t, MatchEmail)
	id := w.create(aliceUser)["id"].(string)

	res := w.mustPatch(id, entraDisable)
	if res.Status != http.StatusOK || res.Resource["active"] != false {
		t.Fatalf("PATCH answered %d active=%v", res.Status, res.Resource["active"])
	}

	// Deny bindings on her email and on the subject resolved from it.
	denies := w.denies()
	for _, key := range []string{"email=" + aliceEmail, "sub=" + aliceSub} {
		d, ok := denies[key]
		if !ok {
			t.Fatalf("no deny binding %s; have %v", key, denies)
		}
		if d.CreatedBy != "scim:entra" {
			t.Errorf("deny %s written by %q, want scim:entra", key, d.CreatedBy)
		}
	}
	if _, ok := denies["email="+bobEmail]; ok {
		t.Fatal("bob was denied")
	}
	// Sessions, the API token and the glasses link.
	if got := w.sessionIDs(); len(got) != 1 || got[0] != "s-bob" {
		t.Fatalf("sessions left: %v", got)
	}
	if !errors.Is(w.tokenErr(w.aliceToken), apitoken.ErrRevoked) ||
		!errors.Is(w.tokenErr(w.aliceGlasses), apitoken.ErrRevoked) {
		t.Fatal("alice's API token or glasses link survived")
	}
	if err := w.tokenErr(w.bobToken); err != nil {
		t.Fatalf("bob's token was revoked: %v", err)
	}
	// Her grant is suspended, not revoked; bob's is untouched; her secret is kept.
	if g := w.grant(w.aliceGrant.ID); g.SuspendedAt.IsZero() || !g.RevokedAt.IsZero() {
		t.Fatalf("alice's grant: suspended %v revoked %v", g.SuspendedAt, g.RevokedAt)
	}
	if g := w.grant(w.bobGrant.ID); !g.SuspendedAt.IsZero() {
		t.Fatal("bob's grant was suspended")
	}
	if !w.secretExists(w.aliceSecret.ID) {
		t.Fatal("alice's personal secret was destroyed by a suspension")
	}
	// Her lease and running task end; bob's do not.
	if got := w.hub.leases.released; len(got) != 1 || got[0] != "lease-alice" {
		t.Fatalf("leases released: %v", got)
	}
	if got := w.hub.tasks.stopped; len(got) != 1 || got[0] != "/srv/alice" {
		t.Fatalf("tasks stopped: %v", got)
	}
	// The hub was told what to stop honouring.
	if len(w.hub.severed) != 1 {
		t.Fatalf("severances: %+v", w.hub.severed)
	}
	sv := w.hub.severed[0]
	if !sv.RoleBindings || len(sv.Tokens) != 2 || len(sv.GrantsSuspended) != 1 || len(sv.Sessions) != 2 {
		t.Fatalf("severance = %+v", sv)
	}
	// One audit row says all of it, as scim:entra.
	rows := w.audit("scim.user_suspend")
	if len(rows) != 1 || rows[0]["_actor"] != "scim:entra" {
		t.Fatalf("scim.user_suspend rows: %v", rows)
	}
	for _, k := range []string{"denies_written", "sessions", "api_tokens", "glasses", "grants_suspended", "leases", "tasks"} {
		if l, _ := rows[0][k].([]any); len(l) == 0 {
			t.Errorf("scim.user_suspend.%s is empty: %v", k, rows[0])
		}
	}
	// A suspended grant is refused by name at the colleague's next lease.
	lease, err := w.broker.LeaseFor(context.Background(), secretbroker.Requester{ExecutorID: "edge-1",
		ProjectID: "/srv/bob", RunID: "run-1"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(lease.Materials) != 1 {
		t.Fatalf("bob's run got %d materials, want only bob's own", len(lease.Materials))
	}
	if len(lease.Refused) != 1 || !strings.Contains(lease.Refused[0].Reason, "suspended") {
		t.Fatalf("the project was not told it lost alice's credential: %+v", lease.Refused)
	}
}

// TestDeactivationIsIdempotent: a retried deactivation changes nothing.
func TestDeactivationIsIdempotent(t *testing.T) {
	w := newWorld(t, MatchEmail)
	id := w.create(aliceUser)["id"].(string)
	first := w.mustPatch(id, entraDisable)
	second := w.mustPatch(id, entraDisable)
	if second.Version != first.Version {
		t.Fatalf("a retried deactivation wrote a new version: %d then %d", first.Version, second.Version)
	}
	if n := len(w.audit("scim.user_suspend")); n != 1 {
		t.Fatalf("%d scim.user_suspend rows, want 1", n)
	}
	if n := len(w.hub.severed); n != 1 {
		t.Fatalf("%d severances, want 1", n)
	}
	// Okta's PUT of the same inactive user is no change either.
	put := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"` + id + `",` + aliceUser[strings.Index(aliceUser, `"userName"`):]
	put = strings.Replace(put, `"active":true`, `"active":false`, 1)
	res, err := w.svc.ReplaceUser(context.Background(), actor, id, []byte(put), "", testBase)
	if err != nil {
		t.Fatal(err)
	}
	if res.Resource["active"] != false || len(w.audit("scim.user_suspend")) != 1 {
		t.Fatalf("Okta's PUT of an inactive user suspended again: %v", res.Resource)
	}
}

// TestReactivationLiftsOnlyWhatTheSuspensionWrote: the lift takes back the
// suspension's own deny bindings and grant suspensions, leaves a deny an
// administrator wrote, and restores nothing the suspension destroyed.
func TestReactivationLiftsOnlyWhatTheSuspensionWrote(t *testing.T) {
	w := newWorld(t, MatchEmail)
	// An administrator demoted alice's subject before the identity provider
	// did anything: that deny is theirs.
	adminDeny, err := rolestore.RowFor(authz.Binding{Claim: authz.ClaimSub, Value: aliceSub, Deny: true},
		"INC-1 investigation", "cli:root", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.db.PutRoleBinding(adminDeny); err != nil {
		t.Fatal(err)
	}
	id := w.create(aliceUser)["id"].(string)
	w.mustPatch(id, entraDisable)
	if d := w.denies()["sub="+aliceSub]; d.CreatedBy != "cli:root" {
		t.Fatalf("the suspension took over the administrator's deny: %+v", d)
	}

	res := w.mustPatch(id, entraEnable)
	if res.Resource["active"] != true {
		t.Fatalf("still inactive: %v", res.Resource)
	}
	denies := w.denies()
	if _, ok := denies["email="+aliceEmail]; ok {
		t.Fatal("the suspension's deny on the email survived the lift")
	}
	if _, ok := denies["sub="+aliceSub]; !ok {
		t.Fatal("the lift removed the administrator's deny")
	}
	if g := w.grant(w.aliceGrant.ID); !g.SuspendedAt.IsZero() {
		t.Fatal("the grant is still suspended")
	}
	// Destroyed stays destroyed.
	if !errors.Is(w.tokenErr(w.aliceToken), apitoken.ErrRevoked) {
		t.Fatal("a reactivation restored a revoked API token")
	}
	if got := w.sessionIDs(); len(got) != 1 {
		t.Fatalf("sessions after the lift: %v", got)
	}
	rows := w.audit("scim.user_reactivate")
	if len(rows) != 1 {
		t.Fatalf("scim.user_reactivate rows: %v", rows)
	}
	if l, _ := rows[0]["denies_lifted"].([]any); len(l) != 1 {
		t.Fatalf("denies_lifted = %v", rows[0])
	}
}

// TestADenyRewrittenDuringSuspensionIsKept: an administrator who writes the
// same deny while the account is suspended owns it from then on.
func TestADenyRewrittenDuringSuspensionIsKept(t *testing.T) {
	w := newWorld(t, MatchEmail)
	id := w.create(aliceUser)["id"].(string)
	w.mustPatch(id, entraDisable)
	row, err := rolestore.RowFor(authz.Binding{Claim: authz.ClaimEmail, Value: aliceEmail, Deny: true},
		"terminated, HR-12", "cli:root", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.db.PutRoleBinding(row); err != nil {
		t.Fatal(err)
	}
	w.mustPatch(id, entraEnable)
	if _, ok := w.denies()["email="+aliceEmail]; !ok {
		t.Fatal("the lift removed a deny an administrator re-wrote")
	}
	rows := w.audit("scim.user_reactivate")
	if l, _ := rows[0]["denies_kept"].([]any); len(l) != 1 {
		t.Fatalf("denies_kept = %v", rows[0])
	}
}

// ── ambiguity ───────────────────────────────────────────────────────────────

func TestAmbiguousMatchesAreRefused(t *testing.T) {
	w := newWorld(t, MatchEmail)
	w.create(aliceUser)

	// A second provisioned user with the same email would be the same hub
	// identity: refused.
	second := strings.Replace(aliceUser, `"userName":"alice@example.com"`, `"userName":"alice2"`, 1)
	second = strings.Replace(second, aliceOID, "other", 1)
	_, err := w.svc.CreateUser(context.Background(), actor, []byte(second), testBase)
	var se *scim.Error
	if !errors.As(err, &se) || se.Status != http.StatusConflict || se.Type != scim.ErrUniqueness {
		t.Fatalf("a second user matching alice's email: %v", err)
	}

	// Two accounts on the hub share carol's email: the directory cannot say
	// which one the provider deactivated.
	w.putSession("s-carol-1", "sub-carol-1", "carol@example.com", "", "")
	w.putSession("s-carol-2", "sub-carol-2", "carol@example.com", "", "")
	carolTok := w.mint("carol-2", "", &apitoken.Owner{Sub: "sub-carol-2"})
	id := w.create(`{"userName":"carol@example.com","active":true}`)["id"].(string)
	w.mustPatch(id, entraDisable)

	denies := w.denies()
	if _, ok := denies["email=carol@example.com"]; !ok {
		t.Fatal("the matched claim was not denied: an ambiguous match must fail closed on it")
	}
	for _, sub := range []string{"sub-carol-1", "sub-carol-2"} {
		if _, ok := denies["sub="+sub]; ok {
			t.Fatalf("the hub chose subject %s for an ambiguous match", sub)
		}
	}
	// The token whose owner carries only a subject was not followed.
	if err := w.tokenErr(carolTok); err != nil {
		t.Fatalf("an ambiguous match was followed to a subject's token: %v", err)
	}
	rows := w.audit("scim.match_ambiguous")
	if len(rows) != 1 || rows[0]["operation"] != "suspend" {
		t.Fatalf("scim.match_ambiguous rows: %v", rows)
	}
	// And the directory grants such a user no groups.
	grp := `{"displayName":"admins","members":[{"value":"` + id + `"}]}`
	if _, err := w.svc.CreateGroup(context.Background(), actor, []byte(grp), testBase); err != nil {
		t.Fatal(err)
	}
	w.mustPatch(id, entraEnable)
	if g := w.dir.DirectoryGroups(&authz.Subject{Sub: "sub-carol-1", Email: "carol@example.com"}); len(g) != 1 {
		t.Fatalf("an active, uniquely provisioned user's groups: %v", g)
	}
}

// ── deletion, holds and the offboard clock ──────────────────────────────────

func TestDeleteRunsTheFullOffboardingUnderAHold(t *testing.T) {
	w := newWorld(t, MatchEmail)
	id := w.create(aliceUser)["id"].(string)
	if _, err := PlaceHold(w.db, aliceEmail, "LH-17 contract dispute", AdminContext{Actor: "cli:root"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	res, err := w.svc.DeleteUser(context.Background(), actor, id, "")
	if err != nil || res.Status != http.StatusNoContent {
		t.Fatalf("DeleteUser: %d %v", res.Status, err)
	}
	if _, err := w.svc.GetUser(id, url.Values{}, testBase); err == nil {
		t.Fatal("the deleted user is still served")
	}
	// The hold kept her personal secret; access went anyway.
	if !w.secretExists(w.aliceSecret.ID) {
		t.Fatal("a held secret was destroyed")
	}
	if g := w.grant(w.aliceGrant.ID); g.RevokedAt.IsZero() {
		t.Fatal("the grant over a held secret was not revoked")
	}
	if _, ok := w.denies()["email="+aliceEmail]; !ok {
		t.Fatal("no deny after the offboarding")
	}
	if rows := w.audit("user.offboard_hold"); len(rows) != 1 {
		t.Fatalf("user.offboard_hold rows: %v", rows)
	}
	rows := w.audit("scim.user_delete")
	if len(rows) != 1 || rows[0]["legal_hold"] != true {
		t.Fatalf("scim.user_delete rows: %v", rows)
	}
	// A late retry, or a reordered deactivation, finds nothing to act on.
	if _, err := w.svc.DeleteUser(context.Background(), actor, id, ""); err == nil {
		t.Fatal("a second DELETE succeeded")
	}
	if _, err := w.patch(id, entraEnable); err == nil {
		t.Fatal("a reactivation after the delete resurrected the user")
	}
}

func TestOffboardAfterDays(t *testing.T) {
	w := newWorld(t, MatchEmail)
	w.svc.Config.OffboardAfter = 30 * 24 * time.Hour
	id := w.create(aliceUser)["id"].(string)
	w.mustPatch(id, entraDisable)

	w.clk.advance(29 * 24 * time.Hour)
	if n, err := w.svc.OffboardExpired(context.Background()); err != nil || n != 0 {
		t.Fatalf("offboarded %d before the clock ran out (%v)", n, err)
	}
	w.clk.advance(2 * 24 * time.Hour)
	if n, err := w.svc.OffboardExpired(context.Background()); err != nil || n != 1 {
		t.Fatalf("offboarded %d after the clock ran out (%v)", n, err)
	}
	if w.secretExists(w.aliceSecret.ID) {
		t.Fatal("the personal secret survived the full offboarding")
	}
	row, _ := w.db.GetSCIMUser(id)
	if row.OffboardedAt.IsZero() || row.Suspension != "" {
		t.Fatalf("the row is not marked offboarded: %+v", row)
	}
	if rows := w.audit("scim.user_offboard_expired"); len(rows) != 1 {
		t.Fatalf("scim.user_offboard_expired rows: %v", rows)
	}
	// Only once.
	if n, _ := w.svc.OffboardExpired(context.Background()); n != 0 {
		t.Fatalf("offboarded again: %d", n)
	}
	// A reactivation now lifts nothing: what the offboarding destroyed stays
	// destroyed, and its denies stay until an administrator removes them.
	w.mustPatch(id, entraEnable)
	if _, ok := w.denies()["email="+aliceEmail]; !ok {
		t.Fatal("a reactivation after the offboarding lifted its deny")
	}
	rows := w.audit("scim.user_reactivate")
	if len(rows) != 1 || rows[0]["offboarded_at"] == nil {
		t.Fatalf("scim.user_reactivate does not say the account was offboarded: %v", rows)
	}
}

// ── groups ──────────────────────────────────────────────────────────────────

// TestProvisionedGroupDemotesOnTheNextDecision: a scim_group binding grants
// admin, and removing the member at the identity provider withdraws it at
// the next decision — with no claim refresh in between.
func TestProvisionedGroupDemotesOnTheNextDecision(t *testing.T) {
	w := newWorld(t, MatchEmail)
	id := w.create(aliceUser)["id"].(string)
	g, err := w.svc.CreateGroup(context.Background(), actor,
		[]byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"cloop-admins",
		"externalId":"0f3b-group","members":[{"value":"`+id+`"}]}`), testBase)
	if err != nil {
		t.Fatal(err)
	}
	gid := g.Resource["id"].(string)
	r, err := authz.New(authz.Config{
		Bindings:  []authz.Binding{{Claim: authz.ClaimSCIMGroup, Value: "cloop-admins", Role: authz.RoleAdmin}},
		Directory: w.dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	alice := &authz.Subject{Sub: aliceSub, Email: aliceEmail}
	if d := r.Resolve(alice, authz.GlobalScope); d.Role != authz.RoleAdmin {
		t.Fatalf("a provisioned member resolves to %s", d.Role)
	}
	if len(alice.SCIMGroups) != 0 {
		t.Fatal("Resolve wrote into the caller's subject")
	}
	// A subject that asserts the group itself gets nothing for it.
	forged := &authz.Subject{Sub: bobSub, Email: bobEmail, SCIMGroups: []string{"cloop-admins"}}
	if d := r.Resolve(forged, authz.GlobalScope); d.Role == authz.RoleAdmin {
		t.Fatal("a subject's own SCIMGroups were believed")
	}
	// Entra removes her.
	if _, err := w.svc.PatchGroup(context.Background(), actor, gid,
		[]byte(`{"Operations":[{"op":"Remove","path":"members","value":[{"value":"`+id+`"}]}]}`), "", testBase); err != nil {
		t.Fatal(err)
	}
	if d := r.Resolve(alice, authz.GlobalScope); d.Role == authz.RoleAdmin {
		t.Fatal("the removal did not reach the next decision")
	}
	// And a group never counts for a suspended account.
	if _, err := w.svc.PatchGroup(context.Background(), actor, gid,
		[]byte(`{"Operations":[{"op":"add","path":"members","value":[{"value":"`+id+`"}]}]}`), "", testBase); err != nil {
		t.Fatal(err)
	}
	if d := r.Resolve(alice, authz.GlobalScope); d.Role != authz.RoleAdmin {
		t.Fatal("re-adding did not grant again")
	}
	w.mustPatch(id, entraDisable)
	if got := w.dir.DirectoryGroups(alice); len(got) != 0 {
		t.Fatalf("a suspended account's groups: %v", got)
	}
	if rows := w.audit("scim.group_members"); len(rows) != 2 {
		t.Fatalf("scim.group_members rows: %d", len(rows))
	}
}

func TestGroupMembershipIsASet(t *testing.T) {
	w := newWorld(t, MatchEmail)
	id := w.create(aliceUser)["id"].(string)
	g, err := w.svc.CreateGroup(context.Background(), actor, []byte(`{"displayName":"eng"}`), testBase)
	if err != nil {
		t.Fatal(err)
	}
	gid := g.Resource["id"].(string)
	add := `{"Operations":[{"op":"Add","path":"members","value":[{"value":"` + id + `"},{"value":"no-such-user"}]}]}`
	for i := 0; i < 2; i++ {
		res, err := w.svc.PatchGroup(context.Background(), actor, gid, []byte(add), "", testBase)
		if err != nil || res.Status != http.StatusNoContent {
			t.Fatalf("add %d: %d %v", i, res.Status, err)
		}
	}
	got, _ := w.db.GetSCIMGroup(gid)
	if len(got.Members) != 1 || got.Members[0] != id {
		t.Fatalf("members = %v", got.Members)
	}
	rows := w.audit("scim.group_members")
	if l, _ := rows[0]["unknown_members"].([]any); len(rows) == 0 || len(l) == 0 {
		t.Fatalf("the unknown member was not reported: %v", rows)
	}
	// Removing somebody who is not a member succeeds and changes nothing.
	rm := `{"Operations":[{"op":"remove","path":"members[value eq \"someone-else\"]"}]}`
	before := got.Version
	if _, err := w.svc.PatchGroup(context.Background(), actor, gid, []byte(rm), "", testBase); err != nil {
		t.Fatal(err)
	}
	if after, _ := w.db.GetSCIMGroup(gid); after.Version != before {
		t.Fatal("a no-op removal wrote a version")
	}
	// A duplicate display name is refused.
	if _, err := w.svc.CreateGroup(context.Background(), actor, []byte(`{"displayName":"ENG"}`), testBase); err == nil {
		t.Fatal("a second group named eng was accepted")
	}
	// Deleting the user drops the membership.
	if _, err := w.svc.DeleteUser(context.Background(), actor, id, ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := w.db.GetSCIMGroup(gid); len(got.Members) != 0 {
		t.Fatalf("a deleted user is still a member: %v", got.Members)
	}
}

// ── match claims ────────────────────────────────────────────────────────────

func TestMatchClaims(t *testing.T) {
	for _, c := range []struct {
		claim MatchClaim
		user  string
		deny  string // claim=value the suspension must write
	}{
		{MatchOID, aliceUser, "oid=" + aliceOID},
		{MatchUsername, aliceUser, "username=" + aliceEmail},
		{MatchSub, strings.Replace(aliceUser, aliceOID, aliceSub, 1), "sub=" + aliceSub},
	} {
		t.Run(string(c.claim), func(t *testing.T) {
			w := newWorld(t, c.claim)
			id := w.create(c.user)["id"].(string)
			w.mustPatch(id, entraDisable)
			denies := w.denies()
			if _, ok := denies[c.deny]; !ok {
				t.Fatalf("no deny %s; have %v", c.deny, denies)
			}
			// The sessions carrying the claim led to her subject and email.
			if _, ok := denies["sub="+aliceSub]; !ok {
				t.Fatalf("the match was not followed to her subject: %v", denies)
			}
			if !errors.Is(w.tokenErr(w.aliceToken), apitoken.ErrRevoked) {
				t.Fatal("her token survived")
			}
			if err := w.tokenErr(w.bobToken); err != nil {
				t.Fatal("bob's token was revoked")
			}
		})
	}
	if _, err := ParseMatchClaim("upn"); err == nil {
		t.Fatal("an unknown match claim was accepted")
	}
}

// TestNeverSignedInIsStillDenied: an account the hub has never seen is denied
// by the match claim, so its first sign-in gets nothing.
func TestNeverSignedInIsStillDenied(t *testing.T) {
	w := newWorld(t, MatchOID)
	id := w.create(`{"userName":"dave@example.com","externalId":"0B7E1C4D-2F3A-4E5B-8C6D-7E8F9A0B1C2D","active":true}`)["id"].(string)
	w.mustPatch(id, `{"Operations":[{"op":"replace","value":{"active":false}}]}`)
	if _, ok := w.denies()["oid=0b7e1c4d-2f3a-4e5b-8c6d-7e8f9a0b1c2d"]; !ok {
		t.Fatalf("no deny on the oid: %v", w.denies())
	}
}

// TestAnExternalIdThatIsNoObjectIDIsUnmatchable: Entra's default mapping
// sends mailNickname as externalId. Matching on oid, that is nobody — and is
// counted as such for the doctor — rather than a deny no token can trip.
func TestAnExternalIdThatIsNoObjectIDIsUnmatchable(t *testing.T) {
	w := newWorld(t, MatchOID)
	id := w.create(`{"userName":"dave@example.com","externalId":"dave","active":true}`)["id"].(string)
	w.mustPatch(id, `{"Operations":[{"op":"replace","value":{"active":false}}]}`)
	for d := range w.denies() {
		if strings.HasPrefix(d, "oid=") {
			t.Fatalf("a deny on an oid no token carries: %s", d)
		}
	}
	d, err := NewDirectory(w.db, MatchOID)
	if err != nil {
		t.Fatal(err)
	}
	if st := d.Stats(); st.Unmatchable != 1 {
		t.Fatalf("the user was not counted unmatchable: %+v", st)
	}
	for _, s := range []string{"6f9a0c3e-6c1b-4b7e-9d36-0a5b5c3f1e01", "6F9A0C3E-6C1B-4B7E-9D36-0A5B5C3F1E01"} {
		if !isObjectID(s) {
			t.Errorf("%s is an object ID", s)
		}
	}
	for _, s := range []string{"", "dave", "6f9a0c3e6c1b4b7e9d360a5b5c3f1e01", "{6f9a0c3e-6c1b-4b7e-9d36-0a5b5c3f1e01}",
		"6f9a0c3e-6c1b-4b7e-9d36-0a5b5c3f1e0g", "6f9a0c3e_6c1b-4b7e-9d36-0a5b5c3f1e01"} {
		if isObjectID(s) {
			t.Errorf("%q is not an object ID", s)
		}
	}
}

// ── reordering and conditional requests ─────────────────────────────────────

func TestAReplaceWithoutActiveDoesNotReactivate(t *testing.T) {
	w := newWorld(t, MatchEmail)
	id := w.create(aliceUser)["id"].(string)
	w.mustPatch(id, entraDisable)
	put := `{"userName":"alice@example.com","name":{"givenName":"Alicia"}}`
	res, err := w.svc.ReplaceUser(context.Background(), actor, id, []byte(put), "", testBase)
	if err != nil {
		t.Fatal(err)
	}
	if res.Resource["active"] != false {
		t.Fatal("a PUT that did not mention active reactivated the account")
	}
	if _, ok := w.denies()["email="+aliceEmail]; !ok {
		t.Fatal("the suspension was lifted by a PUT that did not ask")
	}
}

func TestIfMatchIsHonoured(t *testing.T) {
	w := newWorld(t, MatchEmail)
	res := w.create(aliceUser)
	id := res["id"].(string)
	_, err := w.svc.PatchUser(context.Background(), actor, id, []byte(entraDisable), `W/"99"`, testBase)
	var se *scim.Error
	if !errors.As(err, &se) || se.Status != http.StatusPreconditionFailed {
		t.Fatalf("a stale If-Match: %v", err)
	}
	if _, err := w.svc.PatchUser(context.Background(), actor, id, []byte(entraDisable), `W/"1"`, testBase); err != nil {
		t.Fatalf("a current If-Match: %v", err)
	}
}

func TestListFiltersAndPages(t *testing.T) {
	w := newWorld(t, MatchEmail)
	for _, u := range []string{"a", "b", "c", "d", "e"} {
		w.create(`{"userName":"` + u + `@example.com","externalId":"ext-` + u + `"}`)
	}
	list, err := w.svc.ListUsers(url.Values{"filter": {`userName eq "C@EXAMPLE.COM"`}}, testBase)
	if err != nil || list.TotalResults != 1 || list.Resources[0]["userName"] != "c@example.com" {
		t.Fatalf("filter by userName: %+v %v", list, err)
	}
	list, err = w.svc.ListUsers(url.Values{"filter": {`externalId eq "ext-d"`}}, testBase)
	if err != nil || list.TotalResults != 1 {
		t.Fatalf("filter by externalId: %+v %v", list, err)
	}
	list, err = w.svc.ListUsers(url.Values{"filter": {`userName eq "nobody"`}}, testBase)
	if err != nil || list.TotalResults != 0 || list.Resources == nil {
		t.Fatalf("zero results must be an empty list: %+v %v", list, err)
	}
	list, err = w.svc.ListUsers(url.Values{"startIndex": {"2"}, "count": {"2"}}, testBase)
	if err != nil || list.TotalResults != 5 || len(list.Resources) != 2 || list.StartIndex != 2 {
		t.Fatalf("paging: %+v %v", list, err)
	}
	if list.Resources[0]["userName"] != "b@example.com" {
		t.Fatalf("page 2 starts with %v", list.Resources[0]["userName"])
	}
	if _, err := w.svc.ListUsers(url.Values{"filter": {`userName eq`}}, testBase); err == nil {
		t.Fatal("a malformed filter was answered")
	}
}

func TestRateLimiter(t *testing.T) {
	l := NewRateLimiter(60)
	clk := &clock{t: time.Now()}
	l.SetClock(clk.now)
	n := 0
	for {
		ok, _ := l.Allow("c1")
		if !ok {
			break
		}
		n++
		if n > 100 {
			t.Fatal("the bucket never empties")
		}
	}
	if n != 10 {
		t.Fatalf("burst = %d, want 10", n)
	}
	if ok, wait := l.Allow("c1"); ok || wait <= 0 || wait > 2*time.Second {
		t.Fatalf("an empty bucket: %v %v", ok, wait)
	}
	if ok, _ := l.Allow("c2"); !ok {
		t.Fatal("one credential's limit spent another's")
	}
	clk.advance(time.Second)
	if ok, _ := l.Allow("c1"); !ok {
		t.Fatal("the bucket did not refill")
	}
}
