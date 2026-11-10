package executorpool_test

// Tests for what the hub makes of a pool's controllers (Task 20486): the
// cordon, the controller's name and protocol, its volume counts, and Assess,
// which the pool list and hub doctor share.

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func TestACordonedPoolIsToldNoDemandAndMintsNothing(t *testing.T) {
	s, db, c := newStore(t)
	p := mustCreate(t, s, executorpool.Spec{Name: "held", MaxRunners: 3})
	acc := access{bindings: map[string]string{"/srv/1": p.Binding(), "/srv/2": p.Binding()}}
	for _, id := range []string{"q1", "q2"} {
		if err := db.EnqueuePoolRun(statedb.PoolQueueRow{ID: id, PoolID: p.ID, ProjectPath: "/srv/" + id[1:]}); err != nil {
			t.Fatal(err)
		}
	}
	live, _, err := s.Snapshot(p, acc)
	if err != nil {
		t.Fatal(err)
	}
	if live.Cordoned || live.Demand != 2 || live.Waiting != 2 || live.Wanted != 2 {
		t.Fatalf("a live pool's snapshot %+v", live)
	}

	held, changed, err := s.Cordon(p.ID, true, "admin@example.com", "maintenance")
	if err != nil || !changed || !held.Cordoned() || held.CordonReason != "maintenance" {
		t.Fatalf("cordon: %+v %v %v", held, changed, err)
	}
	if _, changed, err := s.Cordon(p.ID, true, "admin@example.com", "again"); err != nil || changed {
		t.Fatalf("cordon a cordoned pool: changed %v, %v", changed, err)
	}
	snap, _, err := s.Snapshot(held, acc)
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Cordoned || snap.Demand != 0 || snap.Waiting != 2 || snap.Spare != 0 || snap.Wanted != 0 ||
		len(snap.QueuedProjects) != 0 || snap.Revision == live.Revision {
		t.Fatalf("a cordoned pool's snapshot %+v", snap)
	}
	if _, err := s.MintRunners(held, 1, runnerOpts); !errors.Is(err, executorpool.ErrCordoned) {
		t.Fatalf("a mint for a cordoned pool: %v", err)
	}

	// A runner enrolled before the cordon is handed nothing while it lasts.
	freed, _, err := s.Cordon(p.ID, false, "admin@example.com", "")
	if err != nil || freed.Cordoned() || freed.CordonReason != "" {
		t.Fatalf("uncordon: %+v %v", freed, err)
	}
	cfgs, err := s.MintRunners(freed, 1, runnerOpts)
	if err != nil {
		t.Fatal(err)
	}
	agent, err := redeem(t, s, db, cfgs[0].Token, c.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Cordon(p.ID, true, "admin@example.com", ""); err != nil {
		t.Fatal(err)
	}
	if ok, err := db.AssignPoolQueueEntry("q1", agent.AgentID, "member", c.now()); err != nil || ok {
		t.Fatalf("a cordoned pool's runner was handed a run: %v %v", ok, err)
	}
	if _, _, err := s.Cordon(p.ID, false, "admin@example.com", ""); err != nil {
		t.Fatal(err)
	}
	if ok, err := db.AssignPoolQueueEntry("q1", agent.AgentID, "member", c.now()); err != nil || !ok {
		t.Fatalf("an uncordoned pool's runner was not handed the run: %v %v", ok, err)
	}

	// A revoked pool is neither held nor released; a reason has a bound.
	if _, _, err := s.Cordon(p.ID, true, "admin", strings.Repeat("x", 501)); !errors.Is(err, executorpool.ErrInvalidSpec) {
		t.Fatalf("an overlong reason: %v", err)
	}
	if _, err := s.Revoke(p.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Cordon(p.ID, true, "admin", ""); !errors.Is(err, executorpool.ErrRevoked) {
		t.Fatalf("cordon a revoked pool: %v", err)
	}
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{Limit: 100, EventType: "executor_pool.cordon"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("%d executor_pool.cordon rows, want 4: only changes are recorded", len(rows))
	}
}

func TestTheControllerIsKnownByWhatItSays(t *testing.T) {
	s, _, c := newStore(t)
	p := mustCreate(t, s, executorpool.Spec{Name: "named", MaxRunners: 1})
	token, cred, err := s.MintCredential(p.ID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if cred.ControllerProtocol != 0 || cred.ControllerVersion != "" {
		t.Fatalf("a fresh credential names a controller: %+v", cred)
	}
	if err := s.NoteController(cred.ID, "v0.0.8", 4); err != nil {
		t.Fatal(err)
	}
	_, got, err := s.Authenticate(token)
	if err != nil {
		t.Fatal(err)
	}
	if got.ControllerVersion != "v0.0.8" || got.ControllerProtocol != 4 {
		t.Fatalf("the credential's controller: %+v", got)
	}
	in, err := s.HealthInputFor(p)
	if err != nil {
		t.Fatal(err)
	}
	if ctl, ok := in.Controller(); !ok || ctl.ID != cred.ID || !in.LastContact().Equal(c.now()) {
		t.Fatalf("the pool's controller: %+v %v, last contact %s", ctl, ok, in.LastContact())
	}

	for ua, want := range map[string]string{
		"cloop-executor-controller/v0.0.8":                     "v0.0.8",
		"cloop-executor-controller/dev+g1a2b3c4.dirty":         "dev+g1a2b3c4.dirty",
		"cloop-executor-controller/v1.0 (linux; amd64)":        "v1.0",
		"cloop-executor-controller":                            "",
		"cloop-executor-controller/<script>":                   "",
		"curl/8.0":                                             "",
		"cloop-executor-controller/" + strings.Repeat("9", 65): "",
	} {
		if got := executorpool.ParseControllerUserAgent(ua); got != want {
			t.Errorf("ParseControllerUserAgent(%q) = %q, want %q", ua, got, want)
		}
	}
	if executorpool.ParseControllerUserAgent(executorpool.ControllerUserAgent("v2.3.4")) != "v2.3.4" {
		t.Error("a controller's own User-Agent does not parse back")
	}
	for v, want := range map[string]int{"4": 4, " 3 ": 3, "": 0, "x": 0, "-1": 0, "99999999": 0} {
		if got := executorpool.ParseControllerProtocol(v); got != want {
			t.Errorf("ParseControllerProtocol(%q) = %d, want %d", v, got, want)
		}
	}
}

func TestStorageUsageRoundTripsAndRefusesNonsense(t *testing.T) {
	u := &executorpool.StorageUsage{Claims: 3, Bound: 2, Pending: 1, InUse: 1, BytesUsed: 1 << 30, BytesCapacity: 60 << 30}
	if got := executorpool.DecodeStorage(executorpool.EncodeStorage(u)); got == nil || *got != *u {
		t.Fatalf("round trip: %+v", got)
	}
	for _, bad := range []string{"", "{", `{"claims":1,"bound":3}`, `{"claims":-1}`, `{"bytes_used":-5}`} {
		if got := executorpool.DecodeStorage(bad); got != nil {
			t.Errorf("DecodeStorage(%q) = %+v, want nil", bad, got)
		}
	}
	if executorpool.EncodeStorage(nil) != "" {
		t.Error("no usage is stored as something")
	}
}

func TestAssessSaysWhatNeedsAPerson(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	pool := executorpool.Pool{ID: "pool-a", Name: "a", MaxRunners: 2}
	used := func(ago time.Duration, protocol int) executorpool.Credential {
		return executorpool.Credential{ID: "cred", LastUsedAt: now.Add(-ago), ControllerProtocol: protocol,
			ControllerVersion: "v0.0.8"}
	}
	current := used(time.Minute, executorpool.ControllerProtocol)
	cordoned := pool
	cordoned.CordonedAt = now.Add(-time.Hour)
	revoked := pool
	revoked.RevokedAt = now
	kinds := func(ps []executorpool.Problem) string {
		var out []string
		for _, p := range ps {
			out = append(out, p.Severity+":"+p.Kind)
		}
		return strings.Join(out, ",")
	}
	cases := []struct {
		name string
		in   executorpool.HealthInput
		want string
	}{
		{"healthy", executorpool.HealthInput{Pool: pool, Waiting: 1, Runners: 1, OldestWaiting: now.Add(-time.Minute),
			Credentials: []executorpool.Credential{current}}, ""},
		{"nothing waits and no controller", executorpool.HealthInput{Pool: pool}, ""},
		{"runs wait and no credential", executorpool.HealthInput{Pool: pool, Waiting: 2}, "fail:no_controller"},
		{"runs wait and the credential was revoked", executorpool.HealthInput{Pool: pool, Waiting: 1,
			Credentials: []executorpool.Credential{{ID: "c", RevokedAt: now, LastUsedAt: now}}}, "fail:no_controller"},
		{"runs wait and no controller ever called", executorpool.HealthInput{Pool: pool, Waiting: 1,
			Credentials: []executorpool.Credential{{ID: "c"}}}, "fail:no_contact"},
		{"runs wait and the controller went quiet", executorpool.HealthInput{Pool: pool, Waiting: 1,
			Credentials: []executorpool.Credential{used(executorpool.ContactStaleAfter, executorpool.ControllerProtocol)}},
			"fail:no_contact"},
		{"stuck at max", executorpool.HealthInput{Pool: pool, Waiting: 3, Runners: 2,
			OldestWaiting: now.Add(-executorpool.StuckAtMaxAfter), Credentials: []executorpool.Credential{current}},
			"warn:at_max"},
		{"at max, the run only just queued", executorpool.HealthInput{Pool: pool, Waiting: 3, Runners: 2,
			OldestWaiting: now.Add(-time.Minute), Credentials: []executorpool.Credential{current}}, ""},
		{"room for runners and none started", executorpool.HealthInput{Pool: pool, Waiting: 1, Runners: 1,
			OldestWaiting: now.Add(-executorpool.StuckAtMaxAfter), Credentials: []executorpool.Credential{current}},
			"warn:not_starting"},
		{"room, but the controller reports why", executorpool.HealthInput{Pool: pool, Waiting: 1,
			OldestWaiting: now.Add(-time.Hour), Credentials: []executorpool.Credential{current},
			Reports: []executorpool.ControllerReport{{CredentialID: "cred", Reason: "StorageFull",
				ReportedAt: now.Add(-time.Minute)}}}, "warn:storage"},
		{"cordoned with runs waiting", executorpool.HealthInput{Pool: cordoned, Waiting: 1, Runners: 2,
			OldestWaiting: now.Add(-time.Hour)}, "warn:cordoned_waiting"},
		{"volumes stuck Pending", executorpool.HealthInput{Pool: pool, Credentials: []executorpool.Credential{current},
			Reports: []executorpool.ControllerReport{{CredentialID: "cred", Reason: "StoragePending",
				Message: "claim a-storage-0 is Pending", ReportedAt: now.Add(-time.Minute)}}}, "warn:pvcs_pending"},
		{"a full volume", executorpool.HealthInput{Pool: pool, Credentials: []executorpool.Credential{current},
			Reports: []executorpool.ControllerReport{{CredentialID: "cred", Reason: "StorageFull",
				ReportedAt: now.Add(-time.Minute)}}}, "warn:storage"},
		{"an old report of trouble", executorpool.HealthInput{Pool: pool, Credentials: []executorpool.Credential{current},
			Reports: []executorpool.ControllerReport{{CredentialID: "cred", Reason: "StoragePending",
				ReportedAt: now.Add(-executorpool.ReportFreshFor)}}}, ""},
		{"a controller a protocol behind", executorpool.HealthInput{Pool: pool,
			Credentials: []executorpool.Credential{used(time.Minute, executorpool.ControllerProtocol-1)}}, "warn:controller_behind"},
		{"a controller that names no protocol", executorpool.HealthInput{Pool: pool,
			Credentials: []executorpool.Credential{used(time.Minute, 0)}}, "warn:controller_behind"},
		{"an old credential's old controller", executorpool.HealthInput{Pool: pool,
			Credentials: []executorpool.Credential{used(executorpool.BehindCountsFor, 0)}}, ""},
		{"a revoked pool", executorpool.HealthInput{Pool: revoked, Waiting: 5}, ""},
	}
	for _, c := range cases {
		c.in.Now = now
		got := executorpool.Assess(c.in)
		if kinds(got) != c.want {
			t.Errorf("%s: %q, want %q (%+v)", c.name, kinds(got), c.want, got)
		}
		for _, p := range got {
			if p.Message == "" || !strings.Contains(p.Message, c.in.Pool.Name) {
				t.Errorf("%s: a problem that does not name its pool: %+v", c.name, p)
			}
		}
	}
}

func TestCreateWithWritesTheAccessListAndCredentialTogether(t *testing.T) {
	s, db, _ := newStore(t)
	made, err := s.CreateWith(executorpool.Spec{Name: "gpu", MaxRunners: 2}, "admin@example.com",
		[]executorpool.AudienceEntry{{Kind: "Group", Value: " ml-team "}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if made.Credential == nil || !strings.HasPrefix(made.Token, executorpool.CredentialPrefix) {
		t.Fatalf("no credential: %+v", made)
	}
	if p, _, err := s.Authenticate(made.Token); err != nil || p.ID != made.Pool.ID {
		t.Fatalf("the minted credential does not authenticate: %v", err)
	}
	if entries, _ := s.Audience(made.Pool.ID); len(entries) != 1 || entries[0].Kind != "group" || entries[0].Value != "ml-team" {
		t.Fatalf("the access list: %+v", entries)
	}
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range rows {
		seen[r.EventType] = true
	}
	for _, want := range []string{"executor_pool.create", "executor_pool.audience", "executor_pool.credential_mint"} {
		if !seen[want] {
			t.Errorf("no %s row", want)
		}
	}
	if _, err := s.CreateWith(executorpool.Spec{Name: "bad", MaxRunners: 1}, "admin",
		[]executorpool.AudienceEntry{{Kind: "planet", Value: "mars"}}, true); !errors.Is(err, executorpool.ErrInvalidSpec) {
		t.Fatalf("an unknown principal kind: %v", err)
	}
	if pools, _ := s.List(); len(pools) != 1 {
		t.Fatalf("a refused create left a pool: %d pools", len(pools))
	}
}

func TestACordonReasonIsOneCleanLine(t *testing.T) {
	s, _, _ := newStore(t)
	p := mustCreate(t, s, executorpool.Spec{Name: "held", MaxRunners: 1})
	token := "ghp_" + strings.Repeat("q7Zr", 9) // built here: push protection reads literals
	held, _, err := s.Cordon(p.ID, true, "admin", " node upgrade\nsee runbook\t\x07 token "+token+" ")
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(held.CordonReason, "\n\t\x07") || strings.Contains(held.CordonReason, token) ||
		!strings.HasPrefix(held.CordonReason, "node upgrade see runbook") {
		t.Fatalf("the stored reason: %q", held.CordonReason)
	}
}
