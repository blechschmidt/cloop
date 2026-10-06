package ui

// The failover path's half of the stored firewall levels (Task 20363): a
// session re-dispatched onto a replacement executor is composed again for it.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/fwpolicy"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// fwFailoverTarget is a failover target that records the spec it is started
// with and can install firewall rules.
type fwFailoverTarget struct {
	id  string
	got chan executor.Spec
}

func (r *fwFailoverTarget) ID() string   { return r.id }
func (r *fwFailoverTarget) Kind() string { return executor.KindContainer }
func (r *fwFailoverTarget) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: executor.IsolationContainer, NetworkEgress: true}
}
func (r *fwFailoverTarget) Start(_ context.Context, spec executor.Spec) (executor.Handle, error) {
	r.got <- spec
	return executor.Handle{ID: "h-failover", ExecutorID: r.id}, nil
}
func (r *fwFailoverTarget) Signal(context.Context, string, executor.Signal) error { return nil }
func (r *fwFailoverTarget) Status(context.Context, string) (executor.Status, error) {
	return executor.Status{}, nil
}
func (r *fwFailoverTarget) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	return nil, errors.New("no stream")
}
func (r *fwFailoverTarget) HealthCheck(context.Context) error { return nil }
func (r *fwFailoverTarget) EgressPosture() executor.EgressPosture {
	return executor.EgressPosture{DeviceID: r.id, Enforceable: true, RemovesNetwork: true}
}

// TestFirewall_FailoverComposesForTheReplacement: a session re-dispatched onto
// another executor carries that executor's device rules, not the ones it was
// composed under — and not none, which its driver would refuse.
func TestFirewall_FailoverComposesForTheReplacement(t *testing.T) {
	dir := setupProjectDir(t, "firewall failover", nil)
	withControlPlaneDir(t, dir)
	target := &fwFailoverTarget{id: "fw-failover-target", got: make(chan executor.Spec, 1)}
	if err := executor.DefaultRegistry.Register(target); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(target.id) })
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	rules := executor.FirewallRules{AllowPublicInternet: true, AllowPorts: []int{443}, Resolvers: []string{"1.1.1.1"}}
	if err := db.SetExecutorFirewall(target.id, rules, "admin"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	stale := executor.FirewallRules{AllowCIDRs: []string{"10.0.0.0/8"}, AllowPorts: []int{22}}
	ev := executor.FailoverEvent{From: "gone", To: target.id,
		Session: claimedSession(t, dir, executor.Session{ID: "s-1", ExecutorID: "gone",
			Spec: executor.Spec{WorkDir: dir, Argv: []string{"cloop", "run"}, EgressRules: &stale}})}
	_ = redispatchSession(context.Background(), dir, ev)
	select {
	case got := <-target.got:
		if got.EgressRules == nil || !fwpolicy.Equal(*got.EgressRules, rules) || got.EgressBound == nil {
			t.Errorf("the replacement was started with %+v / bound %+v, want its own device's rules",
				got.EgressRules, got.EgressBound)
		}
	default:
		t.Fatal("the replacement was never started")
	}
}

// claimedSession records sess as dispatched and claims it for failover, the
// state a re-dispatch requires of the session it is handed (Task 20391).
func claimedSession(t *testing.T, dir string, sess executor.Session) executor.Session {
	t.Helper()
	sched, db, err := newScheduler(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if sess.ClaimToken == "" {
		sess.ClaimToken = "tok-" + sess.ID
	}
	if err := sched.OpenSession(sess); err != nil {
		t.Fatal(err)
	}
	claimed, exhausted, err := sched.ClaimRequeue(sess.ID, sess.ClaimToken, executor.DefaultMaxFailoverAttempts, time.Now())
	if err != nil || exhausted {
		t.Fatalf("claim = exhausted %v, %v", exhausted, err)
	}
	// The stored spec is the persisted, redacted copy; the test's own spec is
	// what the event carries, as the supervisor's does.
	claimed.Spec = sess.Spec
	return claimed
}
