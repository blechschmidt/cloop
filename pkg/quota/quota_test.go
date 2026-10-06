package quota

import "testing"

// TestSessionCapIsTheOneRuleForZero: a sessions ceiling below one is no cap —
// the authenticator evicts rather than refuses, and a cap of 0 would sign out
// the session being created — while 0 refuses every other resource. Both the
// hub's session limit and `cloop hub doctor`'s zero-limit warning read it here
// (Task 20387).
func TestSessionCapIsTheOneRuleForZero(t *testing.T) {
	for _, tc := range []struct {
		limit float64
		set   bool
		want  int
	}{{0, false, 0}, {0, true, 0}, {-1, true, 0}, {0.5, true, 0}, {3, true, 3}} {
		if got := SessionCap(tc.limit, tc.set); got != tc.want {
			t.Errorf("SessionCap(%v, %v) = %d, want %d", tc.limit, tc.set, got, tc.want)
		}
	}
	for _, r := range AllResources {
		if want := r != ResSessions; r.ZeroAdmitsNone() != want {
			t.Errorf("%s.ZeroAdmitsNone() = %v, want %v", r, !want, want)
		}
	}
}

// TestConstrainsIsWhetherAnythingIsBounded: configured is not constraining —
// a policy of max_sessions: 0 alone bounds nothing (Task 20387).
func TestConstrainsIsWhetherAnythingIsBounded(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want bool
	}{
		{"nothing", Config{}, false},
		{"zero sessions", Config{Defaults: Limits{ResSessions: 0}}, false},
		{"unlimited by -1", Config{Defaults: Limits{ResConcurrentTasks: -1}}, false},
		{"two sessions", Config{Defaults: Limits{ResSessions: 2}}, true},
		{"zero projects refuses", Config{Defaults: Limits{ResProjects: 0}}, true},
	} {
		r, err := New(tc.cfg)
		if err != nil {
			t.Fatalf("%s: New: %v", tc.name, err)
		}
		if got := r.Constrains(); got != tc.want {
			t.Errorf("%s: Constrains() = %v, want %v", tc.name, got, tc.want)
		}
	}
}
