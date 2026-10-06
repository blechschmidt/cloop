package config

import (
	"strings"
	"testing"
)

// executors.failover.max_attempts (Task 20391): unset means the default of two
// re-dispatches, 0 turns re-dispatch off, and anything outside [0, 10] is
// bounded like every other numeric setting (Task 20082) — repaired toward the
// default by Load, refused by the writers. Never toward "no cap".

func TestFailoverMaxAttempts_Load(t *testing.T) {
	cases := []struct {
		name     string
		yaml     string
		want     int
		stated   bool
		warnings bool
	}{
		{"unset is the default", "provider: claudecode\n", FailoverMaxAttemptsDefault, false, false},
		{"zero turns re-dispatch off", "executors:\n  failover:\n    max_attempts: 0\n", 0, true, false},
		{"a value in the band", "executors:\n  failover:\n    max_attempts: 4\n", 4, true, false},
		{"the ceiling", "executors:\n  failover:\n    max_attempts: 10\n", 10, true, false},
		{"past the ceiling", "executors:\n  failover:\n    max_attempts: 11\n", FailoverMaxAttemptsDefault, false, true},
		{"negative", "executors:\n  failover:\n    max_attempts: -1\n", FailoverMaxAttemptsDefault, false, true},
		{"a typo for unlimited", "executors:\n  failover:\n    max_attempts: 1000000\n", FailoverMaxAttemptsDefault, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetClampWarned()
			dir := tempDir(t)
			writeYAMLConfig(t, dir, tc.yaml)
			var cfg *Config
			out := captureStderr(t, func() {
				var err error
				if cfg, err = Load(dir); err != nil {
					t.Fatalf("Load: %v", err)
				}
			})
			if got := cfg.Executors.Failover.MaxRedispatches(); got != tc.want {
				t.Errorf("MaxRedispatches = %d, want %d", got, tc.want)
			}
			if got := cfg.Executors.Failover.MaxAttempts != nil; got != tc.stated {
				t.Errorf("stated after Load = %v, want %v", got, tc.stated)
			}
			if got := strings.Contains(out, "executors.failover.max_attempts"); got != tc.warnings {
				t.Errorf("warning printed = %v, want %v (stderr %q)", got, tc.warnings, out)
			}
			repaired := false
			for _, r := range cfg.LoadRepairs() {
				if r.Field == "executors.failover.max_attempts" {
					repaired = true
				}
			}
			if repaired != tc.warnings {
				t.Errorf("load repair recorded = %v, want %v — `cloop hub doctor` reads these", repaired, tc.warnings)
			}
		})
	}
}

func TestFailoverMaxAttempts_ValidateRefusesOutOfBand(t *testing.T) {
	for _, v := range []int{0, 1, FailoverMaxAttemptsDefault, FailoverMaxAttemptsUpper} {
		v := v
		c := Default()
		c.Executors.Failover.MaxAttempts = &v
		if err := c.ValidateNumeric(); err != nil {
			t.Errorf("ValidateNumeric(%d) = %v, want nil", v, err)
		}
		if err := ValidateExecutors(c.Executors); err != nil {
			t.Errorf("ValidateExecutors(%d) = %v, want nil", v, err)
		}
	}
	for _, v := range []int{-1, FailoverMaxAttemptsUpper + 1, 1 << 20} {
		v := v
		c := Default()
		c.Executors.Failover.MaxAttempts = &v
		err := c.ValidateNumeric()
		if err == nil || !strings.Contains(err.Error(), "executors.failover.max_attempts") {
			t.Errorf("ValidateNumeric(%d) = %v, want a refusal naming the key", v, err)
		}
		if err := ValidateExecutors(c.Executors); err == nil {
			t.Errorf("ValidateExecutors(%d) accepted an out-of-band cap", v)
		}
	}
	if err := Default().ValidateNumeric(); err != nil {
		t.Errorf("the default config fails ValidateNumeric: %v", err)
	}
	if got := Default().Executors.Failover.MaxRedispatches(); got != 2 {
		t.Errorf("the default cap is %d, want 2 re-dispatches", got)
	}
}

// TestFailoverMaxAttempts_OverlayIsTheHubsOwn: a hub-scope key, so the
// per-instance overlay decides it for its hub alone — and is held to the same
// bound, so the overlay cannot escape what config.yaml cannot.
func TestFailoverMaxAttempts_OverlayIsTheHubsOwn(t *testing.T) {
	base := "provider: claudecode\nexecutors:\n  failover:\n    max_attempts: 5\n"
	dir := writeConfigs(t, base, "executors:\n  failover:\n    max_attempts: 1\n", 8081)

	hub, overlay, err := LoadUIInstance(dir, 8081)
	if err != nil || overlay == "" {
		t.Fatalf("LoadUIInstance = %v, %q", err, overlay)
	}
	if got := hub.Executors.Failover.MaxRedispatches(); got != 1 {
		t.Errorf("the overlay's hub runs with cap %d, want the overlay's 1", got)
	}
	other, _, err := LoadUIInstance(dir, 8080)
	if err != nil {
		t.Fatal(err)
	}
	if got := other.Executors.Failover.MaxRedispatches(); got != 5 {
		t.Errorf("the hub without an overlay runs with cap %d, want config.yaml's 5", got)
	}

	resetClampWarned()
	dir = writeConfigs(t, base, "executors:\n  failover:\n    max_attempts: 50\n", 8081)
	var bad *Config
	captureStderr(t, func() {
		bad, _, err = LoadUIInstance(dir, 8081)
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := bad.Executors.Failover.MaxRedispatches(); got != FailoverMaxAttemptsDefault {
		t.Errorf("an out-of-band overlay value left the cap at %d, want the default %d", got, FailoverMaxAttemptsDefault)
	}
}
